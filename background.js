importScripts("utils.js");
 
const MENU_OSINT = "osintLookup";
const MENU_VT_LINK = "vtLinkScan";
 
// ──────────────────────────────────────────────────────
// Context menus
// ──────────────────────────────────────────────────────
function buildMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: MENU_OSINT,
      title: 'MultiOSINT lookup: "%s"',
      contexts: ["selection"]
    });
 
    chrome.contextMenus.create({
      id: MENU_VT_LINK,
      title: "Scan link with VirusTotal + URLScan.io",
      contexts: ["link"]
    });
  });
}
 
chrome.runtime.onInstalled.addListener(buildMenus);
chrome.runtime.onStartup.addListener(buildMenus);
 
// ──────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────
function getKeys() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(
      {
        vtApiKey: "",
        urlscanApiKey: ""
      },
      (d) => {
        resolve({
          vt: String(d.vtApiKey || "").trim(),
          urlscan: String(d.urlscanApiKey || "").trim()
        });
      }
    );
  });
}
 
function notify(title, message) {
  try {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icon.png",
      title,
      message
    });
  } catch (e) {
    // Notifications are optional.
  }
}
 
function openTabbedWindow(urls) {
  if (!urls || !urls.length) {
    notify("MultiOSINT", "No OSINT sources matched this indicator.");
    return;
  }
 
  chrome.windows.create({
    url: urls,
    focused: true
  });
}
 
function extractUuid(resultUrl) {
  if (!resultUrl) return "";
 
  const match = String(resultUrl).match(/\/result\/([^/]+)\/?/i);
  return match ? match[1] : "";
}
 
// VirusTotal URL identifier fallback.
// VT normally returns the URL analysis/report id in the API response.
// This fallback keeps the report-opening logic safe if the response does not contain it.
function vtUrlId(url) {
  return btoa(url)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
 
// ──────────────────────────────────────────────────────
// Selection -> OSINT lookup
// ──────────────────────────────────────────────────────
function runOsintLookup(rawText, tabId) {
  const { urls, type, cleaned } = getOsintUrlsFor(rawText || "");
 
  if (!cleaned) {
    notify("MultiOSINT", "Nothing selected to look up.");
    return;
  }
 
  if (tabId != null) {
    chrome.tabs.sendMessage(
      tabId,
      {
        action: "copyText",
        text: cleaned
      },
      () => void chrome.runtime.lastError
    );
  }
 
  notify(
    "MultiOSINT",
    `Opening ${urls.length} ${type.toUpperCase()} sources for ${cleaned}`
  );
 
  openTabbedWindow(urls);
}
 
// ──────────────────────────────────────────────────────
// URL -> VirusTotal direct API. Returns the report URL to open.
// ──────────────────────────────────────────────────────
async function scanUrlVirusTotal(linkUrl, vtKey) {
  const url = String(linkUrl || "").trim();
  if (!url) return null;

  if (!vtKey) {
    return "https://www.virustotal.com/gui/search/" + encodeURIComponent(url);
  }

  try {
    const response = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": vtKey,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: "url=" + encodeURIComponent(url)
    });

    await response.json().catch(() => ({}));

    // The GUI report page is keyed by the base64url-encoded URL, NOT by the
    // analysis id (u-<sha256>-<ts>) returned in the POST response.
    return "https://www.virustotal.com/gui/url/" + vtUrlId(url);

  } catch (e) {
    notify("VirusTotal", "Submit failed, opening search page.");
    return "https://www.virustotal.com/gui/search/" + encodeURIComponent(url);
  }
}

// ──────────────────────────────────────────────────────
// URL -> URLScan.io direct API. Returns the report URL to open.
// ──────────────────────────────────────────────────────
async function scanUrlUrlscan(linkUrl, urlscanKey) {
  const url = String(linkUrl || "").trim();
  if (!url) return null;

  if (!urlscanKey) {
    return "https://urlscan.io/search/#" + encodeURIComponent(url);
  }

  try {
    const response = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "API-Key": urlscanKey
      },
      body: JSON.stringify({
        url: url,
        visibility: "public"
      })
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(
        data.message || `URLScan submission failed. HTTP ${response.status}`
      );
    }

    const uuid = data.uuid || extractUuid(data.result);
    if (!uuid) {
      throw new Error("Submission succeeded, but no scan UUID was returned.");
    }

    // The plain /result/<uuid>/ page returns HTTP 404 until the scan finishes.
    // The /loading page polls and auto-redirects to the result when ready.
    return `https://urlscan.io/result/${uuid}/loading`;

  } catch (e) {
    notify("URLScan.io", e.message || "Submit failed, opening search page.");
    return "https://urlscan.io/search/#" + encodeURIComponent(url);
  }
}

// ──────────────────────────────────────────────────────
// Scan link with both VirusTotal and URLScan.io
// Opens both reports tabbed together in one new window.
// ──────────────────────────────────────────────────────
async function scanLink(linkUrl) {
  const url = String(linkUrl || "").trim();

  if (!url) {
    notify("MultiOSINT", "No link found to scan.");
    return;
  }

  const { vt, urlscan } = await getKeys();

  const [vtUrl, usUrl] = await Promise.all([
    scanUrlVirusTotal(url, vt),
    scanUrlUrlscan(url, urlscan)
  ]);

  const urls = [vtUrl, usUrl].filter(Boolean);
  notify("MultiOSINT", `Opening VirusTotal + URLScan.io for ${url}`);
  openTabbedWindow(urls);
}
 
// ──────────────────────────────────────────────────────
// Route any single IOC
// URLs -> VT + URLScan.io
// Others -> OSINT tabs
// ──────────────────────────────────────────────────────
async function processIOC(rawText, tabId) {
  const cleaned = cleanIOC(rawText);
 
  if (!cleaned) {
    notify("MultiOSINT", "No valid IOC found.");
    return;
  }
 
  if (getIOCType(cleaned) === "url") {
    await scanLink(cleaned);
  } else {
    runOsintLookup(rawText, tabId);
  }
}
 
// ──────────────────────────────────────────────────────
// Process batch of IOCs
// newline / comma / space separated
// ──────────────────────────────────────────────────────
async function processBatch(text) {
  const items = String(text || "")
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
 
  for (const item of items) {
    await processIOC(item, null);
  }
 
  return items.length;
}
 
// ──────────────────────────────────────────────────────
// Listeners
// ──────────────────────────────────────────────────────
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === MENU_OSINT) {
    processIOC(info.selectionText, tab && tab.id);
    return;
  }
 
  if (info.menuItemId === MENU_VT_LINK) {
    scanLink(info.linkUrl);
    return;
  }
});
 
chrome.commands.onCommand.addListener((command) => {
  if (command !== "lookup-ioc") return;

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab || !tab.id) return;

    // Read the current selection directly via scripting. This does NOT depend
    // on the content script being injected, so the shortcut works reliably.
    chrome.scripting.executeScript(
      {
        target: { tabId: tab.id },
        func: () => (window.getSelection ? window.getSelection().toString() : "")
      },
      (results) => {
        if (chrome.runtime.lastError) {
          notify("MultiOSINT", "Can't read selection on this page. Try the popup box.");
          return;
        }
        const selection = (results && results[0] && results[0].result || "").trim();
        if (!selection) {
          notify("MultiOSINT", "Select an IOC first, then press the shortcut.");
          return;
        }
        processIOC(selection, tab.id);
      }
    );
  });
});
 
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.action === "lookupBatch") {
    const count = String(msg.text || "")
      .split(/[\s,]+/)
      .filter(Boolean).length;
 
    sendResponse({
      ok: true,
      count
    });
 
    processBatch(msg.text);
    return false;
  }
 
  return false;
});