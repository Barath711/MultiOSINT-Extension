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
// URL -> VirusTotal direct API
// ──────────────────────────────────────────────────────
async function scanUrlVirusTotal(linkUrl, vtKey) {
  const url = String(linkUrl || "").trim();
 
  if (!url) {
    notify("VirusTotal", "No URL provided.");
    return;
  }
 
  if (!vtKey) {
    chrome.tabs.create({
      url: "https://www.virustotal.com/gui/search/" + encodeURIComponent(url)
    });
    return;
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
 
    const data = await response.json().catch(() => ({}));
 
    let reportId = "";
 
    if (data && data.data && data.data.id) {
      reportId = data.data.id;
    }
 
    if (!reportId) {
      reportId = vtUrlId(url);
    }
 
    chrome.tabs.create({
      url: "https://www.virustotal.com/gui/url/" + reportId
    });
 
    return {
      id: reportId,
      reportUrl: "https://www.virustotal.com/gui/url/" + reportId
    };
 
  } catch (e) {
    notify("VirusTotal", "Submit failed, opening search page.");
 
    chrome.tabs.create({
      url: "https://www.virustotal.com/gui/search/" + encodeURIComponent(url)
    });
  }
}
 
// ──────────────────────────────────────────────────────
// URL -> URLScan.io direct API
// ──────────────────────────────────────────────────────
async function scanUrlUrlscan(linkUrl, urlscanKey) {
  const url = String(linkUrl || "").trim();
 
  if (!url) {
    notify("URLScan.io", "No URL provided.");
    return;
  }
 
  if (!urlscanKey) {
    chrome.tabs.create({
      url: "https://urlscan.io/search/#" + encodeURIComponent(url)
    });
    return;
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
 
    const reportUrl = data.result || `https://urlscan.io/result/${uuid}/`;
 
    chrome.tabs.create({
      url: reportUrl
    });
 
    return {
      uuid,
      reportUrl
    };
 
  } catch (e) {
    notify("URLScan.io", e.message || "Submit failed, opening search page.");
 
    chrome.tabs.create({
      url: "https://urlscan.io/search/#" + encodeURIComponent(url)
    });
  }
}
 
// ──────────────────────────────────────────────────────
// Scan link with both VirusTotal and URLScan.io
// ──────────────────────────────────────────────────────
async function scanLink(linkUrl) {
  const url = String(linkUrl || "").trim();
 
  if (!url) {
    notify("MultiOSINT", "No link found to scan.");
    return;
  }
 
  const { vt, urlscan } = await getKeys();
 
  await scanUrlVirusTotal(url, vt);
  await scanUrlUrlscan(url, urlscan);
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
 
  chrome.tabs.query(
    {
      active: true,
      currentWindow: true
    },
    (tabs) => {
      const tab = tabs[0];
 
      if (!tab || !tab.id) return;
 
      chrome.tabs.sendMessage(
        tab.id,
        {
          action: "getSelectionAndCopy"
        },
        (response) => {
          if (chrome.runtime.lastError || !response || !response.selection) {
            return;
          }
 
          processIOC(response.selection, tab.id);
        }
      );
    }
  );
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
