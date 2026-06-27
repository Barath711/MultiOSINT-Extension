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
      title: "Scan link with VirusTotal",
      contexts: ["link"]
    });
  });
}

chrome.runtime.onInstalled.addListener(buildMenus);
chrome.runtime.onStartup.addListener(buildMenus);

// ──────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────
function getVtKey() {
  return new Promise((resolve) => {
    chrome.storage.sync.get({ vtApiKey: "" }, (d) => resolve((d.vtApiKey || "").trim()));
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
  } catch (e) { /* notifications optional */ }
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function openTabbedWindow(urls) {
  if (!urls || !urls.length) {
    notify("MultiOSINT", "No OSINT sources matched this indicator.");
    return;
  }
  chrome.windows.create({ url: urls, focused: true });
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
    chrome.tabs.sendMessage(tabId, { action: "copyText", text: cleaned }, () => void chrome.runtime.lastError);
  }
  notify("MultiOSINT", `Opening ${urls.length} ${type.toUpperCase()} sources for ${cleaned}`);
  openTabbedWindow(urls);
}

// ──────────────────────────────────────────────────────
// Link -> VirusTotal
// ──────────────────────────────────────────────────────
async function scanLinkOnVirusTotal(linkUrl) {
  if (!linkUrl) return;
  const key = await getVtKey();

  if (!key) {
    // No API key: fall back to VT GUI search (no key required).
    chrome.tabs.create({ url: "https://www.virustotal.com/gui/search/" + encodeURIComponent(linkUrl) });
    return;
  }

  // With API key: submit the URL for analysis, then open the report page.
  try {
    await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": key,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: "url=" + encodeURIComponent(linkUrl)
    });
  } catch (e) {
    // Submission failed (network / quota) – still try to open whatever VT has.
    notify("VirusTotal", "Submit failed, opening existing report instead.");
  }

  const urlId = await sha256Hex(linkUrl);
  chrome.tabs.create({ url: "https://www.virustotal.com/gui/url/" + urlId });
}

// ──────────────────────────────────────────────────────
// Listeners
// ──────────────────────────────────────────────────────
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === MENU_OSINT) {
    runOsintLookup(info.selectionText, tab && tab.id);
  } else if (info.menuItemId === MENU_VT_LINK) {
    scanLinkOnVirusTotal(info.linkUrl);
  }
});

chrome.commands.onCommand.addListener((command) => {
  if (command !== "lookup-ioc") return;
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab) return;
    chrome.tabs.sendMessage(tab.id, { action: "getSelectionAndCopy" }, (response) => {
      if (chrome.runtime.lastError || !response || !response.selection) return;
      runOsintLookup(response.selection, tab.id);
    });
  });
});
