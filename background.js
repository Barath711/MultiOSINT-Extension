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
    chrome.storage.sync.get({ vtApiKey: "", urlscanApiKey: "" }, (d) => resolve({
      vt: (d.vtApiKey || "").trim(),
      urlscan: (d.urlscanApiKey || "").trim()
    }));
  });
}

function notify(title, message) {
  try {
    chrome.notifications.create({ type: "basic", iconUrl: "icon.png", title, message });
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
// Selection -> OSINT lookup (non-URL indicators)
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
// URL -> VirusTotal + URLScan.io (direct API)
// ──────────────────────────────────────────────────────
async function scanUrlVirusTotal(linkUrl, vtKey) {
  if (!vtKey) {
    chrome.tabs.create({ url: "https://www.virustotal.com/gui/search/" + encodeURIComponent(linkUrl) });
    return;
  }
  try {
    await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: { "x-apikey": vtKey, "Content-Type": "application/x-www-form-urlencoded" },
      body: "url=" + encodeURIComponent(linkUrl)
    });
  } catch (e) {
    notify("VirusTotal", "Submit failed, opening existing report.");
  }
  const urlId = await sha256Hex(linkUrl);
  chrome.tabs.create({ url: "https://www.virustotal.com/gui/url/" + urlId });
}

async function scanUrlUrlscan(linkUrl, urlscanKey) {
  if (!urlscanKey) {
    chrome.tabs.create({ url: "https://urlscan.io/search/#" + encodeURIComponent(linkUrl) });
    return;
  }
  try {
    const resp = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: { "API-Key": urlscanKey, "Content-Type": "application/json" },
      body: JSON.stringify({ url: linkUrl, visibility: "public" })
    });
    const data = await resp.json();
    if (data && data.result) {
      chrome.tabs.create({ url: data.result });
    } else {
      notify("URLScan.io", (data && data.message) ? data.message : "Scan failed, opening search.");
      chrome.tabs.create({ url: "https://urlscan.io/search/#" + encodeURIComponent(linkUrl) });
    }
  } catch (e) {
    chrome.tabs.create({ url: "https://urlscan.io/search/#" + encodeURIComponent(linkUrl) });
  }
}

async function scanLink(linkUrl) {
  if (!linkUrl) return;
  const { vt, urlscan } = await getKeys();
  await scanUrlVirusTotal(linkUrl, vt);
  await scanUrlUrlscan(linkUrl, urlscan);
}

// ──────────────────────────────────────────────────────
// Route any single IOC: URLs -> VT+URLScan, others -> OSINT tabs
// ──────────────────────────────────────────────────────
async function processIOC(rawText, tabId) {
  const cleaned = cleanIOC(rawText);
  if (!cleaned) return;
  if (getIOCType(cleaned) === "url") {
    await scanLink(cleaned);
  } else {
    runOsintLookup(rawText, tabId);
  }
}

// Process a textarea full of IOCs (newline / comma / space separated).
async function processBatch(text) {
  const items = (text || "").split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
  for (const it of items) {
    await processIOC(it, null);
  }
  return items.length;
}

// ──────────────────────────────────────────────────────
// Listeners
// ──────────────────────────────────────────────────────
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === MENU_OSINT) {
    processIOC(info.selectionText, tab && tab.id);
  } else if (info.menuItemId === MENU_VT_LINK) {
    scanLink(info.linkUrl);
  }
});

chrome.commands.onCommand.addListener((command) => {
  if (command !== "lookup-ioc") return;
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab) return;
    chrome.tabs.sendMessage(tab.id, { action: "getSelectionAndCopy" }, (response) => {
      if (chrome.runtime.lastError || !response || !response.selection) return;
      processIOC(response.selection, tab.id);
    });
  });
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.action === "lookupBatch") {
    processBatch(msg.text).then((n) => sendResponse({ ok: true, count: n }));
    return true;
  }
});
