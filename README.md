# 🛡️ MultiOSINT Context Lookup

A Chrome extension (Manifest V3) that turns any selected text or hyperlink into instant
OSINT intelligence. It auto-detects the indicator type — **IP, domain, hash, email, or URL** —
and opens every relevant OSINT source as tabs in a single new window. Links can be scanned
directly on **VirusTotal**.

It mirrors the source/detection logic of the **MultiOSINTv12** desktop tool.

---

## ✨ Features

- **Select text → right-click → “MultiOSINT lookup”**
  - Automatically identifies the IOC type using the same regex logic as the desktop app.
  - Cleans common defang notations (`[dot]`, `[.]`, `hxxp`, `hxxps`, quotes, brackets).
  - Opens **all** matching OSINT sources for that type, each in its own tab, grouped in a
    **new window**.
  - Copies the cleaned indicator to the clipboard and shows a desktop notification.
- **Right-click a link → “Scan link with VirusTotal”**
  - **With a VT API key:** submits the URL to the VirusTotal API for a fresh scan, then
    opens the report page.
  - **Without a key:** opens VirusTotal’s GUI search (no key required).
- **⌨️ Keyboard shortcut:** `Ctrl+Shift+Z` runs the OSINT lookup on the current selection.
- **Settings page / popup:** add, show/hide, save, or clear your VirusTotal API key
  (stored securely via `chrome.storage.sync`).

---

## 🔍 IOC Detection & Sources

| Type    | Detection                                   | Example OSINT sources opened |
|---------|---------------------------------------------|------------------------------|
| `hash`  | 32 / 40 / 64 hex characters                 | VirusTotal, Talos, IBM X-Force, Hybrid Analysis, ThreatFox, MalwareBazaar, Hashlookup, Pulsedive |
| `ip`    | IPv4 dotted quad                            | VirusTotal, Talos, AbuseIPDB, GreyNoise, Shodan, Censys, IPinfo, CriminalIP, Pulsedive, IPQS |
| `email` | `user@domain.tld`                           | IPQS, Breach.vip, XposedOrNot |
| `url`   | starts with `http://` / `https://`          | VirusTotal, urlscan.io, PhishTank, ThreatFox, IPQS |
| `domain`| fallback for anything else                  | VirusTotal, Talos, IBM X-Force, urlscan.io, MXToolbox, ThreatFox, Pulsedive, PhishTank |

---

## 🚀 Installation (Load Unpacked)

1. Download or clone this repository.
2. Open Chrome and navigate to `chrome://extensions`.
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select the `Chrome Extension` folder.
5. Pin the extension and click its icon to open **Settings**.

> After any code change, return to `chrome://extensions` and click **Reload** on the card.

---

## 🔑 VirusTotal API Key (optional)

1. Get a free key at <https://www.virustotal.com/gui/my-apikey>.
2. Click the extension icon (or open the extension’s **Options**).
3. Paste your key and click **Save**.

The key is only used to submit links to VirusTotal and is stored locally in your browser
profile via `chrome.storage.sync`. Link scanning still works without a key (it falls back to
VirusTotal search).

---

## 🧭 Usage

**Investigate an indicator**
1. Select any IP, domain, hash, email, or URL on a page.
2. Right-click → **MultiOSINT lookup**, or press `Ctrl+Shift+Z`.
3. A new window opens with every relevant OSINT source tabbed.

**Scan a link**
1. Right-click any hyperlink.
2. Choose **Scan link with VirusTotal**.
3. The VirusTotal report (or search) opens in a new tab.

---

## 📁 Project Structure

```
Chrome Extension/
├── manifest.json    # MV3 manifest, permissions, menus, options page
├── background.js    # Service worker: context menus, OSINT + VirusTotal logic
├── content.js       # Clipboard helper + selection retrieval
├── utils.js         # OSINT URL map, IOC cleaning & type detection
├── options.html     # Settings UI (also used as the toolbar popup)
├── options.js       # Settings logic (save/clear VT API key)
├── icon.png         # Extension icon
└── README.md
```

---

## 🔒 Permissions

| Permission        | Why it’s needed |
|-------------------|-----------------|
| `contextMenus`    | Adds the right-click lookup / VirusTotal menu items |
| `tabs`            | Opens OSINT results in tabs/windows |
| `scripting` / `activeTab` | Reads the current text selection |
| `storage`         | Saves your VirusTotal API key |
| `notifications`   | Shows lookup status notifications |
| `host_permissions: virustotal.com` | Submits links to the VirusTotal API |

---

## ⚠️ Disclaimer

This tool is intended for **defensive security research and SOC/threat-intel workflows**.
You are responsible for complying with the terms of service and rate limits of each OSINT
provider. No data is sent anywhere except to the OSINT sources you explicitly trigger.

---

## 📜 License

Released under the **MIT License** — see `LICENSE` if included, or add one before publishing.
