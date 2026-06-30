# 🛡️ MultiOSINT Context Lookup

A Chrome extension (Manifest V3) that turns any selected text or hyperlink into instant
OSINT intelligence. It auto-detects the indicator type — **IP, domain, hash, email, or URL** —
and opens every relevant OSINT source as tabs in a single new window. URLs are scanned
directly via the **VirusTotal** and **URLScan.io** APIs, with both reports opening tabbed
together in a new window.

It mirrors the source/detection logic of the **MultiOSINTv12** desktop tool.

---

## ✨ Features

- **Select text → right-click → “MultiOSINT lookup”**
  - Automatically identifies the IOC type using the same regex logic as the desktop app.
  - Cleans common defang notations (`[dot]`, `[.]`, `hxxp`, `hxxps`, quotes, brackets).
  - Opens **all** matching OSINT sources for that type, each in its own tab, grouped in a
    **new window**.
  - Copies the cleaned indicator to the clipboard and shows a desktop notification.
- **Right-click a link → “Scan link with VirusTotal + URLScan.io”**
  - **With API keys:** submits the URL to both the VirusTotal and URLScan.io APIs for fresh
    scans, then opens both reports **tabbed together in one new window**. URLScan opens the
    `/loading` page that auto-redirects when the scan finishes (no more 404s).
  - **Without keys:** opens VirusTotal & URLScan.io search (no key required).
- **Popup IOC box:** click the toolbar icon, paste one or many indicators (space/comma/newline
  separated), hit **Lookup** — each is auto-detected; URLs go straight to VT + URLScan.io,
  everything else opens across all OSINT sources.
- **⌨️ Keyboard shortcut:** `Alt+Shift+S` runs the lookup on the current selection.
- **API settings:** add/save/clear **VirusTotal** and **URLScan.io** API keys
  (stored securely via `chrome.storage.sync`). The key fields tolerate pasted
  config-style values like `"virustotal": "KEY"` and auto-extract the raw key.

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

> **Keyboard shortcut:** the default is `Alt+Shift+S`. If it doesn't fire, open
> `chrome://extensions/shortcuts` and confirm/assign **MultiOSINT → Alt+Shift+S**
> (Chrome skips a suggested key if another extension already claims it).

---

## 🔑 API Keys (optional)

**VirusTotal** — get a free key at <https://www.virustotal.com/gui/my-apikey>.
**URLScan.io** — get a key at <https://urlscan.io/user/profile/>.

1. Click the extension icon → expand **⚙️ API settings**.
2. Paste your VT and URLScan.io keys and click **Save keys**.

URLs are submitted directly to both services via their APIs and the reports open. Keys are
stored locally in your browser profile (`chrome.storage.sync`). Link scanning still works
without keys (falls back to search).

---

## 🧭 Usage

**Investigate an indicator**
1. Select any IP, domain, hash, email, or URL on a page.
2. Right-click → **MultiOSINT lookup**, or press `Alt+Shift+S`.
3. A new window opens with every relevant OSINT source tabbed.

**Scan a link**
1. Right-click any hyperlink.
2. Choose **Scan link with VirusTotal + URLScan.io**.
3. Both reports (or searches) open tabbed together in a new window.

**Use the popup box**
1. Click the toolbar icon.
2. Paste one or many IOCs (space/comma/newline separated) and click **Lookup** (or `Ctrl+Enter`).
3. URLs open in VT + URLScan.io; other indicators open across all OSINT sources.

---

## 📁 Project Structure

```
Chrome Extension/
├── manifest.json    # MV3 manifest, permissions, menus, command, options page
├── background.js    # Service worker: menus, IOC routing, VirusTotal + URLScan.io APIs
├── content.js       # Clipboard helper + selection retrieval
├── utils.js         # OSINT URL map, IOC cleaning & type detection
├── options.html     # Popup UI: IOC box + API key settings
├── options.js       # Popup logic (batch lookup, save/clear API keys)
├── icon.png         # Extension icon
└── README.md
```

---

## 🔒 Permissions

| Permission        | Why it’s needed |
|-------------------|-----------------|
| `contextMenus`    | Adds the right-click lookup / link-scan menu items |
| `tabs`            | Opens OSINT results in tabs/windows |
| `scripting` / `activeTab` | Reads the current text selection (incl. the keyboard shortcut) |
| `storage`         | Saves your VirusTotal & URLScan.io API keys |
| `notifications`   | Shows lookup status notifications |
| `host_permissions: virustotal.com, urlscan.io` | Submits links to the VirusTotal & URLScan.io APIs |

---

## ⚠️ Disclaimer

This tool is intended for **defensive security research and SOC/threat-intel workflows**.
You are responsible for complying with the terms of service and rate limits of each OSINT
provider. No data is sent anywhere except to the OSINT sources you explicitly trigger.

---

## 📜 License

Released under the **MIT License** — see `LICENSE` if included, or add one before publishing.
