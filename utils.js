// ──────────────────────────────────────────────────────
// OSINT data + helpers (ported from MultiOSINTv12.pyw)
// Shared by background service worker (via importScripts)
// ──────────────────────────────────────────────────────

const osintUrls = {
  virustotal:        "https://www.virustotal.com/gui/search/",
  talosintelligence: "https://talosintelligence.com/reputation_center/lookup?search=",
  ibmxforce:         "https://exchange.xforce.ibmcloud.com/search/",
  shodan:            "https://www.shodan.io/search?query=",
  ipinfo:            "https://ipinfo.io/",
  abuseipdb:         "https://www.abuseipdb.com/check/",
  greynoise:         "https://www.greynoise.io/viz/ip/",
  hybridanalysis:    "https://www.hybrid-analysis.com/search?query=",
  urlscan:           "https://urlscan.io/search/#",
  threatfox:         "https://threatfox.abuse.ch/browse.php?search=ioc%3A",
  mxtoolbox:         "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a",
  censys:            "https://search.censys.io/hosts/",
  otx:               "https://otx.alienvault.com/indicator/",
  malwarebazaar:     "https://bazaar.abuse.ch/browse.php?search=",
  pulsedive:         "https://pulsedive.com/indicator/?ioc=",
  criminalip:        "https://www.criminalip.io/asset/report?ip=",
  phishtank:         "https://www.phishtank.com/search.php?valid=y&active=y&Search=Search&url=",
  hashlookup:        "https://hashlookup.circl.lu/lookup/sha256/",
  ipqs:              "https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/",
  breachvip:         "https://breach.vip/",
  xposedornot:       "https://xposedornot.com/xposed/#"
};

const defaultSources = {
  domain: ["virustotal", "talosintelligence", "ibmxforce", "urlscan", "mxtoolbox", "threatfox", "pulsedive", "phishtank"],
  ip:     ["virustotal", "talosintelligence", "abuseipdb", "greynoise", "shodan", "censys", "ipinfo", "criminalip", "pulsedive", "ipqs"],
  hash:   ["virustotal", "talosintelligence", "ibmxforce", "hybridanalysis", "threatfox", "malwarebazaar", "hashlookup", "pulsedive"],
  email:  ["ipqs", "breachvip", "xposedornot"],
  url:    ["virustotal", "urlscan", "phishtank", "threatfox", "ipqs"]
};

function cleanIOC(ioc) {
  if (!ioc) return "";
  ioc = ioc
    .replace(/\[dot\]/gi, ".")
    .replace(/\[\.\]/g, ".")
    .replace(/hxxps/gi, "https")
    .replace(/hxxp/gi, "http");
  ioc = ioc.replace(/["'\[\] ]/g, "");
  return ioc.trim().replace(/\/+$/, "");
}

function isHash(ioc)  { return /^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$/.test(ioc); }
function isIP(ioc)    { return /^((25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)$/.test(ioc); }
function isEmail(ioc) { return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(ioc); }
function isURL(ioc)   { return /^https?:\/\//i.test(ioc); }

function getIOCType(ioc) {
  if (isHash(ioc))  return "hash";
  if (isIP(ioc))    return "ip";
  if (isEmail(ioc)) return "email";
  if (isURL(ioc))   return "url";
  return "domain";
}

// Build [source, url] pairs for a cleaned IOC of a given type.
function buildUrlPairs(ioc, sources, iocType) {
  const pairs = [];
  const needsEncode = (iocType === "url" || iocType === "email");
  for (const src of sources) {
    const base = osintUrls[src];
    if (!base) continue;
    if (src === "otx") {
      const t = { ip: "ip", domain: "domain", hash: "file" }[iocType] || "domain";
      pairs.push([src, `${base}${t}/${encodeURIComponent(ioc)}`]);
    } else {
      const val = needsEncode ? encodeURIComponent(ioc) : ioc;
      pairs.push([src, base + val]);
    }
  }
  return pairs;
}

function getOsintUrlsFor(rawIOC) {
  const cleaned = cleanIOC(rawIOC);
  const type = getIOCType(cleaned);
  const sources = defaultSources[type] || [];
  return {
    cleaned,
    type,
    urls: buildUrlPairs(cleaned, sources, type).map(p => p[1])
  };
}
