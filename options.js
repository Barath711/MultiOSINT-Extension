const vtInput  = document.getElementById("vtKey");
const usInput  = document.getElementById("usKey");
const iocBox   = document.getElementById("iocBox");
const statusEl = document.getElementById("status");

function flash(msg, ok = true) {
  statusEl.textContent = msg;
  statusEl.style.color = ok ? "#58d68d" : "#ff6b6b";
  setTimeout(() => { statusEl.textContent = ""; }, 3000);
}

document.addEventListener("DOMContentLoaded", () => {
  chrome.storage.sync.get({ vtApiKey: "", urlscanApiKey: "" }, (d) => {
    vtInput.value = d.vtApiKey || "";
    usInput.value = d.urlscanApiKey || "";
  });
});

document.getElementById("toggleVis").addEventListener("click", () => {
  const t = vtInput.type === "password" ? "text" : "password";
  vtInput.type = t; usInput.type = t;
});

function extractKey(raw) {
  let s = String(raw || "").trim();
  if (!s) return "";
  // Tolerate pasted config-style values like:  "virustotal": "KEY"  or  virustotal: KEY
  s = s.replace(/^[\s{,]*["']?[A-Za-z0-9_]+["']?\s*[:=]\s*/, "");
  // Strip surrounding quotes / trailing commas / braces left over
  s = s.replace(/^["']|["',}\s]+$/g, "").trim();
  return s;
}

document.getElementById("save").addEventListener("click", () => {
  const vt = extractKey(vtInput.value);
  const us = extractKey(usInput.value);
  vtInput.value = vt;
  usInput.value = us;
  chrome.storage.sync.set({
    vtApiKey: vt,
    urlscanApiKey: us
  }, () => flash("Saved ✔ API keys stored."));
});

document.getElementById("clearKeys").addEventListener("click", () => {
  vtInput.value = ""; usInput.value = "";
  chrome.storage.sync.set({ vtApiKey: "", urlscanApiKey: "" }, () => flash("API keys cleared."));
});

document.getElementById("clearBox").addEventListener("click", () => { iocBox.value = ""; });

document.getElementById("lookup").addEventListener("click", () => {
  const text = iocBox.value.trim();
  if (!text) { flash("Enter at least one indicator.", false); return; }
  chrome.runtime.sendMessage({ action: "lookupBatch", text }, (resp) => {
    if (chrome.runtime.lastError) { flash("Error: " + chrome.runtime.lastError.message, false); return; }
    flash(`Processing ${resp && resp.count ? resp.count : ""} indicator(s)…`);
  });
});

iocBox.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) document.getElementById("lookup").click();
});
