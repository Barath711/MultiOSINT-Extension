const keyInput = document.getElementById("vtKey");
const statusEl = document.getElementById("status");

function flash(msg, ok = true) {
  statusEl.textContent = msg;
  statusEl.style.color = ok ? "#58d68d" : "#ff6b6b";
  setTimeout(() => { statusEl.textContent = ""; }, 2500);
}

document.addEventListener("DOMContentLoaded", () => {
  chrome.storage.sync.get({ vtApiKey: "" }, (d) => {
    keyInput.value = d.vtApiKey || "";
  });
});

document.getElementById("toggleVis").addEventListener("click", () => {
  keyInput.type = keyInput.type === "password" ? "text" : "password";
});

document.getElementById("save").addEventListener("click", () => {
  const vtApiKey = keyInput.value.trim();
  chrome.storage.sync.set({ vtApiKey }, () => {
    flash(vtApiKey ? "Saved ✔ VirusTotal API key stored." : "Saved ✔ (key cleared).");
  });
});

document.getElementById("clear").addEventListener("click", () => {
  keyInput.value = "";
  chrome.storage.sync.set({ vtApiKey: "" }, () => flash("API key cleared."));
});
