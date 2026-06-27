chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "getSelectionAndCopy") {
    const selection = window.getSelection().toString().trim();
    if (selection) {
      navigator.clipboard.writeText(selection)
        .then(() => sendResponse({ selection }))
        .catch(err => {
          console.error(err);
          sendResponse({ selection: null, error: err });
        });
    } else {
      sendResponse({ selection: "" });
    }
    return true; // Keep the message channel open
  }

  if (message.action === "copyText" && message.text) {
    navigator.clipboard.writeText(message.text.trim()).catch(console.error);
  }
});
