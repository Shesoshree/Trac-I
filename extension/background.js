// Trac-I Service Worker (Manifest V3)
chrome.runtime.onInstalled.addListener(() => {
  console.log("Trac-I Extension installed successfully.");
});

// Listen for messages from content script or popup if needed
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getSecurityStatus") {
    sendResponse({ status: "active" });
  }
  return true;
});
