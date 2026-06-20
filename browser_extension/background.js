/**
 * DataShield DLP – Background Service Worker
 * Handles extension lifecycle, status badge updates, and server ping
 */

const DS_SERVER = "http://127.0.0.1:5000";

// Check if local DataShield agent is running
async function checkAgentStatus() {
  try {
    const resp = await fetch(`${DS_SERVER}/scan`, {
      method: "OPTIONS",
      signal: AbortSignal.timeout(3000),
    });
    return resp.ok || resp.status === 200 || resp.status === 204;
  } catch {
    return false;
  }
}

// Update the extension icon badge
async function updateBadge() {
  const alive = await checkAgentStatus();
  chrome.action.setBadgeText({ text: alive ? "ON" : "OFF" });
  chrome.action.setBadgeBackgroundColor({ color: alive ? "#22c55e" : "#ef4444" });
  chrome.action.setTitle({
    title: alive
      ? "DataShield DLP – Agent active (protected)"
      : "DataShield DLP – Agent not running (unprotected)"
  });
}

// Check every 30 seconds
chrome.alarms.create("ds-ping", { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "ds-ping") updateBadge();
});

// Check on install and startup
chrome.runtime.onInstalled.addListener(updateBadge);
chrome.runtime.onStartup.addListener(updateBadge);
updateBadge();
