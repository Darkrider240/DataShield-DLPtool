/**
 * DataShield DLP – Popup Script
 * Checks if the local agent HTTP server is reachable and updates the UI
 */

const DS_SERVER = "http://127.0.0.1:5000";

async function checkAgent() {
  try {
    const resp = await fetch(`${DS_SERVER}/scan`, {
      method: "OPTIONS",
      signal: AbortSignal.timeout(3000),
    });
    return true; // OPTIONS always returns 200
  } catch {
    return false;
  }
}

async function init() {
  const alive = await checkAgent();

  const badge    = document.getElementById("agent-badge");
  const dot      = document.getElementById("status-dot");
  const text     = document.getElementById("agent-status-text");
  const okDiv    = document.getElementById("agent-ok");
  const downDiv  = document.getElementById("agent-down");

  if (alive) {
    badge.className = "badge active";
    dot.className   = "dot green";
    text.textContent = "Protected";
    okDiv.style.display   = "block";
    downDiv.style.display = "none";
  } else {
    badge.className = "badge inactive";
    dot.className   = "dot red";
    text.textContent = "Offline";
    okDiv.style.display   = "none";
    downDiv.style.display = "block";
  }
}

init();
