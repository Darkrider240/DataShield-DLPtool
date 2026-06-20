/**
 * DataShield DLP – Content Script
 * Runs on Gmail, Outlook Live, Outlook Office
 *
 * How it works:
 *   1. Detects when the user clicks "Send" on a compose window
 *   2. Intercepts the email subject, body, and recipients BEFORE the send fires
 *   3. POSTs the content to the local DataShield HTTP server at 127.0.0.1:5000/scan
 *   4. If the server returns BLOCK → prevents send, shows a warning overlay
 *   5. If the server returns WARN  → shows a warning but allows the user to confirm
 *   6. If the server returns ALLOW → does nothing, email sends normally
 *   7. After the user acts, POSTs /log_event to finalise the audit record
 */

const DS_SERVER = "http://127.0.0.1:5000";
const DS_TIMEOUT_MS = 6000; // if server not reachable in 6s, fail open (allow send)

// ── Utility: POST to DataShield local server ─────────────────────────────────
async function dsPost(path, payload) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DS_TIMEOUT_MS);
  try {
    const resp = await fetch(`${DS_SERVER}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timer);
    return await resp.json();
  } catch (e) {
    clearTimeout(timer);
    return null; // server unreachable → fail open
  }
}

// ── Overlay UI ────────────────────────────────────────────────────────────────
function createOverlay(result) {
  // Remove any existing overlay
  document.getElementById("ds-overlay")?.remove();

  const isBlock = result.action === "BLOCK";
  const color   = isBlock ? "#ef4444" : "#f59e0b";
  const title   = isBlock ? "🛡 DataShield: Email Blocked" : "🛡 DataShield: Review Required";
  const msg     = result.explanation || `Policy match: ${result.top_pattern} (${result.risk_level})`;

  const overlay = document.createElement("div");
  overlay.id = "ds-overlay";
  overlay.style.cssText = `
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(0,0,0,0.65); z-index: 99999;
    display: flex; align-items: center; justify-content: center;
    font-family: 'Segoe UI', Arial, sans-serif;
  `;

  overlay.innerHTML = `
    <div style="
      background:#0f172a; border:2px solid ${color}; border-radius:12px;
      padding:32px 40px; max-width:480px; width:90%; box-shadow:0 20px 60px rgba(0,0,0,0.5);
      color:#e2e8f0; text-align:center;
    ">
      <div style="font-size:42px; margin-bottom:12px;">${isBlock ? "🚫" : "⚠️"}</div>
      <h2 style="color:${color}; margin:0 0 10px; font-size:18px;">${title}</h2>
      <p style="color:#94a3b8; font-size:13px; margin:0 0 6px;">
        <strong style="color:#e2e8f0;">Pattern:</strong> ${result.top_pattern || "Unknown"}
        &nbsp;|&nbsp;
        <strong style="color:#e2e8f0;">Risk:</strong> ${result.risk_level}
      </p>
      ${result.regulations && result.regulations.length > 0 ? `
        <p style="color:#94a3b8; font-size:12px; margin:0 0 16px;">
          <strong style="color:#e2e8f0;">Regulations:</strong> ${result.regulations.join(", ")}
        </p>` : "<div style='margin-bottom:16px'></div>"}
      <p style="color:#cbd5e1; font-size:13px; line-height:1.5; margin:0 0 24px; text-align:left;
                background:#1e293b; padding:12px; border-radius:6px;">
        ${msg}
      </p>
      ${isBlock
        ? `<button id="ds-dismiss"
             style="background:#6366f1;color:white;border:none;padding:10px 28px;
                    border-radius:6px;cursor:pointer;font-size:14px;font-weight:bold;">
             OK – I understand
           </button>`
        : `<div style="display:flex;gap:10px;justify-content:center;">
             <button id="ds-cancel"
               style="background:#334155;color:#e2e8f0;border:none;padding:10px 24px;
                      border-radius:6px;cursor:pointer;font-size:13px;">
               Cancel send
             </button>
             <button id="ds-confirm"
               style="background:#f59e0b;color:#0f172a;border:none;padding:10px 24px;
                      border-radius:6px;cursor:pointer;font-size:14px;font-weight:bold;">
               Send anyway
             </button>
           </div>`
      }
      <p style="color:#475569; font-size:10px; margin:16px 0 0;">
        DataShield Enterprise DLP &nbsp;·&nbsp; Contact your IT admin if you need assistance
      </p>
    </div>
  `;

  document.body.appendChild(overlay);
  return overlay;
}

// ── Return a promise that resolves once user acts on the overlay ──────────────
function waitForUserDecision(overlay, isBlock) {
  return new Promise((resolve) => {
    if (isBlock) {
      overlay.querySelector("#ds-dismiss").addEventListener("click", () => {
        overlay.remove();
        resolve("blocked");
      });
    } else {
      overlay.querySelector("#ds-cancel").addEventListener("click", () => {
        overlay.remove();
        resolve("cancelled");
      });
      overlay.querySelector("#ds-confirm").addEventListener("click", () => {
        overlay.remove();
        resolve("confirmed");
      });
    }
  });
}

// ── Gmail email extractor ─────────────────────────────────────────────────────
function extractGmail() {
  const compose    = document.querySelector(".Am.Al.editable");
  const subject    = document.querySelector("input[name='subjectbox']")?.value || "";
  const body       = compose?.innerText || "";
  const toChips    = [...document.querySelectorAll(".vR span[email]")].map(s => s.getAttribute("email"));
  // Sender: logged-in account email shown in the account switcher
  const senderEl   = document.querySelector("[aria-label*='Google Account']") ||
                     document.querySelector(".gb_Cb") ||
                     document.querySelector("header [data-email]");
  const sender     = senderEl?.dataset?.email ||
                     document.querySelector("[data-ogsr-up] [data-email]")?.dataset?.email || "";
  return { subject, body, recipients: toChips.join(", "), sender };
}

// ── Outlook email extractor ───────────────────────────────────────────────────
function extractOutlook() {
  const subject  = document.querySelector("input[aria-label='Add a subject']")?.value
                || document.querySelector("._1Ixb")?.innerText || "";
  const body     = document.querySelector("[aria-label='Message body']")?.innerText
                || document.querySelector(".dFCbN")?.innerText || "";
  const toField  = document.querySelector("[aria-label='To']")?.innerText
                || document.querySelector("input[aria-label='To']")?.value || "";
  // Sender: the signed-in user's email shown in the top-right avatar/profile
  const sender   = document.querySelector("[data-testid='meControl-header-email']")?.textContent
                || document.querySelector("[aria-label*='account manager']")?.textContent?.trim() || "";
  return { subject, body, recipients: toField, sender };
}

// ── Detect current mail client ────────────────────────────────────────────────
function detectClient() {
  if (location.hostname === "mail.google.com") return "gmail";
  if (location.hostname.includes("outlook")) return "outlook";
  return null;
}

// ── Intercept send button ─────────────────────────────────────────────────────
async function interceptSend(event) {
  const client = detectClient();
  if (!client) return; // unknown client, don't interfere

  // Extract email content BEFORE the send fires
  const emailData = client === "gmail" ? extractGmail() : extractOutlook();
  if (!emailData.body && !emailData.subject) return; // empty compose, skip

  // Prevent send immediately while we check
  event.preventDefault();
  event.stopImmediatePropagation();

  // Call DataShield local HTTP server
  const result = await dsPost("/scan", emailData);

  // Server unreachable → fail open (let email send)
  if (!result) {
    console.warn("[DataShield] Local server unreachable – email allowed (fail-open).");
    // Re-trigger the send naturally by finding and clicking the real button
    triggerNativeSend(client);
    return;
  }

  const action = result.action; // "ALLOW" | "WARN" | "BLOCK"

  if (action === "ALLOW") {
    // Clean – re-trigger send
    await dsPost("/log_event", { ...emailData, action: "ALLOW", top_pattern: result.top_pattern });
    triggerNativeSend(client);
    return;
  }

  // WARN or BLOCK – show overlay
  const overlay = createOverlay(result);
  const decision = await waitForUserDecision(overlay, action === "BLOCK");

  if (decision === "confirmed") {
    // User chose to send despite warning
    await dsPost("/log_event", {
      ...emailData,
      action: "ALLOW",
      top_pattern: result.top_pattern,
      justification: "User confirmed send after WARN"
    });
    triggerNativeSend(client);
  } else {
    // Blocked or user cancelled
    await dsPost("/log_event", {
      ...emailData,
      action: "BLOCK",
      top_pattern: result.top_pattern,
      reason: action === "BLOCK" ? "DLP policy violation – BLOCK" : "User cancelled after WARN"
    });
    // Do nothing – email stays in draft
  }
}

// ── Trigger native send after we cleared our interception ─────────────────────
function triggerNativeSend(client) {
  if (client === "gmail") {
    // Click the actual send button but bypass our listener
    const btn = document.querySelector("[data-tooltip='Send ‪(Ctrl-Enter)‬'], [aria-label*='Send']");
    if (btn) {
      btn.removeEventListener("click", interceptSend, true);
      btn.click();
      setTimeout(() => btn.addEventListener("click", interceptSend, true), 500);
    }
  } else {
    // Outlook – dispatch keyboard shortcut Ctrl+Enter to trigger send
    document.activeElement?.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Enter", ctrlKey: true, bubbles: true })
    );
  }
}

// ── Attach send button listeners ──────────────────────────────────────────────
function attachListeners() {
  const client = detectClient();
  if (!client) return;

  // Gmail send button selectors (multiple fallbacks)
  const gmailSelectors = [
    "[data-tooltip='Send ‪(Ctrl-Enter)‬']",
    "[aria-label*='Send']",
    ".T-I.J-J5-Ji.aoO.v7.T-I-atl.L3",
  ];

  // Outlook send button selectors
  const outlookSelectors = [
    "[aria-label='Send']",
    "button[title='Send']",
    "._2MBoa",
  ];

  const selectors = client === "gmail" ? gmailSelectors : outlookSelectors;

  for (const sel of selectors) {
    document.querySelectorAll(sel).forEach(btn => {
      if (!btn.dataset.dsAttached) {
        btn.addEventListener("click", interceptSend, true);
        btn.dataset.dsAttached = "1";
      }
    });
  }
}

// ── MutationObserver: re-attach when compose windows open ─────────────────────
// Gmail and Outlook are SPAs – compose windows appear dynamically
const observer = new MutationObserver(() => attachListeners());
observer.observe(document.body, { childList: true, subtree: true });

// Initial attach
attachListeners();
console.log("[DataShield] DLP extension active on", location.hostname);
