// DataShield DLP — Gmail / Outlook Web content script
// Behaviour when agent is offline: FAIL-OPEN (allow email through, show soft toast)

let isAllowedByDLP = false;
const SCAN_URL   = "http://localhost:5000/scan";
const LOG_URL    = "http://localhost:5000/log_event";
const TIMEOUT_MS = 4000;   // give the local server 4 s to respond
const MAX_RETRY  = 2;       // total attempts before failing-open

// ── Main capture listener ─────────────────────────────────────────────────────
document.addEventListener("click", function (event) {
    const sendButton = findSendButton(event.target);
    if (!sendButton) return;

    if (isAllowedByDLP) {
        isAllowedByDLP = false;
        return;
    }

    event.preventDefault();
    event.stopPropagation();

    const emailData = extractEmailContent(sendButton);
    scanEmail(emailData, sendButton);
}, true);

// ── Send-button detection ─────────────────────────────────────────────────────
function findSendButton(target) {
    let element = target;
    while (element && element !== document.body) {
        if (element.getAttribute) {
            const label = (element.getAttribute("aria-label") || "").toLowerCase();
            const title = (element.getAttribute("title") || "").toLowerCase();
            const role  = element.getAttribute("role") || "";
            if (label.startsWith("send") || title.startsWith("send") ||
                (role === "button" && label.startsWith("send")) ||
                element.classList.contains("aoO")) {
                return element;
            }
        }
        element = element.parentElement;
    }
    return null;
}

// ── Email content extraction ──────────────────────────────────────────────────
function extractEmailContent(sendButton) {
    let subject = "No Subject", body = "", recipients = "Unknown";
    const area = sendButton.closest("div.M9") ||
                 sendButton.closest("div[role='region']") ||
                 document.body;

    const gmailSubject = area.querySelector("input[name='subjectbox']");
    const gmailBody    = area.querySelector("div[role='textbox'][aria-label='Message Body']");
    const gmailRecip   = area.querySelector("span.vR span[email]");
    const owaSubject   = area.querySelector("input[placeholder='Add a subject']");
    const owaBody      = area.querySelector("div[role='textbox'][aria-label='Message body']") ||
                         area.querySelector("div[contenteditable='true']");

    if (gmailSubject) subject    = gmailSubject.value;
    else if (owaSubject) subject = owaSubject.value;
    if (gmailBody) body          = gmailBody.innerText || gmailBody.innerHTML;
    else if (owaBody) body       = owaBody.innerText || owaBody.innerHTML;
    if (gmailRecip) recipients   = gmailRecip.getAttribute("email") || gmailRecip.innerText;

    return { subject, body, recipients };
}

// ── Fetch with timeout helper ─────────────────────────────────────────────────
function fetchWithTimeout(url, options, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    return fetch(url, { ...options, signal: controller.signal })
        .finally(() => clearTimeout(timer));
}

// ── Main scan flow with retry ─────────────────────────────────────────────────
async function scanEmail(emailData, sendButton) {
    showOverlayLoader();

    let lastError = null;
    for (let attempt = 0; attempt < MAX_RETRY; attempt++) {
        try {
            const response = await fetchWithTimeout(SCAN_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(emailData)
            }, TIMEOUT_MS);

            if (!response.ok) throw new Error(`Server returned ${response.status}`);
            const data = await response.json();
            removeOverlayLoader();

            if (data.action === "ALLOW") {
                isAllowedByDLP = true;
                sendButton.click();
            } else {
                showDLPWarning(data, emailData, sendButton);
            }
            return; // success — exit retry loop

        } catch (err) {
            lastError = err;
            if (attempt < MAX_RETRY - 1) {
                await new Promise(r => setTimeout(r, 600)); // wait 600ms before retry
            }
        }
    }

    // All retries failed — FAIL-OPEN: allow email, show soft non-blocking toast
    removeOverlayLoader();
    console.warn("DataShield: agent offline, email allowed through.", lastError);
    showAgentOfflineToast();
    isAllowedByDLP = true;
    sendButton.click();
}

// ── Non-blocking agent-offline toast (no alert()) ────────────────────────────
function showAgentOfflineToast() {
    // Remove any previous toast
    const old = document.getElementById("datashield-offline-toast");
    if (old) old.remove();

    const toast = document.createElement("div");
    toast.id = "datashield-offline-toast";
    toast.style.cssText = `
        position: fixed; bottom: 24px; right: 24px; z-index: 999999;
        background: #1e293b; border: 1px solid #f59e0b; border-radius: 10px;
        padding: 14px 18px; color: #f8fafc; font-family: 'Segoe UI', sans-serif;
        font-size: 13px; box-shadow: 0 8px 24px rgba(0,0,0,0.5);
        display: flex; align-items: flex-start; gap: 12px; max-width: 340px;
        animation: dsSlideIn 0.3s ease-out;
    `;
    toast.innerHTML = `
        <span style="font-size:20px; flex-shrink:0;">⚠️</span>
        <div>
            <div style="font-weight:700; color:#f59e0b; margin-bottom:4px;">DataShield Agent Offline</div>
            <div style="color:#94a3b8; line-height:1.4;">
                Email sent without DLP scan.<br>
                Start the DataShield agent to enable protection.
            </div>
        </div>
        <button onclick="this.closest('#datashield-offline-toast').remove()"
            style="background:none; border:none; color:#64748b; font-size:18px;
                   cursor:pointer; padding:0; margin-left:auto; flex-shrink:0; line-height:1;">✕</button>
        <style>
            @keyframes dsSlideIn {
                from { transform: translateX(60px); opacity: 0; }
                to   { transform: translateX(0);    opacity: 1; }
            }
        </style>
    `;
    document.body.appendChild(toast);

    // Auto-dismiss after 6 seconds
    setTimeout(() => { if (toast.parentNode) toast.remove(); }, 6000);
}

// ── Scanning overlay ──────────────────────────────────────────────────────────
function showOverlayLoader() {
    const loader = document.createElement("div");
    loader.id = "datashield-loader";
    loader.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
        background: rgba(15,23,42,0.7); backdrop-filter: blur(4px);
        z-index: 100000; display: flex; align-items: center; justify-content: center;
        color: #f8fafc; font-family: 'Segoe UI', sans-serif;
    `;
    loader.innerHTML = `
        <div style="text-align:center; background:#1e293b; border:1px solid #334155;
                    padding:28px 36px; border-radius:14px; box-shadow:0 10px 30px rgba(0,0,0,0.5);">
            <div style="border:4px solid #1e293b; border-top:4px solid #6366f1;
                        border-radius:50%; width:40px; height:40px;
                        animation:dsSpin 0.8s linear infinite; margin:0 auto 16px;"></div>
            <div style="font-weight:600; font-size:14px;">DataShield scanning email…</div>
            <div style="font-size:11px; color:#64748b; margin-top:6px;">
                Checking for sensitive data
            </div>
        </div>
        <style>
            @keyframes dsSpin { 0%{transform:rotate(0deg)} 100%{transform:rotate(360deg)} }
        </style>
    `;
    document.body.appendChild(loader);
}

function removeOverlayLoader() {
    const loader = document.getElementById("datashield-loader");
    if (loader) loader.remove();
}

// ── DLP warning / block modal ─────────────────────────────────────────────────
function showDLPWarning(scanData, emailData, sendButton) {
    const overlay = document.createElement("div");
    overlay.id = "datashield-warning-overlay";
    overlay.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
        background: rgba(15,23,42,0.88); backdrop-filter: blur(8px);
        z-index: 100001; display: flex; align-items: center; justify-content: center;
        font-family: 'Segoe UI', sans-serif; color: #f8fafc;
    `;

    const isWarn      = scanData.action === "WARN";
    const titleColor  = isWarn ? "#f59e0b" : "#ef4444";
    const actionTitle = isWarn ? "⚠ Outbound Data Warning" : "🛡 Outbound Data Blocked";
    const explanation = scanData.explanation || `DLP Policy Violation: ${scanData.top_pattern} found.`;

    let html = `
        <div style="background:#0f172a; width:540px; border:2px solid ${titleColor};
                    border-radius:16px; box-shadow:0 20px 50px rgba(0,0,0,0.7);
                    overflow:hidden; animation:dsSlideDown 0.3s ease-out;">
            <div style="background:${titleColor}18; padding:20px 24px;
                        border-bottom:1px solid #1e293b; display:flex; align-items:center; gap:12px;">
                <span style="font-size:26px;">${isWarn ? '⚠' : '🛡'}</span>
                <span style="font-size:18px; font-weight:700; color:${titleColor};">${actionTitle}</span>
            </div>
            <div style="padding:24px;">
                <div style="background:#1e293b; padding:14px; border-radius:8px;
                            font-size:13px; margin-bottom:20px; line-height:1.6;
                            color:#cbd5e1; border:1px solid #334155; white-space:pre-wrap;">${explanation}</div>
    `;

    if (isWarn) {
        html += `
                <label style="display:block; font-size:12px; font-weight:600;
                              color:#94a3b8; margin-bottom:8px;">
                    Business justification required to send anyway:
                </label>
                <textarea id="datashield-justification"
                    style="width:100%; height:72px; background:#1e293b; color:#f8fafc;
                           border:1px solid #334155; border-radius:6px; padding:10px;
                           font-size:13px; outline:none; resize:none; box-sizing:border-box;"
                    placeholder="e.g. Authorised client billing transaction…"></textarea>
                <div style="display:flex; justify-content:space-between; margin-top:16px;">
                    <button id="ds-btn-cancel"
                        style="background:#ef444422; color:#f87171; border:1px solid #ef444444;
                               padding:10px 22px; border-radius:6px; font-weight:600; cursor:pointer;">
                        Cancel
                    </button>
                    <button id="ds-btn-send"
                        style="background:#3b82f6; color:#fff; border:none;
                               padding:10px 22px; border-radius:6px; font-weight:600; cursor:pointer;">
                        Send Anyway
                    </button>
                </div>
        `;
    } else {
        html += `
                <div style="display:flex; justify-content:flex-end; margin-top:8px;">
                    <button id="ds-btn-ok"
                        style="background:#ef4444; color:#fff; border:none;
                               padding:10px 26px; border-radius:6px; font-weight:600; cursor:pointer;">
                        Dismiss
                    </button>
                </div>
        `;
    }

    html += `
            </div>
        </div>
        <style>
            @keyframes dsSlideDown {
                from { transform:translateY(-24px); opacity:0; }
                to   { transform:translateY(0);     opacity:1; }
            }
            #ds-btn-send:hover  { background:#2563eb !important; }
            #ds-btn-cancel:hover{ background:#ef444433 !important; }
            #ds-btn-ok:hover    { background:#dc2626 !important; }
        </style>
    `;

    overlay.innerHTML = html;
    document.body.appendChild(overlay);

    const logAndClose = (action, extra = {}) => {
        fetchWithTimeout(LOG_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                action,
                subject: emailData.subject,
                recipients: emailData.recipients,
                top_pattern: scanData.top_pattern,
                ...extra
            })
        }, 3000).finally(() => overlay.remove());
    };

    if (isWarn) {
        document.getElementById("ds-btn-send").addEventListener("click", () => {
            const j = (document.getElementById("datashield-justification").value || "").trim();
            if (!j) { alert("Please provide a justification."); return; }
            logAndClose("ALLOW", { justification: j });
            isAllowedByDLP = true;
            overlay.remove();
            sendButton.click();
        });
        document.getElementById("ds-btn-cancel").addEventListener("click", () => {
            logAndClose("BLOCK", { reason: "Cancelled by user" });
        });
    } else {
        document.getElementById("ds-btn-ok").addEventListener("click", () => {
            logAndClose("BLOCK", { reason: "Blocked by hard compliance rules" });
        });
    }
}
