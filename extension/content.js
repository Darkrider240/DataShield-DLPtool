// DataShield DLP — Gmail / Outlook Web content script
// Fail-open: if agent is offline, emails are allowed through with a soft warning

let isAllowedByDLP = false;
const SCAN_URL      = "http://localhost:5000/scan";
const ATTACH_URL    = "http://localhost:5000/scan_attachment";
const LOG_URL       = "http://localhost:5000/log_event";
const PING_URL      = "http://localhost:5000/ping";
const ME_URL        = "http://localhost:5000/me";
const OVERRIDE_URL  = "http://localhost:5000/request_override";
const TIMEOUT_MS    = 8000;
const MAX_RETRY     = 2;
const MAX_ATTACH_MB = 10;

// ── Override approval whitelist ───────────────────────────────────────────────
// Filenames are added here when admin approves an override request.
// Keys are lowercased filenames. Value = timestamp of approval (for expiry).
const _approvedFiles = new Map();  // filename.lower -> approvedAtMs
const APPROVAL_TTL_MS = 15 * 60 * 1000;  // whitelist expires after 15 min

function isApproved(filename) {
    const key = filename.toLowerCase();
    const ts  = _approvedFiles.get(key);
    if (!ts) return false;
    if (Date.now() - ts > APPROVAL_TTL_MS) { _approvedFiles.delete(key); return false; }
    return true;
}

// Listen for approval / denial decisions forwarded by the background worker
if (chrome?.runtime?.onMessage) {
    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.type !== "overrideDecision") return;
        const fname = msg.event_detail || "";
        if (msg.status === "APPROVED") {
            if (fname) _approvedFiles.set(fname.toLowerCase(), Date.now());
            const noteStr = msg.admin_note ? `\nAdmin: "${msg.admin_note}"` : "";
            showAttachToast(
                `✅ Override Approved${fname ? ` — "${truncate(fname, 22)}"` : ""}`,
                `You can now reattach and send the file.${noteStr}`,
                "#22c55e", 12000
            );
        } else if (msg.status === "DENIED") {
            showAttachToast(
                `❌ Override Denied${fname ? ` — "${truncate(fname, 22)}"` : ""}`,
                msg.admin_note || "Your request was not approved by the admin.",
                "#ef4444", 12000
            );
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
//  Attachment chip removal — filename-based polling (works across Gmail versions)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Poll the DOM every 300ms for up to 6s looking for an attachment chip that
 * contains `filename` and has a sibling/child remove button.
 * Clicks it if found. Falls back to a manual-removal toast if not.
 */
async function removeAttachmentChip(filename) {
    const basename = filename.replace(/\.[^.]+$/, "").toLowerCase();
    const maxWait  = 6000;   // ms
    const interval = 300;    // ms
    const waited   = { ms: 0 };

    while (waited.ms < maxWait) {
        await new Promise(r => setTimeout(r, interval));
        waited.ms += interval;

        const removeBtn = _findRemoveBtn(filename, basename);
        if (removeBtn) {
            removeBtn.click();
            // Verify removal after 600ms; if chip still there, click again
            await new Promise(r => setTimeout(r, 600));
            if (_findRemoveBtn(filename, basename)) {
                _findRemoveBtn(filename, basename)?.click();
            }
            return;
        }
    }

    // Automatic removal failed — instruct the user
    showAttachToast(
        `⚠️ Please remove "${truncate(filename, 22)}" manually`,
        "Click the ✕ next to the attachment chip to remove it from your email.",
        "#f59e0b", 12000
    );
}

function _findRemoveBtn(filename, basename) {
    // Remove-button selector patterns — ordered from most specific to broadest
    const REMOVE_PATTERNS = [
        // ARIA / title attributes (stable across Gmail redesigns)
        "[aria-label='Remove attachment']",
        "[aria-label='Remove']",
        "[title='Remove attachment']",
        "[title='Remove']",
        "[data-tooltip='Remove attachment']",
        // Image alt text
        "img[alt='Remove attachment']",
        "img[alt='Remove']",
        // Gmail-specific class names (observed in 2024-2025 builds)
        ".aZm",
        ".aWP",
        // Outlook Web Access
        "[data-testid='AttachmentRemoveButton']",
        "[class*='removeButton']",
        "[class*='deleteButton']",
    ];

    // Strategy 1: find remove button inside an element containing the filename
    for (const pattern of REMOVE_PATTERNS) {
        const btns = [...document.querySelectorAll(pattern)];
        for (const btn of btns) {
            let ancestor = btn.parentElement;
            for (let i = 0; i < 6; i++) {
                if (!ancestor) break;
                const text = (ancestor.textContent || "").toLowerCase();
                if (text.includes(basename)) return btn;
                ancestor = ancestor.parentElement;
            }
        }
    }

    // Strategy 2: find chip container by filename, then look for remove button inside
    const containers = document.querySelectorAll(
        "[role='listitem'], [role='option'], .aQjEt, .aZo, [class*='chip'], [class*='attachment']"
    );
    for (const c of containers) {
        const text = (c.textContent || "").toLowerCase();
        if (!text.includes(basename)) continue;
        for (const pattern of REMOVE_PATTERNS) {
            const btn = c.querySelector(pattern);
            if (btn) return btn;
        }
        const roleBtn = c.querySelector("[role='button']");
        if (roleBtn) return roleBtn;
    }

    return null;
}

// ─────────────────────────────────────────────────────────────────────────────
//  File input interception
//  Strategy: stop the change event BEFORE Gmail sees it → scan → re-dispatch
//  if clear, or block if sensitive. No chip removal needed because Gmail never
//  processes the blocked files at all.
// ─────────────────────────────────────────────────────────────────────────────
const _observedInputs  = new WeakSet();
const _passThroughInputs = new WeakMap(); // inputs flagged to skip on next change

function interceptFileInput(input) {
    if (_observedInputs.has(input)) return;
    _observedInputs.add(input);

    input.addEventListener("change", async function (e) {
        // ── If we re-dispatched this event ourselves, let Gmail handle it ──
        if (_passThroughInputs.has(input)) {
            _passThroughInputs.delete(input);
            return;   // Don't stop propagation — Gmail's listener fires normally
        }

        // ── STOP Gmail from seeing this event (capture phase fires first) ──
        e.stopImmediatePropagation();
        e.stopPropagation();

        const files = Array.from(input.files || []);
        if (!files.length) return;

        // Quick agent check
        const agentAlive = await pingAgent();
        if (!agentAlive) {
            showAttachToast("⚠️ DataShield offline",
                "Attachments sent without DLP scan. Start the agent to enable protection.", "#f59e0b");
            // Let Gmail handle it normally
            _passThroughInputs.set(input, true);
            input.dispatchEvent(new Event("change", { bubbles: true }));
            return;
        }

        const blockedFiles = [];
        const warnFiles    = [];
        const cleanFiles   = [];

        // Scan every file sequentially
        for (let i = 0; i < files.length; i++) {
            const file = files[i];

            // ── Override whitelist check ──────────────────────────────────────
            if (isApproved(file.name)) {
                showAttachToast(
                    `✅ ${truncate(file.name, 26)} — override active`,
                    "Sending as authorized by admin.",
                    "#22c55e", 4000
                );
                cleanFiles.push(file);
                continue;
            }

            if (file.size > MAX_ATTACH_MB * 1024 * 1024) {
                showAttachToast(`⚠️ ${truncate(file.name, 25)} skipped`,
                    `Over ${MAX_ATTACH_MB}MB — ensure no sensitive data.`, "#f59e0b");
                cleanFiles.push(file);
                continue;
            }

            const toastId = showAttachToast(
                `🔍 Scanning ${truncate(file.name, 26)}…`,
                files.length > 1 ? `File ${i + 1} of ${files.length}` : "Checking for sensitive data.",
                "#6366f1", 0
            );

            try {
                const form = new FormData();
                form.append("file", file, file.name);
                const resp = await fetch(ATTACH_URL, {
                    method: "POST", body: form,
                    signal: AbortSignal.timeout(TIMEOUT_MS),
                });
                dismissToast(toastId);

                if (!resp.ok) {
                    showAttachToast("⚠️ Scan error",
                        `Could not scan ${truncate(file.name, 22)}. Allowing with caution.`, "#f59e0b");
                    cleanFiles.push(file);
                    continue;
                }

                const data = await resp.json();
                data._filename = file.name;

                if (data.action === "BLOCK")      { blockedFiles.push(data); }
                else if (data.action === "WARN")   { warnFiles.push({ file, data }); }
                else {
                    showAttachToast(`✅ ${truncate(file.name, 26)} cleared`,
                        "No sensitive data detected.", "#22c55e");
                    cleanFiles.push(file);
                }

            } catch (err) {
                dismissToast(toastId);
                showAttachToast(`⚠️ ${truncate(file.name, 22)} — scan failed`,
                    err.name === "AbortError" ? "Timed out. Allowing with caution." : "Agent unreachable.",
                    "#f59e0b");
                cleanFiles.push(file);
            }
        }

        // ── Handle WARN: show modal, user decides per-file ────────────────────
        for (const { file, data } of warnFiles) {
            const userBlocked = await showAttachWarnModal(file.name, data);
            if (!userBlocked) cleanFiles.push(file);
            // if userBlocked: file simply doesn't go into cleanFiles → never uploaded
        }

        // ── Dispatch back to Gmail with only the safe files ───────────────────
        if (cleanFiles.length > 0) {
            try {
                const dt = new DataTransfer();
                cleanFiles.forEach(f => dt.items.add(f));
                input.files = dt.files;
            } catch (_) { /* DataTransfer not supported — keep original */ }
            _passThroughInputs.set(input, true);
            input.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
        } else {
            // All files blocked — clear the input completely
            try { input.value = ""; } catch (_) {}
        }

        // ── Show block modal if any were blocked ──────────────────────────────
        if (blockedFiles.length > 0) {
            const me = await fetchMe();
            showAttachBlockedModal(blockedFiles, me);

        } else if (warnFiles.length > 0) {
            // Show WARN modals one at a time
            for (const wd of warnFiles) {
                const userBlocked = await showAttachWarnModal(wd._filename, wd);
                if (userBlocked) {
                    removeAttachmentChip(wd._filename);  // try to remove chip
                }
            }
        } else {
            // All files clean — nothing to do
        }

    }, true);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Agent helpers
// ─────────────────────────────────────────────────────────────────────────────
async function pingAgent() {
    try {
        const r = await fetch(PING_URL, { method: "GET", signal: AbortSignal.timeout(2000) });
        return r.ok;
    } catch (_) { return false; }
}

async function fetchMe() {
    return new Promise((resolve) => {
        try {
            chrome.runtime.sendMessage({ type: "fetchMe" }, (resp) => {
                resolve(resp || { employee_id: "", email: "", name: "", server_url: "" });
            });
        } catch (_) {
            resolve({ employee_id: "", email: "", name: "", server_url: "" });
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
//  Block modal — supports 1 or multiple blocked files
// ─────────────────────────────────────────────────────────────────────────────
function showAttachBlockedModal(blockedFiles, me = {}) {
    document.getElementById("ds-attach-modal")?.remove();

    const count   = blockedFiles.length;
    const first   = blockedFiles[0];
    const heading = count === 1 ? escHtml(first._filename) : `${count} files blocked`;
    const subtitle = count === 1
        ? "This file has been removed from your email."
        : blockedFiles.map(f => escHtml(f._filename)).join(", ") + " — all removed.";
    const explanation = first.explanation ||
        `Policy violation: ${first.top_pattern || "sensitive data detected"}`;

    const overlay = document.createElement("div");
    overlay.id = "ds-attach-modal";
    overlay.style.cssText = `
        position:fixed; inset:0; background:rgba(15,23,42,0.9);
        backdrop-filter:blur(8px); z-index:200000;
        display:flex; align-items:center; justify-content:center;
        font-family:'Segoe UI',sans-serif;`;

    overlay.innerHTML = `
        <div style="background:#0f172a; width:530px; border:2px solid #ef4444;
                    border-radius:16px; overflow:hidden;
                    box-shadow:0 24px 60px rgba(0,0,0,0.8);
                    animation:dsSlideDown 0.25s ease-out;">

            <div style="background:#ef444420; padding:18px 22px;
                        border-bottom:1px solid #1e293b;
                        display:flex; align-items:flex-start; gap:12px;">
                <span style="font-size:26px; flex-shrink:0;">🛡</span>
                <div>
                    <div style="font-size:15px; font-weight:700; color:#ef4444;">
                        Attachment Blocked &amp; Removed
                    </div>
                    <div style="font-size:12px; color:#94a3b8; margin-top:3px; line-height:1.4;">
                        ${heading}<br>
                        <span style="font-size:11px; color:#64748b;">${subtitle}</span>
                    </div>
                </div>
            </div>

            <div style="padding:20px 22px;">
                <div style="background:#1e293b; padding:12px 14px; border-radius:8px;
                            font-size:12px; color:#cbd5e1; line-height:1.6;
                            border:1px solid #334155; margin-bottom:16px;
                            white-space:pre-wrap; max-height:100px; overflow-y:auto;">
                    ${escHtml(explanation)}
                </div>

                <div id="ds-override-wrap">
                    <div style="font-size:12px; font-weight:600; color:#94a3b8; margin-bottom:6px;">
                        Need to send this file? Request your admin's approval:
                    </div>
                    <textarea id="ds-override-just"
                        style="width:100%; height:60px; background:#1e293b; color:#f8fafc;
                               border:1px solid #334155; border-radius:6px; padding:8px;
                               font-size:13px; outline:none; resize:none; box-sizing:border-box;"
                        placeholder="Explain the business reason…"></textarea>
                    <div id="ds-override-msg"
                        style="font-size:11px; margin-top:5px; display:none;"></div>
                </div>

                <div style="display:flex; gap:10px; justify-content:flex-end; margin-top:14px;">
                    <button id="ds-override-btn"
                        style="background:#6366f122; color:#a5b4fc;
                               border:1px solid #6366f144;
                               padding:9px 16px; border-radius:8px;
                               font-weight:600; font-size:12px; cursor:pointer;">
                        📨 Request Override
                    </button>
                    <button id="ds-attach-ok"
                        style="background:#ef4444; color:#fff; border:none;
                               padding:9px 22px; border-radius:8px;
                               font-weight:700; font-size:13px; cursor:pointer;">
                        OK — Understood
                    </button>
                </div>
            </div>
        </div>
        <style>
            @keyframes dsSlideDown {
                from { transform:translateY(-20px); opacity:0; }
                to   { transform:translateY(0);     opacity:1; }
            }
            #ds-attach-ok:hover    { background:#dc2626 !important; }
            #ds-override-btn:hover { background:#6366f133 !important; }
        </style>`;

    document.body.appendChild(overlay);
    document.getElementById("ds-attach-ok").onclick = () => overlay.remove();

    document.getElementById("ds-override-btn").onclick = () => {
        const just  = document.getElementById("ds-override-just").value.trim();
        const msgEl = document.getElementById("ds-override-msg");
        if (!just) {
            document.getElementById("ds-override-just").style.border = "1px solid #ef4444";
            return;
        }
        const btn = document.getElementById("ds-override-btn");
        btn.textContent = "Submitting…";
        btn.disabled    = true;
        msgEl.style.display = "none";

        // Guard: chrome.runtime becomes undefined if the page wasn't refreshed
        // after the extension was reloaded. Show a clear message instead of crashing.
        if (!chrome?.runtime?.sendMessage) {
            msgEl.style.display = "block";
            msgEl.style.color   = "#f59e0b";
            msgEl.textContent   = "⚠️ Please refresh this Gmail tab (Ctrl+Shift+R) then try again.";
            btn.disabled    = false;
            btn.textContent = "📨 Request Override";
            return;
        }

        // Use background service worker — not subject to CORS restrictions
        chrome.runtime.sendMessage({
            type: "submitOverride",
            payload: {
                employee_id:   me.employee_id   || "",
                agent_id:      "",
                event_channel: "EMAIL ATTACH",
                event_detail:  first._filename  || "",
                pattern:       first.top_pattern || "",
                justification: just,
            },
        }, (result) => {
            msgEl.style.display = "block";
            if (chrome.runtime.lastError) {
                // Extension context invalidated — page needs refresh
                msgEl.style.color = "#f59e0b";
                msgEl.textContent = "⚠️ Please refresh this tab (Ctrl+Shift+R) and try again.";
                btn.disabled = false; btn.textContent = "📨 Request Override";
                return;
            }
            if (result?.ok) {
                msgEl.style.color = "#22c55e";
                msgEl.textContent = "✅ Request submitted — your admin will review it shortly.";
                document.getElementById("ds-override-wrap").style.opacity = "0.5";
                btn.style.display = "none";
            } else {
                msgEl.style.color = "#f87171";
                msgEl.textContent = `❌ ${result?.error || "Unknown error"}`;
                btn.disabled    = false;
                btn.textContent = "📨 Request Override";
            }
        });
    };   // end onclick
}        // end showAttachBlockedModal

// ─────────────────────────────────────────────────────────────────────────────
//  WARN modal
// ─────────────────────────────────────────────────────────────────────────────
function showAttachWarnModal(filename, data) {
    return new Promise((resolve) => {
        document.getElementById("ds-attach-warn")?.remove();
        const overlay = document.createElement("div");
        overlay.id = "ds-attach-warn";
        overlay.style.cssText = `
            position:fixed; inset:0; background:rgba(15,23,42,0.85);
            backdrop-filter:blur(8px); z-index:200001;
            display:flex; align-items:center; justify-content:center;
            font-family:'Segoe UI',sans-serif;`;
        overlay.innerHTML = `
            <div style="background:#0f172a; width:500px; border:2px solid #f59e0b;
                        border-radius:16px; overflow:hidden;
                        box-shadow:0 20px 50px rgba(0,0,0,0.7);">
                <div style="background:#f59e0b18; padding:18px 22px;
                            border-bottom:1px solid #1e293b;
                            display:flex; align-items:center; gap:10px;">
                    <span style="font-size:22px;">⚠️</span>
                    <div>
                        <div style="font-size:15px;font-weight:700;color:#f59e0b;">Attachment Warning</div>
                        <div style="font-size:12px;color:#94a3b8;margin-top:2px;">${escHtml(filename)}</div>
                    </div>
                </div>
                <div style="padding:20px 22px;">
                    <div style="background:#1e293b;padding:12px;border-radius:8px;
                                font-size:12px;color:#cbd5e1;line-height:1.6;
                                border:1px solid #334155;margin-bottom:14px;
                                white-space:pre-wrap;">
                        ${escHtml(data.explanation || "Potential policy violation detected.")}
                    </div>
                    <label style="display:block;font-size:12px;font-weight:600;
                                  color:#94a3b8;margin-bottom:6px;">
                        Business justification (required):
                    </label>
                    <textarea id="ds-warn-just"
                        style="width:100%;height:60px;background:#1e293b;color:#f8fafc;
                               border:1px solid #334155;border-radius:6px;padding:8px;
                               font-size:13px;outline:none;resize:none;box-sizing:border-box;"
                        placeholder="e.g. Authorised client billing transaction…"></textarea>
                    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:14px;">
                        <button id="ds-warn-cancel"
                            style="background:#ef444422;color:#f87171;
                                   border:1px solid #ef444444;padding:9px 18px;
                                   border-radius:8px;font-weight:600;font-size:13px;cursor:pointer;">
                            Remove Attachment
                        </button>
                        <button id="ds-warn-allow"
                            style="background:#f59e0b;color:#0f172a;border:none;
                                   padding:9px 18px;border-radius:8px;
                                   font-weight:600;font-size:13px;cursor:pointer;">
                            Attach Anyway
                        </button>
                    </div>
                </div>
            </div>`;
        document.body.appendChild(overlay);
        document.getElementById("ds-warn-cancel").onclick = () => { overlay.remove(); resolve(true); };
        document.getElementById("ds-warn-allow").onclick = () => {
            const j = document.getElementById("ds-warn-just").value.trim();
            if (!j) {
                document.getElementById("ds-warn-just").style.border = "1px solid #ef4444";
                return;
            }
            overlay.remove();
            resolve(false);
        };
    });
}

// ─────────────────────────────────────────────────────────────────────────────
//  MutationObserver — intercept file inputs added to DOM dynamically
// ─────────────────────────────────────────────────────────────────────────────
const _inputObserver = new MutationObserver((mutations) => {
    for (const m of mutations) {
        for (const node of m.addedNodes) {
            if (node.nodeType !== 1) continue;
            if (node.tagName === "INPUT" && node.type === "file") interceptFileInput(node);
            node.querySelectorAll?.("input[type='file']").forEach(interceptFileInput);
        }
    }
});
_inputObserver.observe(document.body, { childList: true, subtree: true });
document.querySelectorAll("input[type='file']").forEach(interceptFileInput);

// ─────────────────────────────────────────────────────────────────────────────
//  Email send-button interception (body scan)
// ─────────────────────────────────────────────────────────────────────────────
document.addEventListener("click", function (event) {
    const sendButton = findSendButton(event.target);
    if (!sendButton) return;
    if (isAllowedByDLP) { isAllowedByDLP = false; return; }
    event.preventDefault();
    event.stopPropagation();
    scanEmail(extractEmailContent(sendButton), sendButton);
}, true);

function findSendButton(target) {
    let el = target;
    while (el && el !== document.body) {
        if (el.getAttribute) {
            const label = (el.getAttribute("aria-label") || "").toLowerCase();
            const title = (el.getAttribute("title") || "").toLowerCase();
            if (label.startsWith("send") || title.startsWith("send") ||
                el.classList.contains("aoO")) return el;
        }
        el = el.parentElement;
    }
    return null;
}

function extractEmailContent(sendButton) {
    let subject = "No Subject", body = "", recipients = "Unknown";
    const area = sendButton.closest("div.M9") ||
                 sendButton.closest("div[role='region']") || document.body;
    const gmailSubject = area.querySelector("input[name='subjectbox']");
    const gmailBody    = area.querySelector("div[role='textbox'][aria-label='Message Body']");
    const gmailRecip   = area.querySelector("span.vR span[email]");
    const owaSubject   = area.querySelector("input[placeholder='Add a subject']");
    const owaBody      = area.querySelector("div[contenteditable='true']");
    if (gmailSubject) subject    = gmailSubject.value;
    else if (owaSubject) subject = owaSubject.value;
    if (gmailBody) body          = gmailBody.innerText || gmailBody.innerHTML;
    else if (owaBody) body       = owaBody.innerText   || owaBody.innerHTML;
    if (gmailRecip) recipients   = gmailRecip.getAttribute("email") || gmailRecip.innerText;
    return { subject, body, recipients };
}

async function scanEmail(emailData, sendButton) {
    showOverlayLoader();
    for (let i = 0; i < MAX_RETRY; i++) {
        try {
            const r = await fetch(SCAN_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(emailData),
                signal: AbortSignal.timeout(TIMEOUT_MS),
            });
            if (!r.ok) throw new Error(`${r.status}`);
            const data = await r.json();
            removeOverlayLoader();
            if (data.action === "ALLOW") { isAllowedByDLP = true; sendButton.click(); }
            else showDLPWarning(data, emailData, sendButton);
            return;
        } catch (err) {
            if (i < MAX_RETRY - 1) await new Promise(r => setTimeout(r, 600));
        }
    }
    removeOverlayLoader();
    showAgentOfflineToast();
    isAllowedByDLP = true;
    sendButton.click();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Toast / overlay helpers
// ─────────────────────────────────────────────────────────────────────────────
let _seq = 0;
function showAttachToast(title, body, color = "#6366f1", autoDismissMs = 5000) {
    const id = `ds-toast-${++_seq}`;
    const n  = document.querySelectorAll("[id^='ds-toast-']").length;
    const t  = document.createElement("div");
    t.id = id;
    t.style.cssText = `
        position:fixed; bottom:${24 + n * 90}px; right:24px; z-index:199999;
        background:#1e293b; border:1px solid ${color}; border-radius:10px;
        padding:12px 16px; color:#f8fafc; font-family:'Segoe UI',sans-serif;
        font-size:13px; box-shadow:0 8px 24px rgba(0,0,0,0.5);
        display:flex; align-items:flex-start; gap:10px; max-width:320px;
        animation:dsSlideIn 0.25s ease-out;`;
    t.innerHTML = `
        <div style="flex:1;">
            <div style="font-weight:700;color:${color};margin-bottom:3px;">${title}</div>
            <div style="color:#94a3b8;line-height:1.4;font-size:12px;">${body}</div>
        </div>
        <button onclick="document.getElementById('${id}')?.remove()"
            style="background:none;border:none;color:#64748b;font-size:15px;
                   cursor:pointer;padding:0;flex-shrink:0;line-height:1;">✕</button>
        <style>@keyframes dsSlideIn{from{transform:translateX(50px);opacity:0}to{opacity:1}}</style>`;
    document.body.appendChild(t);
    if (autoDismissMs > 0) setTimeout(() => t?.remove(), autoDismissMs);
    return id;
}
function dismissToast(id) { document.getElementById(id)?.remove(); }

function showAgentOfflineToast() {
    const t = document.createElement("div");
    t.style.cssText = `position:fixed;bottom:24px;right:24px;z-index:999999;
        background:#1e293b;border:1px solid #f59e0b;border-radius:10px;
        padding:14px 18px;color:#f8fafc;font-family:'Segoe UI',sans-serif;
        font-size:13px;box-shadow:0 8px 24px rgba(0,0,0,0.5);
        display:flex;align-items:flex-start;gap:12px;max-width:340px;`;
    t.innerHTML = `<span style="font-size:20px;">⚠️</span>
        <div><b style="color:#f59e0b;display:block;margin-bottom:4px;">DataShield Agent Offline</b>
        <span style="color:#94a3b8;">Email sent without DLP scan.</span></div>
        <button onclick="this.parentElement.remove()"
            style="background:none;border:none;color:#64748b;font-size:18px;cursor:pointer;margin-left:auto;">✕</button>`;
    document.body.appendChild(t);
    setTimeout(() => t?.remove(), 6000);
}

function showOverlayLoader() {
    const l = document.createElement("div");
    l.id = "datashield-loader";
    l.style.cssText = `position:fixed;top:0;left:0;width:100vw;height:100vh;
        background:rgba(15,23,42,0.7);backdrop-filter:blur(4px);
        z-index:100000;display:flex;align-items:center;justify-content:center;`;
    l.innerHTML = `<div style="text-align:center;background:#1e293b;border:1px solid #334155;
        padding:28px 36px;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,0.5);">
        <div style="border:4px solid #1e293b;border-top:4px solid #6366f1;border-radius:50%;
            width:40px;height:40px;animation:dsSpin 0.8s linear infinite;margin:0 auto 16px;"></div>
        <div style="font-weight:600;font-size:14px;color:#f8fafc;">DataShield scanning email…</div>
        <style>@keyframes dsSpin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}</style></div>`;
    document.body.appendChild(l);
}
function removeOverlayLoader() { document.getElementById("datashield-loader")?.remove(); }

function showDLPWarning(scanData, emailData, sendButton) {
    const overlay = document.createElement("div");
    overlay.id = "datashield-warning-overlay";
    overlay.style.cssText = `position:fixed;top:0;left:0;width:100vw;height:100vh;
        background:rgba(15,23,42,0.88);backdrop-filter:blur(8px);z-index:100001;
        display:flex;align-items:center;justify-content:center;
        font-family:'Segoe UI',sans-serif;color:#f8fafc;`;
    const isWarn = scanData.action === "WARN";
    const c      = isWarn ? "#f59e0b" : "#ef4444";
    const expl   = escHtml(scanData.explanation || `Policy violation: ${scanData.top_pattern}`);
    let html = `<div style="background:#0f172a;width:540px;border:2px solid ${c};
        border-radius:16px;box-shadow:0 20px 50px rgba(0,0,0,0.7);overflow:hidden;">
        <div style="background:${c}18;padding:20px 24px;border-bottom:1px solid #1e293b;
            display:flex;align-items:center;gap:12px;">
            <span style="font-size:26px;">${isWarn ? "⚠" : "🛡"}</span>
            <span style="font-size:17px;font-weight:700;color:${c};">
                ${isWarn ? "⚠ Outbound Data Warning" : "🛡 Outbound Data Blocked"}</span></div>
        <div style="padding:24px;">
            <div style="background:#1e293b;padding:14px;border-radius:8px;font-size:13px;
                margin-bottom:20px;line-height:1.6;color:#cbd5e1;border:1px solid #334155;
                white-space:pre-wrap;">${expl}</div>`;
    if (isWarn) {
        html += `<label style="display:block;font-size:12px;font-weight:600;color:#94a3b8;margin-bottom:8px;">
            Business justification:</label>
            <textarea id="ds-email-just" style="width:100%;height:68px;background:#1e293b;color:#f8fafc;
                border:1px solid #334155;border-radius:6px;padding:10px;font-size:13px;
                outline:none;resize:none;box-sizing:border-box;"
                placeholder="e.g. Authorised client billing transaction…"></textarea>
            <div style="display:flex;justify-content:space-between;margin-top:16px;">
                <button id="ds-btn-cancel" style="background:#ef444422;color:#f87171;
                    border:1px solid #ef444444;padding:10px 22px;border-radius:6px;
                    font-weight:600;cursor:pointer;">Cancel</button>
                <button id="ds-btn-send" style="background:#3b82f6;color:#fff;border:none;
                    padding:10px 22px;border-radius:6px;font-weight:600;cursor:pointer;">
                    Send Anyway</button></div>`;
    } else {
        html += `<div style="display:flex;justify-content:flex-end;">
            <button id="ds-btn-ok" style="background:#ef4444;color:#fff;border:none;
                padding:10px 26px;border-radius:6px;font-weight:600;cursor:pointer;">
                Dismiss</button></div>`;
    }
    html += `</div></div>`;
    overlay.innerHTML = html;
    document.body.appendChild(overlay);

    const logClose = (action, extra = {}) => fetch(LOG_URL, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, subject: emailData.subject,
            recipients: emailData.recipients, top_pattern: scanData.top_pattern, ...extra }),
    }).finally(() => overlay.remove());

    if (isWarn) {
        document.getElementById("ds-btn-send").onclick = () => {
            const j = (document.getElementById("ds-email-just").value || "").trim();
            if (!j) { alert("Please provide a justification."); return; }
            logClose("ALLOW", { justification: j });
            isAllowedByDLP = true; overlay.remove(); sendButton.click();
        };
        document.getElementById("ds-btn-cancel").onclick = () =>
            logClose("BLOCK", { reason: "Cancelled by user" });
    } else {
        document.getElementById("ds-btn-ok").onclick = () =>
            logClose("BLOCK", { reason: "Blocked by policy" });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Utilities
// ─────────────────────────────────────────────────────────────────────────────
function truncate(s, max) { return s.length > max ? s.slice(0, max - 1) + "…" : s; }
function escHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
