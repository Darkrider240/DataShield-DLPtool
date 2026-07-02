// DataShield — Background Service Worker
// Background workers are NOT subject to CORS restrictions.
// The content script sends messages here; we make the actual HTTP requests.

// ── Override approval polling ──────────────────────────────────────────────────
// After an override is submitted, poll the server every 8 seconds until
// a decision (APPROVED / DENIED) comes back, then forward it to the tab.
let _poll = null;  // { timerId, employeeId, tabId }

function startApprovalPolling(employeeId, tabId) {
    stopApprovalPolling();  // clear any previous poll
    console.log(`[DataShield BG] Polling for override decision (employee=${employeeId} tab=${tabId})`);
    _poll = {
        employeeId,
        tabId,
        timerId: setInterval(() => checkDecisions(employeeId, tabId), 8000),
    };
}

function stopApprovalPolling() {
    if (_poll?.timerId) clearInterval(_poll.timerId);
    _poll = null;
}

async function checkDecisions(employeeId, tabId) {
    if (!employeeId) return;
    const url = `http://localhost:8001/api/overrides/my-notifications?employee_id=${encodeURIComponent(employeeId)}`;
    try {
        const resp = await fetch(url, { signal: AbortSignal.timeout(5000) });
        if (!resp.ok) return;
        const notifications = await resp.json();
        if (!notifications?.length) return;

        // Forward each decision to the content script
        for (const n of notifications) {
            try {
                await chrome.tabs.sendMessage(tabId, { type: "overrideDecision", ...n });
            } catch (err) {
                console.warn("[DataShield BG] Could not reach tab:", err.message);
            }
        }
        // Stop polling once we've delivered decisions
        stopApprovalPolling();
    } catch (err) {
        console.warn("[DataShield BG] Poll error:", err.message);
    }
}

// ── Message handler ────────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "submitOverride") {
        handleOverride(msg.payload, sender.tab?.id).then(sendResponse);
        return true;
    }
    if (msg.type === "fetchMe") {
        handleFetchMe().then(sendResponse);
        return true;
    }
});

// ── Submit override request ────────────────────────────────────────────────────
async function handleOverride(payload, tabId) {
    const ENDPOINTS = [
        "http://localhost:5000/request_override",
        "http://localhost:8001/api/overrides",
    ];

    let lastErr = "";
    for (const url of ENDPOINTS) {
        try {
            const resp = await fetch(url, {
                method:  "POST",
                headers: { "Content-Type": "application/json" },
                body:    JSON.stringify(payload),
                signal:  AbortSignal.timeout(8000),
            });

            if (resp.ok) {
                // Start polling so we can notify the tab when admin decides
                if (payload.employee_id && tabId) {
                    startApprovalPolling(payload.employee_id, tabId);
                }
                return { ok: true };
            }
            let detail = `HTTP ${resp.status}`;
            try { const j = await resp.json(); detail = j.detail || j.error || detail; } catch (_) {}
            lastErr = detail;
            console.warn(`[DataShield BG] Override ${url} → ${detail}`);

        } catch (err) {
            lastErr = err.name === "AbortError" ? "Timed out" : err.message;
            console.warn(`[DataShield BG] Override ${url} failed: ${lastErr}`);
        }
    }
    return { ok: false, error: lastErr };
}

// ── Fetch current employee identity from the agent ─────────────────────────────
async function handleFetchMe() {
    try {
        const resp = await fetch("http://localhost:5000/me", {
            signal: AbortSignal.timeout(3000),
        });
        if (resp.ok) return await resp.json();
    } catch (_) {}
    return { employee_id: "", email: "", name: "", server_url: "" };
}
