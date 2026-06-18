// Flag to track if the email has passed the DLP check
let isAllowedByDLP = false;

// Listen for clicks on the document to catch compose Send button clicks dynamically
document.addEventListener("click", function (event) {
    // Find if the clicked element (or its parent) is the Send button
    const sendButton = findSendButton(event.target);
    if (!sendButton) return;

    // If DLP has already approved this send action, let the event go through
    if (isAllowedByDLP) {
        isAllowedByDLP = false; // reset
        return;
    }

    // Intercept outbound send
    event.preventDefault();
    event.stopPropagation();

    // Extract content
    const emailData = extractEmailContent(sendButton);
    
    // Call local scan server
    scanEmail(emailData, sendButton);
}, true); // Use capture phase to intercept before Gmail/Outlook event handlers fire

function findSendButton(target) {
    // Gmail selectors: div[aria-label^="Send"], div.T-I.J-J5-Ji.aoO.v7.T-I-atl.L3
    // Outlook OWA selectors: button[title^="Send"], button[aria-label^="Send"], div[role="button"][aria-label^="Send"]
    let element = target;
    while (element && element !== document.body) {
        if (element.getAttribute) {
            const label = element.getAttribute("aria-label") || "";
            const title = element.getAttribute("title") || "";
            const role = element.getAttribute("role") || "";
            
            if (label.toLowerCase().startsWith("send") || 
                title.toLowerCase().startsWith("send") || 
                (role === "button" && label.toLowerCase().startsWith("send")) ||
                element.classList.contains("aoO")) {
                return element;
            }
        }
        element = element.parentElement;
    }
    return null;
}

function extractEmailContent(sendButton) {
    let subject = "No Subject";
    let body = "";
    let recipients = "Unknown Recipients";

    // 1. Identify compose container
    const composeArea = sendButton.closest("div.M9") || sendButton.closest("div[role='region']") || document.body;

    // 2. Selectors for Gmail
    const gmailSubject = composeArea.querySelector("input[name='subjectbox']");
    const gmailBody = composeArea.querySelector("div[role='textbox'][aria-label='Message Body']");
    const gmailRecip = composeArea.querySelector("span.vR span[email]");

    // 3. Selectors for Outlook Web
    const owaSubject = composeArea.querySelector("input[placeholder='Add a subject']");
    const owaBody = composeArea.querySelector("div[role='textbox'][aria-label='Message body']") || composeArea.querySelector("div[contenteditable='true']");
    
    if (gmailSubject) subject = gmailSubject.value;
    else if (owaSubject) subject = owaSubject.value;

    if (gmailBody) body = gmailBody.innerText || gmailBody.innerHTML;
    else if (owaBody) body = owaBody.innerText || owaBody.innerHTML;

    if (gmailRecip) {
        recipients = gmailRecip.getAttribute("email") || gmailRecip.innerText;
    } else {
        // Fallback search in compose fields
        const recipField = composeArea.querySelector("div.placeholder[text='To']") || composeArea.querySelector("span.rP");
        if (recipField) recipients = recipField.innerText;
    }

    return { subject, body, recipients };
}

function scanEmail(emailData, sendButton) {
    showOverlayLoader();

    fetch("http://localhost:5000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(emailData)
    })
    .then(response => {
        if (!response.ok) throw new Error("HTTP scan server error");
        return response.json();
    })
    .then(data => {
        removeOverlayLoader();
        if (data.action === "ALLOW") {
            // Let the send happen
            isAllowedByDLP = true;
            sendButton.click();
        } else {
            // Render warning modal
            showDLPWarning(data, emailData, sendButton);
        }
    })
    .catch(error => {
        removeOverlayLoader();
        console.error("DataShield DLP Scan error:", error);
        // Default to block on connection failure to be safe
        alert("DataShield DLP Connection Error:\nLocal API server is not running on port 5000. Outgoing email blocked.");
    });
}

function showOverlayLoader() {
    const loader = document.createElement("div");
    loader.id = "datashield-loader";
    loader.style = `
        position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
        background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(4px);
        z-index: 100000; display: flex; align-items: center; justify-content: center;
        color: #f8fafc; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    `;
    loader.innerHTML = `
        <div style="text-align: center; background: #1e293b; border: 1px solid #334155; padding: 25px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
            <div style="border: 4px solid #f3f3f3; border-top: 4px solid #3b82f6; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 15px;"></div>
            <div style="font-weight: 600;">DataShield DLP scanning email...</div>
        </div>
        <style>
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        </style>
    `;
    document.body.appendChild(loader);
}

function removeOverlayLoader() {
    const loader = document.getElementById("datashield-loader");
    if (loader) loader.remove();
}

function showDLPWarning(scanData, emailData, sendButton) {
    const overlay = document.createElement("div");
    overlay.id = "datashield-warning-overlay";
    overlay.style = `
        position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
        background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(8px);
        z-index: 100001; display: flex; align-items: center; justify-content: center;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #f8fafc;
    `;

    const isWarn = scanData.action === "WARN";
    const titleColor = isWarn ? "#f59e0b" : "#ef4444";
    const actionTitle = isWarn ? "⚠ Outbound Data Warning" : "❌ Outbound Data Blocked";
    
    // Split explanation for formatting
    const explanationText = scanData.explanation || `DLP Policy Violation: ${scanData.top_pattern} found.`;
    
    let modalHTML = `
        <div style="background: #0f172a; width: 520px; border: 2px solid ${titleColor}; border-radius: 16px; box-shadow: 0 20px 40px rgba(0,0,0,0.6); overflow: hidden; animation: slideIn 0.3s ease-out;">
            <div style="background: ${titleColor}15; padding: 20px; border-bottom: 1px solid #1e293b; display: flex; align-items: center; gap: 10px;">
                <span style="font-size: 24px; color: ${titleColor}; font-weight: bold;">${isWarn ? '⚠' : '🛡'}</span>
                <span style="font-size: 18px; font-weight: 700; color: ${titleColor};">${actionTitle}</span>
            </div>
            
            <div style="padding: 25px;">
                <div style="background: #1e293b; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 13px; margin-bottom: 20px; line-height: 1.5; color: #cbd5e1; border: 1px solid #334155; white-space: pre-wrap;">${explanationText}</div>
    `;

    if (isWarn) {
        modalHTML += `
                <div style="margin-bottom: 20px;">
                    <label style="display: block; font-size: 13px; font-weight: 600; color: #94a3b8; margin-bottom: 8px;">A business justification is required to send this email anyway:</label>
                    <textarea id="datashield-justification" style="width: 100%; height: 80px; background: #1e293b; color: #f8fafc; border: 1px solid #334155; border-radius: 6px; padding: 10px; font-size: 14px; outline: none; resize: none; font-family: sans-serif;" placeholder="Provide justification (e.g., Authorized client billing transaction)..."></textarea>
                </div>
                
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <button id="datashield-btn-cancel" style="background: #ef4444; color: #ffffff; border: none; padding: 10px 20px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: background 0.2s;">Cancel Email</button>
                    <button id="datashield-btn-send" style="background: #3b82f6; color: #ffffff; border: none; padding: 10px 20px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: background 0.2s;">Send Anyway</button>
                </div>
        `;
    } else {
        modalHTML += `
                <div style="display: flex; justify-content: flex-end;">
                    <button id="datashield-btn-ok" style="background: #ef4444; color: #ffffff; border: none; padding: 10px 25px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: background 0.2s;">Dismiss</button>
                </div>
        `;
    }

    modalHTML += `
            </div>
        </div>
        <style>
            @keyframes slideIn { from { transform: translateY(-30px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
            #datashield-btn-send:hover { background: #2563eb !important; }
            #datashield-btn-cancel:hover { background: #dc2626 !important; }
            #datashield-btn-ok:hover { background: #dc2626 !important; }
        </style>
    `;

    overlay.innerHTML = modalHTML;
    document.body.appendChild(overlay);

    // Event hooks inside warning dialog
    if (isWarn) {
        document.getElementById("datashield-btn-send").addEventListener("click", () => {
            const justificationBox = document.getElementById("datashield-justification");
            const justification = justificationBox.value.strip ? justificationBox.value.strip() : justificationBox.value.trim();
            if (!justification) {
                alert("Justification is required to bypass this warning.");
                return;
            }
            
            // Log justification to Python backend
            fetch("http://localhost:5000/log_event", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    action: "ALLOW",
                    subject: emailData.subject,
                    recipients: emailData.recipients,
                    top_pattern: scanData.top_pattern,
                    justification: justification
                })
            }).finally(() => {
                isAllowedByDLP = true;
                overlay.remove();
                sendButton.click(); // Dispatch email
            });
        });

        document.getElementById("datashield-btn-cancel").addEventListener("click", () => {
            fetch("http://localhost:5000/log_event", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    action: "BLOCK",
                    subject: emailData.subject,
                    recipients: emailData.recipients,
                    top_pattern: scanData.top_pattern,
                    reason: "Warning cancelled by user"
                })
            }).finally(() => {
                overlay.remove();
            });
        });
    } else {
        document.getElementById("datashield-btn-ok").addEventListener("click", () => {
            fetch("http://localhost:5000/log_event", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    action: "BLOCK",
                    subject: emailData.subject,
                    recipients: emailData.recipients,
                    top_pattern: scanData.top_pattern,
                    reason: "Blocked by hard compliance rules"
                })
            }).finally(() => {
                overlay.remove();
            });
        });
    }
}
