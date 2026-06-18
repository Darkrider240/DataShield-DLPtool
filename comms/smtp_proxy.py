import os
import sys
import asyncio
import threading
import tempfile
import email
from pathlib import Path
from email.parser import BytesParser
from aiosmtpd.controller import Controller
import aiosmtplib
import tkinter as tk
from tkinter import ttk, messagebox

# DataShield components
import scanner
import behaviour
import classifier
import comms.comms_engine as comms_engine

class DataShieldSMTPHandler:
    def __init__(self, state, on_event_callback=None):
        self.state = state  # Shared app state (contains policy manager, audit logger, etc.)
        self.on_event_callback = on_event_callback  # Callback to log to GUI Tab

    async def handle_DATA(self, server, session, envelope):
        """Processes and scans every intercepted outbound email."""
        # 1. Parse raw email content
        try:
            msg = email.message_from_bytes(envelope.content)
        except Exception as e:
            print(f"Warning: Failed to parse raw email body: {e}", file=sys.stderr)
            return '500 Error: failed to parse mail content'

        subject = msg.get("Subject", "No Subject")
        sender = envelope.mail_from
        recipients = envelope.rcpt_tos
        recipients_str = ", ".join(recipients)

        body_parts = []
        attachments = []

        # Extract textual bodies and attachment content
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = part.get("Content-Disposition", "")
                
                # Check for body content
                if content_type == "text/plain" and "attachment" not in disposition:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_parts.append(payload.decode("utf-8", errors="replace"))
                # Check for attachments
                elif "attachment" in disposition or part.get_filename():
                    filename = part.get_filename() or "attachment"
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            attachments.append((filename, payload.decode("utf-8", errors="replace")))
                        except Exception:
                            # Skip binary non-text attachment decoding
                            attachments.append((filename, "[Binary content skipped]"))
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body_parts.append(payload.decode("utf-8", errors="replace"))

        body_text = "\n".join(body_parts)
        attachments_text = "\n".join([f"Attachment: {name}\n{content}" for name, content in attachments])
        
        # Combine all parts into a single string for scanning
        full_scan_text = f"Subject: {subject}\nBody:\n{body_text}\nAttachments:\n{attachments_text}"

        # 2. Write content to a temporary file
        # Use cross-platform temp directory
        if os.name == "nt":
            temp_dir = Path("C:\\Temp\\datashield_scan") if os.path.exists("C:\\") else Path(tempfile.gettempdir()) / "datashield_scan"
        else:
            temp_dir = Path("/tmp/datashield_scan")

        try:
            temp_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=str(temp_dir), delete=False, suffix=".txt", mode="w", encoding="utf-8") as f:
                f.write(full_scan_text)
                temp_file_path = f.name
        except Exception as e:
            print(f"Error: Failed to create temporary scan file: {e}", file=sys.stderr)
            return '500 Error: local scanner storage issue'

        # 3. Perform scan and classification
        try:
            config = {
                "root_path": str(temp_dir),
                "policy_manager": self.state.get("policy_manager")
            }
            matches = scanner.scan_file(temp_file_path, config)
            matches = behaviour.proximity_multiplier(matches)
            classification = classifier.classify_file(matches, file_path=temp_file_path)
        except Exception as e:
            print(f"Error: Scan exception during SMTP intercept: {e}", file=sys.stderr)
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
            return '500 Error: internal scan failure'

        # Retrieve AI explanations if enabled
        enable_ai = self.state.get("enable_ai", True)
        decision = comms_engine.decide(
            classification, channel="EMAIL", 
            audit_logger=self.state["audit_logger"], explain=enable_ai,
            api_key=self.state.get("gemini_api_key")
        )

        # 4. Handle Decisions
        # Clean up temp file immediately after scan
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

        # UI callback to log events to the GUI
        if self.on_event_callback:
            pattern_info = decision.top_pattern if classification["top_matches"] else "CLEAN"
            self.on_event_callback("EMAIL", decision.action, f"{pattern_info} in email to {recipients_str}", decision=decision)

        if decision.action == "BLOCK":
            # Log action
            self.state["audit_logger"].log("EMAIL_BLOCKED", {
                "subject": subject,
                "sender": sender,
                "recipients": recipients,
                "top_pattern": decision.top_pattern,
                "risk_score": decision.risk_score
            })
            
            # Show non-blocking popup using GUI thread
            root = self.state.get("root_window")
            if root:
                alert_msg = comms_engine.format_warning_message(decision)
                root.after(0, lambda: messagebox.showerror("DataShield DLP Blocking", alert_msg))
                
            return '550 DataShield: message blocked — sensitive data detected'

        elif decision.action == "WARN":
            # If user disabled justification bypass in settings, treat WARN as BLOCK
            if not self.state.get("enable_justification_bypass", True):
                self.state["audit_logger"].log("EMAIL_BLOCKED", {
                    "subject": subject,
                    "sender": sender,
                    "recipients": recipients,
                    "top_pattern": decision.top_pattern,
                    "risk_score": decision.risk_score,
                    "reason": "Warning triggered with justification bypass disabled"
                })
                root = self.state.get("root_window")
                if root:
                    alert_msg = comms_engine.format_warning_message(decision)
                    root.after(0, lambda: messagebox.showerror("DataShield DLP Rejection", alert_msg))
                return '550 DataShield: message blocked — sensitive data detected'

            # Blocking justification dialog via thread synchronization
            sync_event = threading.Event()
            justification = [""]
            cancelled = [False]

            def show_justification_dialog():
                root = self.state.get("root_window")
                if not root:
                    sync_event.set()
                    return

                # Build a Toplevel dialog window
                dialog = tk.Toplevel(root)
                dialog.title("DataShield DLP — Business Justification")
                dialog.geometry("500x320")
                dialog.resizable(False, False)
                dialog.configure(background="#0f172a")
                dialog.transient(root)
                dialog.grab_set()

                # Style labels
                style_lbl = {"bg": "#0f172a", "fg": "#f8fafc", "font": ("Segoe UI", 10)}
                
                title_lbl = tk.Label(
                    dialog, 
                    text=f"⚠ DataShield Alert — Outbound Email Contain Sensitive Data\n"
                         f"Framework violation: {', '.join(decision.regulation_tags)}\n"
                         f"Pattern detected: {decision.top_pattern}",
                    bg="#0f172a", fg="#f59e0b", font=("Segoe UI", 10, "bold"), justify="left", wraplength=460
                )
                title_lbl.pack(pady=15, padx=15, anchor="w")

                prompt_lbl = tk.Label(
                    dialog, text="Provide a business justification to proceed with sending this email:",
                    **style_lbl
                )
                prompt_lbl.pack(pady=(0, 5), padx=15, anchor="w")

                entry_box = tk.Text(
                    dialog, height=5, background="#1e293b", foreground="#f8fafc",
                    insertbackground="white", font=("Consolas", 10), wrap="word", borderwidth=1
                )
                entry_box.pack(padx=15, fill="x", pady=5)
                entry_box.focus_set()

                btn_frame = ttk.Frame(dialog)
                btn_frame.pack(fill="x", pady=15, padx=15)

                def on_send():
                    txt = entry_box.get("1.0", "end").strip()
                    if not txt:
                        messagebox.showwarning("Input Required", "Please enter a valid justification or click Cancel.", parent=dialog)
                        return
                    justification[0] = txt
                    dialog.destroy()
                    sync_event.set()

                def on_cancel():
                    cancelled[0] = True
                    dialog.destroy()
                    sync_event.set()

                # Intercept window manager close event
                dialog.protocol("WM_DELETE_WINDOW", on_cancel)

                btn_send = ttk.Button(btn_frame, text="Send Anyway", command=on_send)
                btn_send.pack(side="left", padx=5)

                btn_cancel = ttk.Button(btn_frame, text="Cancel Email", command=on_cancel)
                btn_cancel.pack(side="right", padx=5)

            # Invoke dialog on main GUI thread
            root = self.state.get("root_window")
            if root:
                root.after(0, show_justification_dialog)
                # Wait for user input to release this SMTP handler thread
                sync_event.wait()
            else:
                cancelled[0] = True  # If GUI isn't running, default to block

            if cancelled[0]:
                self.state["audit_logger"].log("EMAIL_BLOCKED", {
                    "subject": subject,
                    "sender": sender,
                    "recipients": recipients,
                    "top_pattern": decision.top_pattern,
                    "reason": "Warning cancelled by user"
                })
                return '550 DataShield: message blocked — sensitive data detected'

            # Relay with justification override
            relay_success = await self.relay_email(envelope)
            if relay_success:
                self.state["audit_logger"].log("EMAIL_ALLOWED", {
                    "subject": subject,
                    "sender": sender,
                    "recipients": recipients,
                    "top_pattern": decision.top_pattern,
                    "justification": justification[0]
                })
                return '250 OK'
            else:
                return '554 Outbound relay configuration failure'

        else:  # ALLOW
            relay_success = await self.relay_email(envelope)
            if relay_success:
                self.state["audit_logger"].log("EMAIL_ALLOWED", {
                    "subject": subject,
                    "sender": sender,
                    "recipients": recipients,
                    "top_pattern": decision.top_pattern
                })
                return '250 OK'
            else:
                return '554 Outbound relay configuration failure'

    async def relay_email(self, envelope) -> bool:
        """Relays the raw email envelope to the real configured SMTP server."""
        smtp_cfg = self.state.get("smtp_config", {})
        host = smtp_cfg.get("host")
        port = smtp_cfg.get("port")
        
        if not host or not port:
            print("Warning: Email relay blocked. Outbound SMTP server is not configured in settings.", file=sys.stderr)
            return False

        try:
            port_val = int(port)
            user = smtp_cfg.get("username")
            pw = smtp_cfg.get("password")

            # Relay transaction using aiosmtplib
            if user and pw:
                await aiosmtplib.send(
                    envelope.content,
                    sender=envelope.mail_from,
                    recipients=envelope.rcpt_tos,
                    hostname=host,
                    port=port_val,
                    username=user,
                    password=pw,
                    timeout=15
                )
            else:
                await aiosmtplib.send(
                    envelope.content,
                    sender=envelope.mail_from,
                    recipients=envelope.rcpt_tos,
                    hostname=host,
                    port=port_val,
                    timeout=15
                )
            return True
        except Exception as e:
            print(f"Warning: Failed to relay message to outbound SMTP: {e}", file=sys.stderr)
            return False


class DataShieldSMTPProxy:
    """Manages start/stop of the SMTP controller wrapper."""
    def __init__(self, state, host="127.0.0.1", port=1025, on_event_callback=None):
        self.state = state
        self.host = host
        self.port = port
        handler = DataShieldSMTPHandler(state, on_event_callback)
        self.controller = Controller(handler, hostname=self.host, port=self.port)

    def start(self):
        """Starts aiosmtpd proxy in its own background thread loop."""
        self.controller.start()

    def stop(self):
        """Stops proxy loop."""
        self.controller.stop()


def start_smtp_proxy(real_smtp_host: str, real_smtp_port: int, proxy_port: int = 1025):
    """
    Start the aiosmtpd proxy in a background asyncio event loop thread.
    Call this from main.py on startup when comms DLP is enabled in settings.
    """
    from audit import AuditLogger
    from policy import PolicyManager
    
    base_dir = Path(__file__).resolve().parent.parent
    audit_path = base_dir / "output" / "datashield_audit.log"
    default_rules = base_dir / "rules" / "default_rules.yaml"
    allowlist = base_dir / "rules" / "allowlist.yaml"
    
    state = {
        "audit_logger": AuditLogger(str(audit_path)),
        "policy_manager": PolicyManager(str(default_rules), str(allowlist)),
        "smtp_config": {
            "host": real_smtp_host,
            "port": real_smtp_port
        },
        "enable_ai": True,
        "enable_justification_bypass": True,
        "root_window": None
    }
    
    proxy = DataShieldSMTPProxy(state, host="127.0.0.1", port=proxy_port)
    proxy.start()
    return proxy
