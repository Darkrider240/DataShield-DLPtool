import os
import sys
import time
import tempfile
import threading
import pyperclip

# DataShield components
import scanner
import classifier
import alerts
import comms.comms_engine as comms_engine

class ClipboardMonitor:
    """
    Background clipboard monitoring daemon. Polls pyperclip every 300ms.
    Clears the clipboard immediately if PII or financial data is pasted.
    """
    def __init__(self, state, on_finding_callback):
        self.state = state  # Shared app state (contains audit logger, policies, etc.)
        self.on_finding_callback = on_finding_callback  # Callback to log events to GUI
        self.running = False
        self.thread = None
        self.last_copied = ""

    def start(self):
        """Starts monitoring loop in a background daemon thread."""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    def stop(self):
        """Gracefully requests the thread loop to exit."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None

    def _monitor_loop(self):
        while self.running:
            try:
                time.sleep(0.3)
                
                # Fetch current clipboard contents
                content = pyperclip.paste()
                if not content:
                    continue
                
                # De-duplicate identical copies and skip short words
                if content == self.last_copied or len(content) < 20:
                    continue
                    
                self.last_copied = content
                
                # Write clipboard contents to temporary file
                # Use delete=False and delete manually in finally to prevent Windows file-sharing lock crashes
                with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w", encoding="utf-8") as f:
                    f.write(content)
                    temp_file_path = f.name

                try:
                    # Scan temporary file
                    config = {
                        "root_path": os.path.dirname(temp_file_path),
                        "policy_manager": self.state.get("policy_manager")
                    }
                    matches = scanner.scan_file(temp_file_path, config)
                    classification = classifier.classify_file(matches, file_path=temp_file_path)
                    
                    if classification["risk_level"] in ["HIGH", "MEDIUM"]:
                        decision = comms_engine.decide(
                            classification, channel="CLIPBOARD",
                            audit_logger=self.state["audit_logger"], explain=False
                        )
                        
                        if decision.action in ["BLOCK", "WARN"]:
                            # Clear clipboard immediately
                            pyperclip.copy('')
                            self.last_copied = ""  # Reset to allow new scans
                            
                            # Write event to audit ledger
                            self.state["audit_logger"].log("CLIPBOARD_CLEARED", {
                                "top_pattern": decision.top_pattern,
                                "risk_score": decision.risk_score
                            })
                            
                            # Dispatch OS notification
                            alerts.send_desktop_notification(
                                "DLP Clipboard Block",
                                f"DataShield cleared your clipboard — {decision.top_pattern} pattern detected."
                            )
                            
                            # Invoke GUI event callback
                            if self.on_finding_callback:
                                root = self.state.get("root_window")
                                if root:
                                    root.after(0, lambda: self.on_finding_callback("CLIPBOARD", "BLOCKED", f"{decision.top_pattern} copied", decision=decision))
                                    
                finally:
                    if os.path.exists(temp_file_path):
                        os.remove(temp_file_path)
                        
            except Exception as e:
                # Keep loop running even if pyperclip or reading fails
                print(f"Warning: Clipboard watcher warning: {e}", file=sys.stderr)
