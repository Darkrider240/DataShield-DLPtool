import os
import sys
import json
import tempfile
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# DataShield components
import scanner
import scanner_analysis as behaviour  # scanner_analysis is the correct module name
import classifier
import comms.comms_engine as comms_engine


class ScanHTTPRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress standard console request logging to keep CLI neat
        pass

    def send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        """Handles browser pre-flight requests."""
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def do_POST(self):
        if self.path == "/scan":
            self.handle_scan()
        elif self.path == "/log_event":
            self.handle_log_event()
        else:
            self.send_response(404)
            self.end_headers()

    def handle_scan(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            payload = json.loads(post_data.decode('utf-8'))

            subject    = payload.get("subject", "")
            body       = payload.get("body", "")
            recipients = payload.get("recipients", "")
            sender     = payload.get("sender", "")   # employee's own email address

            full_scan_text = f"Subject: {subject}\nBody:\n{body}"

            # 1. Create a temporary scan file
            if os.name == "nt":
                temp_dir = Path("C:\\Temp\\datashield_scan") if os.path.exists("C:\\") else Path(tempfile.gettempdir()) / "datashield_scan"
            else:
                temp_dir = Path("/tmp/datashield_scan")

            temp_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=str(temp_dir), delete=False, suffix=".txt", mode="w", encoding="utf-8") as f:
                f.write(full_scan_text)
                temp_file_path = f.name

            # 2. Run scan
            try:
                config = {
                    "root_path": str(temp_dir),
                    "policy_manager": self.server.state.get("policy_manager")
                }
                matches = scanner.scan_file(temp_file_path, config)
                matches = behaviour.proximity_multiplier(matches)
                classification = classifier.classify_file(matches, file_path=temp_file_path)
            finally:
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)

            # 3. Get decision
            enable_ai = self.server.state.get("enable_ai", True)
            decision = comms_engine.decide(
                classification, channel="WEBMAIL",
                audit_logger=self.server.state["audit_logger"], explain=enable_ai,
                api_key=self.server.state.get("gemini_api_key")
            )

            # Reroute alert logs to GUI if hook present
            if self.server.on_event_callback:
                pattern_info = decision.top_pattern if classification["top_matches"] else "CLEAN"
                detail = f"{pattern_info} | From: {sender or 'unknown'} -> To: {recipients or 'unknown'}"
                self.server.on_event_callback("WEBMAIL", decision.action, detail, decision=decision)

            # Respond with decision + attribution echo
            response_data = {
                "action":       decision.action,
                "risk_level":   decision.risk_level,
                "risk_score":   decision.risk_score,
                "top_pattern":  decision.top_pattern,
                "regulations":  decision.regulation_tags,
                "explanation":  comms_engine.format_warning_message(decision) if decision.action != "ALLOW" else "",
                "sender":       sender,
                "recipients":   recipients,
                "subject":      subject,
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))

        except Exception as e:
            print(f"Error handling scan request: {e}", file=sys.stderr)
            self.send_response(500)
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))

    def handle_log_event(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            payload = json.loads(post_data.decode('utf-8'))

            action        = payload.get("action")          # "BLOCK" | "ALLOW"
            subject       = payload.get("subject", "No Subject")
            recipients    = payload.get("recipients", "")
            sender        = payload.get("sender", "")      # employee's own email
            top_pattern   = payload.get("top_pattern", "None")
            justification = payload.get("justification", "")
            reason        = payload.get("reason", "")

            log_entry = {
                "subject":      subject,
                "sender":       sender,
                "recipients":   [recipients],
                "top_pattern":  top_pattern,
                "channel":      "WEBMAIL",
            }

            if action == "ALLOW":
                log_entry["justification"] = justification
                self.server.state["audit_logger"].log("EMAIL_ALLOWED", log_entry)
            else:  # BLOCK
                log_entry["reason"] = reason or "DLP violation"
                self.server.state["audit_logger"].log("EMAIL_BLOCKED", log_entry)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "logged"}).encode('utf-8'))

        except Exception as e:
            print(f"Error logging webmail event: {e}", file=sys.stderr)
            self.send_response(500)
            self.send_cors_headers()
            self.end_headers()


class DataShieldHTTPServer:
    def __init__(self, state, host="127.0.0.1", port=5000, on_event_callback=None):
        self.state = state
        self.host = host
        self.port = port
        self.on_event_callback = on_event_callback

        # ThreadingHTTPServer handles each request in its own thread
        self.server = ThreadingHTTPServer((self.host, self.port), ScanHTTPRequestHandler)
        self.server.state = state
        self.server.on_event_callback = on_event_callback

        self.thread = None
        self.running = False


    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()

    def _run_server(self):
        try:
            self.server.serve_forever()
        except Exception as e:
            print(f"HTTP Server Exception: {e}", file=sys.stderr)

    def stop(self):
        if not self.running:
            return
        self.running = False
        self.server.shutdown()
        self.server.server_close()
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None
