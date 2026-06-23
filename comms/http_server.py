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

    def do_GET(self):
        if self.path == "/ping":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        elif self.path == "/me":
            # Returns current employee identity for the browser extension
            info = {
                "employee_id": self.server.state.get("employee_id", ""),
                "email":       self.server.state.get("employee_email", ""),
                "name":        self.server.state.get("employee_name", ""),
                "server_url":  self.server.state.get("server_url", ""),
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(info).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/scan":
            self.handle_scan()
        elif self.path == "/log_event":
            self.handle_log_event()
        elif self.path == "/scan_attachment":
            self.handle_scan_attachment()
        elif self.path == "/request_override":
            self.handle_request_override()
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

    def handle_scan_attachment(self):
        """
        POST /scan_attachment  — multipart file upload from the browser extension.
        Extension intercepts file attachment dialog → sends chosen file here.
        Returns same ALLOW/BLOCK/WARN structure as /scan.
        """
        try:
            content_type = self.headers.get("Content-Type", "")
            length       = int(self.headers.get("Content-Length", 0))
            raw_body     = self.rfile.read(length)

            # ── Parse multipart/form-data using email library (no cgi module) ──
            import email, email.parser, email.policy

            # Reconstruct a proper MIME message from the raw body + headers
            mime_src = f"Content-Type: {content_type}\r\n\r\n".encode() + raw_body
            msg = email.message_from_bytes(mime_src, policy=email.policy.compat32)

            filename   = None
            file_bytes = None

            for part in msg.walk():
                cd = part.get("Content-Disposition", "")
                if 'name="file"' in cd or "name=file" in cd:
                    filename = None
                    # Extract filename from Content-Disposition
                    for token in cd.split(";"):
                        token = token.strip()
                        if token.lower().startswith("filename"):
                            filename = token.split("=", 1)[-1].strip().strip('"')
                    file_bytes = part.get_payload(decode=True)
                    break

            if file_bytes is None:
                self.send_response(400)
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(b'{"error":"No file found in upload","action":"ALLOW"}')
                return

            filename = filename or "attachment"

            # Write to temp file keeping original extension so scanner rules apply
            suffix = Path(filename).suffix or ".bin"
            if os.name == "nt":
                temp_dir = Path("C:\\Temp\\datashield_scan") if os.path.exists("C:\\") \
                           else Path(tempfile.gettempdir()) / "datashield_scan"
            else:
                temp_dir = Path("/tmp/datashield_scan")
            temp_dir.mkdir(parents=True, exist_ok=True)

            with tempfile.NamedTemporaryFile(
                dir=str(temp_dir), delete=False,
                suffix=suffix, prefix="attach_"
            ) as tmp:
                tmp.write(file_bytes)
                temp_path = tmp.name

            try:
                config = {
                    "root_path": str(temp_dir),
                    "policy_manager": self.server.state.get("policy_manager"),
                }
                matches        = scanner.scan_file(temp_path, config)
                matches        = behaviour.proximity_multiplier(matches)
                classification = classifier.classify_file(matches, file_path=temp_path)
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)

            enable_ai = self.server.state.get("enable_ai", True)
            decision  = comms_engine.decide(
                classification, channel="WEBMAIL",
                audit_logger=self.server.state["audit_logger"], explain=enable_ai,
                api_key=self.server.state.get("gemini_api_key"),
            )

            # Push to agent GUI threat feed
            if self.server.on_event_callback and decision.action != "ALLOW":
                self.server.on_event_callback(
                    "EMAIL ATTACH", decision.action,
                    filename, decision=decision
                )

            response_data = {
                "action":      decision.action,
                "risk_level":  decision.risk_level,
                "risk_score":  decision.risk_score,
                "top_pattern": decision.top_pattern,
                "regulations": decision.regulation_tags,
                "explanation": comms_engine.format_warning_message(decision)
                               if decision.action != "ALLOW" else "",
                "filename":    filename,
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode("utf-8"))

        except Exception as e:
            print(f"Error scanning attachment: {e}", file=sys.stderr)
            self.send_response(500)
            self.send_cors_headers()
            self.end_headers()
            # Fail-open: if scan crashes, let the attachment through
            self.wfile.write(json.dumps({"error": str(e), "action": "ALLOW"}).encode("utf-8"))

    def handle_request_override(self):
        """
        POST /request_override — browser extension submits an override request.
        Proxied to the FastAPI server /api/overrides.
        No JWT required — this endpoint is open for employee submissions.
        """
        try:
            length  = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))

            # Resolve server URL: state first, then .env fallback
            server_url = self.server.state.get("server_url", "").rstrip("/")
            if not server_url:
                # Fallback: read directly from .env so a restart isn't needed
                try:
                    import dotenv, pathlib
                    env = dotenv.dotenv_values(pathlib.Path(__file__).parent.parent / ".env")
                    server_url = env.get("SERVER_URL", "").rstrip("/")
                except Exception:
                    pass

            if not server_url:
                server_url = "http://localhost:8001"   # hard fallback

            target = f"{server_url}/api/overrides"

            # Build body — accept both formats the extension might send
            body = {
                "employee_id":   payload.get("employee_id",   self.server.state.get("employee_id", "")),
                "agent_id":      payload.get("agent_id",      self.server.state.get("agent_id", "")),
                "event_channel": payload.get("event_channel", "EMAIL ATTACH"),
                "event_detail":  payload.get("event_detail",  payload.get("filename", "")),
                "pattern":       payload.get("pattern",       payload.get("top_pattern", "")),
                "justification": payload.get("justification", ""),
            }

            print(f"[*] Override proxy → {target}  employee={body['employee_id']}  file={body['event_detail']}")

            import httpx
            try:
                resp = httpx.post(target, json=body, timeout=10)
                print(f"[*] Override proxy ← {resp.status_code} {resp.text[:200]}")
                self._json_response(resp.status_code, resp.json() if resp.content else {"status": "ok"})
            except httpx.ConnectError:
                msg = f"DataShield server is not reachable at {target}. Start the FastAPI server."
                print(f"[!] {msg}", file=sys.stderr)
                self._json_response(503, {"error": msg})
            except httpx.TimeoutException:
                msg = f"Request to {target} timed out."
                print(f"[!] {msg}", file=sys.stderr)
                self._json_response(504, {"error": msg})

        except Exception as e:
            import traceback
            traceback.print_exc()
            self._json_response(500, {"error": str(e)})

    def _json_response(self, status: int, data: dict):
        """Helper: send JSON response with CORS headers."""
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(body)


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
