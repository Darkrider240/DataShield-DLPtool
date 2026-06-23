"""
DataShield Endpoint Agent
─────────────────────────
PURPOSE
  This process runs on an EMPLOYEE's workstation. It:
    1. Identifies the employee via a login dialog (email + PIN)
    2. Registers this machine with the DataShield server
    3. Starts background protection silently (clipboard, USB, webmail)
    4. Lives in the system tray — employee can open the full window on demand
    5. Sends violation events to the central server for the admin dashboard

  ADMINS: Use the DataShield Web Dashboard (http://localhost:5173)
          This agent is not for admins. Admins are redirected to the browser.
"""
import argparse
import os
import sys
import time
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import scanner
import scanner_analysis as behaviour
import classifier
import ai_explain
import quarantine
import alerts
import reporter
import watcher
import audit
from audit import AuditLogger
from policy import PolicyManager


# ─────────────────────────────────────────────────────────────────────────────
#  CLI scan (unchanged — still available via --cli flag)
# ─────────────────────────────────────────────────────────────────────────────
def run_cli_scan(target_dir: str, output_dir: str, enable_quarantine: bool, client=None):
    target_path = Path(target_dir).resolve()
    output_path = Path(output_dir).resolve()
    if not target_path.exists():
        print(f"Error: Target path '{target_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)
    os.makedirs(output_path, exist_ok=True)
    audit_path  = output_path / "datashield_audit.log"
    report_path = output_path / "report.html"
    csv_path    = output_path / "report.csv"
    audit_logger   = AuditLogger(str(audit_path))
    policy_manager = PolicyManager()
    files_to_scan  = []
    for root, dirs, files in os.walk(str(target_path)):
        if "quarantine" in Path(root).parts:
            continue
        for f in files:
            fp = os.path.join(root, f)
            p  = Path(fp)
            if p.name.endswith(".quarantine_info") or p.name == "datashield_audit.log":
                continue
            files_to_scan.append(fp)
    print(f"[*] Target: {target_path}  |  Files: {len(files_to_scan)}")
    audit_logger.log("SCAN_STARTED", {"target_directory": str(target_path), "total_files": len(files_to_scan)})
    start_time   = time.time()
    file_results = []
    config = {"root_path": str(target_path), "policy_manager": policy_manager}
    for idx, file in enumerate(files_to_scan):
        rel = os.path.relpath(file, target_path)
        print(f"[{idx+1}/{len(files_to_scan)}] {rel} ... ", end="", flush=True)
        try:
            matches     = scanner.scan_file(file, config)
            matches     = behaviour.proximity_multiplier(matches)
            entropy     = behaviour.detect_high_entropy_strings(file)
            matches.extend(entropy)
            mismatch    = behaviour.detect_file_type_mismatch(file)
            file_report = classifier.classify_file(matches, file_path=file, file_type_mismatch=mismatch)
            api_key     = os.environ.get("GEMINI_API_KEY")
            if file_report["risk_level"] != "CLEAN" and api_key and file_report["top_matches"]:
                file_report["ai_explanation"] = ai_explain.explain_finding(
                    file_report["top_matches"][0], file, api_key=api_key)
            if file_report["risk_level"] == "HIGH" and enable_quarantine:
                q_dir = os.path.join(str(target_path), "quarantine")
                triggered = [m.pattern_name for m in file_report["top_matches"]]
                new_path  = quarantine.quarantine_file(file, q_dir, audit_logger, triggered)
                file_report["file_path"] = new_path
                alerts.send_desktop_notification("DLP Quarantine", f"Quarantined: {os.path.basename(file)}")
            elif file_report["risk_level"] in ("HIGH", "MEDIUM"):
                alerts.send_desktop_notification("DLP Alert", f"Sensitive data: {os.path.basename(file)}")
            file_results.append(file_report)
            if client:
                action = "BLOCK" if file_report["risk_level"] == "HIGH" and enable_quarantine else "ALLOW"
                client.enqueue_event(file_report, "FILE", action)
            audit_logger.log("FILE_SCANNED", {
                "file_path": file, "risk_level": file_report["risk_level"],
                "risk_score": file_report["risk_score"], "matches_count": file_report["match_count"]
            })
            print(f"{file_report['risk_level']} (Score: {file_report['risk_score']})")
        except Exception as e:
            print(f"FAILED: {e}")
    scan_duration = time.time() - start_time
    print(f"[*] Done in {scan_duration:.2f}s")
    last_hash = audit_logger._get_last_hash()
    reporter.generate_html_report(file_results, scan_duration, last_hash, str(report_path))
    reporter.export_csv_report(file_results, str(csv_path))
    audit_logger.log("REPORT_GENERATED", {"html": str(report_path), "csv": str(csv_path)})
    is_valid = audit.verify_chain(str(audit_path))
    print(f"[*] Ledger: {'SECURED' if is_valid else 'WARNING — tampering detected'}")
    return file_results, audit_logger


# ─────────────────────────────────────────────────────────────────────────────
#  Tray icon helper (pystray + Pillow)
# ─────────────────────────────────────────────────────────────────────────────
def _build_shield_image(color: str = "#22c55e"):
    """Generate a 64×64 shield icon as a PIL Image."""
    try:
        from PIL import Image, ImageDraw
        img  = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Outer shield polygon
        outer = [(32, 2), (62, 14), (62, 38), (32, 62), (2, 38), (2, 14)]
        draw.polygon(outer, fill=color)
        # Inner darker inset for depth
        r, g, b = int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)
        inner_color = (max(0, r - 50), max(0, g - 50), max(0, b - 50), 255)
        inner = [(32, 12), (54, 22), (54, 38), (32, 54), (10, 38), (10, 22)]
        draw.polygon(inner, fill=inner_color)
        return img
    except ImportError:
        return None


_RISK_COLORS = {
    "CLEAN":  "#22c55e",  # green  — all clear
    "LOW":    "#3b82f6",  # blue   — minor findings
    "MEDIUM": "#f59e0b",  # amber  — attention needed
    "HIGH":   "#ef4444",  # red    — violations detected
}

# Shared state for tray ↔ window communication
_tray_state = {
    "risk_level":  "CLEAN",
    "main_window": None,       # set after MainWindow is created
    "tray_icon":   None,       # set after pystray.Icon is created
    "stop_event":  threading.Event(),
}


def _update_tray_icon():
    """Refresh the tray icon color to reflect current risk level."""
    icon = _tray_state.get("tray_icon")
    if icon:
        img = _build_shield_image(_RISK_COLORS.get(_tray_state["risk_level"], "#6366f1"))
        if img:
            icon.icon = img


def run_system_tray(name: str, email: str):
    """
    Runs the system-tray icon in a background thread.
    Right-click menu lets the employee open the window, scan files, or exit.
    """
    try:
        import pystray
    except ImportError:
        print("[*] pystray not installed — running without system tray. "
              "Install with: pip install pystray pillow")
        return

    def _open_window(icon, item):
        win = _tray_state.get("main_window")
        if win:
            try:
                win.deiconify()
                win.lift()
                win.focus_force()
            except Exception:
                pass

    def _scan_now(icon, item):
        """
        Tray menu: '📁 Scan Folder Before Sending'
        Opens a folder picker in the main thread, then triggers
        trigger_scan_folder() on the MainWindow — the unique employee
        capability to scan a local folder before sending documents.
        """
        win = _tray_state.get("main_window")
        if win and win.winfo_exists():
            def _pick_and_scan():
                from tkinter import filedialog
                folder = filedialog.askdirectory(
                    title="Select Folder to Scan Before Sending",
                    parent=win,
                )
                if folder and hasattr(win, "trigger_scan_folder"):
                    win.trigger_scan_folder(folder)
            win.after(0, _pick_and_scan)
        else:
            # Window not open yet — open it first, then scan
            def _open_then_scan():
                import tkinter as tk
                from tkinter import filedialog
                dummy = tk.Tk()
                dummy.withdraw()
                folder = filedialog.askdirectory(
                    title="Select Folder to Scan Before Sending",
                )
                dummy.destroy()
                if folder:
                    w = _tray_state.get("main_window")
                    if w and hasattr(w, "trigger_scan_folder"):
                        w.after(0, lambda: w.trigger_scan_folder(folder))
            import threading
            threading.Thread(target=_open_then_scan, daemon=True).start()

    def _exit_agent(icon, item):
        print("[*] DataShield agent stopping...")
        _tray_state["stop_event"].set()
        win = _tray_state.get("main_window")
        if win:
            try:
                win.destroy()
            except Exception:
                pass
        icon.stop()

    img = _build_shield_image("#22c55e")
    if img is None:
        print("[*] Pillow not installed — system tray icon disabled. "
              "Install with: pip install pillow")
        return

    menu = pystray.Menu(
        pystray.MenuItem(f"DataShield  —  {name}", None, enabled=False),
        pystray.MenuItem(f"{email}", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Open DataShield",              _open_window, default=True),
        pystray.MenuItem("Scan Folder Before Sending",   _scan_now),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Exit DataShield",              _exit_agent),
    )

    icon = pystray.Icon("DataShield", img, f"DataShield  ({name})", menu)
    _tray_state["tray_icon"] = icon

    # Run the tray on its own thread (pystray.run() blocks)
    t = threading.Thread(target=icon.run, daemon=True)
    t.start()
    print("[*] DataShield is running in the system tray.")


# ─────────────────────────────────────────────────────────────────────────────
#  Admin redirect dialog — shown when an admin logs in via this agent
# ─────────────────────────────────────────────────────────────────────────────
def show_admin_redirect(admin_name: str):
    """
    Admins have no business in the endpoint agent.
    Show a clear redirect to the web dashboard and close.
    """
    import tkinter as tk
    import webbrowser

    root = tk.Tk()
    root.title("DataShield — Admin Console")
    root.resizable(False, False)
    W, H = 460, 320
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
    root.configure(bg="#0b0f1a")

    # Header
    hdr = tk.Canvas(root, width=W, height=80, bg="#0b0f1a", highlightthickness=0)
    hdr.pack()
    hdr.create_text(W // 2, 38, text="DataShield", fill="#6366f1",
                    font=("Arial", 22, "bold"))
    hdr.create_text(W // 2, 62, text="Enterprise Data Loss Prevention",
                    fill="#475569", font=("Arial", 9))
    tk.Frame(root, height=1, bg="#1e293b").pack(fill="x")

    card = tk.Frame(root, bg="#0f172a", padx=40, pady=28)
    card.pack(fill="both", expand=True)

    tk.Label(card, text="🛡", bg="#0f172a", fg="#6366f1",
             font=("Arial", 32)).pack()
    tk.Label(card, text=f"Hello, {admin_name.split()[0]}",
             bg="#0f172a", fg="#e2e8f0", font=("Arial", 14, "bold")).pack(pady=(6, 2))
    tk.Label(card,
             text="This agent runs on employee workstations.\n"
                  "Admins manage DataShield from the Web Dashboard.",
             bg="#0f172a", fg="#64748b", font=("Arial", 10),
             justify="center").pack(pady=(0, 20))

    def _open():
        webbrowser.open("http://localhost:5173")
        root.destroy()

    tk.Button(card, text="Open Web Dashboard  →",
              bg="#6366f1", fg="white", activebackground="#818cf8",
              activeforeground="white", relief="flat",
              font=("Arial", 11, "bold"), cursor="hand2",
              command=_open, bd=0).pack(fill="x", ipady=11)

    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()


# ─────────────────────────────────────────────────────────────────────────────
#  Login dialog (employee + admin, but admin gets redirected)
# ─────────────────────────────────────────────────────────────────────────────
def show_login_dialog(server_url: str, agent_api_key: str):
    """
    Shows the sign-in dialog.
    Returns dict {role, name, email} on success, or None if cancelled.
    Admins are flagged so main() can redirect them to the web dashboard.
    """
    import tkinter as tk
    import httpx

    result = {}

    root = tk.Tk()
    root.title("DataShield — Sign In")
    root.resizable(False, False)
    W, H = 460, 530
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
    root.configure(bg="#0b0f1a")

    canvas = tk.Canvas(root, width=W, height=100, bg="#0b0f1a", highlightthickness=0)
    canvas.pack()
    canvas.create_text(W // 2, 42, text="DataShield", fill="#6366f1",
                       font=("Arial", 26, "bold"))
    canvas.create_text(W // 2, 68, text="Enterprise Data Loss Prevention",
                       fill="#475569", font=("Arial", 10))
    canvas.create_text(W // 2, 88, text="Sign in with your work email",
                       fill="#334155", font=("Arial", 8))

    tk.Frame(root, height=1, bg="#1e293b").pack(fill="x")

    card = tk.Frame(root, bg="#0f172a", padx=40, pady=30)
    card.pack(fill="both", expand=True)

    tk.Label(card, text="Sign in to continue",
             bg="#0f172a", fg="#94a3b8", font=("Arial", 11)).pack(pady=(0, 20))

    # Work Email
    tk.Label(card, text="Work Email", bg="#0f172a", fg="#cbd5e1",
             font=("Arial", 9, "bold"), anchor="w").pack(fill="x")
    email_var = tk.StringVar()
    email_entry = tk.Entry(card, textvariable=email_var, bg="#1e293b", fg="white",
                           insertbackground="white", relief="flat",
                           font=("Arial", 12), bd=0)
    email_entry.pack(fill="x", pady=(4, 4), ipady=10)
    tk.Frame(card, height=1, bg="#334155").pack(fill="x", pady=(0, 16))

    # Password / PIN
    tk.Label(card, text="Password / PIN", bg="#0f172a", fg="#cbd5e1",
             font=("Arial", 9, "bold"), anchor="w").pack(fill="x")
    pw_var = tk.StringVar()
    pw_entry = tk.Entry(card, textvariable=pw_var, show="*", bg="#1e293b", fg="white",
                        insertbackground="white", relief="flat",
                        font=("Arial", 12), bd=0)
    pw_entry.pack(fill="x", pady=(4, 4), ipady=10)
    tk.Frame(card, height=1, bg="#334155").pack(fill="x", pady=(0, 8))

    # Status / error label
    info_var = tk.StringVar(value="")
    tk.Label(card, textvariable=info_var, bg="#0f172a", fg="#f59e0b",
             font=("Arial", 9), wraplength=360, justify="center").pack(pady=(4, 14))

    def do_login(event=None):
        email = email_var.get().strip()
        pw    = pw_var.get().strip()
        if not email or "@" not in email:
            info_var.set("Please enter a valid work email address.")
            return
        info_var.set("Verifying…")
        root.update()
        try:
            # First: try admin JWT login (email + password)
            admin_resp = httpx.post(
                f"{server_url}/api/auth/login",
                json={"email": email, "password": pw or ""},
                timeout=8.0
            )
            if admin_resp.status_code == 200:
                data = admin_resp.json()
                result["role"]   = "admin"  # normalise — always opens AdminConsole
                result["name"]   = data.get("full_name") or data.get("name") or email.split("@")[0].title()
                result["email"]  = email
                result["token"]  = data.get("access_token", "")
                root.destroy()
                return

            # Second: try employee PIN validation
            emp_resp = httpx.post(
                f"{server_url}/api/auth/validate-employee",
                json={"email": email, "password": pw or ""},
                headers={"X-DataShield-Agent-Key": agent_api_key},
                timeout=8.0
            )
            if emp_resp.status_code == 200:
                data = emp_resp.json()
                # Employee has no PIN set yet
                if data.get("role") == "employee" and not data.get("pin_set", True):
                    info_var.set(
                        "Your account has no PIN yet.\n"
                        "Ask your admin to set one in the DataShield console."
                    )
                    return
                result["role"]        = data["role"]
                result["name"]        = data["name"]
                result["email"]       = data["email"]
                result["employee_id"] = data.get("employee_id", "")
                result["token"]       = ""
                root.destroy()
                return
            elif emp_resp.status_code == 401:
                try:
                    detail = emp_resp.json().get("detail", "")
                except Exception:
                    detail = ""
                if detail == "pin_required":
                    info_var.set("Enter your PIN in the Password field.")
                elif detail == "Wrong PIN":
                    info_var.set("Wrong PIN. Contact your admin to reset it.")
                elif "wrong password" in detail.lower():
                    info_var.set("Wrong admin password. Use your DataShield admin password.")
                else:
                    info_var.set("Wrong credentials. Please try again.")
            elif emp_resp.status_code == 404:
                info_var.set(
                    "Email not registered.\n"
                    "Ask your admin to add you in the DataShield console."
                )
            else:
                info_var.set(f"Server error ({emp_resp.status_code}). Check the server console.")
        except Exception as ex:
            info_var.set(f"Cannot reach server at {server_url}.\nMake sure the server is running.\n({type(ex).__name__})")

    tk.Button(card, text="Sign In  →", bg="#6366f1", fg="white",
              activebackground="#818cf8", activeforeground="white",
              relief="flat", font=("Arial", 12, "bold"),
              cursor="hand2", command=do_login, bd=0).pack(fill="x", ipady=12)

    # Help text
    help_frame = tk.Frame(card, bg="#0f172a")
    help_frame.pack(pady=(16, 0), fill="x")
    tk.Label(help_frame,
             text="Employees: email + PIN (set by your IT admin)",
             bg="#0f172a", fg="#475569", font=("Arial", 8)).pack()
    tk.Label(help_frame,
             text="Admins: email + admin password  →  opens Admin Console",
             bg="#0f172a", fg="#475569", font=("Arial", 8)).pack(pady=(2, 0))

    email_entry.focus_set()
    root.bind("<Return>", do_login)
    root.protocol("WM_DELETE_WINDOW", lambda: sys.exit(0))
    root.mainloop()

    return result or None


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="DataShield — Employee Endpoint Agent")
    parser.add_argument("--cli",             action="store_true",
                        help="CLI scan mode (no GUI)")
    parser.add_argument("--path",            default="./demo_vault")
    parser.add_argument("--output",          default="./output")
    parser.add_argument("--watch",           action="store_true")
    parser.add_argument("--auto-quarantine", action="store_true")
    args = parser.parse_args()

    from dotenv import load_dotenv
    load_dotenv()
    server_url    = os.environ.get("SERVER_URL", "").rstrip("/")
    agent_api_key = os.environ.get("AGENT_API_KEY", "")

    # Build reporting client
    client = None
    if server_url and agent_api_key:
        from agent.reporting_client import ServerReportingClient
        client = ServerReportingClient(server_url, agent_api_key)

    # ── CLI MODE ──────────────────────────────────────────────────────────────
    if args.cli:
        if client:
            client.start()
        run_cli_scan(args.path, args.output, args.auto_quarantine, client=client)
        return

    # ── GUI MODE ──────────────────────────────────────────────────────────────

    # Step 1: Login
    if server_url and agent_api_key:
        user_info = show_login_dialog(server_url, agent_api_key)
        if not user_info:
            sys.exit(0)
    else:
        user_info = {"role": "employee", "name": "Local User", "email": "local@datashield"}
        print("[*] No SERVER_URL in .env — running in standalone mode (no reporting).")

    role        = user_info["role"]
    name        = user_info["name"]
    email       = user_info["email"]
    token       = user_info.get("token", "")
    employee_id = user_info.get("employee_id", "")

    # ── ADMIN -> open the desktop management console ────────────────────────────
    if role == "admin":
        print(f"[*] Admin '{name}' signed in — opening DataShield Management Console.")
        os.environ["EMPLOYEE_NAME"]  = name
        os.environ["EMPLOYEE_EMAIL"] = email
        try:
            from gui.admin_window import AdminConsole
            console = AdminConsole(
                admin_name=name,
                admin_email=email,
                server_url=server_url,
                token=token,
            )
            console.mainloop()
        except ImportError as e:
            print(f"[!] Could not open admin console: {e}")
            import webbrowser, tkinter as tk
            tk.messagebox.showinfo(
                "DataShield — Admin Console",
                "Admin console not available.\nOpening Web Dashboard instead."
            )
            webbrowser.open("http://localhost:5173")
        sys.exit(0)

    # ── EMPLOYEE → start the endpoint agent ───────────────────────────────────
    os.environ["EMPLOYEE_NAME"]  = name
    os.environ["EMPLOYEE_EMAIL"] = email
    print(f"[*] Employee signed in: {name} <{email}>")
    print(f"[*] Starting DataShield endpoint protection...")

    # Step 2: Register + start reporting
    if client:
        client.employee_name = name
        client.start()
        time.sleep(1.5)  # allow registration to complete

    # Step 3: Background monitors
    audit_logger   = AuditLogger("datashield_agent_audit.log")
    policy_manager = PolicyManager()
    bg_state = {
        "audit_logger":  audit_logger,
        "policy_manager": policy_manager,
        "root_window":   None,
    }

    def _bg_event(channel, action, detail, decision=None, **kwargs):
        """Bridge: background monitor → reporting client."""
        if client:
            if decision and hasattr(decision, "risk_level"):
                cr = {
                    "risk_level":     decision.risk_level,
                    "risk_score":     decision.risk_score,
                    "file_path":      detail,
                    "top_matches":    [],
                    "ai_explanation": getattr(decision, "ai_explanation", ""),
                }
            else:
                cr = {
                    "risk_level":  "HIGH"   if action == "BLOCK" else
                                   "MEDIUM" if action == "WARN"  else "CLEAN",
                    "risk_score":  10.0     if action == "BLOCK" else
                                   4.0      if action == "WARN"  else 0.0,
                    "file_path":   detail,
                    "top_matches": [],
                    "ai_explanation": "",
                }
            client.enqueue_event(cr, channel, action)

            # Update tray icon color if risk escalated
            lvl = cr["risk_level"]
            order = ["CLEAN", "LOW", "MEDIUM", "HIGH"]
            if order.index(lvl) > order.index(_tray_state["risk_level"]):
                _tray_state["risk_level"] = lvl
                _update_tray_icon()

    # -- Read per-employee monitoring settings ---------------------------------
    monitoring = {
        "clipboard": user_info.get("monitor_clipboard", True),
        "usb":       user_info.get("monitor_usb",       True),
        "webmail":   user_info.get("monitor_webmail",   True),
        "file_scan": user_info.get("monitor_file_scan", True),
    }
    disabled = [k.upper() for k, v in monitoring.items() if not v]
    if disabled:
        print("[*] Channels DISABLED by admin: " + ", ".join(disabled))
    else:
        print("[*] All monitoring channels enabled for this account.")

    clipboard_monitor = None
    usb_monitor       = None
    webmail_server    = None

    if monitoring["clipboard"]:
        try:
            from comms.clipboard_monitor import ClipboardMonitor
            clipboard_monitor = ClipboardMonitor(bg_state, on_finding_callback=_bg_event)
            clipboard_monitor.start()
            print("[*] Clipboard monitor active.")
        except Exception as e:
            print("[*] Clipboard monitor unavailable:", e)
    else:
        print("[*] Clipboard monitor DISABLED by admin policy.")

    if monitoring["usb"]:
        try:
            from comms.usb_watcher import USBWatcher
            usb_monitor = USBWatcher(bg_state, on_report_callback=None, on_event_callback=_bg_event)
            usb_monitor.start()
            print("[*] USB watcher active.")
        except Exception as e:
            print("[*] USB watcher unavailable:", e)
    else:
        print("[*] USB watcher DISABLED by admin policy.")

    if monitoring["webmail"]:
        try:
            from comms.http_server import DataShieldHTTPServer
            # Inject identity so /me and /request_override endpoints work
            bg_state["employee_id"]    = employee_id
            bg_state["employee_email"] = email
            bg_state["employee_name"]  = name
            bg_state["server_url"]     = server_url
            webmail_server = DataShieldHTTPServer(bg_state, on_event_callback=_bg_event)
            webmail_server.start()
            print("[*] Webmail scan API active on port 5000.")
        except Exception as e:
            print("[*] Webmail HTTP server unavailable:", e)
    else:
        print("[*] Webmail monitor DISABLED by admin policy.")

    # Step 4: System tray
    run_system_tray(name, email)

    # Step 5: Employee home window
    try:
        from gui.main_window import EmployeeHomeWindow

        def _do_logout():
            print("[*] Employee logged out.")
            for mon in [clipboard_monitor, usb_monitor]:
                if mon:
                    try: mon.stop()
                    except Exception: pass
            if webmail_server:
                try: webmail_server.stop()
                except Exception: pass
            if client:
                try: client.stop()
                except Exception: pass
            import subprocess
            subprocess.Popen([sys.executable] + sys.argv)
            sys.exit(0)

        app = EmployeeHomeWindow(
            user_name=name,
            user_email=email,
            monitors=monitoring,
            server_url=server_url,
            logout_callback=_do_logout,
        )
        if client:
            app.state["reporting_client"] = client
        bg_state["root_window"] = app
        _tray_state["main_window"] = app

        def _on_close():
            app.withdraw()
            alerts.send_desktop_notification(
                "DataShield",
                "Still protecting your workstation in the background.")
        app.protocol("WM_DELETE_WINDOW", _on_close)

        _orig_bg = _bg_event
        def _bg_event_with_feed(channel, action, detail, decision=None, **kwargs):
            _orig_bg(channel, action, detail, decision=decision, **kwargs)
            if action in ("ALLOW", "LOG"):
                return
            rl = "HIGH"
            if decision and hasattr(decision, "risk_level"):
                rl = decision.risk_level
            elif action == "WARN":
                rl = "MEDIUM"
            pattern = getattr(decision, "top_pattern", "") if decision else ""
            app.after(0, lambda c=channel, a=action, d=detail, r=rl, p=pattern:
                       app.push_threat(c, a, d, r, p))

        if clipboard_monitor and hasattr(clipboard_monitor, "on_finding_callback"):
            clipboard_monitor.on_finding_callback = _bg_event_with_feed
        if usb_monitor and hasattr(usb_monitor, "on_event_callback"):
            usb_monitor.on_event_callback = _bg_event_with_feed
        if webmail_server and hasattr(webmail_server, "on_event_callback"):
            webmail_server.on_event_callback = _bg_event_with_feed

        def _ping_server():
            online = False
            if server_url:
                try:
                    import httpx as _hx
                    resp = _hx.get(server_url + "/api/health", timeout=3)
                    online = resp.status_code < 500
                except Exception:
                    online = False
            app.set_agent_status(online)
            app.after(30000, _ping_server)

        app.after(2000, _ping_server)

        # Start override notification polling (60s interval)
        if employee_id and server_url:
            app.state["employee_id"] = employee_id
            app.after(5000, app._start_override_poll)

        print("[*] DataShield running. Opening employee portal...")
        first_name = name.split()[0] if name else "there"
        alerts.send_desktop_notification(
            "DataShield Active",
            "Hello " + first_name + "! Your workstation is now protected.")
        app.deiconify()
        app.mainloop()


    except ImportError as e:
        print(f"Error launching GUI: {e}", file=sys.stderr)
        # Keep running monitors even without GUI
        _tray_state["stop_event"].wait()
    finally:
        print("[*] DataShield shutting down...")
        if clipboard_monitor:
            clipboard_monitor.stop()
        if usb_monitor:
            usb_monitor.stop()
        if webmail_server:
            try:
                webmail_server.stop()
            except Exception:
                pass
        if client:
            try:
                client.stop()
            except Exception:
                pass


if __name__ == "__main__":
    main()
