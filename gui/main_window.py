import os
import yaml
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path

# Import shared modules
from audit import AuditLogger
from policy import PolicyManager
from gui.scan_tab import ScanTab
from gui.results_tab import ResultsTab
from gui.report_tab import ReportTab
from gui.comms_tab import CommsTab

class MainWindow(tk.Tk):
    """
    MainWindow — role-aware Tkinter GUI.
    role='admin'    → all tabs visible
    role='employee' → only Scan + Detections (monitors run in background via main.py)
    """
    def __init__(self, role: str = "employee", user_name: str = "", user_email: str = ""):
        super().__init__()
        self.role       = role
        self.user_name  = user_name
        self.user_email = user_email
        is_admin        = (role == "admin")

        title_suffix = f"  |  {user_name or user_email}  [{role.upper()}]"
        self.title(f"DataShield{title_suffix}")
        self.geometry("920x680")
        self.minsize(820, 600)

        self.base_dir           = Path(__file__).resolve().parent.parent
        self.allowlist_path     = self.base_dir / "rules" / "allowlist.yaml"
        self.default_rules_path = self.base_dir / "rules" / "default_rules.yaml"
        self.audit_log_path     = self.base_dir / "output" / "datashield_agent_audit.log"

        self.state = {
            "scan_directory":   "",
            "scan_results":     [],
            "audit_logger":     AuditLogger(str(self.audit_log_path)),
            "policy_manager":   PolicyManager(
                rules_path=str(self.default_rules_path),
                allowlist_path=str(self.allowlist_path)
            ),
            "gemini_api_key":   os.environ.get("GEMINI_API_KEY", ""),
            "allowlist_path":   str(self.allowlist_path),
            "custom_rules_path": "",
            "smtp_config":      {},
            "is_scanning":      False,
            "root_window":      self,
            "role":             role,
            "user_email":       user_email,
        }

        self.configure_styles()
        self._build_header(is_admin)
        self.create_layout(is_admin)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_header(self, is_admin: bool):
        """Slim status bar showing logged-in user and role badge."""
        bar = tk.Frame(self, bg="#0f172a", height=36)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)

        badge_color = "#6366f1" if is_admin else "#0ea5e9"
        badge_text  = "ADMIN" if is_admin else "EMPLOYEE"

        tk.Label(bar, text="DataShield Enterprise", bg="#0f172a",
                 fg="#6366f1", font=("Segoe UI", 11, "bold")).pack(side="left", padx=14)
        tk.Label(bar, text=f"  {badge_text}  ", bg=badge_color, fg="white",
                 font=("Segoe UI", 8, "bold")).pack(side="left", pady=8)
        name_lbl = self.user_name or self.user_email
        tk.Label(bar, text=name_lbl, bg="#0f172a",
                 fg="#94a3b8", font=("Segoe UI", 9)).pack(side="left", padx=10)

        if not is_admin:
            tk.Label(bar,
                     text="USB, Clipboard & SMTP monitors running automatically in background",
                     bg="#0f172a", fg="#475569", font=("Segoe UI", 8)).pack(side="right", padx=14)

        tk.Frame(self, height=1, bg="#1e293b").pack(fill="x")



    def configure_styles(self):
        # Apply Clam theme as a baseline for styling
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Color Palette Definition (Slate-900 Dark Mode)
        self.bg_dark = "#0f172a"      # slate-900
        self.bg_card = "#1e293b"      # slate-800
        self.fg_light = "#f8fafc"     # slate-50
        self.fg_muted = "#94a3b8"     # slate-400
        self.color_blue = "#3b82f6"   # primary blue
        self.color_purple = "#8b5cf6" # secondary violet
        
        self.configure(background=self.bg_dark)

        # Style bindings
        self.style.configure(".", background=self.bg_dark, foreground=self.fg_light, font=("Segoe UI", 10))
        self.style.configure("TLabel", background=self.bg_dark, foreground=self.fg_light)
        self.style.configure("TFrame", background=self.bg_dark)
        
        # Entry Style
        self.style.configure("TEntry", fieldbackground=self.bg_card, foreground=self.fg_light, bordercolor=self.bg_card)
        
        # Button Styles
        self.style.configure("TButton", background=self.color_blue, foreground=self.fg_light, borderwidth=0, padding=6)
        self.style.map("TButton", background=[("active", self.color_purple)])
        
        # Tab Notebook Styles
        self.style.configure("TNotebook", background=self.bg_dark, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=self.bg_card, foreground=self.fg_light, padding=[15, 6], font=("Segoe UI", 10, "bold"))
        self.style.map("TNotebook.Tab", background=[("selected", self.bg_dark)], foreground=[("selected", self.fg_light)])

        # Treeview (Risk Table) Styles
        self.style.configure("Treeview", background=self.bg_card, fieldbackground=self.bg_card, foreground=self.fg_light, rowheight=24)
        self.style.map("Treeview", background=[("selected", self.color_blue)], foreground=[("selected", self.fg_light)])
        self.style.configure("Heading", background=self.bg_card, foreground=self.fg_light, font=("Segoe UI", 10, "bold"))

        # LabelFrame customization
        self.style.configure("TLabelframe", background=self.bg_dark, bordercolor=self.bg_card, padding=10)
        self.style.configure("TLabelframe.Label", background=self.bg_dark, foreground=self.color_blue, font=("Segoe UI", 10, "bold"))

    def create_layout(self, is_admin: bool = True):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)

        self.scan_tab    = ScanTab(self.notebook, self.state)
        self.results_tab = ResultsTab(self.notebook, self.state)

        # All users get Scan + Detections
        self.notebook.add(self.scan_tab,    text="  Scan Files  ")
        self.notebook.add(self.results_tab, text="  Detections  ")

        # Admin-only tabs
        if is_admin:
            self.comms_tab    = CommsTab(self.notebook, self.state)
            self.report_tab   = ReportTab(self.notebook, self.state)
            self.settings_tab = self.create_settings_tab()
            self.notebook.add(self.comms_tab,    text="  Comms DLP  ")
            self.notebook.add(self.report_tab,   text="  Reports  ")
            self.notebook.add(self.settings_tab, text="  Configuration  ")

        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)

    def trigger_scan_folder(self, folder: str = ""):
        """
        Called from the system tray 'Scan Folder Before Sending' menu item.

        This is the UNIQUE capability of the endpoint agent —
        scan a local folder before sending bulk documents externally.
        No browser-based dashboard can access the local file system.

        Flow:
          1. Open folder picker (if no folder given)
          2. Show & focus this window
          3. Switch to the Scan Files tab
          4. Pre-fill the directory and auto-start the scan
        """
        if not folder:
            folder = filedialog.askdirectory(
                title="Select Folder to Scan Before Sending",
                parent=self,
            )
        if not folder:
            return  # user cancelled

        self.deiconify()
        self.lift()
        self.focus_force()
        self.notebook.select(0)   # Scan Files is always tab index 0

        if hasattr(self, "scan_tab"):
            self.scan_tab.set_directory(folder)
            self.after(250, self.scan_tab.start_scan)



    def toggle_comms_daemons(self):
        """Starts/stops background monitor daemons depending on Settings variables."""
        enable_smtp = self.state.get("enable_smtp_monitor", False)
        enable_clip = self.state.get("enable_clipboard_monitor", False)
        enable_usb = self.state.get("enable_usb_monitor", False)
        enable_webmail = self.state.get("enable_webmail_monitor", False)
        
        # Lazy imports to prevent circular dependencies
        from comms.smtp_proxy import DataShieldSMTPProxy
        from comms.clipboard_monitor import ClipboardMonitor
        from comms.usb_watcher import USBWatcher
        from comms.http_server import DataShieldHTTPServer
        
        # SMTP Intercept Proxy Control
        if enable_smtp:
            if not hasattr(self, "smtp_proxy_obj") or not self.smtp_proxy_obj:
                try:
                    self.smtp_proxy_obj = DataShieldSMTPProxy(self.state, on_event_callback=self.comms_tab.log_event)
                    self.smtp_proxy_obj.start()
                    print("SMTP Intercept Proxy active on port 1025.")
                except Exception as e:
                    self.smtp_proxy_obj = None
                    self.state["enable_smtp_monitor"] = False
                    self.comms_tab.smtp_chk_var.set(False)
                    messagebox.showerror("SMTP Proxy Error", f"Failed to start SMTP proxy on port 1025. The port might be in use by another application.\nError: {e}")
        else:
            if hasattr(self, "smtp_proxy_obj") and self.smtp_proxy_obj:
                self.smtp_proxy_obj.stop()
                self.smtp_proxy_obj = None
                print("SMTP Intercept Proxy deactivated.")
                
        # Clipboard Monitor control
        if enable_clip:
            if not hasattr(self, "clip_monitor_obj") or not self.clip_monitor_obj:
                self.clip_monitor_obj = ClipboardMonitor(self.state, on_finding_callback=self.comms_tab.log_event)
                self.clip_monitor_obj.start()
                print("Clipboard Monitor active.")
        else:
            if hasattr(self, "clip_monitor_obj") and self.clip_monitor_obj:
                self.clip_monitor_obj.stop()
                self.clip_monitor_obj = None
                print("Clipboard Monitor deactivated.")
                
        # USB mount scanner control
        if enable_usb:
            if not hasattr(self, "usb_watcher_obj") or not self.usb_watcher_obj:
                def handle_usb_report(report):
                    # Inject findings into results tab so they show up in main lists
                    results = self.state.get("scan_results", [])
                    for finding in report.all_findings:
                        results = [r for r in results if r["file_path"] != finding["file_path"]]
                        results.append(finding)
                    self.state["scan_results"] = results
                    self.results_tab.refresh_results()
                    
                self.usb_watcher_obj = USBWatcher(
                    self.state, 
                    on_report_callback=handle_usb_report,
                    on_event_callback=self.comms_tab.log_event
                )
                self.usb_watcher_obj.start()
                print("USB Watcher active.")
        else:
            if hasattr(self, "usb_watcher_obj") and self.usb_watcher_obj:
                self.usb_watcher_obj.stop()
                self.usb_watcher_obj = None
                print("USB Watcher deactivated.")

        # Webmail Scan HTTP Server control
        if enable_webmail:
            if not hasattr(self, "webmail_server_obj") or not self.webmail_server_obj:
                try:
                    self.webmail_server_obj = DataShieldHTTPServer(self.state, on_event_callback=self.comms_tab.log_event)
                    self.webmail_server_obj.start()
                    print("Webmail scan HTTP API active on port 5000.")
                except Exception as e:
                    self.webmail_server_obj = None
                    self.state["enable_webmail_monitor"] = False
                    self.comms_tab.webmail_chk_var.set(False)
                    messagebox.showerror("Webmail API Error", f"Failed to start HTTP scan API on port 5000. The port might be in use by another application.\nError: {e}")
        else:
            if hasattr(self, "webmail_server_obj") and self.webmail_server_obj:
                self.webmail_server_obj.stop()
                self.webmail_server_obj = None
                print("Webmail scan HTTP API deactivated.")

    def on_close(self):
        """Stops all running background threads before destroying GUI to prevent hangs."""
        print("Stopping background daemons...")
        self.state["enable_smtp_monitor"] = False
        self.state["enable_clipboard_monitor"] = False
        self.state["enable_usb_monitor"] = False
        self.state["enable_webmail_monitor"] = False
        if hasattr(self, "comms_tab"):
            self.toggle_comms_daemons()
        self.destroy()

    def on_tab_changed(self, event):
        if hasattr(self, "report_tab"):
            selected_index = self.notebook.index("current")
            report_index = self.notebook.index(self.report_tab)
            if selected_index == report_index:
                self.report_tab.update_report_stats()


    def create_settings_tab(self) -> ttk.Frame:
        """Builds settings panel for API key, allowlist, SMTP, and custom rules."""
        tab = ttk.Frame(self.notebook)
        
        tab.columnconfigure(0, weight=1)
        tab.columnconfigure(1, weight=1)
        
        # --- Left Column Settings ---
        left_frame = ttk.Frame(tab)
        left_frame.grid(row=0, column=0, padx=15, pady=10, sticky="nsew")
        left_frame.columnconfigure(0, weight=1)

        # 1. API Credentials Frame
        api_frame = ttk.LabelFrame(left_frame, text=" Gemini API Settings ")
        api_frame.grid(row=0, column=0, pady=5, sticky="ew")
        api_frame.columnconfigure(1, weight=1)

        ttk.Label(api_frame, text="Gemini API Key:").grid(row=0, column=0, padx=5, pady=10, sticky="w")
        self.api_key_var = tk.StringVar(value=self.state["gemini_api_key"])
        self.entry_api = ttk.Entry(api_frame, textvariable=self.api_key_var, show="*")
        self.entry_api.grid(row=0, column=1, padx=5, pady=10, sticky="ew")

        # 2. Custom Rules Selection Frame
        rules_frame = ttk.LabelFrame(left_frame, text=" Custom Rules YAML ")
        rules_frame.grid(row=1, column=0, pady=10, sticky="ew")
        rules_frame.columnconfigure(1, weight=1)

        self.custom_rules_var = tk.StringVar(value="")
        self.entry_rules = ttk.Entry(rules_frame, textvariable=self.custom_rules_var, state="readonly")
        self.entry_rules.grid(row=0, column=0, columnspan=2, padx=5, pady=10, sticky="ew")
        
        btn_rules_picker = ttk.Button(rules_frame, text="Load Rules...", command=self.load_custom_rules)
        btn_rules_picker.grid(row=0, column=2, padx=5, pady=10, sticky="e")

        # 3. SMTP Server settings
        smtp_frame = ttk.LabelFrame(left_frame, text=" SMTP Email Alert Alerts ")
        smtp_frame.grid(row=2, column=0, pady=5, sticky="ew")
        smtp_frame.columnconfigure(1, weight=1)

        # Fields: host, port, sender, recipient
        ttk.Label(smtp_frame, text="SMTP Host:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.smtp_host_var = tk.StringVar()
        ttk.Entry(smtp_frame, textvariable=self.smtp_host_var).grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(smtp_frame, text="SMTP Port:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.smtp_port_var = tk.StringVar(value="25")
        ttk.Entry(smtp_frame, textvariable=self.smtp_port_var).grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(smtp_frame, text="Sender email:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.smtp_sender_var = tk.StringVar(value="datashield-alerts@security.local")
        ttk.Entry(smtp_frame, textvariable=self.smtp_sender_var).grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(smtp_frame, text="Recipient:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.smtp_recip_var = tk.StringVar()
        ttk.Entry(smtp_frame, textvariable=self.smtp_recip_var).grid(row=3, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(smtp_frame, text="Username:").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.smtp_user_var = tk.StringVar()
        ttk.Entry(smtp_frame, textvariable=self.smtp_user_var).grid(row=4, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(smtp_frame, text="Password:").grid(row=5, column=0, padx=5, pady=5, sticky="w")
        self.smtp_pass_var = tk.StringVar()
        ttk.Entry(smtp_frame, textvariable=self.smtp_pass_var, show="*").grid(row=5, column=1, padx=5, pady=5, sticky="ew")

        # --- Right Column Settings (Allowlist Editor) ---
        right_frame = ttk.LabelFrame(tab, text=" Allowlist Suppression (One rule/value per line) ")
        right_frame.grid(row=0, column=1, rowspan=4, padx=15, pady=15, sticky="nsew")
        right_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(0, weight=1)

        self.allowlist_textbox = tk.Text(
            right_frame, background="#030712", foreground="#e2e8f0", 
            insertbackground="white", font=("Consolas", 10)
        )
        self.allowlist_textbox.grid(row=0, column=0, sticky="nsew")
        
        # Load existing allowlist values into text editor
        self.refresh_allowlist_editor()

        # Save Button at the bottom
        btn_save = ttk.Button(tab, text="Apply & Save Settings", command=self.save_settings)
        btn_save.grid(row=3, column=0, columnspan=2, pady=15)

        return tab

    def load_custom_rules(self):
        rules_file = filedialog.askopenfilename(
            filetypes=[("YAML Files", "*.yaml;*.yml"), ("All Files", "*.*")],
            title="Load Custom DLP Rules"
        )
        if rules_file:
            self.custom_rules_var.set(rules_file)
            self.state["custom_rules_path"] = rules_file
            messagebox.showinfo("Rules Configured", f"Loaded custom rules from:\n{os.path.basename(rules_file)}")

    def refresh_allowlist_editor(self):
        self.allowlist_textbox.delete("1.0", "end")
        if os.path.exists(self.allowlist_path):
            try:
                with open(self.allowlist_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data and "allowlist" in data:
                        for item in data["allowlist"]:
                            self.allowlist_textbox.insert("end", f"{item}\n")
            except Exception as e:
                print(f"Warning: Failed to load allowlist to editor: {e}")

    def save_settings(self):
        # 1. Save API Key in memory
        self.state["gemini_api_key"] = self.api_key_var.get().strip()

        # 2. Parse and save allowlist back to yaml
        allowlist_raw = self.allowlist_textbox.get("1.0", "end").splitlines()
        allowlist_items = [line.strip() for line in allowlist_raw if line.strip()]

        try:
            os.makedirs(os.path.dirname(self.allowlist_path), exist_ok=True)
            with open(self.allowlist_path, "w", encoding="utf-8") as f:
                yaml.dump({"allowlist": allowlist_items}, f, default_flow_style=False)
            
            # Reload policies
            self.state["policy_manager"].load_allowlist(str(self.allowlist_path))
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save allowlist to disk: {e}")
            return

        # 3. Save SMTP Server configs
        host = self.smtp_host_var.get().strip()
        port = self.smtp_port_var.get().strip()
        sender = self.smtp_sender_var.get().strip()
        recip = self.smtp_recip_var.get().strip()
        username = self.smtp_user_var.get().strip()
        password = self.smtp_pass_var.get().strip()

        if host or recip:
            self.state["smtp_config"] = {
                "host": host,
                "port": port,
                "sender": sender,
                "recipient": recip,
                "username": username,
                "password": password
            }
        else:
            self.state["smtp_config"] = {}

        self.state["audit_logger"].log("SETTINGS_UPDATED", {
            "custom_rules": os.path.basename(self.state["custom_rules_path"]) if self.state["custom_rules_path"] else "Default",
            "allowlist_entries_count": len(allowlist_items),
            "email_alerts_configured": bool(self.state["smtp_config"])
        })

        messagebox.showinfo("Settings Saved", "All configurations applied and database rules reloaded successfully!")
