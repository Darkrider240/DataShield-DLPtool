import os
import time
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

# Import DataShield core components
import scanner
import behaviour
import classifier
import ai_explain
import quarantine
import alerts
import watcher
from policy import PolicyManager

class ScanTab(ttk.Frame):
    """
    ScanTab manages selecting folders, configuring real-time watch, auto-quarantine,
    running recursive folder scans asynchronously, and updating progress bars.
    """
    def __init__(self, parent, state):
        super().__init__(parent)
        self.state = state  # Dictionary containing shared state from parent window
        self.scan_thread = None
        self.watcher_obj = None
        
        self.create_widgets()

    def create_widgets(self):
        # Configure layout Grid columns
        self.columnconfigure(0, weight=1)
        
        # 1. Folder Selection Section
        folder_frame = ttk.LabelFrame(self, text=" Target Scan Directory ", padding=15)
        folder_frame.grid(row=0, column=0, padx=15, pady=10, sticky="ew")
        folder_frame.columnconfigure(1, weight=1)

        self.dir_var = tk.StringVar(value="")
        ttk.Label(folder_frame, text="Scan Location:").grid(row=0, column=0, padx=(0, 10), sticky="w")
        self.entry_dir = ttk.Entry(folder_frame, textvariable=self.dir_var, state="readonly")
        self.entry_dir.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        
        btn_browse = ttk.Button(folder_frame, text="Browse Folder...", command=self.browse_folder)
        btn_browse.grid(row=0, column=2, sticky="e")

        # 2. Scanner Configurations
        config_frame = ttk.LabelFrame(self, text=" Configuration & Settings ", padding=15)
        config_frame.grid(row=1, column=0, padx=15, pady=5, sticky="ew")

        self.watch_var = tk.BooleanVar(value=False)
        self.chk_watch = ttk.Checkbutton(
            config_frame, text="Enable Live Watch Mode (Watchdog)", 
            variable=self.watch_var, command=self.toggle_live_watch
        )
        self.chk_watch.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.quarantine_var = tk.BooleanVar(value=False)
        self.chk_quar = ttk.Checkbutton(
            config_frame, text="Enable Auto-Quarantine (High Risk Files)", 
            variable=self.quarantine_var, command=self.confirm_quarantine
        )
        self.chk_quar.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        self.ai_var = tk.BooleanVar(value=False)
        self.chk_ai = ttk.Checkbutton(
            config_frame, text="Enable Gemini AI Explanations", 
            variable=self.ai_var
        )
        self.chk_ai.grid(row=0, column=2, padx=10, pady=5, sticky="w")

        # 3. Actions Section
        action_frame = ttk.Frame(self, padding=10)
        action_frame.grid(row=2, column=0, padx=15, pady=5, sticky="ew")
        
        self.btn_scan = ttk.Button(action_frame, text="Start Full Scan", command=self.start_scan_thread)
        self.btn_scan.pack(side="left", padx=5)

        self.btn_stop = ttk.Button(action_frame, text="Stop Live Watch", command=self.stop_live_watch, state="disabled")
        self.btn_stop.pack(side="left", padx=5)

        # 4. Progress and Log Output
        log_frame = ttk.LabelFrame(self, text=" Live Scan Activity Logs ", padding=15)
        log_frame.grid(row=3, column=0, padx=15, pady=10, sticky="nsew")
        self.rowconfigure(3, weight=1)
        log_frame.rowconfigure(1, weight=1)
        log_frame.columnconfigure(0, weight=1)

        # Progress bar
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(log_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))

        self.progress_label = ttk.Label(log_frame, text="0 / 0 Files Scanned (0%)")
        self.progress_label.grid(row=0, column=1, sticky="e", pady=(0, 10))

        # Log Text Box
        self.log_text = tk.Text(log_frame, height=12, state="disabled", background="#030712", foreground="#10b981", insertbackground="white", font=("Consolas", 9))
        self.log_text.grid(row=1, column=0, sticky="nsew")
        
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scrollbar.set)

    def browse_folder(self):
        selected = filedialog.askdirectory()
        if selected:
            # Resolve absolute path
            resolved = str(Path(selected).resolve())
            self.dir_var.set(resolved)
            self.state["scan_directory"] = resolved
            self.log_message(f"Target directory selected: {resolved}")

    def confirm_quarantine(self):
        if self.quarantine_var.get():
            confirm = messagebox.askyesno(
                "Warning: Security Auto-Quarantine",
                "Enabling auto-quarantine will automatically move files identified as 'HIGH' risk into a local quarantine folder. "
                "Are you sure you want to enable this safeguard?"
            )
            if not confirm:
                self.quarantine_var.set(False)
            else:
                self.log_message("Auto-Quarantine enabled.")
        else:
            self.log_message("Auto-Quarantine disabled.")

    def log_message(self, message):
        """Thread-safe UI callback for appending logs."""
        def append():
            self.log_text.configure(state="normal")
            self.log_text.insert("end", f"[{time.strftime('%H:%M:%S')}] {message}\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        self.master.after(0, append)

    def update_progress(self, current, total):
        """Thread-safe UI callback for progress bar updates."""
        def update():
            percent = (current / total * 100) if total > 0 else 0
            self.progress_var.set(percent)
            self.progress_label.configure(text=f"{current} / {total} Files Scanned ({percent:.1f}%)")
        self.master.after(0, update)

    def start_scan_thread(self):
        target = self.state.get("scan_directory")
        if not target or not os.path.exists(target):
            messagebox.showerror("Scan Error", "Please select a valid target directory first.")
            return

        if self.state.get("is_scanning", False):
            return

        self.state["is_scanning"] = True
        self.btn_scan.configure(state="disabled")
        self.progress_var.set(0)
        self.log_message("--- Full Scan Started ---")

        # Refresh rules & allowlist from settings variables
        rules_path = self.state.get("custom_rules_path")
        self.state["policy_manager"] = PolicyManager(rules_path=rules_path)
        self.state["policy_manager"].load_allowlist(self.state.get("allowlist_path"))

        # Launch scanning thread
        self.scan_thread = threading.Thread(target=self.run_full_scan, daemon=True)
        self.scan_thread.start()

    def run_full_scan(self):
        start_time = time.time()
        target_dir = self.state["scan_directory"]
        
        # 1. Discover files
        files_to_scan = []
        for root, dirs, files in os.walk(target_dir):
            # Sandbox: skip directory if it is the quarantine folder
            if "quarantine" in Path(root).parts:
                continue
            for f in files:
                filepath = os.path.join(root, f)
                path_obj = Path(filepath)
                # Skip quarantine info sidecars and audit log itself
                if path_obj.name.endswith(".quarantine_info") or path_obj.name == "datashield_audit.log":
                    continue
                files_to_scan.append(filepath)

        total_files = len(files_to_scan)
        self.update_progress(0, total_files)

        # Audit start
        audit = self.state["audit_logger"]
        audit.log("SCAN_STARTED", {"target_directory": target_dir, "total_files": total_files})

        scanned_results = []
        high_threat_detected = False

        config = {
            "root_path": target_dir,
            "policy_manager": self.state["policy_manager"]
        }

        # 2. Iterate and Scan
        for idx, file in enumerate(files_to_scan):
            self.log_message(f"Scanning file: {os.path.basename(file)}")
            
            try:
                # Regex matching
                matches = scanner.scan_file(file, config)
                
                # Proximity multiplication
                matches = behaviour.proximity_multiplier(matches)
                
                # Shannon entropy analysis
                entropy_matches = behaviour.detect_high_entropy_strings(file)
                matches.extend(entropy_matches)
                
                # Magic byte extension checking
                mismatch = behaviour.detect_file_type_mismatch(file)
                
                # Risk scoring and classification
                file_report = classifier.classify_file(matches, file_path=file, file_type_mismatch=mismatch)
                
                # AI compliance generation (requires GEMINI_API_KEY)
                if file_report["risk_level"] != "CLEAN" and self.ai_var.get():
                    self.log_message(f"Generating AI Compliance Explanation for {os.path.basename(file)}...")
                    # Take top match for context explanation
                    if file_report["top_matches"]:
                        top_m = file_report["top_matches"][0]
                        explanation = ai_explain.explain_finding(top_m, file, api_key=self.state.get("gemini_api_key"))
                        file_report["ai_explanation"] = explanation
                
                # Auto-quarantine logic
                if file_report["risk_level"] == "HIGH" and self.quarantine_var.get():
                    self.log_message(f"⚠️ HIGH risk detected! Quarantining: {os.path.basename(file)}")
                    q_dir = os.path.join(target_dir, "quarantine")
                    triggered_patterns = [m.pattern_name for m in file_report["top_matches"]]
                    
                    new_path = quarantine.quarantine_file(file, q_dir, audit, triggered_patterns)
                    file_report["file_path"] = new_path
                    self.log_message(f"Relocated to: {os.path.basename(new_path)}")
                    
                    # Desktop notifications for quarantine
                    alerts.send_desktop_notification(
                        "DLP Threat Quarantined",
                        f"High-risk file {os.path.basename(file)} moved to quarantine."
                    )
                elif file_report["risk_level"] == "HIGH" or file_report["risk_level"] == "MEDIUM":
                    high_threat_detected = True
                    # Desktop notifications
                    alerts.send_desktop_notification(
                        "DLP Incident Alert",
                        f"Risk {file_report['risk_level']} detected in {os.path.basename(file)}!"
                    )

                scanned_results.append(file_report)
                audit.log("FILE_SCANNED", {
                    "file_path": file,
                    "risk_level": file_report["risk_level"],
                    "risk_score": file_report["risk_score"],
                    "matches_count": file_report["match_count"]
                })
                
            except Exception as e:
                self.log_message(f"Error scanning {os.path.basename(file)}: {e}")

            self.update_progress(idx + 1, total_files)

        duration = time.time() - start_time
        self.state["scan_results"] = scanned_results
        self.state["is_scanning"] = False
        
        # Email alerts dispatcher (if threat found and configured)
        if high_threat_detected and self.state.get("smtp_config"):
            smtp_cfg = self.state["smtp_config"]
            alerts.send_email_alert(
                smtp_cfg, 
                "DataShield Alert — Security Incident Detected",
                f"DataShield v2 scanner identified sensitive information violations inside target: {target_dir}. "
                "Please review the exported assessment report."
            )

        self.log_message(f"--- Full Scan Completed in {duration:.2f}s ---")
        
        # Notify Results Tab to refresh trees
        if hasattr(self.master.master, "results_tab"):
            self.master.master.results_tab.refresh_results()

        # Unlock Scan Button
        self.master.after(0, lambda: self.btn_scan.configure(state="normal"))

    def toggle_live_watch(self):
        if self.watch_var.get():
            target = self.state.get("scan_directory")
            if not target or not os.path.exists(target):
                messagebox.showerror("Watchdog Error", "Please browse and select a valid directory to watch.")
                self.watch_var.set(False)
                return
            
            # Start Watchdog
            self.log_message(f"Initializing live monitoring on: {target}")
            self.watcher_obj = watcher.DLPWatcher(
                target, self.handle_incremental_change, 
                quarantine_name="quarantine", audit_name="datashield_audit.log"
            )
            self.watcher_obj.start()
            self.btn_stop.configure(state="normal")
            self.log_message("Live Watch Mode active.")
        else:
            self.stop_live_watch()

    def handle_incremental_change(self, filepath):
        self.log_message(f"Change detected: {os.path.basename(filepath)}")
        
        # Incremental Scan
        target_dir = self.state["scan_directory"]
        config = {
            "root_path": target_dir,
            "policy_manager": self.state["policy_manager"]
        }
        
        try:
            # Run scan
            matches = scanner.scan_file(filepath, config)
            matches = behaviour.proximity_multiplier(matches)
            entropy_matches = behaviour.detect_high_entropy_strings(filepath)
            matches.extend(entropy_matches)
            mismatch = behaviour.detect_file_type_mismatch(filepath)
            file_report = classifier.classify_file(matches, file_path=filepath, file_type_mismatch=mismatch)
            
            # AI
            if file_report["risk_level"] != "CLEAN" and self.ai_var.get():
                if file_report["top_matches"]:
                    file_report["ai_explanation"] = ai_explain.explain_finding(
                        file_report["top_matches"][0], filepath, api_key=self.state.get("gemini_api_key")
                    )

            # Auto-quarantine
            if file_report["risk_level"] == "HIGH" and self.quarantine_var.get():
                self.log_message(f"⚠️ Action: Auto-Quarantining modified file: {os.path.basename(filepath)}")
                q_dir = os.path.join(target_dir, "quarantine")
                triggered_patterns = [m.pattern_name for m in file_report["top_matches"]]
                
                new_path = quarantine.quarantine_file(filepath, q_dir, self.state["audit_logger"], triggered_patterns)
                file_report["file_path"] = new_path
                self.log_message(f"Moved to: {os.path.basename(new_path)}")
                
                alerts.send_desktop_notification(
                    "DLP Incremental Threat Quarantined",
                    f"High-risk file {os.path.basename(filepath)} moved to quarantine."
                )
            elif file_report["risk_level"] == "HIGH" or file_report["risk_level"] == "MEDIUM":
                alerts.send_desktop_notification(
                    "DLP Incremental Alert",
                    f"Risk {file_report['risk_level']} detected in modified file!"
                )

            # Merge or replace report results in state list
            results = self.state.get("scan_results", [])
            
            # Remove old report for this file if present
            results = [r for r in results if r["file_path"] != filepath]
            results.append(file_report)
            self.state["scan_results"] = results
            
            self.state["audit_logger"].log("FILE_SCANNED", {
                "file_path": filepath,
                "risk_level": file_report["risk_level"],
                "risk_score": file_report["risk_score"],
                "matches_count": file_report["match_count"]
            })
            
            # Refresh tree views
            if hasattr(self.master.master, "results_tab"):
                self.master.master.results_tab.refresh_results()
                
        except Exception as e:
            self.log_message(f"Error during incremental scan: {e}")

    def stop_live_watch(self):
        if self.watcher_obj:
            self.watcher_obj.stop()
            self.watcher_obj = None
            self.watch_var.set(False)
            self.btn_stop.configure(state="disabled")
            self.log_message("Live Watch Mode stopped.")
