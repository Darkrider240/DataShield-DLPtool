import os
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

# Import DataShield reporter
import reporter

class CommsTab(ttk.Frame):
    """
    CommsTab handles controls for email (SMTP), clipboard, and USB monitoring.
    Contains stats cards, a real-time color-coded event log, and report export buttons.
    """
    def __init__(self, parent, state):
        super().__init__(parent)
        self.state = state
        self.state["comms_events"] = []  # List to hold communication DLP logs
        
        # Default settings configurations
        self.state["enable_smtp_monitor"] = False
        self.state["enable_clipboard_monitor"] = False
        self.state["enable_usb_monitor"] = False
        self.state["enable_webmail_monitor"] = False
        self.state["enable_justification_bypass"] = True

        self.create_widgets()

    def create_widgets(self):
        # Grid layout
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1) # Log feed
        self.rowconfigure(1, weight=0) # Stats
        self.rowconfigure(2, weight=0) # Controls

        # 1. Real-time Event Feed (Top)
        feed_frame = ttk.LabelFrame(self, text=" Outbound Interceptions Live Feed ", padding=10)
        feed_frame.grid(row=0, column=0, padx=15, pady=5, sticky="nsew")
        self.rowconfigure(0, weight=3)
        feed_frame.columnconfigure(0, weight=1)
        feed_frame.rowconfigure(0, weight=1)

        self.log_text = tk.Text(
            feed_frame, height=12, state="disabled", background="#030712",
            foreground="#f8fafc", insertbackground="white", font=("Consolas", 9), wrap="word"
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")

        scroll_feed = ttk.Scrollbar(feed_frame, orient="vertical", command=self.log_text.yview)
        scroll_feed.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scroll_feed.set)

        # Style tags for color-coding logs
        self.log_text.tag_configure("BLOCK", foreground="#ef4444", font=("Consolas", 9, "bold"))
        self.log_text.tag_configure("WARN", foreground="#f59e0b", font=("Consolas", 9, "bold"))
        self.log_text.tag_configure("ALLOW", foreground="#10b981")
        self.log_text.tag_configure("timestamp", foreground="#94a3b8")

        # 2. Stats cards (Middle)
        stats_frame = ttk.Frame(self, padding=5)
        stats_frame.grid(row=1, column=0, padx=15, pady=5, sticky="ew")
        for col in range(4):
            stats_frame.columnconfigure(col, weight=1)

        stat_font = ("Segoe UI", 16, "bold")

        self.card_intercept = tk.Label(stats_frame, text="0\nINTERCEPTED", font=stat_font, bg="#334155", fg="#cbd5e1", relief="solid", borderwidth=1, pady=8)
        self.card_intercept.grid(row=0, column=0, padx=5, sticky="ew")

        self.card_email_block = tk.Label(stats_frame, text="0\nEMAILS BLOCKED", font=stat_font, bg="#7f1d1d", fg="#fca5a5", relief="solid", borderwidth=1, pady=8)
        self.card_email_block.grid(row=0, column=1, padx=5, sticky="ew")

        self.card_clip_clear = tk.Label(stats_frame, text="0\nCLIPBOARD CLEARS", font=stat_font, bg="#78350f", fg="#fde047", relief="solid", borderwidth=1, pady=8)
        self.card_clip_clear.grid(row=0, column=2, padx=5, sticky="ew")

        self.card_usb_scan = tk.Label(stats_frame, text="0\nUSB SCANS", font=stat_font, bg="#14532d", fg="#86efac", relief="solid", borderwidth=1, pady=8)
        self.card_usb_scan.grid(row=0, column=3, padx=5, sticky="ew")

        # 3. Controls and Settings Section (Bottom)
        ctrl_frame = ttk.LabelFrame(self, text=" Module Controls & Channels ", padding=10)
        ctrl_frame.grid(row=2, column=0, padx=15, pady=10, sticky="ew")
        ctrl_frame.columnconfigure(0, weight=1)
        ctrl_frame.columnconfigure(1, weight=1)

        chk_container = ttk.Frame(ctrl_frame)
        chk_container.grid(row=0, column=0, sticky="w")

        # Checkbuttons mapping to triggers
        self.smtp_chk_var = tk.BooleanVar(value=False)
        self.chk_smtp = ttk.Checkbutton(
            chk_container, text="Monitor Outbound Email (SMTP Proxy port 1025)", 
            variable=self.smtp_chk_var, command=self.apply_controls
        )
        self.chk_smtp.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.clip_chk_var = tk.BooleanVar(value=False)
        self.chk_clip = ttk.Checkbutton(
            chk_container, text="Monitor Clipboard Changes", 
            variable=self.clip_chk_var, command=self.apply_controls
        )
        self.chk_clip.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        self.usb_chk_var = tk.BooleanVar(value=False)
        self.chk_usb = ttk.Checkbutton(
            chk_container, text="Monitor USB Drive Connections", 
            variable=self.usb_chk_var, command=self.apply_controls
        )
        self.chk_usb.grid(row=2, column=0, padx=10, pady=5, sticky="w")

        self.webmail_chk_var = tk.BooleanVar(value=False)
        self.chk_webmail = ttk.Checkbutton(
            chk_container, text="Monitor Webmail (Chrome/Edge Extension API port 5000)", 
            variable=self.webmail_chk_var, command=self.apply_controls
        )
        self.chk_webmail.grid(row=3, column=0, padx=10, pady=5, sticky="w")

        self.justification_chk_var = tk.BooleanVar(value=True)
        self.chk_just = ttk.Checkbutton(
            chk_container, text="Allow Justification Dialog for Warning (Medium Risk)", 
            variable=self.justification_chk_var, command=self.apply_controls
        )
        self.chk_just.grid(row=4, column=0, padx=10, pady=5, sticky="w")

        # Export Report side panel
        export_container = ttk.Frame(ctrl_frame)
        export_container.grid(row=0, column=1, rowspan=5, sticky="nsew", padx=20)
        
        ttk.Label(
            export_container, text="Download communications specific DLP assessment report logs:", 
            wraplength=280
        ).pack(anchor="w", pady=(5, 15))

        btn_export = ttk.Button(export_container, text="Export Comms Report...", command=self.export_comms_report)
        btn_export.pack(anchor="w")

    def apply_controls(self):
        """Saves configuration variables to shared state dictionary."""
        self.state["enable_smtp_monitor"] = self.smtp_chk_var.get()
        self.state["enable_clipboard_monitor"] = self.clip_chk_var.get()
        self.state["enable_usb_monitor"] = self.usb_chk_var.get()
        self.state["enable_webmail_monitor"] = self.webmail_chk_var.get()
        self.state["enable_justification_bypass"] = self.justification_chk_var.get()

        # Log change to audit ledger
        self.state["audit_logger"].log("COMMS_POLICY_UPDATED", {
            "smtp_monitor": self.state["enable_smtp_monitor"],
            "clipboard_monitor": self.state["enable_clipboard_monitor"],
            "usb_monitor": self.state["enable_usb_monitor"],
            "webmail_monitor": self.state["enable_webmail_monitor"],
            "allow_justification": self.state["enable_justification_bypass"]
        })

        # Trigger main startup/shutdown logic for monitors
        main_win = self.master.master
        if hasattr(main_win, "toggle_comms_daemons"):
            main_win.toggle_comms_daemons()

    def log_event(self, channel, action, detail, decision=None):
        """
        Thread-safe callback to log communication DLP events,
        increment statistics, and color-code lines.
        """
        timestamp = time.strftime('%H:%M:%S')
        
        # Save event metadata to shared state for reports
        event_dict = {
            "timestamp": timestamp,
            "channel": channel,
            "action": action,  # "BLOCK" | "WARN" | "ALLOW"
            "detail": detail,
            "pattern": decision.top_pattern if decision else "None",
            "regulation_tags": decision.regulation_tags if decision else [],
            "ai_explanation": decision.ai_explanation if decision else ""
        }
        self.state["comms_events"].append(event_dict)

        # Reroute log to central server if client exists
        client = self.state.get("reporting_client")
        if client:
            if decision:
                classification_result = {
                    "risk_level": decision.risk_level,
                    "risk_score": decision.risk_score,
                    "file_path": decision.classification.get("file_path", "") if (hasattr(decision, "classification") and isinstance(decision.classification, dict)) else "",
                    "top_matches": decision.classification.get("top_matches", []) if (hasattr(decision, "classification") and isinstance(decision.classification, dict)) else [],
                    "regulation_hits": decision.regulation_tags,
                    "ai_explanation": decision.ai_explanation
                }
            else:
                classification_result = {
                    "risk_level": "MEDIUM" if action == "WARN" else ("HIGH" if action == "BLOCK" else "CLEAN"),
                    "risk_score": 4.0 if action == "WARN" else (10.0 if action == "BLOCK" else 0.0),
                    "file_path": detail,
                    "top_matches": [],
                    "regulation_hits": [],
                    "ai_explanation": ""
                }
            client.enqueue_event(classification_result, channel, action)

        # Renders the line in the GUI Text Feed
        def render():
            self.log_text.configure(state="normal")
            
            # Timestamp
            self.log_text.insert("end", f"[{timestamp}] ", "timestamp")
            # Channel
            self.log_text.insert("end", f"[{channel}] ")
            # Action (Color Tagged)
            self.log_text.insert("end", f"{action} — ", action)
            # Detail
            self.log_text.insert("end", f"{detail}\n")
            
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

            # Update stats metrics UI
            self.refresh_stats_ui()

        self.master.after(0, render)

    def refresh_stats_ui(self):
        """Recalculates count totals and updates stat label cards."""
        events = self.state["comms_events"]
        total = len(events)
        
        emails_blocked = sum(1 for e in events if e["channel"] in ["EMAIL", "WEBMAIL"] and e["action"] in ["BLOCK", "BLOCKED"])
        clipboard_clears = sum(1 for e in events if e["channel"] == "CLIPBOARD")
        usb_scans = sum(1 for e in events if e["channel"] == "USB" and "mounted" in e["detail"])

        self.card_intercept.configure(text=f"{total}\nINTERCEPTED")
        self.card_email_block.configure(text=f"{emails_blocked}\nEMAILS BLOCKED")
        self.card_clip_clear.configure(text=f"{clipboard_clears}\nCLIPBOARD CLEARS")
        self.card_usb_scan.configure(text=f"{usb_scans}\nUSB SCANS")

    def export_comms_report(self):
        events = self.state.get("comms_events", [])
        if not events:
            messagebox.showerror("Export Error", "No communications DLP events logged yet.")
            return

        dest = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Report", "*.html")],
            title="Export Communications DLP Report"
        )
        if dest:
            try:
                # Retrieve last log hash from audit
                last_hash = self.state["audit_logger"]._get_last_hash()
                
                # Render report.html specifically for comms events
                # Pass file_results as empty since this is a comms-only log report
                reporter.generate_html_report(
                    file_results=[], scan_duration=0.0, 
                    audit_hash=last_hash, output_path=dest, 
                    comms_events=events
                )
                messagebox.showinfo("Export Success", f"Comms report written to:\n{dest}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to generate report: {e}")
