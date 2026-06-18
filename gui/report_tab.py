import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import webbrowser

# Import DataShield modules
import reporter
import audit

class ReportTab(ttk.Frame):
    """
    ReportTab provides controls to export scan results to HTML/CSV,
    preview reports in the native web browser, view top-level stats,
    and trigger SHA-256 chain verification of the audit ledger.
    """
    def __init__(self, parent, state):
        super().__init__(parent)
        self.state = state  # Dictionary containing shared state from parent window
        
        self.create_widgets()

    def create_widgets(self):
        self.columnconfigure(0, weight=1)
        
        # 1. Report Export & Preview Actions Frame
        export_frame = ttk.LabelFrame(self, text=" Export Options ", padding=20)
        export_frame.grid(row=0, column=0, padx=15, pady=10, sticky="ew")
        
        ttk.Label(
            export_frame, 
            text="Generate detailed compliance assessment logs and download self-contained visual HTML dashboards:",
            wraplength=700
        ).pack(anchor="w", pady=(0, 15))

        btn_container = ttk.Frame(export_frame)
        btn_container.pack(fill="x")

        # HTML Button
        self.btn_export_html = ttk.Button(btn_container, text="Export HTML Report...", command=self.export_html)
        self.btn_export_html.pack(side="left", padx=5)

        # CSV Button
        self.btn_export_csv = ttk.Button(btn_container, text="Export CSV Metadata...", command=self.export_csv)
        self.btn_export_csv.pack(side="left", padx=5)

        # Browser View Button
        self.btn_open_browser = ttk.Button(btn_container, text="Open Report in Browser", command=self.open_in_browser)
        self.btn_open_browser.pack(side="left", padx=5)

        # 2. Audit Ledger Chaining Integrity Frame
        audit_frame = ttk.LabelFrame(self, text=" Tamper-Evident Ledger Integrity ", padding=20)
        audit_frame.grid(row=1, column=0, padx=15, pady=10, sticky="ew")

        ttk.Label(
            audit_frame,
            text="Each file scan operation triggers a chained hash block inside the audit ledger. "
                 "Run ledger verification below to guarantee that records have not been altered or deleted:",
            wraplength=700
        ).pack(anchor="w", pady=(0, 15))

        audit_btn_container = ttk.Frame(audit_frame)
        audit_btn_container.pack(fill="x", pady=5)

        btn_verify = ttk.Button(audit_btn_container, text="Verify Audit Ledger Chain", command=self.run_audit_verification)
        btn_verify.pack(side="left", padx=5)

        self.lbl_verification_status = ttk.Label(
            audit_frame, 
            text="Ledger Status: Unknown (Execute verification to audit status)", 
            font=("Segoe UI", 10, "italic"),
            foreground="#94a3b8"
        )
        self.lbl_verification_status.pack(anchor="w", pady=(15, 0))

        # 3. High-level Summary statistics display
        stats_frame = ttk.LabelFrame(self, text=" Assessment Statistics Summary ", padding=20)
        stats_frame.grid(row=2, column=0, padx=15, pady=10, sticky="ew")

        self.stats_text = tk.Text(
            stats_frame, height=8, state="disabled", background="#030712",
            foreground="#f8fafc", font=("Consolas", 10), wrap="word", borderwidth=1
        )
        self.stats_text.pack(fill="both", expand=True)

    def update_report_stats(self):
        """Refreshes summary analytics inside the text window."""
        results = self.state.get("scan_results", [])
        total = len(results)
        
        high = sum(1 for r in results if r["risk_level"] == "HIGH")
        med = sum(1 for r in results if r["risk_level"] == "MEDIUM")
        low = sum(1 for r in results if r["risk_level"] == "LOW")
        clean = sum(1 for r in results if r["risk_level"] == "CLEAN")
        
        violations = sum(r["match_count"] for r in results)
        
        regs_list = []
        for r in results:
            regs_list.extend(r.get("regulation_hits", []))
        regs_unique = set(regs_list)

        stats_summary = (
            f"SUMMARY ASSESSMENTS METRICS\n"
            f"=========================================\n"
            f"Scanned Files count    : {total}\n"
            f"Threat Detections      : {violations} individual patterns matches\n"
            f"High-Risk violations   : {high} (Action Required)\n"
            f"Medium-Risk violations : {med}\n"
            f"Low-Risk violations    : {low}\n"
            f"Clean files            : {clean}\n"
            f"Regulations triggered  : {len(regs_unique)} unique frameworks ({', '.join(regs_unique) if regs_unique else 'None'})\n"
        )

        def update():
            self.stats_text.configure(state="normal")
            self.stats_text.delete("1.0", "end")
            self.stats_text.insert("1.0", stats_summary)
            self.stats_text.configure(state="disabled")
        
        self.master.after(0, update)

    def export_html(self):
        # Delegate to results tab function
        if hasattr(self.master.master, "results_tab"):
            self.master.master.results_tab.export_html()

    def export_csv(self):
        # Delegate to results tab function
        if hasattr(self.master.master, "results_tab"):
            self.master.master.results_tab.export_csv()

    def open_in_browser(self):
        # Delegate to results tab function
        if hasattr(self.master.master, "results_tab"):
            self.master.master.results_tab.open_in_browser()

    def run_audit_verification(self):
        # Locate audit path from state logger
        logger_obj = self.state.get("audit_logger")
        if not logger_obj:
            messagebox.showerror("Verification Error", "Audit log has not been initialized.")
            return

        log_path = logger_obj.log_path
        if not os.path.exists(log_path):
            self.lbl_verification_status.configure(
                text="Ledger Status: Empty (No scan events registered yet)",
                foreground="#94a3b8"
            )
            return

        # Execute chain verification
        is_intact = audit.verify_chain(log_path)
        
        if is_intact:
            self.lbl_verification_status.configure(
                text="✅ LEDGER SECURED: Chain is intact. No database tampering or modifications detected.",
                foreground="#10b981"
            )
            messagebox.showinfo("Ledger Integrity Check", "Verification Succeeded!\nAll blocks are properly linked with valid cryptographic SHA-256 hashes.")
        else:
            self.lbl_verification_status.configure(
                text="❌ WARNING: Chain is broken. Audit ledger logs may have been modified or tampered with!",
                foreground="#ef4444"
            )
            messagebox.showerror("Ledger Integrity Check", "Verification Failed!\nWe detected a mismatch in block hashes or invalid linkage.")
