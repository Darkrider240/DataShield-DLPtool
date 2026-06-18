import os
import webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

# Import DataShield reporter
import reporter

class ResultsTab(ttk.Frame):
    """
    ResultsTab displays scan summaries (HIGH/MED/LOW/CLEAN cards),
    a detailed treeview of scanned file risks, an inspector panel showing
    individual matches and AI explanations, and report export options.
    """
    def __init__(self, parent, state):
        super().__init__(parent)
        self.state = state  # Dictionary containing shared state from parent window
        self.selected_file_result = None
        
        self.create_widgets()

    def create_widgets(self):
        # Configure layout rows/cols
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=3) # Treeview
        self.rowconfigure(2, weight=2) # Detail Panel

        # 1. Summary Cards Panel (Top)
        summary_frame = ttk.Frame(self, padding=10)
        summary_frame.grid(row=0, column=0, sticky="ew")
        
        # Configure card layout columns
        for col in range(4):
            summary_frame.columnconfigure(col, weight=1)

        # Style cards
        card_font = ("Segoe UI", 11, "bold")
        stat_font = ("Segoe UI", 18, "bold")

        # High Card
        self.card_high_lbl = tk.Label(
            summary_frame, text="0\nHIGH", font=stat_font, bg="#7f1d1d", fg="#fca5a5", 
            relief="solid", borderwidth=1, padx=10, pady=10
        )
        self.card_high_lbl.grid(row=0, column=0, padx=5, sticky="ew")

        # Medium Card
        self.card_med_lbl = tk.Label(
            summary_frame, text="0\nMEDIUM", font=stat_font, bg="#78350f", fg="#fde047", 
            relief="solid", borderwidth=1, padx=10, pady=10
        )
        self.card_med_lbl.grid(row=0, column=1, padx=5, sticky="ew")

        # Low Card
        self.card_low_lbl = tk.Label(
            summary_frame, text="0\nLOW", font=stat_font, bg="#14532d", fg="#86efac", 
            relief="solid", borderwidth=1, padx=10, pady=10
        )
        self.card_low_lbl.grid(row=0, column=2, padx=5, sticky="ew")

        # Clean Card
        self.card_clean_lbl = tk.Label(
            summary_frame, text="0\nCLEAN", font=stat_font, bg="#334155", fg="#cbd5e1", 
            relief="solid", borderwidth=1, padx=10, pady=10
        )
        self.card_clean_lbl.grid(row=0, column=3, padx=5, sticky="ew")

        # 2. Results Table Frame
        table_frame = ttk.LabelFrame(self, text=" Assessment Scans Results ", padding=10)
        table_frame.grid(row=1, column=0, padx=15, pady=5, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        # Treeview setup
        cols = ("file", "level", "score", "matches", "top_reg")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.tree.grid(row=0, column=0, sticky="nsew")

        # Tree columns layout
        self.tree.heading("file", text="Scanned File Path")
        self.tree.heading("level", text="Risk Level")
        self.tree.heading("score", text="Score")
        self.tree.heading("matches", text="Matches")
        self.tree.heading("top_reg", text="Primary Regulation")

        self.tree.column("file", anchor="w", width=350)
        self.tree.column("level", anchor="center", width=120)
        self.tree.column("score", anchor="center", width=80)
        self.tree.column("matches", anchor="center", width=80)
        self.tree.column("top_reg", anchor="w", width=180)

        # Tree scrollbars
        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scroll_y.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scroll_y.set)

        self.tree.bind("<<TreeviewSelect>>", self.on_row_selected)

        # 3. Details Panel Frame
        detail_frame = ttk.LabelFrame(self, text=" Violation Details & compliance Guidance ", padding=10)
        detail_frame.grid(row=2, column=0, padx=15, pady=5, sticky="nsew")
        detail_frame.columnconfigure(0, weight=1)
        detail_frame.rowconfigure(0, weight=1)

        self.detail_text = tk.Text(
            detail_frame, state="disabled", background="#0f172a", foreground="#f8fafc",
            insertbackground="white", font=("Consolas", 9), wrap="word"
        )
        self.detail_text.grid(row=0, column=0, sticky="nsew")

        scroll_detail = ttk.Scrollbar(detail_frame, orient="vertical", command=self.detail_text.yview)
        scroll_detail.grid(row=0, column=1, sticky="ns")
        self.detail_text.configure(yscrollcommand=scroll_detail.set)

        # Tags for colored logging in detail text
        self.detail_text.tag_configure("header", font=("Consolas", 10, "bold"), foreground="#a78bfa")
        self.detail_text.tag_configure("highlight", foreground="#ef4444")
        self.detail_text.tag_configure("context", foreground="#10b981")
        self.detail_text.tag_configure("ai_section", foreground="#c084fc")
        self.detail_text.tag_configure("regulation", foreground="#3b82f6")

    def refresh_results(self):
        """Refreshes tree table and cards using latest state results."""
        results = self.state.get("scan_results", [])
        
        # Calculate card metrics
        high = sum(1 for r in results if r["risk_level"] == "HIGH")
        med = sum(1 for r in results if r["risk_level"] == "MEDIUM")
        low = sum(1 for r in results if r["risk_level"] == "LOW")
        clean = sum(1 for r in results if r["risk_level"] == "CLEAN")

        # Update labels thread-safely
        def update():
            self.card_high_lbl.configure(text=f"{high}\nHIGH")
            self.card_med_lbl.configure(text=f"{med}\nMEDIUM")
            self.card_low_lbl.configure(text=f"{low}\nLOW")
            self.card_clean_lbl.configure(text=f"{clean}\nCLEAN")

            # Clear old rows in tree
            for item in self.tree.get_children():
                self.tree.delete(item)

            # Insert new rows
            for res in results:
                filepath = res["file_path"]
                level = f"{res['risk_level']} ({res['risk_label']})"
                score = res["risk_score"]
                matches = res["match_count"]
                
                # Check for file extension mismatch warning
                if res.get("file_type_mismatch"):
                    level = "⚠️ MISMATCH / " + level
                    
                top_reg = res["regulation_hits"][0] if res["regulation_hits"] else "None"

                self.tree.insert("", "end", values=(filepath, level, score, matches, top_reg))
        
        self.master.after(0, update)

    def on_row_selected(self, event):
        selected = self.tree.selection()
        if not selected:
            return
            
        # Get selected row items
        values = self.tree.item(selected[0], "values")
        if not values:
            return
            
        target_path = values[0]
        # Clean warning prefix from path lookup if present
        if target_path.startswith("⚠️"):
            target_path = target_path.replace("⚠️ MISMATCH / ", "")

        results = self.state.get("scan_results", [])
        # Find exact result dict matching this file path
        result_dict = next((r for r in results if r["file_path"] == target_path or Path(r["file_path"]).name == Path(target_path).name), None)
        
        if result_dict:
            self.selected_file_result = result_dict
            self.display_findings(result_dict)

    def display_findings(self, res):
        """Renders match summaries, context lines, and Gemini answers in the details box."""
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")

        self.detail_text.insert("end", f"FILE PROFILE ASSESSMENT\n", "header")
        self.detail_text.insert("end", f"Path: {res['file_path']}\n")
        self.detail_text.insert("end", f"Risk Level: {res['risk_level']} ({res['risk_label']}) | Score: {res['risk_score']} | Violations: {res['match_count']}\n")
        if res.get("file_type_mismatch"):
            self.detail_text.insert("end", f"⚠️ CRITICAL WARNING: File extension does not match binary magic byte signature!\n", "highlight")
        self.detail_text.insert("end", "="*70 + "\n\n")

        if not res["top_matches"]:
            self.detail_text.insert("end", "Status: CLEAN. No sensitive text patterns or high-entropy anomalies detected.\n", "context")
        else:
            for idx, m in enumerate(res["top_matches"]):
                self.detail_text.insert("end", f"Match #{idx+1}: {m.pattern_name} in {m.category}\n", "header")
                self.detail_text.insert("end", f"  Line: {m.line_number} | Base Weight: {m.base_weight} ")
                if m.proximity_triggered:
                    self.detail_text.insert("end", f"(Proximity doubled)", "highlight")
                self.detail_text.insert("end", f"\n  Matched String (Redacted): {m.matched_value}\n")
                self.detail_text.insert("end", f"  Regulations Triggered: {', '.join(m.regulation_tags)}\n")
                
                # Context lines
                self.detail_text.insert("end", "  Context Lines:\n")
                for line in m.context_lines:
                    self.detail_text.insert("end", f"    > {line}\n", "context")
                self.detail_text.insert("end", "-"*50 + "\n")

            # AI compliance paragraph (if generated)
            if res.get("ai_explanation"):
                self.detail_text.insert("end", "\n[GEMINI COMPLIANCE AUDIT ANALYSIS]\n", "ai_section")
                self.detail_text.insert("end", res["ai_explanation"] + "\n")

        self.detail_text.configure(state="disabled")

    def export_html(self):
        results = self.state.get("scan_results")
        if not results:
            messagebox.showerror("Export Error", "No scan results available to export.")
            return

        dest = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Report", "*.html")],
            title="Export HTML Assessment Report"
        )
        if dest:
            try:
                # Retrieve last log hash from audit
                last_hash = self.state["audit_logger"]._get_last_hash()
                reporter.generate_html_report(results, 0.0, last_hash, dest)
                messagebox.showinfo("Export Success", f"HTML report successfully written to:\n{dest}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to generate report: {e}")

    def export_csv(self):
        results = self.state.get("scan_results")
        if not results:
            messagebox.showerror("Export Error", "No scan results available to export.")
            return

        dest = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV File", "*.csv")],
            title="Export CSV Metadata Table"
        )
        if dest:
            try:
                reporter.export_csv_report(results, dest)
                messagebox.showinfo("Export Success", f"CSV metadata successfully exported to:\n{dest}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export CSV: {e}")

    def open_in_browser(self):
        results = self.state.get("scan_results")
        if not results:
            messagebox.showerror("Report Error", "No scan results available to view.")
            return
            
        target_dir = self.state.get("scan_directory")
        if not target_dir:
            target_dir = "."
            
        temp_dir = os.path.join(target_dir, "output")
        os.makedirs(temp_dir, exist_ok=True)
        report_path = os.path.join(temp_dir, "temp_report.html")
        
        try:
            last_hash = self.state["audit_logger"]._get_last_hash()
            reporter.generate_html_report(results, 0.0, last_hash, report_path)
            webbrowser.open("file://" + os.path.abspath(report_path))
        except Exception as e:
            messagebox.showerror("Browser Error", f"Failed to open report: {e}")
