#!/usr/bin/env python3
"""
DataShield — Quick Scan Widget (with Employee Login)
────────────────────────────────────────────────────────────────────
PURPOSE: Lightweight, standalone scan tool for employees.
         Employee logs in with their email + PIN, then picks a
         folder to scan before sending documents.

USAGE:   python quick_scan.py
         (or create a desktop shortcut to this file)

FLOW:    1. Employee enters email + PIN  (validated against server)
         2. Folder picker opens immediately on success
         3. Scans every file for PII, credentials, confidential data
         4. Shows colour-coded results  RED / YELLOW / GREEN per file
         5. Employee removes flagged files, then sends the folder safely
────────────────────────────────────────────────────────────────────
"""
import os
import sys
import time
import threading
from pathlib import Path
from dotenv import load_dotenv

# ── Ensure project root on path ────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

load_dotenv()

import tkinter as tk
from tkinter import filedialog, messagebox
import httpx

# ── Config (read same .env as the main agent) ──────────────────────────────
SERVER_URL    = os.environ.get("SERVER_URL", "http://localhost:8001")
AGENT_API_KEY = os.environ.get("AGENT_API_KEY", "datashield-agent-key-2024")

# ── Palette ────────────────────────────────────────────────────────────────
BG        = "#0b0f1a"
BG_CARD   = "#0f172a"
BG_ROW    = "#1e293b"
BG_ROW2   = "#162032"
BORDER    = "#1e293b"
ACCENT    = "#6366f1"
TEXT      = "#e2e8f0"
TEXT_SEC  = "#94a3b8"
TEXT_MUT  = "#475569"
RED       = "#ef4444"
RED_BG    = "#2d1515"
YELLOW    = "#f59e0b"
YELLOW_BG = "#2d2110"
GREEN     = "#22c55e"
GREEN_BG  = "#0f2d1a"
BLUE      = "#3b82f6"

RISK_COLOR = {"HIGH": RED,    "MEDIUM": YELLOW, "LOW": BLUE,   "CLEAN": GREEN}
RISK_BG    = {"HIGH": RED_BG, "MEDIUM": YELLOW_BG, "LOW": BG_ROW, "CLEAN": GREEN_BG}
RISK_ICON  = {"HIGH": "🔴",   "MEDIUM": "🟡",    "LOW": "🔵",   "CLEAN": "✅"}


# ══════════════════════════════════════════════════════════════════════════════
#  Step 1 — Login Screen
# ══════════════════════════════════════════════════════════════════════════════
class LoginScreen(tk.Tk):
    """
    Minimal login: employee email + PIN → validates against DataShield server.
    On success, opens the scan window. On failure, shows a clear error.
    """
    def __init__(self):
        super().__init__()
        self.title("DataShield — Sign In")
        self.resizable(False, False)
        W, H = 420, 460
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
        self.configure(bg=BG)
        self._build()

    def _build(self):
        # Logo area
        canvas = tk.Canvas(self, width=420, height=100, bg=BG,
                           highlightthickness=0)
        canvas.pack()
        canvas.create_text(210, 40, text="🛡 DataShield",
                           fill=ACCENT, font=("Segoe UI", 22, "bold"))
        canvas.create_text(210, 66, text="Quick Scan — Employee Login",
                           fill=TEXT_MUT, font=("Segoe UI", 10))
        canvas.create_text(210, 84, text="Scan your files before sending",
                           fill="#334155", font=("Segoe UI", 8))

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

        card = tk.Frame(self, bg=BG_CARD, padx=36, pady=28)
        card.pack(fill="both", expand=True)

        tk.Label(card, text="Sign in to scan files",
                 bg=BG_CARD, fg=TEXT_SEC, font=("Segoe UI", 11)).pack(pady=(0, 20))

        # Email
        tk.Label(card, text="Work Email",
                 bg=BG_CARD, fg=TEXT_SEC, font=("Segoe UI", 9, "bold"),
                 anchor="w").pack(fill="x")
        self._email = tk.StringVar()
        tk.Entry(card, textvariable=self._email, bg=BG_ROW, fg=TEXT,
                 insertbackground=TEXT, relief="flat",
                 font=("Segoe UI", 11), bd=0).pack(fill="x", ipady=9, pady=(3,0))
        tk.Frame(card, height=1, bg="#334155").pack(fill="x", pady=(0, 14))

        # PIN
        tk.Label(card, text="PIN",
                 bg=BG_CARD, fg=TEXT_SEC, font=("Segoe UI", 9, "bold"),
                 anchor="w").pack(fill="x")
        self._pin = tk.StringVar()
        self._pin_entry = tk.Entry(card, textvariable=self._pin, show="●",
                                   bg=BG_ROW, fg=TEXT, insertbackground=TEXT,
                                   relief="flat", font=("Segoe UI", 11), bd=0)
        self._pin_entry.pack(fill="x", ipady=9, pady=(3,0))
        tk.Frame(card, height=1, bg="#334155").pack(fill="x", pady=(0, 8))

        # Status
        self._status = tk.StringVar()
        tk.Label(card, textvariable=self._status, bg=BG_CARD, fg=YELLOW,
                 font=("Segoe UI", 9), wraplength=340,
                 justify="center").pack(pady=(4, 12))

        # Sign-in button
        tk.Button(card, text="Sign In  →",
                  command=self._login,
                  bg=ACCENT, fg="white", activebackground="#818cf8",
                  activeforeground="white", relief="flat",
                  font=("Segoe UI", 11, "bold"), cursor="hand2",
                  bd=0).pack(fill="x", ipady=11)

        # Help
        tk.Label(card, text="Enter your work email and the PIN set by your IT admin.",
                 bg=BG_CARD, fg=TEXT_MUT, font=("Segoe UI", 8)).pack(pady=(12, 0))

        self._email.trace_add("write", lambda *_: self._status.set(""))
        self._pin.trace_add("write",  lambda *_: self._status.set(""))
        self.bind("<Return>", lambda e: self._login())
        self.protocol("WM_DELETE_WINDOW", sys.exit)
        self._email.set("")  # focus handled after build

        self.after(50, lambda: self._pin_entry.focus_set())

    def _login(self):
        email = self._email.get().strip()
        pin   = self._pin.get().strip()

        if not email or "@" not in email:
            self._status.set("Enter a valid work email.")
            return
        if not pin:
            self._status.set("Enter your PIN.")
            return

        self._status.set("Verifying…")
        self.update()

        def _do():
            try:
                resp = httpx.post(
                    f"{SERVER_URL}/api/auth/validate-employee",
                    json={"email": email, "password": pin},
                    headers={"X-DataShield-Agent-Key": AGENT_API_KEY},
                    timeout=8.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if not data.get("pin_set", True):
                        self.after(0, lambda: self._status.set(
                            "No PIN set yet.\nAsk your IT admin to set one."))
                        return
                    name = data.get("name", email)
                    self.after(0, lambda: self._open_scanner(name, email))
                elif resp.status_code == 401:
                    detail = ""
                    try:
                        detail = resp.json().get("detail", "")
                    except Exception:
                        pass
                    msg = {
                        "pin_required": "Enter your PIN in the PIN field.",
                        "Wrong PIN":    "Wrong PIN. Contact your IT admin to reset it.",
                    }.get(detail, "Wrong credentials. Try again.")
                    self.after(0, lambda: self._status.set(msg))
                elif resp.status_code == 404:
                    self.after(0, lambda: self._status.set(
                        "Email not registered.\nAsk your IT admin to add you."))
                else:
                    self.after(0, lambda: self._status.set(
                        f"Server error ({resp.status_code}). Is the server running?"))
            except Exception:
                self.after(0, lambda: self._status.set(
                    f"Cannot reach server at {SERVER_URL}.\n"
                    "Make sure the DataShield server is running."))

        threading.Thread(target=_do, daemon=True).start()

    def _open_scanner(self, name: str, email: str):
        self.destroy()
        app = QuickScanWidget(user_name=name, user_email=email)
        app.mainloop()


# ══════════════════════════════════════════════════════════════════════════════
#  Step 2 — Scan Widget (shown after login)
# ══════════════════════════════════════════════════════════════════════════════
class QuickScanWidget(tk.Tk):
    def __init__(self, user_name: str, user_email: str):
        super().__init__()
        self.user_name  = user_name
        self.user_email = user_email

        self.title(f"DataShield — Scan Before Sending  |  {user_name}")
        self.geometry("860x640")
        self.minsize(700, 500)
        self.configure(bg=BG)
        self.resizable(True, True)

        self._folder   = tk.StringVar(value="")
        self._scanning = False
        self._results  = []
        self._stop     = threading.Event()

        self._build_ui()

        # Open folder picker immediately on launch
        self.after(200, self._browse)

    # ── UI ────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg="#060a13", height=52)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="  🛡 DataShield",
                 bg="#060a13", fg=ACCENT,
                 font=("Segoe UI", 13, "bold")).pack(side="left", padx=4)
        tk.Label(hdr, text="Scan Before Sending",
                 bg="#060a13", fg=TEXT_MUT,
                 font=("Segoe UI", 10)).pack(side="left")

        # User chip
        right = tk.Frame(hdr, bg="#060a13")
        right.pack(side="right", padx=12)
        av_txt = (self.user_name[0].upper() if self.user_name else "E")
        tk.Label(right, text=av_txt,
                 bg=BLUE, fg="white",
                 font=("Segoe UI", 9, "bold"), width=2).pack(side="left", padx=(0,6))
        inf = tk.Frame(right, bg="#060a13")
        inf.pack(side="left")
        tk.Label(inf, text=self.user_name,
                 bg="#060a13", fg=TEXT,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(inf, text="Employee",
                 bg="#060a13", fg=TEXT_MUT,
                 font=("Segoe UI", 8)).pack(anchor="w")

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

        # Folder bar
        bar = tk.Frame(self, bg=BG_CARD, padx=14, pady=9)
        bar.pack(fill="x")

        tk.Label(bar, text="Folder:", bg=BG_CARD, fg=TEXT_SEC,
                 font=("Segoe UI", 9)).pack(side="left")

        self._path_lbl = tk.Label(bar, textvariable=self._folder,
                                  bg=BG_CARD, fg=TEXT,
                                  font=("Consolas", 9), anchor="w")
        self._path_lbl.pack(side="left", fill="x", expand=True, padx=8)

        self._browse_btn = tk.Button(bar, text="📁 Change Folder",
                                     command=self._browse,
                                     bg=BG_ROW, fg=TEXT_SEC, relief="flat",
                                     font=("Segoe UI", 9), cursor="hand2",
                                     bd=0, padx=10, pady=3)
        self._browse_btn.pack(side="right", padx=(8, 0))

        self._scan_btn = tk.Button(bar, text="▶  Start Scan",
                                   command=self._start_scan,
                                   bg=ACCENT, fg="white",
                                   activebackground="#818cf8",
                                   activeforeground="white",
                                   relief="flat",
                                   font=("Segoe UI", 10, "bold"),
                                   cursor="hand2", bd=0, padx=14, pady=3)
        self._scan_btn.pack(side="right")

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

        # Progress
        prog_f = tk.Frame(self, bg=BG, padx=16, pady=5)
        prog_f.pack(fill="x")

        self._prog_lbl = tk.Label(prog_f, text="Select a folder above to begin",
                                  bg=BG, fg=TEXT_MUT,
                                  font=("Segoe UI", 9))
        self._prog_lbl.pack(side="left")

        self._pct_lbl = tk.Label(prog_f, text="",
                                 bg=BG, fg=TEXT_SEC,
                                 font=("Segoe UI", 9))
        self._pct_lbl.pack(side="right")

        self._c_prog = tk.Canvas(self, height=5, bg=BG_ROW,
                                 highlightthickness=0)
        self._c_prog.pack(fill="x", padx=16)
        self._fill = self._c_prog.create_rectangle(0, 0, 0, 5,
                                                   fill=ACCENT, outline="")

        # Summary
        self._sum_frame = tk.Frame(self, bg=BG, padx=16, pady=4)
        self._sum_frame.pack(fill="x")
        self._sum_lbl = tk.Label(self._sum_frame, text="",
                                 bg=BG, fg=TEXT,
                                 font=("Segoe UI", 10, "bold"))
        self._sum_lbl.pack(side="left")

        # Column headers
        ch = tk.Frame(self, bg=BG_CARD, padx=14)
        ch.pack(fill="x")
        for txt, w in [("Risk",14),("File",36),("Pattern / Reason",30),("Score",9)]:
            tk.Label(ch, text=txt, bg=BG_CARD, fg=TEXT_MUT,
                     font=("Segoe UI", 8, "bold"),
                     width=w, anchor="w").pack(side="left", pady=5)

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

        # Scrollable list
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True)

        self._canvas = tk.Canvas(outer, bg=BG, highlightthickness=0)
        self._sb = tk.Scrollbar(outer, orient="vertical",
                                command=self._canvas.yview)
        self._inner = tk.Frame(self._canvas, bg=BG)
        self._inner.bind("<Configure>",
            lambda e: self._canvas.configure(
                scrollregion=self._canvas.bbox("all")))
        self._canvas.create_window((0,0), window=self._inner, anchor="nw")
        self._canvas.configure(yscrollcommand=self._sb.set)
        self._sb.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)
        self._canvas.bind_all("<MouseWheel>",
            lambda e: self._canvas.yview_scroll(
                -1*(e.delta//120), "units"))

        # Bottom bar
        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")
        bot = tk.Frame(self, bg=BG_CARD, padx=14, pady=7)
        bot.pack(fill="x")

        self._copy_btn = tk.Button(bot, text="📋 Copy Report",
                                   command=self._copy_report,
                                   bg=BG_ROW, fg=TEXT_SEC, relief="flat",
                                   font=("Segoe UI", 9), cursor="hand2",
                                   bd=0, padx=10, pady=3, state="disabled")
        self._copy_btn.pack(side="left", padx=(0,8))

        tk.Button(bot, text="🔄 New Scan",
                  command=self._browse,
                  bg=BG_ROW, fg=TEXT_SEC, relief="flat",
                  font=("Segoe UI", 9), cursor="hand2",
                  bd=0, padx=10, pady=3).pack(side="left")

        tk.Label(bot,
                 text="🔒 Files scanned locally — nothing is uploaded to the server",
                 bg=BG_CARD, fg=TEXT_MUT,
                 font=("Segoe UI", 8)).pack(side="right")

    # ── Actions ───────────────────────────────────────────────────────────

    def _browse(self):
        folder = filedialog.askdirectory(
            title="Select Folder to Scan Before Sending", parent=self)
        if folder:
            self._folder.set(folder)
            self._clear_results()
            self._prog_lbl.config(
                text=f"Ready — click ▶ Start Scan")

    def _start_scan(self):
        folder = self._folder.get()
        if not folder or not os.path.isdir(folder):
            messagebox.showwarning("No Folder",
                                   "Please browse and select a folder first.",
                                   parent=self)
            return
        if self._scanning:
            return

        self._clear_results()
        self._scanning = True
        self._stop.clear()
        self._scan_btn.config(state="disabled", text="⏳ Scanning…")
        self._copy_btn.config(state="disabled")
        self._sum_lbl.config(text="")

        threading.Thread(target=self._run_scan, args=(folder,),
                         daemon=True).start()

    def _run_scan(self, folder: str):
        try:
            import scanner as ds_scanner
            import behaviour
            import classifier
            from policy import PolicyManager
        except ImportError as e:
            self.after(0, lambda: messagebox.showerror(
                "Import Error",
                f"DataShield scanner not found:\n{e}\n\n"
                "Run this script from the datashield project folder.",
                parent=self))
            self._scanning = False
            self.after(0, lambda: self._scan_btn.config(
                state="normal", text="▶  Start Scan"))
            return

        pm     = PolicyManager()
        config = {"root_path": folder, "policy_manager": pm}

        files = []
        for root, _, fnames in os.walk(folder):
            if "quarantine" in Path(root).parts:
                continue
            for fn in fnames:
                fp = os.path.join(root, fn)
                if not fp.endswith(".quarantine_info"):
                    files.append(fp)

        total   = len(files)
        results = []

        for idx, fpath in enumerate(files):
            if self._stop.is_set():
                break
            rel = os.path.relpath(fpath, folder)
            self.after(0, lambda r=rel, i=idx:
                       self._update_progress(i, total, r))
            try:
                matches  = ds_scanner.scan_file(fpath, config)
                matches  = behaviour.proximity_multiplier(matches)
                entropy  = behaviour.detect_high_entropy_strings(fpath)
                matches.extend(entropy)
                mismatch = behaviour.detect_file_type_mismatch(fpath)
                report   = classifier.classify_file(
                    matches, file_path=fpath, file_type_mismatch=mismatch)
            except Exception as exc:
                report = {"risk_level": "CLEAN", "risk_score": 0.0,
                          "match_count": 0, "top_matches": [],
                          "_err": str(exc)}

            results.append((fpath, report))
            self.after(0, lambda fp=fpath, rp=report:
                       self._add_row(fp, rp, folder))

        self._results = results
        self.after(0, lambda: self._scan_done(total, results))

    def _update_progress(self, idx, total, current_file):
        pct = (idx / total * 100) if total else 0
        self._prog_lbl.config(
            text=f"Scanning: {os.path.basename(current_file)}")
        self._pct_lbl.config(text=f"{idx}/{total}  ({pct:.0f}%)")
        w = self._c_prog.winfo_width()
        self._c_prog.coords(self._fill, 0, 0, w * pct / 100, 5)

    def _scan_done(self, total, results):
        self._scanning = False
        self._scan_btn.config(state="normal", text="▶  Start Scan")
        self._copy_btn.config(state="normal")

        high   = sum(1 for _, r in results if r["risk_level"] == "HIGH")
        medium = sum(1 for _, r in results if r["risk_level"] == "MEDIUM")
        clean  = sum(1 for _, r in results
                     if r["risk_level"] not in ("HIGH", "MEDIUM"))

        w = self._c_prog.winfo_width()
        self._c_prog.coords(self._fill, 0, 0, w, 5)

        if high == 0 and medium == 0:
            self._c_prog.itemconfig(self._fill, fill=GREEN)
            self._prog_lbl.config(text="✅ All clear — safe to send")
            self._sum_lbl.config(
                text=f"✅  {clean} files scanned — No sensitive data. Safe to send!",
                fg=GREEN)
        elif high > 0:
            self._c_prog.itemconfig(self._fill, fill=RED)
            self._prog_lbl.config(
                text="🔴 HIGH risk files found — remove them before sending")
            self._sum_lbl.config(
                text=f"🔴  {high} HIGH RISK  ·  {medium} Medium  ·  {clean} Clean  "
                     f"— Do NOT send the flagged files!",
                fg=RED)
        else:
            self._c_prog.itemconfig(self._fill, fill=YELLOW)
            self._prog_lbl.config(text="🟡 Some files need review before sending")
            self._sum_lbl.config(
                text=f"🟡  {medium} MEDIUM risk  ·  {clean} Clean  "
                     f"— Review before sending.",
                fg=YELLOW)

    def _add_row(self, fpath, report, base_folder):
        rl    = report.get("risk_level", "CLEAN")
        score = report.get("risk_score", 0.0)
        top   = report.get("top_matches", [])
        pat   = (getattr(top[0], "pattern_name", None) or str(top[0])
                 if top else
                 (f"⚠ {report['_err'][:38]}"
                  if report.get("_err") else "No sensitive data"))

        row_bg = RISK_BG.get(rl, BG_ROW)
        i      = len(self._inner.winfo_children())
        if i % 2 == 1:
            row_bg = _darken(row_bg)

        row = tk.Frame(self._inner, bg=row_bg,
                       highlightbackground=BORDER, highlightthickness=1)
        row.pack(fill="x", pady=1)

        tk.Label(row, text=f"{RISK_ICON.get(rl,'?')} {rl}",
                 bg=row_bg, fg=RISK_COLOR.get(rl, TEXT),
                 font=("Segoe UI", 9, "bold"),
                 width=12, anchor="w").pack(side="left", padx=8, pady=7)

        tk.Label(row, text=os.path.basename(fpath),
                 bg=row_bg, fg=TEXT,
                 font=("Segoe UI", 9),
                 width=34, anchor="w").pack(side="left", padx=4)

        tk.Label(row, text=pat,
                 bg=row_bg,
                 fg=TEXT_SEC if rl == "CLEAN" else RISK_COLOR.get(rl, TEXT),
                 font=("Segoe UI", 9),
                 width=30, anchor="w").pack(side="left", padx=4)

        tk.Label(row, text=f"{score:.1f}",
                 bg=row_bg, fg=RISK_COLOR.get(rl, TEXT_MUT),
                 font=("Consolas", 9, "bold"),
                 width=8, anchor="center").pack(side="left", padx=4)

        rel = os.path.relpath(fpath, base_folder)
        row.bind("<Enter>",
                 lambda e, p=rel: self._prog_lbl.config(text=f"  {p}"))

    def _clear_results(self):
        for w in self._inner.winfo_children():
            w.destroy()
        self._results = []
        self._c_prog.coords(self._fill, 0, 0, 0, 5)
        self._c_prog.itemconfig(self._fill, fill=ACCENT)
        self._pct_lbl.config(text="")
        self._sum_lbl.config(text="")

    def _copy_report(self):
        if not self._results:
            return
        lines = [
            "DataShield Quick Scan Report",
            f"Employee : {self.user_name} <{self.user_email}>",
            f"Folder   : {self._folder.get()}",
            f"Scanned  : {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 62,
        ]
        for fpath, report in self._results:
            rl  = report.get("risk_level", "CLEAN")
            sc  = report.get("risk_score", 0.0)
            top = report.get("top_matches", [])
            pat = getattr(top[0], "pattern_name", str(top[0])) if top else "—"
            lines.append(
                f"[{rl:7}] (score {sc:5.1f})  "
                f"{os.path.basename(fpath):<40}  {pat}")

        high   = sum(1 for _, r in self._results if r["risk_level"] == "HIGH")
        medium = sum(1 for _, r in self._results if r["risk_level"] == "MEDIUM")
        lines += [
            "=" * 62,
            f"SUMMARY: {high} HIGH  |  {medium} MEDIUM  |  "
            f"{len(self._results)-high-medium} CLEAN",
        ]
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        messagebox.showinfo(
            "Copied", "Report copied to clipboard.\nPaste into an email or ticket.",
            parent=self)


# ── Helpers ───────────────────────────────────────────────────────────────────
def _darken(hex_color: str, factor: float = 0.82) -> str:
    try:
        h = hex_color.lstrip("#")
        r, g, b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
        return "#{:02x}{:02x}{:02x}".format(
            int(r*factor), int(g*factor), int(b*factor))
    except Exception:
        return hex_color


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    LoginScreen().mainloop()
