#!/usr/bin/env python3
"""
DataShield — Quick Scan Launcher
─────────────────────────────────────────────────────────────────────────────
PURPOSE  Employee desktop shortcut for scanning files before sending them.
         Employees sign in once, pick a folder, and see colour-coded results.

USAGE    python quick_scan.py
         (double-click the shortcut on the employee's desktop)

FLOW     1. Employee enters email + PIN  (validated against DataShield server)
         2. If the main agent (main.py) is already running, sends the folder
            to the existing tray window via the trigger_scan_folder() API.
         3. Otherwise, opens a lightweight scan window directly.

This file is intentionally thin — all scan logic lives in gui/scan_tab.py
and gui/main_window.py so there is exactly one implementation.
─────────────────────────────────────────────────────────────────────────────
"""
import os
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv()

import tkinter as tk
from tkinter import filedialog
import httpx

SERVER_URL    = os.environ.get("SERVER_URL", "http://localhost:8001").rstrip("/")
AGENT_API_KEY = os.environ.get("AGENT_API_KEY", "")

# ── Palette (matches main agent design) ──────────────────────────────────────
BG      = "#0b0f1a"
BG_CARD = "#0f172a"
BG_ROW  = "#1e293b"
BORDER  = "#1e293b"
ACCENT  = "#6366f1"
TEXT    = "#e2e8f0"
TEXT_SEC = "#94a3b8"
TEXT_MUT = "#475569"
YELLOW  = "#f59e0b"


# ═════════════════════════════════════════════════════════════════════════════
#  Login screen
# ═════════════════════════════════════════════════════════════════════════════
class QuickScanLogin(tk.Tk):
    """
    Minimal sign-in dialog for the Quick Scan shortcut.
    Validates email + PIN against the DataShield server, then opens the
    full employee scan window (gui/main_window.py) with a folder pre-selected.
    """

    def __init__(self):
        super().__init__()
        self.title("DataShield — Quick Scan")
        self.resizable(False, False)
        W, H = 420, 430
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
        self.configure(bg=BG)
        self._build()

    def _build(self):
        # Logo
        canvas = tk.Canvas(self, width=420, height=95, bg=BG, highlightthickness=0)
        canvas.pack()
        canvas.create_text(210, 38, text="🛡 DataShield",
                           fill=ACCENT, font=("Segoe UI", 22, "bold"))
        canvas.create_text(210, 62, text="Quick Scan — Pre-send File Check",
                           fill=TEXT_MUT, font=("Segoe UI", 10))
        canvas.create_text(210, 80, text="Scan a folder before sending documents",
                           fill="#334155", font=("Segoe UI", 8))

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

        card = tk.Frame(self, bg=BG_CARD, padx=36, pady=24)
        card.pack(fill="both", expand=True)

        # Email
        tk.Label(card, text="Work Email", bg=BG_CARD, fg=TEXT_SEC,
                 font=("Segoe UI", 9, "bold"), anchor="w").pack(fill="x")
        self._email = tk.StringVar()
        tk.Entry(card, textvariable=self._email, bg=BG_ROW, fg=TEXT,
                 insertbackground=TEXT, relief="flat",
                 font=("Segoe UI", 11), bd=0).pack(fill="x", ipady=9, pady=(3, 0))
        tk.Frame(card, height=1, bg="#334155").pack(fill="x", pady=(0, 12))

        # PIN
        tk.Label(card, text="PIN", bg=BG_CARD, fg=TEXT_SEC,
                 font=("Segoe UI", 9, "bold"), anchor="w").pack(fill="x")
        self._pin = tk.StringVar()
        self._pin_entry = tk.Entry(
            card, textvariable=self._pin, show="●",
            bg=BG_ROW, fg=TEXT, insertbackground=TEXT,
            relief="flat", font=("Segoe UI", 11), bd=0,
        )
        self._pin_entry.pack(fill="x", ipady=9, pady=(3, 0))
        tk.Frame(card, height=1, bg="#334155").pack(fill="x", pady=(0, 6))

        # Status
        self._status = tk.StringVar()
        tk.Label(card, textvariable=self._status, bg=BG_CARD, fg=YELLOW,
                 font=("Segoe UI", 9), wraplength=340,
                 justify="center").pack(pady=(4, 10))

        # Sign-in button
        tk.Button(
            card, text="Sign In  →",
            command=self._do_login,
            bg=ACCENT, fg="white", activebackground="#818cf8",
            activeforeground="white", relief="flat",
            font=("Segoe UI", 11, "bold"), cursor="hand2", bd=0,
        ).pack(fill="x", ipady=11)

        tk.Label(
            card,
            text="Enter your work email and the PIN set by your IT admin.",
            bg=BG_CARD, fg=TEXT_MUT, font=("Segoe UI", 8),
        ).pack(pady=(10, 0))

        self._email.trace_add("write", lambda *_: self._status.set(""))
        self._pin.trace_add("write",   lambda *_: self._status.set(""))
        self.bind("<Return>", lambda e: self._do_login())
        self.protocol("WM_DELETE_WINDOW", sys.exit)
        self.after(50, self._pin_entry.focus_set)

    def _do_login(self):
        email = self._email.get().strip()
        pin   = self._pin.get().strip()
        if not email or "@" not in email:
            self._status.set("Enter a valid work email.")
            return
        self._status.set("Verifying…")
        self.update()
        threading.Thread(target=self._validate, args=(email, pin), daemon=True).start()

    def _validate(self, email: str, pin: str):
        try:
            resp = httpx.post(
                f"{SERVER_URL}/api/auth/validate-employee",
                json={"email": email, "password": pin},
                headers={"X-DataShield-Agent-Key": AGENT_API_KEY},
                timeout=8.0,
            )
        except Exception as exc:
            self.after(0, lambda: self._status.set(
                f"Cannot reach server.\nMake sure DataShield is running.\n({type(exc).__name__})"
            ))
            return

        if resp.status_code == 200:
            data = resp.json()
            if not data.get("pin_set", True):
                self.after(0, lambda: self._status.set(
                    "No PIN set yet.\nAsk your admin to set a PIN in the DataShield console."
                ))
                return
            # Success — open scan window
            name = data.get("name", email)
            self.after(0, lambda: self._open_scan(name, email))
        elif resp.status_code == 401:
            detail = resp.json().get("detail", "")
            msg = "Enter your PIN." if detail == "pin_required" else "Wrong PIN. Try again."
            self.after(0, lambda: self._status.set(msg))
        elif resp.status_code == 404:
            self.after(0, lambda: self._status.set(
                "Email not registered.\nContact your IT admin."
            ))
        else:
            self.after(0, lambda: self._status.set(
                f"Server error ({resp.status_code})."
            ))

    def _open_scan(self, name: str, email: str):
        """Login succeeded — pick folder and open the employee scan window."""
        # Withdraw login screen while folder picker is open
        self.withdraw()

        folder = filedialog.askdirectory(
            title="Select Folder to Scan Before Sending",
        )

        if not folder:
            # User cancelled folder picker — just exit
            sys.exit(0)

        # Destroy login window and launch full employee scan window
        self.destroy()

        from gui.main_window import MainWindow
        app = MainWindow(role="employee", user_name=name, user_email=email)
        # Pre-fill folder and start scan immediately
        app.after(100, lambda: app.trigger_scan_folder(folder))
        app.mainloop()


# ═════════════════════════════════════════════════════════════════════════════
#  Entry point
# ═════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if not SERVER_URL or not AGENT_API_KEY:
        # No server configured — launch scan window directly (standalone mode)
        print("[quick_scan] No SERVER_URL/AGENT_API_KEY — running in standalone mode.")
        from gui.main_window import MainWindow
        app = MainWindow(role="employee", user_name="Local User", user_email="local")
        app.mainloop()
    else:
        login = QuickScanLogin()
        login.mainloop()
