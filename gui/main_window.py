"""
DataShield Employee Home Window
---------------------------------
A focused, minimal window for employees. Shows:
  - Connection status to the DataShield server
  - Protection status (which monitors are running)
  - "Scan Folder Before Sending" — the primary employee action
  - Live threat feed updated by both manual scans AND background monitors
  - Logout button

All monitoring (clipboard, USB, webmail) runs silently in the background.
"""
import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
from datetime import datetime
from collections import Counter

from audit import AuditLogger
from policy import PolicyManager
from gui.local_history import save_event, load_recent, cache_events, clear_all as clear_history

# ── Palette ──────────────────────────────────────────────────────────────────
BG       = "#0b0f1a"
BG_CARD  = "#0f172a"
BG_ROW   = "#1e293b"
BORDER   = "#1e293b"
ACCENT   = "#6366f1"
ACCENT2  = "#0ea5e9"
OK       = "#22c55e"
WARN     = "#f59e0b"
DANGER   = "#ef4444"
TEXT     = "#e2e8f0"
TEXT_SEC = "#94a3b8"
TEXT_MUT = "#475569"

RISK_COLOR = {
    "CLEAN":  OK,
    "LOW":    ACCENT2,
    "MEDIUM": WARN,
    "HIGH":   DANGER,
}


class EmployeeHomeWindow(tk.Tk):
    """
    Employee-facing DataShield window.

    What it shows:
      1. Header        — name, email, connection status, logout button
      2. Monitor pills — which channels are active right now
      3. Scan button   — big "Browse & Scan Folder" button
      4. Threat feed   — live detections from manual scans + background monitors

    Public API (called from background monitors in main.py):
      push_threat(channel, action, detail, risk_level, pattern)
      set_agent_status(online: bool)
    """

    def __init__(
        self,
        user_name:       str  = "",
        user_email:      str  = "",
        monitors:        dict = None,
        server_url:      str  = "",
        logout_callback  = None,   # callable() — what to do on logout
    ):
        super().__init__()

        self.user_name       = user_name or user_email.split("@")[0].title()
        self.user_email      = user_email
        self.monitors        = monitors or {
            "clipboard": True, "usb": True,
            "webmail": True,   "file_scan": True,
        }
        self.server_url      = server_url
        self.logout_callback = logout_callback

        base_dir = Path(__file__).resolve().parent.parent
        self.state = {
            "audit_logger":     AuditLogger(
                str(base_dir / "output" / "datashield_agent_audit.log")
            ),
            "policy_manager":   PolicyManager(
                rules_path=str(base_dir / "rules" / "default_rules.yaml"),
                allowlist_path=str(base_dir / "rules" / "allowlist.yaml"),
            ),
            "gemini_api_key":   os.environ.get("GEMINI_API_KEY", ""),
            "root_window":      self,
            "reporting_client": None,   # injected by main.py after login
        }

        self._threat_rows   = []
        self._scan_running  = threading.Event()
        self._agent_online  = True   # updated by set_agent_status()
        self._risk_score    = None   # fetched from server in background

        self.title("DataShield  —  Protected")
        W, H = 500, 680
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{W}x{H}+{sw - W - 40}+{(sh - H) // 2}")
        self.resizable(False, False)
        self.configure(bg=BG)

        os.makedirs(base_dir / "output", exist_ok=True)

        # Feature 2: load history — prefer PostgreSQL, fall back to SQLite cache
        # The actual fetch runs in background after the window is visible.
        # Pre-populate from the local cache immediately (fastest startup).
        cached = load_recent(limit=80)
        self._threat_rows = cached   # may be replaced by server data in 2s

        self._build()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Kick off server history fetch after window renders
        if self.server_url and self.user_email:
            self.after(2000, self._fetch_history_from_server)

    # ─────────────────────────────────────────────────────────────────────────
    #  Build UI
    # ─────────────────────────────────────────────────────────────────────────
    def _build(self):
        self._build_header()
        self._build_monitor_strip()
        self._build_risk_score_bar()   # Feature 1
        self._build_scan_button()
        self._build_threat_feed()

    # ── Header ────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg=BG_CARD)
        hdr.pack(fill="x")

        inner = tk.Frame(hdr, bg=BG_CARD)
        inner.pack(fill="x", padx=16, pady=12)

        # Brand
        brand = tk.Frame(inner, bg=BG_CARD)
        brand.pack(side="left")
        tk.Label(brand, text="  DS  ", bg=ACCENT, fg="white",
                 font=("Segoe UI", 12, "bold")).pack(side="left")
        names = tk.Frame(brand, bg=BG_CARD)
        names.pack(side="left", padx=8)
        tk.Label(names, text="DataShield", bg=BG_CARD, fg=ACCENT,
                 font=("Segoe UI", 13, "bold")).pack(anchor="w")
        tk.Label(names, text="Employee Portal", bg=BG_CARD, fg=TEXT_MUT,
                 font=("Segoe UI", 8)).pack(anchor="w")

        # Right side: user + logout
        right = tk.Frame(inner, bg=BG_CARD)
        right.pack(side="right")

        # Logout button
        logout_btn = tk.Label(
            right, text="Logout", bg=BG_ROW, fg=TEXT_SEC,
            font=("Segoe UI", 8, "bold"), padx=10, pady=4, cursor="hand2"
        )
        logout_btn.pack(side="right", padx=(8, 0))
        logout_btn.bind("<Button-1>", lambda e: self._do_logout())
        logout_btn.bind("<Enter>", lambda e: logout_btn.configure(fg=DANGER))
        logout_btn.bind("<Leave>", lambda e: logout_btn.configure(fg=TEXT_SEC))

        # User info
        user_box = tk.Frame(right, bg=BG_ROW, padx=10, pady=4)
        user_box.pack(side="right")
        tk.Label(user_box, text=self.user_name, bg=BG_ROW, fg=TEXT,
                 font=("Segoe UI", 9, "bold")).pack(anchor="e")
        tk.Label(user_box, text=self.user_email, bg=BG_ROW, fg=TEXT_MUT,
                 font=("Segoe UI", 7)).pack(anchor="e")

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

        # Agent connection status bar
        self._status_bar = tk.Frame(self, bg=OK, pady=3)
        self._status_bar.pack(fill="x")
        self._status_label = tk.Label(
            self._status_bar,
            text="● Agent connected  —  events reported to security dashboard",
            bg=OK, fg="#052e16",
            font=("Segoe UI", 8, "bold")
        )
        self._status_label.pack()

    # ── Monitor pills ─────────────────────────────────────────────────────────
    def _build_monitor_strip(self):
        outer = tk.Frame(self, bg=BG, pady=10)
        outer.pack(fill="x", padx=16)

        tk.Label(outer, text="ACTIVE MONITORS", bg=BG, fg=TEXT_MUT,
                 font=("Segoe UI", 7, "bold")).pack(anchor="w", pady=(0, 6))

        row = tk.Frame(outer, bg=BG)
        row.pack(fill="x")

        channel_defs = [
            ("clipboard", "Clipboard"),
            ("usb",       "USB Drive"),
            ("webmail",   "Webmail"),
            ("file_scan", "File Scan"),
            ("cloud",     "Cloud DLP"),
        ]
        self._monitor_pills = {}
        for key, label in channel_defs:
            active = self.monitors.get(key, False)
            pill = tk.Frame(row, bg=(OK if active else BG_ROW), padx=8, pady=3)
            pill.pack(side="left", padx=(0, 4))
            lbl = tk.Label(pill, text=label,
                           bg=(OK if active else BG_ROW),
                           fg="white" if active else TEXT_MUT,
                           font=("Segoe UI", 8, "bold"))
            lbl.pack()
            self._monitor_pills[key] = (pill, lbl)

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

    # ── Risk score bar (Feature 1) ─────────────────────────────────────────────
    def _build_risk_score_bar(self):
        """Shows the employee's own risk score fetched from the server."""
        self._risk_bar = tk.Frame(self, bg=BG, pady=8)
        self._risk_bar.pack(fill="x", padx=16)

        row = tk.Frame(self._risk_bar, bg=BG)
        row.pack(fill="x")

        tk.Label(row, text="YOUR RISK SCORE", bg=BG, fg=TEXT_MUT,
                 font=("Segoe UI", 7, "bold")).pack(side="left")

        self._risk_score_var  = tk.StringVar(value="Loading…")
        self._risk_score_lbl  = tk.Label(
            row, textvariable=self._risk_score_var,
            bg=BG, fg=TEXT_MUT, font=("Segoe UI", 9, "bold")
        )
        self._risk_score_lbl.pack(side="left", padx=8)

        self._risk_flag_var = tk.StringVar(value="")
        self._risk_flag_lbl = tk.Label(
            row, textvariable=self._risk_flag_var,
            bg=BG, fg=DANGER, font=("Segoe UI", 8, "bold")
        )
        self._risk_flag_lbl.pack(side="left")

        tk.Label(row, text="(30-day rolling  ·  refreshes every 5 min)",
                 bg=BG, fg=TEXT_MUT, font=("Segoe UI", 7)).pack(side="right")

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

        # Fetch in background immediately + schedule refresh
        self.after(1500, self._refresh_risk_score)

    def _refresh_risk_score(self):
        """Background fetch of employee risk score from server."""
        def _fetch():
            score_text = "Unavailable"
            color      = TEXT_MUT
            flag_text  = ""
            if self.server_url and self.user_email:
                try:
                    import httpx
                    resp = httpx.get(
                        f"{self.server_url}/api/auth/me/risk",
                        params={"email": self.user_email},
                        timeout=5,
                    )
                    if resp.status_code == 200:
                        data  = resp.json()
                        score = float(data.get("risk_score", 0))
                        score_text = f"{score:.1f}"
                        color = (
                            DANGER if score >= 10
                            else WARN if score >= 5
                            else OK
                        )
                        if data.get("is_flagged"):
                            flag_text = "  ⚠ FLAGGED"
                    elif resp.status_code == 404:
                        score_text = "No data yet"
                except Exception:
                    score_text = "Offline"
            def _update():
                self._risk_score_var.set(score_text)
                self._risk_score_lbl.configure(fg=color)
                self._risk_flag_var.set(flag_text)
            self.after(0, _update)
        threading.Thread(target=_fetch, daemon=True).start()
        # Schedule next refresh in 5 minutes
        self.after(300_000, self._refresh_risk_score)

    def _fetch_history_from_server(self):
        """
        Feature 2 — PostgreSQL-first history load.
        Runs in background thread 2 seconds after window opens.
        On success: replaces feed with server data + refreshes local cache.
        On failure: silently keeps the SQLite fallback already loaded.
        """
        def _fetch():
            try:
                import httpx
                resp = httpx.get(
                    f"{self.server_url}/api/events/my-feed",
                    params={"email": self.user_email, "limit": 80},
                    timeout=6,
                )
                if resp.status_code == 200:
                    events = resp.json()   # list of push_threat-compatible dicts
                    if events:
                        # Update SQLite cache with authoritative data
                        threading.Thread(
                            target=cache_events, args=(events,), daemon=True
                        ).start()
                        # Replace the in-memory feed on the UI thread
                        self.after(0, lambda evts=events: self._replace_feed(evts))
            except Exception:
                pass   # Server offline — keep SQLite fallback silently

        threading.Thread(target=_fetch, daemon=True).start()

    def _replace_feed(self, events: list):
        """Replace _threat_rows with freshly fetched server events and redraw."""
        self._threat_rows = events
        self._refresh_feed()

    # ── Feature 5: Override approval / denial notifications ───────────────────
    def _start_override_poll(self):
        """
        Start polling /api/overrides/my-notifications every 60s.
        Called once after successful login.
        """
        self._poll_overrides()

    def _poll_overrides(self):
        """Check server for any new override decisions and notify the employee."""
        employee_id = self.state.get("employee_id", "")
        if not employee_id or not self.server_url:
            return   # not logged in or no server — stop polling silently

        def _fetch():
            try:
                import httpx
                resp = httpx.get(
                    f"{self.server_url}/api/overrides/my-notifications",
                    params={"employee_id": employee_id},
                    timeout=6,
                )
                if resp.status_code == 200:
                    notifications = resp.json()
                    for notif in notifications:
                        # Show each notification on the main thread
                        self.after(0, lambda n=notif: self._show_override_notification(n))
            except Exception:
                pass   # server offline — try again next cycle

        threading.Thread(target=_fetch, daemon=True).start()
        # Schedule next poll in 60 seconds
        self.after(60_000, self._poll_overrides)

    def _show_override_notification(self, notif: dict):
        """Show a native Tkinter popup telling the employee their override result."""
        status     = notif.get("status", "")
        admin_note = notif.get("admin_note", "").strip()
        channel    = notif.get("event_channel", "")
        pattern    = notif.get("pattern", "")

        approved = (status == "APPROVED")
        color    = OK if approved else DANGER
        icon     = "✅" if approved else "❌"
        title    = "Override Approved" if approved else "Override Denied"

        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.configure(bg=BG)
        dialog.resizable(False, False)
        dw, dh = 420, 230
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        dialog.geometry(f"{dw}x{dh}+{(sw - dw) // 2}+{(sh - dh) // 2}")
        dialog.grab_set()
        dialog.lift()
        dialog.focus_force()

        # Coloured header bar
        header = tk.Frame(dialog, bg=color, pady=10, padx=14)
        header.pack(fill="x")
        tk.Label(
            header,
            text=f"{icon}  {title}",
            bg=color, fg="#0f172a" if approved else "white",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w")

        # Context (channel + pattern)
        if channel or pattern:
            ctx = f"{channel}  ·  {pattern}".strip(" · ")
            tk.Label(
                dialog, text=ctx,
                bg=BG, fg=TEXT_MUT, font=("Segoe UI", 8),
            ).pack(anchor="w", padx=14, pady=(8, 0))

        # Main message
        if approved:
            msg = "Your override request has been approved by your admin.\nYou may now proceed with the transfer."
        else:
            msg = "Your override request was denied by your admin.\nPlease contact your manager if you believe this is an error."

        tk.Label(
            dialog, text=msg,
            bg=BG, fg=TEXT,
            font=("Segoe UI", 9),
            wraplength=390, justify="left",
        ).pack(anchor="w", padx=14, pady=(6, 0))

        # Admin note (if present)
        if admin_note:
            note_frame = tk.Frame(dialog, bg="#1e293b", padx=10, pady=8)
            note_frame.pack(fill="x", padx=14, pady=(8, 0))
            tk.Label(
                note_frame, text="Admin note:",
                bg="#1e293b", fg=TEXT_MUT, font=("Segoe UI", 7, "bold"),
            ).pack(anchor="w")
            tk.Label(
                note_frame, text=admin_note,
                bg="#1e293b", fg=TEXT_SEC, font=("Segoe UI", 8),
                wraplength=370, justify="left",
            ).pack(anchor="w", pady=(2, 0))

        # OK button
        btn_row = tk.Frame(dialog, bg=BG)
        btn_row.pack(fill="x", padx=14, pady=(10, 14))
        ok = tk.Label(
            btn_row, text="OK",
            bg=color, fg="#0f172a" if approved else "white",
            font=("Segoe UI", 9, "bold"),
            padx=20, pady=6, cursor="hand2",
        )
        ok.pack(side="right")
        ok.bind("<Button-1>", lambda e: dialog.destroy())

    def _build_scan_button(self):
        section = tk.Frame(self, bg=BG, pady=14)
        section.pack(fill="x", padx=16)

        tk.Label(section, text="Check a folder for sensitive data before sending",
                 bg=BG, fg=TEXT_SEC, font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 8))

        btn_outer = tk.Frame(section, bg=ACCENT, cursor="hand2")
        btn_outer.pack(fill="x")

        self._scan_lbl = tk.Label(
            btn_outer,
            text="📂   Browse & Scan Folder",
            bg=ACCENT, fg="white",
            font=("Segoe UI", 12, "bold"),
            pady=14, cursor="hand2",
        )
        self._scan_lbl.pack(fill="x")

        def _enter(e): btn_outer.configure(bg="#818cf8"); self._scan_lbl.configure(bg="#818cf8")
        def _leave(e): btn_outer.configure(bg=ACCENT);   self._scan_lbl.configure(bg=ACCENT)

        for w in (btn_outer, self._scan_lbl):
            w.bind("<Button-1>", lambda e: self.trigger_scan_folder())
            w.bind("<Enter>", _enter)
            w.bind("<Leave>", _leave)

        self._scan_status = tk.Label(
            section, text="", bg=BG, fg=TEXT_MUT, font=("Segoe UI", 8)
        )
        self._scan_status.pack(anchor="w", pady=(5, 0))

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

    # ── Threat feed ───────────────────────────────────────────────────────────
    def _build_threat_feed(self):
        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x", padx=16, pady=(10, 4))

        self._feed_title = tk.StringVar(value="Recent Threats")
        tk.Label(hdr, textvariable=self._feed_title, bg=BG, fg=TEXT_SEC,
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        tk.Label(hdr, text="This session", bg=BG, fg=TEXT_MUT,
                 font=("Segoe UI", 8)).pack(side="right")

        container = tk.Frame(self, bg=BG)
        container.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        canvas = tk.Canvas(container, bg=BG, highlightthickness=0)
        sb = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        self._feed_frame  = tk.Frame(canvas, bg=BG)
        self._feed_win    = canvas.create_window((0, 0), window=self._feed_frame, anchor="nw")
        self._canvas      = canvas

        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfig(self._feed_win, width=e.width))
        self._feed_frame.bind("<Configure>",
                    lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        # Mouse-wheel scroll
        canvas.bind("<MouseWheel>",
                    lambda e: canvas.yview_scroll(-1 * (e.delta // 120), "units"))

        self._show_empty_state()

    def _show_empty_state(self):
        for w in self._feed_frame.winfo_children():
            w.destroy()
        tk.Label(self._feed_frame, text="✅", bg=BG, fg=OK,
                 font=("Segoe UI", 26)).pack(pady=(24, 6))
        tk.Label(self._feed_frame, text="No threats detected this session",
                 bg=BG, fg=TEXT_SEC, font=("Segoe UI", 11)).pack()
        tk.Label(self._feed_frame, text="All monitored channels are clean",
                 bg=BG, fg=TEXT_MUT, font=("Segoe UI", 9)).pack(pady=(3, 0))

    # ─────────────────────────────────────────────────────────────────────────
    #  Public API — called from main.py / background monitors
    # ─────────────────────────────────────────────────────────────────────────
    def push_threat(self, channel: str, action: str, detail: str,
                    risk_level: str = "HIGH", pattern: str = "",
                    match=None, file_path: str = ""):
        """
        Thread-safe. Add a detection to the feed.
        Also saves to local SQLite (Feature 2).
        match  — the scanner.Match namedtuple (optional) used for AI explanation
        file_path — full path of the scanned file (optional, for AI explainer)
        """
        entry = {
            "time":       datetime.now().strftime("%H:%M:%S"),
            "channel":    channel,
            "action":     action,
            "detail":     detail,
            "risk_level": risk_level,
            "pattern":    pattern,
            "match":      match,
            "file_path":  file_path,
            "ai_text":    None,   # populated lazily on first expand
        }
        self._threat_rows.insert(0, entry)
        # Feature 2: persist to local SQLite
        threading.Thread(
            target=save_event, args=(entry,), daemon=True
        ).start()
        self.after(0, self._refresh_feed)

    def set_agent_status(self, online: bool):
        """Update the connection status bar. Thread-safe via after()."""
        self._agent_online = online
        self.after(0, self._update_status_bar)

    def _update_status_bar(self):
        if self._agent_online:
            self._status_bar.configure(bg=OK)
            self._status_label.configure(
                bg=OK, fg="#052e16",
                text="● Agent connected  —  events reported to security dashboard"
            )
        else:
            self._status_bar.configure(bg=DANGER)
            self._status_label.configure(
                bg=DANGER, fg="white",
                text="● Agent offline  —  events queued locally until server reconnects"
            )

    # ─────────────────────────────────────────────────────────────────────────
    #  Feed rendering
    # ─────────────────────────────────────────────────────────────────────────
    def _refresh_feed(self):
        for w in self._feed_frame.winfo_children():
            w.destroy()

        count = len(self._threat_rows)
        self._feed_title.set(
            f"Recent Threats  ({count})" if count else "Recent Threats"
        )

        if not self._threat_rows:
            self._show_empty_state()
            return

        for entry in self._threat_rows[:50]:
            self._add_row(entry)

        self._canvas.yview_moveto(0)   # scroll to top (newest)

    def _add_row(self, entry: dict):
        rl     = entry.get("risk_level", "HIGH")
        color  = RISK_COLOR.get(rl, DANGER)
        action = entry.get("action", "")

        # ── Outer card (clickable) ────────────────────────────────────────────
        card = tk.Frame(self._feed_frame, bg=BG_CARD, pady=0, padx=0, cursor="hand2")
        card.pack(fill="x", pady=2, padx=2)

        # ── Summary row ───────────────────────────────────────────────────────
        summary = tk.Frame(card, bg=BG_CARD, pady=8)
        summary.pack(fill="x")

        # Left colour bar
        tk.Frame(summary, bg=color, width=4).pack(side="left", fill="y")

        content = tk.Frame(summary, bg=BG_CARD, padx=10)
        content.pack(side="left", fill="both", expand=True)

        # Top line: toggle arrow + channel + action badge + time
        top = tk.Frame(content, bg=BG_CARD)
        top.pack(fill="x")

        arrow_var = tk.StringVar(value="▶")
        tk.Label(top, textvariable=arrow_var, bg=BG_CARD, fg=TEXT_MUT,
                 font=("Segoe UI", 7)).pack(side="left", padx=(0, 4))

        tk.Label(top, text=entry.get("channel", ""),
                 bg=BG_CARD, fg=TEXT, font=("Segoe UI", 9, "bold")).pack(side="left")

        badge_bg = DANGER if action == "BLOCK" else WARN if action == "WARN" else OK if action == "ALLOW" else BG_ROW
        badge_fg = "#0f172a" if action in ("WARN", "ALLOW") else "white"
        tk.Label(top, text=f"  {action}  ",
                 bg=badge_bg, fg=badge_fg,
                 font=("Segoe UI", 7, "bold")).pack(side="left", padx=6)

        tk.Label(top, text=entry.get("time", ""),
                 bg=BG_CARD, fg=TEXT_MUT, font=("Segoe UI", 8)).pack(side="right")

        if entry.get("pattern"):
            tk.Label(top, text=entry["pattern"],
                     bg=BG_ROW, fg=TEXT_SEC,
                     font=("Segoe UI", 7, "bold"), padx=6).pack(side="right", padx=(0, 4))

        detail_text = entry.get("detail", "")
        if detail_text:
            tk.Label(content, text=detail_text,
                     bg=BG_CARD, fg=TEXT_SEC, font=("Segoe UI", 9),
                     anchor="w", wraplength=420, justify="left").pack(fill="x", pady=(2, 0))

        # "Click for AI explanation" hint — only for non-clean events
        has_ai = entry.get("match") is not None or entry.get("pattern")
        if rl not in ("CLEAN", "LOW") and has_ai:
            tk.Label(content, text="Click for AI explanation  ›",
                     bg=BG_CARD, fg=ACCENT, font=("Segoe UI", 7),
                     cursor="hand2").pack(anchor="w", pady=(2, 0))

        # ── Expandable AI panel (hidden by default) ───────────────────────────
        ai_panel = tk.Frame(card, bg="#0a0e1a", padx=14, pady=0)
        # Not packed yet — shown on click

        ai_text_var = tk.StringVar(value="")
        ai_label = tk.Label(
            ai_panel,
            textvariable=ai_text_var,
            bg="#0a0e1a", fg="#c7d2fe",
            font=("Segoe UI", 8),
            wraplength=430, justify="left", anchor="w",
        )
        ai_label.pack(fill="x", pady=(8, 10))

        panel_open = [False]

        def _fetch_and_show():
            """Called in a background thread — fetches AI text and updates label."""
            text = entry.get("ai_text")
            if text is None:
                # Try to call Gemini
                match_obj  = entry.get("match")
                fp         = entry.get("file_path") or entry.get("detail", "")
                api_key    = self.state.get("gemini_api_key", "")
                if match_obj is not None:
                    try:
                        from ai_explain import explain_finding
                        text = explain_finding(match_obj, fp, api_key)
                    except Exception as ex:
                        text = f"AI explanation unavailable: {ex}"
                elif entry.get("pattern"):
                    # No Match object — build a short static explanation from pattern name
                    p   = entry["pattern"]
                    ch  = entry.get("channel", "")
                    rl_ = entry.get("risk_level", "HIGH")
                    api_key = self.state.get("gemini_api_key", "")
                    if api_key:
                        try:
                            import google.generativeai as genai
                            genai.configure(api_key=api_key)
                            model = genai.GenerativeModel(
                                "gemini-1.5-flash",
                                generation_config={"max_output_tokens": 200, "temperature": 0.2}
                            )
                            prompt = (
                                f"A DLP agent detected a '{p}' pattern in a {ch} channel event "
                                f"(risk: {rl_}). Explain in two short paragraphs: "
                                f"(1) why this is a data privacy risk, "
                                f"(2) what the employee should do right now."
                            )
                            resp = model.generate_content(prompt, request_options={"timeout": 8})
                            text = resp.text.strip() if resp.text else None
                        except Exception:
                            text = None
                    if not text:
                        text = (
                            f"Pattern '{p}' was detected in a {ch} event.\n"
                            f"This may indicate sensitive data was about to leave the organisation. "
                            f"Do not share this content externally without approval from your IT security team."
                        )
                else:
                    text = "No detailed explanation available for this event."
                entry["ai_text"] = text
            self.after(0, lambda t=text: ai_text_var.set(t))

        def _toggle(event=None):
            if panel_open[0]:
                ai_panel.pack_forget()
                arrow_var.set("▶")
                panel_open[0] = False
            else:
                ai_panel.pack(fill="x")
                arrow_var.set("▼")
                panel_open[0] = True
                if entry.get("ai_text") is None:
                    ai_text_var.set("⏳  Asking Gemini…")
                    threading.Thread(target=_fetch_and_show, daemon=True).start()
                self.after(100, lambda: self._canvas.yview_moveto(
                    self._canvas.yview()[0]))

        # Bind click on the whole summary row (but only for non-clean events)
        if rl not in ("CLEAN",):
            for widget in [card, summary, content, top]:
                widget.bind("<Button-1>", _toggle)

        # ── Feature 5: Override request button (BLOCK only) ───────────────────
        if action == "BLOCK":
            override_bar = tk.Frame(card, bg="#0d1117", pady=5, padx=14)
            override_bar.pack(fill="x")

            tk.Label(
                override_bar,
                text="This transfer was blocked by policy.  ",
                bg="#0d1117", fg="#475569", font=("Segoe UI", 7),
            ).pack(side="left")

            req_btn = tk.Label(
                override_bar,
                text="Request Override →",
                bg="#0d1117", fg=ACCENT,
                font=("Segoe UI", 7, "bold"),
                cursor="hand2",
            )
            req_btn.pack(side="left")

            def _open_override_dialog(e=None, _entry=entry):
                """Open a small justification dialog and POST to server."""
                dialog = tk.Toplevel(self)
                dialog.title("Request Override")
                dialog.configure(bg=BG)
                dialog.resizable(False, False)
                dw, dh = 420, 230
                sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
                dialog.geometry(f"{dw}x{dh}+{(sw - dw) // 2}+{(sh - dh) // 2}")
                dialog.grab_set()

                tk.Label(dialog, text="Why do you need to send this?",
                         bg=BG, fg=TEXT, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=16, pady=(16, 4))
                tk.Label(dialog,
                         text=f"Channel: {_entry.get('channel', '')}  ·  Pattern: {_entry.get('pattern', '')}",
                         bg=BG, fg=TEXT_MUT, font=("Segoe UI", 8)).pack(anchor="w", padx=16)

                txt = tk.Text(dialog, height=4, bg=BG_ROW, fg=TEXT, insertbackground=TEXT,
                              font=("Segoe UI", 9), relief="flat", padx=8, pady=6,
                              wrap="word", highlightthickness=1, highlightbackground=BORDER)
                txt.pack(fill="x", padx=16, pady=(8, 0))

                status_var = tk.StringVar(value="")
                status_lbl = tk.Label(dialog, textvariable=status_var, bg=BG,
                                      fg=ACCENT, font=("Segoe UI", 8))
                status_lbl.pack(anchor="w", padx=16, pady=(4, 0))

                def _submit():
                    justification = txt.get("1.0", "end").strip()
                    if not justification:
                        status_var.set("Please enter a reason.")
                        return
                    status_var.set("Submitting…")
                    dialog.update()

                    def _post():
                        try:
                            import httpx, json as _json
                            payload = {
                                "employee_id":   self.state.get("employee_id", ""),
                                "agent_id":      self.state.get("agent_id", ""),
                                "event_channel": _entry.get("channel", ""),
                                "event_detail":  _entry.get("detail", ""),
                                "pattern":       _entry.get("pattern", ""),
                                "justification": justification,
                            }
                            if self.server_url:
                                httpx.post(
                                    f"{self.server_url}/api/overrides",
                                    json=payload, timeout=6,
                                )
                            self.after(0, lambda: status_var.set("✓ Request submitted. Your manager will be notified."))
                            self.after(2500, dialog.destroy)
                        except Exception as ex:
                            self.after(0, lambda msg=str(ex): status_var.set(f"Failed: {msg}"))

                    threading.Thread(target=_post, daemon=True).start()

                btn_row = tk.Frame(dialog, bg=BG)
                btn_row.pack(fill="x", padx=16, pady=(8, 16))
                tk.Label(btn_row, text="", bg=BG).pack(side="left", expand=True)
                cancel_btn = tk.Label(btn_row, text="Cancel", bg=BG_ROW, fg=TEXT_SEC,
                                      font=("Segoe UI", 8, "bold"), padx=10, pady=4, cursor="hand2")
                cancel_btn.pack(side="left", padx=(0, 6))
                cancel_btn.bind("<Button-1>", lambda e: dialog.destroy())

                submit_btn = tk.Label(btn_row, text="Submit Request", bg=ACCENT, fg="white",
                                      font=("Segoe UI", 8, "bold"), padx=12, pady=4, cursor="hand2")
                submit_btn.pack(side="left")
                submit_btn.bind("<Button-1>", lambda e: _submit())

            req_btn.bind("<Button-1>", _open_override_dialog)


    # ─────────────────────────────────────────────────────────────────────────
    #  Scan folder
    # ─────────────────────────────────────────────────────────────────────────
    def trigger_scan_folder(self, folder: str = ""):
        """Called by scan button or system tray."""
        if self._scan_running.is_set():
            self._scan_status.configure(text="Scan already in progress…", fg=WARN)
            return

        if not folder:
            folder = filedialog.askdirectory(
                title="Select Folder to Scan Before Sending",
                parent=self,
            )
        if not folder:
            return

        self._scan_running.set()
        self._scan_lbl.configure(text="⏳   Scanning…", bg="#334155")
        self._scan_status.configure(text=f"Scanning: {folder}", fg=TEXT_MUT)
        self.update()

        threading.Thread(target=self._run_scan, args=(folder,), daemon=True).start()

    def _run_scan(self, folder: str):
        """Runs in a background thread. Pushes results to the feed via after()."""
        found   = []
        all_fps = []

        try:
            import scanner
            import scanner_analysis as behaviour
            import classifier

            policy_manager = self.state["policy_manager"]
            config = {"root_path": folder, "policy_manager": policy_manager}

            # Collect files
            for root, _, fnames in os.walk(folder):
                for fname in fnames:
                    fp = os.path.join(root, fname)
                    if not fname.endswith(".quarantine_info"):
                        all_fps.append(fp)

            total = len(all_fps)
            self.after(0, lambda t=total: self._scan_status.configure(
                text=f"Scanning {t} file(s)…", fg=TEXT_MUT
            ))

            for fp in all_fps:
                try:
                    matches    = scanner.scan_file(fp, config)
                    matches    = behaviour.proximity_multiplier(matches)
                    result     = classifier.classify_file(matches, file_path=fp)
                    rl         = result.get("risk_level", "CLEAN")

                    if rl != "CLEAN":
                        # Extract pattern from Match object (has .pattern_name, not .get())
                        top_matches = result.get("top_matches", [])
                        if top_matches:
                            m = top_matches[0]
                            # Match is a namedtuple/dataclass — use attribute access
                            pattern = getattr(m, "pattern_name",
                                     getattr(m, "rule_name",
                                     m.get("pattern_name", "") if isinstance(m, dict) else ""))
                        else:
                            pattern = ""

                        rel    = os.path.relpath(fp, folder)
                        action = "BLOCK" if rl == "HIGH" else "WARN"

                        found.append({
                            "channel":    "FILE SCAN",
                            "action":     action,
                            "detail":     rel,
                            "risk_level": rl,
                            "pattern":    pattern,
                            "result":     result,
                        })

                        # Capture top Match object for AI explainer
                        top_match = top_matches[0] if top_matches else None

                        # Push to UI immediately — pass match + full path for AI
                        self.after(0, lambda c="FILE SCAN", a=action, d=rel, r=rl,
                                   p=pattern, mo=top_match, fpp=fp:
                                   self.push_threat(c, a, d, r, p,
                                                    match=mo, file_path=fpp))

                except Exception:
                    pass   # skip unreadable files silently

            # Feature 3: Pattern hit count summary row
            if not found:
                self.after(0, lambda t=total: self.push_threat(
                    "FILE SCAN", "ALLOW",
                    f"All {t} file(s) clean — safe to send",
                    "CLEAN", ""
                ))
                self.after(0, lambda: self._scan_status.configure(
                    text=f"Scan complete — {total} file(s), no issues found", fg=OK
                ))
            else:
                n = len(found)
                # Build pattern breakdown string e.g. "2× CREDIT_CARD, 1× SSN"
                pattern_counts = Counter(
                    item["pattern"] for item in found if item.get("pattern")
                )
                breakdown = ", ".join(
                    f"{cnt}× {pat}" for pat, cnt in pattern_counts.most_common()
                )
                summary_detail = f"{n} file(s) flagged out of {total} scanned"
                if breakdown:
                    summary_detail += f"  —  {breakdown}"

                self.after(0, lambda sd=summary_detail: self.push_threat(
                    "FILE SCAN", "WARN",
                    sd,
                    "MEDIUM", ""
                ))
                self.after(0, lambda n=n, t=total: self._scan_status.configure(
                    text=f"Scan complete — {n} issue(s) found in {t} file(s)", fg=WARN
                ))

            # Report found issues to server
            client = self.state.get("reporting_client")
            if client and found:
                for item in found:
                    try:
                        client.enqueue_event(item["result"], "FILE", item["action"])
                    except Exception:
                        pass

        except Exception as e:
            self.after(0, lambda err=str(e): self.push_threat(
                "FILE SCAN", "ERROR", f"Scan failed: {err}", "MEDIUM", ""
            ))
            self.after(0, lambda err=str(e): self._scan_status.configure(
                text=f"Scan error: {err}", fg=DANGER
            ))
        finally:
            self._scan_running.clear()
            self.after(0, lambda: self._scan_lbl.configure(
                text="📂   Browse & Scan Folder", bg=ACCENT
            ))

    # ─────────────────────────────────────────────────────────────────────────
    #  Logout
    # ─────────────────────────────────────────────────────────────────────────
    def _do_logout(self):
        if messagebox.askyesno(
            "Logout",
            "Logging out will stop all monitoring on this machine.\n\nAre you sure?",
            parent=self,
        ):
            # Clear local history so next employee starts fresh
            try:
                clear_history()
            except Exception:
                pass
            self.destroy()
            if self.logout_callback:
                self.logout_callback()
            else:
                sys.exit(0)

    # ─────────────────────────────────────────────────────────────────────────
    #  Close: hide to tray
    # ─────────────────────────────────────────────────────────────────────────
    def on_close(self):
        self.withdraw()
