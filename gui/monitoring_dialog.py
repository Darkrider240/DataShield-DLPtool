"""
DataShield — Per-Employee Monitoring Controls Dialog
Admin can toggle which DLP channels are active for each employee.
Changes are saved immediately via PATCH to the server API.
"""
import tkinter as tk
import threading

# Local colour constants (mirrors admin_window.py palette)
BG_CARD  = "#0f172a"
BG_ROW   = "#1e293b"
BORDER   = "#1e293b"
ACCENT   = "#6366f1"
TEXT_PRI = "#e2e8f0"
TEXT_MUT = "#475569"
TEXT_SEC = "#94a3b8"
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_SM   = ("Segoe UI", 9)
OK        = "#22c55e"
DANGER    = "#ef4444"


def _btn(parent, text, cmd, color=ACCENT, fg="white", **kw):
    return tk.Button(parent, text=text, command=cmd,
                     bg=color, fg=fg, activebackground="#818cf8",
                     activeforeground="white", relief="flat",
                     font=FONT_BOLD, cursor="hand2", bd=0, **kw)


class MonitoringDialog(tk.Toplevel):
    """
    Per-employee monitoring controls popup.

    The admin toggles which DLP channels are active for this specific employee.
    Changes are saved to the server immediately on each toggle flip.

    Channels controlled:
        - Clipboard monitoring   (monitor_clipboard)
        - USB drive monitoring   (monitor_usb)
        - Webmail / email scan   (monitor_webmail)
        - Manual file scanning   (monitor_file_scan)
    """

    _CHANNELS = [
        ("monitor_clipboard",
         "\U0001f4cb  Clipboard Monitoring",
         "Intercept copy/paste of sensitive data"),
        ("monitor_usb",
         "\U0001f50c  USB Drive Monitoring",
         "Detect USB insertions and file copy events"),
        ("monitor_webmail",
         "\u2709\ufe0f   Webmail / Email",
         "Scan outgoing Gmail and Outlook webmail content"),
        ("monitor_file_scan",
         "\U0001f4c1  File Scanning",
         "Employee can trigger DataShield manual file scans"),
    ]

    def __init__(self, parent, api, emp: dict):
        """
        Parameters
        ----------
        parent : tk widget
        api    : gui.admin_window.APIClient
        emp    : employee dict with at minimum 'id', 'full_name', 'email'
        """
        super().__init__(parent)
        self.api  = api
        self.emp  = emp
        name = emp.get("full_name") or emp.get("email", "")

        self.title(f"Monitoring Controls  \u2014  {name}")
        self.configure(bg=BG_CARD)
        self.resizable(False, False)
        self.geometry("460x400")

        self._vars: dict[str, tk.BooleanVar] = {}
        self._pills: dict[str, tk.Canvas]    = {}
        self._status_var = tk.StringVar(value="Loading\u2026")

        # ── Header ──────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg="#060a13", height=52)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(
            hdr,
            text=f"\U0001f512  Monitoring Controls  \u2014  {name}",
            bg="#060a13", fg=ACCENT,
            font=("Segoe UI", 11, "bold"),
        ).pack(side="left", padx=16)

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

        tk.Label(
            self,
            text="Toggle which monitoring channels are active for this employee.",
            bg=BG_CARD, fg=TEXT_MUT, font=FONT_SM,
        ).pack(anchor="w", padx=24, pady=(12, 4))

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x", padx=24)

        # ── Toggle rows ──────────────────────────────────────────────────────
        tf = tk.Frame(self, bg=BG_CARD)
        tf.pack(fill="x", padx=24, pady=4)

        for key, label, desc in self._CHANNELS:
            var = tk.BooleanVar(value=True)
            self._vars[key] = var

            row = tk.Frame(tf, bg=BG_CARD)
            row.pack(fill="x", pady=7)

            # Left: label + description
            info = tk.Frame(row, bg=BG_CARD)
            info.pack(side="left", fill="x", expand=True)
            tk.Label(info, text=label, bg=BG_CARD, fg=TEXT_PRI,
                     font=FONT_BOLD, anchor="w").pack(anchor="w")
            tk.Label(info, text=desc, bg=BG_CARD, fg=TEXT_MUT,
                     font=FONT_SM, anchor="w").pack(anchor="w")

            # Right: pill toggle (drawn on a Canvas for smooth appearance)
            pill = tk.Canvas(row, width=52, height=28, bg=BG_CARD,
                             highlightthickness=0, cursor="hand2")
            pill.pack(side="right")
            self._pills[key] = pill
            self._draw_pill(pill, on=True)   # default ON until server responds

            def _make_click(k=key):
                def _click(event=None):
                    self._vars[k].set(not self._vars[k].get())
                    self._draw_pill(self._pills[k], self._vars[k].get())
                    self._save(k)
                return _click

            pill.bind("<Button-1>", _make_click())

        # ── Footer: status label + close button ─────────────────────────────
        tk.Frame(self, height=1, bg=BORDER).pack(fill="x", pady=(12, 0))
        foot = tk.Frame(self, bg=BG_CARD, padx=24, pady=10)
        foot.pack(fill="x")
        tk.Label(foot, textvariable=self._status_var,
                 bg=BG_CARD, fg=TEXT_SEC, font=FONT_SM).pack(side="left")
        _btn(foot, "Close", self.destroy, color=ACCENT).pack(
            side="right", ipadx=20, ipady=4)

        # Load current settings from server
        self._load()

    # ── Drawing ─────────────────────────────────────────────────────────────

    def _draw_pill(self, canvas: tk.Canvas, on: bool):
        """Draw a rounded pill toggle on the given Canvas widget."""
        canvas.delete("all")
        fc = ACCENT if on else "#334155"
        # Pill body (three overlapping shapes → rounded rect)
        canvas.create_oval(0, 2, 28, 26,  fill=fc, outline="")
        canvas.create_oval(24, 2, 52, 26, fill=fc, outline="")
        canvas.create_rectangle(14, 2, 38, 26, fill=fc, outline="")
        # Knob
        kx = 38 if on else 14
        canvas.create_oval(kx - 11, 4, kx + 11, 24, fill="white", outline="")

    # ── Data ────────────────────────────────────────────────────────────────

    def _load(self):
        """Fetch current settings from server in background thread."""
        def _do():
            data = self.api.get(f"/api/employees/{self.emp['id']}/monitoring")
            self.after(0, lambda: self._apply(data))

        threading.Thread(target=_do, daemon=True).start()

    def _apply(self, data: dict):
        """Apply server-returned settings to the toggle widgets."""
        if "_error" in data:
            self._status_var.set(f"Could not load settings: {data['_error']}")
            return
        for key, _, __ in self._CHANNELS:
            val = data.get(key, True)
            self._vars[key].set(val)
            self._draw_pill(self._pills[key], val)
        self._status_var.set("Ready \u2014 click a toggle to enable or disable a channel.")

    def _save(self, changed_key: str):
        """PATCH all 4 settings to server; called whenever a toggle flips."""
        body = {k: v.get() for k, v in self._vars.items()}
        self._status_var.set("Saving\u2026")

        def _do():
            result = self.api.patch(
                f"/api/employees/{self.emp['id']}/monitoring", body)
            if "_error" in result:
                self.after(0, lambda: self._status_var.set(
                    f"Error saving: {result['_error']}"))
            else:
                lbl   = next(l for k, l, _ in self._CHANNELS if k == changed_key)
                state = "ON \u2705" if body[changed_key] else "OFF \u274c"
                self.after(0, lambda: self._status_var.set(
                    f"Saved \u2014 {lbl.strip()} is now {state}"))

        threading.Thread(target=_do, daemon=True).start()
