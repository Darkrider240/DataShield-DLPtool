"""
DataShield — Admin Management Console (Tkinter)
─────────────────────────────────────────────────
Purpose:
  A local desktop console for admins to manage DataShield without a browser.
  Useful for on-premises, offline, or quick-access scenarios.

  Tabs:
    Overview   — live stats: employees, open alerts, today's events
    Employees  — list all employees, set PIN, flag/unflag, add new
    Alerts     — open alert inbox with acknowledge action
    Policies   — view active policies, push updates to all agents
    Settings   — encryption status, rotate keys, server info
"""
import os
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import httpx
from gui.monitoring_dialog import MonitoringDialog


# ─────────────────────────────────────────────────────────────────────────────
#  Colour / style constants  (matching the dark web dashboard palette)
# ─────────────────────────────────────────────────────────────────────────────
BG_MAIN  = "#0b0f1a"
BG_CARD  = "#0f172a"
BG_ROW   = "#1e293b"
BG_ROW2  = "#162032"
BORDER   = "#1e293b"
ACCENT   = "#6366f1"
ACCENT_H = "#818cf8"
TEXT_PRI = "#e2e8f0"
TEXT_SEC = "#94a3b8"
TEXT_MUT = "#475569"
DANGER   = "#ef4444"
WARN     = "#f59e0b"
OK       = "#22c55e"
BLUE     = "#3b82f6"

SEV_COLORS = {
    "CRITICAL": DANGER,
    "HIGH":     "#f97316",
    "MEDIUM":   WARN,
    "LOW":      BLUE,
}
RISK_COLORS = {
    "HIGH":   DANGER,
    "MEDIUM": WARN,
    "LOW":    BLUE,
    "CLEAN":  OK,
}

FONT      = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_SM   = ("Segoe UI", 9)
FONT_H    = ("Segoe UI", 13, "bold")
FONT_MONO = ("Consolas", 9)


# ─────────────────────────────────────────────────────────────────────────────
#  HTTP helper
# ─────────────────────────────────────────────────────────────────────────────
class APIClient:
    def __init__(self, server_url: str, token: str):
        self.base   = server_url.rstrip("/")
        self.token  = token
        self._http  = httpx.Client(
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0
        )

    def get(self, path: str, **params):
        try:
            r = self._http.get(f"{self.base}{path}", params=params)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"_error": str(e)}

    def post(self, path: str, body: dict):
        try:
            r = self._http.post(f"{self.base}{path}", json=body)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"_error": str(e)}

    def patch(self, path: str, body: dict = None):
        try:
            r = self._http.patch(f"{self.base}{path}", json=body or {})
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"_error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
#  Reusable UI helpers
# ─────────────────────────────────────────────────────────────────────────────
def _section(parent, text):
    f = tk.Frame(parent, bg=BG_MAIN)
    f.pack(fill="x", padx=20, pady=(14, 4))
    tk.Label(f, text=text.upper(), bg=BG_MAIN, fg=TEXT_MUT,
             font=("Segoe UI", 8, "bold")).pack(anchor="w")
    tk.Frame(f, height=1, bg=BORDER).pack(fill="x", pady=(3, 0))
    return f


def _card(parent, **pack_kw):
    f = tk.Frame(parent, bg=BG_CARD, bd=0, relief="flat",
                 highlightbackground=BORDER, highlightthickness=1)
    f.pack(**pack_kw)
    return f


def _lbl(parent, text, fg=TEXT_PRI, font=None, **kw):
    return tk.Label(parent, text=text, bg=parent.cget("bg"),
                    fg=fg, font=font or FONT, **kw)


def _btn(parent, text, cmd, color=ACCENT, fg="white", **kw):
    b = tk.Button(parent, text=text, command=cmd,
                  bg=color, fg=fg, activebackground=ACCENT_H,
                  activeforeground="white", relief="flat",
                  font=FONT_BOLD, cursor="hand2", bd=0, **kw)
    return b


def _stat_card(parent, label: str, value: str, color: str = ACCENT):
    card = tk.Frame(parent, bg=BG_CARD,
                    highlightbackground=BORDER, highlightthickness=1)
    card.pack(side="left", expand=True, fill="both", padx=6)
    tk.Label(card, text=value, bg=BG_CARD, fg=color,
             font=("Segoe UI", 26, "bold")).pack(pady=(16, 2))
    tk.Label(card, text=label, bg=BG_CARD, fg=TEXT_SEC,
             font=FONT_SM).pack(pady=(0, 14))
    return card


# ─────────────────────────────────────────────────────────────────────────────
#  Scrollable frame
# ─────────────────────────────────────────────────────────────────────────────
class ScrollFrame(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        canvas = tk.Canvas(self, bg=kw.get("bg", BG_MAIN),
                           highlightthickness=0)
        sb = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.inner = tk.Frame(canvas, bg=kw.get("bg", BG_MAIN))
        self.inner.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)


# ─────────────────────────────────────────────────────────────────────────────
#  Individual tab frames
# ─────────────────────────────────────────────────────────────────────────────

class OverviewTab(tk.Frame):
    def __init__(self, parent, api: APIClient):
        super().__init__(parent, bg=BG_MAIN)
        self.api = api
        self._build()
        self.refresh()

    def _build(self):
        tk.Label(self, text="System Overview", bg=BG_MAIN, fg=TEXT_PRI,
                 font=FONT_H).pack(anchor="w", padx=20, pady=(20, 4))
        tk.Label(self, text="Live statistics from the DataShield server",
                 bg=BG_MAIN, fg=TEXT_MUT, font=FONT_SM).pack(anchor="w", padx=20)
        tk.Frame(self, height=1, bg=BORDER).pack(fill="x", padx=20, pady=12)

        # Stat cards row
        self._stat_row = tk.Frame(self, bg=BG_MAIN)
        self._stat_row.pack(fill="x", padx=14, pady=(0, 16))
        self._emp_card  = _stat_card(self._stat_row, "Employees",    "—", ACCENT)
        self._alt_card  = _stat_card(self._stat_row, "Open Alerts",  "—", DANGER)
        self._evt_card  = _stat_card(self._stat_row, "Events Today", "—", BLUE)
        self._flg_card  = _stat_card(self._stat_row, "Flagged",      "—", WARN)

        # Refresh button
        btn_row = tk.Frame(self, bg=BG_MAIN)
        btn_row.pack(anchor="e", padx=20)
        _btn(btn_row, "↻  Refresh", self.refresh).pack()

        # Recent alerts preview
        _section(self, "Recent Open Alerts")
        self._alert_frame = tk.Frame(self, bg=BG_MAIN)
        self._alert_frame.pack(fill="x", padx=20)

    def _update_stat(self, card_frame, value: str):
        # The value label is the first child
        for w in card_frame.winfo_children():
            if isinstance(w, tk.Label) and w.cget("font") and "26" in str(w.cget("font")):
                w.config(text=value)
                break

    def refresh(self):
        def _load():
            metrics  = self.api.get("/api/reports/metrics")
            alerts   = self.api.get("/api/alerts", status="OPEN", per_page=5)
            emps     = self.api.get("/api/employees", per_page=1)

            self.after(0, lambda: self._apply(metrics, alerts))

        threading.Thread(target=_load, daemon=True).start()

    def _apply(self, metrics: dict, alerts):
        if "_error" not in metrics:
            self._update_stat(self._emp_card,  str(metrics.get("total_employees", "—")))
            self._update_stat(self._alt_card,  str(metrics.get("open_alerts", "—")))
            self._update_stat(self._evt_card,  str(metrics.get("total_events", "—")))
            self._update_stat(self._flg_card,  str(metrics.get("flagged_employees", "—")))

        for w in self._alert_frame.winfo_children():
            w.destroy()

        if isinstance(alerts, list) and alerts:
            for a in alerts:
                row = tk.Frame(self._alert_frame, bg=BG_ROW,
                               highlightbackground=BORDER, highlightthickness=1)
                row.pack(fill="x", pady=3, ipady=8, padx=0)
                sev   = a.get("severity", "")
                color = SEV_COLORS.get(sev, TEXT_SEC)
                tk.Label(row, text=f"  ● {sev}", bg=BG_ROW, fg=color,
                         font=FONT_BOLD, width=12, anchor="w").pack(side="left")
                tk.Label(row, text=a.get("title", ""), bg=BG_ROW, fg=TEXT_PRI,
                         font=FONT, anchor="w").pack(side="left", padx=8)
        else:
            tk.Label(self._alert_frame, text="No open alerts  ✓",
                     bg=BG_MAIN, fg=OK, font=FONT).pack(pady=12)


class EmployeesTab(tk.Frame):
    def __init__(self, parent, api: APIClient):
        super().__init__(parent, bg=BG_MAIN)
        self.api  = api
        self._employees: list = []
        self._build()
        self.refresh()

    def _build(self):
        # Header
        hdr = tk.Frame(self, bg=BG_MAIN)
        hdr.pack(fill="x", padx=20, pady=(18, 0))
        tk.Label(hdr, text="Employee Management", bg=BG_MAIN, fg=TEXT_PRI,
                 font=FONT_H).pack(side="left")
        btn_r = tk.Frame(hdr, bg=BG_MAIN)
        btn_r.pack(side="right")
        _btn(btn_r, "+ Add Employee", self._add_employee).pack(side="left", padx=(0, 8))
        _btn(btn_r, "↻ Refresh", self.refresh,
             color=BG_ROW).pack(side="left")

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x", padx=20, pady=10)

        # Table header
        cols_frame = tk.Frame(self, bg=BG_CARD)
        cols_frame.pack(fill="x", padx=20)
        for txt, w in [("Name / Email", 260), ("Department", 130),
                       ("Risk", 80), ("Score", 70), ("Flagged", 70), ("Actions", 200)]:
            tk.Label(cols_frame, text=txt, bg=BG_CARD, fg=TEXT_MUT,
                     font=("Segoe UI", 8, "bold"), width=w // 8,
                     anchor="w").pack(side="left", padx=6, pady=8)

        # Scrollable rows
        sf = ScrollFrame(self, bg=BG_MAIN)
        sf.pack(fill="both", expand=True, padx=20)
        self._rows_frame = sf.inner

    def refresh(self):
        def _load():
            data = self.api.get("/api/employees", per_page=100)
            self.after(0, lambda: self._render(data if isinstance(data, list) else []))
        threading.Thread(target=_load, daemon=True).start()

    def _render(self, employees: list):
        self._employees = employees
        for w in self._rows_frame.winfo_children():
            w.destroy()

        if not employees:
            tk.Label(self._rows_frame, text="No employees registered yet.",
                     bg=BG_MAIN, fg=TEXT_MUT, font=FONT).pack(pady=24)
            return

        for i, emp in enumerate(employees):
            row_bg = BG_ROW if i % 2 == 0 else BG_ROW2
            row = tk.Frame(self._rows_frame, bg=row_bg,
                           highlightbackground=BORDER, highlightthickness=1)
            row.pack(fill="x", pady=2, ipady=6)

            # Name + email column
            name_cell = tk.Frame(row, bg=row_bg, width=260)
            name_cell.pack(side="left", padx=8)
            tk.Label(name_cell, text=emp.get("full_name") or emp.get("email", ""),
                     bg=row_bg, fg=TEXT_PRI, font=FONT_BOLD, anchor="w").pack(anchor="w")
            tk.Label(name_cell, text=emp.get("email", ""),
                     bg=row_bg, fg=TEXT_MUT, font=FONT_SM, anchor="w").pack(anchor="w")

            # Department
            tk.Label(row, text=emp.get("department", "—"),
                     bg=row_bg, fg=TEXT_SEC, font=FONT,
                     width=16, anchor="w").pack(side="left", padx=4)

            # Risk badge
            rl    = emp.get("risk_level", "CLEAN")
            rc    = RISK_COLORS.get(rl, TEXT_SEC)
            tk.Label(row, text=rl, bg=row_bg, fg=rc,
                     font=FONT_BOLD, width=8, anchor="w").pack(side="left", padx=4)

            # Score
            tk.Label(row, text=f"{emp.get('risk_score', 0):.1f}",
                     bg=row_bg, fg=TEXT_PRI, font=FONT_MONO,
                     width=7, anchor="w").pack(side="left", padx=4)

            # Flagged
            flagged = emp.get("is_flagged", False)
            tk.Label(row, text="⚑ Yes" if flagged else "—",
                     bg=row_bg, fg=DANGER if flagged else TEXT_MUT,
                     font=FONT_SM, width=8, anchor="w").pack(side="left", padx=4)

            # Action buttons
            acts = tk.Frame(row, bg=row_bg)
            acts.pack(side="left", padx=8)

            _btn(acts, "🔑 PIN", lambda e=emp: self._set_pin(e),
                 color=BG_CARD).pack(side="left", padx=2, ipadx=4, ipady=2)

            _btn(acts, "🔒 Monitoring", lambda e=emp: self._edit_monitoring(e),
                 color="#1a2744", fg="#93c5fd").pack(side="left", padx=2, ipadx=4, ipady=2)

            if flagged:
                _btn(acts, "✓ Unflag", lambda e=emp: self._unflag(e),
                     color="#1e3a2e", fg=OK).pack(side="left", padx=2, ipadx=4, ipady=2)
            else:
                _btn(acts, "⚑ Flag", lambda e=emp: self._flag(e),
                     color="#3a1e1e", fg=DANGER).pack(side="left", padx=2, ipadx=4, ipady=2)

    def _edit_monitoring(self, emp: dict):
        dlg = MonitoringDialog(self, self.api, emp)
        self.wait_window(dlg)

    def _set_pin(self, emp: dict):
        pin = simpledialog.askstring(
            "Set PIN",
            f"Set login PIN for {emp.get('full_name') or emp.get('email')}:\n"
            "(minimum 4 characters)",
            show="*", parent=self
        )
        if not pin:
            return
        if len(pin) < 4:
            messagebox.showwarning("PIN too short", "PIN must be at least 4 characters.", parent=self)
            return
        result = self.api.post(f"/api/employees/{emp['id']}/set-pin", {"pin": pin})
        if "_error" in result:
            messagebox.showerror("Error", f"Failed to set PIN:\n{result['_error']}", parent=self)
        else:
            messagebox.showinfo("PIN Set", f"PIN set successfully for {emp.get('full_name') or emp.get('email')}.", parent=self)

    def _flag(self, emp: dict):
        reason = simpledialog.askstring(
            "Flag Employee",
            f"Flag {emp.get('full_name') or emp.get('email')} for review?\n\nReason:",
            parent=self
        )
        if reason is None:
            return
        result = self.api.post(f"/api/employees/{emp['id']}/flag", {"reason": reason or "Manually flagged by admin"})
        if "_error" not in result:
            self.refresh()

    def _unflag(self, emp: dict):
        if messagebox.askyesno("Unflag", f"Remove flag from {emp.get('full_name') or emp.get('email')}?", parent=self):
            result = self.api.post(f"/api/employees/{emp['id']}/unflag", {})
            if "_error" not in result:
                self.refresh()

    def _add_employee(self):
        dlg = _AddEmployeeDialog(self, self.api)
        self.wait_window(dlg)
        self.refresh()


class _AddEmployeeDialog(tk.Toplevel):
    def __init__(self, parent, api: APIClient):
        super().__init__(parent)
        self.api = api
        self.title("Add Employee")
        self.configure(bg=BG_CARD)
        self.resizable(False, False)
        W, H = 400, 340
        self.geometry(f"{W}x{H}")

        tk.Label(self, text="Add New Employee", bg=BG_CARD, fg=TEXT_PRI,
                 font=FONT_H).pack(pady=(20, 4))
        tk.Frame(self, height=1, bg=BORDER).pack(fill="x", padx=20, pady=8)

        form = tk.Frame(self, bg=BG_CARD, padx=24)
        form.pack(fill="x")

        self._fields = {}
        for label, key in [("Full Name", "full_name"), ("Email", "email"),
                            ("Department", "department"), ("Job Title", "job_title")]:
            tk.Label(form, text=label, bg=BG_CARD, fg=TEXT_SEC,
                     font=FONT_SM, anchor="w").pack(fill="x", pady=(8, 1))
            var = tk.StringVar()
            tk.Entry(form, textvariable=var, bg=BG_ROW, fg=TEXT_PRI,
                     insertbackground=TEXT_PRI, relief="flat",
                     font=FONT, bd=0).pack(fill="x", ipady=8)
            tk.Frame(form, height=1, bg=BORDER).pack(fill="x")
            self._fields[key] = var

        self._err = tk.StringVar()
        tk.Label(self, textvariable=self._err, bg=BG_CARD, fg=DANGER,
                 font=FONT_SM, wraplength=340).pack(pady=4)

        _btn(self, "Add Employee", self._submit).pack(
            fill="x", padx=24, ipady=10, pady=(4, 16))

    def _submit(self):
        body = {k: v.get().strip() for k, v in self._fields.items()}
        if not body["email"] or "@" not in body["email"]:
            self._err.set("A valid email is required.")
            return
        if not body["full_name"]:
            self._err.set("Full name is required.")
            return
        result = self.api.post("/api/employees", body)
        if "_error" in result:
            self._err.set(f"Error: {result['_error']}")
        else:
            self.destroy()


class AlertsTab(tk.Frame):
    def __init__(self, parent, api: APIClient):
        super().__init__(parent, bg=BG_MAIN)
        self.api = api
        self._build()
        self.refresh()

    def _build(self):
        hdr = tk.Frame(self, bg=BG_MAIN)
        hdr.pack(fill="x", padx=20, pady=(18, 0))
        tk.Label(hdr, text="Alert Inbox", bg=BG_MAIN, fg=TEXT_PRI,
                 font=FONT_H).pack(side="left")
        _btn(hdr, "↻ Refresh", self.refresh, color=BG_ROW).pack(side="right")

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x", padx=20, pady=10)

        sf = ScrollFrame(self, bg=BG_MAIN)
        sf.pack(fill="both", expand=True, padx=20)
        self._rows = sf.inner

    def refresh(self):
        def _load():
            data = self.api.get("/api/alerts", status="OPEN", per_page=50)
            self.after(0, lambda: self._render(data if isinstance(data, list) else []))
        threading.Thread(target=_load, daemon=True).start()

    def _render(self, alerts: list):
        for w in self._rows.winfo_children():
            w.destroy()

        if not alerts:
            tk.Label(self._rows, text="✓  No open alerts",
                     bg=BG_MAIN, fg=OK, font=FONT).pack(pady=24)
            return

        for a in alerts:
            sev   = a.get("severity", "")
            color = SEV_COLORS.get(sev, TEXT_SEC)

            row = tk.Frame(self._rows, bg=BG_ROW,
                           highlightbackground=color, highlightthickness=1)
            row.pack(fill="x", pady=4, ipady=10)

            # Left: severity dot + info
            left = tk.Frame(row, bg=BG_ROW)
            left.pack(side="left", padx=12, fill="x", expand=True)
            tk.Label(left, text=f"● {sev}", bg=BG_ROW, fg=color,
                     font=FONT_BOLD).pack(anchor="w")
            tk.Label(left, text=a.get("title", ""), bg=BG_ROW, fg=TEXT_PRI,
                     font=FONT).pack(anchor="w")
            tk.Label(left, text=a.get("description", "")[:100],
                     bg=BG_ROW, fg=TEXT_MUT, font=FONT_SM,
                     wraplength=500, anchor="w").pack(anchor="w")

            # Right: acknowledge button
            _btn(row, "✓ Acknowledge",
                 lambda aid=a["id"]: self._ack(aid),
                 color="#1e2d1e", fg=OK).pack(side="right", padx=12, ipady=4, ipadx=6)

    def _ack(self, alert_id: str):
        result = self.api.patch(f"/api/alerts/{alert_id}/acknowledge")
        if "_error" not in result:
            self.refresh()
        else:
            messagebox.showerror("Error", result["_error"], parent=self)


class PoliciesTab(tk.Frame):
    def __init__(self, parent, api: APIClient):
        super().__init__(parent, bg=BG_MAIN)
        self.api = api
        self._build()
        self.refresh()

    def _build(self):
        hdr = tk.Frame(self, bg=BG_MAIN)
        hdr.pack(fill="x", padx=20, pady=(18, 0))
        tk.Label(hdr, text="DLP Policies", bg=BG_MAIN, fg=TEXT_PRI,
                 font=FONT_H).pack(side="left")
        btn_r = tk.Frame(hdr, bg=BG_MAIN)
        btn_r.pack(side="right")
        _btn(btn_r, "⬆ Push to All Agents", self._push_all).pack(side="left", padx=(0, 8))
        _btn(btn_r, "↻ Refresh", self.refresh, color=BG_ROW).pack(side="left")

        tk.Label(self, text="Active rules pushed to all registered agent machines.",
                 bg=BG_MAIN, fg=TEXT_MUT, font=FONT_SM).pack(anchor="w", padx=20)
        tk.Frame(self, height=1, bg=BORDER).pack(fill="x", padx=20, pady=10)

        # Status bar
        self._status_var = tk.StringVar(value="")
        tk.Label(self, textvariable=self._status_var, bg=BG_MAIN, fg=OK,
                 font=FONT_SM).pack(anchor="w", padx=20)

        sf = ScrollFrame(self, bg=BG_MAIN)
        sf.pack(fill="both", expand=True, padx=20)
        self._rows = sf.inner

    def refresh(self):
        def _load():
            data = self.api.get("/api/policies")
            self.after(0, lambda: self._render(data if isinstance(data, list) else []))
        threading.Thread(target=_load, daemon=True).start()

    def _render(self, policies: list):
        for w in self._rows.winfo_children():
            w.destroy()
        for p in policies:
            row = tk.Frame(self._rows, bg=BG_ROW,
                           highlightbackground=BORDER, highlightthickness=1)
            row.pack(fill="x", pady=3, ipady=8)
            tk.Label(row, text=f"  {p.get('name', '')}",
                     bg=BG_ROW, fg=TEXT_PRI, font=FONT_BOLD,
                     width=28, anchor="w").pack(side="left")
            tk.Label(row, text=p.get("category", ""),
                     bg=BG_ROW, fg=TEXT_MUT, font=FONT_SM,
                     width=14, anchor="w").pack(side="left")
            tk.Label(row, text=p.get("pattern", ""),
                     bg=BG_ROW, fg=ACCENT, font=FONT_MONO,
                     anchor="w").pack(side="left", padx=8)

    def _push_all(self):
        if not messagebox.askyesno("Push Policies",
                                   "Push current policies to ALL registered agents?\n"
                                   "Agents will fetch updates on next heartbeat.",
                                   parent=self):
            return
        result = self.api.post("/api/policies/push", {})
        if "_error" in result:
            messagebox.showerror("Error", result["_error"], parent=self)
        else:
            self._status_var.set("✓ Policies pushed — agents will update on next heartbeat.")


class SettingsTab(tk.Frame):
    def __init__(self, parent, api: APIClient, server_url: str):
        super().__init__(parent, bg=BG_MAIN)
        self.api        = api
        self.server_url = server_url
        self._build()
        self.refresh()

    def _build(self):
        tk.Label(self, text="Settings & Encryption", bg=BG_MAIN, fg=TEXT_PRI,
                 font=FONT_H).pack(anchor="w", padx=20, pady=(18, 4))
        tk.Frame(self, height=1, bg=BORDER).pack(fill="x", padx=20, pady=(0, 12))

        # Server info
        _section(self, "Server")
        info = _card(self, fill="x", padx=20, pady=(0, 4))
        info.configure(padx=16, pady=10)
        row = tk.Frame(info, bg=BG_CARD)
        row.pack(fill="x")
        tk.Label(row, text="Server URL:", bg=BG_CARD, fg=TEXT_MUT,
                 font=FONT_SM, width=16, anchor="w").pack(side="left")
        tk.Label(row, text=self.server_url, bg=BG_CARD, fg=TEXT_PRI,
                 font=FONT_MONO).pack(side="left")

        # Encryption section
        _section(self, "Encryption Key Management")
        enc = _card(self, fill="x", padx=20, pady=(0, 4))
        enc.configure(padx=16, pady=14)

        self._key_age_var    = tk.StringVar(value="Loading…")
        self._dek_total_var  = tk.StringVar(value="Loading…")
        self._rotation_var   = tk.StringVar(value="Loading…")
        self._enc_status_var = tk.StringVar(value="")

        for label, var in [
            ("Master Key Age (days):", self._key_age_var),
            ("Total Employees (DEKs):", self._dek_total_var),
            ("Rotation Needed:",        self._rotation_var),
        ]:
            r = tk.Frame(enc, bg=BG_CARD)
            r.pack(fill="x", pady=3)
            tk.Label(r, text=label, bg=BG_CARD, fg=TEXT_MUT,
                     font=FONT_SM, width=24, anchor="w").pack(side="left")
            tk.Label(r, textvariable=var, bg=BG_CARD, fg=TEXT_PRI,
                     font=FONT_BOLD, anchor="w").pack(side="left")

        btn_r = tk.Frame(enc, bg=BG_CARD)
        btn_r.pack(fill="x", pady=(12, 0))
        _btn(btn_r, "↻ Refresh Status", self.refresh,
             color=BG_ROW).pack(side="left", ipadx=6, ipady=4)
        _btn(btn_r, "🔑 Rotate All Keys", self._rotate,
             color="#3a1e1e", fg=DANGER).pack(side="left", padx=8, ipadx=6, ipady=4)

        tk.Label(enc, textvariable=self._enc_status_var, bg=BG_CARD,
                 fg=OK, font=FONT_SM).pack(anchor="w", pady=(8, 0))

    def refresh(self):
        def _load():
            data = self.api.get("/api/encryption/status")
            self.after(0, lambda: self._apply(data))
        threading.Thread(target=_load, daemon=True).start()

    def _apply(self, data: dict):
        if "_error" in data:
            self._key_age_var.set("Error")
            self._dek_total_var.set("Error")
            self._rotation_var.set("Error")
            return
        age      = data.get("master_key_age_days", 0)
        total    = data.get("total_employees", 0)
        needed   = data.get("dek_rotation_needed", False)
        self._key_age_var.set(f"{age} days" if age < 999 else "Never rotated")
        self._dek_total_var.set(str(total))
        self._rotation_var.set("⚠ YES — rotate soon" if needed else "✓ Not required")

    def _rotate(self):
        if not messagebox.askyesno(
            "Rotate Keys",
            "This will rotate ALL employee encryption keys.\n"
            "All existing events will be re-encrypted with new keys.\n\n"
            "This may take a moment. Proceed?",
            parent=self
        ):
            return
        self._enc_status_var.set("Rotating keys… please wait.")
        self.update()
        def _do():
            result = self.api.post("/api/encryption/rotate", {})
            def _done():
                if "_error" in result:
                    self._enc_status_var.set(f"Error: {result['_error']}")
                else:
                    n = result.get("employees_rotated", 0)
                    self._enc_status_var.set(f"✓ Rotated {n} employee key(s) successfully.")
                    self.refresh()
            self.after(0, _done)
        threading.Thread(target=_do, daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
#  Main Admin Console Window
# ─────────────────────────────────────────────────────────────────────────────
class AdminConsole(tk.Tk):
    """
    The DataShield desktop management console for administrators.
    Tabs: Overview | Employees | Alerts | Policies | Settings
    """
    def __init__(self, admin_name: str, admin_email: str,
                 server_url: str, token: str):
        super().__init__()
        self.admin_name  = admin_name
        self.admin_email = admin_email
        self.server_url  = server_url
        self.api         = APIClient(server_url, token)

        self.title(f"DataShield Management Console  —  {admin_name}")
        self.geometry("1060x700")
        self.minsize(880, 580)
        self.configure(bg=BG_MAIN)

        self._build_header()
        self._build_tabs()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_header(self):
        hdr = tk.Frame(self, bg="#060a13", height=52)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        # Logo + title
        tk.Label(hdr, text="  🛡 DataShield", bg="#060a13", fg=ACCENT,
                 font=("Segoe UI", 14, "bold")).pack(side="left", padx=4)
        tk.Label(hdr, text="Management Console", bg="#060a13", fg=TEXT_MUT,
                 font=("Segoe UI", 10)).pack(side="left")

        # Right: user chip
        right = tk.Frame(hdr, bg="#060a13")
        right.pack(side="right", padx=16)
        avatar_txt = (admin_name := self.admin_name)[0].upper() if self.admin_name else "A"
        av = tk.Label(right, text=avatar_txt, bg=ACCENT, fg="white",
                      font=("Segoe UI", 10, "bold"), width=2)
        av.pack(side="left", padx=(0, 6))
        info = tk.Frame(right, bg="#060a13")
        info.pack(side="left")
        tk.Label(info, text=self.admin_name, bg="#060a13", fg=TEXT_PRI,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(info, text="Administrator", bg="#060a13", fg=TEXT_MUT,
                 font=("Segoe UI", 8)).pack(anchor="w")

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

    def _build_tabs(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook",        background=BG_MAIN, borderwidth=0)
        style.configure("TNotebook.Tab",    background=BG_CARD, foreground=TEXT_SEC,
                        padding=[16, 8], font=("Segoe UI", 9))
        style.map("TNotebook.Tab",
                  background=[("selected", BG_MAIN)],
                  foreground=[("selected", TEXT_PRI)])

        self._overview  = OverviewTab(nb,  self.api)
        self._employees = EmployeesTab(nb, self.api)
        self._alerts    = AlertsTab(nb,    self.api)
        self._policies  = PoliciesTab(nb,  self.api)
        self._settings  = SettingsTab(nb,  self.api, self.server_url)

        nb.add(self._overview,  text="  Overview  ")
        nb.add(self._employees, text="  Employees  ")
        nb.add(self._alerts,    text="  Alerts  ")
        nb.add(self._policies,  text="  Policies  ")
        nb.add(self._settings,  text="  Settings  ")

    def _on_close(self):
        self.destroy()
