"""
DataShield — Admin Management Console (Tkinter)
────────────────────────────────────────────────
PURPOSE: Local IT Helpdesk & Employee Enrollment tool.
This is NOT a duplicate of the web dashboard.

Web Dashboard  → remote monitoring, analytics, compliance, alerts, policies
This Console   → enroll new employees, set PINs, configure monitoring,
                  check which agents are connected/offline

Tabs:
  Overview         — quick stats + recent agent connections
  Employees        — manage employees (PIN / monitoring / flag)
  Enroll New       — step-by-step wizard to onboard a new employee
  Agent Status     — which endpoints are connected/offline
"""
import os
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import httpx
from gui.monitoring_dialog import MonitoringDialog

# ─── Colour palette (dark enterprise theme) ────────────────────────────────
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

RISK_COLORS = {"HIGH": DANGER, "MEDIUM": WARN, "LOW": BLUE, "CLEAN": OK}

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
#  Individual tab frames
# ─────────────────────────────────────────────────────────────────────────────

class OverviewTab(tk.Frame):
    def __init__(self, parent, api: APIClient):
        super().__init__(parent, bg=BG_MAIN)
        self.api = api
        self._build()
        self.refresh()

    def _build(self):
        # Header
        tk.Label(self, text="IT Admin Overview", bg=BG_MAIN, fg=TEXT_PRI, font=FONT_H).pack(anchor="w", padx=20, pady=(20,2))
        tk.Label(self, text="Quick view of employee enrollment and agent connections", bg=BG_MAIN, fg=TEXT_MUT, font=FONT_SM).pack(anchor="w", padx=20)
        tk.Frame(self, height=1, bg=BORDER).pack(fill="x", padx=20, pady=10)

        # Stat cards row
        self._stat_row = tk.Frame(self, bg=BG_MAIN)
        self._stat_row.pack(fill="x", padx=14, pady=(0,16))
        self._emp_card    = _stat_card(self._stat_row, "Total Employees", "—", ACCENT)
        self._online_card = _stat_card(self._stat_row, "Online Agents",   "—", OK)
        self._flag_card   = _stat_card(self._stat_row, "Flagged",         "—", WARN)
        self._today_card  = _stat_card(self._stat_row, "Events Today",    "—", BLUE)

        btn_row = tk.Frame(self, bg=BG_MAIN)
        btn_row.pack(anchor="e", padx=20)
        _btn(btn_row, "↻  Refresh", self.refresh).pack()

        # Recent connections
        _section(self, "Recent Agent Connections")
        self._conn_frame = tk.Frame(self, bg=BG_MAIN)
        self._conn_frame.pack(fill="x", padx=20)

    def _update_stat(self, card_frame, value: str):
        for w in card_frame.winfo_children():
            if isinstance(w, tk.Label) and "26" in str(w.cget("font")):
                w.config(text=value)
                break

    def refresh(self):
        def _load():
            metrics = self.api.get("/api/reports/metrics")
            agents  = self.api.get("/api/agents")
            self.after(0, lambda: self._apply(metrics, agents))
        threading.Thread(target=_load, daemon=True).start()

    def _apply(self, metrics, agents):
        if "_error" not in metrics:
            self._update_stat(self._emp_card,    str(metrics.get("total_employees", "—")))
            self._update_stat(self._flag_card,   str(metrics.get("flagged_employees", "—")))
            self._update_stat(self._today_card,  str(metrics.get("total_events", "—")))

        # Count online agents (last heartbeat < 5 min)
        if isinstance(agents, list):
            from datetime import datetime, timezone, timedelta
            now = datetime.now(timezone.utc)
            online = 0
            for a in agents:
                hb = a.get("last_heartbeat", "")
                if hb:
                    try:
                        dt = datetime.fromisoformat(hb.replace("Z","+00:00"))
                        if (now - dt) < timedelta(minutes=5):
                            online += 1
                    except: pass
            self._update_stat(self._online_card, str(online))

        for w in self._conn_frame.winfo_children():
            w.destroy()

        if isinstance(agents, list) and agents:
            for a in agents[:6]:
                row = tk.Frame(self._conn_frame, bg=BG_ROW,
                               highlightbackground=BORDER, highlightthickness=1)
                row.pack(fill="x", pady=2, ipady=8)

                # Online indicator
                try:
                    from datetime import datetime, timezone, timedelta
                    hb = a.get("last_heartbeat","")
                    dt = datetime.fromisoformat(hb.replace("Z","+00:00"))
                    is_online = (datetime.now(timezone.utc) - dt) < timedelta(minutes=5)
                except:
                    is_online = False

                dot_color = OK if is_online else DANGER
                tk.Label(row, text="●", bg=BG_ROW, fg=dot_color, font=FONT_BOLD, width=3).pack(side="left")
                tk.Label(row, text=a.get("employee_name") or a.get("employee_email",""),
                         bg=BG_ROW, fg=TEXT_PRI, font=FONT_BOLD, width=22, anchor="w").pack(side="left")
                tk.Label(row, text=a.get("hostname","—"),
                         bg=BG_ROW, fg=TEXT_SEC, font=FONT_MONO, width=18, anchor="w").pack(side="left")
                hb_str = a.get("last_heartbeat","Never")
                if hb_str and hb_str != "Never":
                    try:
                        from datetime import datetime, timezone
                        dt2 = datetime.fromisoformat(hb_str.replace("Z","+00:00"))
                        diff = datetime.now(timezone.utc) - dt2
                        mins = int(diff.total_seconds()//60)
                        hb_str = f"{mins}m ago" if mins < 60 else f"{mins//60}h ago"
                    except: pass
                tk.Label(row, text=hb_str, bg=BG_ROW, fg=TEXT_MUT, font=FONT_SM).pack(side="left", padx=8)
        else:
            tk.Label(self._conn_frame, text="No agents connected yet.",
                     bg=BG_MAIN, fg=TEXT_MUT, font=FONT).pack(pady=12)


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
        _btn(btn_r, "↻ Refresh", self.refresh,
             color=BG_ROW).pack(side="left")

        tk.Label(self, text="Manage existing employees — reset PINs, configure monitoring, flag for review.",
                 bg=BG_MAIN, fg=TEXT_MUT, font=FONT_SM).pack(anchor="w", padx=20, pady=(4, 0))
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
            tk.Label(self._rows_frame, text="No employees registered yet.\nUse the '✚ Enroll New' tab to add your first employee.",
                     bg=BG_MAIN, fg=TEXT_MUT, font=FONT, justify="center").pack(pady=24)
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


class EnrollmentWizardTab(tk.Frame):
    """
    Step-by-step employee enrollment wizard.
    IT admin uses this when setting up a new employee's machine.
    Steps: 1) Employee Info → 2) Set PIN → 3) Monitoring Channels → 4) Done
    """
    def __init__(self, parent, api: APIClient):
        super().__init__(parent, bg=BG_MAIN)
        self.api = api
        self._emp_id    = None   # set after Step 1 creates the employee
        self._emp_name  = ""
        self._emp_email = ""
        self._step      = 0

        self._frames = {}  # step_number → frame
        self._build()

    def _build(self):
        # Page title
        tk.Label(self, text="Enroll New Employee", bg=BG_MAIN, fg=TEXT_PRI, font=FONT_H).pack(anchor="w", padx=20, pady=(20,2))
        tk.Label(self, text="Walk through these steps to add an employee and set up their DataShield agent.",
                 bg=BG_MAIN, fg=TEXT_MUT, font=FONT_SM).pack(anchor="w", padx=20)
        tk.Frame(self, height=1, bg=BORDER).pack(fill="x", padx=20, pady=10)

        # Step indicator (breadcrumb)
        self._step_bar = tk.Frame(self, bg=BG_MAIN)
        self._step_bar.pack(fill="x", padx=20, pady=(0,12))
        self._step_labels = []
        for i, name in enumerate(["1. Employee Info", "2. Set PIN", "3. Monitoring", "4. Done"]):
            lbl = tk.Label(self._step_bar, text=name, bg=BG_MAIN, fg=TEXT_MUT, font=FONT_SM)
            lbl.pack(side="left", padx=(0, 24))
            self._step_labels.append(lbl)

        # Content area — different frame per step
        self._content = tk.Frame(self, bg=BG_MAIN)
        self._content.pack(fill="both", expand=True, padx=20)

        self._build_step0()  # Employee info
        self._build_step1()  # PIN
        self._build_step2()  # Monitoring
        self._build_step3()  # Done

        self._show_step(0)

    def _build_step0(self):
        """Step 1: Employee info form."""
        f = tk.Frame(self._content, bg=BG_MAIN)
        self._frames[0] = f

        card = tk.Frame(f, bg=BG_CARD, padx=28, pady=20,
                        highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", pady=4)

        tk.Label(card, text="Employee Details", bg=BG_CARD, fg=TEXT_PRI, font=FONT_BOLD).pack(anchor="w", pady=(0,14))

        self._fields = {}
        for label, key, placeholder in [
            ("Full Name *",   "full_name",  "Jane Smith"),
            ("Work Email *",  "email",      "jane@company.com"),
            ("Department",    "department", "Engineering"),
            ("Job Title",     "job_title",  "Software Developer"),
        ]:
            tk.Label(card, text=label, bg=BG_CARD, fg=TEXT_SEC, font=FONT_SM, anchor="w").pack(fill="x", pady=(8,2))
            var = tk.StringVar()
            ent = tk.Entry(card, textvariable=var, bg=BG_ROW, fg=TEXT_PRI,
                           insertbackground=TEXT_PRI, relief="flat", font=FONT, bd=0)
            ent.pack(fill="x", ipady=9)
            tk.Frame(card, height=1, bg=ACCENT).pack(fill="x")
            self._fields[key] = var

        self._step0_err = tk.StringVar()
        tk.Label(card, textvariable=self._step0_err, bg=BG_CARD, fg=DANGER, font=FONT_SM).pack(anchor="w", pady=(8,0))

        _btn(card, "Create Employee & Continue →", self._submit_step0).pack(
            fill="x", ipady=11, pady=(16,0))

    def _build_step1(self):
        """Step 2: Set PIN."""
        f = tk.Frame(self._content, bg=BG_MAIN)
        self._frames[1] = f

        card = tk.Frame(f, bg=BG_CARD, padx=28, pady=20,
                        highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", pady=4)

        self._pin_target_label = tk.StringVar(value="Set a login PIN")
        tk.Label(card, textvariable=self._pin_target_label, bg=BG_CARD, fg=TEXT_PRI, font=FONT_BOLD).pack(anchor="w", pady=(0,8))
        tk.Label(card, text="The employee will use this PIN to sign in to their DataShield agent.",
                 bg=BG_CARD, fg=TEXT_MUT, font=FONT_SM).pack(anchor="w", pady=(0,16))

        tk.Label(card, text="PIN (min. 4 characters)", bg=BG_CARD, fg=TEXT_SEC, font=FONT_SM).pack(anchor="w")
        self._pin_var = tk.StringVar()
        tk.Entry(card, textvariable=self._pin_var, show="●", bg=BG_ROW, fg=TEXT_PRI,
                 insertbackground=TEXT_PRI, relief="flat", font=FONT, bd=0).pack(fill="x", ipady=9)
        tk.Frame(card, height=1, bg=ACCENT).pack(fill="x", pady=(0,12))

        tk.Label(card, text="Confirm PIN", bg=BG_CARD, fg=TEXT_SEC, font=FONT_SM).pack(anchor="w")
        self._pin2_var = tk.StringVar()
        tk.Entry(card, textvariable=self._pin2_var, show="●", bg=BG_ROW, fg=TEXT_PRI,
                 insertbackground=TEXT_PRI, relief="flat", font=FONT, bd=0).pack(fill="x", ipady=9)
        tk.Frame(card, height=1, bg=ACCENT).pack(fill="x")

        self._step1_err = tk.StringVar()
        tk.Label(card, textvariable=self._step1_err, bg=BG_CARD, fg=DANGER, font=FONT_SM).pack(anchor="w", pady=(8,0))

        btn_row = tk.Frame(card, bg=BG_CARD)
        btn_row.pack(fill="x", pady=(16,0))
        _btn(btn_row, "← Back", lambda: self._show_step(0), color=BG_ROW).pack(side="left", ipadx=12, ipady=9)
        _btn(btn_row, "Set PIN & Continue →", self._submit_step1).pack(side="right", ipadx=12, ipady=9)

    def _build_step2(self):
        """Step 3: Monitoring channels."""
        f = tk.Frame(self._content, bg=BG_MAIN)
        self._frames[2] = f

        card = tk.Frame(f, bg=BG_CARD, padx=28, pady=20,
                        highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", pady=4)

        tk.Label(card, text="Configure Monitoring Channels", bg=BG_CARD, fg=TEXT_PRI, font=FONT_BOLD).pack(anchor="w", pady=(0,4))
        tk.Label(card, text="Choose which DLP channels to enable for this employee. Defaults are all ON.",
                 bg=BG_CARD, fg=TEXT_MUT, font=FONT_SM).pack(anchor="w", pady=(0,16))

        self._mon_vars = {}
        CHANNELS = [
            ("monitor_clipboard", "📋 Clipboard Monitoring",  "Intercept sensitive copy/paste"),
            ("monitor_usb",       "🔌 USB Drive Monitoring",  "Detect USB insertions"),
            ("monitor_webmail",   "✉️  Webmail / Email",       "Scan outgoing email content"),
            ("monitor_file_scan", "📁 File Scanning",          "Employee can scan files manually"),
        ]
        for key, label, desc in CHANNELS:
            var = tk.BooleanVar(value=True)
            self._mon_vars[key] = var
            row = tk.Frame(card, bg=BG_CARD)
            row.pack(fill="x", pady=6)
            cb = tk.Checkbutton(row, variable=var, bg=BG_CARD, fg=TEXT_PRI,
                                activebackground=BG_CARD, selectcolor=ACCENT,
                                font=FONT_BOLD, text=label, cursor="hand2",
                                anchor="w")
            cb.pack(side="left")
            tk.Label(row, text=f"  —  {desc}", bg=BG_CARD, fg=TEXT_MUT, font=FONT_SM).pack(side="left")

        tk.Label(card, text="", bg=BG_CARD).pack()  # spacer

        btn_row = tk.Frame(card, bg=BG_CARD)
        btn_row.pack(fill="x", pady=(8,0))
        _btn(btn_row, "← Back", lambda: self._show_step(1), color=BG_ROW).pack(side="left", ipadx=12, ipady=9)
        _btn(btn_row, "Apply & Finish →", self._submit_step2).pack(side="right", ipadx=12, ipady=9)

    def _build_step3(self):
        """Step 4: Done."""
        f = tk.Frame(self._content, bg=BG_MAIN)
        self._frames[3] = f

        card = tk.Frame(f, bg=BG_CARD, padx=28, pady=28,
                        highlightbackground="#22c55e", highlightthickness=2)
        card.pack(fill="x", pady=4)

        tk.Label(card, text="✅ Employee Enrolled Successfully!", bg=BG_CARD, fg=OK,
                 font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=(0,8))

        self._done_name_var = tk.StringVar(value="")
        tk.Label(card, textvariable=self._done_name_var, bg=BG_CARD, fg=TEXT_PRI,
                 font=FONT_BOLD).pack(anchor="w", pady=(0,16))

        tk.Label(card, text="📋  Give the employee these setup instructions:",
                 bg=BG_CARD, fg=TEXT_SEC, font=FONT_BOLD).pack(anchor="w", pady=(0,8))

        steps_text = (
            "  1. On their workstation, open a terminal and run:\n"
            "         python main.py\n\n"
            "  2. In the login screen, enter:\n"
            "         Email  →  their work email\n"
            "         PIN    →  the PIN you just set\n\n"
            "  3. DataShield will activate and run silently in the system tray.\n\n"
            "  4. They can right-click the tray icon to open the agent\n"
            "     and scan files before sending."
        )
        tk.Label(card, text=steps_text, bg=BG_ROW, fg=TEXT_PRI, font=FONT_MONO,
                 justify="left", anchor="w", padx=16, pady=12,
                 relief="flat").pack(fill="x", pady=(0,16))

        btn_row = tk.Frame(card, bg=BG_CARD)
        btn_row.pack(fill="x")
        _btn(btn_row, "+ Enroll Another Employee", self._reset_wizard).pack(side="left", ipadx=12, ipady=9)

    def _show_step(self, step: int):
        self._step = step
        for s, frame in self._frames.items():
            frame.pack_forget()
        self._frames[step].pack(fill="both", expand=True)
        # Update step indicator colors
        for i, lbl in enumerate(self._step_labels):
            if i < step:
                lbl.config(fg=OK)
            elif i == step:
                lbl.config(fg=ACCENT)
            else:
                lbl.config(fg=TEXT_MUT)

    def _submit_step0(self):
        body = {k: v.get().strip() for k, v in self._fields.items()}
        if not body["full_name"]:
            self._step0_err.set("Full name is required."); return
        if not body["email"] or "@" not in body["email"]:
            self._step0_err.set("A valid email is required."); return
        self._step0_err.set("Creating employee…")
        def _do():
            result = self.api.post("/api/employees", body)
            if "_error" in result:
                self.after(0, lambda: self._step0_err.set(f"Error: {result['_error']}"))
            else:
                self._emp_id    = result.get("id")
                self._emp_name  = body["full_name"]
                self._emp_email = body["email"]
                self._pin_target_label.set(f"Set PIN for {self._emp_name}")
                self.after(0, lambda: self._show_step(1))
        threading.Thread(target=_do, daemon=True).start()

    def _submit_step1(self):
        pin  = self._pin_var.get()
        pin2 = self._pin2_var.get()
        if len(pin) < 4:
            self._step1_err.set("PIN must be at least 4 characters."); return
        if pin != pin2:
            self._step1_err.set("PINs do not match."); return
        self._step1_err.set("Setting PIN…")
        def _do():
            result = self.api.post(f"/api/employees/{self._emp_id}/set-pin", {"pin": pin})
            if "_error" in result:
                self.after(0, lambda: self._step1_err.set(f"Error: {result['_error']}"))
            else:
                self.after(0, lambda: self._show_step(2))
        threading.Thread(target=_do, daemon=True).start()

    def _submit_step2(self):
        body = {k: v.get() for k, v in self._mon_vars.items()}
        def _do():
            result = self.api.patch(f"/api/employees/{self._emp_id}/monitoring", body)
            self._done_name_var.set(
                f"{self._emp_name}  ({self._emp_email})")
            self.after(0, lambda: self._show_step(3))
        threading.Thread(target=_do, daemon=True).start()

    def _reset_wizard(self):
        self._emp_id    = None
        self._emp_name  = ""
        self._emp_email = ""
        for v in self._fields.values(): v.set("")
        self._pin_var.set("")
        self._pin2_var.set("")
        for v in self._mon_vars.values(): v.set(True)
        self._step0_err.set("")
        self._step1_err.set("")
        self._show_step(0)


class AgentStatusTab(tk.Frame):
    """Shows all registered endpoint agents with their connection status."""
    def __init__(self, parent, api: APIClient):
        super().__init__(parent, bg=BG_MAIN)
        self.api = api
        self._build()
        self.refresh()

    def _build(self):
        hdr = tk.Frame(self, bg=BG_MAIN)
        hdr.pack(fill="x", padx=20, pady=(18,0))
        tk.Label(hdr, text="Agent Status — Connected Endpoints",
                 bg=BG_MAIN, fg=TEXT_PRI, font=FONT_H).pack(side="left")
        _btn(hdr, "↻ Refresh", self.refresh, color=BG_ROW).pack(side="right")

        tk.Label(self, text="Endpoints where the DataShield agent has been installed and is reporting in.",
                 bg=BG_MAIN, fg=TEXT_MUT, font=FONT_SM).pack(anchor="w", padx=20)
        tk.Frame(self, height=1, bg=BORDER).pack(fill="x", padx=20, pady=10)

        # Column headers
        cols = tk.Frame(self, bg=BG_CARD)
        cols.pack(fill="x", padx=20)
        for txt, w in [("Status",14),("Employee",24),("Hostname",20),("Platform",12),("Last Seen",14)]:
            tk.Label(cols, text=txt, bg=BG_CARD, fg=TEXT_MUT,
                     font=("Segoe UI",8,"bold"), width=w, anchor="w").pack(side="left", padx=6, pady=8)

        sf = ScrollFrame(self, bg=BG_MAIN)
        sf.pack(fill="both", expand=True, padx=20)
        self._rows = sf.inner

    def refresh(self):
        def _load():
            data = self.api.get("/api/agents")
            self.after(0, lambda: self._render(data if isinstance(data, list) else []))
        threading.Thread(target=_load, daemon=True).start()

    def _render(self, agents: list):
        for w in self._rows.winfo_children():
            w.destroy()

        if not agents:
            tk.Label(self._rows, text="No agents registered yet.\nEnroll employees and ask them to run python main.py on their machine.",
                     bg=BG_MAIN, fg=TEXT_MUT, font=FONT, justify="center").pack(pady=32)
            return

        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)

        for i, a in enumerate(agents):
            row_bg = BG_ROW if i % 2 == 0 else BG_ROW2
            row = tk.Frame(self._rows, bg=row_bg,
                           highlightbackground=BORDER, highlightthickness=1)
            row.pack(fill="x", pady=2, ipady=8)

            # Online/offline
            hb = a.get("last_heartbeat","")
            is_online = False
            hb_str = "Never"
            if hb:
                try:
                    dt = datetime.fromisoformat(hb.replace("Z","+00:00"))
                    diff = now - dt
                    is_online = diff < timedelta(minutes=5)
                    mins = int(diff.total_seconds()//60)
                    hb_str = f"{mins}m ago" if mins < 60 else f"{mins//60}h {mins%60}m ago"
                except: pass

            status_color = OK if is_online else DANGER
            status_text  = "● ONLINE" if is_online else "● OFFLINE"
            tk.Label(row, text=status_text, bg=row_bg, fg=status_color,
                     font=FONT_BOLD, width=14, anchor="w").pack(side="left", padx=6)

            emp_name = a.get("employee_name") or a.get("employee_email","—")
            tk.Label(row, text=emp_name, bg=row_bg, fg=TEXT_PRI,
                     font=FONT, width=24, anchor="w").pack(side="left", padx=4)
            tk.Label(row, text=a.get("hostname","—"), bg=row_bg, fg=TEXT_SEC,
                     font=FONT_MONO, width=20, anchor="w").pack(side="left", padx=4)
            tk.Label(row, text=a.get("platform","—"), bg=row_bg, fg=TEXT_MUT,
                     font=FONT_SM, width=12, anchor="w").pack(side="left", padx=4)
            tk.Label(row, text=hb_str, bg=row_bg, fg=TEXT_MUT,
                     font=FONT_SM, width=14, anchor="w").pack(side="left", padx=4)


# ─────────────────────────────────────────────────────────────────────────────
#  Main Admin Console Window
# ─────────────────────────────────────────────────────────────────────────────
class AdminConsole(tk.Tk):
    """
    DataShield Desktop Management Console — for IT Admins & Helpdesk.

    Purpose: local employee enrollment and agent management.
    For full monitoring/analytics/reports → use the Web Dashboard.
    """
    def __init__(self, admin_name, admin_email, server_url, token):
        super().__init__()
        self.admin_name  = admin_name
        self.admin_email = admin_email
        self.server_url  = server_url
        self.api         = APIClient(server_url, token)

        self.title(f"DataShield IT Console  —  {admin_name}")
        self.geometry("1060x700")
        self.minsize(880, 580)
        self.configure(bg=BG_MAIN)

        self._build_header()
        self._build_tabs()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _build_header(self):
        hdr = tk.Frame(self, bg="#060a13", height=52)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="  🛡 DataShield", bg="#060a13", fg=ACCENT,
                 font=("Segoe UI",14,"bold")).pack(side="left", padx=4)
        tk.Label(hdr, text="IT Helpdesk Console", bg="#060a13", fg=TEXT_MUT,
                 font=("Segoe UI",10)).pack(side="left")

        # Right side: user info + web dashboard link
        right = tk.Frame(hdr, bg="#060a13")
        right.pack(side="right", padx=16)

        _btn(right, "🌐 Open Web Dashboard",
             lambda: __import__('webbrowser').open('http://localhost:5173'),
             color="#1e293b", fg=TEXT_SEC).pack(side="right", ipadx=8, ipady=3)

        av = tk.Label(right, text=self.admin_name[0].upper() if self.admin_name else "A",
                      bg=ACCENT, fg="white", font=("Segoe UI",10,"bold"), width=2)
        av.pack(side="left", padx=(0,6))
        info = tk.Frame(right, bg="#060a13")
        info.pack(side="left", padx=(0,12))
        tk.Label(info, text=self.admin_name, bg="#060a13", fg=TEXT_PRI,
                 font=("Segoe UI",9,"bold")).pack(anchor="w")
        tk.Label(info, text="IT Administrator", bg="#060a13", fg=TEXT_MUT,
                 font=("Segoe UI",8)).pack(anchor="w")

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

    def _build_tabs(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook",     background=BG_MAIN, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_CARD, foreground=TEXT_SEC,
                        padding=[16,8], font=("Segoe UI",9))
        style.map("TNotebook.Tab",
                  background=[("selected", BG_MAIN)],
                  foreground=[("selected", TEXT_PRI)])

        ov  = OverviewTab(nb, self.api)
        emp = EmployeesTab(nb, self.api)
        enr = EnrollmentWizardTab(nb, self.api)
        agt = AgentStatusTab(nb, self.api)

        nb.add(ov,  text="  Overview  ")
        nb.add(emp, text="  Employees  ")
        nb.add(enr, text="  ✚ Enroll New  ")
        nb.add(agt, text="  Agent Status  ")
