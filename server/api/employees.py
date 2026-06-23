"""Employee management routes."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel
from server.database import get_db
from server.models.employee import Employee
from server.schemas import EmployeeCreate, EmployeeOut, FlagRequest, MonitoringSettings
from server.middleware.auth_middleware import get_current_user, require_analyst_or_above, require_superadmin
from server.services.crypto_service import create_employee_dek
from server.models.user import AdminUser

router = APIRouter(prefix="/api/employees", tags=["employees"])


@router.get("", response_model=list[EmployeeOut])
async def list_employees(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, le=100),
    search: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _: AdminUser = Depends(get_current_user),
):
    q = select(Employee)
    if search:
        q = q.where(Employee.email.ilike(f"%{search}%") | Employee.full_name.ilike(f"%{search}%"))
    q = q.order_by(Employee.risk_score.desc()).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("", response_model=EmployeeOut, dependencies=[Depends(require_superadmin)])
async def create_employee(body: EmployeeCreate, db: AsyncSession = Depends(get_db)):
    emp = Employee(**body.model_dump(), encrypted_dek=create_employee_dek())
    db.add(emp)
    await db.flush()
    await db.commit()
    await db.refresh(emp)
    return emp


@router.get("/{employee_id}", response_model=EmployeeOut)
async def get_employee(employee_id: str, db: AsyncSession = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    result = await db.execute(select(Employee).where(Employee.id == employee_id))
    emp = result.scalar_one_or_none()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    return emp


@router.post("/{employee_id}/flag", dependencies=[Depends(require_analyst_or_above)])
async def flag_employee(employee_id: str, body: FlagRequest, db: AsyncSession = Depends(get_db), current_user: AdminUser = Depends(require_analyst_or_above)):
    result = await db.execute(select(Employee).where(Employee.id == employee_id))
    emp = result.scalar_one_or_none()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    emp.is_flagged = True
    emp.flag_reason = body.reason
    emp.flagged_at = datetime.now(timezone.utc)
    emp.flagged_by = current_user.email
    await db.commit()
    return {"status": "flagged"}


@router.post("/{employee_id}/unflag", dependencies=[Depends(require_analyst_or_above)])
async def unflag_employee(employee_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Employee).where(Employee.id == employee_id))
    emp = result.scalar_one_or_none()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    emp.is_flagged = False
    emp.flag_reason = ""
    emp.flagged_at = None
    await db.commit()
    return {"status": "unflagged"}


from passlib.context import CryptContext as _CryptContext
_pwd = _CryptContext(schemes=["bcrypt"], deprecated="auto")


class SetPinRequest(BaseModel):
    pin: str  # plain text, will be hashed server-side


@router.post("/{employee_id}/set-pin", dependencies=[Depends(require_superadmin)])
async def set_employee_pin(
    employee_id: str,
    body: SetPinRequest,
    db: AsyncSession = Depends(get_db)
):
    """Admin sets or resets an employee's login PIN."""
    result = await db.execute(select(Employee).where(Employee.id == employee_id))
    emp = result.scalar_one_or_none()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    if not body.pin or len(body.pin) < 4:
        raise HTTPException(status_code=422, detail="PIN must be at least 4 characters")
    emp.pin_hash = _pwd.hash(body.pin)
    emp.pin_set = True
    await db.commit()
    return {"status": "ok", "message": "PIN set successfully"}


@router.get("/{employee_id}/monitoring", response_model=MonitoringSettings)
async def get_monitoring_settings(
    employee_id: str,
    db: AsyncSession = Depends(get_db),
    _: AdminUser = Depends(get_current_user),
):
    """Get per-employee monitoring channel settings."""
    result = await db.execute(select(Employee).where(Employee.id == employee_id))
    emp = result.scalar_one_or_none()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    return MonitoringSettings.model_validate(emp)


@router.patch("/{employee_id}/monitoring", response_model=MonitoringSettings,
              dependencies=[Depends(require_superadmin)])
async def update_monitoring_settings(
    employee_id: str,
    body: MonitoringSettings,
    db: AsyncSession = Depends(get_db),
):
    """Admin sets which monitoring channels are active for this employee."""
    result = await db.execute(select(Employee).where(Employee.id == employee_id))
    emp = result.scalar_one_or_none()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    emp.monitor_clipboard  = body.monitor_clipboard
    emp.monitor_usb        = body.monitor_usb
    emp.monitor_webmail    = body.monitor_webmail
    emp.monitor_file_scan  = body.monitor_file_scan
    await db.commit()
    await db.refresh(emp)
    return MonitoringSettings.model_validate(emp)


# ── Feature 11: CSV Bulk Import ───────────────────────────────────────────────
import csv, io, uuid as _uuid
from fastapi import UploadFile, File

@router.post("/import", dependencies=[Depends(require_superadmin)])
async def import_employees_csv(
    file: UploadFile = File(...),
    db:   AsyncSession = Depends(get_db),
):
    """Bulk-create employees from a CSV with columns: name, email, department."""
    content = await file.read()
    text    = content.decode("utf-8", errors="replace")
    reader  = csv.DictReader(io.StringIO(text))

    created, skipped, errors = 0, 0, []

    for row in reader:
        email = (row.get("email") or "").strip().lower()
        name  = (row.get("name") or row.get("full_name") or "").strip()
        dept  = (row.get("department") or row.get("dept") or "").strip()

        if not email or "@" not in email:
            errors.append(f"Skipped — invalid email: '{email or 'empty'}'")
            skipped += 1
            continue

        existing = await db.execute(select(Employee).where(Employee.email == email))
        if existing.scalar_one_or_none():
            skipped += 1
            continue

        emp = Employee(
            id=str(_uuid.uuid4()),
            email=email,
            full_name=name or email.split("@")[0].title(),
            department=dept,
            risk_score=0.0,
            is_active=True,
            encrypted_dek=create_employee_dek(),
        )
        db.add(emp)
        created += 1

    await db.commit()
    return {"status": "ok", "created": created, "skipped": skipped, "errors": errors}


# ── Feature 6: Employee Report Card ──────────────────────────────────────────
from collections import Counter as _Counter
from datetime import timedelta

@router.get("/{employee_id}/report")
async def get_employee_report(
    employee_id: str,
    db: AsyncSession = Depends(get_db),
    _: AdminUser = Depends(get_current_user),
):
    """Full 30-day stats report card for one employee."""
    from server.models.event import DLPEvent

    emp_r = await db.execute(select(Employee).where(Employee.id == employee_id))
    emp   = emp_r.scalar_one_or_none()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")

    cutoff   = datetime.now(timezone.utc) - timedelta(days=30)
    events_r = await db.execute(
        select(DLPEvent)
        .where(DLPEvent.employee_id == employee_id)
        .where(DLPEvent.occurred_at >= cutoff)
        .order_by(DLPEvent.occurred_at.asc())
    )
    events = events_r.scalars().all()

    pattern_ctr: _Counter = _Counter()
    channel_ctr: _Counter = _Counter()
    high = med = low = 0
    daily: dict[str, float] = {}

    for ev in events:
        channel_ctr[ev.channel] += 1
        if   ev.risk_level == "HIGH":   high += 1
        elif ev.risk_level == "MEDIUM": med  += 1
        elif ev.risk_level == "LOW":    low  += 1
        for p in (ev.pattern_names or []):
            pattern_ctr[p] += 1
        day = ev.occurred_at.strftime("%Y-%m-%d")
        daily[day] = max(daily.get(day, 0.0), float(ev.risk_score or 0))

    # Org-average risk score
    avg_r = await db.execute(
        select(func.avg(Employee.risk_score)).where(Employee.is_active == True)
    )
    org_avg = float(avg_r.scalar() or 0.0)

    return {
        "employee_id":       emp.id,
        "employee_name":     emp.full_name or emp.email,
        "employee_email":    emp.email,
        "risk_score":        emp.risk_score or 0.0,
        "is_flagged":        emp.is_flagged or False,
        "flag_reason":       emp.flag_reason or "",
        "total_events_30d":  len(events),
        "high_events_30d":   high,
        "medium_events_30d": med,
        "low_events_30d":    low,
        "top_patterns":      [p for p, _ in pattern_ctr.most_common(5)],
        "channel_breakdown": dict(channel_ctr),
        "daily_risk_scores": [{"date": k, "score": v} for k, v in sorted(daily.items())],
        "org_avg_risk_score": org_avg,
    }
