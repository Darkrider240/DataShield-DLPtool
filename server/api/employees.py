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
