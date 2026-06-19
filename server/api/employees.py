"""Employee management routes."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from server.database import get_db
from server.models.employee import Employee
from server.schemas import EmployeeCreate, EmployeeOut, FlagRequest
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
    return {"status": "unflagged"}
