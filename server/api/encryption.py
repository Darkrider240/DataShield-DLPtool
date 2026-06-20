"""Encryption key status and rotation endpoint."""
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from server.database import get_db
from server.models.employee import Employee
from server.models.settings import ServerSetting
from server.schemas import KeyStatusOut, RotationStatusOut
from server.middleware.auth_middleware import require_superadmin
from server.services.crypto_service import rotate_all_employee_deks

router = APIRouter(prefix="/api/encryption", tags=["encryption"])

ROTATION_INTERVAL_DAYS = 90
SETTING_KEY = "last_key_rotation_at"


async def _get_last_rotation(db: AsyncSession) -> datetime | None:
    result = await db.execute(select(ServerSetting).where(ServerSetting.key == SETTING_KEY))
    row = result.scalar_one_or_none()
    if row and row.value:
        try:
            return datetime.fromisoformat(row.value)
        except Exception:
            return None
    return None


async def _set_last_rotation(db: AsyncSession, ts: datetime):
    result = await db.execute(select(ServerSetting).where(ServerSetting.key == SETTING_KEY))
    row = result.scalar_one_or_none()
    if row:
        row.value = ts.isoformat()
    else:
        db.add(ServerSetting(key=SETTING_KEY, value=ts.isoformat()))
    await db.commit()


@router.get("/status", response_model=KeyStatusOut, dependencies=[Depends(require_superadmin)])
async def key_status(db: AsyncSession = Depends(get_db)):
    total_emps = (await db.execute(select(func.count(Employee.id)))).scalar_one()
    last_rotated = await _get_last_rotation(db)
    now = datetime.now(timezone.utc)

    if last_rotated is None:
        master_key_age_days = 999
        rotation_needed = total_emps > 0
    else:
        # Make last_rotated timezone-aware if naive
        if last_rotated.tzinfo is None:
            last_rotated = last_rotated.replace(tzinfo=timezone.utc)
        age = now - last_rotated
        master_key_age_days = age.days
        rotation_needed = age.days >= ROTATION_INTERVAL_DAYS

    return KeyStatusOut(
        master_key_age_days=master_key_age_days,
        total_employees=total_emps,
        dek_rotation_needed=rotation_needed,
    )


@router.post("/rotate", response_model=RotationStatusOut, dependencies=[Depends(require_superadmin)])
async def rotate_keys(db: AsyncSession = Depends(get_db)):
    count = await rotate_all_employee_deks(db)
    await _set_last_rotation(db, datetime.now(timezone.utc))
    return RotationStatusOut(employees_rotated=count, status="success")
