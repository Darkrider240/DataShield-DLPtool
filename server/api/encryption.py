"""Encryption key status and rotation endpoint."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from server.database import get_db
from server.models.employee import Employee
from server.schemas import KeyStatusOut, RotationStatusOut
from server.middleware.auth_middleware import require_superadmin
from server.services.crypto_service import rotate_all_employee_deks

router = APIRouter(prefix="/api/encryption", tags=["encryption"])


@router.get("/status", response_model=KeyStatusOut, dependencies=[Depends(require_superadmin)])
async def key_status(db: AsyncSession = Depends(get_db)):
    total_emps = (await db.execute(select(func.count(Employee.id)))).scalar_one()
    # Master key age is tracked externally; we report 0 as placeholder when not in config
    return KeyStatusOut(
        master_key_age_days=0,
        total_employees=total_emps,
        dek_rotation_needed=(total_emps > 0),
    )


@router.post("/rotate", response_model=RotationStatusOut, dependencies=[Depends(require_superadmin)])
async def rotate_keys(db: AsyncSession = Depends(get_db)):
    count = await rotate_all_employee_deks(db)
    return RotationStatusOut(employees_rotated=count, status="success")
