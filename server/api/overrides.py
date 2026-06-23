"""Override request endpoints — employee submits, admin reviews."""
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel

from server.database import get_db
from server.models.override import OverrideRequest
from server.models.employee import Employee
from server.middleware.auth_middleware import get_current_user
from server.models.user import AdminUser

router = APIRouter(prefix="/api/overrides", tags=["overrides"])


# ── Schemas ───────────────────────────────────────────────────────────────────
class CreateOverrideBody(BaseModel):
    employee_id:   str
    agent_id:      str = ""
    event_channel: str
    event_detail:  str = ""
    pattern:       str = ""
    justification: str


class ReviewOverrideBody(BaseModel):
    status:     str              # APPROVED | DENIED
    admin_note: Optional[str] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.post("", status_code=201)
async def create_override_request(
    body: CreateOverrideBody,
    db:   AsyncSession = Depends(get_db),
):
    """Employee submits an override request for a blocked event. No auth required."""
    if not body.justification.strip():
        raise HTTPException(status_code=422, detail="Justification cannot be empty")

    import uuid
    req = OverrideRequest(
        id=str(uuid.uuid4()),
        employee_id=body.employee_id,
        agent_id=body.agent_id,
        event_channel=body.event_channel,
        event_detail=body.event_detail,
        pattern=body.pattern,
        justification=body.justification,
    )
    db.add(req)
    await db.commit()
    await db.refresh(req)
    return {"status": "submitted", "id": req.id}


@router.get("/pending-count")
async def pending_count(
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    """Returns count of PENDING requests — used for navbar badge."""
    result = await db.execute(
        select(func.count()).select_from(OverrideRequest)
        .where(OverrideRequest.status == "PENDING")
    )
    return {"pending": result.scalar() or 0}


@router.get("")
async def list_override_requests(
    status: str = "",
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    """Admin lists override requests, optionally filtered by status."""
    q = select(OverrideRequest).order_by(OverrideRequest.created_at.desc())
    if status:
        q = q.where(OverrideRequest.status == status)
    result = await db.execute(q)
    requests = result.scalars().all()

    # Batch-fetch employee names
    emp_ids = list({r.employee_id for r in requests})
    emp_map: dict[str, Employee] = {}
    if emp_ids:
        emp_res = await db.execute(select(Employee).where(Employee.id.in_(emp_ids)))
        emp_map = {e.id: e for e in emp_res.scalars().all()}

    out = []
    for req in requests:
        emp = emp_map.get(req.employee_id)
        out.append({
            "id":             req.id,
            "employee_id":    req.employee_id,
            "employee_name":  (emp.full_name or emp.email) if emp else None,
            "employee_email": emp.email if emp else None,
            "event_channel":  req.event_channel,
            "event_detail":   req.event_detail,
            "pattern":        req.pattern,
            "justification":  req.justification,
            "status":         req.status,
            "admin_note":     req.admin_note,
            "created_at":     req.created_at.isoformat() if req.created_at else None,
            "reviewed_at":    req.reviewed_at.isoformat() if req.reviewed_at else None,
        })
    return out


@router.patch("/{request_id}")
async def review_override_request(
    request_id: str,
    body: ReviewOverrideBody,
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    """Admin approves or denies an override request."""
    if body.status not in ("APPROVED", "DENIED"):
        raise HTTPException(status_code=422, detail="status must be APPROVED or DENIED")

    result = await db.execute(
        select(OverrideRequest).where(OverrideRequest.id == request_id)
    )
    req = result.scalar_one_or_none()
    if not req:
        raise HTTPException(status_code=404, detail="Override request not found")

    req.status      = body.status
    req.admin_note  = body.admin_note
    req.reviewed_by = current_user.email
    req.reviewed_at = datetime.now(timezone.utc)
    await db.commit()
    return {"status": "ok", "new_status": req.status}


# ── Agent notification polling ─────────────────────────────────────────────────
@router.get("/my-notifications")
async def get_my_notifications(
    employee_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Agent polls this every 60s to check if any of its overrides were reviewed.
    Returns APPROVED or DENIED requests that haven't been notified yet,
    then marks them as notified so they don't appear again.
    No admin JWT required — employee identified by their own employee_id.
    """
    result = await db.execute(
        select(OverrideRequest)
        .where(
            OverrideRequest.employee_id == employee_id,
            OverrideRequest.status.in_(["APPROVED", "DENIED"]),
            OverrideRequest.agent_notified == False,  # noqa: E712
        )
        .order_by(OverrideRequest.reviewed_at.asc())
    )
    pending_notifications = result.scalars().all()

    if not pending_notifications:
        return []

    out = []
    for req in pending_notifications:
        out.append({
            "id":            req.id,
            "status":        req.status,         # APPROVED | DENIED
            "event_channel": req.event_channel,
            "event_detail":  req.event_detail,   # original filename
            "pattern":       req.pattern,
            "justification": req.justification,
            "admin_note":    req.admin_note or "",
            "reviewed_at":   req.reviewed_at.isoformat() if req.reviewed_at else None,
        })
        # Mark as notified immediately so the next poll won't return it again
        req.agent_notified = True

    await db.commit()
    return out
