"""DLP events query routes — returns employee attribution + email metadata."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from server.database import get_db
from server.models.event import DLPEvent
from server.models.employee import Employee
from server.schemas import EventOut
from server.middleware.auth_middleware import get_current_user
from server.services.crypto_service import get_employee_dek, decrypt_field
from server.models.user import AdminUser

router = APIRouter(prefix="/api/events", tags=["events"])


def _enrich(ev_dict: dict, emp: Employee | None) -> dict:
    """Attach employee identity fields to an event dict."""
    if emp:
        ev_dict["employee_name"]  = emp.full_name or emp.email
        ev_dict["employee_email"] = emp.email
        ev_dict["employee_dept"]  = emp.department or ""
    # Email attribution already on the event row — pass through from model
    return ev_dict


@router.get("", response_model=list[EventOut])
async def list_events(
    employee_id: str = Query(""),
    channel:     str = Query(""),
    risk_level:  str = Query(""),
    page:        int = Query(1, ge=1),
    per_page:    int = Query(30, le=500),
    db:          AsyncSession = Depends(get_db),
    current_user: AdminUser   = Depends(get_current_user),
):
    q = select(DLPEvent).order_by(DLPEvent.occurred_at.desc())
    if employee_id:
        q = q.where(DLPEvent.employee_id == employee_id)
    if channel:
        q = q.where(DLPEvent.channel == channel)
    if risk_level:
        q = q.where(DLPEvent.risk_level == risk_level)
    q = q.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(q)
    events = result.scalars().all()

    # Pre-fetch employees referenced in this page (avoids N+1)
    emp_ids = list({ev.employee_id for ev in events})
    emp_map: dict[str, Employee] = {}
    if emp_ids:
        emp_res = await db.execute(
            select(Employee).where(Employee.id.in_(emp_ids))
        )
        emp_map = {e.id: e for e in emp_res.scalars().all()}

    out = []
    for ev in events:
        ev_dict = EventOut.model_validate(ev).model_dump()
        emp = emp_map.get(ev.employee_id)
        ev_dict = _enrich(ev_dict, emp)

        # Decrypt sensitive fields for authorised roles
        if current_user.role in ("superadmin", "analyst") and emp:
            try:
                dek = get_employee_dek(emp.encrypted_dek)
                ev_dict["file_path"]      = decrypt_field(ev.file_path_encrypted, dek)
                ev_dict["ai_explanation"] = decrypt_field(ev.ai_explanation_encrypted, dek)
            except Exception:
                pass
        out.append(ev_dict)
    return out


@router.get("/{event_id}", response_model=EventOut)
async def get_event(
    event_id: str,
    db:           AsyncSession = Depends(get_db),
    current_user: AdminUser    = Depends(get_current_user),
):
    result = await db.execute(select(DLPEvent).where(DLPEvent.id == event_id))
    ev = result.scalar_one_or_none()
    if not ev:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Event not found")

    ev_dict = EventOut.model_validate(ev).model_dump()

    emp_r = await db.execute(select(Employee).where(Employee.id == ev.employee_id))
    emp   = emp_r.scalar_one_or_none()
    ev_dict = _enrich(ev_dict, emp)

    if current_user.role in ("superadmin", "analyst") and emp:
        try:
            dek = get_employee_dek(emp.encrypted_dek)
            ev_dict["file_path"]      = decrypt_field(ev.file_path_encrypted, dek)
            ev_dict["ai_explanation"] = decrypt_field(ev.ai_explanation_encrypted, dek)
        except Exception:
            pass

    return ev_dict
