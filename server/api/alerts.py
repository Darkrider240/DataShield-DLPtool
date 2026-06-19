"""Alert acknowledgement and escalation routes."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from server.database import get_db
from server.models.alert import Alert
from server.schemas import AlertOut, AlertAcknowledgeRequest
from server.middleware.auth_middleware import get_current_user, require_analyst_or_above
from server.models.user import AdminUser

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    status: str = Query(""),
    severity: str = Query(""),
    page: int = Query(1, ge=1),
    per_page: int = Query(30, le=100),
    db: AsyncSession = Depends(get_db),
    _: AdminUser = Depends(get_current_user),
):
    q = select(Alert).order_by(Alert.created_at.desc())
    if status:
        q = q.where(Alert.status == status)
    if severity:
        q = q.where(Alert.severity == severity)
    q = q.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/{alert_id}/acknowledge", dependencies=[Depends(require_analyst_or_above)])
async def acknowledge(alert_id: str, body: AlertAcknowledgeRequest, db: AsyncSession = Depends(get_db), current_user: AdminUser = Depends(require_analyst_or_above)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "ACKNOWLEDGED"
    alert.acknowledged_by = current_user.email
    alert.acknowledged_at = datetime.now(timezone.utc)
    return {"status": "acknowledged"}


@router.post("/{alert_id}/resolve", dependencies=[Depends(require_analyst_or_above)])
async def resolve(alert_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "RESOLVED"
    alert.resolved_at = datetime.now(timezone.utc)
    return {"status": "resolved"}
