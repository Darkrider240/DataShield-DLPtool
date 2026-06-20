"""Agent registration, heartbeat, event ingestion, and policy sync routes."""
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from server.database import get_db
from server.models.agent import Agent
from server.models.employee import Employee
from server.models.event import DLPEvent
from server.models.policy import Policy
from server.schemas import (
    AgentRegisterRequest, AgentRegisterResponse,
    HeartbeatRequest, HeartbeatResponse, EventIngest,
)
from server.services.crypto_service import create_employee_dek, get_employee_dek, encrypt_field
from server.services.alert_engine import evaluate_event
from server.services.behaviour import recalculate_risk
from server.api.websocket import manager as ws_manager
from server.middleware.auth_middleware import get_current_user
from server.config import get_settings
from server.models.user import AdminUser

settings = get_settings()
router = APIRouter(prefix="/api/agents", tags=["agents"])


# ── Agent-key guard ──────────────────────────────────────────────────────────
def _verify_agent_key(x_datashield_agent_key: str = Header(...)):
    if x_datashield_agent_key != settings.AGENT_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent key",
        )


# ── Admin: list all registered agents ───────────────────────────────────────
@router.get("", tags=["agents"])
async def list_agents(
    db: AsyncSession = Depends(get_db),
    _: AdminUser = Depends(get_current_user),
):
    """
    Returns all registered agents with denormalised employee info and
    a computed is_online flag (last heartbeat within 5 minutes).
    Used by the admin console Overview tab.
    """
    result = await db.execute(select(Agent).order_by(Agent.registered_at.desc()))
    agents = result.scalars().all()
    now = datetime.now(timezone.utc)
    out = []
    for a in agents:
        hb = a.last_heartbeat
        is_online = bool(hb and (now - hb) < timedelta(minutes=5))
        out.append({
            "id":                   a.id,
            "hostname":             a.hostname,
            "employee_id":          a.employee_id,
            "employee_email":       a.employee_email,
            "employee_name":        a.employee_name,
            "platform":             a.platform,
            "agent_version":        a.agent_version,
            "is_active":            a.is_active,
            "is_online":            is_online,
            "last_heartbeat":       hb.isoformat() if hb else None,
            "registered_at":        a.registered_at.isoformat() if a.registered_at else None,
            "policy_update_available": a.policy_update_available,
        })
    return out


# ── Agent: self-registration ─────────────────────────────────────────────────
@router.post(
    "/register",
    response_model=AgentRegisterResponse,
    dependencies=[Depends(_verify_agent_key)],
)
async def register_agent(body: AgentRegisterRequest, db: AsyncSession = Depends(get_db)):
    # Resolve or create employee
    emp_result = await db.execute(
        select(Employee).where(Employee.email == body.employee_email)
    )
    employee = emp_result.scalar_one_or_none()
    if not employee:
        employee = Employee(
            email=body.employee_email,
            full_name=body.employee_name or body.hostname,
            encrypted_dek=create_employee_dek(),
        )
    db.add(employee)

    # Create a new agent record each time (supports multiple machines per employee)
    agent = Agent(
        hostname=body.hostname,
        employee_id=employee.id,
        employee_email=body.employee_email,
        employee_name=body.employee_name or employee.full_name,
        platform=body.platform,
        agent_version=body.agent_version,
        last_heartbeat=datetime.now(timezone.utc),
    )
    db.add(agent)

    # Commit now — flush alone risks losing records if the connection drops
    await db.commit()
    await db.refresh(agent)

    # Fetch active policies for the agent
    pol_result = await db.execute(select(Policy).where(Policy.is_active == True))
    policies = pol_result.scalars().all()
    policy_list = [
        {
            "name": p.name,
            "category": p.category,
            "pattern": p.pattern,
            "base_weight": p.base_weight,
            "regulation_tags": p.regulation_tags,
            "description": p.description,
        }
        for p in policies
    ]
    latest_version = str(max((p.updated_at.timestamp() for p in policies), default=0))

    return AgentRegisterResponse(
        agent_id=agent.id,
        policy_version=latest_version,
        policies=policy_list,
    )


# ── Agent: heartbeat ─────────────────────────────────────────────────────────
@router.post(
    "/heartbeat",
    response_model=HeartbeatResponse,
    dependencies=[Depends(_verify_agent_key)],
)
async def heartbeat(body: HeartbeatRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Agent).where(Agent.id == body.agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent.last_heartbeat = datetime.now(timezone.utc)

    pol_result = await db.execute(select(Policy).where(Policy.is_active == True))
    policies = pol_result.scalars().all()
    latest_version = str(max((p.updated_at.timestamp() for p in policies), default=0))

    needs_update = (
        latest_version != body.current_policy_version
        or agent.policy_update_available
    )
    if needs_update:
        agent.policy_update_available = False

    await db.commit()
    return HeartbeatResponse(policy_update_available=needs_update)


# ── Agent: fetch current policy ──────────────────────────────────────────────
@router.get("/{agent_id}/policy", dependencies=[Depends(_verify_agent_key)])
async def get_policy(agent_id: str, db: AsyncSession = Depends(get_db)):
    pol_result = await db.execute(select(Policy).where(Policy.is_active == True))
    policies = pol_result.scalars().all()
    policy_list = [
        {
            "name": p.name,
            "category": p.category,
            "pattern": p.pattern,
            "base_weight": p.base_weight,
            "regulation_tags": p.regulation_tags,
        }
        for p in policies
    ]
    version = str(max((p.updated_at.timestamp() for p in policies), default=0))
    return {"policy_version": version, "policies": policy_list}


# ── Agent: ingest DLP events ─────────────────────────────────────────────────
@router.post("/events", status_code=200, dependencies=[Depends(_verify_agent_key)])
async def ingest_events(
    body: list[EventIngest],
    db: AsyncSession = Depends(get_db),
):
    ingested = 0
    for ev_data in body:
        # Resolve employee via agent_id only — prevents email-spoofing attribution
        employee = None
        if ev_data.agent_id:
            agent_r = await db.execute(
                select(Agent).where(Agent.id == ev_data.agent_id)
            )
            agent_obj = agent_r.scalar_one_or_none()
            if agent_obj and agent_obj.employee_id:
                emp_r = await db.execute(
                    select(Employee).where(Employee.id == agent_obj.employee_id)
                )
                employee = emp_r.scalar_one_or_none()

        # Fallback: email-based lookup only for first-contact (no agent_id yet)
        if not employee and ev_data.agent_id == "" and ev_data.employee_email:
            emp_r = await db.execute(
                select(Employee).where(Employee.email == ev_data.employee_email)
            )
            employee = emp_r.scalar_one_or_none()

        if not employee:
            continue

        try:
            dek = get_employee_dek(employee.encrypted_dek)
            event = DLPEvent(
                employee_id=employee.id,
                agent_id=ev_data.agent_id or "",
                channel=ev_data.channel,
                action_taken=ev_data.action_taken,
                justification=ev_data.justification,
                risk_level=ev_data.risk_level,
                risk_score=ev_data.risk_score,
                file_path_encrypted=encrypt_field(ev_data.file_path, dek),
                ai_explanation_encrypted=encrypt_field(ev_data.ai_explanation, dek),
                matched_value_redacted=ev_data.matched_value_redacted,
                pattern_names=ev_data.pattern_names,
                regulation_tags=ev_data.regulation_tags,
                occurred_at=ev_data.occurred_at,
                # Email attribution — populated for WEBMAIL/EMAIL channels
                sender_email=ev_data.sender_email or None,
                recipient_emails=ev_data.recipient_emails or None,
                email_subject=ev_data.email_subject or None,
            )
            db.add(event)
            await db.flush()                           # get event.id before risk calc
            await recalculate_risk(employee.id, db)
            await evaluate_event(event, db, ws_manager)
            await ws_manager.broadcast({
                "type": "EVENT",
                "channel": event.channel,
                "risk_level": event.risk_level,
                "employee_id": str(employee.id),
                "employee_email": employee.email,
            })
            ingested += 1
        except Exception as exc:
            print(f"[ingest_events] Failed for event {ev_data.channel}: {exc}")
            await db.rollback()
            continue

    await db.commit()
    return {"status": "ok", "ingested": ingested}
