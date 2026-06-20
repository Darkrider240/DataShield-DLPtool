"""Policy YAML import, listing, and agent push routes."""
import yaml
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from server.database import get_db
from server.models.policy import Policy
from server.schemas import PolicyOut, PolicyImportRequest
from server.middleware.auth_middleware import require_superadmin, get_current_user
from server.services.policy_pusher import mark_policy_update_for_all_agents
from server.models.user import AdminUser

router = APIRouter(prefix="/api/policies", tags=["policies"])


@router.get("", response_model=list[PolicyOut])
async def list_policies(db: AsyncSession = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    result = await db.execute(select(Policy).order_by(Policy.name))
    return result.scalars().all()


@router.post("/import", dependencies=[Depends(require_superadmin)])
async def import_policies(body: PolicyImportRequest, db: AsyncSession = Depends(get_db)):
    try:
        data = yaml.safe_load(body.yaml_content)
        rules = data.get("rules", [])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")

    imported = 0
    for rule in rules:
        name = rule.get("name", "")
        if not name:
            continue
        existing_r = await db.execute(select(Policy).where(Policy.name == name))
        existing = existing_r.scalar_one_or_none()
        if existing:
            existing.pattern = rule.get("pattern", existing.pattern)
            existing.category = rule.get("category", existing.category)
            existing.base_weight = float(rule.get("base_weight", existing.base_weight))
            existing.regulation_tags = rule.get("regulation_tags", existing.regulation_tags)
            existing.description = rule.get("description", existing.description)
            existing.is_active = True
        else:
            db.add(Policy(
                name=name,
                pattern=rule.get("pattern", ""),
                category=rule.get("category", "PII"),
                base_weight=float(rule.get("base_weight", 1.0)),
                regulation_tags=rule.get("regulation_tags", []),
                description=rule.get("description", ""),
            ))
        imported += 1

    await mark_policy_update_for_all_agents(db)
    return {"imported": imported, "status": "pushed"}


@router.post("/push", dependencies=[Depends(require_superadmin)])
async def push_policies(db: AsyncSession = Depends(get_db)):
    await mark_policy_update_for_all_agents(db)
    return {"status": "all agents flagged for policy update"}
