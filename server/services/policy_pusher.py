"""Policy pusher: marks all active agents as needing a policy update."""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import update
from server.models.agent import Agent


async def mark_policy_update_for_all_agents(db: AsyncSession):
    await db.execute(update(Agent).where(Agent.is_active == True).values(policy_update_available=True))
    await db.commit()
