"""
FastAPI application entry point.
Mounts all routers, configures CORS, APScheduler anomaly detection,
and provides a lifespan context that creates tables on startup.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from server.database import create_all_tables, AsyncSessionFactory
from server.config import get_settings
from server.api import auth, agents, employees, events, policies, alerts, reports, encryption
from server.api.websocket import router as ws_router
from server.services.behaviour import detect_anomalies

settings = get_settings()
scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Guard against shipping with default CHANGEME secrets
    _validate_secrets()

    # Create tables (dev convenience; use Alembic for production)
    await create_all_tables()

    # Seed default policies from the local YAML if the DB is empty
    await _seed_default_policies()

    # Start anomaly detection scheduler — runs every 15 minutes
    scheduler.add_job(_run_anomaly_check, "interval", minutes=15, id="anomaly_check")
    scheduler.start()

    yield

    scheduler.shutdown(wait=False)


def _validate_secrets():
    """Refuse to start with unchanged default secrets."""
    dangerous = [
        ("JWT_SECRET_KEY",        settings.JWT_SECRET_KEY,        "CHANGEME"),
        ("MASTER_KEY_PASSPHRASE", settings.MASTER_KEY_PASSPHRASE, "CHANGEME"),
        ("AGENT_API_KEY",         settings.AGENT_API_KEY,         "CHANGEME"),
    ]
    bad = [name for name, val, marker in dangerous if marker in val]
    if bad:
        raise RuntimeError(
            f"[DataShield] FATAL: The following secrets still have CHANGEME defaults:\n"
            f"  {', '.join(bad)}\n"
            f"Set them in your .env file before starting the server."
        )


async def _run_anomaly_check():
    from server.api.websocket import manager as ws_manager
    async with AsyncSessionFactory() as db:
        await detect_anomalies(db, ws_manager)
        await db.commit()


async def _seed_default_policies():
    """Seed rules from local default_rules.yaml if the policies table is empty."""
    import os, yaml
    from sqlalchemy import select, func
    from server.models.policy import Policy
    from pathlib import Path

    rules_path = Path(__file__).parents[1] / "rules" / "default_rules.yaml"
    if not rules_path.exists():
        return

    async with AsyncSessionFactory() as db:
        count = (await db.execute(select(func.count(Policy.id)))).scalar_one()
        if count > 0:
            return
        with open(rules_path, "r") as f:
            data = yaml.safe_load(f)
        for rule in data.get("rules", []):
            db.add(Policy(
                name=rule.get("name", ""),
                pattern=rule.get("pattern", ""),
                category=rule.get("category", "PII"),
                base_weight=float(rule.get("base_weight", 1.0)),
                regulation_tags=rule.get("regulation_tags", []),
                description=rule.get("description", ""),
            ))
        await db.commit()
        print("[*] Default DLP rules seeded into database.")


app = FastAPI(
    title="DataShield Enterprise API",
    version=settings.APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

# CORS — allow the dashboard (Vite dev :5173 and prod :80) and extension origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:80", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routers
app.include_router(ws_router)
app.include_router(auth.router)
app.include_router(agents.router)
app.include_router(employees.router)
app.include_router(events.router)
app.include_router(policies.router)
app.include_router(alerts.router)
app.include_router(reports.router)
app.include_router(encryption.router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}
