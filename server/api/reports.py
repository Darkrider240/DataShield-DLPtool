"""Compliance metrics and Gemini-powered executive summary reports."""
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from server.database import get_db
from server.models.event import DLPEvent
from server.models.employee import Employee
from server.models.agent import Agent
from server.models.alert import Alert
from server.schemas import ComplianceMetricsOut, ExecutiveSummaryOut
from server.middleware.auth_middleware import get_current_user, require_analyst_or_above
from server.config import get_settings
from server.models.user import AdminUser

settings = get_settings()
router = APIRouter(prefix="/api/reports", tags=["reports"])

# ── Gemini singleton + response cache ────────────────────────────────────────
# One client shared for the whole server process — not re-created per request.
_gemini_client = None
_GEMINI_MODELS  = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-flash-8b"]

# Simple in-process cache to avoid hammering free-tier quota
_summary_cache: dict = {}
_CACHE_TTL_SECONDS = 600   # reuse last result for 10 minutes


def _get_gemini_client():
    """Lazily initialise and return the singleton Gemini client."""
    global _gemini_client
    if _gemini_client is None and settings.GEMINI_API_KEY:
        try:
            from google import genai as _genai
            _gemini_client = _genai.Client(api_key=settings.GEMINI_API_KEY)
        except Exception:
            _gemini_client = None
    return _gemini_client


def _call_gemini(prompt: str) -> str:
    """Try each model in fallback order; return a friendly string on any error."""
    client = _get_gemini_client()
    if client is None:
        return "Gemini API key not configured — summary unavailable."

    try:
        from google.genai.errors import APIError
    except ImportError:
        APIError = Exception  # type: ignore

    errors = []
    for model_name in _GEMINI_MODELS:
        try:
            resp = client.models.generate_content(model=model_name, contents=prompt)
            return resp.text or "No summary generated."
        except APIError as e:
            msg = getattr(e, "message", str(e))
            errors.append(f"{model_name}: {msg}")
            # Try next model in fallback order
            continue
        except Exception as e:
            errors.append(f"{model_name}: {e}")
            continue

    # All models exhausted
    err_str = " | ".join(errors)
    return (
        f"Gemini API could not generate summary. Details: {err_str}. "
        "Please check your API key / model permissions or try again later."
    )


# ── Admin console overview stats ─────────────────────────────────────────────
@router.get("/overview")
async def admin_overview(
    db: AsyncSession = Depends(get_db),
    _: AdminUser = Depends(get_current_user),
):
    """
    Fast summary for the admin console Overview tab.
    Returns total_employees, flagged_employees, open_alerts, total_events (today).
    """
    now = datetime.now(timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    total_emp    = (await db.execute(select(func.count(Employee.id)))).scalar_one()
    flagged_emp  = (await db.execute(
        select(func.count(Employee.id)).where(Employee.is_flagged == True)
    )).scalar_one()
    open_alerts  = (await db.execute(
        select(func.count(Alert.id)).where(Alert.status == "OPEN")
    )).scalar_one()
    today_events = (await db.execute(
        select(func.count(DLPEvent.id)).where(DLPEvent.occurred_at >= today)
    )).scalar_one()

    return {
        "total_employees":   total_emp,
        "flagged_employees": flagged_emp,
        "open_alerts":       open_alerts,
        "total_events":      today_events,
    }


# ── Compliance metrics ────────────────────────────────────────────────────────
@router.get("/metrics", response_model=ComplianceMetricsOut)
async def compliance_metrics(
    db: AsyncSession = Depends(get_db),
    _: AdminUser = Depends(get_current_user),
):
    now = datetime.now(timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    total = (await db.execute(
        select(func.count(DLPEvent.id)).where(DLPEvent.occurred_at >= today)
    )).scalar_one()
    high  = (await db.execute(
        select(func.count(DLPEvent.id)).where(
            and_(DLPEvent.occurred_at >= today, DLPEvent.risk_level == "HIGH")
        )
    )).scalar_one()
    med   = (await db.execute(
        select(func.count(DLPEvent.id)).where(
            and_(DLPEvent.occurred_at >= today, DLPEvent.risk_level == "MEDIUM")
        )
    )).scalar_one()
    low   = (await db.execute(
        select(func.count(DLPEvent.id)).where(
            and_(DLPEvent.occurred_at >= today, DLPEvent.risk_level == "LOW")
        )
    )).scalar_one()
    blk   = (await db.execute(
        select(func.count(DLPEvent.id)).where(
            and_(DLPEvent.occurred_at >= today, DLPEvent.action_taken == "BLOCK")
        )
    )).scalar_one()
    flagged   = (await db.execute(
        select(func.count(Employee.id)).where(Employee.is_flagged == True)
    )).scalar_one()
    open_alts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.status == "OPEN")
    )).scalar_one()
    crit_alts = (await db.execute(
        select(func.count(Alert.id)).where(
            and_(Alert.status == "OPEN", Alert.severity == "CRITICAL")
        )
    )).scalar_one()

    ev_result = await db.execute(select(DLPEvent.regulation_tags))
    reg_counts: dict[str, int] = {}
    for row in ev_result.scalars():
        for tag in (row or []):
            reg_counts[tag] = reg_counts.get(tag, 0) + 1

    return ComplianceMetricsOut(
        total_events=total,
        high_events=high,
        medium_events=med,
        low_events=low,
        blocked_events=blk,
        flagged_employees=flagged,
        open_alerts=open_alts,
        critical_alerts=crit_alts,
        regulation_hit_counts=reg_counts,
    )


# ── Gemini executive summary ──────────────────────────────────────────────────
@router.get(
    "/executive-summary",
    response_model=ExecutiveSummaryOut,
    dependencies=[Depends(require_analyst_or_above)],
)
async def executive_summary(db: AsyncSession = Depends(get_db)):
    """
    Feeds live compliance numbers to Gemini for an executive DLP posture summary.

    Results are cached for 10 minutes so repeated clicks don't burn quota.
    Model fallback order: gemini-2.0-flash → 1.5-flash → 1.5-flash-8b.
    """
    global _summary_cache
    now = datetime.now(timezone.utc)

    # Return cached result if it is still fresh
    if _summary_cache:
        expires = _summary_cache.get("expires_at")
        if expires and now < expires:
            return ExecutiveSummaryOut(
                summary=_summary_cache["summary"],
                generated_at=_summary_cache["generated_at"],
            )

    # Gather live numbers
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    total = (await db.execute(
        select(func.count(DLPEvent.id)).where(DLPEvent.occurred_at >= today)
    )).scalar_one()
    high  = (await db.execute(
        select(func.count(DLPEvent.id)).where(
            and_(DLPEvent.occurred_at >= today, DLPEvent.risk_level == "HIGH")
        )
    )).scalar_one()
    med   = (await db.execute(
        select(func.count(DLPEvent.id)).where(
            and_(DLPEvent.occurred_at >= today, DLPEvent.risk_level == "MEDIUM")
        )
    )).scalar_one()
    blk   = (await db.execute(
        select(func.count(DLPEvent.id)).where(
            and_(DLPEvent.occurred_at >= today, DLPEvent.action_taken == "BLOCK")
        )
    )).scalar_one()
    flagged   = (await db.execute(
        select(func.count(Employee.id)).where(Employee.is_flagged == True)
    )).scalar_one()
    open_alts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.status == "OPEN")
    )).scalar_one()

    # Short, token-efficient prompt
    prompt = (
        f"DLP security report {now.strftime('%Y-%m-%d %H:%M UTC')}: "
        f"{total} events today ({high} HIGH, {med} MEDIUM, {blk} blocked), "
        f"{open_alts} open alerts, {flagged} flagged employees. "
        "Write a 3-5 sentence executive security posture summary, "
        "then list exactly 3 numbered remediation actions. Be concise."
    )

    summary_text = _call_gemini(prompt)

    # Cache the result
    _summary_cache = {
        "summary":      summary_text,
        "generated_at": now,
        "expires_at":   now + timedelta(seconds=_CACHE_TTL_SECONDS),
    }

    return ExecutiveSummaryOut(summary=summary_text, generated_at=now)
