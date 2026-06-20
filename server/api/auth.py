"""Authentication routes: login, refresh, profile, agent employee validation."""
import jwt
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from passlib.context import CryptContext
from server.database import get_db
from server.models.user import AdminUser
from server.models.employee import Employee
from server.schemas import LoginRequest, TokenResponse, RefreshRequest, UserOut
from server.config import get_settings
from server.middleware.auth_middleware import get_current_user

settings = get_settings()
router = APIRouter(prefix="/api/auth", tags=["auth"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _make_access_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": user_id, "exp": expire, "type": "access"},
        settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )


def _make_refresh_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    return jwt.encode(
        {"sub": user_id, "exp": expire, "type": "refresh"},
        settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )


# ── Dashboard login ──────────────────────────────────────────────────────────
@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AdminUser).where(AdminUser.email == body.email))
    user = result.scalar_one_or_none()
    if not user or not pwd_context.verify(body.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")
    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    return {
        "access_token":  _make_access_token(user.id),
        "refresh_token": _make_refresh_token(user.id),
        "token_type":    "bearer",
        "role":          user.role,
        "full_name":     user.full_name,
        "email":         user.email,
    }


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest):
    try:
        payload = jwt.decode(
            body.refresh_token, settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        if payload.get("type") != "refresh":
            raise ValueError
        user_id = payload["sub"]
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    return TokenResponse(
        access_token=_make_access_token(user_id),
        refresh_token=_make_refresh_token(user_id)
    )


@router.get("/me", response_model=UserOut)
async def profile(current_user: AdminUser = Depends(get_current_user)):
    return current_user


# ── Agent / Tkinter login ─────────────────────────────────────────────────────
@router.post("/validate-employee")
async def validate_employee(
    body: LoginRequest,
    x_datashield_agent_key: str = Header(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Called by the Tkinter agent on startup login.
    - Admin: verified by email + password against admin_users table.
    - Employee: email must exist in employees table (no password — admin registers them).
    Returns: { role, name, email }
    """
    if x_datashield_agent_key != settings.AGENT_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid agent key")

    # Check if admin
    admin_result = await db.execute(
        select(AdminUser).where(AdminUser.email == body.email)
    )
    admin = admin_result.scalar_one_or_none()
    if admin:
        if not pwd_context.verify(body.password, admin.hashed_password):
            raise HTTPException(status_code=401, detail="Wrong password for admin account")
        return {"role": "admin", "name": admin.full_name, "email": admin.email, "pin_set": True}

    # Check if registered employee
    emp_result = await db.execute(
        select(Employee).where(Employee.email == body.email)
    )
    emp = emp_result.scalar_one_or_none()
    if emp:
        # If a PIN has been set, require it
        if emp.pin_set and emp.pin_hash:
            if not body.password:  # password field is used for PIN
                raise HTTPException(status_code=401, detail="pin_required")
            from passlib.context import CryptContext as _PC
            _pc = _PC(schemes=["bcrypt"], deprecated="auto")
            if not _pc.verify(body.password, emp.pin_hash):
                raise HTTPException(status_code=401, detail="Wrong PIN")
        elif not emp.pin_set:
            # PIN not yet set — return a special status so Tkinter can show a message
            return {"role": "employee", "name": emp.full_name or emp.email, "email": emp.email, "pin_set": False,
                    "monitor_clipboard": emp.monitor_clipboard, "monitor_usb": emp.monitor_usb,
                    "monitor_webmail": emp.monitor_webmail, "monitor_file_scan": emp.monitor_file_scan}
        return {"role": "employee", "name": emp.full_name or emp.email, "email": emp.email, "pin_set": True,
                "monitor_clipboard": emp.monitor_clipboard, "monitor_usb": emp.monitor_usb,
                "monitor_webmail": emp.monitor_webmail, "monitor_file_scan": emp.monitor_file_scan}

    # Not found
    raise HTTPException(
        status_code=404,
        detail="not_registered"
    )
