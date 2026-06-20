"""Pydantic schemas for DataShield Enterprise API."""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime


# ── Auth ──────────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str      # plain str — EmailStr rejects .local / reserved domains
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshRequest(BaseModel):
    refresh_token: str

class UserOut(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime
    model_config = {"from_attributes": True}


# ── Employee ──────────────────────────────────────────────────────────────────
class EmployeeCreate(BaseModel):
    email: str            # plain str — EmailStr rejects non-standard domains
    full_name: str = ""
    department: str = ""
    job_title: str = ""

class EmployeeOut(BaseModel):
    id: str
    email: str
    full_name: str
    department: str
    job_title: str
    risk_score: float
    risk_level: str
    high_violations_7d: int
    medium_violations_7d: int
    total_events_30d: int
    is_flagged: bool
    flag_reason: str
    flagged_at: Optional[datetime]
    created_at: datetime
    model_config = {"from_attributes": True}

class FlagRequest(BaseModel):
    reason: str = "Manually flagged by admin"

class MonitoringSettings(BaseModel):
    """Per-employee monitoring channel controls."""
    monitor_clipboard: bool = True
    monitor_usb: bool = True
    monitor_webmail: bool = True
    monitor_file_scan: bool = True
    model_config = {"from_attributes": True}


# ── Agent ─────────────────────────────────────────────────────────────────────
class AgentRegisterRequest(BaseModel):
    hostname: str
    employee_email: str       # plain str — EmailStr rejects .local domains
    employee_name: str = ""   # optional full name from the login dialog
    platform: str
    agent_version: str

class AgentRegisterResponse(BaseModel):
    agent_id: str
    policy_version: str
    policies: List[dict]

class HeartbeatRequest(BaseModel):
    agent_id: str
    current_policy_version: str

class HeartbeatResponse(BaseModel):
    policy_update_available: bool


# ── Event ─────────────────────────────────────────────────────────────────────
class EventIngest(BaseModel):
    agent_id: str = ""           # used to resolve the correct employee
    employee_email: str = ""     # fallback if agent_id not yet assigned
    channel: str
    action_taken: str
    justification: str = ""
    risk_level: str
    risk_score: float = 0.0
    file_path: str = ""
    matched_value_redacted: str = ""
    pattern_names: List[str] = []
    regulation_tags: List[str] = []
    ai_explanation: str = ""
    occurred_at: datetime

class EventOut(BaseModel):
    id: str
    employee_id: str
    agent_id: str
    channel: str
    action_taken: str
    risk_level: str
    risk_score: float
    matched_value_redacted: str
    pattern_names: List[str]
    regulation_tags: List[str]
    occurred_at: datetime
    ingested_at: datetime
    # Decrypted fields — only populated for authorized roles
    file_path: Optional[str] = None
    ai_explanation: Optional[str] = None
    model_config = {"from_attributes": True}


# ── Alert ─────────────────────────────────────────────────────────────────────
class AlertOut(BaseModel):
    id: str
    employee_id: str
    title: str
    description: str
    severity: str
    status: str
    top_pattern: str
    escalation_count: int
    created_at: datetime
    acknowledged_by: str
    acknowledged_at: Optional[datetime]
    model_config = {"from_attributes": True}

class AlertAcknowledgeRequest(BaseModel):
    note: str = ""


# ── Policy ────────────────────────────────────────────────────────────────────
class PolicyOut(BaseModel):
    id: str
    name: str
    category: str
    pattern: str
    base_weight: float
    regulation_tags: List[str]
    description: str
    is_active: bool
    version: str
    updated_at: datetime
    model_config = {"from_attributes": True}

class PolicyImportRequest(BaseModel):
    yaml_content: str


# ── Reports ───────────────────────────────────────────────────────────────────
class ComplianceMetricsOut(BaseModel):
    total_events: int
    high_events: int
    medium_events: int
    low_events: int
    blocked_events: int
    flagged_employees: int
    open_alerts: int
    critical_alerts: int
    regulation_hit_counts: dict

class ExecutiveSummaryOut(BaseModel):
    summary: str
    generated_at: datetime


# ── Encryption ────────────────────────────────────────────────────────────────
class KeyStatusOut(BaseModel):
    master_key_age_days: int
    total_employees: int
    dek_rotation_needed: bool

class RotationStatusOut(BaseModel):
    employees_rotated: int
    status: str
