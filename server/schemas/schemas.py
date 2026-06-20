import datetime
from pydantic import BaseModel, EmailStr, Field

# User schemas
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "viewer"  # superadmin, analyst, viewer

class UserLogin(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: datetime.datetime
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str

# Employee schemas
class EmployeeOut(BaseModel):
    id: int
    name: str
    email: str
    department: str
    risk_score: float
    high_violations_7d: int
    is_flagged: bool
    flag_reason: str | None = None
    average_volume_30d: float
    created_at: datetime.datetime
    
    class Config:
        from_attributes = True

# Policy schemas
class PolicyCreate(BaseModel):
    name: str
    description: str | None = None
    rules_yaml: str
    is_active: bool = True

class PolicyOut(BaseModel):
    id: int
    name: str
    description: str | None = None
    rules_yaml: str
    version: int
    is_active: bool
    created_at: datetime.datetime
    
    class Config:
        from_attributes = True

# Alert schemas
class AlertOut(BaseModel):
    id: int
    employee_id: int
    title: str
    description: str
    severity: str
    status: str
    escalation_count: int
    pattern: str
    last_triggered_at: datetime.datetime
    created_at: datetime.datetime
    
    class Config:
        from_attributes = True

class AlertUpdate(BaseModel):
    status: str

# Agent schemas
class AgentRegister(BaseModel):
    agent_uuid: str
    hostname: str
    ip_address: str
    version: str = "1.0.0"

class AgentHeartbeat(BaseModel):
    agent_uuid: str
    ip_address: str | None = None

class AgentEventIngest(BaseModel):
    employee_email: EmailStr
    employee_name: str
    employee_department: str
    event_type: str
    risk_level: str
    channel: str
    pattern: str
    plaintext_data: str
    timestamp: datetime.datetime
