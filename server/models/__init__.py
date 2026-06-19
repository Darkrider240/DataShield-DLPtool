# server/models/__init__.py
# Import all models so Alembic autogenerate can discover them
from server.models.user import AdminUser
from server.models.employee import Employee
from server.models.agent import Agent
from server.models.event import DLPEvent
from server.models.alert import Alert
from server.models.policy import Policy

__all__ = ["AdminUser", "Employee", "Agent", "DLPEvent", "Alert", "Policy"]
