"""
Pydantic-settings configuration for DataShield Enterprise Server.
Loads all settings from environment variables / .env file.
"""
import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://datashield:datashield@localhost:5432/datashield"

    # ── JWT ───────────────────────────────────────────────────────────────────
    JWT_SECRET_KEY: str = "CHANGEME_USE_STRONG_SECRET_IN_PROD"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── Envelope Encryption ───────────────────────────────────────────────────
    # Master key passphrase — used to derive the AES-256 master key via PBKDF2
    MASTER_KEY_PASSPHRASE: str = "CHANGEME_USE_STRONG_PASSPHRASE_IN_PROD"
    # Salt persisted alongside encrypted DEKs (hex string, 16 bytes → 32 hex chars)
    MASTER_KEY_SALT_HEX: str = ""

    # ── Gemini AI ────────────────────────────────────────────────────────────
    GEMINI_API_KEY: str = ""

    # ── SMTP Alert Notifications ─────────────────────────────────────────────
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "datashield@datashield.local"
    ALERT_EMAIL_RECIPIENTS: str = ""   # comma-separated

    # ── Agent API ────────────────────────────────────────────────────────────
    AGENT_API_KEY: str = "CHANGEME_AGENT_SECRET"

    # ── App ───────────────────────────────────────────────────────────────────
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False

    @property
    def alert_email_recipient_list(self) -> list[str]:
        return [e.strip() for e in self.ALERT_EMAIL_RECIPIENTS.split(",") if e.strip()]


@lru_cache()
def get_settings() -> Settings:
    return Settings()
