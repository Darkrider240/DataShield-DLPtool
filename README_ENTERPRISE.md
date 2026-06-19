# DataShield Enterprise — Setup & Operations Guide

## Overview

DataShield Enterprise upgrades the standalone DLP agent into a full multi-tier architecture:

| Tier | Technology | Purpose |
|------|-----------|---------|
| Endpoint Agent | Python (existing) | Scans files, email, clipboard, USB on user machines |
| Central Server | FastAPI + PostgreSQL | Receives events, evaluates risk, manages policies, serves dashboard API |
| Dashboard | React 18 + Vite | Browser-based SIEM-style management interface |
| Orchestration | Docker Compose | Single-command deployment of all services |

---

## Prerequisites

- **Docker Desktop** (Windows) with Compose V2 enabled
- **Node 20+** (for local dashboard development)
- **Python 3.12+** (for local server development)
- A **Gemini API key** for AI executive summaries (optional)

---

## Quick Start (Docker)

```bash
# 1. Clone / navigate to the datashield directory
cd C:\Users\HP\.gemini\antigravity\scratch\datashield

# 2. Copy and configure the environment file
copy server\.env.example server\.env
# Edit server\.env and set:
#   MASTER_KEY_PASSPHRASE, JWT_SECRET_KEY, AGENT_API_KEY, GEMINI_API_KEY

# 3. Launch the full stack
docker compose up --build -d

# 4. First run: note the MASTER_KEY_SALT_HEX printed in server logs
docker compose logs server | findstr MASTER_KEY_SALT_HEX
# Copy that value into server\.env as MASTER_KEY_SALT_HEX=<value>
# Then restart: docker compose restart server

# 5. Open the dashboard
# http://localhost:3000
# Default credentials: admin@datashield.local / DataShield@2025!
```

---

## Local Development

### Backend Server

```bash
cd datashield

# Install dependencies
pip install -r server/requirements.txt

# Set up environment
copy server\.env.example server\.env
# Edit .env values

# Initialize the database (first time)
python -m server.init_db

# Start the API server
uvicorn server.main:app --reload --port 8000
# Swagger UI: http://localhost:8000/api/docs
```

### Dashboard

```bash
cd datashield/dashboard
npm install
npm run dev
# Dashboard: http://localhost:5173
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  User Machine (Endpoint Agent)                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ Scanner  │  │Behaviour │  │ Comms    │  │ GUI      │  │
│  │ (files,  │  │ (risk    │  │ (SMTP,   │  │(tkinter) │  │
│  │  USB,    │  │  score)  │  │  ext)    │  │          │  │
│  │  clip)   │  └──────────┘  └──────────┘  └──────────┘  │
│  └────┬─────┘                                              │
│       │ events (HTTPS + HMAC)                              │
└───────┼─────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────┐
│  Central Server  (FastAPI + Uvicorn)                      │
│                                                           │
│  /api/agents  →  ingest events, heartbeat, policy sync   │
│  /api/auth    →  JWT login / refresh                      │
│  /api/employees, /api/events, /api/alerts                 │
│  /api/reports →  compliance metrics + Gemini summary      │
│  /api/encryption → DEK key rotation                       │
│  /ws/events   →  WebSocket live feed                      │
│                                                           │
│  ┌────────────────┐  ┌──────────────────────┐            │
│  │ Alert Engine   │  │ Envelope Encryption   │            │
│  │ (dedup, SMTP,  │  │ Master Key → DEK      │            │
│  │  WS broadcast) │  │ AES-256-GCM per field │            │
│  └────────────────┘  └──────────────────────┘            │
│                                                           │
│  ┌──────────────────────────┐                            │
│  │ PostgreSQL (asyncpg)     │                            │
│  │ employees, events, alerts│                            │
│  │ agents, policies         │                            │
│  └──────────────────────────┘                            │
└───────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────┐
│  Dashboard  (React 18 + Vite → nginx)                     │
│                                                           │
│  /          →  Dashboard (metrics, live feed, charts)     │
│  /employees →  Risk heatmap, flag/unflag                  │
│  /events    →  Paginated DLP event log                    │
│  /policies  →  YAML editor, push to agents                │
│  /alerts    →  Acknowledge / resolve alerts               │
│  /encryption→  Key status, DEK rotation                   │
│  /reports   →  Compliance metrics + Gemini AI summary     │
└───────────────────────────────────────────────────────────┘
```

---

## Envelope Encryption Model

1. A **Master Key** is derived from your passphrase via PBKDF2-HMAC-SHA256 (310,000 iterations).
2. Each employee gets a unique **Data Encryption Key (DEK)**, stored AES-256-GCM encrypted with the master key.
3. Sensitive event fields (`file_path`, `ai_explanation`) are encrypted with the employee's DEK — never stored in plaintext.
4. Analysts/superadmins who view events trigger a **per-request DEK decrypt** — the raw DEK never persists in memory beyond the request.
5. Key rotation re-encrypts all DEKs and event fields with fresh keys without changing the master passphrase.

---

## Role-Based Access Control

| Role | Dashboard Access |
|------|----------------|
| `superadmin` | Full access including Policies, Encryption, Reports, and decrypted file paths |
| `analyst` | Events (with decrypted paths), Employees, Alerts, Reports |
| `viewer` | Read-only Dashboard, Employees (no decryption), Alerts |

---

## Agent Configuration

Endpoint agents communicate with the server using:
- **Header**: `X-DataShield-Agent-Key: <AGENT_API_KEY>`
- **Endpoints**: `POST /api/agents/register`, `POST /api/agents/heartbeat`, `POST /api/agents/events`

Set in `agent/reporting_client.py` or via the agent config:
```python
DATASHIELD_SERVER_URL = "http://localhost:8000"
DATASHIELD_AGENT_KEY  = "your-agent-api-key"
```

---

## Alembic Migrations (Production)

```bash
# Inside the datashield directory
alembic -c server/alembic.ini revision --autogenerate -m "initial"
alembic -c server/alembic.ini upgrade head
```

---

## Security Hardening Checklist

- [ ] Change all default credentials in `.env`
- [ ] Use a strong, random `JWT_SECRET_KEY` (32+ bytes)
- [ ] Use a strong `MASTER_KEY_PASSPHRASE` and store it in a secrets manager
- [ ] Enable HTTPS (TLS termination at nginx or a load balancer)
- [ ] Restrict CORS `allow_origins` to your dashboard domain only
- [ ] Configure `ALERT_EMAIL_RECIPIENTS` for critical alert notifications
- [ ] Set up periodic database backups for the `pg_data` volume
