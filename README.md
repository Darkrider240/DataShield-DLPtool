# DataShield Enterprise DLP

> **Enterprise-grade Data Loss Prevention** — multi-component, AI-powered, encryption-first.  
> Built as an internship project demonstrating real-world DLP architecture.

---

## What It Does

DataShield monitors and prevents sensitive data from leaving your organisation across all major channels:

| Channel | How it's monitored |
|---|---|
| 📂 **Files** | Scan before sending — employee picks folder, agent scans with 40+ DLP patterns |
| 📧 **Webmail** | Browser extension intercepts Gmail attachment upload before it ever reaches Gmail |
| 📋 **Clipboard** | Background monitor flags paste of **any single** sensitive entity (Aadhaar, SSN, PAN, IBAN, IFSC, ICD-10, credit card, API keys…) — clears clipboard immediately |
| 💾 **USB** | Live watchdog starts **immediately on insertion** (before the mount scan) — intercepts sensitive file copies in real time. Encrypted/password-protected files that cannot be scanned are flagged with an admin prompt |

Every violation is:
- Encrypted per-employee (AES-256-GCM envelope encryption)
- Reported to the central server in real-time via WebSocket
- Scored by a risk engine with time-of-day, volume, and repeat multipliers
- Explained by Gemini AI (shown to the employee inline, and in the admin dashboard)

---

## Recent Improvements

| Area | Change |
|---|---|
| 🔴 **USB — No Blind Spot** | Live watchdog observer now arms **before** the full mount scan. Files copied during the scan are intercepted in real time (previously ignored until scan completed) |
| 🔒 **USB — Encrypted File Detection** | Password-protected / encrypted PDFs and DOCX files that cannot be content-scanned are flagged as `UNREADABLE` and an admin prompt offers to remove them from the drive |
| 📋 **Clipboard — Single Entity Block** | Reduced minimum length filter from 10 → 4 chars; any single high-value pattern (weight ≥ 1.5) now triggers a block even without multiple co-located matches |
| 🔇 **PDF Noise Suppression** | Silenced `pdfminer` internal loggers — "Data-loss while decompressing corrupted data" warnings are suppressed; unreadable PDFs are skipped silently |
| 🤖 **Gemini Multi-Model Fallback** | Both `ai_explain.py` and `server/api/reports.py` now try `gemini-2.5-flash → 2.0-flash → 1.5-flash → 1.5-flash-8b` in sequence and continue on **any** error (not just 429), returning a static fallback if all fail |
| 🖥️ **Server Startup Fix** | Server must be started from the **project root** with `uvicorn server.main:app --port 8001 --reload` (not from inside `server/`) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  EMPLOYEE MACHINE                                                   │
│                                                                     │
│  main.py (login)                                                    │
│      ↓                                                              │
│  EmployeeHomeWindow (Tkinter)                                       │
│    ├── Monitor pills (Clipboard · USB · Webmail)                    │
│    ├── Scan Folder button → results + Gemini AI explanation         │
│    └── Live Threat Feed (click any row for AI explanation)          │
│                                                                     │
│  Background threads:                                                │
│    ClipboardMonitor · USBWatcher · WebmailHTTPServer (:5000)        │
│                                                                     │
│  Chrome Extension (MV3)  — extension/                               │
│    ├── content.js     Intercepts Gmail file input (capture phase)   │
│    │                  Blocks/warns on DLP match                     │
│    │                  Whitelists admin-approved files               │
│    └── background.js  Service worker — CORS-free HTTP proxy         │
│                        Polls server for override approval decisions  │
└────────────────┬────────────────────────────────────────────────────┘
                 │ HTTP :5000 (agent proxy)
                 │ POST /api/agents/events  (JWT auth)
                 │ WebSocket /ws/events     (live feed)
                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  FASTAPI SERVER  (:8001)                                            │
│                                                                     │
│  API Routes:                                                        │
│    /api/auth        Login (admin → dashboard, employee → agent)     │
│    /api/agents      Register · Heartbeat · Event ingest             │
│    /api/events      List with employee attribution + email details  │
│    /api/employees   Profiles · Timeline · Flag/Unflag · Set PIN     │
│    /api/alerts      Acknowledge · Escalate                          │
│    /api/policies    YAML import · Push to agents                    │
│    /api/overrides   Submit · Review · Approve/Deny · Notifications  │
│    /api/reports     Compliance metrics · Gemini executive summary   │
│    /api/encryption  Key status · Rotate all DEKs                   │
│    /ws/events       Live WebSocket broadcast                        │
│                                                                     │
│  Services:                                                          │
│    alert_engine.py   — severity scoring, deduplication, SMTP        │
│    behaviour.py      — risk score: base × volume × time × repeat   │
│    crypto_service.py — AES-256-GCM per-employee DEK management     │
└────────────────┬────────────────────────────────────────────────────┘
                 │ asyncpg
                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  INFRASTRUCTURE                                                     │
│                                                                     │
│  PostgreSQL  (Docker :5432)                                         │
│    dlp_events        (channel, risk_level, file_path_encrypted,     │
│                       sender_email, recipient_emails)               │
│    employees         (risk_score, is_flagged, encrypted_dek,        │
│                       pin_hash, pin_set)                            │
│    agents            (heartbeat, policy_version)                    │
│    alerts            (severity, escalation_count)                   │
│    policies          (yaml_content, version)                        │
│    override_requests (status, justification, agent_notified)        │
│                                                                     │
│  Gemini AI  — Inline employee explanations + dashboard reports      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Override Request Flow

When Gmail DLP blocks an attachment, the employee can request admin approval:

```
Employee attaches file → DLP scan → BLOCKED
         ↓
Employee types justification → "Request Override"
         ↓
background.js POSTs to :5000 proxy → :8001/api/overrides
         ↓ (polls every 8 seconds)
Admin reviews in dashboard → Approves / Denies
         ↓
background.js gets decision → sends to Gmail tab
         ↓
APPROVED → file whitelisted for 15 min → employee reattaches → sent ✅
DENIED   → red toast shown with admin note
```

---

## Quick Start

### Prerequisites

```bash
# 1. Start PostgreSQL via Docker
docker-compose up -d

# 2. Create the virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
pip install -r server/requirements.txt
```

### 1. Server (FastAPI)

```bash
# From project root (not inside server/)
cp server/.env.example server/.env   # fill in DB_URL, JWT_SECRET_KEY, GEMINI_API_KEY, AGENT_API_KEY
python -m server.init_db             # seeds admin@datashield.local / Admin@123
uvicorn server.main:app --host 0.0.0.0 --port 8001 --reload
```

### 2. Admin Dashboard (React)

```bash
cd dashboard
npm install
npm run dev                  # opens http://localhost:5173
```

Login: `admin@datashield.local` / `Admin@123`

### 3. Employee Agent (Tkinter)

```bash
# From project root (with venv active)
cp .env.example .env         # set SERVER_URL=http://localhost:8001
python main.py               # login dialog appears
```

### 4. Browser Extension (Chrome MV3)

1. Open `chrome://extensions` → Enable **Developer mode**
2. Click **Load unpacked** → select the `extension/` folder
3. Extension activates automatically on Gmail
4. Hard-refresh Gmail after any extension reload (`Ctrl+Shift+R`)

---

## Key Technical Decisions

| Decision | Rationale |
|---|---|
| **Background service worker for HTTP** | Content scripts are CORS-restricted; background workers bypass CORS for host_permissions URLs entirely |
| **Capture-phase event interception** | `addEventListener('change', fn, { capture: true })` fires before Gmail's own handler — only reliable way to block files before Gmail processes them |
| **Per-employee DEK** | If one key leaks, only that employee's events are exposed |
| **Alert deduplication** | Same pattern within 4h increments `escalation_count` instead of flooding alerts |
| **Risk multipliers** | Off-hours (22:00–06:00) ×1.3, high-volume ×1.5, repeat pattern ×1.4 |
| **Envelope encryption** | Master key (derived, never stored) encrypts per-employee DEKs; DEKs encrypt event data |
| **Tkinter not Electron** | No Node.js dependency on employee machines — single `python main.py` |
| **Fail-open DLP** | If agent is offline, attachments are warned but not blocked — availability over security for usability |

---

## Roles

| Role | Access |
|---|---|
| `superadmin` | Full access: policies, encryption key rotation, all events (decrypted), override decisions |
| `analyst` | Events (decrypted), employees, alerts — no policy changes |
| `viewer` | Read-only dashboard metrics |
| `employee` | Agent only — sees own threats, can scan folders, submit override requests |

---

## Environment Variables

### `server/.env`

```env
DATABASE_URL=postgresql+asyncpg://datashield:datashield@localhost:5432/datashield
JWT_SECRET=your-secret-here
JWT_ALGORITHM=HS256
GEMINI_API_KEY=your-gemini-key
MASTER_KEY_PASSPHRASE=your-passphrase
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=alerts@yourcompany.com
SMTP_PASS=your-app-password
```

### `.env` (agent root)

```env
SERVER_URL=http://localhost:8001
GEMINI_API_KEY=your-gemini-key
AGENT_API_KEY=your-agent-api-key   # must match AGENT_API_KEY in server/.env
```

> **Note:** `AGENT_API_KEY` must be identical in both `server/.env` and the agent root `.env`. The agent uses it as a shared secret when posting events to the server.

---

## Project Structure

```
datashield/
├── main.py                  # Agent entry point (login + monitor orchestration)
├── gui/
│   ├── main_window.py       # EmployeeHomeWindow (Tkinter)
│   └── local_history.py     # Local event history viewer
├── comms/
│   └── http_server.py       # Agent HTTP server (:5000) — scan + proxy
├── extension/               # Chrome MV3 browser extension
│   ├── manifest.json
│   ├── content.js           # Gmail DLP interceptor
│   └── background.js        # Service worker (CORS-free HTTP + approval polling)
├── server/                  # FastAPI backend
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   ├── models/              # SQLAlchemy models
│   ├── schemas/             # Pydantic schemas
│   ├── api/                 # Route handlers
│   │   ├── auth.py
│   │   ├── agents.py
│   │   ├── employees.py
│   │   ├── events.py
│   │   ├── overrides.py     # Override request + approval flow
│   │   ├── alerts.py
│   │   ├── policies.py
│   │   ├── reports.py
│   │   └── encryption.py
│   └── services/
│       ├── alert_engine.py
│       ├── behaviour.py
│       └── crypto_service.py
├── crypto/
│   └── encryption.py        # AES-256-GCM + PBKDF2 key derivation
├── dashboard/               # React + TypeScript admin dashboard
│   └── src/
│       ├── pages/           # Dashboard, Employees, Events, Alerts, Overrides...
│       ├── components/      # Navbar, LiveFeed, RiskBadge, Charts...
│       └── api/             # Axios clients for each endpoint
└── docker-compose.yml       # PostgreSQL container
```

---

## Networking Overview

| Port | Service | Used by |
|---|---|---|
| `:5000` | Agent HTTP server | Browser extension (scan, ping, me, override proxy) |
| `:8001` | FastAPI server | Agent (event ingest), Dashboard (all API), Extension background worker |
| `:5432` | PostgreSQL (Docker) | FastAPI via asyncpg |
| `:5173` | Vite dev server | Admin dashboard in browser |

**CORS**: FastAPI allows `chrome-extension://` origins via `allow_origin_regex`.  
**Extension HTTP**: All fetch calls from content scripts go through `background.js` (service worker) to avoid CORS preflight restrictions.
