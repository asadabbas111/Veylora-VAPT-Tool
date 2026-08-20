# Veylora

**AI Autonomous Vulnerability Assessment & Authorized Penetration Testing Platform**

A modular, secure, explainable platform that orchestrates **authorized** vulnerability
assessment and penetration-testing workflows. It discovers assets, drives scanners,
computes explainable risk scores, chains **attack paths**, runs an **AI security analyst**,
performs **controlled validation**, tracks **remediation with re-tests**, and generates
professional, **branded PDF reports** — all behind a polished web dashboard and a full REST API.

> **⚠️ AUTHORIZED USE ONLY.** Every active operation is restricted to explicitly authorized
> assessment scopes enforced **server-side**. The platform is designed for isolated labs,
> research networks, and engagements with written consent. It must never be pointed at
> systems you do not own or have permission to test.

---

## ✨ Features

| Area | What it does |
| --- | --- |
| **Frontend** | React 18 + TypeScript + Vite + Tailwind. Professional SOC theme, brand logo, fully responsive. Sessions are browser-scoped: every new visit starts at the *Sign in / Sign up* screen. |
| **Auth** | Sign up → **email OTP verification** (Gmail SMTP), sign in, refresh tokens, JWT, RBAC (admin / analyst / viewer), rate limiting, and a **Forgot password** reset flow (code by email or on-screen in lab mode). |
| **Assessments** | Engagement lifecycle: scope definition → in-scope targets (server-side validation blocks out-of-scope) → stage-based or full workflow → pause/resume/cancel/delete. **Select-all + bulk delete** supported. |
| **Scanners** | Adapter architecture: `simulated-lab` (deterministic demo dataset with real CVSS + vectors), `nmap` (real), `nuclei` (optional). Selectable per run. |
| **Risk Engine** | Explainable 0–100 score from CVSS, asset criticality, exploitability, exposure, confidence, attack-path importance, minus false-positive penalty. Full breakdown per finding. |
| **Attack Paths** | Graph-based exploitation chains (Asset → Service → Vuln → Privilege → Critical asset) with lateral movement, deduped per endpoint, visualized with React Flow. |
| **AI Analyst** | Provider abstraction: rule/heuristic (offline default), OpenAI, Ollama. Returns priority (P1–P4), severity, confidence, false-positive assessment, remediation, with traceable basis. |
| **Validation** | Leveled (0–3) controlled PoC engine, admin approval for level > 1, verdicts, audited evidence. |
| **Remediation** | Task tracking, status workflow, **authorized re-test** showing risk before → after. |
| **Reports** | Professional branded PDFs — cover with **Veylora logo**, header/footer on every page, executive summary, scope, methodology, assets, risk summary, **web-app findings (HTTP/HTTPS with exact endpoints)**, findings by severity with **CVSS + vectors + affected location**, attack paths, MITRE mapping, evidence, remediation, timeline. SHA-256 fingerprints. Download & **bulk delete** from the UI. |
| **Audit** | Append-only, immutable audit log of every action. |
| **ML sub-project** | Preprocessing, training and evaluation comparing CVSS-only vs ML prioritisation (Random Forest ≈ 86.1% accuracy / 0.98 AUROC vs 30.5% baseline). |
| **Ops** | Docker Compose (Postgres, Redis, Neo4j, API, web), `.env` configuration, health checks. |

---

## 📸 Branding

- Product name: **Veylora**
- Logo: `frontend/public/logo.png` (also embedded on the cover of every generated PDF report)

---

## 🏗 Architecture

```
┌─────────────────────────┐
│  Web (React + Vite)     │  :5173 dev / :8080 docker
│  Veylora SOC theme      │
└───────────┬─────────────┘
            │ /api (proxied, JWT)
┌───────────▼─────────────────────────────┐
│  FastAPI REST API  (:8000)             │
│  ├─ auth / OTP / forgot-password       │
│  ├─ assessments / scope / targets      │
│  ├─ assets / findings / risk           │
│  ├─ attack paths / AI / validation     │
│  ├─ remediation / reports / audit      │
│  └─ admin / kill-switch / ml           │
└───┬──────────┬──────────┬──────────────┘
    │          │          │
 SQLite/  Scanner     TaskManager (local worker
 Postgres  adapters   or Celery/Redis) → Pipeline
    │          │          │
    │     SimulatedLab / Nmap / Nuclei
    │          └── evidence store (SHA-256, immutable)
 NetworkX / Neo4j attack-graph store
```

### Component map

- `backend/app/` — FastAPI application (layered: `api` → `services` → `models`).
- `backend/app/api/routes/` — REST endpoints per domain.
- `backend/app/tasks/pipeline.py` — workflow orchestration (`run_full_workflow`).
- `backend/app/scanners/` — adapter-based scanner engine (SimulatedLab / Nmap / Nuclei).
- `backend/app/risk/` — explainable scoring.
- `backend/app/attack_graph/` — NetworkX + optional Neo4j attack-path engine.
- `backend/app/ai/` — AI analyst with pluggable providers.
- `backend/app/validators/` — controlled validation engine.
- `backend/app/reports/` — ReportLab PDF generation (branded, logo, web-findings section).
- `backend/app/services/scope_service.py` — server-side authorized-scope enforcement.
- `frontend/` — React + TypeScript SPA.
- `ml/` — research-grade ML prioritisation experiment.
- `infrastructure/` — Dockerfiles, nginx config, lab scaffolding.
- `docs/` — design & research documentation.

---

## 🚀 Quickstart (no Docker / Windows)

### 1. Backend

```powershell
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
Copy-Item ..\.env.example .env      # optional; defaults work out of the box
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

- API + Swagger UI: <http://127.0.0.1:8000/api/docs>
- Health: <http://127.0.0.1:8000/>

### 2. Frontend

```powershell
cd frontend
npm install
npm run dev          # http://127.0.0.1:5173  (proxies /api to :8000)
```

### 3. Sign in

- **Admin:** `admin@secops.io` / `Admin@12345` (seeded automatically)
- **Self-signup:** create an account → verify the 6-digit OTP by email
  (in lab mode `DEV_OTP_RETURN=true` echoes the code in the API response) → signed in.
- **Forgot password:** link on the sign-in page — a reset code is emailed,
  or shown on-screen while SMTP credentials are placeholders.

> Authenticated PDF downloads use your session token; the report download button
> in the UI handles this automatically.

### 4. Seed demo data

On the **Settings** page click **"Seed demo assessment"**, or call:

```
POST /api/admin/seed-demo
Authorization: Bearer <admin-token>
```

This creates the *Metasploitable Lab Assessment* against the authorized `192.168.56.0/24`
scope and runs the full workflow — assets, findings (including **web application**
HTTP/HTTPS findings), risk, attack paths, AI analysis, and a branded PDF report.

---

## 🚀 Quickstart (Docker Compose)

```bash
cp .env.example .env   # then edit secrets
docker compose up --build
```

- Web UI: <http://localhost:8080>
- API docs: <http://localhost:8000/api/docs>
- Postgres on 5432, Redis on 6379, Neo4j on 7474/7687

---

## 🔒 Security model

- **Server-side scope enforcement** — targets are validated against the authorized scope
  (CIDR / IP / hostname / domain / URL) before anything runs; out-of-scope attempts are
  blocked **and audited**.
- **Role-based access control** — granular permissions: `create_assessment`, `run_scan`,
  `generate_report`, `delete_report`, `delete_assessment`, `manage_users`,
  `kill_switch`, `validate`, `approve_validation`, …
- **OTP email verification** — new accounts are inactive until they prove mailbox ownership.
- **Reset-code rotation** — forgot-password OTPs are single-use and time-limited.
- **Global kill switch** — immediate halt of all active pipelines and validations.
- **Immutable evidence** — evidence is content-addressed (SHA-256) and locked after completion.
- **Append-only audit trail** — every action, including failed/blocked actions, is logged.
- **Minimal active testing** — non-destructive by default; validation levels ≥ 2 require
  explicit admin approval and are gated by the kill switch and scope checks.
- **Password hygiene** — bcrypt-hashed, strength policy, rate-limited auth endpoints.

---

## 📚 API overview

| Group | Endpoints (prefix `/api`) |
| --- | --- |
| Auth | `POST /auth/register`, `POST /auth/verify-email`, `POST /auth/resend-otp`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/forgot-password`, `POST /auth/reset-password`, `GET /auth/me` |
| Assessments | CRUD `/assessments` (+ `POST /assessments/bulk-delete`, `DELETE /assessments/{id}`), `POST /assessments/{id}/workflow`, `POST /assessments/{id}/scopes`, `POST /assessments/{id}/targets`, `POST /assessments/{id}/scope-check`, pause/resume/cancel, `GET /assessments/{id}/overview` |
| Assets | `GET /assets?assessment_id=`, `GET /assets/{id}`, `GET /assets/{id}/services`, `GET /assets/{id}/findings` |
| Findings | `GET /findings?assessment_id=`, `GET /findings/{id}`, `PATCH /findings/{id}`, `GET /findings/{id}/analyses` |
| Risk | risk calculation / breakdown endpoints |
| Attack paths | `GET /attack-paths?assessment_id=`, `POST /attack-paths/build`, `GET /attack-paths/graph/summary` |
| AI | `POST /ai/analyze/{finding_id}`, `POST /ai/analyze-assessment/{id}`, `GET /ai/prioritization` |
| Validation | `POST /validation/request/{finding_id}`, `POST /validation/approve/{task_id}`, `POST /validation/run/{task_id}`, `GET /validation/tasks` |
| Remediation | `GET /remediation`, `POST /remediation/{task_id}/status`, `POST /remediation/{task_id}/retest` |
| Reports | `GET /reports`, `POST /reports/generate/{assessment_id}`, `GET /reports/download/{report_id}`, `DELETE /reports/{report_id}`, `POST /reports/bulk-delete` |
| Audit | `GET /audit` (paginated, filterable, admin) |
| Admin | users, kill switch, `POST /admin/seed-demo`, ML endpoints |

Full interactive docs: <http://127.0.0.1:8000/api/docs>

---

## 🧪 Tests

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pytest -q                        # 53 unit + integration tests (auth/OTP, RBAC, scope
                                 #   enforcement, risk, pipeline, validation, report, audit)
pytest --cov=app --cov-report=term-missing   # coverage report (~76% overall; core paths 80-100%)
.\.venv\Scripts\python scripts\smoke_test.py   # full end-to-end (API) smoke test
```

Browser E2E (optional, requires Chrome installed):

```
cd %TEMP%\opencode\e2e   # scripts written there during development
npm i puppeteer-core
node assert-test.js       # 10-page UI walk-through incl. login
node signup-test.js       # signup → OTP → verify → re-login
```

---

## ⚙️ Continuous Integration

`.github/workflows/ci.yml` runs on every push/PR to `main`:

| Job | What it checks |
| --- | --- |
| `backend-tests` | Python 3.13, installs `requirements*.txt`, runs the full pytest suite with coverage |
| `frontend-build` | Node 24, `npm ci`, TypeScript type-check (`tsc --noEmit`), production build |
| `docker-build` | Builds both Docker images (`Dockerfile.api`, `Dockerfile.web`) |

To use it, push this repository to GitHub — the workflow activates automatically.

---

## 🧠 ML research sub-project

`ml/` compares classical CVSS-only prioritisation against trained classifiers on a
deterministic synthetic dataset (3000 samples, scenarios A–E).

| Model | Accuracy | ROC-AUC |
| --- | --- | --- |
| CVSS-only baseline | 30.5% | – |
| Logistic Regression | ≈ 83% | ≈ 0.96 |
| **Random Forest** | **86.1%** | **0.977** |
| XGBoost (optional dep) | (skipped if not installed) | – |

```powershell
cd ml
py -m venv .venv ; .\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\python preprocessing\preprocess.py
.\.venv\Scripts\python training\train.py
```

The trained model is exported to `ml/models/priority_model.joblib` and can back the
platform's `rule` AI provider semantics (`priority_model.joblib` referenced by the AI layer).

---

## 📁 Project roadmap status

- [x] PHASE 1 — Foundation & security skeleton (config, DB, auth, RBAC, OTP, audit)
- [x] PHASE 2 — Assessment lifecycle & scope enforcement
- [x] PHASE 3 — Scanner adapters (simulated-lab, nmap, nuclei) + pipeline
- [x] PHASE 4 — Explainable risk engine
- [x] PHASE 5 — Attack-path engine (NetworkX + optional Neo4j)
- [x] PHASE 6 — AI analyst (rule / OpenAI / Ollama) + prioritisation
- [x] PHASE 7 — Controlled validation engine + MITRE mapping
- [x] PHASE 8 — Remediation + re-test flow
- [x] PHASE 9 — Branded PDF reporting + web-app findings + evidence store
- [x] PHASE 10 — ML research + dashboard v2 (frontend)
- [x] Auth hardening: forgot-password / reset flow, session-scoped login
- [x] Data management: delete + select-all/bulk-delete for assessments and reports
- [x] Docker Compose, environment templates, README, docs
- [ ] CI pipeline (GitHub Actions) — *next*
- [ ] Production locking (TLS, secrets vault, RBAC policies hardening)

---

## 📄 License & disclaimer

Educational and research use. The author(s) bear no responsibility for misuse. Users are
responsible for ensuring all testing is performed only on systems they own or are
explicitly authorized to test. See the security model above.

---

**Veylora** — *attack knowingly, test only what you're allowed to.*