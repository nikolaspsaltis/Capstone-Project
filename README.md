# Secure APIs for Web Services (Capstone)

## 1) Project Overview
This project is a security-focused REST API built with FastAPI for a university capstone.
It demonstrates practical authentication, authorization, and defensive controls in a reproducible
local environment, with scripts and result artifacts for evaluation.

The implementation targets clear, testable security behavior rather than framework-heavy complexity.

## 2) Feature List
- JWT authentication (`/register`, `/login`, `/profile`, `/refresh`, `/logout`)
- API key authentication (`X-API-Key`) for service-style access
- RBAC with admin-only routes (for example `/admin/users`)
- Login defenses:
  - rate limiting
  - account lockout/cooldown
  - auth-failure audit logging
- Additional admin security operations:
  - API key lifecycle endpoints
  - auth failure and audit log endpoints
  - security alerts endpoint
- Reproducible attack/performance scripts in `scripts/`
- Evaluation/report artifacts in `results/`

## 3) Architecture
Detailed architecture notes: [docs/architecture.md](docs/architecture.md)

Short description:
- Client requests (curl/scripts/tests) hit FastAPI routes in `app/main.py`.
- Auth is enforced through shared dependency functions (JWT and API key paths).
- Persistence is SQLite via SQLAlchemy models and Alembic migrations.
- Security telemetry and evaluation artifacts are emitted to logs and `results/` outputs.

Diagram placeholder (replace with your final diagram image in report):

```text
[Client: curl / scripts / tests]
            |
            v
[FastAPI app (app/main.py)]
   | authn/authz deps (JWT, API key)
   | rate limit + lockout + audit logs
            |
            v
[SQLite (SQLAlchemy + Alembic)]
            |
            v
[results/ artifacts + logs]
```

## 4) Setup
From repo root:

```bash
cd "/home/nikolas/Documents/UoE Documents/Captone-Project"
```

### Fresh setup
For a clean machine/environment, run:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env and set required values (at minimum: JWT_SECRET, API_KEYS, DATABASE_URL)
alembic upgrade head
uvicorn app.main:app --reload
```

With server running, execute security/performance scripts and regenerate results:

```bash
python scripts/bruteforce_login.py
python scripts/token_tampering.py
python scripts/unauthorized_admin_access.py
python scripts/performance_test.py
python scripts/run_capstone_evaluation.py
```

Create and activate virtual environment:

```bash
python3 -m venv secure-api-capstone/.venv
source secure-api-capstone/.venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Copy environment configuration:

```bash
cp .env.example .env
```

Load environment variables for current shell:

```bash
set -a
. ./.env
set +a
```

Run migrations and start server:

```bash
alembic upgrade head
uvicorn app.main:app --reload
```

Password hashing compatibility note:
- `passlib==1.7.4`
- `bcrypt==4.0.1`

This pinned pair avoids known passlib/bcrypt runtime incompatibility seen with newer bcrypt builds.

## 5) Usage with curl
Set base URL:

```bash
BASE_URL="http://127.0.0.1:8000"
```

Health:

```bash
curl -i "$BASE_URL/health"
```

Register a normal user:

```bash
USER_NAME="user_$(date +%s)"
curl -i -X POST "$BASE_URL/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USER_NAME\",\"password\":\"secret123\"}"
```

Login and capture JWT:

```bash
LOGIN_JSON=$(curl -s -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USER_NAME\",\"password\":\"secret123\"}")

ACCESS_TOKEN=$(printf '%s' "$LOGIN_JSON" | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
```

Profile with JWT:

```bash
curl -i "$BASE_URL/profile" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

`/data` with JWT:

```bash
curl -i "$BASE_URL/data" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

`/data` with API key (from `.env`, default `capstone-demo-key`):

```bash
curl -i "$BASE_URL/data" \
  -H "X-API-Key: capstone-demo-key"
```

Admin vs non-admin on `/admin/users`:

```bash
# Create admin user
ADMIN_NAME="admin_$(date +%s)"
curl -s -X POST "$BASE_URL/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$ADMIN_NAME\",\"password\":\"adminpass123\",\"role\":\"admin\"}" >/dev/null

# Admin login
ADMIN_LOGIN=$(curl -s -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$ADMIN_NAME\",\"password\":\"adminpass123\"}")
ADMIN_TOKEN=$(printf '%s' "$ADMIN_LOGIN" | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

# Non-admin should be 403
curl -i "$BASE_URL/admin/users" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Admin should be 200
curl -i "$BASE_URL/admin/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## 6) Running Scripts
Run with server active:

```bash
python scripts/bruteforce_login.py
python scripts/token_tampering.py
python scripts/unauthorized_admin_access.py
python scripts/performance_test.py
```

Optional full evaluation runner:

```bash
python scripts/run_capstone_evaluation.py
```

## 7) Results
For full artifact documentation and regeneration commands, see
[docs/results.md](docs/results.md).

Artifacts are written to `results/`.

Typical outputs:
- `performance_*.csv`: per-request latency samples from performance test script
- `evaluation_report_*.md`: human-readable summary of multi-script evaluation
- `evaluation_summary_*.json`: machine-readable summary (script exit codes and log paths)
- `*_*.log`: raw script logs (stdout/stderr)
- `graph_*.png`: generated analysis/figure outputs

How generated:
- `python scripts/performance_test.py` -> performance CSV
- `python scripts/run_capstone_evaluation.py` -> report + summary + script logs
- plotting utilities in `scripts/` generate graphs from summary/CSV inputs

## Notes for Markers
- No secrets are committed; `.env` is local-only.
- `requirements.txt` is the authoritative dependency list.
- API root `/` intentionally returns `404` (use `/docs` and `/health`).

## Submission Packaging
Create a submission archive while excluding unsafe/non-portable files:

```bash
bash scripts/make_submission_zip.sh
```

Manual equivalent:

```bash
zip -r submission.zip . \
  -x ".git/*" ".venv/*" "*/.venv/*" "secure-api-capstone/.venv/*" \
  -x "__pycache__/*" "*/__pycache__/*" "*.pyc" \
  -x ".pytest_cache/*" ".ruff_cache/*" ".coverage" \
  -x ".env" "app.db" "test_app.db" \
  -x "results/*.csv" "results/*.log"
```
