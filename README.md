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
- Controlled admin bootstrap script (`scripts/seed_admin.py`)
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

## 4) Fresh Setup (from zero)
From repository root:

```bash
cd "/home/nikolas/Documents/UoE Documents/Captone-Project"
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Set required values in `.env`:
- `JWT_SECRET`: required, must be a strong non-placeholder value
- `API_KEYS`: required, must be one or more strong non-placeholder values (comma-separated)
- `DATABASE_URL`: defaults to `sqlite:///./app.db` if not changed

Commonly used optional values:
- `JWT_BACKEND` (`python-jose` by default)
- `JWT_EXPIRE_MINUTES`, `JWT_REFRESH_EXPIRE_MINUTES`
- `MAX_LOGIN_ATTEMPTS`, `LOCKOUT_MINUTES`
- `RATE_LIMIT_WINDOW_SECONDS`, `RATE_LIMIT_MAX_ATTEMPTS`
- `ALLOWED_ORIGINS` (comma-separated origins for browser CORS access, for example `http://localhost:3000,http://127.0.0.1:3000`)
- `ADMIN_USERNAME`, `ADMIN_PASSWORD` (used by `scripts/seed_admin.py`)

Startup hardening note:
- The app intentionally fails fast if `JWT_SECRET` or `API_KEYS` is missing, empty, or left on placeholder/demo values.

Load `.env` into current shell, migrate schema, run app:

```bash
set -a
. ./.env
set +a
alembic upgrade head
uvicorn app.main:app --reload
```

Create or promote an admin account through the controlled seed script:

```bash
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="adminpass123"
python scripts/seed_admin.py
```

Password hashing compatibility note:
- `passlib==1.7.4`
- `bcrypt==4.0.1`

This pinned pair avoids known passlib/bcrypt runtime incompatibility seen with newer bcrypt builds.

## 5) Quick Verification
Run these in a second terminal while the server is running.

```bash
source .venv/bin/activate
set -a
. ./.env
set +a
BASE_URL="http://127.0.0.1:8000"
```

Expected status behavior:
- `400`: invalid request or validation errors
- `401`: invalid credentials/token or missing auth
- `403`: authenticated but forbidden (for example non-admin on admin routes, account lockout)
- `429`: login rate limit triggered (`Retry-After` header included)

| Endpoint | Expected statuses | Notes |
|---|---|---|
| `GET /health` | `200` | Liveness check |
| `POST /register` | `201`, `400`, `409*` | `201` created; `400` validation/duplicate in current tests; `409` conflict can be used by alternate duplicate-handling policy |
| `POST /login` | `200`, `401`, `429` | `429` when login rate limit triggers |
| `GET /profile` | `200`, `401` | `401` for missing/invalid bearer token |
| `GET /data` | `200`, `401`, `429**` | `200` with JWT or API key; `401` without valid auth; `429` optional if additional data-route throttling is enabled |
| `GET /admin/users` | `200`, `401`, `403` | `401` unauthenticated, `403` authenticated non-admin |

\* Current code/tests use `400` for duplicate username on `/register`.
\** Current code applies rate limiting to `/login`; `/data` normally returns `200` or `401`.

1. GET `/health`

```bash
curl -i "$BASE_URL/health"
```

2. POST `/register` (normal user)

```bash
USER_NAME="user_$(date +%s)"
USER_PASS="secret123"
curl -i -X POST "$BASE_URL/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USER_NAME\",\"password\":\"$USER_PASS\"}"
```

3. POST `/login` and capture JWT

```bash
LOGIN_JSON=$(curl -s -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USER_NAME\",\"password\":\"$USER_PASS\"}")
ACCESS_TOKEN=$(printf '%s' "$LOGIN_JSON" | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
echo "$LOGIN_JSON"
```

4. GET `/profile` with Bearer token

```bash
curl -i "$BASE_URL/profile" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

5. GET `/data` with JWT

```bash
curl -i "$BASE_URL/data" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

6. GET `/data` with `X-API-Key` (must be from your configured `API_KEYS`)

```bash
API_KEY_FIRST=$(printf '%s' "$API_KEYS" | cut -d',' -f1)
curl -i "$BASE_URL/data" \
  -H "X-API-Key: $API_KEY_FIRST"
```

7. GET `/admin/users` as user vs admin

```bash
# Expect 403 with non-admin token
curl -i "$BASE_URL/admin/users" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Create or promote admin via seed script, then login
ADMIN_NAME="admin_$(date +%s)"
ADMIN_PASS="adminpass123"
export ADMIN_USERNAME="$ADMIN_NAME"
export ADMIN_PASSWORD="$ADMIN_PASS"
python scripts/seed_admin.py
ADMIN_LOGIN=$(curl -s -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$ADMIN_NAME\",\"password\":\"$ADMIN_PASS\"}")
ADMIN_TOKEN=$(printf '%s' "$ADMIN_LOGIN" | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

# Expect 200 with admin token
curl -i "$BASE_URL/admin/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## 6) Running Scripts
Run with server active:

```bash
BASE_URL="http://127.0.0.1:8000"
API_KEY_FIRST=$(printf '%s' "$API_KEYS" | cut -d',' -f1)

# Brute force / defense check (expects lockout or rate-limit by default)
python scripts/bruteforce_login.py \
  --base-url "$BASE_URL" \
  --attempts 12 \
  --rate 20 \
  --output "results/bruteforce_attempts.csv"

# Token tampering check (expects 401 by default)
python scripts/token_tampering.py \
  --base-url "$BASE_URL"

# RBAC check for non-admin user (expects 403 by default)
python scripts/unauthorized_admin_access.py \
  --base-url "$BASE_URL"

# Performance CSV (health endpoint by default)
python scripts/performance_test.py \
  --base-url "$BASE_URL" \
  --attempts 100 \
  --output "results/performance_manual.csv"

# Optional: benchmark API-key authenticated /data endpoint
python scripts/performance_test.py \
  --base-url "$BASE_URL" \
  --endpoint "/data" \
  --api-key "$API_KEY_FIRST" \
  --attempts 50 \
  --output "results/performance_data_apikey.csv"

python scripts/seed_admin.py  # requires ADMIN_USERNAME and ADMIN_PASSWORD
```

Optional full evaluation runner:

```bash
python scripts/run_capstone_evaluation.py
```

## 7) Automated Tests

Deterministic local test commands:

```bash
source .venv/bin/activate
pytest -q
pytest -vv
```

Expected runtime:
- With the test harness (`tests/conftest.py`) forcing `TESTING=1` and low bcrypt rounds,
  the full suite should typically finish in under 30 seconds on a normal laptop.

## 8) One-Command QA
Run the full grader-friendly QA sequence:

```bash
bash scripts/check_all.sh
```

What it runs, in order:
- `ruff check .`
- `pytest -q`
- optional `ruff format --check .` when `QA_FORMAT_CHECK=1`
- optional smoke test (`uvicorn` + `GET /health`) when `QA_SMOKE=1`

Useful variants:

```bash
QA_FORMAT_CHECK=1 bash scripts/check_all.sh
QA_FORMAT_CHECK=1 QA_SMOKE=1 bash scripts/check_all.sh
QA_PYTEST_TIMEOUT_SECONDS=600 bash scripts/check_all.sh
QA_PYTEST_ARGS="-q --no-cov tests/test_auth.py::test_api_keys_loader_requires_explicit_value" bash scripts/check_all.sh
```

The script prints a PASS/FAIL/SKIP summary and exits non-zero on failure.

## 9) Results
For full artifact documentation and regeneration commands, see
[docs/results.md](docs/results.md).

Artifacts are written to `results/`.

Typical outputs:
- `performance_*.csv`: per-request latency samples from performance test script
- `bruteforce_attempts*.csv`: brute-force attempt status traces (optional)
- `evaluation_report_*.md`: human-readable summary of multi-script evaluation
- `evaluation_summary_*.json`: machine-readable summary (script exit codes and log paths)
- `*_*.log`: raw script logs (stdout/stderr)
- `graph_*.png`: generated analysis/figure outputs

How generated:
- `python scripts/performance_test.py --base-url "$BASE_URL" --output "results/<name>.csv"` -> performance CSV
- `python scripts/bruteforce_login.py --base-url "$BASE_URL" --output "results/<name>.csv"` -> optional brute-force CSV
- `python scripts/run_capstone_evaluation.py` -> report + summary + script logs
- `python scripts/plot_evaluation_diagnostics.py --summary <results/evaluation_summary_*.json>` -> diagnostics graph PNG

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
  -x ".git/*" ".venv/*" "*/.venv/*" \
  -x "__pycache__/*" "*/__pycache__/*" "*.pyc" \
  -x ".pytest_cache/*" ".ruff_cache/*" ".coverage" \
  -x ".env" "app.db" "test_app.db" \
  -x "results/*.csv" "results/*.log"
```
