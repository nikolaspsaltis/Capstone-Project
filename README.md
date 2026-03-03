# CAPSTONE-PROJECT

FastAPI security capstone API with:
- JWT access + refresh token flow
- API key authentication
- RBAC (admin vs user)
- account lockout + DB-backed rate limiting
- auth failure logging
- refresh token revocation/rotation
- one-time password reset tokens
- optional admin MFA/TOTP
- DB-backed API key metadata and rotation
- request IDs + structured JSON request logs
- liveness/readiness split (`/healthz`, `/readyz`)
- basic auth security metrics (`/metrics`)

## Quick Start

From project root:

```bash
cd "/home/nicholas/Documents/UoE Documents/Captone-Project"
```

Use the project venv (recommended):

```bash
source secure-api-capstone/.venv/bin/activate
```

If that venv does not exist:

```bash
python3 -m venv secure-api-capstone/.venv
source secure-api-capstone/.venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Configure environment variables:

```bash
cp .env.example .env
set -a
. ./.env
set +a
```

Run the API:

```bash
alembic upgrade head
uvicorn app.main:app --reload
```

## Environment Variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `JWT_SECRET` | Yes | none | Signing secret for JWT tokens |
| `JWT_BACKEND` | No | `python-jose` | JWT backend selector (`python-jose` or `pyjwt`) |
| `JWT_ALGORITHM` | No | `HS256` | JWT algorithm |
| `JWT_EXPIRE_MINUTES` | No | `30` | Access token expiry |
| `JWT_REFRESH_EXPIRE_MINUTES` | No | `10080` | Refresh token expiry |
| `PASSWORD_RESET_TOKEN_EXPIRE_MINUTES` | No | `15` | Password reset token expiry |
| `JWT_ISSUER` | No | `capstone-project` | Expected `iss` claim |
| `JWT_AUDIENCE` | No | `capstone-client` | Expected `aud` claim |
| `DATABASE_URL` | No | `sqlite:///./app.db` | SQLAlchemy DB URL |
| `API_KEYS` | No | `capstone-demo-key` | Comma-separated API keys |
| `MAX_LOGIN_ATTEMPTS` | No | `5` | Failed attempts before lockout |
| `LOCKOUT_MINUTES` | No | `15` | Lockout duration |
| `RATE_LIMIT_WINDOW_SECONDS` | No | `60` | Login rate limit window |
| `RATE_LIMIT_MAX_ATTEMPTS` | No | `10` | Max login attempts per IP per window |
| `AUTH_FAILURE_LOG_RETENTION_DAYS` | No | `30` | Retention window for auth failure logs |
| `LOGIN_ATTEMPT_RETENTION_DAYS` | No | `7` | Retention window for login-attempt records |
| `CLEANUP_INTERVAL_MINUTES` | No | `60` | Minimum interval for automatic cleanup runs |

## API Smoke Test (Copy/Paste)

```bash
BASE_URL="http://127.0.0.1:8000"

curl -s "$BASE_URL/health"
curl -s "$BASE_URL/healthz"
curl -s "$BASE_URL/readyz"
curl -s "$BASE_URL/metrics"

curl -s -X POST "$BASE_URL/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123"}'

LOGIN_JSON=$(curl -s -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123"}')

ACCESS_TOKEN=$(printf '%s' "$LOGIN_JSON" | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
REFRESH_TOKEN=$(printf '%s' "$LOGIN_JSON" | python -c 'import sys,json; print(json.load(sys.stdin)["refresh_token"])')

curl -s "$BASE_URL/profile" -H "Authorization: Bearer $ACCESS_TOKEN"
curl -s "$BASE_URL/data" -H "X-API-Key: capstone-demo-key"

curl -s -X POST "$BASE_URL/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"

# Password reset (demo flow; token returned directly)
RESET_TOKEN=$(curl -s -X POST "$BASE_URL/password-reset/request" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice"}' \
  | python -c 'import sys,json; print(json.load(sys.stdin).get("reset_token",""))')

curl -s -X POST "$BASE_URL/password-reset/confirm" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$RESET_TOKEN\",\"new_password\":\"newsecret123\"}"
```

## Admin Security Operations

Admin-only endpoints:

- `GET /admin/users`
- `POST /admin/users/{username}/unlock`
- `GET /admin/auth-failures?page=1&page_size=50&username=&ip_address=&reason=`
- `GET /admin/audit-logs?page=1&page_size=50&actor_username=&actor_role=&action=&status=&target_username=`
- `GET /admin/security-alerts?window_minutes=60&min_failed_logins=5&min_admin_denials=3`
- `POST /admin/users/{username}/revoke-refresh-tokens`
- `POST /admin/maintenance/cleanup`
- `POST /admin/mfa/setup`
- `POST /admin/mfa/enable`
- `POST /admin/mfa/disable`
- `GET /admin/api-keys`
- `POST /admin/api-keys`
- `POST /admin/api-keys/{key_id}/rotate`
- `POST /admin/api-keys/{key_id}/revoke`

Example admin flow:

```bash
BASE_URL="http://127.0.0.1:8000"

curl -s -X POST "$BASE_URL/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin1","password":"adminpass","role":"admin"}'

ADMIN_ACCESS=$(curl -s -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin1","password":"adminpass"}' \
  | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -s "$BASE_URL/admin/users" \
  -H "Authorization: Bearer $ADMIN_ACCESS"

curl -s -X POST "$BASE_URL/admin/users/alice/unlock" \
  -H "Authorization: Bearer $ADMIN_ACCESS"

curl -s "$BASE_URL/admin/auth-failures?page=1&page_size=20&username=alice" \
  -H "Authorization: Bearer $ADMIN_ACCESS"

curl -s "$BASE_URL/admin/audit-logs?page=1&page_size=20&action=login&status=success" \
  -H "Authorization: Bearer $ADMIN_ACCESS"

curl -s -X POST "$BASE_URL/admin/users/alice/revoke-refresh-tokens" \
  -H "Authorization: Bearer $ADMIN_ACCESS"

curl -s -X POST "$BASE_URL/admin/maintenance/cleanup" \
  -H "Authorization: Bearer $ADMIN_ACCESS"

NEW_API_KEY=$(curl -s -X POST "$BASE_URL/admin/api-keys" \
  -H "Authorization: Bearer $ADMIN_ACCESS" \
  -H "Content-Type: application/json" \
  -d '{"name":"integration-key","scopes":["data:read","metrics:read"]}' \
  | python -c 'import sys,json; print(json.load(sys.stdin)["api_key"])')

curl -s "$BASE_URL/data" -H "X-API-Key: $NEW_API_KEY"

curl -s "$BASE_URL/admin/security-alerts?window_minutes=60&min_failed_logins=3" \
  -H "Authorization: Bearer $ADMIN_ACCESS"
```

## Development Commands

Lint/format/test:

```bash
python -m ruff check .
python -m black --check --quiet .
python -m pytest
```

Coverage gate is currently set to `85%` (`--cov-fail-under=85`) and should be
raised to `90%` once the next set of endpoint and CI smoke tests are stable.

Targeted strategy checks:

```bash
python -m pytest tests/test_admin_auth_depth_endpoints.py
python -m pytest tests/test_migrations.py
```

## Python 3.13 Readiness Plan

Current warnings come from dependency internals, not failing behavior:

- `fastapi` startup hook deprecation:
  - Status: addressed by migrating app startup to FastAPI lifespan in `app/main.py`.
- Password hashing:
  - Status: migrated to direct `bcrypt` only; `passlib` removed from runtime path.
- JWT migration layer:
  - Status: app now uses `app/jwt_backend.py` abstraction.
  - Current default: `JWT_BACKEND=python-jose`.
  - Migration path: set `JWT_BACKEND=pyjwt` in environment to test/roll over backend without endpoint changes.

Observability checks:

```bash
curl -i http://127.0.0.1:8000/healthz
curl -i http://127.0.0.1:8000/readyz
curl -i http://127.0.0.1:8000/metrics
```

`/metrics` now includes enriched counters for:
- HTTP request totals and error class counts
- login success/failure and lockout/rate-limit events
- JWT/API-key authentication successes
- admin access granted/denied counts
- total audit events written
- active JWT backend label (`jwt_backend`)

Migrations:

```bash
alembic upgrade head
```

Note: the app now relies on Alembic-managed schema and will fail startup if required
tables are missing.

## Scripts

- `scripts/bruteforce_login.py`
- `scripts/token_tampering.py`
- `scripts/unauthorized_admin_access.py`
- `scripts/performance_test.py`
- `scripts/run_capstone_evaluation.py`
- `scripts/create_release_tag.sh`

Reproducible capstone evidence run (writes timestamped artifacts to `results/`):

```bash
python scripts/run_capstone_evaluation.py
```

## Release

Create and push a release tag:

```bash
./scripts/create_release_tag.sh v0.3.0
```

Pushing a `v*.*.*` tag triggers the GitHub Release workflow.

## Troubleshooting

- If `ruff`, `black`, or `pytest` is "not found", activate `secure-api-capstone/.venv` first.
- If app startup fails with `JWT_SECRET must be set`, load `.env` before running `uvicorn`.
- If a refresh token stops working after admin revoke, that is expected behavior.
