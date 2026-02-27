# CAPSTONE-PROJECT

FastAPI security capstone API with:
- JWT access + refresh token flow
- API key authentication
- RBAC (admin vs user)
- account lockout + DB-backed rate limiting
- auth failure logging
- refresh token revocation/rotation

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
uvicorn app.main:app --reload
```

## Environment Variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `JWT_SECRET` | Yes | none | Signing secret for JWT tokens |
| `JWT_ALGORITHM` | No | `HS256` | JWT algorithm |
| `JWT_EXPIRE_MINUTES` | No | `30` | Access token expiry |
| `JWT_REFRESH_EXPIRE_MINUTES` | No | `10080` | Refresh token expiry |
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
```

## Admin Security Operations

Admin-only endpoints:

- `GET /admin/users`
- `POST /admin/users/{username}/unlock`
- `GET /admin/auth-failures?page=1&page_size=50&username=&ip_address=&reason=`
- `POST /admin/users/{username}/revoke-refresh-tokens`
- `POST /admin/maintenance/cleanup`

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

curl -s -X POST "$BASE_URL/admin/users/alice/revoke-refresh-tokens" \
  -H "Authorization: Bearer $ADMIN_ACCESS"

curl -s -X POST "$BASE_URL/admin/maintenance/cleanup" \
  -H "Authorization: Bearer $ADMIN_ACCESS"
```

## Development Commands

Lint/format/test:

```bash
python -m ruff check .
python -m black --check .
python -m pytest
```

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
- `scripts/create_release_tag.sh`

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
