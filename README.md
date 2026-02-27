# CAPSTONE-PROJECT

FastAPI security capstone app with JWT auth, API key auth, RBAC, refresh token rotation, and basic security defenses.

## Setup

1. Create virtual environment (if needed):
   ```bash
   python3 -m venv .venv
   ```
2. Activate virtual environment:
   ```bash
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Configure environment variables:
   ```bash
   cp .env.example .env
   export $(grep -v '^#' .env | xargs)
   ```
5. Run the API:
   ```bash
   uvicorn app.main:app --reload
   ```

## Core Endpoints

### Health
```bash
curl -X GET http://127.0.0.1:8000/health
```
Expected:
```json
{"status":"ok"}
```

### Register
```bash
curl -X POST http://127.0.0.1:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123"}'
```
Expected:
```json
{"id":1,"username":"alice","role":"user"}
```

### Login (access + refresh)
```bash
curl -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123"}'
```
Expected:
```json
{"access_token":"<jwt>","refresh_token":"<refresh>","token_type":"bearer"}
```

### Refresh
```bash
curl -X POST http://127.0.0.1:8000/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh>"}'
```
Expected:
```json
{"access_token":"<new-jwt>","refresh_token":"<new-refresh>","token_type":"bearer"}
```

### Logout (revoke refresh token)
```bash
curl -X POST http://127.0.0.1:8000/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh>"}'
```
Expected:
```json
{"status":"ok","message":"Refresh token revoked"}
```

### Profile (Bearer token)
```bash
curl -X GET http://127.0.0.1:8000/profile \
  -H "Authorization: Bearer <jwt>"
```
Expected:
```json
{"id":1,"username":"alice","role":"user"}
```

### Data with API Key
```bash
curl -X GET http://127.0.0.1:8000/data \
  -H "X-API-Key: capstone-demo-key"
```
Expected:
```json
{"data":"Sensitive data payload"}
```

### Admin users (admin only)
```bash
curl -X GET http://127.0.0.1:8000/admin/users \
  -H "Authorization: Bearer <admin-jwt>"
```
Expected:
- admin token: list of users
- non-admin token: `{"detail":"Forbidden"}` with HTTP 403

## Security Notes

- JWT includes `iss`, `aud`, and `jti` claims; tokens are validated against configured issuer/audience.
- Refresh tokens are rotated and revoked on use/logout.
- Login rate limits are persisted in DB (`login_attempts` table).
- Auth failures are logged to DB (`auth_failure_logs` table).
- API key rotation is supported via `API_KEYS` (comma-separated).

## Testing and Quality

Run checks locally:
```bash
ruff check .
black --check .
pytest
```

## Alembic Migrations

Create/upgrade schema with Alembic:
```bash
alembic upgrade head
```

## Scripts

- `scripts/bruteforce_login.py` - brute-force simulation against `/login`
- `scripts/token_tampering.py` - JWT tampering check
- `scripts/unauthorized_admin_access.py` - non-admin RBAC check
- `scripts/performance_test.py` - latency + requests/sec CSV output
- `scripts/create_release_tag.sh` - release tag helper

## Release Flow

```bash
./scripts/create_release_tag.sh v0.2.0
```

Pushing a `v*.*.*` tag triggers GitHub Actions release workflow.
