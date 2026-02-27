# CAPSTONE-PROJECT

FastAPI security capstone app with JWT auth, API key auth, RBAC, and basic login defenses.

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
4. Set environment variables (minimum required):
   ```bash
   export JWT_SECRET="replace-with-a-long-random-secret"
   ```
   Or copy `.env.example` and export values from there.
5. Run the API:
   ```bash
   uvicorn app.main:app --reload
   ```

## Quick Test (curl)

### 1) Health
```bash
curl -X GET http://127.0.0.1:8000/health
```
Expected:
```json
{"status":"ok"}
```

### 2) Register
```bash
curl -X POST http://127.0.0.1:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123"}'
```
Expected (first call):
```json
{"id":1,"username":"alice","role":"user"}
```

### 3) Login
```bash
curl -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123"}'
```
Expected:
```json
{"access_token":"<jwt>","token_type":"bearer"}
```

### 4) Profile (Bearer token)
```bash
curl -X GET http://127.0.0.1:8000/profile \
  -H "Authorization: Bearer <jwt>"
```
Expected:
```json
{"id":1,"username":"alice","role":"user"}
```

### 5) Data with API Key
```bash
curl -X GET http://127.0.0.1:8000/data \
  -H "X-API-Key: capstone-demo-key"
```
Expected:
```json
{"data":"Sensitive data payload"}
```

### 6) Data with JWT
```bash
curl -X GET http://127.0.0.1:8000/data \
  -H "Authorization: Bearer <jwt>"
```
Expected:
```json
{"data":"Sensitive data payload"}
```

### 7) Admin users (admin only)
```bash
curl -X GET http://127.0.0.1:8000/admin/users \
  -H "Authorization: Bearer <admin-jwt>"
```
Expected:
- admin token: list of users
- non-admin token: `{"detail":"Forbidden"}` with HTTP 403

## Scripts

- `scripts/bruteforce_login.py` - brute-force simulation against `/login`
- `scripts/token_tampering.py` - modifies JWT payload and checks token rejection
- `scripts/unauthorized_admin_access.py` - verifies non-admin cannot access `/admin/users`
- `scripts/performance_test.py` - measures latency + requests/sec and writes CSV to `results/`

Run examples:
```bash
python scripts/bruteforce_login.py
python scripts/token_tampering.py
python scripts/unauthorized_admin_access.py
python scripts/performance_test.py
```

## Tag + Release Flow

Create a semantic version tag for each milestone submission:

```bash
git tag -a v0.1.0 -m "Milestone 1"
git push origin v0.1.0
```

Pushing a `v*.*.*` tag triggers GitHub Actions to create a GitHub Release automatically.
