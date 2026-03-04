# 3-Minute Capstone Demo Script

Use two terminals.

## Terminal A: Setup + Run API
```bash
cd "/home/nikolas/Documents/UoE Documents/Captone-Project"
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and set at least:
- `JWT_SECRET` to a strong non-placeholder value
- `API_KEYS` to one or more strong non-placeholder values (comma-separated)

Then run:
```bash
set -a
. ./.env
set +a

# Demo-only override so brute-force script visibly triggers lockout defense.
export MAX_LOGIN_ATTEMPTS=3

alembic upgrade head
uvicorn app.main:app --reload
```

## Terminal B: Functional + Security Demo
```bash
cd "/home/nikolas/Documents/UoE Documents/Captone-Project"
source .venv/bin/activate
set -a
. ./.env
set +a

BASE_URL="http://127.0.0.1:8000"
```

### 1) Health check
```bash
curl -i "$BASE_URL/health"
```

### 2) Register and login (capture JWT)
```bash
USER_NAME="demo_user_$(date +%s)"
USER_PASS="secret123"

curl -i -X POST "$BASE_URL/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USER_NAME\",\"password\":\"$USER_PASS\"}"

LOGIN_JSON=$(curl -s -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USER_NAME\",\"password\":\"$USER_PASS\"}")
ACCESS_TOKEN=$(printf '%s' "$LOGIN_JSON" | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
echo "$LOGIN_JSON"
```

### 3) Protected profile with Bearer token
```bash
curl -i "$BASE_URL/profile" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

### 4) `/data` via API key auth
```bash
API_KEY_FIRST=$(printf '%s' "$API_KEYS" | cut -d',' -f1)
curl -i "$BASE_URL/data" \
  -H "X-API-Key: $API_KEY_FIRST"
```

### 5) RBAC demo (`/admin/users`)
Non-admin should be denied (403):
```bash
curl -i "$BASE_URL/admin/users" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

Create admin, login, and access should succeed (200):
```bash
ADMIN_NAME="demo_admin_$(date +%s)"
ADMIN_PASS="adminpass123"

export ADMIN_USERNAME="$ADMIN_NAME"
export ADMIN_PASSWORD="$ADMIN_PASS"
python scripts/seed_admin.py

ADMIN_LOGIN=$(curl -s -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$ADMIN_NAME\",\"password\":\"$ADMIN_PASS\"}")
ADMIN_TOKEN=$(printf '%s' "$ADMIN_LOGIN" | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -i "$BASE_URL/admin/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### 6) Attack script + defense trigger
Run one attack script:
```bash
python scripts/bruteforce_login.py
```

Expected: by attempt 3 or 4 you should see `403` responses, showing lockout defense after repeated failed logins.

## Results talking points (30 seconds)
- CSV example: `results/performance_20260304_154048.csv`
  - Per-request latency samples from the performance test (`latency_ms`) used to derive throughput and response-time behavior.
- Graph example: `results/graph_report_combined_2x2_20260302_182627.png`
  - Combined report-ready figure summarizing security script outcomes and performance trends for evaluation discussion.

If you regenerate artifacts, filenames will include new timestamps:
```bash
python scripts/performance_test.py
python scripts/run_capstone_evaluation.py
ls -lt results/
```
