#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

find_bin() {
  local name="$1"
  if [[ -x "$ROOT_DIR/.venv/bin/$name" ]]; then
    echo "$ROOT_DIR/.venv/bin/$name"
    return 0
  fi
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return 0
  fi
  return 1
}

print_summary() {
  local overall="$1"
  echo
  echo "==== QA Summary ===="
  echo "PASS: $PASS_COUNT"
  echo "FAIL: $FAIL_COUNT"
  echo "SKIP: $SKIP_COUNT"
  echo "RESULT: $overall"
}

run_required_step() {
  local label="$1"
  shift
  echo "==> $label"
  if "$@"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "[PASS] $label"
  else
    local code=$?
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "[FAIL] $label (exit code: $code)"
    print_summary "FAIL"
    exit "$code"
  fi
}

run_optional_step() {
  local label="$1"
  shift
  echo "==> $label"
  if "$@"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "[PASS] $label"
  else
    local code=$?
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "[FAIL] $label (exit code: $code)"
    print_summary "FAIL"
    exit "$code"
  fi
}

RUFF_BIN="$(find_bin ruff || true)"
PYTEST_BIN="$(find_bin pytest || true)"

if [[ -z "$RUFF_BIN" ]]; then
  echo "[FAIL] Could not find ruff (looked in .venv/bin and PATH)."
  print_summary "FAIL"
  exit 127
fi

if [[ -z "$PYTEST_BIN" ]]; then
  echo "[FAIL] Could not find pytest (looked in .venv/bin and PATH)."
  print_summary "FAIL"
  exit 127
fi

run_required_step "ruff check ." "$RUFF_BIN" check .
PYTEST_ARGS=(-q --ignore=.venv --ignore=secure-api-capstone/.venv)
if [[ -n "${QA_PYTEST_ARGS:-}" ]]; then
  # shellcheck disable=SC2206
  PYTEST_ARGS=(${QA_PYTEST_ARGS})
fi

PYTEST_TIMEOUT_SECONDS="${QA_PYTEST_TIMEOUT_SECONDS:-300}"
if command -v timeout >/dev/null 2>&1 \
  && [[ "$PYTEST_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] \
  && [[ "$PYTEST_TIMEOUT_SECONDS" -gt 0 ]]; then
  run_required_step \
    "pytest -q" \
    timeout \
    "$PYTEST_TIMEOUT_SECONDS" \
    "$PYTEST_BIN" \
    "${PYTEST_ARGS[@]}"
else
  run_required_step "pytest -q" "$PYTEST_BIN" "${PYTEST_ARGS[@]}"
fi

if [[ "${QA_FORMAT_CHECK:-0}" == "1" ]]; then
  run_optional_step "ruff format --check ." "$RUFF_BIN" format --check .
else
  SKIP_COUNT=$((SKIP_COUNT + 1))
  echo "[SKIP] ruff format --check . (set QA_FORMAT_CHECK=1 to enable)"
fi

if [[ "${QA_SMOKE:-0}" == "1" ]]; then
  UVICORN_BIN="$(find_bin uvicorn || true)"
  ALEMBIC_BIN="$(find_bin alembic || true)"
  if [[ -z "$UVICORN_BIN" || -z "$ALEMBIC_BIN" ]]; then
    echo "[FAIL] QA_SMOKE=1 requires uvicorn and alembic in .venv/bin or PATH."
    print_summary "FAIL"
    exit 127
  fi

  if [[ -f ".env" ]]; then
    set -a
    # shellcheck disable=SC1091
    . ".env"
    set +a
  fi

  if [[ -z "${JWT_SECRET:-}" || -z "${API_KEYS:-}" ]]; then
    echo "[FAIL] QA_SMOKE=1 requires JWT_SECRET and API_KEYS (export or set in .env)."
    print_summary "FAIL"
    exit 2
  fi

  run_optional_step "alembic upgrade head (smoke prep)" "$ALEMBIC_BIN" upgrade head

  SMOKE_PORT="${QA_SMOKE_PORT:-8010}"
  SMOKE_URL="http://127.0.0.1:${SMOKE_PORT}/health"
  UVICORN_LOG="$(mktemp)"
  UVICORN_PID=""

  cleanup_smoke() {
    if [[ -n "$UVICORN_PID" ]]; then
      kill "$UVICORN_PID" >/dev/null 2>&1 || true
      wait "$UVICORN_PID" >/dev/null 2>&1 || true
    fi
    rm -f "$UVICORN_LOG"
  }
  trap cleanup_smoke EXIT

  echo "==> smoke test (/health via uvicorn on port ${SMOKE_PORT})"
  "$UVICORN_BIN" app.main:app --host 127.0.0.1 --port "$SMOKE_PORT" >"$UVICORN_LOG" 2>&1 &
  UVICORN_PID="$!"

  HEALTH_OK=0
  for _ in $(seq 1 30); do
    if curl -fsS "$SMOKE_URL" >/dev/null 2>&1; then
      HEALTH_OK=1
      break
    fi
    sleep 0.5
  done

  if [[ "$HEALTH_OK" -ne 1 ]]; then
    echo "[FAIL] smoke test (/health) did not become ready."
    echo "----- uvicorn log -----"
    sed -n '1,80p' "$UVICORN_LOG"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    print_summary "FAIL"
    exit 1
  fi

  PASS_COUNT=$((PASS_COUNT + 1))
  echo "[PASS] smoke test (/health)"
  cleanup_smoke
  trap - EXIT
else
  SKIP_COUNT=$((SKIP_COUNT + 1))
  echo "[SKIP] smoke test (set QA_SMOKE=1 to enable)"
fi

print_summary "PASS"
