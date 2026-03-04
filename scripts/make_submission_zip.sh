#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

rm -f submission.zip

zip -r submission.zip . \
  -x ".git/*" \
  -x ".venv/*" \
  -x "*/.venv/*" \
  -x "secure-api-capstone/.venv/*" \
  -x "__pycache__/*" \
  -x "*/__pycache__/*" \
  -x "*.pyc" \
  -x ".pytest_cache/*" \
  -x ".ruff_cache/*" \
  -x ".coverage" \
  -x ".env" \
  -x "app.db" \
  -x "test_app.db" \
  -x "results/*.csv" \
  -x "results/*.log" \
  -x "submission.zip"

echo "Created submission.zip"
