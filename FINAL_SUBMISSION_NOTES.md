# Final Submission Notes

## Snapshot
- Branch: `main`
- Target release tag: `v0.4.0`
- Scope includes audit logging, admin audit endpoint, enriched metrics, migrations, tests, and report artifacts.

## Reproducibility
1. `set -a; . ./.env; set +a`
2. `secure-api-capstone/.venv/bin/alembic upgrade head`
3. `secure-api-capstone/.venv/bin/python -m pytest -q`
4. `secure-api-capstone/.venv/bin/python -m ruff check .`
5. `secure-api-capstone/.venv/bin/python -m black --check --quiet .`

## Evidence Artifacts (results/)
- `evaluation_report_20260302_182627.md`
- `evaluation_summary_20260302_182627.json`
- `performance_20260302_182451.csv`
- `graph_report_combined_2x2_20260302_182627.png`
- Supporting logs and component graphs from the same run timestamp set.

## Notes
- Root path `/` intentionally returns `404` (no root endpoint defined).
- Remaining warnings are dependency deprecations (`passlib`/`python-jose`) and do not fail checks.
