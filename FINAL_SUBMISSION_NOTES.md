# Final Submission Notes

## Snapshot
- Branch: `main`
- Target release tag: `v0.6.0`
- Scope includes audit logging, admin audit endpoint, enriched metrics, migrations, tests, and report artifacts.

## Reproducibility
1. `python -m venv .venv`
2. `source .venv/bin/activate`
3. `pip install -r requirements.txt`
4. `set -a; . ./.env; set +a`
5. `alembic upgrade head`
6. `pytest -q`
7. `ruff check .`
8. `black --check --quiet .`

## Evidence Artifacts (results/)
- `evaluation_report_20260304_154048.md`
- `evaluation_summary_20260304_154048.json`
- `performance_20260304_154048.csv` (from full evaluation runner)
- `graph_evaluation_diagnostics_20260304_154048.png`
- `graph_report_combined_2x2_20260302_182627.png` (archived report figure)

## Notes
- Root path `/` intentionally returns `404` (no root endpoint defined).
- Password hashing runtime uses `passlib` + `bcrypt` (`passlib==1.7.4`, `bcrypt==4.0.1`) with a direct `bcrypt` fallback path in code.
- `JWT_BACKEND=python-jose` is the active default backend unless changed.
