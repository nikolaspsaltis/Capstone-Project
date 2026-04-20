# Final Submission Notes

## Snapshot
- Branch: `main`
- Release tag: `v0.8.0`
- Scope: complete zero-trust REST API with Ed25519 JWT, workload identity, token-exchange broker, policy engine, JWKS, Docker deployment, and supply chain attack framing.

## Test Status
- **70 tests passed**, 0 failed
- **Coverage: 90.57%** (gate: 85%)
- Suite runtime: ~22 seconds (bcrypt rounds reduced to 4 in test mode)
- Lint: `ruff check .` — zero errors
- Format: `black --check --quiet .` — clean

## Reproducibility
1. `python -m venv .venv`
2. `source .venv/bin/activate`
3. `pip install -r requirements.txt`
4. `set -a; . ./.env; set +a`
5. `alembic upgrade head`
6. `pytest -q`
7. `ruff check .`
8. `black --check --quiet .`

## Docker (optional)
```bash
docker compose up --build
```
Starts `api` on port 8000 and `downstream-service` stub on port 8001. The downstream service enforces `SERVICE_AUDIENCE` on incoming tokens.

## Evidence Artifacts (results/)
- `evaluation_report_*.md` — timestamped zero-trust attack scenario report
- `evaluation_summary_*.json` — machine-readable summary
- `graph_evaluation_diagnostics_*.png` — performance and attack scenario visualisation
- `graph_report_combined_2x2_*.png` — combined performance report figure

## Notes
- Root path `/` intentionally returns `404` (no root endpoint defined).
- Access tokens use Ed25519 (via `cryptography` library directly — python-jose 3.3.0 lacks EdDSA). Refresh tokens use HS256 via python-jose.
- `JWT_BACKEND=python-jose` is the active default backend unless changed.
- Password hashing uses `passlib` + `bcrypt` (`passlib==1.7.4`, `bcrypt==4.0.1`) with a direct `bcrypt` fallback path.
- `WORKLOAD_ATTESTATION_SECRET` must be set in `.env` for the M2M zero-trust flow and CI zero-trust stage.
