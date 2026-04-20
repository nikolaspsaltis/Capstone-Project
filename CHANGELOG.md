# Changelog

## v0.8.0 - 2026-04-15
- Added Docker Compose two-service deployment (`api` + `downstream-service` stub).
- Added `Dockerfile` for the API service; added `downstream-service/` with audience-enforcing FastAPI stub.
- Added supply chain attack framing to report Introduction and Section 6.4, explicitly naming persistent-credential supply chain attacks and the workload identity mitigation.
- Fixed `scripts/demo_service_to_service.py`: introduced `DEMO_AUDIENCE` constant, added `_seed_service_registry()` step 0 so no manual pre-setup is required, added early-exit on exchange failure with error text.
- Fixed `scripts/run_capstone_evaluation.py`: added `_seed_eval_fixtures()` called before attack scenarios, registering test accounts and `eval-worker` in the service registry so ATTACK-3 executes instead of always emitting `[SKIP]`.
- Added source-level documentation (present-simple-tense docstrings) across all `app/` modules: `main.py`, `auth.py`, `security.py`, `jwt_backend.py`, `models.py`, `database.py`, `policy.py`, `workload_identity.py`, `broker.py`, `jwks.py`.
- Fixed ruff E401/I001 import style in `downstream-service/main.py`.

## v0.7.0 - 2026-04-09
- Added Ed25519 asymmetric JWT signing for access tokens using the `cryptography` library directly (python-jose 3.3.0 lacks EdDSA support); refresh tokens retain HS256 via python-jose.
- Added JWKS endpoint (`GET /auth/jwks.json`) publishing the server's OKP/Ed25519 public key in RFC 8037 format with `kty=OKP`, `crv=Ed25519`, `kid` fingerprint, `use=sig`, `alg=EdDSA`.
- Added workload SVID issuance endpoint (`POST /workload/identity/issue`): HMAC-SHA256 attestation with configurable minute-window replay tolerance; issued SVIDs scoped to `aud=trust-broker`.
- Added token-exchange broker (`POST /token/exchange`): three-layer authorisation (token validity + near-expiry guard, service registry + `allowed_callers`, policy engine evaluation); issues narrow audience-scoped tokens with `scope=service:call` and `orig_jti` back-reference.
- Added file-driven YAML policy engine (`app/policy.py`): deny-by-first-match semantics, six condition types (`role`, `method`, `path_prefix`, `utc_hour_range`, `token_env`, `target_audience_prefix`), SIGHUP hot-reload, documented OPA migration path.
- Added service registry admin endpoints (`GET/POST /admin/service-registry`) and policy rules admin endpoint (`GET /admin/policy/rules`).
- Added Alembic migration `0006_hash_chain_audit_log` (adds `prev_hash`, `record_hash` columns to `audit_logs`).
- Added Alembic migration `0007_service_registry` (adds `service_registry` table).
- Added test modules: `test_token_exchange.py`, `test_workload_identity.py`, `test_policy.py`.
- Added three attack scenarios to `run_capstone_evaluation.py`: ATTACK-1 (JTI token replay → 401), ATTACK-2 (audience mismatch → 401), ATTACK-3 (dev SVID targeting prod audience → 403 via policy).
- Added in-memory JTI replay cache (`_replay_cache` in `jwt_backend.py`) for single-use enforcement on scoped tokens.

## v0.6.0 - 2026-02-27
- Added dedicated admin auth-depth endpoint tests in
  `tests/test_admin_auth_depth_endpoints.py`.
- Added Alembic migration lifecycle tests (upgrade/downgrade/re-upgrade) in
  `tests/test_migrations.py`.
- Added CI smoke regression step for:
  `scripts/bruteforce_login.py`,
  `scripts/token_tampering.py`,
  `scripts/unauthorized_admin_access.py`,
  `scripts/performance_test.py`.
- Raised coverage gate from 80% to 85% (`--cov-fail-under=85`) with staged
  target to move to 90%.

## v0.5.0 - 2026-02-27
- Added password reset request/confirm flow with one-time reset tokens.
- Added optional admin MFA/TOTP setup, enable, disable, and enforced MFA on admin login.
- Added DB-backed API key management endpoints for listing, creation, rotation, and revocation.
- Added migration `0003_auth_depth_features` for MFA fields and new auth tables.
- Added tests for password reset, MFA, and API key lifecycle behavior.

## v0.4.0 - 2026-02-27
- Removed runtime schema auto-creation/mutation from app startup.
- Added startup schema validation that requires Alembic-managed tables.
- Added DB cleanup jobs for:
  - expired revoked tokens
  - stale auth failure logs
  - stale login-attempt records
- Added admin trigger endpoint: `POST /admin/maintenance/cleanup`.
- Extended `GET /admin/auth-failures` with pagination and filters
  (`page`, `page_size`, `username`, `ip_address`, `reason`).
- Added/updated tests for new admin hardening behavior.

## v0.3.0 - 2026-02-27
- Added admin endpoint to unlock users: `POST /admin/users/{username}/unlock`.
- Added admin endpoint to inspect auth failures: `GET /admin/auth-failures`.
- Added admin endpoint to revoke all refresh tokens for a user by rotating
  `refresh_token_version`: `POST /admin/users/{username}/revoke-refresh-tokens`.
- Added Alembic migration `0002_add_refresh_token_version`.
- Added new tests in `tests/test_admin_security_ops.py` for all admin security operations.

## v0.2.0 - 2026-02-27
- Added JWT issuer/audience/jti claims validation.
- Added refresh token rotation and logout revocation.
- Added database-backed login rate limiting and auth failure logs.
- Added pytest test suite with coverage threshold.
- Added Alembic migration scaffolding and initial revision.
- Added CI quality gates for ruff, black, and pytest.
