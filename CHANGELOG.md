# Changelog

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
