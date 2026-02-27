# Changelog

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
