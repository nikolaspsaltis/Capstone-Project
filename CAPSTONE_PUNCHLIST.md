# Capstone Readiness Punchlist

Audit date: 2026-03-04

Scope checked: security correctness, reproducibility, documentation consistency, and repository hygiene.

## Must Fix (submission blockers)

1. Self-service admin privilege escalation in registration
- Files: `app/main.py`, `README.md`, `DEMO.md`
- Evidence: `register()` currently accepts `role="admin"` from public input (`app/main.py:521`), so any user can create an admin account.
- Fix plan: Restrict `/register` to always create `role="user"` and move admin creation to a controlled path (seed script/manual DB command/admin-only endpoint). Update docs/demo commands to stop using public admin registration.

2. Quality gate fails on lint
- Files: `scripts/plot_evaluation_diagnostics.py`
- Evidence: `ruff check .` reports `E501` at `scripts/plot_evaluation_diagnostics.py:98`.
- Fix plan: Wrap the long `ArgumentParser` line and re-run `ruff check .` to restore a clean lint pass for submission evidence.

3. Test run stability is not reliable
- Files: `tests/conftest.py`, `app/auth.py`, `README.md`
- Evidence: `timeout 90 .venv/bin/python -m pytest -vv` stalled on the first test (`tests/test_admin_auth_depth_endpoints.py::test_non_admin_forbidden_on_new_admin_endpoints[...]`) and timed out.
- Fix plan: Reduce password-hash cost in tests (test-only hash rounds/context) and document a deterministic test command with expected runtime. Re-run full `pytest -q` and capture a successful output log for submission appendix.

4. Predictable default API key weakens secure-by-default posture
- Files: `app/auth.py`, `.env.example`, `README.md`
- Evidence: `API_KEYS` falls back to `"capstone-demo-key"` in code (`app/auth.py:56`), which is guessable if env setup is missed.
- Fix plan: Fail fast when `API_KEYS` is empty (or disable API-key auth until configured) and keep only explicit keys in `.env`. Document this clearly in setup steps.

## Should Fix (marks boosters)

1. Use standard rate-limit status code
- Files: `app/security.py`, tests covering login defense behavior
- Evidence: rate limit currently raises `403` (`app/security.py:155`), where `429 Too Many Requests` is the standard for throttling.
- Fix plan: Return `429` plus optional `Retry-After` header, then update tests/docs so behavior is clear and standards-aligned.

2. Make scripts configurable for reproducible marking
- Files: `scripts/bruteforce_login.py`, `scripts/token_tampering.py`, `scripts/unauthorized_admin_access.py`, `scripts/performance_test.py`, `README.md`, `docs/results.md`
- Evidence: scripts hardcode `BASE_URL` and other inputs (for example `scripts/bruteforce_login.py:6`, `scripts/performance_test.py:8`).
- Fix plan: Add `argparse` (or env overrides) for `--base-url` and key inputs; document exact commands so markers can run against any host/port without editing code.

3. Remove or implement unused env variable
- Files: `.env.example`, `README.md` (or CORS setup in app if intentional)
- Evidence: `ALLOWED_ORIGINS` exists in `.env.example` (`.env.example:18`) but is not read anywhere in `app/`.
- Fix plan: Either implement CORS using this variable or remove it from docs/env examples to avoid confusion and “dead config” marks.

4. Standardize tool commands to one venv path
- Files: `README.md`, `FINAL_SUBMISSION_NOTES.md`, `DEMO.md`
- Evidence: repository contains two local venv conventions (`.venv` and `secure-api-capstone/.venv` folder exists locally), which has caused command drift in past logs.
- Fix plan: Declare `.venv` as canonical and normalize all doc commands to that path; explicitly state legacy nested venv should not be used.

## Nice to Have (optional)

1. Add one-command QA runner
- Files: `scripts/` (new `check_all.sh`), `README.md`
- Fix plan: Add a single script that runs migrations, tests, lint, and format-check in order with clear pass/fail summaries; this makes submission verification faster and less error-prone.

2. Reduce tracked artifact noise
- Files: `results/` (tracked files selection), `docs/results.md`
- Fix plan: Keep only the minimal evidence set referenced in report appendices and remove redundant legacy graphs to make the repo easier to review.

3. Add explicit expected status table to docs
- Files: `README.md`
- Fix plan: Add a compact table for key endpoints (`200/201/400/401/403/429`) so marker validation is quicker and aligns with your security claims.
