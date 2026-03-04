# Architecture

This document gives a simple, high-level view of the capstone system.

## High-Level Diagram

```text
      +-------------------------------+
      | Client Layer                  |
      | - Browser (/docs)             |
      | - curl                         |
      | - scripts/ + tests/           |
      +---------------+---------------+
                      |
                      v
      +-------------------------------+
      | FastAPI App (app/main.py)     |
      | - Route handlers              |
      | - Request validation          |
      | - Error/status responses      |
      +---------------+---------------+
                      |
                      v
      +-------------------------------+
      | AuthN / AuthZ Layer           |
      | - JWT verification            |
      | - API key verification        |
      | - RBAC checks (admin/user)    |
      | - Rate limit + lockout rules  |
      +---------------+---------------+
                      |
                      v
      +-------------------------------+
      | Data Layer                    |
      | - SQLAlchemy models           |
      | - SQLite database (app.db)    |
      | - Alembic migrations          |
      +-------------------------------+
```

## Component Summary

- `Client Layer`:
  Sends requests to API endpoints. This includes manual curl checks, attack/performance scripts, and automated tests.

- `FastAPI App`:
  Main request entry point. Handles endpoint routing, payload parsing, and response generation.

- `AuthN / AuthZ Layer`:
  Enforces security controls:
  - authentication by JWT or API key
  - authorization by role (`user` vs `admin`)
  - login defenses (rate limiting and lockout)

- `Data Layer`:
  Persists users, auth events, API key metadata, and audit/security records using SQLAlchemy + SQLite with schema control from Alembic.

## Where `scripts/` and `results/` Fit

- `scripts/`:
  Operational and evaluation drivers. They simulate attacks, authorization abuse, and performance measurements against the running API.

- `results/`:
  Evidence output directory. Contains CSV measurements, run logs, summary files, and generated graphs used in the capstone write-up.
