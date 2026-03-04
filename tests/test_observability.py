from app import main as main_app
from app import security as security_app


def register(client, username: str, password: str, role: str | None = None):
    response = client.post("/register", json={"username": username, "password": password})
    if role == "admin" and response.status_code == 201:
        db = main_app.SessionLocal()
        try:
            user = main_app.get_user_by_username(db, username)
            assert user is not None
            user.role = "admin"
            db.commit()
        finally:
            db.close()
    return response


def login(client, username: str, password: str):
    return client.post("/login", json={"username": username, "password": password})


def test_request_id_header_is_set_and_preserved(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert "X-Request-ID" in resp.headers
    assert resp.headers["X-Request-ID"]

    custom = client.get("/healthz", headers={"X-Request-ID": "abc-123"})
    assert custom.status_code == 200
    assert custom.headers["X-Request-ID"] == "abc-123"


def test_healthz_and_readyz(client):
    health = client.get("/healthz")
    ready = client.get("/readyz")

    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"


def test_metrics_track_login_failures_lockouts_and_rate_limit_hits(client):
    register(client, "alice", "secret123")

    original_limit = security_app.RATE_LIMIT_MAX_ATTEMPTS
    security_app.RATE_LIMIT_MAX_ATTEMPTS = 100
    try:
        # Trigger failed logins and one lockout.
        for _ in range(security_app.MAX_LOGIN_ATTEMPTS):
            bad = login(client, "alice", "wrongpass")
            assert bad.status_code == 401

        locked = login(client, "alice", "secret123")
        assert locked.status_code == 403
    finally:
        security_app.RATE_LIMIT_MAX_ATTEMPTS = original_limit

    # Trigger rate-limit hits.
    for _ in range(security_app.RATE_LIMIT_MAX_ATTEMPTS):
        login(client, "ghost", "bad")
    blocked = login(client, "ghost", "bad")
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    body = metrics.json()
    counters = body["counters"]
    assert body["jwt_backend"] in {"python-jose", "pyjwt"}

    assert counters["login_failures"] >= security_app.MAX_LOGIN_ATTEMPTS
    assert counters["lockouts"] >= 1
    assert counters["rate_limit_hits"] >= 1
    assert "http_requests_total" in counters
    assert "login_successes" in counters
    assert "jwt_auth_successes" in counters
    assert "api_key_auth_successes" in counters
    assert "admin_access_granted" in counters
    assert "admin_access_denied" in counters
    assert "audit_events_total" in counters
    assert body["uptime_seconds"] >= 0
