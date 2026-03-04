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


def test_non_admin_forbidden_on_security_alerts(client):
    register(client, "user", "userpass")
    token = login(client, "user", "userpass").json()["access_token"]

    denied = client.get("/admin/security-alerts", headers={"Authorization": f"Bearer {token}"})
    assert denied.status_code == 403


def test_security_alerts_detect_login_failure_spike(client):
    register(client, "admin", "adminpass", role="admin")
    register(client, "victim", "secret123")
    admin_token = login(client, "admin", "adminpass").json()["access_token"]

    original_limit = security_app.RATE_LIMIT_MAX_ATTEMPTS
    security_app.RATE_LIMIT_MAX_ATTEMPTS = 100
    try:
        for _ in range(5):
            failed = login(client, "victim", "wrongpass")
            assert failed.status_code == 401
    finally:
        security_app.RATE_LIMIT_MAX_ATTEMPTS = original_limit

    alerts = client.get(
        "/admin/security-alerts?window_minutes=60&min_failed_logins=3",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert alerts.status_code == 200
    payload = alerts.json()
    assert payload["window_minutes"] == 60
    assert any(
        alert["alert_type"] == "login_failure_spike"
        and alert["context"].get("username") == "victim"
        for alert in payload["alerts"]
    )


def test_security_alerts_detect_admin_denial_spike(client):
    register(client, "admin", "adminpass", role="admin")
    register(client, "user", "userpass")
    admin_token = login(client, "admin", "adminpass").json()["access_token"]
    user_token = login(client, "user", "userpass").json()["access_token"]

    for _ in range(3):
        denied = client.get("/admin/users", headers={"Authorization": f"Bearer {user_token}"})
        assert denied.status_code == 403

    alerts = client.get(
        "/admin/security-alerts?window_minutes=60&min_admin_denials=2",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert alerts.status_code == 200
    payload = alerts.json()
    assert any(
        alert["alert_type"] == "admin_access_denied_spike"
        and alert["context"].get("actor_username") == "user"
        for alert in payload["alerts"]
    )
