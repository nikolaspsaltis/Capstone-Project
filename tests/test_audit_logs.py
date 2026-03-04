from app import main as main_app


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


def test_auth_flows_write_audit_logs(client):
    register(client, "alice", "secret123")

    bad = login(client, "alice", "wrongpass")
    assert bad.status_code == 401

    good = login(client, "alice", "secret123")
    assert good.status_code == 200

    db = main_app.SessionLocal()
    try:
        rows = (
            db.execute(
                main_app.select(main_app.AuditLog).where(
                    main_app.AuditLog.actor_username == "alice"
                )
            )
            .scalars()
            .all()
        )
        statuses = {(row.action, row.status) for row in rows}
        assert ("register", "success") in statuses
        assert ("login", "failed_invalid_credentials") in statuses
        assert ("login", "success") in statuses
    finally:
        db.close()


def test_non_admin_denied_for_audit_log_endpoint_and_audited(client):
    register(client, "user1", "userpass")
    user_token = login(client, "user1", "userpass").json()["access_token"]

    denied = client.get("/admin/audit-logs", headers={"Authorization": f"Bearer {user_token}"})
    assert denied.status_code == 403

    db = main_app.SessionLocal()
    try:
        denied_event = (
            db.execute(
                main_app.select(main_app.AuditLog).where(
                    main_app.AuditLog.action == "admin_access",
                    main_app.AuditLog.status == "denied",
                    main_app.AuditLog.actor_username == "user1",
                )
            )
            .scalars()
            .first()
        )
        assert denied_event is not None
    finally:
        db.close()


def test_admin_can_query_audit_logs_with_filters(client):
    register(client, "admin", "adminpass", role="admin")
    admin_token = login(client, "admin", "adminpass").json()["access_token"]

    register(client, "bob", "secret123")
    login(client, "bob", "secret123")

    page = client.get(
        "/admin/audit-logs?page=1&page_size=50&action=register&status=success",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert page.status_code == 200
    body = page.json()
    assert body["page"] == 1
    assert body["page_size"] == 50
    assert body["total"] >= 2
    assert len(body["items"]) >= 1
    assert all(item["action"] == "register" for item in body["items"])
    assert all(item["status"] == "success" for item in body["items"])

    bob_only = client.get(
        "/admin/audit-logs?page=1&page_size=20&actor_username=bob",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert bob_only.status_code == 200
    assert any(item["actor_username"] == "bob" for item in bob_only.json()["items"])
