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


def test_api_key_scopes_enforced_on_data_endpoint(client):
    register(client, "admin", "adminpass", role="admin")
    admin_token = login(client, "admin", "adminpass").json()["access_token"]

    restricted_key = client.post(
        "/admin/api-keys",
        json={"name": "metrics-only", "scopes": ["metrics:read"]},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert restricted_key.status_code == 200
    restricted_raw_key = restricted_key.json()["api_key"]

    denied = client.get("/data", headers={"X-API-Key": restricted_raw_key})
    assert denied.status_code == 403

    data_key = client.post(
        "/admin/api-keys",
        json={"name": "data-key", "scopes": ["data:read"]},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert data_key.status_code == 200
    assert data_key.json()["metadata"]["scopes"] == ["data:read"]

    allowed = client.get("/data", headers={"X-API-Key": data_key.json()["api_key"]})
    assert allowed.status_code == 200


def test_api_key_invalid_scope_rejected(client):
    register(client, "admin", "adminpass", role="admin")
    admin_token = login(client, "admin", "adminpass").json()["access_token"]

    created = client.post(
        "/admin/api-keys",
        json={"name": "bad-scope", "scopes": ["not:real"]},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert created.status_code == 400
    assert "Invalid API key scope" in created.json()["detail"]


def test_api_key_rotate_preserves_or_updates_scopes(client):
    register(client, "admin", "adminpass", role="admin")
    admin_token = login(client, "admin", "adminpass").json()["access_token"]

    created = client.post(
        "/admin/api-keys",
        json={"name": "rotatable", "scopes": ["metrics:read"]},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert created.status_code == 200
    key_id = created.json()["metadata"]["id"]

    rotated = client.post(
        f"/admin/api-keys/{key_id}/rotate",
        json={"name": "rotated", "scopes": ["data:read", "metrics:read"]},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert rotated.status_code == 200
    assert rotated.json()["metadata"]["scopes"] == ["data:read", "metrics:read"]

    usable = client.get("/data", headers={"X-API-Key": rotated.json()["api_key"]})
    assert usable.status_code == 200
