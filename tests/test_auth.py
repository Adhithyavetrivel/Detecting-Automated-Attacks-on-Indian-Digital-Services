"""Tests for authentication and role-based access control."""


def test_health_check_no_auth_required(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_login_success(admin_token):
    assert admin_token  # fixture already asserts a 200 + token present


def test_login_wrong_password(client, admin_token):
    response = client.post(
        "/api/auth/login", data={"username": "testadmin", "password": "wrongpassword"}
    )
    assert response.status_code == 401


def test_protected_route_requires_token(client):
    response = client.get("/api/devices")
    assert response.status_code == 401


def test_get_me_returns_current_user(client, admin_token):
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200
    assert response.json()["username"] == "testadmin"
    assert response.json()["role"] == "ADMIN"


def test_viewer_cannot_create_device(client, db_session):
    from app.models.user import User, UserRole
    from app.security.auth import hash_password

    viewer = User(
        username="viewer1",
        hashed_password=hash_password("viewerpass"),
        role=UserRole.VIEWER,
    )
    db_session.add(viewer)
    db_session.commit()

    login = client.post("/api/auth/login", data={"username": "viewer1", "password": "viewerpass"})
    token = login.json()["access_token"]

    response = client.post(
        "/api/devices",
        headers={"Authorization": f"Bearer {token}"},
        json={"ip_address": "10.0.0.5"},
    )
    assert response.status_code == 403
