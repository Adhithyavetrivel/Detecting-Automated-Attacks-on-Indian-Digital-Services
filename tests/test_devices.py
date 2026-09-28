"""Tests for device management endpoints."""


def _auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def test_create_and_get_device(client, admin_token):
    response = client.post(
        "/api/devices",
        headers=_auth_headers(admin_token),
        json={"ip_address": "192.168.56.10", "hostname": "ubuntu-lab"},
    )
    assert response.status_code == 201
    device_id = response.json()["id"]

    get_response = client.get(f"/api/devices/{device_id}", headers=_auth_headers(admin_token))
    assert get_response.status_code == 200
    assert get_response.json()["ip_address"] == "192.168.56.10"


def test_duplicate_ip_rejected(client, admin_token):
    payload = {"ip_address": "192.168.56.20"}
    first = client.post("/api/devices", headers=_auth_headers(admin_token), json=payload)
    assert first.status_code == 201

    second = client.post("/api/devices", headers=_auth_headers(admin_token), json=payload)
    assert second.status_code == 409


def test_get_nonexistent_device_404(client, admin_token):
    response = client.get("/api/devices/9999", headers=_auth_headers(admin_token))
    assert response.status_code == 404


def test_update_device(client, admin_token):
    create = client.post(
        "/api/devices", headers=_auth_headers(admin_token), json={"ip_address": "192.168.56.30"}
    )
    device_id = create.json()["id"]

    update = client.patch(
        f"/api/devices/{device_id}",
        headers=_auth_headers(admin_token),
        json={"notes": "Kali lab VM"},
    )
    assert update.status_code == 200
    assert update.json()["notes"] == "Kali lab VM"


def test_delete_device(client, admin_token):
    create = client.post(
        "/api/devices", headers=_auth_headers(admin_token), json={"ip_address": "192.168.56.40"}
    )
    device_id = create.json()["id"]

    delete = client.delete(f"/api/devices/{device_id}", headers=_auth_headers(admin_token))
    assert delete.status_code == 204

    get_after_delete = client.get(f"/api/devices/{device_id}", headers=_auth_headers(admin_token))
    assert get_after_delete.status_code == 404
