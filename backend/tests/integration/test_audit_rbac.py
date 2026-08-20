"""Integration test: RBAC enforcement, audit immutability, and the kill switch."""
import time

from tests.helpers import make_assessment


def test_admin_and_analyst_can_view_audit(client, analyst_client):
    r = client.get("/api/audit", headers=analyst_client["headers"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert "items" in body and body["total"] >= 1
    actions = {item["action"] for item in body["items"]}
    assert "Email verified" in actions  # the analyst's own flow is recorded


def test_blocked_out_of_scope_audited(client, analyst_client):
    aid = make_assessment(client, analyst_client["headers"])
    r = client.post(
        f"/api/assessments/{aid}/scopes",
        json={"target": "192.168.56.0/24", "description": "lab"},
        headers=analyst_client["headers"],
    )
    assert r.status_code == 201, r.text

    r = client.post(f"/api/assessments/{aid}/targets", json={"target": "8.8.8.8"},
                    headers=analyst_client["headers"])
    assert r.status_code == 403, r.text

    body = client.get("/api/audit", headers=analyst_client["headers"]).json()
    blocked = [i for i in body["items"] if i["action"] == "Target blocked (out of scope)"]
    assert blocked, "out-of-scope block must be written to the audit log"


def test_viewer_is_restricted(client, admin_headers):
    import time as _t

    email = f"viewer{_t.time_ns()}@example.com"
    r = client.post("/api/admin/users",
                    json={"full_name": "Limited Viewer", "email": email, "password": "Str0ng!Pass",
                          "role": "viewer"},
                    headers=admin_headers)
    assert r.status_code == 201, r.text

    r = client.post("/api/auth/login", json={"email": email, "password": "Str0ng!Pass"})
    assert r.status_code == 200, r.text
    viewer_headers = {"Authorization": f"Bearer {r.json()['access_token']}"}

    # Viewer cannot create assessments.
    r = client.post("/api/assessments", json={"name": "Nope", "start_date": "2026-01-01"},
                    headers=viewer_headers)
    assert r.status_code == 403, r.text

    # Viewer cannot read the audit log or hit admin endpoints.
    assert client.get("/api/audit", headers=viewer_headers).status_code == 403
    assert client.get("/api/admin/users", headers=viewer_headers).status_code == 403
    assert client.post("/api/admin/kill-switch/arm", headers=viewer_headers).status_code == 403


def test_analyst_cannot_manage_users(client, analyst_client):
    r = client.get("/api/admin/users", headers=analyst_client["headers"])
    assert r.status_code == 403, r.text


def test_kill_switch_arm_and_disarm(client, admin_headers):
    assert client.get("/api/admin/kill-switch/status", headers=admin_headers).json()["armed"] is False

    r = client.post("/api/admin/kill-switch/arm", headers=admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["armed"] is True
    try:
        body = client.get("/api/admin/kill-switch/status", headers=admin_headers).json()
        assert body["armed"] is True
    finally:
        client.post("/api/admin/kill-switch/disarm", headers=admin_headers)

    body = client.get("/api/admin/kill-switch/status", headers=admin_headers).json()
    assert body["armed"] is False

    audit_body = client.get("/api/audit", params={"action": "KILL SWITCH ARMED"},
                            headers=admin_headers).json()
    assert audit_body["total"] >= 1


def test_audit_has_no_update_or_delete_routes(client):
    """Append-only guarantee: mutating verbs must not exist for audit records."""
    import app.main as main_app

    routes = {f"{sorted(r.methods)[0]} {r.path}" for r in main_app.app.routes
              if hasattr(r, "methods") and "/audit" in getattr(r, "path", "")}
    for method in ("PUT", "PATCH", "DELETE"):
        assert not any(m.startswith(method) for m in routes), f"audit {method} route must not exist"
