"""Integration test: server-side scope enforcement on targets and scanning."""
from tests.helpers import add_scope, add_target, make_assessment


def test_out_of_scope_target_rejected(client, analyst_client):
    aid = make_assessment(client, analyst_client["headers"])
    add_scope(client, analyst_client["headers"], aid)

    # In-scope target accepted.
    r = add_target(client, analyst_client["headers"], aid, "192.168.56.101")
    assert r.status_code in (201, 200), r.text

    # Internet host is blocked server-side regardless of scope.
    r = add_target(client, analyst_client["headers"], aid, "8.8.8.8")
    assert r.status_code == 403, r.text
    assert "scope" in r.json().get("detail", "").lower()

    # Unauthorized target outside authorized CIDR blocked.
    r = add_target(client, analyst_client["headers"], aid, "10.99.99.1")
    assert r.status_code == 403, r.text


def test_scope_check_endpoint(client, analyst_client):
    aid = make_assessment(client, analyst_client["headers"])
    add_scope(client, analyst_client["headers"], aid)

    r = client.post(
        f"/api/assessments/{aid}/scope-check",
        json={"target": "192.168.56.200"},
        headers=analyst_client["headers"],
    )
    assert r.status_code == 200, r.text
    assert r.json()["in_scope"] is True

    r = client.post(
        f"/api/assessments/{aid}/scope-check",
        json={"target": "8.8.8.8"},
        headers=analyst_client["headers"],
    )
    assert r.status_code == 200, r.text
    assert r.json()["in_scope"] is False


def test_scan_requires_scope(client, analyst_client):
    aid = make_assessment(client, analyst_client["headers"])
    # No scope declared -> workflow must refuse to start.
    r = client.post(f"/api/assessments/{aid}/workflow", json={"stage": "full"},
                    headers=analyst_client["headers"])
    assert r.status_code == 400, r.text


def test_public_host_scan_blocked(client, analyst_client):
    aid = make_assessment(client, analyst_client["headers"])
    add_scope(client, analyst_client["headers"], aid, "scanme.example.org")
    r = add_target(client, analyst_client["headers"], aid, "8.8.8.8")
    assert r.status_code == 403, r.text
