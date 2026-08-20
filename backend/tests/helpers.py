"""Shared HTTP helpers for integration tests (stateless wrappers over the API)."""


def make_assessment(client, headers, name="Test Assessment"):
    r = client.post(
        "/api/assessments",
        json={
            "name": name,
            "client_name": "Lab",
            "assessment_type": "vulnerability_assessment",
            "start_date": "2026-01-01",
            "validation_level": 1,
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


def add_scope(client, headers, assessment_id, target="192.168.56.0/24"):
    r = client.post(
        f"/api/assessments/{assessment_id}/scopes",
        json={"target": target, "description": "authorized lab"},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    return r.json()


def add_target(client, headers, assessment_id, target):
    return client.post(f"/api/assessments/{assessment_id}/targets", json={"target": target}, headers=headers)