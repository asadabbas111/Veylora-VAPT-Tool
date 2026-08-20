"""Integration test: the controlled validation workflow (request->approve->run)."""
from tests.helpers import add_scope, add_target, make_assessment


def test_validation_flow(client, analyst_client, admin_headers):
    aid = make_assessment(client, analyst_client["headers"], name="Validation Flow")
    add_scope(client, analyst_client["headers"], aid, "192.168.56.0/24")
    add_target(client, analyst_client["headers"], aid, "192.168.56.101")

    r = client.post(f"/api/assessments/{aid}/workflow", json={"stage": "full"},
                    headers=analyst_client["headers"])
    assert r.status_code == 202, r.text

    # Grab a finding to validate.
    import time

    findings = []
    for _ in range(60):
        findings = client.get("/api/findings", params={"assessment_id": aid, "page_size": 50},
                              headers=analyst_client["headers"]).json().get("items", [])
        if findings:
            break
        time.sleep(1)
    assert findings, "no findings produced"

    f = findings[0]
    # Level 2 (controlled PoC) requires admin approval.
    r = client.post(f"/api/validation/request/{f['id']}", json={"level": 2},
                    headers=analyst_client["headers"])
    assert r.status_code == 201, r.text
    task = r.json()
    assert task["status"] == "pending", "level>default must wait for approval"

    # Running before approval must be refused.
    r = client.post(f"/api/validation/run/{task['id']}", headers=analyst_client["headers"])
    assert r.status_code == 403, r.text

    # Analyst cannot approve (admin-only).
    r = client.post(f"/api/validation/approve/{task['id']}", json={"approve": True},
                    headers=analyst_client["headers"])
    assert r.status_code == 403, r.text

    # Admin approves, then analyst runs.
    r = client.post(f"/api/validation/approve/{task['id']}", json={"approve": True},
                    headers=admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "approved"

    r = client.post(f"/api/validation/run/{task['id']}", headers=analyst_client["headers"])
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]

    # Poll job to completion.
    for _ in range(60):
        jobs = client.get(f"/api/assessments/{aid}/jobs", headers=analyst_client["headers"]).json()
        job = next((j for j in jobs if j["id"] == job_id), None)
        if job and job["status"] in ("completed", "failed"):
            break
        time.sleep(1)

    tasks = client.get("/api/validation/tasks", params={"assessment_id": aid},
                       headers=analyst_client["headers"]).json()
    assert tasks, "validation task must be listed"
    done = [t for t in tasks if t["id"] == task["id"]]
    assert done and done[0]["status"] in ("completed", "failed", "blocked")


def test_validation_blocked_out_of_scope_asset(client, analyst_client):
    """Asset not inside the authorized scope must never be validated."""
    from datetime import date

    from app.database import SessionLocal
    from app.models.asset import Asset
    from app.models.finding import Finding
    from app.models.assessment import Assessment, AssessmentScope
    from app.models.validation import ValidationTask
    from app.validators.engine import validation_engine, ValidationBlocked

    db = SessionLocal()
    try:
        # Build an assessment whose scope does NOT cover the asset.
        assessment = Assessment(name="Scope Guard", start_date=date(2026, 1, 1),
                                owner_id=1, status="completed")
        db.add(assessment)
        db.flush()
        db.add(AssessmentScope(assessment_id=assessment.id, target="192.168.56.0/24",
                               target_type="cidr", created_by=1))
        asset = Asset(assessment_id=assessment.id, ip_address="203.0.113.77", criticality=5, risk_score=50)
        db.add(asset)
        db.flush()
        finding = Finding(assessment_id=assessment.id, asset_id=asset.id, title="Out of scope test",
                          severity="high", risk_score=60, confidence=80)
        db.add(finding)
        db.flush()
        task = validation_engine.request_task(db, finding, 1, 1)
        assert task.status == "approved"  # level 1 auto-approves
        db.commit()

        import pytest

        with pytest.raises(ValidationBlocked):
            validation_engine.run(db, task)
        db.rollback()
        assert task.status == "blocked"
    finally:
        db.close()