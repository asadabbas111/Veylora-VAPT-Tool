"""Integration test: full pipeline produces findings, risk, attack paths, and a report."""
import time

from tests.helpers import add_scope, add_target, make_assessment


def _wait_for_job(client, headers, aid, job_id, timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/assessments/{aid}/jobs", headers=headers)
        if r.status_code == 200:
            for job in r.json():
                if job.get("id") == job_id:
                    if job.get("status") in ("completed", "failed", "cancelled"):
                        return job.get("status")
        time.sleep(1)
    return "timeout"


def test_pipeline_and_report(client, analyst_client):
    aid = make_assessment(client, analyst_client["headers"], name="Pipeline Report")
    add_scope(client, analyst_client["headers"], aid, "192.168.56.0/24")
    add_target(client, analyst_client["headers"], aid, "192.168.56.101")

    r = client.post(f"/api/assessments/{aid}/workflow", json={"stage": "full"},
                    headers=analyst_client["headers"])
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]
    status = _wait_for_job(client, analyst_client["headers"], aid, job_id)
    assert status == "completed", f"workflow job ended as {status}"

    # Findings must be enriched with risk + explainable breakdown.
    findings = client.get("/api/findings", params={"assessment_id": aid, "page_size": 100},
                          headers=analyst_client["headers"])
    assert findings.status_code == 200, findings.text
    items = findings.json().get("items", [])
    assert items, "expected findings from the lab simulation"
    for f in items:
        assert f["severity"] in ("critical", "high", "medium", "low", "info")
        assert f["risk_score"] >= 0.0

    # Report generation must be available and downloadable.
    r = client.post(f"/api/reports/generate/{aid}", headers=analyst_client["headers"])
    assert r.status_code == 202, r.text
    time.sleep(2)  # allow the report job to finish
    reports = client.get("/api/reports", params={"assessment_id": aid},
                         headers=analyst_client["headers"])
    assert reports.status_code == 200, reports.text
    rep = reports.json()
    assert rep, "expected at least one generated report"
    assert rep[0]["report_type"] == "full"

    dl = client.get(f"/api/reports/download/{rep[0]['id']}", headers=analyst_client["headers"])
    assert dl.status_code == 200, dl.text
    assert dl.headers.get("content-type", "").startswith("application/pdf")
    if dl.content:
        assert dl.content[:4] == b"%PDF"


def test_attack_paths_present(client, analyst_client):
    aid = make_assessment(client, analyst_client["headers"], name="Attack Paths")
    add_scope(client, analyst_client["headers"], aid, "192.168.56.0/24")
    add_target(client, analyst_client["headers"], aid, "192.168.56.101")

    r = client.post(f"/api/assessments/{aid}/workflow", json={"stage": "full"},
                    headers=analyst_client["headers"])
    assert r.status_code == 202, r.text

    r = client.get("/api/attack-paths", params={"assessment_id": aid},
                   headers=analyst_client["headers"])
    assert r.status_code == 200, r.text
    paths = r.json()
    assert isinstance(paths, list)
    for p in paths:
        assert p["cumulative_risk"] >= 0
        assert p["end_node_type"] in ("asset", "service", "vuln")
        assert isinstance(p["nodes_json"], list) and isinstance(p["edges_json"], list)
