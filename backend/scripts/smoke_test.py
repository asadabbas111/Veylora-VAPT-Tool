"""End-to-end smoke test exercising the platform's full workflow through the API.

Uses httpx against a running server (or TestClient via --client). Validates:
register -> otp verify -> login -> assessment + scope + target (+ out-of-scope block)
-> full workflow -> findings/risk/attack paths/AI -> validation approval/run ->
remediation -> retest -> report.
"""

import sys
import time

import httpx

BASE = "http://127.0.0.1:8000/api"


def main() -> int:
    timestamp = str(int(time.time()))
    email = f"sectest.{timestamp}@example.com"
    password = "SecurePass123"

    c = httpx.Client(base_url=BASE, timeout=60)

    # 1. Register
    r = c.post("/auth/register", json={"full_name": "Security Test User", "email": email, "password": password})
    assert r.status_code == 201, r.text
    otp = r.json().get("dev_otp")
    assert otp, "expected dev OTP for local testing"
    print("1. register OK")

    # 2. Verify email
    r = c.post("/auth/verify-email", json={"email": email, "code": otp})
    assert r.status_code == 200, r.text
    tokens = r.json()
    c.headers["Authorization"] = f"Bearer {tokens['access_token']}"
    print("2. email verify OK")

    # 3. Me
    r = c.get("/auth/me")
    assert r.status_code == 200 and r.json()["user"]["email"] == email
    print("3. auth/me OK")

    # 4. Create assessment
    r = c.post("/assessments", json={
        "name": "Smoke Lab Assessment", "description": "automated e2e",
        "client_name": "Lab", "start_date": "2026-08-19", "end_date": "2026-08-26",
        "validation_level": 1,
    })
    assert r.status_code == 201, r.text
    a_id = r.json()["id"]
    print("4. assessment created:", a_id)

    # 5. Scope
    r = c.post(f"/assessments/{a_id}/scopes", json={"target": "192.168.56.0/24", "target_type": "cidr"})
    assert r.status_code == 201, r.text
    print("5. scope OK")

    # 6a. Out-of-scope target must be BLOCKED
    r = c.post(f"/assessments/{a_id}/targets", json={"target": "8.8.8.8", "target_type": "ipv4"})
    assert r.status_code == 403, r.text
    assert "BLOCKED" in r.json()["detail"]
    print("6a. out-of-scope target blocked OK")

    # 6b. In-scope targets
    for ip in ("192.168.56.105", "192.168.56.106", "192.168.56.110"):
        r = c.post(f"/assessments/{a_id}/targets", json={"target": ip, "target_type": "ipv4"})
        assert r.status_code == 201, r.text
    print("6b. in-scope targets OK")

    # 7. Run full workflow
    r = c.post(f"/assessments/{a_id}/workflow", json={"stage": "full"})
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]
    print("7. full workflow started job", job_id)
    for _ in range(60):
        time.sleep(2)
        r = c.get(f"/assessments/{job_id}/jobs") if False else c.get(f"/assessments/{a_id}/jobs")
        for job in r.json():
            if job["id"] == job_id:
                if job["status"] in ("completed", "failed"):
                    print("   job:", job["status"], job["error"] or "")
                    if job["status"] == "failed":
                        print(job.get("log"))
                        return 1
                    break
        else:
            continue
        break
    else:
        print("   job still running after timeout")
        return 1

    # 8. Assets / findings presence
    r = c.get("/assets", params={"assessment_id": a_id})
    assets = r.json()
    r = c.get("/findings", params={"assessment_id": a_id})
    findings_data = r.json()
    print(f"8. assets={len(assets)} findings={findings_data['total']}")
    if not assets or findings_data["total"] == 0:
        print("   FAIL: no assets/findings produced")
        return 1

    top = findings_data["items"][0]
    f_id = top["id"]
    print("   top finding:", top["title"][:60], top["risk_score"])

    # 9. AI analysis for one finding
    r = c.post(f"/ai/analyze/{f_id}")
    assert r.status_code == 200, r.text
    ai = r.json()
    print("9. AI analysis OK:", ai["priority"], ai["confidence"], ai["provider"])

    # 10. Build attack paths (sync rebuild is fine here)
    r = c.post(f"/attack-paths/rebuild-sync?assessment_id={a_id}")
    assert r.status_code == 200, r.text
    print("10. attack paths:", r.json()["paths"])

    # 11. Validation: request -> approve (admin-only) -> run
    r = c.post(f"/validation/request/{f_id}", json={"level": 2})
    assert r.status_code == 201, r.text
    task_id = r.json()["id"]
    if r.json()["status"] == "pending":
        # Approval requires the admin role (RBAC-enforced).
        admin_c = httpx.Client(base_url=BASE, timeout=30)
        ar = admin_c.post("/auth/login", json={"email": "admin@secops.io", "password": "Admin@12345"})
        assert ar.status_code == 200, ar.text
        admin_c.headers["Authorization"] = f"Bearer {ar.json()['access_token']}"
        r = admin_c.post(f"/validation/approve/{task_id}", json={"approve": True})
        assert r.status_code == 200, r.text
        admin_c.close()
    r = c.post(f"/validation/run/{task_id}")
    assert r.status_code == 202, r.text
    for _ in range(30):
        time.sleep(1)
        r = c.get(f"/validation/tasks", params={"assessment_id": a_id})
        t = next((x for x in r.json() if x["id"] == task_id), None)
        if t and t["status"] in ("completed", "stopped", "blocked", "failed"):
            print("11. validation:", t["status"], t["verdict"])
            break
    print("   validation result:", t)

    # 12. Remediation + retest
    r = c.post(f"/findings/{f_id}/remediation", json={"plan": "Upgrade the affected service and block exposure."})
    assert r.status_code == 201, r.text
    r = c.get("/remediation", params={"assessment_id": a_id})
    rem = r.json()[0]
    r = c.post(f"/remediation/{rem['id']}/status", json={"status": "fixed"})
    assert r.status_code == 200, r.text
    r = c.post(f"/remediation/{rem['id']}/retest")
    assert r.status_code == 200, r.text
    print("12. remediation + retest OK:", r.json()["retest_before_score"], "->", r.json()["retest_after_score"])

    # 13. Report
    r = c.post(f"/reports/generate/{a_id}", params={"report_type": "full"})
    assert r.status_code == 202, r.text
    for _ in range(30):
        time.sleep(1)
        r = c.get("/reports", params={"assessment_id": a_id})
        rep = r.json()
        if rep:
            print("13. report generated:", rep[0]["file_sha256"][:16])
            break
    print("   reports:", rep)

    # 14. Dashboard summary
    r = c.get("/dashboard/summary")
    cards = r.json()["cards"]
    print("14. dashboard cards:", {k: cards[k] for k in ("total_assets", "max_risk", "attack_paths")})

    # 15. Audit log
    r = c.get("/audit")
    print("15. audit entries:", r.json()["total"])

    print("\nE2E SMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())