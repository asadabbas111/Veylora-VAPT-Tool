import os
import shutil
import tempfile

import pytest

_TEST_DIR = tempfile.mkdtemp(prefix="apt-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(_TEST_DIR, 'test.db')}"
os.environ["DEV_OTP_RETURN"] = "true"
os.environ["EMAIL_ENABLED"] = "false"
os.environ["JWT_SECRET"] = "test_secret_not_for_production"

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.database import SessionLocal, init_db  # noqa: E402
from app.main import app  # noqa: E402


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_TEST_DIR, ignore_errors=True)


@pytest.fixture(scope="session")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def db():
    init_db()
    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture()
def admin_headers(client):
    r = client.post(
        "/api/auth/login",
        json={"email": "admin@secops.io", "password": "Admin@12345"},
    )
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def analyst_client(client):
    """Create a throwaway verified analyst account and return (client, headers)."""
    email = f"ana{os.getpid()}@{abs(hash(__name__)) % 10**7}.example.com"
    email = f"analyst{__import__('time').time_ns()}@example.com"
    r = client.post("/api/auth/register", json={"full_name": "Test Analyst", "email": email, "password": "Passw0rd!"})
    assert r.status_code == 201, r.text
    otp = r.json()["dev_otp"]
    r = client.post("/api/auth/verify-email", json={"email": email, "code": otp})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return {"email": email, "headers": {"Authorization": f"Bearer {token}"}}


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