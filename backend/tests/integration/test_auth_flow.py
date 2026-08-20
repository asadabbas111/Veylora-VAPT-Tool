"""Integration test: end-to-end auth flow (register -> OTP verify -> login -> refresh -> me)."""


def test_full_auth_flow(client):
    import time

    email = f"auth{time.time_ns()}@example.com"
    r = client.post("/api/auth/register", json={"full_name": "Flow User", "email": email, "password": "Str0ng!Pass"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert "dev_otp" in body  # dev mode returns the code
    otp = body["dev_otp"]

    # Wrong code must be rejected.
    r = client.post("/api/auth/verify-email", json={"email": email, "code": "000000"})
    assert r.status_code == 400, r.text

    # Correct code issues tokens.
    r = client.post("/api/auth/verify-email", json={"email": email, "code": otp})
    assert r.status_code == 200, r.text
    tokens = r.json()
    assert tokens["access_token"] and tokens["refresh_token"]
    assert tokens["expires_in"] > 0

    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    me = client.get("/api/auth/me", headers=headers)
    assert me.status_code == 200, me.text
    assert me.json()["user"]["email"] == email
    assert me.json()["user"]["role"] == "analyst"

    # Login with password now works.
    r = client.post("/api/auth/login", json={"email": email, "password": "Str0ng!Pass"})
    assert r.status_code == 200, r.text

    # Refresh token roundtrip.
    r = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200, r.text
    assert r.json()["access_token"]

    # Expired/garbage access token denied.
    me = client.get("/api/auth/me", headers={"Authorization": "Bearer garbage.token.here"})
    assert me.status_code == 401


def test_duplicate_registration_rejected(client):
    import time

    email = f"dup{time.time_ns()}@example.com"
    payload = {"full_name": "Dup", "email": email, "password": "Str0ng!Pass"}
    assert client.post("/api/auth/register", json=payload).status_code == 201
    assert client.post("/api/auth/register", json=payload).status_code == 409


def test_weak_password_rejected(client):
    import time

    email = f"weak{time.time_ns()}@example.com"
    r = client.post("/api/auth/register", json={"full_name": "Weak", "email": email, "password": "x"})
    assert r.status_code == 422, r.text