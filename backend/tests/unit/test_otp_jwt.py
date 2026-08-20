"""Unit tests for OTP generation/hashing and JWT issuance/validation."""
import datetime as dt

from app.security.jwt import create_access_token, create_refresh_token, decode_token
from app.security.otp import generate_otp, hash_otp, verify_otp
from app.config import settings


def test_generate_otp_structure():
    for _ in range(50):
        otp = generate_otp()
        assert len(otp) == settings.OTP_LENGTH
        assert otp.isdigit()


def test_hash_is_deterministic_and_bind_to_email():
    otp = "123456"
    assert hash_otp(otp, "a@b.com") == hash_otp(otp, "a@b.com")
    assert hash_otp(otp, "a@b.com") != hash_otp(otp, "c@d.com")


def test_verify_otp_valid_and_expired():
    future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=10)
    h = hash_otp("654321", "u@example.com")
    assert verify_otp("654321", "u@example.com", h, future) is True
    assert verify_otp("000000", "u@example.com", h, future) is False
    assert verify_otp("654321", "u@example.com", h, past) is False


def test_access_token_roundtrip():
    tok = create_access_token(42, "admin")
    data = decode_token(tok)
    assert data["sub"] == "42"
    assert data["role"] == "admin"
    assert data["type"] == "access"
    assert data["exp"] > data["iat"]


def test_refresh_token_type():
    tok = create_refresh_token(7)
    data = decode_token(tok)
    assert data["type"] == "refresh"
    assert data["sub"] == "7"


def test_garbage_token_rejected():
    assert decode_token("not.a.jwt") is None
    assert decode_token("") is None