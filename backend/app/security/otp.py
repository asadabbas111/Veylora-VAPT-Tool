import hashlib
import secrets
import datetime as dt

from app.config import settings


def generate_otp() -> str:
    """Generate a cryptographically-secure numeric OTP."""
    return f"{secrets.randbelow(10 ** settings.OTP_LENGTH):0{settings.OTP_LENGTH}d}"


def hash_otp(otp: str, email: str) -> str:
    """Hash an OTP together with the email so the stored value cannot be replayed
    for a different mailbox. Salted with a random value derived from the secret."""
    salt = hashlib.sha256(f"{settings.JWT_SECRET}:{email}".encode()).hexdigest()
    return hashlib.sha256(f"{otp}:{salt}".encode()).hexdigest()


def verify_otp(raw_otp: str, email: str, expected_hash: str, expires_at: dt.datetime) -> bool:
    if dt.datetime.now(dt.timezone.utc) > expires_at.replace(tzinfo=dt.timezone.utc):
        return False
    return secrets.compare_digest(hash_otp(raw_otp, email), expected_hash)