import datetime as dt

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.config import settings
from app.deps import CurrentUser, DbDep
from app.models.user import User
from app.schemas.auth import (
    ForgotPasswordRequest, LoginRequest, MeResponse, RefreshRequest, RegisterRequest,
    ResetPasswordRequest, ResendOtpRequest, TokenResponse, UserOut, VerifyEmailRequest,
)
from app.security.email import send_otp_email
from app.security.jwt import create_access_token, create_refresh_token, decode_token
from app.security.otp import generate_otp, hash_otp, verify_otp
from app.security.passwords import hash_password, verify_password
from app.security.rbac import ROLES
from app.services.audit_service import audit

router = APIRouter(prefix="/auth", tags=["auth"])


def _issue_tokens(user: User) -> TokenResponse:
    return TokenResponse(
        access_token=create_access_token(user.id, user.role),
        refresh_token=create_refresh_token(user.id),
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/register", status_code=201)
def register(payload: RegisterRequest, db: DbDep):
    if db.query(User).filter(User.email == payload.email.lower()).first():
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    now = dt.datetime.now(dt.timezone.utc)
    otp = generate_otp()
    user = User(
        full_name=payload.full_name.strip(),
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        role="analyst",  # self-registered users start as analysts; promotion to admin is manual
        is_active=False,
        is_verified=False,
        otp_hash=hash_otp(otp, payload.email.lower()),
        otp_expires_at=now + dt.timedelta(minutes=settings.OTP_TTL_MINUTES),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    sent = send_otp_email(payload.email, otp)
    audit(db, user.id, "User registered (pending verification)", result="success")
    # Fail-safe: if SMTP is disabled or the send fails, the code is returned so
    # the account is never left unusable in a dev/lab environment.
    return {
        "message": "Account created. Verify your email with the code we sent.",
        "dev_otp": otp if (settings.DEV_OTP_RETURN and not sent) else None,
        "email": payload.email,
    }


@router.post("/verify-email")
def verify_email(payload: VerifyEmailRequest, db: DbDep):
    email = payload.email.lower()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Account not found.")
    if user.is_verified:
        raise HTTPException(status_code=400, detail="Email already verified.")
    if not user.otp_hash or not user.otp_expires_at:
        raise HTTPException(status_code=400, detail="No verification requested. Register again.")
    if not verify_otp(payload.code.strip(), email, user.otp_hash, user.otp_expires_at):
        audit(db, user.id, "Email verification failed", result="blocked")
        raise HTTPException(status_code=400, detail="Invalid or expired verification code.")
    user.is_verified = True
    user.is_active = True
    user.otp_hash = None
    user.otp_expires_at = None
    user.last_login_at = dt.datetime.utcnow()
    db.add(user)
    db.commit()
    db.refresh(user)
    audit(db, user.id, "Email verified", result="success")
    return _issue_tokens(user)


@router.post("/resend-otp")
def resend_otp(payload: ResendOtpRequest, db: DbDep):
    email = payload.email.lower()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Account not found.")
    if user.is_verified:
        raise HTTPException(status_code=400, detail="Email already verified.")
    otp = generate_otp()
    now = dt.datetime.now(dt.timezone.utc)
    user.otp_hash = hash_otp(otp, email)
    user.otp_expires_at = now + dt.timedelta(minutes=settings.OTP_TTL_MINUTES)
    db.add(user)
    db.commit()
    sent = send_otp_email(email, otp)
    audit(db, user.id, "OTP resent", result="success")
    return {
        "message": "A new verification code has been sent.",
        "dev_otp": otp if (settings.DEV_OTP_RETURN and not sent) else None,
    }


@router.post("/forgot-password", status_code=200)
def forgot_password(payload: ForgotPasswordRequest, db: DbDep):
    """Send a password-reset code. The code is also echoed as `reset_code` when
    SMTP is unavailable so the account is never locked out of recovery."""
    email = payload.email.lower()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="No account found for this email.")
    otp = generate_otp()
    now = dt.datetime.now(dt.timezone.utc)
    user.otp_hash = hash_otp(otp, email)
    user.otp_expires_at = now + dt.timedelta(minutes=settings.OTP_TTL_MINUTES)
    db.add(user)
    db.commit()
    sent = send_otp_email(email, otp)
    audit(db, user.id, "Password reset requested", result="success")
    return {
        "message": "If the account exists, a reset code has been sent.",
        "reset_code": otp if (settings.DEV_OTP_RETURN and not sent) else None,
        "email": email,
    }


@router.post("/reset-password", status_code=200)
def reset_password(payload: ResetPasswordRequest, db: DbDep):
    """Verify the emailed code and set a new password."""
    email = payload.email.lower()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="No account found for this email.")
    if not user.otp_hash or not user.otp_expires_at:
        raise HTTPException(status_code=400, detail="No reset requested. Request a code first.")
    if not verify_otp(payload.code.strip(), email, user.otp_hash, user.otp_expires_at):
        audit(db, user.id, "Password reset failed", result="blocked")
        raise HTTPException(status_code=400, detail="Invalid or expired reset code.")
    user.password_hash = hash_password(payload.new_password)
    user.otp_hash = None
    user.otp_expires_at = None
    db.add(user)
    db.commit()
    audit(db, user.id, "Password reset completed", result="success")
    return {"message": "Password reset. You can now sign in."}


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: DbDep):
    email = payload.email.lower()
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified. Check your inbox for the verification code.")
    if user.disabled or not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled.")
    user.last_login_at = dt.datetime.utcnow()
    db.add(user)
    db.commit()
    audit(db, user.id, "User logged in", result="success",
          ip_address=request.client.host if request.client else None)
    return _issue_tokens(user)


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: DbDep):
    data = decode_token(payload.refresh_token)
    if not data or data.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token.")
    user = db.get(User, int(data["sub"])) if data.get("sub") else None
    if not user or not user.is_active or user.disabled:
        raise HTTPException(status_code=401, detail="Account unavailable.")
    return _issue_tokens(user)


@router.get("/me", response_model=MeResponse)
def me(user: CurrentUser):
    return MeResponse(user=UserOut.model_validate(user))


@router.get("/roles")
def roles():
    return {"roles": sorted(ROLES)}