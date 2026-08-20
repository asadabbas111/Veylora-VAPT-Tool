from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.security.jwt import decode_token
from app.security.rbac import ensure_permission
from app.security.rate_limit import rate_limiter

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_PREFIX}/auth/login", auto_error=False)

DbDep = Annotated[Session, Depends(get_db)]


def get_current_user(
    db: DbDep,
    token: str | None = Depends(oauth2_scheme),
) -> User:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_error
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise credentials_error
    user_id = payload.get("sub")
    user = db.get(User, int(user_id)) if user_id else None
    if not user:
        raise credentials_error
    if user.disabled or not user.is_verified or not user.is_active:
        raise HTTPException(status_code=403, detail="Account is not active.")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_permission(permission: str):
    def checker(user: CurrentUser) -> User:
        if not ensure_permission(user.role, permission):
            raise HTTPException(status_code=403, detail=f"Permission denied: {permission}")
        return user

    return checker


def RequirePermission(permission: str):
    """Annotated alias that ACTUALLY applies the permission dependency.

    NOTE: `user: CurrentUser = require_permission(...)` silently skips the check
    (FastAPI ignores a non-Depends callable default when the annotation already
    declares a Depends). This helper must be used instead.
    """
    return Annotated[User, Depends(require_permission(permission))]


def enforce_rate_limit(request):
    """Callable dependency using the request client IP as the key."""
    def dep(request=request):
        if not rate_limiter.allow(request.client.host if request.client else "unknown"):
            raise HTTPException(status_code=429, detail="Rate limit exceeded. Slow down.")
        return True

    return dep