"""FastAPI dependency callables for authentication, authorization, and utilities."""
from __future__ import annotations

from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kms.auth.jwt_handler import decode_token
from kms.auth.rbac import Permission, has_permission
from kms.db.models import User
from kms.db.session import get_db

bearer = HTTPBearer(auto_error=True)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
    session: AsyncSession = Depends(get_db),
) -> User:
    """Decode the Bearer JWT, load the ``User`` from the DB.

    Raises ``HTTP 401`` if the token is missing, malformed, expired, or the
    referenced user no longer exists / is deactivated.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(credentials.credentials)
    except JWTError:
        raise credentials_exception

    username: str | None = payload.get("sub")
    if not username:
        raise credentials_exception

    result = await session.execute(select(User).where(User.username == username))
    user: User | None = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise credentials_exception

    return user


def require_permission(permission: Permission) -> Callable:
    """Return a dependency that enforces *permission* on the current user.

    The returned dependency resolves to the authenticated ``User`` so callers
    can use it directly::

        @router.get("/")
        async def list_keys(user: User = Depends(require_permission(Permission.KEY_READ))):
            ...
    """

    async def _dep(user: User = Depends(get_current_user)) -> User:
        if not has_permission(user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return _dep


async def get_client_ip(request: Request) -> str:
    """Extract the real client IP from the request.

    Checks ``X-Forwarded-For`` first (set by reverse proxies), then falls back
    to the direct client address.
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # The header may contain a comma-separated list; the leftmost is the client.
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"
