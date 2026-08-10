"""JWT authentication and role-based authorization."""

import datetime
import logging
from typing import Any, Dict, List, Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import settings
from .portal_store import ROLES, PortalStore

log = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False)

# Capability model. Roles are checked against named capabilities rather than
# by name at each call site, so adding a role later is a table change instead
# of a hunt through every endpoint.
CAPABILITIES: Dict[str, set] = {
    "Administrator":   {"read", "audit", "audit.export", "key.create", "key.lifecycle",
                        "key.destroy", "user.manage"},
    "SecurityOfficer": {"read", "audit", "audit.export", "key.create", "key.lifecycle",
                        "key.destroy"},
    "Operator":        {"read", "key.create", "key.lifecycle"},
    "Auditor":         {"read", "audit", "audit.export"},
    "ReadOnly":        {"read"},
}


def create_token(username: str, role: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + datetime.timedelta(minutes=settings.jwt_ttl_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.ExpiredSignatureError:
        # Distinguished from a bad signature so the portal can prompt a
        # re-login rather than showing a generic failure.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")


def get_store(request: Request) -> PortalStore:
    return request.app.state.portal


async def current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Dict[str, Any]:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")

    claims = decode_token(credentials.credentials)
    user = request.app.state.portal.get_user(claims.get("sub", ""))
    if not user or not user.get("enabled"):
        # The account may have been disabled or deleted after the token was
        # issued; a still-valid signature must not outlive the account.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account is not active")

    return {
        "username": user["username"],
        "role": user["role"],
        "display_name": user.get("display_name") or user["username"],
    }


def requires(capability: str):
    """Dependency enforcing a capability.

    The role is re-read from the database rather than trusted from the token,
    so a role change takes effect on the next request instead of whenever the
    token happens to expire.
    """
    async def _check(user: Dict[str, Any] = Depends(current_user)) -> Dict[str, Any]:
        granted = CAPABILITIES.get(user["role"], set())
        if capability not in granted:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Role '{user['role']}' does not permit {capability}",
            )
        return user
    return _check


def client_ip(request: Request) -> str:
    """Source address for the audit trail.

    X-Forwarded-For is honoured because the portal reaches the API through a
    reverse proxy in the compose deployment; without it every audit row would
    record the proxy's address and the field would be worthless.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def role_list() -> List[str]:
    return list(ROLES)
