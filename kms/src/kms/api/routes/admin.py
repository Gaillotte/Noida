"""System administration routes — user management, HSM, and health.

Prefix: /api/v1/admin
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from kms.api.deps import get_client_ip, require_permission
from kms.api.schemas import (
    CreateUserRequest,
    HealthResponse,
    MessageResponse,
    UpdateRoleRequest,
    UserSummary,
)
from kms.audit.logger import record as audit_record
from kms.auth.jwt_handler import hash_password
from kms.auth.rbac import Permission, Role
from kms.core.hsm import get_hsm
from kms.db.models import User
from kms.db.session import get_db

logger = logging.getLogger(__name__)
router = APIRouter()


def _to_user_summary(user: User) -> UserSummary:
    return UserSummary.model_validate(user)


# ---------------------------------------------------------------------------
# POST /users
# ---------------------------------------------------------------------------


@router.post(
    "/users",
    response_model=UserSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user account",
)
async def create_user(
    body: CreateUserRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
    actor: User = Depends(require_permission(Permission.USER_WRITE)),
    client_ip: str = Depends(get_client_ip),
) -> UserSummary:
    # Validate role
    try:
        Role(body.role)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown role '{body.role}'. Valid roles: {[r.value for r in Role]}",
        )

    # Check for duplicate username
    existing = await session.execute(select(User).where(User.username == body.username))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{body.username}' is already taken",
        )

    if len(body.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must be at least 8 characters",
        )

    user = User(
        username=body.username,
        email=body.email,
        hashed_password=hash_password(body.password),
        role=body.role,
        is_active=True,
    )
    session.add(user)
    await session.flush()

    await audit_record(
        session,
        actor=actor.username,
        actor_ip=client_ip,
        operation="CreateUser",
        result="Success",
        details={"new_user": body.username, "role": body.role},
    )

    return _to_user_summary(user)


# ---------------------------------------------------------------------------
# GET /users
# ---------------------------------------------------------------------------


@router.get(
    "/users",
    response_model=list[UserSummary],
    summary="List all user accounts",
)
async def list_users(
    session: AsyncSession = Depends(get_db),
    actor: User = Depends(require_permission(Permission.USER_READ)),
) -> list[UserSummary]:
    result = await session.execute(select(User).order_by(User.created_at.desc()))
    users: list[User] = list(result.scalars().all())
    return [_to_user_summary(u) for u in users]


# ---------------------------------------------------------------------------
# PUT /users/{uid}/role
# ---------------------------------------------------------------------------


@router.put(
    "/users/{uid}/role",
    response_model=UserSummary,
    summary="Change a user's role",
    responses={404: {"description": "User not found"}},
)
async def update_user_role(
    uid: str,
    body: UpdateRoleRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
    actor: User = Depends(require_permission(Permission.USER_WRITE)),
    client_ip: str = Depends(get_client_ip),
) -> UserSummary:
    # Validate role
    try:
        Role(body.role)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown role '{body.role}'. Valid roles: {[r.value for r in Role]}",
        )

    result = await session.execute(select(User).where(User.id == uid))
    user: User | None = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    old_role = user.role
    user.role = body.role
    session.add(user)

    await audit_record(
        session,
        actor=actor.username,
        actor_ip=client_ip,
        operation="UpdateUserRole",
        result="Success",
        details={"target_user": user.username, "old_role": old_role, "new_role": body.role},
    )

    return _to_user_summary(user)


# ---------------------------------------------------------------------------
# DELETE /users/{uid}
# ---------------------------------------------------------------------------


@router.delete(
    "/users/{uid}",
    response_model=MessageResponse,
    summary="Deactivate a user account (soft delete)",
    responses={
        404: {"description": "User not found"},
        409: {"description": "User is already deactivated"},
    },
)
async def deactivate_user(
    uid: str,
    request: Request,
    session: AsyncSession = Depends(get_db),
    actor: User = Depends(require_permission(Permission.USER_WRITE)),
    client_ip: str = Depends(get_client_ip),
) -> MessageResponse:
    result = await session.execute(select(User).where(User.id == uid))
    user: User | None = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is already deactivated",
        )

    # Prevent self-deactivation
    if user.id == actor.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot deactivate your own account",
        )

    user.is_active = False
    session.add(user)

    await audit_record(
        session,
        actor=actor.username,
        actor_ip=client_ip,
        operation="DeactivateUser",
        result="Success",
        details={"target_user": user.username},
    )

    return MessageResponse(message=f"User '{user.username}' deactivated")


# ---------------------------------------------------------------------------
# GET /hsm/status
# ---------------------------------------------------------------------------


@router.get(
    "/hsm/status",
    summary="Query HSM health and KEK status",
)
async def hsm_status(
    actor: User = Depends(require_permission(Permission.SYS_HSM)),
) -> dict:
    try:
        hsm = await get_hsm()
        return await hsm.status()
    except Exception as exc:
        logger.error("HSM status check failed: %s", exc)
        return {
            "token_label": None,
            "slot_id": None,
            "mechanism_count": 0,
            "kek_present": False,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Overall system health — database, HSM, and KMIP server",
)
async def health_check(
    session: AsyncSession = Depends(get_db),
) -> HealthResponse:
    """Public health endpoint (no authentication required for liveness checks).

    Returns component statuses: ``ok`` or ``error: <message>``.
    """
    # --- Database ---
    db_status: str
    try:
        await session.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as exc:
        logger.error("DB health check failed: %s", exc)
        db_status = f"error: {exc}"

    # --- HSM ---
    hsm_status: str
    try:
        hsm = await get_hsm()
        hsm_info = await hsm.status()
        if hsm_info.get("kek_present"):
            hsm_status = "ok"
        else:
            hsm_status = "degraded: KEK not found"
    except Exception as exc:
        logger.error("HSM health check failed: %s", exc)
        hsm_status = f"error: {exc}"

    # --- KMIP server (check TCP reachability on configured port) ---
    from kms.config import settings
    import asyncio

    kmip_status: str
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(settings.kmip_host if settings.kmip_host != "0.0.0.0" else "127.0.0.1", settings.kmip_port),
            timeout=2.0,
        )
        writer.close()
        await writer.wait_closed()
        kmip_status = "ok"
    except asyncio.TimeoutError:
        kmip_status = "error: connection timeout"
    except OSError as exc:
        kmip_status = f"error: {exc}"

    overall = "ok" if all(s == "ok" for s in (db_status, hsm_status, kmip_status)) else "degraded"

    return HealthResponse(
        status=overall,
        database=db_status,
        hsm=hsm_status,
        kmip_server=kmip_status,
    )
