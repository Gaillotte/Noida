"""Authentication and user-profile routes.

Prefix: /api/v1/auth
"""
from __future__ import annotations

import base64
import logging
import urllib.parse

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kms.api.deps import get_client_ip, get_current_user
from kms.api.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    MeResponse,
    MfaEnableResponse,
    MfaVerifyRequest,
    MessageResponse,
    TokenResponse,
)
from kms.audit.logger import record as audit_record
from kms.auth.jwt_handler import (
    create_access_token,
    hash_password,
    verify_password,
)
from kms.db.models import User
from kms.db.session import get_db

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# POST /login
# ---------------------------------------------------------------------------


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive a JWT",
    responses={401: {"description": "Invalid credentials"}},
)
async def login(
    body: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
    client_ip: str = Depends(get_client_ip),
) -> TokenResponse:
    """Verify username + password (and optional TOTP), return a signed JWT."""
    result = await session.execute(select(User).where(User.username == body.username))
    user: User | None = result.scalar_one_or_none()

    def _fail(reason: str = "Invalid username or password") -> None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=reason)

    if user is None or not user.is_active:
        # Record failed attempt without leaking whether user exists
        await audit_record(
            session,
            actor=body.username,
            actor_ip=client_ip,
            operation="Login",
            result="Failure",
            result_reason="Unknown user or inactive account",
        )
        _fail()

    if not verify_password(body.password, user.hashed_password):
        await audit_record(
            session,
            actor=body.username,
            actor_ip=client_ip,
            operation="Login",
            result="Failure",
            result_reason="Wrong password",
        )
        _fail()

    # TOTP check — required only when MFA is enabled for this account
    if user.mfa_enabled:
        if not body.totp_code:
            await audit_record(
                session,
                actor=body.username,
                actor_ip=client_ip,
                operation="Login",
                result="Failure",
                result_reason="TOTP code required",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA is enabled — totp_code is required",
            )
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(body.totp_code, valid_window=1):
            await audit_record(
                session,
                actor=body.username,
                actor_ip=client_ip,
                operation="Login",
                result="Failure",
                result_reason="Invalid TOTP code",
            )
            _fail("Invalid TOTP code")

    # Issue token
    access_token = create_access_token({"sub": user.username, "role": user.role})

    from datetime import datetime, timezone
    user.last_login = datetime.now(timezone.utc)
    session.add(user)

    await audit_record(
        session,
        actor=user.username,
        actor_ip=client_ip,
        operation="Login",
        result="Success",
    )

    return TokenResponse(
        access_token=access_token,
        role=user.role,
        username=user.username,
    )


# ---------------------------------------------------------------------------
# GET /me
# ---------------------------------------------------------------------------


@router.get(
    "/me",
    response_model=MeResponse,
    summary="Return the authenticated user's profile",
)
async def get_me(current_user: User = Depends(get_current_user)) -> MeResponse:
    return MeResponse.model_validate(current_user)


# ---------------------------------------------------------------------------
# POST /me/mfa/enable
# ---------------------------------------------------------------------------


@router.post(
    "/me/mfa/enable",
    response_model=MfaEnableResponse,
    summary="Generate a new TOTP secret; returns provisioning URI and QR code",
)
async def mfa_enable(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    client_ip: str = Depends(get_client_ip),
) -> MfaEnableResponse:
    """Generate a random TOTP secret and persist it (not yet activated).

    The client must call ``POST /me/mfa/verify`` with a valid code to actually
    enable MFA on the account.
    """
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.username,
        issuer_name="KMS",
    )

    # Store secret immediately so /me/mfa/verify can look it up,
    # but keep mfa_enabled=False until the user verifies a code.
    current_user.mfa_secret = secret
    session.add(current_user)

    # Return the provisioning URI as a data URI so clients can render a QR code
    # using any standard TOTP authenticator app or QR library of their choice.
    qr_data_uri = (
        "data:text/plain;base64,"
        + base64.b64encode(provisioning_uri.encode()).decode()
    )

    await audit_record(
        session,
        actor=current_user.username,
        actor_ip=client_ip,
        operation="MFAEnable",
        result="Success",
    )

    return MfaEnableResponse(
        totp_secret=secret,
        totp_uri=provisioning_uri,
        qr_data_uri=qr_data_uri,
    )


# ---------------------------------------------------------------------------
# POST /me/mfa/verify
# ---------------------------------------------------------------------------


@router.post(
    "/me/mfa/verify",
    response_model=MessageResponse,
    summary="Verify TOTP code and activate MFA on the account",
)
async def mfa_verify(
    body: MfaVerifyRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    client_ip: str = Depends(get_client_ip),
) -> MessageResponse:
    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No MFA secret found — call POST /me/mfa/enable first",
        )

    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(body.totp_code, valid_window=1):
        await audit_record(
            session,
            actor=current_user.username,
            actor_ip=client_ip,
            operation="MFAVerify",
            result="Failure",
            result_reason="Invalid TOTP code",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code",
        )

    current_user.mfa_enabled = True
    session.add(current_user)

    await audit_record(
        session,
        actor=current_user.username,
        actor_ip=client_ip,
        operation="MFAVerify",
        result="Success",
    )

    return MessageResponse(message="MFA enabled successfully")


# ---------------------------------------------------------------------------
# POST /me/password
# ---------------------------------------------------------------------------


@router.post(
    "/me/password",
    response_model=MessageResponse,
    summary="Change the authenticated user's password",
)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    client_ip: str = Depends(get_client_ip),
) -> MessageResponse:
    if not verify_password(body.current_password, current_user.hashed_password):
        await audit_record(
            session,
            actor=current_user.username,
            actor_ip=client_ip,
            operation="ChangePassword",
            result="Failure",
            result_reason="Wrong current password",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    if len(body.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="New password must be at least 8 characters",
        )

    current_user.hashed_password = hash_password(body.new_password)
    session.add(current_user)

    await audit_record(
        session,
        actor=current_user.username,
        actor_ip=client_ip,
        operation="ChangePassword",
        result="Success",
    )

    return MessageResponse(message="Password changed successfully")
