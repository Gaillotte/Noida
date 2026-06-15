"""KMIP client management routes.

Prefix: /api/v1/clients
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kms.api.deps import get_client_ip, require_permission
from kms.api.schemas import ClientSummary, EnrollClientRequest, MessageResponse
from kms.audit.logger import record as audit_record
from kms.auth.rbac import Permission
from kms.db.models import KmipClient, User
from kms.db.session import get_db

logger = logging.getLogger(__name__)
router = APIRouter()


def _to_summary(client: KmipClient) -> ClientSummary:
    return ClientSummary.model_validate(client)


# ---------------------------------------------------------------------------
# POST /
# ---------------------------------------------------------------------------


@router.post(
    "/",
    response_model=ClientSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Enroll a new KMIP client",
)
async def enroll_client(
    body: EnrollClientRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.CLIENT_ENROLL)),
    client_ip: str = Depends(get_client_ip),
) -> ClientSummary:
    # Check for duplicate name
    existing = await session.execute(
        select(KmipClient).where(KmipClient.name == body.name)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A client named '{body.name}' already exists",
        )

    client = KmipClient(
        name=body.name,
        client_type=body.client_type,
        object_group=body.object_group,
        access_policy=body.access_policy,
        notes=body.notes,
        enrolled_by=user.username,
        is_active=True,
    )
    session.add(client)
    await session.flush()  # assign client.id

    await audit_record(
        session,
        actor=user.username,
        actor_ip=client_ip,
        operation="EnrollClient",
        result="Success",
        details={"client_name": body.name, "client_id": client.id},
    )

    return _to_summary(client)


# ---------------------------------------------------------------------------
# GET /
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=list[ClientSummary],
    summary="List all enrolled KMIP clients",
)
async def list_clients(
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.CLIENT_READ)),
) -> list[ClientSummary]:
    result = await session.execute(select(KmipClient).order_by(KmipClient.created_at.desc()))
    clients: list[KmipClient] = list(result.scalars().all())
    return [_to_summary(c) for c in clients]


# ---------------------------------------------------------------------------
# GET /{client_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{client_id}",
    response_model=ClientSummary,
    summary="Retrieve a specific KMIP client by ID",
    responses={404: {"description": "Client not found"}},
)
async def get_client(
    client_id: str,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.CLIENT_READ)),
) -> ClientSummary:
    result = await session.execute(
        select(KmipClient).where(KmipClient.id == client_id)
    )
    client: KmipClient | None = result.scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")
    return _to_summary(client)


# ---------------------------------------------------------------------------
# DELETE /{client_id}
# ---------------------------------------------------------------------------


@router.delete(
    "/{client_id}",
    response_model=MessageResponse,
    summary="Deactivate (soft-delete) a KMIP client",
    responses={
        404: {"description": "Client not found"},
        409: {"description": "Client is already deactivated"},
    },
)
async def deactivate_client(
    client_id: str,
    request: Request,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.CLIENT_REVOKE)),
    client_ip: str = Depends(get_client_ip),
) -> MessageResponse:
    result = await session.execute(
        select(KmipClient).where(KmipClient.id == client_id)
    )
    client: KmipClient | None = result.scalar_one_or_none()

    if client is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    if not client.is_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Client is already deactivated",
        )

    client.is_active = False
    session.add(client)

    await audit_record(
        session,
        actor=user.username,
        actor_ip=client_ip,
        operation="DeactivateClient",
        result="Success",
        details={"client_name": client.name, "client_id": client_id},
    )

    return MessageResponse(message=f"Client '{client.name}' deactivated")
