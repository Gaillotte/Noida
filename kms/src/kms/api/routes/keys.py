"""Key and managed-object routes.

Prefix: /api/v1/keys
"""
from __future__ import annotations

import base64
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kms.api.deps import get_client_ip, get_current_user, require_permission
from kms.api.schemas import (
    ActivateRequest,
    CreateKeyPairRequest,
    CreateKeyPairResponse,
    CreateSymmetricKeyRequest,
    DestroyRequest,
    KeyValueResponse,
    LocateRequest,
    ManagedObjectDetail,
    ManagedObjectSummary,
    MessageResponse,
    RegisterObjectRequest,
    RekeyRequest,
    RevokeRequest,
)
from kms.audit.logger import record as audit_record
from kms.auth.rbac import Permission
from kms.core.manager import KeyManager, LocateFilter
from kms.db.models import ManagedObject, User
from kms.db.session import get_db

logger = logging.getLogger(__name__)
router = APIRouter()

# Module-level singleton — initialized once on first import.
key_manager = KeyManager()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _summarize(obj: ManagedObject) -> ManagedObjectSummary:
    """Map a ``ManagedObject`` ORM instance to a summary response schema."""
    return ManagedObjectSummary(
        id=obj.id,
        object_type=obj.object_type,
        state=obj.state,
        algorithm=obj.cryptographic_algorithm,
        length=obj.cryptographic_length,
        usage_mask=obj.cryptographic_usage_mask,
        initial_date=obj.initial_date,
        last_change_date=obj.last_change_date,
        names=[n.name_value for n in obj.names],
        object_group=obj.object_group,
    )


def _detail(obj: ManagedObject) -> ManagedObjectDetail:
    """Map a ``ManagedObject`` ORM instance to a detailed response schema."""
    return ManagedObjectDetail(
        id=obj.id,
        object_type=obj.object_type,
        state=obj.state,
        algorithm=obj.cryptographic_algorithm,
        length=obj.cryptographic_length,
        usage_mask=obj.cryptographic_usage_mask,
        initial_date=obj.initial_date,
        last_change_date=obj.last_change_date,
        names=[n.name_value for n in obj.names],
        object_group=obj.object_group,
        activation_date=obj.activation_date,
        deactivation_date=obj.deactivation_date,
        destroy_date=obj.destroy_date,
        compromise_date=obj.compromise_date,
        revocation_reason=obj.revocation_reason,
        links=[
            {"link_type": lnk.link_type, "linked_id": lnk.linked_id}
            for lnk in obj.links
        ],
        app_info=[
            {"namespace": ai.namespace, "value": ai.value}
            for ai in obj.app_info
        ],
        extra_attrs=obj.extra_attrs or {},
    )


async def _get_object_or_404(uid: str, session: AsyncSession) -> ManagedObject:
    result = await session.execute(
        select(ManagedObject).where(ManagedObject.id == uid)
    )
    obj: ManagedObject | None = result.scalar_one_or_none()
    if obj is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Object not found")
    return obj


# ---------------------------------------------------------------------------
# POST /symmetric
# ---------------------------------------------------------------------------


@router.post(
    "/symmetric",
    response_model=ManagedObjectSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new symmetric key",
)
async def create_symmetric_key(
    body: CreateSymmetricKeyRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.KEY_CREATE)),
    client_ip: str = Depends(get_client_ip),
) -> ManagedObjectSummary:
    try:
        obj: ManagedObject = await key_manager.create_symmetric_key(
            session=session,
            algorithm=body.algorithm,
            length=body.length,
            usage_mask=body.usage_mask,
            names=body.names,
            object_group=body.object_group,
            activation_date=body.activation_date,
            deactivation_date=body.deactivation_date,
            owner=user.username,
            extra_attrs=body.extra_attrs,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to create symmetric key")
        await audit_record(
            session,
            actor=user.username,
            actor_ip=client_ip,
            operation="Create",
            result="Failure",
            result_reason=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Key creation failed")

    await audit_record(
        session,
        actor=user.username,
        actor_ip=client_ip,
        operation="Create",
        object_id=obj.id,
        result="Success",
        details={"algorithm": body.algorithm, "length": body.length},
    )
    return _summarize(obj)


# ---------------------------------------------------------------------------
# POST /keypair
# ---------------------------------------------------------------------------


@router.post(
    "/keypair",
    response_model=CreateKeyPairResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an asymmetric key pair",
)
async def create_key_pair(
    body: CreateKeyPairRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.KEY_CREATE)),
    client_ip: str = Depends(get_client_ip),
) -> CreateKeyPairResponse:
    try:
        private_obj, public_obj = await key_manager.create_key_pair(
            session=session,
            algorithm=body.algorithm,
            length=body.length,
            curve=body.curve,
            private_usage_mask=body.private_usage_mask,
            public_usage_mask=body.public_usage_mask,
            names=body.names,
            object_group=body.object_group,
            owner=user.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to create key pair")
        await audit_record(
            session,
            actor=user.username,
            actor_ip=client_ip,
            operation="CreateKeyPair",
            result="Failure",
            result_reason=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Key pair creation failed")

    await audit_record(
        session,
        actor=user.username,
        actor_ip=client_ip,
        operation="CreateKeyPair",
        object_id=private_obj.id,
        result="Success",
        details={
            "algorithm": body.algorithm,
            "private_key_id": private_obj.id,
            "public_key_id": public_obj.id,
        },
    )
    return CreateKeyPairResponse(
        private_key_unique_identifier=private_obj.id,
        public_key_unique_identifier=public_obj.id,
    )


# ---------------------------------------------------------------------------
# POST /register
# ---------------------------------------------------------------------------


@router.post(
    "/register",
    response_model=ManagedObjectSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Import / register an existing managed object",
)
async def register_object(
    body: RegisterObjectRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.KEY_IMPORT)),
    client_ip: str = Depends(get_client_ip),
) -> ManagedObjectSummary:
    # Decode optional base64 key material
    key_material: bytes | None = None
    if body.key_material_b64:
        try:
            key_material = base64.b64decode(body.key_material_b64)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="key_material_b64 is not valid base64",
            )

    try:
        obj: ManagedObject = await key_manager.register_object(
            session=session,
            object_type=body.object_type,
            algorithm=body.algorithm,
            length=body.length,
            usage_mask=body.usage_mask,
            key_material=key_material,
            certificate_pem=body.certificate_pem,
            secret_value=body.secret_value,
            names=body.names,
            object_group=body.object_group,
            owner=user.username,
            extra_attrs=body.extra_attrs,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to register object")
        await audit_record(
            session,
            actor=user.username,
            actor_ip=client_ip,
            operation="Register",
            result="Failure",
            result_reason=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Registration failed")

    await audit_record(
        session,
        actor=user.username,
        actor_ip=client_ip,
        operation="Register",
        object_id=obj.id,
        result="Success",
        details={"object_type": body.object_type},
    )
    return _summarize(obj)


# ---------------------------------------------------------------------------
# GET /
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=list[ManagedObjectSummary],
    summary="List / locate managed objects",
)
async def locate_objects(
    object_type: str | None = Query(None),
    state: str | None = Query(None),
    algorithm: str | None = Query(None),
    object_group: str | None = Query(None),
    name: str | None = Query(None),
    max_items: int = Query(100, ge=1, le=1000),
    offset_items: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.KEY_READ)),
) -> list[ManagedObjectSummary]:
    locate_filter = LocateFilter(
        object_type=object_type,
        state=state,
        algorithm=algorithm,
        object_group=object_group,
        name=name,
        max_items=max_items,
        offset_items=offset_items,
    )
    objects: list[ManagedObject] = await key_manager.locate_objects(session=session, filter=locate_filter)
    return [_summarize(obj) for obj in objects]


# ---------------------------------------------------------------------------
# GET /{uid}
# ---------------------------------------------------------------------------


@router.get(
    "/{uid}",
    response_model=ManagedObjectDetail,
    summary="Retrieve detailed attributes of a managed object",
    responses={404: {"description": "Object not found"}},
)
async def get_object(
    uid: str,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.KEY_READ)),
) -> ManagedObjectDetail:
    obj = await _get_object_or_404(uid, session)
    return _detail(obj)


# ---------------------------------------------------------------------------
# GET /{uid}/value
# ---------------------------------------------------------------------------


@router.get(
    "/{uid}/value",
    response_model=KeyValueResponse,
    summary="Export raw key material (requires KEY_EXPORT)",
    responses={
        404: {"description": "Object not found"},
        409: {"description": "Object is not in an exportable state"},
    },
)
async def get_key_value(
    uid: str,
    request: Request,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.KEY_EXPORT)),
    client_ip: str = Depends(get_client_ip),
) -> KeyValueResponse:
    obj = await _get_object_or_404(uid, session)

    if obj.state not in ("Active", "Pre-Active"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot export key in state '{obj.state}'",
        )

    try:
        key_material: bytes = await key_manager.get_key_material(session=session, obj=obj)
    except Exception as exc:
        logger.exception("Failed to export key material for %s", uid)
        await audit_record(
            session,
            actor=user.username,
            actor_ip=client_ip,
            operation="Get",
            object_id=uid,
            result="Failure",
            result_reason=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Export failed")

    await audit_record(
        session,
        actor=user.username,
        actor_ip=client_ip,
        operation="Get",
        object_id=uid,
        result="Success",
    )
    return KeyValueResponse(
        unique_identifier=uid,
        key_material_b64=base64.b64encode(key_material).decode(),
    )


# ---------------------------------------------------------------------------
# POST /{uid}/activate
# ---------------------------------------------------------------------------


@router.post(
    "/{uid}/activate",
    response_model=MessageResponse,
    summary="Activate a Pre-Active managed object",
    responses={
        404: {"description": "Object not found"},
        409: {"description": "Object is not in Pre-Active state"},
    },
)
async def activate_object(
    uid: str,
    request: Request,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.KEY_ACTIVATE)),
    client_ip: str = Depends(get_client_ip),
) -> MessageResponse:
    obj = await _get_object_or_404(uid, session)

    if obj.state != "Pre-Active":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot activate object in state '{obj.state}'",
        )

    try:
        await key_manager.activate(session=session, obj=obj)
    except Exception as exc:
        logger.exception("Failed to activate object %s", uid)
        await audit_record(
            session,
            actor=user.username,
            actor_ip=client_ip,
            operation="Activate",
            object_id=uid,
            result="Failure",
            result_reason=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Activation failed")

    await audit_record(
        session,
        actor=user.username,
        actor_ip=client_ip,
        operation="Activate",
        object_id=uid,
        result="Success",
    )
    return MessageResponse(message=f"Object {uid} activated")


# ---------------------------------------------------------------------------
# POST /{uid}/revoke
# ---------------------------------------------------------------------------


@router.post(
    "/{uid}/revoke",
    response_model=MessageResponse,
    summary="Revoke an Active managed object",
    responses={
        404: {"description": "Object not found"},
        409: {"description": "Object cannot be revoked in its current state"},
    },
)
async def revoke_object(
    uid: str,
    body: RevokeRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.KEY_REVOKE)),
    client_ip: str = Depends(get_client_ip),
) -> MessageResponse:
    obj = await _get_object_or_404(uid, session)

    if obj.state not in ("Active", "Pre-Active", "Deactivated"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot revoke object in state '{obj.state}'",
        )

    try:
        await key_manager.revoke(
            session=session,
            obj=obj,
            reason=body.reason,
            message=body.message,
        )
    except Exception as exc:
        logger.exception("Failed to revoke object %s", uid)
        await audit_record(
            session,
            actor=user.username,
            actor_ip=client_ip,
            operation="Revoke",
            object_id=uid,
            result="Failure",
            result_reason=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Revocation failed")

    await audit_record(
        session,
        actor=user.username,
        actor_ip=client_ip,
        operation="Revoke",
        object_id=uid,
        result="Success",
        details={"reason": body.reason, "message": body.message},
    )
    return MessageResponse(message=f"Object {uid} revoked")


# ---------------------------------------------------------------------------
# POST /{uid}/destroy
# ---------------------------------------------------------------------------


@router.post(
    "/{uid}/destroy",
    response_model=MessageResponse,
    summary="Destroy a managed object (irreversible)",
    responses={
        404: {"description": "Object not found"},
        409: {"description": "Object must be Deactivated or Compromised before destruction"},
    },
)
async def destroy_object(
    uid: str,
    request: Request,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.KEY_DESTROY)),
    client_ip: str = Depends(get_client_ip),
) -> MessageResponse:
    obj = await _get_object_or_404(uid, session)

    if obj.state not in ("Deactivated", "Compromised", "Pre-Active"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Object must be Deactivated or Compromised before destruction (current state: '{obj.state}')",
        )

    try:
        await key_manager.destroy(session=session, obj=obj)
    except Exception as exc:
        logger.exception("Failed to destroy object %s", uid)
        await audit_record(
            session,
            actor=user.username,
            actor_ip=client_ip,
            operation="Destroy",
            object_id=uid,
            result="Failure",
            result_reason=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Destroy failed")

    await audit_record(
        session,
        actor=user.username,
        actor_ip=client_ip,
        operation="Destroy",
        object_id=uid,
        result="Success",
    )
    return MessageResponse(message=f"Object {uid} destroyed")


# ---------------------------------------------------------------------------
# POST /{uid}/rekey
# ---------------------------------------------------------------------------


@router.post(
    "/{uid}/rekey",
    response_model=ManagedObjectSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Rotate (re-key) a symmetric key — creates a new version",
    responses={
        404: {"description": "Object not found"},
        409: {"description": "Object must be Active to be re-keyed"},
    },
)
async def rekey_object(
    uid: str,
    request: Request,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.KEY_ROTATE)),
    client_ip: str = Depends(get_client_ip),
) -> ManagedObjectSummary:
    obj = await _get_object_or_404(uid, session)

    if obj.state != "Active":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Only Active objects can be re-keyed (current state: '{obj.state}')",
        )

    try:
        new_obj: ManagedObject = await key_manager.rekey(session=session, obj=obj, owner=user.username)
    except Exception as exc:
        logger.exception("Failed to rekey object %s", uid)
        await audit_record(
            session,
            actor=user.username,
            actor_ip=client_ip,
            operation="Rekey",
            object_id=uid,
            result="Failure",
            result_reason=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Rekey failed")

    await audit_record(
        session,
        actor=user.username,
        actor_ip=client_ip,
        operation="Rekey",
        object_id=uid,
        result="Success",
        details={"new_object_id": new_obj.id},
    )
    return _summarize(new_obj)
