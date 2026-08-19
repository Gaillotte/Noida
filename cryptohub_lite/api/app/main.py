"""
IDEMIA CryptoHub Lite — REST API.

A thin service layer over the existing ``kmip_pkcs11`` package. It adds the
things the package never had — real user accounts, JWT sessions, RBAC and a
persisted audit trail — and delegates everything KMIP to the existing
implementation.
"""

import datetime
import hmac
import logging
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from kmip_pkcs11.metadata.store import MetadataStore

from . import audit_view
from .config import settings
from .kmip_identity import KmipIdentityMirror
from .kmip_service import KmipService, Pkcs11Service
from .portal_store import ROLE_DESCRIPTIONS, ROLES, PortalStore
from .security import client_ip, create_token, current_user, requires

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
log = logging.getLogger("cryptohub_lite")

app = FastAPI(
    title="IDEMIA CryptoHub Lite API",
    description="Management API over the existing KMIP/PKCS#11 platform",
    version="1.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    app.state.metadata = MetadataStore(settings.database_url)
    app.state.portal = PortalStore(settings.database_url)
    # Keeps the engine's own identity and role tables in step with portal
    # administration. The engine authenticates KMIP clients against those
    # tables itself, so a portal account that is never projected cannot use a
    # KMIP client at all.
    app.state.identities = KmipIdentityMirror(app.state.portal, app.state.metadata)
    app.state.kmip = KmipService(app.state.metadata)
    app.state.pkcs11 = Pkcs11Service(
        settings.pkcs11_library, settings.pkcs11_token, settings.pkcs11_pin
    )
    # Write operations need the PKCS#11 session. Wired here rather than in the
    # constructor so a missing HSM leaves the read paths working.
    if app.state.pkcs11.available:
        app.state.kmip.attach_shim(app.state.pkcs11.shim)

    # Seed an administrator only when there are no users at all, so this can
    # never overwrite or resurrect an account on a running system.
    if app.state.portal.count_users() == 0:
        app.state.portal.create_user(
            settings.bootstrap_admin, settings.bootstrap_password,
            role="Administrator", display_name="Bootstrap Administrator",
        )
        app.state.identities.on_password_set(
            settings.bootstrap_admin, settings.bootstrap_password, "Administrator",
        )
        log.warning(
            "Created bootstrap administrator '%s'. Change this password immediately.",
            settings.bootstrap_admin,
        )

    # Heals role drift and reports portal users the engine has no credential
    # for. Cheap, and it means an upgrade from a build that predates the engine's
    # own identity table says so at startup rather than at a client's first
    # rejected connection.
    app.state.identities.reconcile()

    log.info("CryptoHub Lite API ready (store=%s)",
             "postgresql" if app.state.metadata.is_postgres else "sqlite")


# ── models ───────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str
    display_name: str
    capabilities: List[str]
    # True when the account still uses the shipped bootstrap password. Decided
    # here, at the one moment the plaintext is legitimately in hand, rather
    # than by storing a "must change password" flag that could drift out of
    # step with the actual credential.
    using_default_password: bool = False


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8)
    role: str = "ReadOnly"
    display_name: str = ""
    email: str = ""


class UserUpdate(BaseModel):
    role: Optional[str] = None
    enabled: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=8)


# ── authentication ───────────────────────────────────────────────────────────

@app.post("/api/auth/login", response_model=LoginResponse, tags=["Authentication"])
def login(body: LoginRequest, request: Request):
    portal: PortalStore = request.app.state.portal
    user = portal.verify_password(body.username, body.password)

    if not user:
        # Recorded before raising: a failed login is exactly the event an
        # auditor needs, and it is the one case where nothing else would.
        portal.audit("auth.login", "FAILURE", username=body.username,
                     source_ip=client_ip(request), detail="Invalid credentials")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")

    portal.touch_login(user["username"])
    portal.audit("auth.login", "SUCCESS", username=user["username"],
                 source_ip=client_ip(request))

    # The engine hashes credentials separately (scrypt, against its own
    # kmip_identities table) and cannot derive one from the stored portal hash,
    # so a successful login is one of only three moments the cleartext exists.
    # For an account that already has an engine credential this is a cheap
    # existence check, not a re-derivation.
    request.app.state.identities.on_login(user["username"], body.password, user["role"])

    # Compared in constant time, and only against the known default — this
    # reveals nothing an attacker does not already have, since they just
    # supplied the password themselves.
    using_default = hmac.compare_digest(body.password, settings.bootstrap_password)
    if using_default:
        log.warning("User '%s' signed in with the default bootstrap password",
                    user["username"])

    from .security import CAPABILITIES
    return LoginResponse(
        access_token=create_token(user["username"], user["role"]),
        username=user["username"],
        role=user["role"],
        display_name=user.get("display_name") or user["username"],
        capabilities=sorted(CAPABILITIES.get(user["role"], set())),
        using_default_password=using_default,
    )


@app.get("/api/auth/me", tags=["Authentication"])
def whoami(user: Dict[str, Any] = Depends(current_user)):
    from .security import CAPABILITIES
    return {**user, "capabilities": sorted(CAPABILITIES.get(user["role"], set()))}


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


@app.post("/api/auth/password", tags=["Authentication"])
def change_own_password(body: PasswordChange, request: Request,
                        user: Dict[str, Any] = Depends(current_user)):
    """Changes the signed-in user's own password.

    Deliberately not behind ``user.manage``. That capability belongs to
    administrators, and requiring it here would mean an Operator, Auditor or
    ReadOnly user could never change their own password — leaving whatever an
    administrator first set in place indefinitely.

    The current password is re-checked even though the caller holds a valid
    token: a token may have been taken from an unattended session, and this is
    the one operation that would let it lock the real owner out.
    """
    portal: PortalStore = request.app.state.portal

    if portal.verify_password(user["username"], body.current_password) is None:
        portal.audit("auth.password_change", "FAILURE", username=user["username"],
                     source_ip=client_ip(request), detail="Current password incorrect")
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")

    if body.current_password == body.new_password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "The new password must differ from the current one")

    portal.set_password(user["username"], body.new_password)
    # Rotate the engine credential in the same breath. Skipping it would leave
    # the user's KMIP client authenticating with the old password after the
    # portal stopped accepting it.
    request.app.state.identities.on_password_set(user["username"], body.new_password)
    portal.audit("auth.password_change", "SUCCESS", username=user["username"],
                 source_ip=client_ip(request))
    return {"detail": "Password changed"}


@app.post("/api/auth/logout", tags=["Authentication"])
def logout(request: Request, user: Dict[str, Any] = Depends(current_user)):
    # JWTs are stateless, so this records the intent rather than revoking a
    # session. Saying so is better than implying a revocation that does not
    # happen; token lifetime is bounded by JWT_TTL_MINUTES.
    request.app.state.portal.audit("auth.logout", "SUCCESS",
                                   username=user["username"], source_ip=client_ip(request))
    return {"detail": "Token discarded client-side; it remains valid until expiry"}


# ── dashboard ────────────────────────────────────────────────────────────────

@app.get("/api/dashboard", tags=["Dashboard"])
def dashboard(request: Request, user: Dict[str, Any] = Depends(requires("read"))):
    kmip: KmipService = request.app.state.kmip
    pkcs11: Pkcs11Service = request.app.state.pkcs11
    portal: PortalStore = request.app.state.portal

    stats = kmip.statistics()
    day_ago = (datetime.datetime.now(datetime.timezone.utc)
               - datetime.timedelta(days=1)).timestamp()

    pkcs11_objects = pkcs11.objects()
    return {
        **stats,
        "pkcs11_objects": len(pkcs11_objects),
        "hsm": pkcs11.health(),
        "audit_events_24h": portal.count_audit(since=day_ago),
        "audit_events_total": portal.count_audit(),
        "users": len(portal.list_users()),
        "system": {
            "database": "PostgreSQL" if request.app.state.metadata.is_postgres else "SQLite",
            "kmip_version": "2.1",
            "operations_supported": 41,
        },
    }


# ── KMIP objects ─────────────────────────────────────────────────────────────

@app.get("/api/kmip/operations", tags=["KMIP"])
def kmip_operations(request: Request, user: Dict[str, Any] = Depends(requires("read"))):
    """Which KMIP operations this engine implements, and which it does not.

    Derived from the dispatcher's handler table, so the answer is the engine's
    actual capability rather than a list maintained alongside it.
    """
    return request.app.state.kmip.supported_operations()


@app.get("/api/kmip/objects", tags=["KMIP"])
def kmip_objects(request: Request, user: Dict[str, Any] = Depends(requires("read"))):
    return request.app.state.kmip.list_objects()


@app.get("/api/kmip/objects/{uid}", tags=["KMIP"])
def kmip_object(uid: str, request: Request,
                user: Dict[str, Any] = Depends(requires("read"))):
    obj = request.app.state.kmip.get_object(uid)
    if obj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No object {uid}")
    return obj


# ── KMIP write operations ────────────────────────────────────────────────────
#
# Each of these calls the existing KMIP operation handler in-process. The
# lifecycle rules — which transitions are legal, what Destroy does to key
# material — stay in the engine; this layer only authorizes, audits and
# translates. Reimplementing any of it here would create a second definition
# of the lifecycle that could drift from the one KMIP clients see.

class CreateKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    algorithm: str = "AES"
    length: int = 256
    # PKCS#11 attributes the engine sets on the token: CKA_ENCRYPT, CKA_DECRYPT,
    # CKA_WRAP, CKA_UNWRAP, CKA_SENSITIVE, CKA_EXTRACTABLE. Defaults match what
    # the API did before these were selectable, so an existing client sees no
    # change in behaviour.
    encrypt: bool = True
    decrypt: bool = True
    wrap: bool = False
    unwrap: bool = False
    sensitive: bool = True
    extractable: bool = False


class CreateKeyPairRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    algorithm: str = "RSA"
    length: int = 2048
    # Ignored for RSA and DSA. Kept on the same request rather than split into
    # two endpoints because the caller is filling in one form.
    curve: str = "P_256"
    # CKA_SIGN on the private half, CKA_VERIFY on the public one. Sensitive and
    # extractable are absent because the engine fixes them per half — private
    # sensitive and non-extractable, public neither — and accepting a value it
    # would ignore is worse than not offering it.
    sign: bool = True
    verify: bool = True
    derive: bool = False


class RevokeRequest(BaseModel):
    reason: str = "CessationOfOperation"
    message: str = ""


@app.post("/api/kmip/objects", status_code=status.HTTP_201_CREATED, tags=["KMIP"])
def create_key(body: CreateKeyRequest, request: Request,
               user: Dict[str, Any] = Depends(requires("key.create"))):
    service: KmipService = request.app.state.kmip
    portal: PortalStore = request.app.state.portal
    try:
        uid = service.create_symmetric_key(
            body.name, body.algorithm, body.length, owner=user["username"],
            encrypt=body.encrypt, decrypt=body.decrypt,
            wrap=body.wrap, unwrap=body.unwrap,
            sensitive=body.sensitive, extractable=body.extractable,
        )
    except Exception as exc:                    # noqa: BLE001
        portal.audit("kmip.Create", "FAILURE", username=user["username"],
                     source_ip=client_ip(request), provider="KMIP", detail=str(exc))
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    portal.audit("kmip.Create", "SUCCESS", username=user["username"],
                 source_ip=client_ip(request), object_uid=uid, provider="KMIP",
                 detail=f"{body.algorithm}-{body.length} '{body.name}'")
    return {"uid": uid, "name": body.name}


@app.post("/api/kmip/keypairs", status_code=status.HTTP_201_CREATED, tags=["KMIP"])
def create_key_pair(body: CreateKeyPairRequest, request: Request,
                    user: Dict[str, Any] = Depends(requires("key.create"))):
    """Creates an asymmetric key pair, producing two linked managed objects."""
    service: KmipService = request.app.state.kmip
    portal: PortalStore = request.app.state.portal
    try:
        pair = service.create_key_pair(
            body.name, body.algorithm, body.length, body.curve,
            owner=user["username"], sign=body.sign, verify=body.verify,
            derive=body.derive,
        )
    except Exception as exc:                    # noqa: BLE001
        portal.audit("kmip.CreateKeyPair", "FAILURE", username=user["username"],
                     source_ip=client_ip(request), provider="KMIP", detail=str(exc))
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    # The private key is the one that matters for custody, so it is the object
    # the audit record points at; the public half is named in the detail.
    detail = f"{body.algorithm} '{body.name}', public {pair['public_uid']}"
    portal.audit("kmip.CreateKeyPair", "SUCCESS", username=user["username"],
                 source_ip=client_ip(request), object_uid=pair["private_uid"],
                 provider="KMIP", detail=detail)
    return {**pair, "name": body.name}


@app.post("/api/kmip/objects/{uid}/activate", tags=["KMIP"])
def activate_object(uid: str, request: Request,
                    user: Dict[str, Any] = Depends(requires("key.lifecycle"))):
    return _lifecycle_action(request, user, uid, "Activate")


@app.post("/api/kmip/objects/{uid}/revoke", tags=["KMIP"])
def revoke_object(uid: str, body: RevokeRequest, request: Request,
                  user: Dict[str, Any] = Depends(requires("key.lifecycle"))):
    return _lifecycle_action(request, user, uid, "Revoke",
                             reason=body.reason, message=body.message)


@app.post("/api/kmip/objects/{uid}/rekey", tags=["KMIP"])
def rekey_object(uid: str, request: Request,
                 user: Dict[str, Any] = Depends(requires("key.lifecycle"))):
    return _lifecycle_action(request, user, uid, "ReKey")


@app.delete("/api/kmip/objects/{uid}", tags=["KMIP"])
def destroy_object(uid: str, request: Request,
                   user: Dict[str, Any] = Depends(requires("key.destroy"))):
    return _lifecycle_action(request, user, uid, "Destroy")


def _lifecycle_action(request: Request, user: Dict[str, Any], uid: str,
                      action: str, **kwargs):
    """Runs one lifecycle operation and records the outcome either way.

    Failures are audited as well as successes: a refused Destroy is exactly
    the event worth keeping, and auditing only what succeeded would hide
    every attempt that was denied.
    """
    service: KmipService = request.app.state.kmip
    portal: PortalStore = request.app.state.portal

    try:
        result = service.lifecycle(uid, action, owner=user["username"], **kwargs)
    except Exception as exc:                    # noqa: BLE001
        portal.audit(f"kmip.{action}", "FAILURE", username=user["username"],
                     source_ip=client_ip(request), object_uid=uid,
                     provider="KMIP", detail=str(exc))
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    portal.audit(f"kmip.{action}", "SUCCESS", username=user["username"],
                 source_ip=client_ip(request), object_uid=uid, provider="KMIP",
                 detail=kwargs.get("reason"))
    return {"uid": uid, "action": action, "result": result}


@app.get("/api/certificates", tags=["Certificates"])
def certificates(request: Request, user: Dict[str, Any] = Depends(requires("read"))):
    """Certificate objects with validity parsed, soonest to expire first."""
    return request.app.state.kmip.certificates()


@app.get("/api/keys", tags=["Keys"])
def keys(request: Request, user: Dict[str, Any] = Depends(requires("read")),
         kind: Optional[str] = Query(None, description="SymmetricKey, PrivateKey, PublicKey, Certificate")):
    objects = request.app.state.kmip.list_objects()
    if kind:
        objects = [o for o in objects if o["object_type"] == kind]
    return objects


# ── PKCS#11 explorer ─────────────────────────────────────────────────────────

@app.get("/api/pkcs11/health", tags=["PKCS#11"])
def pkcs11_health(request: Request, user: Dict[str, Any] = Depends(requires("read"))):
    return request.app.state.pkcs11.health()


@app.get("/api/pkcs11/slots", tags=["PKCS#11"])
def pkcs11_slots(request: Request, user: Dict[str, Any] = Depends(requires("read"))):
    return request.app.state.pkcs11.slots()


@app.get("/api/pkcs11/objects", tags=["PKCS#11"])
def pkcs11_objects(request: Request, user: Dict[str, Any] = Depends(requires("read"))):
    return request.app.state.pkcs11.objects()


# ── audit ────────────────────────────────────────────────────────────────────

@app.get("/api/audit", tags=["Audit"])
def audit(request: Request,
          user: Dict[str, Any] = Depends(requires("audit")),
          limit: int = Query(200, le=1000), offset: int = 0,
          username: Optional[str] = None, action: Optional[str] = None,
          result: Optional[str] = None):
    """The audit trail: portal actions and KMIP operations in one list.

    They are two logs — the portal's own table, and the engine's hash-chained
    ``kmip_audit`` — merged on read. See :mod:`app.audit_view` for why they are
    not merged on write.
    """
    return audit_view.list_events(
        request.app.state.portal, request.app.state.metadata,
        limit=limit, offset=offset, username=username, action=action, result=result,
    )


@app.get("/api/audit/verify", tags=["Audit"])
def audit_verify(request: Request, user: Dict[str, Any] = Depends(requires("audit"))):
    """Whether the KMIP audit log's hash chain is intact.

    Only the engine's log is chained; the portal's own table is not, so this
    reports on the KMIP half and says so.
    """
    return audit_view.verify(request.app.state.metadata)


@app.get("/api/audit/export", tags=["Audit"])
def audit_export(request: Request, fmt: str = Query("csv", pattern="^(csv|json|excel)$"),
                 user: Dict[str, Any] = Depends(requires("audit.export"))):
    portal: PortalStore = request.app.state.portal
    limit = 100_000
    (payload, media_type, filename), total = audit_view.export(
        portal, request.app.state.metadata, fmt, limit=limit)

    # Exporting the audit trail is itself auditable — otherwise the one action
    # that copies the whole record out of the system leaves no trace. The record
    # names the bound when one applied, so a truncated export is not mistaken
    # for a complete one later.
    truncated = f", truncated to {limit} of {total} events" if total > limit else ""
    portal.audit("audit.export", "SUCCESS", username=user["username"],
                 source_ip=client_ip(request), detail=f"format={fmt}{truncated}")

    return Response(content=payload, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ── administration ───────────────────────────────────────────────────────────

@app.get("/api/admin/users", tags=["Administration"])
def list_users(request: Request, user: Dict[str, Any] = Depends(requires("user.manage"))):
    return request.app.state.portal.list_users()


@app.get("/api/admin/roles", tags=["Administration"])
def list_roles(user: Dict[str, Any] = Depends(requires("read"))):
    from .security import CAPABILITIES
    return [
        {"name": role, "description": ROLE_DESCRIPTIONS[role],
         "capabilities": sorted(CAPABILITIES.get(role, set()))}
        for role in ROLES
    ]


@app.post("/api/admin/users", status_code=status.HTTP_201_CREATED, tags=["Administration"])
def create_user(body: UserCreate, request: Request,
                user: Dict[str, Any] = Depends(requires("user.manage"))):
    portal: PortalStore = request.app.state.portal
    if portal.get_user(body.username):
        raise HTTPException(status.HTTP_409_CONFLICT, "That username already exists")
    try:
        created = portal.create_user(body.username, body.password, body.role,
                                     body.display_name, body.email)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    # Provision the engine credential now, while the cleartext is in hand. This
    # is the only moment it can be done for a user who never signs in to the
    # portal and only ever uses a KMIP client.
    request.app.state.identities.on_password_set(body.username, body.password, body.role)

    portal.audit("user.create", "SUCCESS", username=user["username"],
                 source_ip=client_ip(request),
                 detail=f"created {body.username} as {body.role}")
    return portal._public_user(dict(created))


@app.patch("/api/admin/users/{username}", tags=["Administration"])
def update_user(username: str, body: UserUpdate, request: Request,
                user: Dict[str, Any] = Depends(requires("user.manage"))):
    portal: PortalStore = request.app.state.portal
    if not portal.get_user(username):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such user")

    # Each change is mirrored into the engine's own tables as it is made. The
    # engine decides KMIP access from those, so a change applied only to the
    # portal would leave the user's KMIP client on the old role, the old
    # password, or still working after the account was disabled.
    identities: KmipIdentityMirror = request.app.state.identities

    changes = []
    if body.role is not None:
        try:
            portal.set_role(username, body.role)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
        identities.on_role_changed(username, body.role)
        changes.append(f"role={body.role}")
    if body.enabled is not None:
        # Locking yourself out is easy to do and tedious to undo, so the one
        # account that cannot be disabled here is your own.
        if username == user["username"] and not body.enabled:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                "You cannot disable your own account")
        portal.set_enabled(username, body.enabled)
        identities.on_enabled_changed(username, body.enabled)
        changes.append(f"enabled={body.enabled}")
    if body.password is not None:
        portal.set_password(username, body.password)
        identities.on_password_set(username, body.password)
        changes.append("password reset")

    portal.audit("user.update", "SUCCESS", username=user["username"],
                 source_ip=client_ip(request), detail=f"{username}: {', '.join(changes)}")
    return portal.get_user(username) and portal._public_user(portal.get_user(username))


@app.delete("/api/admin/users/{username}", tags=["Administration"])
def delete_user(username: str, request: Request,
                user: Dict[str, Any] = Depends(requires("user.manage"))):
    portal: PortalStore = request.app.state.portal
    if username == user["username"]:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot delete your own account")
    if not portal.get_user(username):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such user")

    portal.delete_user(username)
    # Otherwise the engine credential outlives the account it belonged to, and
    # the deleted user's KMIP client keeps authenticating.
    request.app.state.identities.on_deleted(username)
    portal.audit("user.delete", "SUCCESS", username=user["username"],
                 source_ip=client_ip(request), detail=f"deleted {username}")
    return {"detail": f"Deleted {username}"}


@app.get("/api/health", tags=["System"])
def health(request: Request):
    """Unauthenticated liveness probe for Docker and the portal's login page."""
    return {
        "status": "ok",
        "database": "postgresql" if request.app.state.metadata.is_postgres else "sqlite",
        "hsm_available": request.app.state.pkcs11.available,
    }
