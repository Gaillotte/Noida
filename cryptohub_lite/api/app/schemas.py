"""
Response models, so /api/docs shows the shape of every endpoint.

Before these, 27 of 28 operations documented their response as a bare ``{}``:
Swagger showed "successful response" and nothing about the JSON, and a client
generator produced untyped stubs. The request side was already modelled; this
is the other half.

**Every field here was read from the live API**, not inferred from the code
that builds it. A response model is a promise to the caller, and FastAPI
*enforces* it — a field declared here but absent at run time becomes a 500, and
an undeclared field is silently dropped from the response. A guessed schema is
therefore worse than none, so where a payload is genuinely open-ended it is
typed as such rather than invented.

That is why several models below carry loose types:

* ``by_state`` / ``by_algorithm`` are keyed by whatever states and algorithms
  exist in the store, so they are ``Dict[str, int]`` rather than a fixed shape.
* Audit rows are merged from two tables with different columns
  (see :mod:`app.audit_view`), so the row model marks the union and allows the
  rest.
* Anything nullable in the store is ``Optional`` here, because a key that was
  never revoked has no revocation date and returning ``null`` is correct.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class KMIPObject(BaseModel):
    """A managed object as the portal sees it.

    Enum columns are rendered to names (``state``) as well as numbers
    (``state_value``) by ``KmipService.render``, so a caller does not need the
    KMIP enumeration tables to display one.
    """
    # Extra keys are allowed rather than rejected: the renderer gains fields as
    # the engine gains attributes, and a strict model would turn that into a
    # 500 on the next sync.
    model_config = ConfigDict(extra="allow")

    uid: str = Field(description="KMIP Unique Identifier")
    object_type: Optional[str] = Field(None, description="e.g. SymmetricKey, PrivateKey")
    object_type_value: Optional[int] = Field(None, description="the KMIP enum value")
    state: Optional[str] = Field(None, description="PreActive, Active, Deactivated, …")
    state_value: Optional[int] = None
    algorithm: Optional[str] = Field(None, description="e.g. AES, RSA, EC")
    length: Optional[int] = Field(None, description="key length in bits")
    owner: Optional[str] = Field(None, description="identity that created it")
    sensitive: Optional[bool] = None
    extractable: Optional[bool] = None
    archived: Optional[bool] = None
    initial_date: Optional[str] = None
    activation_date: Optional[str] = None
    deactivation_date: Optional[str] = None
    destroy_date: Optional[str] = None
    compromise_date: Optional[str] = None
    revocation_reason: Optional[str] = None
    usage_mask: Optional[List[str]] = Field(None, description="PKCS#11 usage flags")
    created_at: Optional[str] = None
    name: Optional[str] = Field(None, description="first KMIP Name attribute, if any")
    cka_id: Optional[str] = Field(None, description="PKCS#11 CKA_ID on the token")


class KMIPObjectDetail(KMIPObject):
    """One object, with the parts only the detail view needs."""
    attributes: Optional[List[Dict[str, Any]]] = Field(
        None, description="raw KMIP attributes: attr_name, attr_index, attr_value")
    grants: Optional[List[Dict[str, Any]]] = Field(
        None, description="delegated access: grantee, permission")


class CreatedObject(BaseModel):
    """What a create returns: enough to address the new object, nothing more."""
    uid: str
    name: Optional[str] = None


class CreatedKeyPair(BaseModel):
    private_uid: str
    public_uid: str
    name: Optional[str] = None
    model_config = ConfigDict(extra="allow")


class Detail(BaseModel):
    """A plain acknowledgement, used where there is nothing else to say."""
    detail: str


class HSMHealth(BaseModel):
    available: bool = Field(description="False when the token could not be opened")
    library: Optional[str] = Field(None, description="path to the PKCS#11 module")
    token: Optional[str] = Field(None, description="token label")
    error: Optional[str] = Field(None, description="why it is unavailable, if it is")


class Health(BaseModel):
    status: str
    database: str = Field(description="postgresql or sqlite")
    hsm_available: bool


class Dashboard(BaseModel):
    total_objects: int
    total_keys: int
    active_keys: int
    symmetric_keys: int
    private_keys: int
    public_keys: int
    certificates: int
    secret_data: int
    by_state: Dict[str, int] = Field(description="counts keyed by state name")
    by_algorithm: Dict[str, int] = Field(description="counts keyed by algorithm name")
    pkcs11_objects: int
    hsm: HSMHealth
    model_config = ConfigDict(extra="allow")


class Slot(BaseModel):
    slot_id: int
    description: Optional[str] = None
    manufacturer: Optional[str] = None
    has_token: bool
    token: Optional[Dict[str, Any]] = Field(None, description="token details when present")


class Role(BaseModel):
    name: str
    description: str
    capabilities: List[str]


class User(BaseModel):
    """A portal account. Never carries password_hash or password_salt —
    ``PortalStore._public_user`` strips both before the row leaves the store."""
    model_config = ConfigDict(extra="allow")
    username: str
    display_name: Optional[str] = None
    email: Optional[str] = None
    role: str
    enabled: Optional[bool] = None
    created_at: Optional[float] = None
    last_login: Optional[float] = None


class AuditEvent(BaseModel):
    """One row of the merged trail.

    Portal rows and engine rows come from different tables, so the union is
    declared and anything else is allowed through.
    """
    model_config = ConfigDict(extra="allow")
    occurred_at: Optional[float] = None
    occurred_at_iso: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    action: str
    object_uid: Optional[str] = None
    provider: Optional[str] = None
    result: str
    detail: Optional[str] = None
    source: Optional[str] = Field(
        None, description="'portal' or 'kmip' — which log the row came from")


class AuditPage(BaseModel):
    total: int = Field(description="size of the whole trail, not of this page")
    events: List[AuditEvent]


class AuditChain(BaseModel):
    """Whether the engine's hash-chained log verifies. Only the KMIP half is
    chained; the portal's own table is not."""
    model_config = ConfigDict(extra="allow")
    ok: Optional[bool] = Field(None, description="null when it could not be checked")
    entries: Optional[int] = None
    broken_at: Optional[int] = Field(None, description="seq of the first bad row")
    detail: Optional[str] = None


class RestBinding(BaseModel):
    """Where a KMIP operation is reachable from in this REST API."""
    method: str
    path: str
    kind: str = Field(description="'invokes' — the handler runs; "
                                  "'equivalent' — reads the store directly")


class OperationEntry(BaseModel):
    name: str
    rest: List[RestBinding] = Field(
        default_factory=list,
        description="empty when the operation is reachable only over KMIP on 5696")


class OperationGroup(BaseModel):
    title: str
    description: str
    operations: List[OperationEntry]


class SupportedOperations(BaseModel):
    """What the engine implements, read from the dispatcher's handler table."""
    implemented: List[str]
    deferred: List[str] = Field(description="defined by KMIP but not built here")
    implemented_count: int
    total: int
    groups: List[OperationGroup]
    deferred_reason: Optional[str] = None
    rest_index: Optional[Dict[str, List[RestBinding]]] = None
    rest_reachable_count: Optional[int] = Field(
        None, description="how many implemented operations this REST API exposes")


class LifecycleResult(BaseModel):
    """The outcome of Activate, Revoke, ReKey or Destroy.

    `result` is whatever the engine handler returned — for ReKey that is the
    replacement key's identifier, so it is not always a status word.
    """
    uid: str = Field(description="the object the action was applied to")
    action: str = Field(description="Activate, Revoke, ReKey or Destroy")
    result: Optional[Any] = None
