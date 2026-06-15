"""Pydantic v2 request / response schemas for the KMS REST API."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class MeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    email: str | None
    role: str
    mfa_enabled: bool


class MfaEnableResponse(BaseModel):
    totp_secret: str
    totp_uri: str
    qr_data_uri: str


class MfaVerifyRequest(BaseModel):
    totp_code: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


# ---------------------------------------------------------------------------
# Managed Objects — create
# ---------------------------------------------------------------------------


class CreateSymmetricKeyRequest(BaseModel):
    algorithm: str = "AES"
    length: int = 256
    usage_mask: int = 0x0C  # Encrypt | Decrypt
    names: list[dict[str, Any]] = Field(default_factory=list)
    object_group: str | None = None
    activation_date: datetime | None = None
    deactivation_date: datetime | None = None
    extra_attrs: dict[str, Any] = Field(default_factory=dict)


class CreateKeyPairRequest(BaseModel):
    algorithm: str = "RSA"   # RSA, EC, Ed25519, Ed448
    length: int | None = 2048    # for RSA
    curve: str | None = "P-256"  # for EC
    private_usage_mask: int = 0x01   # Sign
    public_usage_mask: int = 0x02    # Verify
    names: list[dict[str, Any]] = Field(default_factory=list)
    object_group: str | None = None


class RegisterObjectRequest(BaseModel):
    object_type: str  # SymmetricKey, Certificate, SecretData, etc.
    algorithm: str | None = None
    length: int | None = None
    usage_mask: int = 0
    key_material_b64: str | None = None   # base64-encoded raw key bytes
    certificate_pem: str | None = None
    secret_value: str | None = None       # for SecretData
    names: list[dict[str, Any]] = Field(default_factory=list)
    object_group: str | None = None
    extra_attrs: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Managed Objects — responses
# ---------------------------------------------------------------------------


class ManagedObjectSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    object_type: str
    state: str
    algorithm: str | None
    length: int | None
    usage_mask: int
    initial_date: datetime
    last_change_date: datetime
    names: list[str]
    object_group: str | None


class ManagedObjectDetail(ManagedObjectSummary):
    activation_date: datetime | None
    deactivation_date: datetime | None
    destroy_date: datetime | None
    compromise_date: datetime | None
    revocation_reason: str | None
    links: list[dict[str, Any]]
    app_info: list[dict[str, Any]]
    extra_attrs: dict[str, Any]


class KeyValueResponse(BaseModel):
    unique_identifier: str
    key_material_b64: str  # base64-encoded


class CreateKeyPairResponse(BaseModel):
    private_key_unique_identifier: str
    public_key_unique_identifier: str


# ---------------------------------------------------------------------------
# Locate
# ---------------------------------------------------------------------------


class LocateRequest(BaseModel):
    object_type: str | None = None
    state: str | None = None
    algorithm: str | None = None
    object_group: str | None = None
    name: str | None = None
    max_items: int = 100
    offset_items: int = 0


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class ActivateRequest(BaseModel):
    unique_identifier: str


class RevokeRequest(BaseModel):
    unique_identifier: str
    reason: str = "Unspecified"
    message: str = ""


class DestroyRequest(BaseModel):
    unique_identifier: str


class RekeyRequest(BaseModel):
    unique_identifier: str


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------


class EnrollClientRequest(BaseModel):
    name: str
    client_type: str = "application"
    object_group: str | None = None
    access_policy: str = "default"
    notes: str | None = None


class ClientSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    client_type: str
    object_group: str | None
    access_policy: str
    is_active: bool
    created_at: datetime
    last_seen: datetime | None


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "reader"
    email: str | None = None


class UpdateRoleRequest(BaseModel):
    role: str


class UserSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    role: str
    email: str | None
    is_active: bool
    created_at: datetime


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    actor: str
    actor_ip: str | None
    protocol: str
    operation: str
    object_id: str | None
    result: str
    result_reason: str | None
    details: dict[str, Any] | None


class AuditQueryRequest(BaseModel):
    actor: str | None = None
    operation: str | None = None
    result: str | None = None
    object_id: str | None = None
    from_dt: datetime | None = None
    to_dt: datetime | None = None
    limit: int = 100
    offset: int = 0


class AuditStatsResponse(BaseModel):
    total: int
    by_operation: dict[str, int]
    by_result: dict[str, int]
    window_hours: int = 24


# ---------------------------------------------------------------------------
# Generic
# ---------------------------------------------------------------------------


class MessageResponse(BaseModel):
    message: str


class ErrorResponse(BaseModel):
    detail: str


class HealthResponse(BaseModel):
    status: str
    database: str
    hsm: str
    kmip_server: str
    version: str = "1.0.0"
