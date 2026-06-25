from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import (
    Boolean, DateTime, Enum, ForeignKey, Integer,
    LargeBinary, String, Text, JSON, func
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Managed Objects (KMIP objects)
# ---------------------------------------------------------------------------

class ManagedObject(Base):
    __tablename__ = "managed_objects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    object_type: Mapped[str] = mapped_column(String(50), nullable=False)
    state: Mapped[str] = mapped_column(String(50), nullable=False, default="Pre-Active")

    # Lifecycle dates
    initial_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_change_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    activation_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deactivation_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    destroy_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    compromise_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    process_start_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    protect_stop_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    archive_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Cryptographic attributes
    cryptographic_algorithm: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    cryptographic_length: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cryptographic_usage_mask: Mapped[int] = mapped_column(Integer, default=0)
    key_format_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Certificate specific
    certificate_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    certificate_value: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)

    # Secret / key material — encrypted by KEK in HSM
    encrypted_value: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    value_iv: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)  # IV for AES-GCM
    value_tag: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)  # GCM auth tag

    # HSM-resident object reference (for keys stored directly in HSM)
    hsm_object_id: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    hsm_slot: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    in_hsm: Mapped[bool] = mapped_column(Boolean, default=False)

    # Ownership and grouping
    object_group: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    contact_information: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)

    # Revocation
    revocation_reason: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    revocation_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Extensible metadata
    extra_attrs: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)

    # Relationships
    names: Mapped[list["ObjectName"]] = relationship(
        "ObjectName", back_populates="obj", cascade="all, delete-orphan", lazy="selectin"
    )
    links: Mapped[list["ObjectLink"]] = relationship(
        "ObjectLink", foreign_keys="ObjectLink.source_id",
        back_populates="source", cascade="all, delete-orphan", lazy="selectin"
    )
    app_info: Mapped[list["AppSpecificInfo"]] = relationship(
        "AppSpecificInfo", back_populates="obj", cascade="all, delete-orphan", lazy="selectin"
    )
    audit_events: Mapped[list["AuditEvent"]] = relationship(
        "AuditEvent", back_populates="obj", lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"<ManagedObject id={self.id} type={self.object_type} state={self.state}>"


class ObjectName(Base):
    __tablename__ = "object_names"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    object_id: Mapped[str] = mapped_column(String(36), ForeignKey("managed_objects.id", ondelete="CASCADE"))
    name_value: Mapped[str] = mapped_column(String(500), nullable=False)
    name_type: Mapped[str] = mapped_column(String(50), default="Uninterpreted")

    obj: Mapped["ManagedObject"] = relationship("ManagedObject", back_populates="names")


class ObjectLink(Base):
    __tablename__ = "object_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_id: Mapped[str] = mapped_column(String(36), ForeignKey("managed_objects.id", ondelete="CASCADE"))
    link_type: Mapped[str] = mapped_column(String(50))  # Previous, Next, Replacement, Parent, Child, ...
    linked_id: Mapped[str] = mapped_column(String(36))

    source: Mapped["ManagedObject"] = relationship(
        "ManagedObject", foreign_keys=[source_id], back_populates="links"
    )


class AppSpecificInfo(Base):
    __tablename__ = "app_specific_info"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    object_id: Mapped[str] = mapped_column(String(36), ForeignKey("managed_objects.id", ondelete="CASCADE"))
    namespace: Mapped[str] = mapped_column(String(200), nullable=False)
    value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    obj: Mapped["ManagedObject"] = relationship("ManagedObject", back_populates="app_info")


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="reader")
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<User username={self.username} role={self.role}>"


# ---------------------------------------------------------------------------
# KMIP Clients (machine accounts / applications)
# ---------------------------------------------------------------------------

class KmipClient(Base):
    __tablename__ = "kmip_clients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    client_type: Mapped[str] = mapped_column(String(100), default="application")
    object_group: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    access_policy: Mapped[str] = mapped_column(String(100), default="default")
    certificate_cn: Mapped[Optional[str]] = mapped_column(String(400), nullable=True)
    certificate_serial: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    certificate_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    enrolled_by: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<KmipClient name={self.name} type={self.client_type}>"


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    actor_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), default="REST")  # REST or KMIP
    operation: Mapped[str] = mapped_column(String(100), nullable=False)
    object_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("managed_objects.id", ondelete="SET NULL"), nullable=True
    )
    result: Mapped[str] = mapped_column(String(50), default="Success")
    result_reason: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    obj: Mapped[Optional["ManagedObject"]] = relationship("ManagedObject", back_populates="audit_events")
