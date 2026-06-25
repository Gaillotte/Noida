"""
Key lifecycle manager — the heart of the KMS.

``KeyManager`` implements all KMIP-aligned lifecycle operations: create,
register, locate, get, activate, revoke, destroy, rekey, and attribute
management.  All methods are ``async`` and accept an ``AsyncSession`` from
SQLAlchemy.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from kms.core import crypto
from kms.core.hsm import get_hsm
from kms.db.models import AppSpecificInfo, ManagedObject, ObjectLink, ObjectName

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uid() -> str:
    return str(uuid4())


# ---------------------------------------------------------------------------
# LocateFilter
# ---------------------------------------------------------------------------


@dataclass
class LocateFilter:
    """Filter criteria for :meth:`KeyManager.locate_objects`."""

    object_type: str | None = None
    state: str | None = None
    algorithm: str | None = None
    object_group: str | None = None
    name: str | None = None
    activated_after: datetime | None = None
    deactivated_before: datetime | None = None
    max_items: int = 100
    offset_items: int = 0


# ---------------------------------------------------------------------------
# KeyManager
# ---------------------------------------------------------------------------


class KeyManager:
    """High-level key lifecycle operations (KMIP-aligned).

    Each method accepts an open ``AsyncSession`` and commits / flushes
    as needed.  Callers are responsible for the outer transaction boundary.
    """

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _load_obj(
        self,
        session: AsyncSession,
        uid: str,
        *,
        with_relationships: bool = False,
    ) -> ManagedObject | None:
        """Load a :class:`ManagedObject` by primary key with optional eager
        loading of names, links, and app_info."""
        if with_relationships:
            stmt = (
                select(ManagedObject)
                .where(ManagedObject.id == uid)
                .options(
                    selectinload(ManagedObject.names),
                    selectinload(ManagedObject.links),
                    selectinload(ManagedObject.app_info),
                )
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()
        return await session.get(ManagedObject, uid)

    async def _wrap_and_store(
        self,
        session: AsyncSession,
        obj: ManagedObject,
        key_material: bytes,
    ) -> None:
        """Wrap *key_material* with the HSM KEK and attach the envelope to *obj*."""
        hsm = await get_hsm()
        ciphertext, iv, tag = await hsm.wrap_key(key_material)
        obj.encrypted_value = ciphertext
        obj.value_iv = iv
        obj.value_tag = tag

    @staticmethod
    def _apply_names(obj: ManagedObject, names: list[dict] | None) -> None:
        """Append :class:`ObjectName` rows to *obj* from the provided list."""
        if not names:
            return
        for entry in names:
            obj.names.append(
                ObjectName(
                    object_id=obj.id,
                    name_value=entry.get("value", ""),
                    name_type=entry.get("type", "Uninterpreted"),
                )
            )

    @staticmethod
    def _apply_app_info(obj: ManagedObject, app_info: list[dict] | None) -> None:
        """Append :class:`AppSpecificInfo` rows to *obj*."""
        if not app_info:
            return
        for entry in app_info:
            obj.app_info.append(
                AppSpecificInfo(
                    object_id=obj.id,
                    namespace=entry.get("namespace", ""),
                    value=entry.get("value", ""),
                )
            )

    # ------------------------------------------------------------------
    # Create symmetric key
    # ------------------------------------------------------------------

    async def create_symmetric_key(
        self,
        session: AsyncSession,
        *,
        algorithm: str,
        length: int,
        usage_mask: int,
        names: list[dict] | None = None,
        object_group: str | None = None,
        activation_date: datetime | None = None,
        deactivation_date: datetime | None = None,
        owner: str | None = None,
        app_info: list[dict] | None = None,
        extra_attrs: dict | None = None,
    ) -> ManagedObject:
        """Generate a new symmetric key and store it in the KMS.

        Steps
        -----
        1. Generate key material in software.
        2. Wrap it with the HSM KEK.
        3. Persist a :class:`ManagedObject` row with the encrypted envelope.
        4. If ``activation_date`` is ``None`` or in the past, set state to
           ``"Active"``; otherwise set it to ``"Pre-Active"``.

        Returns the newly created :class:`ManagedObject`.
        """
        algorithm_upper = algorithm.upper()

        # Generate key material
        if algorithm_upper in ("AES",):
            key_material = crypto.generate_aes_key(length)
        elif algorithm_upper in ("CHACHA20", "CHACHA20-POLY1305"):
            if length != 256:
                raise ValueError("ChaCha20 requires a 256-bit key.")
            key_material = crypto.generate_random(32)
        else:
            # Generic: generate raw random bytes for the requested length
            key_material = crypto.generate_random(length // 8)

        now = _utcnow()
        if activation_date is None or activation_date <= now:
            state = "Active"
            effective_activation = activation_date or now
        else:
            state = "Pre-Active"
            effective_activation = activation_date

        obj = ManagedObject(
            id=_new_uid(),
            object_type="SymmetricKey",
            state=state,
            cryptographic_algorithm=algorithm_upper,
            cryptographic_length=length,
            cryptographic_usage_mask=usage_mask,
            key_format_type="Raw",
            object_group=object_group,
            activation_date=effective_activation if state == "Active" else None,
            deactivation_date=deactivation_date,
            initial_date=now,
            last_change_date=now,
            owner=owner,
            in_hsm=False,
            extra_attrs=extra_attrs or {},
        )

        # Wrap key material and attach envelope
        await self._wrap_and_store(session, obj, key_material)

        # Attach names and app info
        self._apply_names(obj, names)
        self._apply_app_info(obj, app_info)

        session.add(obj)
        await session.flush()

        logger.info(
            "Created SymmetricKey id=%s alg=%s len=%d state=%s",
            obj.id, algorithm_upper, length, state,
        )
        # Reload with relationships to avoid lazy-load issues in async context
        return await self._load_obj(session, obj.id, with_relationships=True)

    # ------------------------------------------------------------------
    # Create key pair
    # ------------------------------------------------------------------

    async def create_key_pair(
        self,
        session: AsyncSession,
        *,
        algorithm: str,
        length: int | None = None,
        curve: str | None = None,
        private_usage_mask: int,
        public_usage_mask: int,
        names: list[dict] | None = None,
        object_group: str | None = None,
        owner: str | None = None,
        extra_attrs: dict | None = None,
    ) -> tuple[ManagedObject, ManagedObject]:
        """Generate an asymmetric key pair and store both halves in the KMS.

        Returns
        -------
        (private_key_obj, public_key_obj)
        """
        algorithm_upper = algorithm.upper()
        now = _utcnow()

        if algorithm_upper == "RSA":
            if length is None:
                raise ValueError("RSA key generation requires 'length'.")
            private_der, public_der = crypto.generate_rsa_key_pair(length)
            key_format = "PKCS8"
            crypto_length = length
        elif algorithm_upper == "EC":
            if curve is None:
                raise ValueError("EC key generation requires 'curve'.")
            private_der, public_der = crypto.generate_ec_key_pair(curve)
            key_format = "PKCS8"
            # Derive length from curve name for common curves
            _curve_len = {
                "P-192": 192, "P-256": 256, "P-384": 384,
                "P-521": 521, "secp256k1": 256,
            }
            crypto_length = _curve_len.get(curve, 0)
        elif algorithm_upper == "ED25519":
            private_der, public_der = crypto.generate_ed25519_key_pair()
            key_format = "PKCS8"
            crypto_length = 256
        elif algorithm_upper == "ED448":
            private_der, public_der = crypto.generate_ed448_key_pair()
            key_format = "PKCS8"
            crypto_length = 448
        else:
            raise ValueError(
                f"Unsupported algorithm '{algorithm}'. "
                "Supported: RSA, EC, Ed25519, Ed448."
            )

        priv_id = _new_uid()
        pub_id = _new_uid()

        private_obj = ManagedObject(
            id=priv_id,
            object_type="PrivateKey",
            state="Active",
            cryptographic_algorithm=algorithm_upper,
            cryptographic_length=crypto_length,
            cryptographic_usage_mask=private_usage_mask,
            key_format_type=key_format,
            object_group=object_group,
            activation_date=now,
            initial_date=now,
            last_change_date=now,
            owner=owner,
            in_hsm=False,
            extra_attrs=extra_attrs or {},
        )
        public_obj = ManagedObject(
            id=pub_id,
            object_type="PublicKey",
            state="Active",
            cryptographic_algorithm=algorithm_upper,
            cryptographic_length=crypto_length,
            cryptographic_usage_mask=public_usage_mask,
            key_format_type="X509",
            object_group=object_group,
            activation_date=now,
            initial_date=now,
            last_change_date=now,
            owner=owner,
            in_hsm=False,
            extra_attrs=extra_attrs or {},
        )

        # Wrap private key
        await self._wrap_and_store(session, private_obj, private_der)

        # Public key stored unencrypted as certificate_value (DER) for easy retrieval
        public_obj.certificate_value = public_der

        # Apply names to both
        self._apply_names(private_obj, names)
        self._apply_names(public_obj, names)

        # Cross-links
        private_obj.links.append(
            ObjectLink(source_id=priv_id, link_type="PublicKey", linked_id=pub_id)
        )
        public_obj.links.append(
            ObjectLink(source_id=pub_id, link_type="PrivateKey", linked_id=priv_id)
        )

        session.add(private_obj)
        session.add(public_obj)
        await session.flush()

        logger.info(
            "Created key pair alg=%s private_id=%s public_id=%s",
            algorithm_upper, priv_id, pub_id,
        )
        priv = await self._load_obj(session, priv_id, with_relationships=True)
        pub = await self._load_obj(session, pub_id, with_relationships=True)
        return priv, pub

    # ------------------------------------------------------------------
    # Register (import)
    # ------------------------------------------------------------------

    async def register_object(
        self,
        session: AsyncSession,
        *,
        object_type: str,
        algorithm: str | None,
        length: int | None,
        usage_mask: int,
        key_material: bytes | None = None,
        key_format: str = "Raw",
        certificate_value: bytes | None = None,
        names: list[dict] | None = None,
        object_group: str | None = None,
        owner: str | None = None,
        extra_attrs: dict | None = None,
    ) -> ManagedObject:
        """Import an existing object into the KMS.

        Symmetric keys and private keys are wrapped before storage.
        Certificates and public keys are stored in plaintext.
        """
        now = _utcnow()
        obj = ManagedObject(
            id=_new_uid(),
            object_type=object_type,
            state="Active",
            cryptographic_algorithm=algorithm.upper() if algorithm else None,
            cryptographic_length=length,
            cryptographic_usage_mask=usage_mask,
            key_format_type=key_format,
            object_group=object_group,
            activation_date=now,
            initial_date=now,
            last_change_date=now,
            owner=owner,
            in_hsm=False,
            extra_attrs=extra_attrs or {},
        )

        if object_type == "Certificate":
            obj.certificate_value = certificate_value
            obj.certificate_type = "X.509"
        elif object_type == "PublicKey":
            # Public keys stored as-is (DER)
            obj.certificate_value = key_material or certificate_value
        elif key_material is not None:
            # SymmetricKey, PrivateKey, SecretData — wrap before storage
            await self._wrap_and_store(session, obj, key_material)
        else:
            raise ValueError(
                f"object_type='{object_type}' requires key_material or certificate_value."
            )

        self._apply_names(obj, names)

        session.add(obj)
        await session.flush()

        logger.info("Registered %s id=%s", object_type, obj.id)
        return await self._load_obj(session, obj.id, with_relationships=True)

    # ------------------------------------------------------------------
    # Retrieve
    # ------------------------------------------------------------------

    async def get_object(
        self,
        session: AsyncSession,
        uid: str,
        *,
        include_value: bool = False,
    ) -> ManagedObject | None:
        """Load a :class:`ManagedObject` by UID.

        If *include_value* is ``True`` and the object has an encrypted
        envelope, decrypt it and set the transient attribute
        ``obj._decrypted_value``.
        """
        obj = await self._load_obj(session, uid, with_relationships=True)
        if obj is None:
            return None

        if include_value and obj.encrypted_value is not None:
            hsm = await get_hsm()
            plaintext = await hsm.unwrap_key(
                obj.encrypted_value, obj.value_iv, obj.value_tag
            )
            # Transient attribute — not mapped to any column
            obj._decrypted_value = plaintext  # type: ignore[attr-defined]

        return obj

    async def get_key_material(self, session: AsyncSession, uid: str) -> bytes:
        """Return raw key bytes for a managed object.

        Raises
        ------
        ValueError
            If the object is not found, is in state ``Destroyed``, or has no
            available key material.
        """
        obj = await self._load_obj(session, uid)
        if obj is None:
            raise ValueError(f"Object '{uid}' not found.")
        if obj.state in ("Destroyed", "Destroyed Compromised"):
            raise ValueError(
                f"Object '{uid}' is in state '{obj.state}'; key material is gone."
            )

        # Public key / certificate stored in certificate_value
        if obj.object_type in ("PublicKey", "Certificate") and obj.certificate_value:
            return obj.certificate_value

        if obj.encrypted_value is None:
            raise ValueError(
                f"Object '{uid}' has no key material (in_hsm={obj.in_hsm})."
            )

        hsm = await get_hsm()
        return await hsm.unwrap_key(obj.encrypted_value, obj.value_iv, obj.value_tag)

    # ------------------------------------------------------------------
    # Locate
    # ------------------------------------------------------------------

    async def locate_objects(
        self,
        session: AsyncSession,
        f: LocateFilter,
        owner: str | None = None,
    ) -> list[str]:
        """Return a list of UIDs matching *f* (and optionally restricted to *owner*)."""
        conditions = []

        if f.object_type:
            conditions.append(ManagedObject.object_type == f.object_type)
        if f.state:
            conditions.append(ManagedObject.state == f.state)
        if f.algorithm:
            conditions.append(
                ManagedObject.cryptographic_algorithm == f.algorithm.upper()
            )
        if f.object_group:
            conditions.append(ManagedObject.object_group == f.object_group)
        if owner:
            conditions.append(ManagedObject.owner == owner)
        if f.activated_after:
            conditions.append(ManagedObject.activation_date >= f.activated_after)
        if f.deactivated_before:
            conditions.append(ManagedObject.deactivation_date <= f.deactivated_before)

        if f.name:
            # Join to ObjectName to filter by name_value
            stmt = (
                select(ManagedObject.id)
                .join(ObjectName, ObjectName.object_id == ManagedObject.id)
                .where(and_(*conditions, ObjectName.name_value == f.name))
                .offset(f.offset_items)
                .limit(f.max_items)
            )
        else:
            stmt = (
                select(ManagedObject.id)
                .where(and_(*conditions) if conditions else True)
                .offset(f.offset_items)
                .limit(f.max_items)
            )

        result = await session.execute(stmt)
        return [row[0] for row in result.fetchall()]

    # ------------------------------------------------------------------
    # Attributes
    # ------------------------------------------------------------------

    async def get_attributes(
        self,
        session: AsyncSession,
        uid: str,
        attribute_names: list[str] | None = None,
    ) -> dict[str, Any]:
        """Return KMIP attribute name → value for the object.

        If *attribute_names* is ``None``, all attributes are returned.
        """
        obj = await self._load_obj(session, uid, with_relationships=True)
        if obj is None:
            raise ValueError(f"Object '{uid}' not found.")

        all_attrs: dict[str, Any] = {
            "Unique Identifier": obj.id,
            "Object Type": obj.object_type,
            "State": obj.state,
            "Cryptographic Algorithm": obj.cryptographic_algorithm,
            "Cryptographic Length": obj.cryptographic_length,
            "Cryptographic Usage Mask": obj.cryptographic_usage_mask,
            "Key Format Type": obj.key_format_type,
            "Initial Date": obj.initial_date.isoformat() if obj.initial_date else None,
            "Last Change Date": obj.last_change_date.isoformat() if obj.last_change_date else None,
            "Activation Date": obj.activation_date.isoformat() if obj.activation_date else None,
            "Deactivation Date": (
                obj.deactivation_date.isoformat() if obj.deactivation_date else None
            ),
            "Destroy Date": obj.destroy_date.isoformat() if obj.destroy_date else None,
            "Compromise Date": (
                obj.compromise_date.isoformat() if obj.compromise_date else None
            ),
            "Object Group": obj.object_group,
            "Name": [
                {"value": n.name_value, "type": n.name_type} for n in obj.names
            ],
            "Link": [
                {"type": lk.link_type, "linked_object_identifier": lk.linked_id}
                for lk in obj.links
            ],
            "Application Specific Information": [
                {"namespace": ai.namespace, "value": ai.value} for ai in obj.app_info
            ],
            "Revocation Reason": obj.revocation_reason,
            "Revocation Message": obj.revocation_message,
            "Owner": obj.owner,
            "In HSM": obj.in_hsm,
        }

        # Merge any extra / custom attributes
        if obj.extra_attrs:
            all_attrs.update(obj.extra_attrs)

        if attribute_names is None:
            return all_attrs

        return {k: all_attrs[k] for k in attribute_names if k in all_attrs}

    async def set_attribute(
        self,
        session: AsyncSession,
        uid: str,
        name: str,
        value: Any,
    ) -> None:
        """Set a standard or custom attribute on an object.

        Standard KMIP attributes (``Object Group``, ``Deactivation Date``,
        ``Contact Information``, etc.) are written to the appropriate column.
        Unknown attributes go into ``extra_attrs``.
        """
        obj = await self._load_obj(session, uid)
        if obj is None:
            raise ValueError(f"Object '{uid}' not found.")

        _standard_setters: dict[str, str] = {
            "Object Group": "object_group",
            "Deactivation Date": "deactivation_date",
            "Activation Date": "activation_date",
            "Contact Information": "contact_information",
            "Revocation Reason": "revocation_reason",
            "Revocation Message": "revocation_message",
            "Owner": "owner",
            "Cryptographic Usage Mask": "cryptographic_usage_mask",
        }

        if name in _standard_setters:
            setattr(obj, _standard_setters[name], value)
        else:
            attrs = dict(obj.extra_attrs or {})
            attrs[name] = value
            obj.extra_attrs = attrs

        obj.last_change_date = _utcnow()
        await session.flush()

    # ------------------------------------------------------------------
    # Name management
    # ------------------------------------------------------------------

    async def add_name(
        self,
        session: AsyncSession,
        uid: str,
        name_value: str,
        name_type: str = "Uninterpreted",
    ) -> None:
        """Add a name to an existing object."""
        obj = await self._load_obj(session, uid, with_relationships=True)
        if obj is None:
            raise ValueError(f"Object '{uid}' not found.")
        obj.names.append(
            ObjectName(object_id=uid, name_value=name_value, name_type=name_type)
        )
        obj.last_change_date = _utcnow()
        await session.flush()

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    async def activate(self, session: AsyncSession, uid: str) -> ManagedObject:
        """Transition ``Pre-Active`` → ``Active``.

        Sets ``activation_date`` to now if it is not already set.
        Raises ``ValueError`` if the object is not in ``Pre-Active`` state.
        """
        obj = await self._load_obj(session, uid)
        if obj is None:
            raise ValueError(f"Object '{uid}' not found.")
        if obj.state != "Pre-Active":
            raise ValueError(
                f"Cannot activate object '{uid}': current state is '{obj.state}' "
                "(expected 'Pre-Active')."
            )
        now = _utcnow()
        obj.state = "Active"
        if obj.activation_date is None:
            obj.activation_date = now
        obj.last_change_date = now
        await session.flush()
        logger.info("Activated object id=%s", uid)
        return obj

    async def revoke(
        self,
        session: AsyncSession,
        uid: str,
        *,
        reason: str = "Unspecified",
        message: str = "",
        compromise_date: datetime | None = None,
    ) -> ManagedObject:
        """Revoke an active or pre-active object.

        If *reason* contains the word ``"Compromise"`` (case-insensitive) the
        new state is ``"Compromised"``; otherwise it is ``"Deactivated"``.

        Raises ``ValueError`` if the current state does not permit revocation.
        """
        obj = await self._load_obj(session, uid)
        if obj is None:
            raise ValueError(f"Object '{uid}' not found.")
        if obj.state not in ("Active", "Pre-Active"):
            raise ValueError(
                f"Cannot revoke object '{uid}': current state is '{obj.state}'."
            )

        now = _utcnow()
        is_compromise = "compromise" in reason.lower()
        obj.state = "Compromised" if is_compromise else "Deactivated"
        obj.deactivation_date = obj.deactivation_date or now
        obj.revocation_reason = reason
        obj.revocation_message = message
        if is_compromise:
            obj.compromise_date = compromise_date or now
        obj.last_change_date = now
        await session.flush()

        logger.info(
            "Revoked object id=%s new_state=%s reason=%s", uid, obj.state, reason
        )
        return obj

    async def destroy(self, session: AsyncSession, uid: str) -> ManagedObject:
        """Destroy a deactivated, compromised, or pre-active object.

        Clears the encrypted key material.  The row is retained for audit
        purposes but the key material is irrecoverably gone.

        Raises ``ValueError`` if the object cannot be destroyed in its current
        state.
        """
        obj = await self._load_obj(session, uid)
        if obj is None:
            raise ValueError(f"Object '{uid}' not found.")
        if obj.state not in ("Deactivated", "Compromised", "Pre-Active"):
            raise ValueError(
                f"Cannot destroy object '{uid}': current state is '{obj.state}'. "
                "Object must be Deactivated, Compromised, or Pre-Active first."
            )

        now = _utcnow()
        new_state = (
            "Destroyed Compromised" if obj.state == "Compromised" else "Destroyed"
        )
        obj.state = new_state
        obj.destroy_date = now
        obj.last_change_date = now

        # Erase key material
        obj.encrypted_value = None
        obj.value_iv = None
        obj.value_tag = None
        obj.certificate_value = None
        obj.in_hsm = False

        await session.flush()
        logger.info("Destroyed object id=%s new_state=%s", uid, new_state)
        return obj

    async def archive(self, session: AsyncSession, uid: str) -> ManagedObject:
        """Mark an object as archived.

        Sets ``archive_date`` on the object.  The object remains ``Active``
        but is flagged as archived in its ``extra_attrs``.
        """
        obj = await self._load_obj(session, uid)
        if obj is None:
            raise ValueError(f"Object '{uid}' not found.")

        now = _utcnow()
        obj.archive_date = now
        obj.last_change_date = now

        # Also record in extra_attrs for KMIP attribute querying
        attrs = dict(obj.extra_attrs or {})
        attrs["Archive Date"] = now.isoformat()
        obj.extra_attrs = attrs

        await session.flush()
        logger.info("Archived object id=%s", uid)
        return obj

    # ------------------------------------------------------------------
    # Rekey
    # ------------------------------------------------------------------

    async def rekey(
        self,
        session: AsyncSession,
        uid: str,
        *,
        owner: str | None = None,
    ) -> ManagedObject:
        """Create a new version of the key at *uid*.

        Steps
        -----
        1. Load the original object and read its policy (alg, length, usage).
        2. Generate a fresh key with the same parameters.
        3. Link old → new (``Next``) and new → old (``Previous``).
        4. Deactivate the old key (revoke with reason "Superseded").
        5. Return the new :class:`ManagedObject`.

        Only symmetric keys are currently supported for rekey.  Asymmetric
        key pairs should use :meth:`create_key_pair` directly.
        """
        old = await self._load_obj(session, uid, with_relationships=True)
        if old is None:
            raise ValueError(f"Object '{uid}' not found.")
        if old.state != "Active":
            raise ValueError(
                f"Cannot rekey object '{uid}': state is '{old.state}' (expected 'Active')."
            )
        if old.object_type != "SymmetricKey":
            raise ValueError(
                f"rekey() currently supports SymmetricKey only (got '{old.object_type}')."
            )

        # Create new key with same parameters
        new_obj = await self.create_symmetric_key(
            session,
            algorithm=old.cryptographic_algorithm or "AES",
            length=old.cryptographic_length or 256,
            usage_mask=old.cryptographic_usage_mask,
            object_group=old.object_group,
            owner=owner or old.owner,
            extra_attrs=dict(old.extra_attrs or {}),
        )

        now = _utcnow()

        # Cross-link: old → new (Next), new → old (Previous)
        old.links.append(
            ObjectLink(source_id=old.id, link_type="Next", linked_id=new_obj.id)
        )
        new_obj.links.append(
            ObjectLink(source_id=new_obj.id, link_type="Previous", linked_id=old.id)
        )

        # Deactivate the old key
        old.state = "Deactivated"
        old.deactivation_date = now
        old.revocation_reason = "Superseded"
        old.revocation_message = f"Rekeyed to {new_obj.id}"
        old.last_change_date = now

        await session.flush()

        logger.info(
            "Rekeyed object old_id=%s new_id=%s", uid, new_obj.id
        )
        return new_obj


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

key_manager: KeyManager = KeyManager()
