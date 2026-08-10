"""
Thin façade over the existing ``kmip_pkcs11`` package.

This module holds **no KMIP business logic**. Every call delegates to the
existing implementation, which remains the authoritative source for object
creation, retrieval, destruction and lifecycle. What is added here is only:

* translation between REST-friendly shapes and the package's own types
* label/enum rendering, so the portal shows "AES" rather than 3

If a behaviour looks like it belongs to KMIP, it belongs in ``kmip_pkcs11``
and should be called from here, not reimplemented.
"""

import datetime
import logging
import threading
from typing import Any, Dict, List, Optional

from kmip_pkcs11.core import enums
from kmip_pkcs11.metadata.store import MetadataStore

log = logging.getLogger(__name__)


def _name(enum_cls, value):
    """Renders an enum value as its symbolic name, falling back to the number."""
    if value is None:
        return None
    try:
        return enum_cls(value).name
    except (ValueError, KeyError):
        return str(value)


def _iso(timestamp: Optional[float]) -> Optional[str]:
    if not timestamp:
        return None
    return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).isoformat()


def _parse_certificate(der: bytes) -> Dict[str, Any]:
    """Extracts the fields the Certificates page shows from a DER certificate.

    Uses asn1crypto, already a dependency of the Certify operation, so this
    adds nothing new to the image. A certificate that will not parse is
    reported as such rather than omitted: an object the system cannot read is
    exactly what an operator needs to be told about.
    """
    try:
        from asn1crypto import x509

        certificate = x509.Certificate.load(der)
        tbs = certificate["tbs_certificate"]
        not_before = tbs["validity"]["not_before"].native
        not_after = tbs["validity"]["not_after"].native

        now = datetime.datetime.now(datetime.timezone.utc)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=datetime.timezone.utc)

        subject = tbs["subject"].human_friendly
        issuer = tbs["issuer"].human_friendly

        return {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before.isoformat() if not_before else None,
            "not_after": not_after.isoformat(),
            "days_remaining": (not_after - now).days,
            "serial": format(int(tbs["serial_number"].native), "X"),
            "self_signed": subject == issuer,
            "parse_error": None,
        }
    except Exception as exc:                    # noqa: BLE001 - see docstring
        log.warning("Certificate could not be parsed: %s", exc)
        return {"parse_error": str(exc)}


class KmipService:
    """Read and lifecycle access to KMIP managed objects."""

    def __init__(self, store: MetadataStore):
        self._store = store
        # Supplied after construction by attach_shim(); read operations work
        # without it, so the portal still functions when the HSM is down.
        self._shim = None

    # ── objects ──────────────────────────────────────────────────────────────

    def list_objects(self, owner: Optional[str] = None) -> List[Dict[str, Any]]:
        uids = self._store.list_objects()
        objects = []
        for uid in uids:
            row = self._store.get_object(uid)
            if row is None:
                continue
            if owner and row.get("owner_identity") not in (owner, None):
                continue
            objects.append(self.render(row))
        return objects

    def get_object(self, uid: str) -> Optional[Dict[str, Any]]:
        row = self._store.get_object(uid)
        if row is None:
            return None
        rendered = self.render(row)
        rendered["attributes"] = self._store.get_attributes(uid)
        rendered["grants"] = self._store.list_grants(uid)
        return rendered

    def render(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Turns a store row into the shape the portal renders.

        Enum columns are rendered to names here rather than in the UI so the
        REST API is self-describing and the PHP tier holds no KMIP knowledge.
        """
        return {
            "uid": row["uuid"],
            "object_type": _name(enums.ObjectType, row.get("object_type")),
            "object_type_value": row.get("object_type"),
            "state": _name(enums.State, row.get("state")),
            "state_value": row.get("state"),
            "algorithm": _name(enums.CryptographicAlgorithm, row.get("cryptographic_algorithm")),
            "length": row.get("cryptographic_length"),
            "owner": row.get("owner_identity"),
            "sensitive": bool(row.get("sensitive")),
            "extractable": bool(row.get("extractable")),
            "archived": bool(row.get("archived")),
            "initial_date": _iso(row.get("initial_date")),
            "activation_date": _iso(row.get("activation_date")),
            "deactivation_date": _iso(row.get("deactivation_date")),
            "destroy_date": _iso(row.get("destroy_date")),
            "compromise_date": _iso(row.get("compromise_date")),
            "revocation_reason": _name(enums.RevocationReasonCode, row.get("revocation_reason")),
            "created_at": _iso(row.get("created_at")),
            "name": self._first_name(row["uuid"]),
        }

    def _first_name(self, uid: str) -> Optional[str]:
        values = self._store.get_attribute(uid, "Name")
        if not values:
            return None
        first = values[0]
        if isinstance(first, dict):
            return first.get("value")
        return str(first)

    # ── write operations ─────────────────────────────────────────────────────
    #
    # These call the engine's own operation handlers, building the same
    # request payload a KMIP client would send. That is deliberate: the
    # handlers carry the authorization checks, the lifecycle state machine and
    # the PKCS#11 calls, so going through them means the REST API and a KMIP
    # client cannot diverge on what an operation does or who may do it.

    def attach_shim(self, shim) -> None:
        """Supplies the PKCS#11 shim needed by write operations."""
        self._shim = shim

    def create_symmetric_key(self, name: str, algorithm: str, length: int,
                             owner: str) -> str:
        from kmip_pkcs11.operations.create import create_symmetric_key

        if self._shim is None:
            raise RuntimeError("The HSM is unavailable; key creation is not possible")

        try:
            algorithm_value = int(getattr(enums.CryptographicAlgorithm, algorithm.upper()))
        except AttributeError:
            supported = ", ".join(a.name for a in enums.CryptographicAlgorithm)
            raise ValueError(f"Unsupported algorithm '{algorithm}'. Supported: {supported}")

        usage = int(enums.CryptographicUsageMask.Encrypt | enums.CryptographicUsageMask.Decrypt)

        # Calls the same helper Create and ReKey share, so a key made here is
        # indistinguishable from one made over the wire.
        return create_symmetric_key(
            algorithm_value, length, usage, [name],
            True,      # sensitive
            False,     # extractable — the HSM keeps the material
            owner, self._store, self._shim,
        )

    def lifecycle(self, uid: str, action: str, owner: str, **kwargs) -> str:
        """Runs Activate, Revoke, ReKey or Destroy through the engine handler."""
        from kmip_pkcs11.core.ttlv import (
            decode_one, encode_enumeration, encode_structure, encode_text_string
        )
        from kmip_pkcs11.core.enums import Tag
        from kmip_pkcs11.operations import activate, destroy, rekey, revoke

        handlers = {
            "Activate": activate.handle,
            "Revoke":   revoke.handle,
            "Destroy":  destroy.handle,
            "ReKey":    rekey.handle,
        }
        handler = handlers.get(action)
        if handler is None:
            raise ValueError(f"Unsupported lifecycle action '{action}'")

        children = encode_text_string(Tag.UniqueIdentifier, uid)

        if action == "Revoke":
            reason_name = kwargs.get("reason") or "CessationOfOperation"
            try:
                reason_code = int(getattr(enums.RevocationReasonCode, reason_name))
            except AttributeError:
                raise ValueError(f"Unknown revocation reason '{reason_name}'")
            reason = encode_enumeration(Tag.RevocationReasonCode, reason_code)
            if kwargs.get("message"):
                reason += encode_text_string(Tag.RevocationMessage, kwargs["message"])
            children += encode_structure(Tag.RevocationReason, reason)

        payload = decode_one(encode_structure(Tag.RequestPayload, children))
        result = handler(payload, owner, self._store, self._shim)

        # ReKey answers with the identifier of the replacement key, which the
        # caller needs; the others echo the original.
        try:
            item = decode_one(encode_structure(Tag.ResponsePayload, result))
            returned = item.get(Tag.UniqueIdentifier)
            return returned.value if returned else uid
        except Exception:                       # noqa: BLE001
            return uid

    # ── certificates ─────────────────────────────────────────────────────────

    def certificates(self) -> List[Dict[str, Any]]:
        """Certificate objects with subject, issuer and validity parsed out.

        Parsed here rather than in the portal because the DER lives in the
        metadata store and the PHP tier deliberately holds no crypto. Sorted
        by remaining validity so the ones about to lapse are at the top —
        an expiry list that needs sorting to be useful usually is not.
        """
        certificate_type = int(enums.ObjectType.Certificate)
        results = []

        for uid in self._store.list_objects():
            row = self._store.get_object(uid)
            if row is None or row.get("object_type") != certificate_type:
                continue

            entry = self.render(row)
            entry.update({
                "subject": None, "issuer": None, "not_before": None,
                "not_after": None, "days_remaining": None,
                "serial": None, "self_signed": False, "parse_error": None,
            })

            der = row.get("raw_key_value")
            if der:
                entry.update(_parse_certificate(bytes(der)))
            results.append(entry)

        # None sorts last: an unparseable certificate is not urgent, it is
        # unknown, and putting it above a genuinely expiring one would bury
        # the thing that needs action.
        return sorted(results,
                      key=lambda c: (c["days_remaining"] is None,
                                     c["days_remaining"] if c["days_remaining"] is not None else 0))

    # ── dashboard aggregation ────────────────────────────────────────────────

    def statistics(self) -> Dict[str, Any]:
        """Counts for the dashboard, computed from the metadata store."""
        objects = [self._store.get_object(uid) for uid in self._store.list_objects()]
        objects = [o for o in objects if o]

        def count_type(object_type) -> int:
            return sum(1 for o in objects if o.get("object_type") == object_type)

        by_state: Dict[str, int] = {}
        for obj in objects:
            label = _name(enums.State, obj.get("state")) or "Unknown"
            by_state[label] = by_state.get(label, 0) + 1

        by_algorithm: Dict[str, int] = {}
        for obj in objects:
            if obj.get("cryptographic_algorithm") is None:
                continue
            label = _name(enums.CryptographicAlgorithm, obj["cryptographic_algorithm"])
            by_algorithm[label] = by_algorithm.get(label, 0) + 1

        active = sum(1 for o in objects if o.get("state") == int(enums.State.Active))

        return {
            "total_objects": len(objects),
            "total_keys": count_type(int(enums.ObjectType.SymmetricKey))
                          + count_type(int(enums.ObjectType.PrivateKey))
                          + count_type(int(enums.ObjectType.PublicKey)),
            "active_keys": active,
            "symmetric_keys": count_type(int(enums.ObjectType.SymmetricKey)),
            "private_keys": count_type(int(enums.ObjectType.PrivateKey)),
            "public_keys": count_type(int(enums.ObjectType.PublicKey)),
            "certificates": count_type(int(enums.ObjectType.Certificate)),
            "secret_data": count_type(int(enums.ObjectType.SecretData)),
            "by_state": by_state,
            "by_algorithm": by_algorithm,
        }


class Pkcs11Service:
    """
    Slot, token and object introspection for the PKCS#11 Explorer.

    The shim owns a single PKCS#11 session guarded by a lock (a deliberate
    design decision documented in the design document, §13). Calls are made
    through it rather than opening sessions here, so the portal cannot
    accidentally introduce the concurrency problem that design avoids.
    """

    def __init__(self, library: str, token_label: str, pin: str):
        self._library = library
        self._token_label = token_label
        self._pin = pin
        self._shim = None
        self._error: Optional[str] = None
        self._lock = threading.Lock()

    def _ensure(self):
        """Connects on first use, remembering failure.

        Lazy rather than at startup so the API still serves — and can report
        *why* the HSM is unavailable — when SoftHSM2 is missing. An HSM being
        down is an operational condition the dashboard should show, not a
        reason the whole portal fails to boot.
        """
        with self._lock:
            if self._shim is not None:
                return self._shim
            try:
                from kmip_pkcs11.pkcs11_shim.shim import PKCS11Shim
                shim = PKCS11Shim(self._library, self._token_label, self._pin)
                shim.initialize()
                self._shim = shim
                self._error = None
            except Exception as exc:  # noqa: BLE001 - surfaced to the UI
                self._error = str(exc)
                log.error("PKCS#11 unavailable: %s", exc)
            return self._shim

    @property
    def available(self) -> bool:
        return self._ensure() is not None

    @property
    def shim(self):
        """The initialised shim, or None.

        Exposed so write operations can reuse the one session this class
        already owns. Opening a second session elsewhere is what the engine's
        single-locked-session design exists to prevent.
        """
        return self._ensure()

    @property
    def error(self) -> Optional[str]:
        self._ensure()
        return self._error

    def health(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "library": self._library,
            "token": self._token_label,
            "error": self._error,
        }

    def slots(self) -> List[Dict[str, Any]]:
        shim = self._ensure()
        if shim is None:
            return []
        try:
            return shim.list_slots()
        except Exception as exc:  # noqa: BLE001
            log.error("list_slots failed: %s", exc)
            return []

    def objects(self) -> List[Dict[str, Any]]:
        shim = self._ensure()
        if shim is None:
            return []
        try:
            return shim.list_objects()
        except Exception as exc:  # noqa: BLE001
            log.error("list_objects failed: %s", exc)
            return []
