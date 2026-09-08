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


def _usage_names(mask: Optional[int]) -> List[str]:
    """Expands a CryptographicUsageMask into the flag names it carries."""
    if not mask:
        return []
    return [flag.name for flag in enums.CryptographicUsageMask if int(flag) & int(mask)]


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

    # ── capability ───────────────────────────────────────────────────────────

    # What each KMIP operation is *for*. A flat list of 41 names says nothing
    # about why the set is so broad, and the fourth group is the one that
    # explains this architecture: since KMIP 1.2 the protocol does not only
    # administer keys, it will use them on the client's behalf, which is what
    # lets the key stay inside the HSM.
    #
    # Unlike the implemented/deferred split, this grouping is editorial — the
    # specification does not tag operations this way — so it is a static map.
    # Anything absent from it still appears, under OPERATION_GROUP_OTHER; see
    # supported_operations().
    OPERATION_GROUPS = (
        ("Object lifecycle",
         "Bring an object into existence, move it through its states, and end it.",
         ("Create", "CreateKeyPair", "Register", "DeriveKey", "ReKey", "ReKeyKeyPair",
          "Certify", "ReCertify", "CreateSplitKey", "JoinSplitKey", "Import", "Export",
          "Activate", "Revoke", "Destroy", "Archive", "Recover", "Check", "ObtainLease")),
        ("Retrieval and discovery",
         "Find objects, and ask the server what it supports.",
         ("Get", "GetAttributes", "GetAttributeList", "Locate", "Query",
          "DiscoverVersions", "GetUsageAllocation")),
        ("Attribute management",
         "The metadata KMIP keeps about an object, rather than the key itself.",
         ("AddAttribute", "ModifyAttribute", "DeleteAttribute", "SetAttribute",
          "AdjustAttribute")),
        ("Cryptographic services",
         "The server performs the operation and returns the result, so the key "
         "never leaves the HSM.",
         ("Encrypt", "Decrypt", "Sign", "SignatureVerify", "MAC", "MACVerify",
          "Hash", "RNGRetrieve", "RNGSeed", "Validate")),
    )

    OPERATION_GROUP_OTHER = "Other"

    DEFERRED_REASON = (
        "Session, asynchronous and vendor operations, which do not fit a "
        "synchronous server that authenticates every request. A client calling "
        "one receives OperationNotSupported rather than a silent failure."
    )

    @staticmethod
    def supported_operations() -> Dict[str, Any]:
        """Which KMIP operations the engine implements, read from the engine.

        Asked of the dispatcher's handler table rather than answered from a
        list kept here. That table *is* the behaviour — an operation with no
        entry in it is refused with OperationNotSupported — so this cannot claim
        an operation that would not actually run, and an operation added
        upstream appears without anyone remembering to update a page.

        The portal used to hardcode the badge list, and it had drifted: the card
        said 41 operations while displaying 28 of them.

        Returns the flat lists as well as the grouped view. The flat
        ``implemented`` list stays the authoritative count; the groups are a
        presentation of it and are asserted to hold exactly the same names, so a
        grouping mistake cannot quietly change what the card claims.
        """
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher

        # __init__ only populates the handler table and stores its arguments;
        # building one this way avoids requiring a store or an open HSM session
        # just to ask what the engine can do.
        dispatcher = OperationDispatcher.__new__(OperationDispatcher)
        OperationDispatcher.__init__(dispatcher, store=None, shim=None)
        implemented_codes = set(dispatcher._handlers)

        implemented, deferred = [], []
        for operation in enums.Operation:
            (implemented if operation.value in implemented_codes
             else deferred).append(operation.name)

        remaining = set(implemented)
        groups = []
        for title, description, names in KmipService.OPERATION_GROUPS:
            present = [n for n in names if n in remaining]
            remaining.difference_update(present)
            if present:
                groups.append({"title": title, "description": description,
                               "operations": present})

        # An operation the engine gained upstream that nobody has categorised
        # here. Shown rather than dropped: a card that silently omits an
        # implemented operation is worse than one with an untidy last group.
        if remaining:
            log.info("KMIP operations not in any documented group: %s",
                     ", ".join(sorted(remaining)))
            groups.append({
                "title": KmipService.OPERATION_GROUP_OTHER,
                "description": "Implemented, but not yet described in a group here.",
                "operations": sorted(remaining),
            })

        grouped_total = sum(len(g["operations"]) for g in groups)
        assert grouped_total == len(implemented), (
            f"grouping lost operations: {grouped_total} grouped vs "
            f"{len(implemented)} implemented"
        )

        return {
            "implemented": sorted(implemented),
            "deferred": sorted(deferred),
            "implemented_count": len(implemented),
            "total": len(implemented) + len(deferred),
            "groups": groups,
            "deferred_reason": KmipService.DEFERRED_REASON,
        }

    # ── objects ──────────────────────────────────────────────────────────────

    def list_objects(self, owner: Optional[str] = None) -> List[Dict[str, Any]]:
        uids = self._store.list_objects()
        objects = []
        for uid in uids:
            # One bad object must not empty the list. A row this process cannot
            # decrypt - written under a master key it has no access to - used to
            # raise straight out of here and return 500 for every key in the
            # store. Report it as unreadable and carry on: an operator needs to
            # be told the object exists and cannot be read, which is exactly
            # what a blanked page fails to say.
            try:
                row = self._store.get_object(uid)
            except Exception as exc:            # noqa: BLE001 - see comment
                log.warning("Object %s could not be read: %s", uid, exc)
                objects.append(self._unreadable(uid, exc))
                continue
            if row is None:
                continue
            if owner and row.get("owner_identity") not in (owner, None):
                continue
            objects.append(self.render(row))
        return objects

    def _unreadable(self, uid: str, exc: Exception) -> Dict[str, Any]:
        """A placeholder in render()'s own shape, so anything that can display
        an object can display this one.

        Built by rendering an empty row rather than by listing the keys again:
        two hand-written copies of that shape would drift. The attribute tables
        are not encrypted, so the object's name usually still resolves - which
        is the one thing an operator needs in order to identify it.
        """
        try:
            rendered = self.render({"uuid": uid})
        except Exception:                       # noqa: BLE001
            rendered = {"uid": uid}
        rendered["object_type"] = "Unreadable"
        rendered["state"] = "Unknown"
        rendered["read_error"] = str(exc)
        return rendered

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
            "usage_mask": _usage_names(row.get("usage_mask")),
            "created_at": _iso(row.get("created_at")),
            "name": self._first_name(row["uuid"]),
            "cka_id": self._cka_id(row["uuid"]),
        }

    def _cka_id(self, uid: str) -> Optional[str]:
        """The PKCS#11 CKA_ID, which the engine stores as a private attribute.

        Read rather than derived: it is generated inside the shim, so this is
        the only place the portal can learn what identifies the key on the
        token itself.
        """
        values = self._store.get_attribute(uid, "_pkcs11_cka_id")
        return str(values[0]).upper() if values else None

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

    def create_symmetric_key(self, name: str, algorithm: str, length: int, owner: str,
                             encrypt: bool = True, decrypt: bool = True,
                             wrap: bool = False, unwrap: bool = False,
                             sensitive: bool = True, extractable: bool = False) -> str:
        from kmip_pkcs11.operations.create import create_symmetric_key

        if self._shim is None:
            raise RuntimeError("The HSM is unavailable; key creation is not possible")

        try:
            algorithm_value = int(getattr(enums.CryptographicAlgorithm, algorithm.upper()))
        except AttributeError:
            supported = ", ".join(a.name for a in enums.CryptographicAlgorithm)
            raise ValueError(f"Unsupported algorithm '{algorithm}'. Supported: {supported}")

        # Only these four reach a PKCS#11 attribute for a secret key — the
        # engine derives CKA_ENCRYPT/DECRYPT/WRAP/UNWRAP from the mask. Offering
        # Sign or Verify here would set a bit the token never sees.
        mask = enums.CryptographicUsageMask
        usage = 0
        if encrypt:
            usage |= int(mask.Encrypt)
        if decrypt:
            usage |= int(mask.Decrypt)
        if wrap:
            usage |= int(mask.WrapKey)
        if unwrap:
            usage |= int(mask.UnwrapKey)
        if usage == 0:
            raise ValueError("Select at least one usage: encrypt, decrypt, wrap or unwrap")

        # Calls the same helper Create and ReKey share, so a key made here is
        # indistinguishable from one made over the wire.
        return create_symmetric_key(
            algorithm_value, length, usage, [name],
            sensitive, extractable,
            owner, self._store, self._shim,
        )

    def create_key_pair(self, name: str, algorithm: str, length: int,
                        curve: str, owner: str, sign: bool = True,
                        verify: bool = True, derive: bool = False) -> Dict[str, str]:
        """Generates an asymmetric key pair. Returns both identifiers.

        The usage masks are not chosen here — they mirror what
        ``create_keypair.handle`` defaults to for each algorithm family, so a
        pair made from the portal carries the same attributes as one made by a
        KMIP client sending CreateKeyPair with no explicit mask.
        """
        from kmip_pkcs11.operations.create_keypair import (
            CURVE_TO_NAME, create_key_pair_objects,
        )

        if self._shim is None:
            raise RuntimeError("The HSM is unavailable; key creation is not possible")

        try:
            algorithm_value = int(getattr(enums.CryptographicAlgorithm, algorithm.upper()))
        except AttributeError:
            raise ValueError(f"Unsupported algorithm '{algorithm}'. "
                             "Supported: RSA, EC, ECDSA, ECDH, DSA, DH")

        try:
            curve_value = getattr(enums.RecommendedCurve, curve.upper())
        except AttributeError:
            supported = ", ".join(c.name for c in CURVE_TO_NAME)
            raise ValueError(f"Unsupported curve '{curve}'. Supported: {supported}")

        # For an EC key the curve fixes the size, and the caller's `length` is
        # meaningless. Left alone it lands in CryptographicLength as the
        # engine's RSA-shaped default of 2048, so the portal would list a
        # P-384 key as "EC 2048". Supplying the curve's own bit size is what a
        # well-behaved KMIP client would send, not a second opinion about what
        # the key is.
        curve_bits = {"P_192": 192, "P_224": 224, "P_256": 256,
                      "P_384": 384, "P_521": 521, "SECP256K1": 256}
        elliptic = (int(enums.CryptographicAlgorithm.EC),
                    int(enums.CryptographicAlgorithm.ECDSA),
                    int(enums.CryptographicAlgorithm.ECDH))
        if algorithm_value in elliptic:
            # Falls back to the caller's value for a curve this map has not
            # heard of, leaving the engine to reject it with its own message.
            length = curve_bits.get(curve.upper(), length)

        key_agreement = algorithm_value in (int(enums.CryptographicAlgorithm.DH),
                                            int(enums.CryptographicAlgorithm.ECDH))
        mask = enums.CryptographicUsageMask
        if key_agreement:
            # The engine forces derive on for these algorithms regardless, so a
            # sign/verify choice here would be quietly ignored.
            pub_mask = priv_mask = int(mask.KeyAgreement)
        else:
            pub_mask = int(mask.Verify) if verify else 0
            priv_mask = int(mask.Sign) if sign else 0
            if derive:
                priv_mask |= int(mask.KeyAgreement)
            if pub_mask == 0 and priv_mask == 0:
                raise ValueError("Select at least one usage: sign, verify or derive")

        public_uid, private_uid = create_key_pair_objects(
            algorithm_value, length, curve_value, pub_mask, priv_mask, [name],
            owner, self._store, self._shim,
        )
        return {"public_uid": public_uid, "private_uid": private_uid}

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
