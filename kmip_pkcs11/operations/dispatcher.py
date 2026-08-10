"""
Central operation dispatcher — routes KMIP Batch Items to handler methods.
All handlers receive a TTLVItem (the request payload) and the identity string,
and return a TTLVItem (the response payload).
"""

import logging
from typing import Callable, Dict

from ..core.enums import Operation, ResultStatus, ResultReason, Tag, Type
from ..core.ttlv import (
    TTLVItem, encode_structure, encode_enumeration, encode_text_string,
    encode_byte_string, encode_integer, decode_one
)
from ..core.exceptions import KMIPError, OperationNotSupported
from ..metadata.store import MetadataStore
from ..pkcs11_shim.shim import PKCS11Shim

from . import (
    create, create_keypair, register, get as get_op,
    locate, destroy, activate, revoke,
    encrypt as enc_op, decrypt as dec_op,
    query as query_op, discover_versions,
    get_attributes, add_attribute, delete_attribute,
    sign as sign_op, signature_verify as sigver_op,
    rng_retrieve, modify_attribute, set_attribute, adjust_attribute,
    mac as mac_op, mac_verify as macver_op, hash_op,
    import_op, export_op, derive_key,
    certify, validate,
    archive, recover, obtain_lease, get_usage_allocation, check as check_op,
    rekey, rekey_keypair, recertify, rng_seed, create_split_key, join_split_key,
)

log = logging.getLogger(__name__)


def _operation_name(op_code) -> str:
    """Symbolic operation name for the audit trail.

    An audit row reading "kmip.Destroy" is answerable; one reading
    "kmip.0x00000014" sends the reader to a specification table first.
    """
    if op_code is None:
        return "Unknown"
    try:
        return Operation(op_code).name
    except (ValueError, KeyError):
        return f"0x{op_code:08X}"


def _extract_uid(payload) -> "str | None":
    """Reads the Unique Identifier from a request payload, if it carries one."""
    if payload is None:
        return None
    try:
        item = payload.get(Tag.UniqueIdentifier)
        return item.value if item is not None else None
    except Exception:                          # noqa: BLE001
        return None


def _extract_uid_from_bytes(payload_bytes: bytes) -> "str | None":
    """Reads the Unique Identifier out of an encoded response payload.

    Used for Create and its relatives, where the identifier the operation
    produced only exists in the response. Decoding failure is not propagated:
    a malformed-looking payload here must not fail an operation that already
    succeeded, so the record simply carries no UID.
    """
    if not payload_bytes:
        return None
    try:
        item, _ = decode_one(encode_structure(Tag.ResponsePayload, payload_bytes), 0)
        uid = item.get(Tag.UniqueIdentifier)
        return uid.value if uid is not None else None
    except Exception:                          # noqa: BLE001 - see docstring
        return None


class OperationDispatcher:
    def __init__(self, store: MetadataStore, shim: PKCS11Shim, audit_sink=None):
        """
        :param audit_sink: optional ``callable(record: dict)`` invoked once per
            operation, successful or not.

            Placed here rather than in each of the 41 handlers deliberately.
            This is the single point every KMIP operation passes through, so a
            new operation is audited the moment it is routed — there is no
            handler to forget to instrument, which is exactly how audit
            coverage decays.
        """
        self._store = store
        self._shim  = shim
        self._audit_sink = audit_sink
        self._handlers: Dict[int, Callable] = {
            Operation.Create:           create.handle,
            Operation.CreateKeyPair:    create_keypair.handle,
            Operation.Register:         register.handle,
            Operation.Get:              get_op.handle,
            Operation.Locate:           locate.handle,
            Operation.Destroy:          destroy.handle,
            Operation.Activate:         activate.handle,
            Operation.Revoke:           revoke.handle,
            Operation.Encrypt:          enc_op.handle,
            Operation.Decrypt:          dec_op.handle,
            Operation.Query:            query_op.handle,
            Operation.DiscoverVersions: discover_versions.handle,
            Operation.GetAttributes:    get_attributes.handle,
            Operation.GetAttributeList: get_attributes.handle_add,
            Operation.AddAttribute:     add_attribute.handle,
            Operation.DeleteAttribute:  delete_attribute.handle,
            Operation.ModifyAttribute:  modify_attribute.handle,
            Operation.SetAttribute:     set_attribute.handle,
            Operation.AdjustAttribute:  adjust_attribute.handle,
            Operation.Sign:             sign_op.handle,
            Operation.SignatureVerify:  sigver_op.handle,
            Operation.RNGRetrieve:      rng_retrieve.handle,
            Operation.MAC:              mac_op.handle,
            Operation.MACVerify:        macver_op.handle,
            Operation.Hash:             hash_op.handle,
            Operation.Import:           import_op.handle,
            Operation.Export:           export_op.handle,
            Operation.DeriveKey:        derive_key.handle,
            Operation.Certify:          certify.handle,
            Operation.Validate:         validate.handle,
            Operation.Archive:          archive.handle,
            Operation.Recover:          recover.handle,
            Operation.ObtainLease:      obtain_lease.handle,
            Operation.GetUsageAllocation: get_usage_allocation.handle,
            Operation.Check:            check_op.handle,
            Operation.ReKey:            rekey.handle,
            Operation.ReKeyKeyPair:     rekey_keypair.handle,
            Operation.ReCertify:        recertify.handle,
            Operation.RNGSeed:          rng_seed.handle,
            Operation.CreateSplitKey:   create_split_key.handle,
            Operation.JoinSplitKey:     join_split_key.handle,
        }

    def dispatch(self, batch_item: TTLVItem, identity: str) -> bytes:
        """Process one Batch Item. Returns encoded response BatchItem bytes."""
        op_item = batch_item.get(Tag.Operation)
        op_code = op_item.value if op_item else None

        payload = batch_item.get(Tag.RequestPayload)
        uid_item = batch_item.get(Tag.UniqueBatchItemID)

        operation_name = _operation_name(op_code)
        object_uid = _extract_uid(payload)

        try:
            handler = self._handlers.get(op_code)
            if handler is None:
                raise OperationNotSupported(f"Operation 0x{op_code:08X} not supported")

            response_payload = handler(payload, identity, self._store, self._shim)

            # Created objects have no UID in the request, only the response —
            # so a Create audit record would otherwise never name what it made.
            if object_uid is None and response_payload:
                object_uid = _extract_uid_from_bytes(response_payload)

            self._audit(operation_name, identity, object_uid, "SUCCESS", None)
            return self._success_item(op_code, response_payload, uid_item)

        except KMIPError as e:
            log.warning("KMIP operation 0x%08X failed: %s", op_code or 0, e)
            self._audit(operation_name, identity, object_uid, "FAILURE", str(e))
            return self._failure_item(op_code, e.reason, str(e), uid_item)
        except Exception as e:
            log.exception("Unexpected error in operation 0x%08X", op_code or 0)
            self._audit(operation_name, identity, object_uid, "FAILURE", str(e))
            return self._failure_item(op_code, ResultReason.GeneralFailure, str(e), uid_item)

    def _audit(self, operation: str, identity: str, uid, result: str, detail):
        """Emits one audit record.

        Never raises. An audit backend that is down must not turn a completed
        key operation into a client-visible error — that would make the system
        less reliable the more closely it is watched. Failures degrade to a log
        line, which is the one place a fallback is acceptable.
        """
        if self._audit_sink is None:
            return
        try:
            self._audit_sink({
                "action": f"kmip.{operation}",
                "username": identity,
                "object_uid": uid,
                "result": result,
                "detail": detail,
                "provider": "KMIP",
            })
        except Exception:                      # noqa: BLE001 - see docstring
            log.exception("Audit sink failed for %s by %s", operation, identity)

    @staticmethod
    def _success_item(op_code, payload_bytes: bytes, uid_item) -> bytes:
        children  = encode_enumeration(Tag.Operation, op_code)
        children += encode_enumeration(Tag.ResultStatus, ResultStatus.Success)
        if payload_bytes:
            children += encode_structure(Tag.ResponsePayload, payload_bytes)
        if uid_item:
            children += encode_byte_string(Tag.UniqueBatchItemID, uid_item.value)
        return encode_structure(Tag.BatchItem, children)

    @staticmethod
    def _failure_item(op_code, reason: int, message: str, uid_item) -> bytes:
        children  = encode_enumeration(Tag.Operation, op_code or 0)
        children += encode_enumeration(Tag.ResultStatus, ResultStatus.OperationFailed)
        children += encode_enumeration(Tag.ResultReason, reason)
        children += encode_text_string(Tag.ResultMessage, message[:256])
        if uid_item:
            children += encode_byte_string(Tag.UniqueBatchItemID, uid_item.value)
        return encode_structure(Tag.BatchItem, children)
