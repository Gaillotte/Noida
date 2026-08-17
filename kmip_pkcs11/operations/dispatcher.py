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
    encode_byte_string, encode_integer, decode_one, decode_all
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


class OperationDispatcher:
    def __init__(self, store: MetadataStore, shim: PKCS11Shim):
        self._store = store
        self._shim  = shim
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

    def dispatch(self, batch_item: TTLVItem, identity: str, client: str = None) -> bytes:
        """Process one Batch Item. Returns encoded response BatchItem bytes."""
        op_item = batch_item.get(Tag.Operation)
        op_code = op_item.value if op_item else None

        payload = batch_item.get(Tag.RequestPayload)
        uid_item = batch_item.get(Tag.UniqueBatchItemID)

        try:
            if op_code is None:
                raise OperationNotSupported("BatchItem is missing an Operation")
            handler = self._handlers.get(op_code)
            if handler is None:
                raise OperationNotSupported(f"Operation 0x{op_code:08X} not supported")

            response_payload = handler(payload, identity, self._store, self._shim)

            self._audit(op_code, identity, client, payload, response_payload, "success")
            return self._success_item(op_code, response_payload, uid_item)

        except KMIPError as e:
            log.warning("KMIP operation 0x%08X failed: %s", op_code or 0, e)
            self._audit(op_code, identity, client, payload, None, "failure",
                        reason=e.reason, message=str(e))
            return self._failure_item(op_code, e.reason, str(e), uid_item)
        except Exception:
            # Internal fault — full detail to the log, generic text to the wire.
            log.exception("Unexpected error in operation 0x%08X", op_code or 0)
            self._audit(op_code, identity, client, payload, None, "failure",
                        reason=ResultReason.GeneralFailure, message="Internal server error")
            return self._failure_item(
                op_code, ResultReason.GeneralFailure, "Internal server error", uid_item
            )

    # ── audit ────────────────────────────────────────────────────────────────

    # Query and DiscoverVersions touch no managed object and carry no
    # authorization decision — they are capability discovery. Auditing them
    # would bury the records that matter in handshake noise. Everything else is
    # recorded, reads included: "who exported this key" is the question an
    # audit log most needs to answer, and it is a read.
    _UNAUDITED = frozenset({Operation.Query, Operation.DiscoverVersions})

    def _audit(self, op_code, identity, client, request_payload,
               response_payload, result, reason=None, message=None):
        if op_code in self._UNAUDITED:
            return
        try:
            self._store.append_audit(
                identity=identity,
                operation=op_code,
                operation_name=self._operation_name(op_code),
                object_uid=self._object_uid(request_payload, response_payload),
                result=result,
                result_reason=reason,
                message=message,
                client=client,
            )
        except Exception:
            # An audit failure must never turn a successful operation into a
            # failed one, but it is serious enough to log loudly — a silently
            # unrecorded operation is exactly what an attacker would want.
            log.exception("Failed to write audit record for operation %r", op_code)

    @staticmethod
    def _operation_name(op_code) -> str:
        try:
            return Operation(op_code).name
        except (ValueError, TypeError):
            return f"0x{op_code:08X}" if isinstance(op_code, int) else "unknown"

    @staticmethod
    def _object_uid(request_payload, response_payload):
        """The object an operation acted on. Usually named in the request, but
        Create/CreateKeyPair/Register only learn it from the response."""
        if request_payload is not None:
            item = request_payload.get(Tag.UniqueIdentifier)
            if item is not None:
                return item.value
        if response_payload:
            try:
                for item in decode_all(response_payload):
                    if item.tag == Tag.UniqueIdentifier:
                        return item.value
            except Exception:
                return None
        return None

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
