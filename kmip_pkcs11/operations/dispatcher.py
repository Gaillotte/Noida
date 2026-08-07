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
        }

    def dispatch(self, batch_item: TTLVItem, identity: str) -> bytes:
        """Process one Batch Item. Returns encoded response BatchItem bytes."""
        op_item = batch_item.get(Tag.Operation)
        op_code = op_item.value if op_item else None

        payload = batch_item.get(Tag.RequestPayload)
        uid_item = batch_item.get(Tag.UniqueBatchItemID)

        try:
            handler = self._handlers.get(op_code)
            if handler is None:
                raise OperationNotSupported(f"Operation 0x{op_code:08X} not supported")

            response_payload = handler(payload, identity, self._store, self._shim)

            return self._success_item(op_code, response_payload, uid_item)

        except KMIPError as e:
            log.warning("KMIP operation 0x%08X failed: %s", op_code or 0, e)
            return self._failure_item(op_code, e.reason, str(e), uid_item)
        except Exception as e:
            log.exception("Unexpected error in operation 0x%08X", op_code or 0)
            return self._failure_item(op_code, ResultReason.GeneralFailure, str(e), uid_item)

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
