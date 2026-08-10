"""Handle KMIP Revoke operation."""

import logging
from ..core.enums import Tag, State, RevocationReasonCode
from ..core.ttlv import encode_text_string
from ..core.exceptions import ItemNotFound, IllegalOperation, MissingData
from ..lifecycle.state_machine import transition, revoke_operation
from ..lifecycle.access_control import check_owner

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("Revoke requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required")
    uid = uid_item.value

    # Revocation reason
    rev_reason_item = payload.get(Tag.RevocationReason)
    reason_code = RevocationReasonCode.Unspecified
    reason_msg  = ""
    if rev_reason_item:
        code_item = rev_reason_item.get(Tag.RevocationReasonCode)
        msg_item  = rev_reason_item.get(Tag.RevocationMessage)
        if code_item:
            reason_code = code_item.value
        if msg_item:
            reason_msg = msg_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")
    check_owner(identity, obj.get("owner_identity"), "Revoke", store=store, uid=uid)

    op_name  = revoke_operation(reason_code)
    new_state = transition(obj["state"], op_name)

    store.set_revoke(uid, new_state, reason_code, reason_msg)
    log.info("Revoked uid=%s reason=%d new_state=%d", uid, reason_code, new_state)

    return encode_text_string(Tag.UniqueIdentifier, uid)
