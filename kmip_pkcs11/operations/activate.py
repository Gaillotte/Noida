"""Handle KMIP Activate operation."""

import logging
from ..core.enums import Tag, State
from ..core.ttlv import encode_text_string
from ..core.exceptions import ItemNotFound, IllegalOperation, MissingData
from ..lifecycle.state_machine import transition

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("Activate requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required")
    uid = uid_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")

    transition(obj["state"], "activate")  # raises if invalid
    store.activate(uid)
    log.info("Activated object uid=%s", uid)

    return encode_text_string(Tag.UniqueIdentifier, uid)
