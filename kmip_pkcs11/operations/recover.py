"""Handle KMIP Recover operation — restore an archived object to normal usability."""

import logging
from ..core.enums import Tag
from ..core.ttlv import encode_text_string
from ..core.exceptions import ItemNotFound, IllegalOperation, MissingData

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("Recover requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required")
    uid = uid_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")

    if not obj.get("archived"):
        raise IllegalOperation("Object is not archived")

    store.recover_object(uid)
    log.info("Recovered uid=%s", uid)

    return encode_text_string(Tag.UniqueIdentifier, uid)
