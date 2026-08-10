"""Handle KMIP DeleteAttribute operation."""

import logging
from ..core.enums import Tag
from ..core.ttlv import encode_text_string
from ..core.exceptions import ItemNotFound, MissingData
from ..lifecycle.access_control import check_owner

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("DeleteAttribute requires payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier required")
    uid = uid_item.value

    owner = store.get_owner(uid)
    if owner is None:
        raise ItemNotFound(f"Object '{uid}' not found")
    check_owner(identity, owner, "DeleteAttribute", store=store, uid=uid)

    attr_item = payload.get(Tag.Attribute)
    if attr_item is None:
        raise MissingData("Attribute is required")

    name_item = attr_item.get(Tag.AttributeName)
    idx_item  = attr_item.get(Tag.AttributeIndex)
    if name_item is None:
        raise MissingData("AttributeName required")

    name  = name_item.value
    index = idx_item.value if idx_item else 0

    store.delete_attribute(uid, name, index)
    log.debug("Deleted attribute '%s'[%d] from %s", name, index, uid)

    return encode_text_string(Tag.UniqueIdentifier, uid)
