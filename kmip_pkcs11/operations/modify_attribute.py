"""Handle KMIP ModifyAttribute operation — update an existing attribute value."""

import logging
from ..core.enums import Tag
from ..core.ttlv import encode_text_string, encode_integer, encode_structure
from ..core.exceptions import ItemNotFound, MissingData

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("ModifyAttribute requires payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier required")
    uid = uid_item.value

    if not store.object_exists(uid):
        raise ItemNotFound(f"Object '{uid}' not found")

    attr_item = payload.get(Tag.Attribute)
    if attr_item is None:
        raise MissingData("Attribute required")

    name_item  = attr_item.get(Tag.AttributeName)
    value_item = attr_item.get(Tag.AttributeValue)
    index_item = attr_item.get(Tag.AttributeIndex)
    if name_item is None:
        raise MissingData("AttributeName required")

    name  = name_item.value
    value = value_item.value if value_item else ""
    index = index_item.value if index_item else 0

    rows = store.update_attribute(uid, name, value, index)
    if rows == 0:
        raise ItemNotFound(f"Attribute '{name}' index {index} not found on '{uid}'")

    log.debug("Modified attribute '%s'[%d] on %s", name, index, uid)

    return (
        encode_text_string(Tag.UniqueIdentifier, uid)
        + encode_structure(
            Tag.Attribute,
            encode_text_string(Tag.AttributeName, name)
            + encode_integer(Tag.AttributeIndex, index)
        )
    )
