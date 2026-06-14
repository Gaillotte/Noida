"""Handle KMIP AddAttribute and DeleteAttribute operations."""

import logging
from ..core.enums import Tag
from ..core.ttlv import encode_text_string
from ..core.exceptions import ItemNotFound, MissingData

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("AddAttribute requires payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier required")
    uid = uid_item.value

    if not store.object_exists(uid):
        raise ItemNotFound(f"Object '{uid}' not found")

    attr_item = payload.get(Tag.Attribute)
    if attr_item is None:
        raise MissingData("Attribute is required")

    name_item  = attr_item.get(Tag.AttributeName)
    value_item = attr_item.get(Tag.AttributeValue)
    if name_item is None:
        raise MissingData("AttributeName required")

    name  = name_item.value
    value = value_item.value if value_item else ""

    store.add_attribute(uid, name, value)
    log.debug("Added attribute '%s' to %s", name, uid)

    return (
        encode_text_string(Tag.UniqueIdentifier, uid)
        + encode_text_string(Tag.AttributeName, name)
    )
