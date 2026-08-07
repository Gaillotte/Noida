"""Handle KMIP AdjustAttribute operation — atomically increment/decrement/set a numeric attribute."""

import logging
from ..core.enums import Tag, AdjustmentType
from ..core.ttlv import encode_text_string, encode_integer, encode_structure
from ..core.exceptions import ItemNotFound, MissingData, InvalidField

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("AdjustAttribute requires payload")

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
    delta = value_item.value if value_item else 0
    index = index_item.value if index_item else 0

    adj_item  = payload.get(Tag.AdjustmentType)
    adjustment = adj_item.value if adj_item else AdjustmentType.Set

    existing = store.get_attribute(uid, name)
    current = existing[index] if index < len(existing) else 0
    if not isinstance(current, (int, float)):
        raise InvalidField(f"Attribute '{name}' is not numeric, cannot adjust")

    if adjustment == AdjustmentType.Increment:
        new_value = current + delta
    elif adjustment == AdjustmentType.Decrement:
        new_value = current - delta
    elif adjustment == AdjustmentType.Set:
        new_value = delta
    else:
        raise InvalidField(f"Unknown AdjustmentType {adjustment!r}")

    store.set_or_add_attribute(uid, name, new_value, index)
    log.debug("Adjusted attribute '%s'[%d] on %s -> %r", name, index, uid, new_value)

    return (
        encode_text_string(Tag.UniqueIdentifier, uid)
        + encode_structure(
            Tag.Attribute,
            encode_text_string(Tag.AttributeName, name)
            + encode_integer(Tag.AttributeValue, new_value)
        )
    )
