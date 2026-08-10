"""Handle KMIP SetAttribute operation (v2.0+) — set (create or overwrite) a single-instance attribute."""

import logging
from ..core.enums import Tag
from ..core.ttlv import encode_text_string
from ..core.exceptions import ItemNotFound, MissingData
from ..lifecycle.access_control import check_owner

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("SetAttribute requires payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier required")
    uid = uid_item.value

    owner = store.get_owner(uid)
    if owner is None:
        raise ItemNotFound(f"Object '{uid}' not found")
    check_owner(identity, owner, "SetAttribute")

    name_item  = payload.get(Tag.AttributeName)
    value_item = payload.get(Tag.AttributeValue)
    if name_item is None:
        raise MissingData("AttributeName required")

    name  = name_item.value
    value = value_item.value if value_item else ""

    store.set_or_add_attribute(uid, name, value)
    log.debug("Set attribute '%s' on %s", name, uid)

    return encode_text_string(Tag.UniqueIdentifier, uid)
