"""Handle KMIP GetAttributes operation."""

import json
import logging
import datetime
from ..core.enums import Tag
from ..core.ttlv import (
    encode_text_string, encode_structure, encode_enumeration,
    encode_integer, encode_datetime, encode_long_integer
)
from ..core.exceptions import ItemNotFound, MissingData
from ..lifecycle.access_control import check_owner

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("GetAttributes requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required")
    uid = uid_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")
    check_owner(identity, obj.get("owner_identity"), "GetAttributes", store=store, uid=uid)

    # Requested attribute names
    requested = [i.value for i in payload.get_all(Tag.AttributeName)]

    response = encode_text_string(Tag.UniqueIdentifier, uid)

    def add_attr(name: str, value_bytes: bytes):
        nonlocal response
        attr_bytes = encode_text_string(Tag.AttributeName, name) + value_bytes
        response += encode_structure(Tag.Attribute, attr_bytes)

    def want(name):
        return not requested or name in requested

    if want("Object Type") and obj["object_type"] is not None:
        add_attr("Object Type", encode_enumeration(Tag.AttributeValue, obj["object_type"]))

    if want("State") and obj["state"] is not None:
        add_attr("State", encode_enumeration(Tag.AttributeValue, obj["state"]))

    if want("Cryptographic Algorithm") and obj["cryptographic_algorithm"]:
        add_attr("Cryptographic Algorithm",
                 encode_enumeration(Tag.AttributeValue, obj["cryptographic_algorithm"]))

    if want("Cryptographic Length") and obj["cryptographic_length"]:
        add_attr("Cryptographic Length",
                 encode_integer(Tag.AttributeValue, obj["cryptographic_length"]))

    if want("Cryptographic Usage Mask") and obj["usage_mask"]:
        add_attr("Cryptographic Usage Mask",
                 encode_integer(Tag.AttributeValue, obj["usage_mask"]))

    if want("Sensitive"):
        add_attr("Sensitive", encode_integer(Tag.AttributeValue, obj["sensitive"]))

    if want("Extractable"):
        add_attr("Extractable", encode_integer(Tag.AttributeValue, obj["extractable"]))

    if want("Initial Date") and obj["initial_date"]:
        dt = datetime.datetime.fromtimestamp(obj["initial_date"], tz=datetime.timezone.utc)
        add_attr("Initial Date", encode_datetime(Tag.AttributeValue, dt))

    if want("Activation Date") and obj["activation_date"]:
        dt = datetime.datetime.fromtimestamp(obj["activation_date"], tz=datetime.timezone.utc)
        add_attr("Activation Date", encode_datetime(Tag.AttributeValue, dt))

    # Custom / name attributes from attribute table
    extra_attrs = store.get_attributes(uid)
    for a in extra_attrs:
        name = a["attr_name"]
        if name.startswith("_"):
            continue
        if want(name):
            try:
                parsed = json.loads(a["attr_value"])
            except (json.JSONDecodeError, TypeError):
                parsed = a["attr_value"]
            add_attr(name, encode_text_string(Tag.AttributeValue, str(parsed)))

    return response


def handle_add(payload, identity: str, store, shim) -> bytes:
    """GetAttributeList — return attribute names only."""
    if payload is None:
        raise MissingData("GetAttributeList requires payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier required")
    uid = uid_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")
    check_owner(identity, obj.get("owner_identity"), "GetAttributeList", store=store, uid=uid)

    response = encode_text_string(Tag.UniqueIdentifier, uid)
    for name in ["Object Type", "State", "Cryptographic Algorithm",
                 "Cryptographic Length", "Cryptographic Usage Mask",
                 "Sensitive", "Extractable", "Initial Date"]:
        response += encode_text_string(Tag.AttributeName, name)

    extra = store.get_attributes(uid)
    for a in extra:
        if not a["attr_name"].startswith("_"):
            response += encode_text_string(Tag.AttributeName, a["attr_name"])

    return response
