"""Handle KMIP Check operation — verify usage constraints without performing
any operation or mutating state.

Request may include UsageLimitsCount, CryptographicUsageMask, and/or State;
each present field is checked independently. Per the KMIP convention, the
response only echoes back the fields that FAILED their check — an absent
field means that aspect checked out fine.
"""

import logging
from ..core.enums import Tag
from ..core.ttlv import encode_text_string, encode_long_integer, encode_integer, encode_enumeration
from ..core.exceptions import ItemNotFound, MissingData

log = logging.getLogger(__name__)

_USAGE_LIMITS_ATTR = "Usage Limits Count"


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("Check requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required")
    uid = uid_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")

    response = encode_text_string(Tag.UniqueIdentifier, uid)

    count_item = payload.get(Tag.UsageLimitsCount)
    if count_item is not None:
        requested = count_item.value
        existing  = store.get_attribute(uid, _USAGE_LIMITS_ATTR)
        if existing:
            remaining = existing[0]
            if not isinstance(remaining, (int, float)) or remaining < requested:
                response += encode_long_integer(Tag.UsageLimitsCount, requested)

    mask_item = payload.get(Tag.CryptographicUsageMask)
    if mask_item is not None:
        requested_mask = mask_item.value
        object_mask = obj.get("usage_mask") or 0
        if (object_mask & requested_mask) != requested_mask:
            response += encode_integer(Tag.CryptographicUsageMask, requested_mask)

    state_item = payload.get(Tag.State)
    if state_item is not None:
        if obj["state"] != state_item.value:
            response += encode_enumeration(Tag.State, state_item.value)

    log.debug("Check uid=%s failures_present=%s", uid, response != encode_text_string(Tag.UniqueIdentifier, uid))
    return response
