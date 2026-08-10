"""Handle KMIP GetUsageAllocation operation — atomically consume from an
object's "Usage Limits Count" attribute (set via AddAttribute/SetAttribute).

Objects with no "Usage Limits Count" attribute configured are treated as
unlimited: the request always succeeds and nothing is decremented.
"""

import logging
from ..core.enums import Tag
from ..core.ttlv import encode_text_string
from ..core.exceptions import ItemNotFound, MissingData, NotAuthorized
from ..lifecycle.state_machine import check_usage_allowed
from ..lifecycle.access_control import check_owner

log = logging.getLogger(__name__)

_USAGE_LIMITS_ATTR = "Usage Limits Count"


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("GetUsageAllocation requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required")
    uid = uid_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")
    check_owner(identity, obj.get("owner_identity"), "GetUsageAllocation")

    check_usage_allowed(obj["state"], "get", archived=bool(obj.get("archived")))

    count_item = payload.get(Tag.UsageLimitsCount)
    requested  = count_item.value if count_item else 1

    existing = store.get_attribute(uid, _USAGE_LIMITS_ATTR)
    if existing:
        remaining = existing[0]
        if not isinstance(remaining, (int, float)) or remaining < requested:
            raise NotAuthorized(f"Insufficient usage allocation remaining for '{uid}'")
        store.set_or_add_attribute(uid, _USAGE_LIMITS_ATTR, remaining - requested)
        log.debug("GetUsageAllocation uid=%s consumed=%d remaining=%d", uid, requested, remaining - requested)

    return encode_text_string(Tag.UniqueIdentifier, uid)
