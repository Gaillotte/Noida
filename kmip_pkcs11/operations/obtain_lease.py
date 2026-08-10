"""Handle KMIP ObtainLease operation — grant a time-boxed lease on an object.

The server does not track per-client lease state (no revocation-on-expiry
enforcement); this simply reports a fixed lease duration and the object's
last-change timestamp, matching the shape real clients expect.
"""

import logging
import datetime
from ..core.enums import Tag, State
from ..core.ttlv import encode_text_string, encode_interval, encode_datetime
from ..core.exceptions import ItemNotFound, MissingData
from ..lifecycle.state_machine import check_usage_allowed
from ..lifecycle.access_control import check_owner

log = logging.getLogger(__name__)

_LEASE_SECONDS = 3600


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("ObtainLease requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required")
    uid = uid_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")
    check_owner(identity, obj.get("owner_identity"), "ObtainLease", store=store, uid=uid)

    check_usage_allowed(obj["state"], "get", archived=bool(obj.get("archived")))

    last_change = datetime.datetime.fromtimestamp(obj["created_at"], tz=datetime.timezone.utc)

    log.debug("Leased uid=%s for %ds", uid, _LEASE_SECONDS)
    return (
        encode_text_string(Tag.UniqueIdentifier, uid)
        + encode_interval(Tag.LeaseTime, _LEASE_SECONDS)
        + encode_datetime(Tag.LastChangeDate, last_change)
    )
