"""Handle KMIP Archive operation — move a managed object to archival storage.

Archival is orthogonal to the KMIP lifecycle State: an archived object keeps
its State but becomes unusable for anything except metadata reads until it
is Recovered (see recover.py and lifecycle/state_machine.py's `archived` gate).
"""

import logging
from ..core.enums import Tag, State
from ..core.ttlv import encode_text_string
from ..core.exceptions import ItemNotFound, IllegalOperation, MissingData
from ..lifecycle.access_control import check_owner

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("Archive requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required")
    uid = uid_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")
    check_owner(identity, obj.get("owner_identity"), "Archive", store=store, uid=uid)

    if obj["state"] in (State.Destroyed, State.DestroyedCompromised):
        raise IllegalOperation("Cannot archive a destroyed object")
    if obj.get("archived"):
        raise IllegalOperation("Object is already archived")

    store.archive_object(uid)
    log.info("Archived uid=%s", uid)

    return encode_text_string(Tag.UniqueIdentifier, uid)
