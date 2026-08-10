"""Handle KMIP Import operation (v2.0+) — register client-supplied material
under a client-chosen UniqueIdentifier, optionally replacing an existing object."""

import logging
from ..core.enums import Tag, ObjectType
from ..core.ttlv import encode_text_string
from ..core.exceptions import MissingData, InvalidField
from ..lifecycle.access_control import check_owner
from .register import register_object
from .destroy import _pkcs11_class

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("Import requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required for Import")
    uid = uid_item.value

    otype_item = payload.get(Tag.ObjectType)
    if otype_item is None:
        raise MissingData("ObjectType is required for Import")
    obj_type = otype_item.value

    replace_item     = payload.get(Tag.ReplaceExisting)
    replace_existing = bool(replace_item.value) if replace_item else False

    existing = store.get_object(uid)
    if existing is not None:
        if not replace_existing:
            raise InvalidField(f"Object '{uid}' already exists; ReplaceExisting was not set")
        check_owner(identity, existing.get("owner_identity"), "Import (replace)")

        cka_ids = store.get_attribute(uid, "_pkcs11_cka_id")
        if cka_ids:
            obj_class = _pkcs11_class(existing["object_type"])
            shim.destroy_object(bytes.fromhex(cka_ids[0]), obj_class)
        store.delete_object(uid)
        log.info("Import replacing existing object uid=%s", uid)

    result_uid = register_object(obj_type, payload, identity, store, shim, uid=uid)

    log.info("Imported object uid=%s type=%d", result_uid, obj_type)
    return encode_text_string(Tag.UniqueIdentifier, result_uid)
