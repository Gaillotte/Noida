"""Handle KMIP Destroy operation — zeroize key on HSM and mark destroyed."""

import logging
from pkcs11.constants import ObjectClass
from ..core.enums import Tag, ObjectType, State
from ..core.ttlv import encode_text_string
from ..core.exceptions import ItemNotFound, IllegalOperation, MissingData
from ..lifecycle.state_machine import transition
from ..lifecycle.access_control import check_owner

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("Destroy requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required")
    uid = uid_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")
    check_owner(identity, obj.get("owner_identity"), "Destroy", store=store, uid=uid)

    # Validate transition
    transition(obj["state"], "destroy")

    # Destroy on HSM
    cka_ids = store.get_attribute(uid, "_pkcs11_cka_id")
    if cka_ids:
        cka_id = bytes.fromhex(cka_ids[0])
        obj_class = _pkcs11_class(obj["object_type"])
        shim.destroy_object(cka_id, obj_class)

    # Update metadata
    store.set_destroy(uid)
    log.info("Destroyed object uid=%s", uid)

    return encode_text_string(Tag.UniqueIdentifier, uid)


def _pkcs11_class(obj_type: int):
    if obj_type == ObjectType.SymmetricKey:
        return ObjectClass.SECRET_KEY
    if obj_type == ObjectType.PublicKey:
        return ObjectClass.PUBLIC_KEY
    if obj_type == ObjectType.PrivateKey:
        return ObjectClass.PRIVATE_KEY
    return None
