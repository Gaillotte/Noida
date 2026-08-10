"""Handle KMIP ReKey operation — create a new SymmetricKey inheriting the
attributes of an existing one, cross-linked to it for lineage tracking."""

import logging
from ..core.enums import Tag, ObjectType, CryptographicUsageMask
from ..core.ttlv import encode_text_string
from ..core.exceptions import ItemNotFound, MissingData, InvalidField
from ..lifecycle.access_control import check_owner
from .create import _parse_attributes, create_symmetric_key

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("ReKey requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier (of the SymmetricKey to rekey) is required")
    old_uid = uid_item.value

    old_obj = store.get_object(old_uid)
    if old_obj is None:
        raise ItemNotFound(f"Object '{old_uid}' not found")
    check_owner(identity, old_obj.get("owner_identity"), "ReKey")
    if old_obj["object_type"] != ObjectType.SymmetricKey:
        raise InvalidField("ReKey requires the UniqueIdentifier of a SymmetricKey")

    tmpl  = payload.get(Tag.TemplateAttribute) or payload.get(Tag.Attributes)
    attrs = _parse_attributes(tmpl)

    algorithm   = attrs.get("algorithm", old_obj["cryptographic_algorithm"])
    length      = attrs.get("length", old_obj["cryptographic_length"])
    usage_mask  = attrs.get("usage_mask", old_obj["usage_mask"] or CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt)
    names       = attrs.get("names", [])
    sensitive   = attrs.get("sensitive", bool(old_obj["sensitive"]))
    extractable = attrs.get("extractable", bool(old_obj["extractable"]))

    new_uid = create_symmetric_key(
        algorithm, length, usage_mask, names, sensitive, extractable, identity, store, shim
    )

    store.add_attribute(old_uid, "Link_ReplacementKey", new_uid)
    store.add_attribute(new_uid, "Link_ReplacedKey", old_uid)

    log.info("ReKeyed %s -> %s", old_uid, new_uid)
    return encode_text_string(Tag.UniqueIdentifier, new_uid)
