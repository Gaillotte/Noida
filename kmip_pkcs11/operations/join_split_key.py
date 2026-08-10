"""Handle KMIP JoinSplitKey operation — reconstruct a key from all of its
XOR split parts (see create_split_key.py for the scheme and its limits)."""

import logging
from ..core.enums import Tag, ObjectType, State
from ..core.ttlv import encode_text_string
from ..core.exceptions import MissingData, InvalidField, ItemNotFound
from ..lifecycle.access_control import check_owner
from .create import _parse_attributes

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("JoinSplitKey requires a request payload")

    uid_items = payload.get_all(Tag.UniqueIdentifier)
    if not uid_items:
        raise MissingData("UniqueIdentifier(s) of the split key parts are required")
    part_uids = [i.value for i in uid_items]
    if len(set(part_uids)) != len(part_uids):
        raise InvalidField("Duplicate part UniqueIdentifiers supplied")

    parts       = []
    group_id    = None
    total_parts = None
    algorithm   = None
    length      = None
    usage_mask  = None

    for part_uid in part_uids:
        obj = store.get_object(part_uid)
        if obj is None:
            raise ItemNotFound(f"Object '{part_uid}' not found")
        check_owner(identity, obj.get("owner_identity"), "JoinSplitKey")
        if obj["object_type"] != ObjectType.SplitKey:
            raise InvalidField(f"'{part_uid}' is not a SplitKey part")

        this_group = store.get_attribute(part_uid, "_split_key_group_id")
        this_total = store.get_attribute(part_uid, "_split_key_total_parts")
        if not this_group or not this_total:
            raise InvalidField(f"'{part_uid}' is missing split-key metadata")

        if group_id is None:
            group_id    = this_group[0]
            total_parts = this_total[0]
            algorithm   = obj["cryptographic_algorithm"]
            length      = obj["cryptographic_length"]
            usage_mask  = obj["usage_mask"]
        elif this_group[0] != group_id:
            raise InvalidField("All parts must belong to the same split-key group")

        parts.append(obj["raw_key_value"])

    if len(parts) != total_parts:
        raise InvalidField(f"XOR reconstruction requires all {total_parts} parts; got {len(parts)}")

    key_len = len(parts[0])
    reconstructed = bytearray(key_len)
    for part in parts:
        if len(part) != key_len:
            raise InvalidField("Split key parts have mismatched lengths")
        for i in range(key_len):
            reconstructed[i] ^= part[i]

    tmpl  = payload.get(Tag.TemplateAttribute) or payload.get(Tag.Attributes)
    attrs = _parse_attributes(tmpl)
    names       = attrs.get("names", [])
    extractable = attrs.get("extractable", True)

    label  = names[0] if names else f"kmip-joined-{algorithm}"
    cka_id = shim.import_symmetric_key(
        algorithm=algorithm,
        length_bits=length,
        key_bytes=bytes(reconstructed),
        label=label,
        extractable=extractable,
    )

    uid = store.create_object(
        object_type=ObjectType.SymmetricKey,
        state=State.Active,
        cryptographic_algorithm=algorithm,
        cryptographic_length=length,
        usage_mask=usage_mask,
        sensitive=False,
        extractable=extractable,
        owner_identity=identity,
        names=names,
    )
    store.add_attribute(uid, "_pkcs11_cka_id", cka_id.hex())

    log.info("JoinSplitKey group=%s -> %s", group_id, uid)
    return encode_text_string(Tag.UniqueIdentifier, uid)
