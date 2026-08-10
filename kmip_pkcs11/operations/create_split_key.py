"""Handle KMIP CreateSplitKey operation — split a symmetric key's raw
material into N XOR shares.

Only SplitKeyMethod.XOR is implemented, and only as N-of-N: every part is
required to reconstruct the key (see join_split_key.py). True threshold
(k-of-n) schemes like Shamir's polynomial secret sharing need finite-field
arithmetic this server has no library support for and are out of scope.
"""

import os
import uuid
import logging
from ..core.enums import Tag, ObjectType, State, SplitKeyMethod, CryptographicUsageMask
from ..core.ttlv import encode_text_string
from ..core.exceptions import MissingData, InvalidField, ItemNotFound, OperationNotSupported
from ..lifecycle.access_control import check_owner
from .create import _parse_attributes

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("CreateSplitKey requires a request payload")

    parts_item     = payload.get(Tag.SplitKeyParts)
    threshold_item = payload.get(Tag.SplitKeyThreshold)
    method_item    = payload.get(Tag.SplitKeyMethod)
    if parts_item is None:
        raise MissingData("SplitKeyParts is required")
    parts     = parts_item.value
    threshold = threshold_item.value if threshold_item else parts
    method    = method_item.value if method_item else SplitKeyMethod.XOR

    if method != SplitKeyMethod.XOR:
        raise OperationNotSupported(f"SplitKeyMethod {method!r} is not supported (only XOR)")
    if parts < 2:
        raise InvalidField("SplitKeyParts must be at least 2")
    if threshold != parts:
        raise OperationNotSupported("XOR splitting only supports SplitKeyThreshold == SplitKeyParts (N-of-N)")

    tmpl  = payload.get(Tag.TemplateAttribute) or payload.get(Tag.Attributes)
    attrs = _parse_attributes(tmpl)
    names = attrs.get("names", [])

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is not None:
        # Split an existing key's material
        source_uid = uid_item.value
        source = store.get_object(source_uid)
        if source is None:
            raise ItemNotFound(f"Object '{source_uid}' not found")
        check_owner(identity, source.get("owner_identity"), "CreateSplitKey")
        if not source["extractable"]:
            raise InvalidField("Source key must be extractable to split")
        cka_ids = store.get_attribute(source_uid, "_pkcs11_cka_id")
        if not cka_ids:
            raise ItemNotFound("PKCS#11 handle not found for source key")
        key_bytes  = shim.get_key_value(bytes.fromhex(cka_ids[0]))
        algorithm  = source["cryptographic_algorithm"]
        length     = source["cryptographic_length"]
        usage_mask = source["usage_mask"]
    else:
        algorithm  = attrs.get("algorithm")
        length     = attrs.get("length")
        usage_mask = attrs.get("usage_mask", CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt)
        if algorithm is None or length is None:
            raise MissingData(
                "CryptographicAlgorithm and CryptographicLength are required "
                "when no source UniqueIdentifier is given"
            )
        key_bytes = shim.generate_random(length // 8)

    key_len = len(key_bytes)
    shares  = [os.urandom(key_len) for _ in range(parts - 1)]
    last    = bytearray(key_bytes)
    for share in shares:
        for i in range(key_len):
            last[i] ^= share[i]
    shares.append(bytes(last))

    group_id  = str(uuid.uuid4())
    part_uids = []
    for index, part_bytes in enumerate(shares):
        part_names = [f"{n}-part{index}" for n in names] if names else None
        part_uid = store.create_object(
            object_type=ObjectType.SplitKey,
            state=State.Active,
            cryptographic_algorithm=algorithm,
            cryptographic_length=length,
            usage_mask=usage_mask,
            sensitive=True,
            extractable=True,
            owner_identity=identity,
            raw_key_value=part_bytes,
            names=part_names,
        )
        store.add_attribute(part_uid, "_split_key_group_id", group_id)
        store.add_attribute(part_uid, "_split_key_part_index", index)
        store.add_attribute(part_uid, "_split_key_total_parts", parts)
        part_uids.append(part_uid)

    log.info("CreateSplitKey group=%s parts=%d alg=%d len=%d", group_id, parts, algorithm, length)

    response = b""
    for part_uid in part_uids:
        response += encode_text_string(Tag.UniqueIdentifier, part_uid)
    return response
