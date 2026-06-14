"""Handle KMIP Register operation — import client-supplied key material."""

import logging
from ..core.enums import Tag, ObjectType, State, CryptographicUsageMask, KeyFormatType
from ..core.ttlv import encode_text_string
from ..core.exceptions import MissingData, InvalidField, OperationNotSupported
from .create import _parse_attributes

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("Register requires a request payload")

    otype_item = payload.get(Tag.ObjectType)
    if otype_item is None:
        raise MissingData("ObjectType is required for Register")

    obj_type = otype_item.value

    if obj_type == ObjectType.SymmetricKey:
        uid = _register_symmetric(payload, identity, store, shim)
    elif obj_type == ObjectType.SecretData:
        uid = _register_secret_data(payload, identity, store)
    elif obj_type == ObjectType.OpaqueObject:
        uid = _register_opaque(payload, identity, store)
    else:
        raise OperationNotSupported(f"Register not implemented for ObjectType {obj_type}")

    log.info("Registered object uid=%s type=%d", uid, obj_type)
    return encode_text_string(Tag.UniqueIdentifier, uid)


def _register_symmetric(payload, identity, store, shim) -> str:
    key_block = payload.get(Tag.KeyBlock)
    if key_block is None:
        raise MissingData("KeyBlock is required for SymmetricKey registration")

    key_value_item = key_block.get(Tag.KeyValue)
    key_material   = key_value_item.get(Tag.KeyMaterial) if key_value_item else None
    if key_material is None:
        raise MissingData("KeyMaterial is required")

    key_bytes = key_material.value
    length    = len(key_bytes) * 8

    tmpl      = payload.get(Tag.TemplateAttribute) or payload.get(Tag.Attributes)
    attrs     = _parse_attributes(tmpl)
    algorithm = attrs.get("algorithm")
    names     = attrs.get("names", [])
    usage_mask= attrs.get("usage_mask", CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt)

    if algorithm is None:
        raise MissingData("CryptographicAlgorithm is required")

    label  = names[0] if names else f"kmip-reg-{algorithm}"
    cka_id = shim.import_symmetric_key(
        algorithm=algorithm,
        length_bits=length,
        key_bytes=key_bytes,
        label=label,
        extractable=True,
    )

    uid = store.create_object(
        object_type=ObjectType.SymmetricKey,
        pkcs11_handle=int.from_bytes(cka_id[:8], 'big') & 0x7FFFFFFFFFFFFFFF,
        state=State.Active,
        cryptographic_algorithm=algorithm,
        cryptographic_length=length,
        usage_mask=usage_mask,
        sensitive=False,
        extractable=True,
        owner_identity=identity,
        names=names,
    )
    store.add_attribute(uid, "_pkcs11_cka_id", cka_id.hex())
    return uid


def _register_secret_data(payload, identity, store) -> str:
    """Store secret data (password, HMAC secret) in metadata DB only."""
    key_block = payload.get(Tag.KeyBlock)
    key_value_item = key_block.get(Tag.KeyValue) if key_block else None
    key_material   = key_value_item.get(Tag.KeyMaterial) if key_value_item else None
    raw = key_material.value if key_material else b""

    uid = store.create_object(
        object_type=ObjectType.SecretData,
        state=State.Active,
        owner_identity=identity,
        raw_key_value=raw,
        extractable=True,
        sensitive=True,
    )
    return uid


def _register_opaque(payload, identity, store) -> str:
    opaque_item = payload.get(Tag.OpaqueObject) if hasattr(Tag, 'OpaqueObject') else None
    raw = opaque_item.value if opaque_item else b""
    uid = store.create_object(
        object_type=ObjectType.OpaqueObject,
        state=State.Active,
        owner_identity=identity,
        raw_key_value=raw,
        extractable=True,
    )
    return uid
