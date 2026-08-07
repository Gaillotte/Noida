"""Handle KMIP Register operation — import client-supplied key material."""

import logging
from ..core.enums import Tag, ObjectType, State, CryptographicUsageMask, KeyFormatType, CertificateType
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

    uid = register_object(otype_item.value, payload, identity, store, shim)

    log.info("Registered object uid=%s type=%d", uid, otype_item.value)
    return encode_text_string(Tag.UniqueIdentifier, uid)


def register_object(obj_type, payload, identity, store, shim, uid=None) -> str:
    """Shared routing logic — creates a managed object from a Register/Import
    request payload. Passing `uid` lets Import target a client-supplied ID."""
    if obj_type == ObjectType.SymmetricKey:
        return _register_symmetric(payload, identity, store, shim, uid)
    elif obj_type == ObjectType.SecretData:
        return _register_secret_data(payload, identity, store, uid)
    elif obj_type == ObjectType.OpaqueObject:
        return _register_opaque(payload, identity, store, uid)
    elif obj_type == ObjectType.PublicKey:
        return _register_public_key(payload, identity, store, shim, uid)
    elif obj_type == ObjectType.PrivateKey:
        return _register_private_key(payload, identity, store, shim, uid)
    elif obj_type == ObjectType.Certificate:
        return _register_certificate(payload, identity, store, uid)
    else:
        raise OperationNotSupported(f"Register not implemented for ObjectType {obj_type}")


def _register_symmetric(payload, identity, store, shim, uid=None) -> str:
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
        uid=uid,
    )
    store.add_attribute(uid, "_pkcs11_cka_id", cka_id.hex())
    return uid


def _register_secret_data(payload, identity, store, uid=None) -> str:
    """Store secret data (password, HMAC secret) in metadata DB only."""
    key_block = payload.get(Tag.KeyBlock)
    key_value_item = key_block.get(Tag.KeyValue) if key_block else None
    key_material   = key_value_item.get(Tag.KeyMaterial) if key_value_item else None
    raw = key_material.value if key_material else b""

    return store.create_object(
        object_type=ObjectType.SecretData,
        state=State.Active,
        owner_identity=identity,
        raw_key_value=raw,
        extractable=True,
        sensitive=True,
        uid=uid,
    )


def _register_opaque(payload, identity, store, uid=None) -> str:
    opaque_item = payload.get(Tag.OpaqueObject) if hasattr(Tag, 'OpaqueObject') else None
    raw = opaque_item.value if opaque_item else b""
    return store.create_object(
        object_type=ObjectType.OpaqueObject,
        state=State.Active,
        owner_identity=identity,
        raw_key_value=raw,
        extractable=True,
        uid=uid,
    )


def _key_material_and_format(payload):
    key_block = payload.get(Tag.KeyBlock)
    if key_block is None:
        raise MissingData("KeyBlock is required")
    if key_block.get(Tag.KeyWrappingData) is not None:
        raise OperationNotSupported("Register of wrapped key material is not supported")

    key_value_item = key_block.get(Tag.KeyValue)
    key_material    = key_value_item.get(Tag.KeyMaterial) if key_value_item else None
    if key_material is None:
        raise MissingData("KeyMaterial is required")

    fmt_item = key_block.get(Tag.KeyFormatType)
    fmt      = fmt_item.value if fmt_item else KeyFormatType.PKCS1
    return key_material.value, fmt


def _register_public_key(payload, identity, store, shim, uid=None) -> str:
    der_bytes, fmt = _key_material_and_format(payload)

    tmpl      = payload.get(Tag.TemplateAttribute) or payload.get(Tag.Attributes) or payload.get(Tag.PublicKeyAttributes)
    attrs     = _parse_attributes(tmpl)
    algorithm = attrs.get("algorithm")
    names     = attrs.get("names", [])
    usage_mask= attrs.get("usage_mask", CryptographicUsageMask.Verify)

    if algorithm is None:
        raise MissingData("CryptographicAlgorithm is required")

    label  = names[0] if names else f"kmip-reg-pub-{algorithm}"
    cka_id = shim.import_public_key(
        algorithm=algorithm,
        der_bytes=der_bytes,
        key_format_type=fmt,
        label=label,
        verify=bool(usage_mask & CryptographicUsageMask.Verify),
    )

    uid = store.create_object(
        object_type=ObjectType.PublicKey,
        state=State.Active,
        cryptographic_algorithm=algorithm,
        usage_mask=usage_mask,
        sensitive=False,
        extractable=True,
        owner_identity=identity,
        names=names,
        uid=uid,
    )
    store.add_attribute(uid, "_pkcs11_cka_id", cka_id.hex())
    return uid


def _register_private_key(payload, identity, store, shim, uid=None) -> str:
    der_bytes, fmt = _key_material_and_format(payload)

    tmpl      = payload.get(Tag.TemplateAttribute) or payload.get(Tag.Attributes) or payload.get(Tag.PrivateKeyAttributes)
    attrs     = _parse_attributes(tmpl)
    algorithm = attrs.get("algorithm")
    names     = attrs.get("names", [])
    usage_mask= attrs.get("usage_mask", CryptographicUsageMask.Sign)
    extractable = attrs.get("extractable", False)
    sensitive   = attrs.get("sensitive", True)

    if algorithm is None:
        raise MissingData("CryptographicAlgorithm is required")

    label  = names[0] if names else f"kmip-reg-priv-{algorithm}"
    cka_id = shim.import_private_key(
        algorithm=algorithm,
        der_bytes=der_bytes,
        key_format_type=fmt,
        label=label,
        extractable=extractable,
        sensitive=sensitive,
        sign=bool(usage_mask & CryptographicUsageMask.Sign),
    )

    uid = store.create_object(
        object_type=ObjectType.PrivateKey,
        state=State.Active,
        cryptographic_algorithm=algorithm,
        usage_mask=usage_mask,
        sensitive=sensitive,
        extractable=extractable,
        owner_identity=identity,
        names=names,
        uid=uid,
    )
    store.add_attribute(uid, "_pkcs11_cka_id", cka_id.hex())
    return uid


def _register_certificate(payload, identity, store, uid=None) -> str:
    """Certificates are public, non-sensitive data — stored in metadata only (not on the token)."""
    cert_item = payload.get(Tag.Certificate)
    if cert_item is None:
        raise MissingData("Certificate is required for Certificate registration")

    type_item  = cert_item.get(Tag.CertificateType)
    value_item = cert_item.get(Tag.CertificateValue)
    if value_item is None:
        raise MissingData("CertificateValue is required")

    cert_type = type_item.value if type_item else CertificateType.X509

    uid = store.create_object(
        object_type=ObjectType.Certificate,
        state=State.Active,
        owner_identity=identity,
        raw_key_value=value_item.value,
        extractable=True,
        sensitive=False,
        uid=uid,
    )
    store.add_attribute(uid, "_certificate_type", cert_type)
    return uid
