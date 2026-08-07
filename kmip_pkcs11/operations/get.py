"""Handle KMIP Get operation — retrieve key material from HSM."""

import logging
from ..core.enums import (
    Tag, ObjectType, State, KeyFormatType,
    CryptographicAlgorithm
)
from ..core.ttlv import (
    encode_text_string, encode_byte_string, encode_structure,
    encode_enumeration, encode_integer
)
from ..core.exceptions import ItemNotFound, NotExtractable, IllegalOperation, MissingData
from ..lifecycle.state_machine import check_usage_allowed

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("Get requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required")
    uid = uid_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")

    check_usage_allowed(obj["state"], "get", archived=bool(obj.get("archived")))

    obj_type = obj["object_type"]

    if obj_type == ObjectType.SymmetricKey:
        return _get_symmetric(uid, obj, store, shim)
    elif obj_type in (ObjectType.PublicKey, ObjectType.PrivateKey):
        return _get_asymmetric(uid, obj, store, shim, obj_type)
    elif obj_type == ObjectType.SecretData:
        return _get_secret_data(uid, obj, store)
    elif obj_type == ObjectType.Certificate:
        return _get_certificate(uid, obj, store)
    elif obj_type == ObjectType.SplitKey:
        return _get_split_key(uid, obj, store)
    else:
        raise NotExtractable(f"Get not supported for object type {obj_type}")


def _get_symmetric(uid, obj, store, shim) -> bytes:
    if not obj["extractable"]:
        raise NotExtractable("Key is not extractable")

    cka_ids = store.get_attribute(uid, "_pkcs11_cka_id")
    if not cka_ids:
        raise ItemNotFound("PKCS#11 handle not found for object")

    cka_id    = bytes.fromhex(cka_ids[0])
    key_bytes = shim.get_key_value(cka_id)

    key_material = encode_byte_string(Tag.KeyMaterial, key_bytes)
    key_value    = encode_structure(Tag.KeyValue, key_material)
    key_block    = encode_structure(
        Tag.KeyBlock,
        encode_enumeration(Tag.KeyFormatType, KeyFormatType.Raw)
        + key_value
        + encode_integer(Tag.CryptographicLength, obj["cryptographic_length"] or len(key_bytes) * 8)
        + encode_enumeration(Tag.CryptographicAlgorithm, obj["cryptographic_algorithm"] or 0)
    )
    sym_key  = encode_structure(Tag.ManagedObject, key_block)

    return (
        encode_text_string(Tag.UniqueIdentifier, uid)
        + encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
        + sym_key
    )


def _get_asymmetric(uid, obj, store, shim, obj_type) -> bytes:
    if obj_type == ObjectType.PrivateKey and not obj["extractable"]:
        raise NotExtractable("Private key is not extractable")

    cka_ids = store.get_attribute(uid, "_pkcs11_cka_id")
    if not cka_ids:
        raise ItemNotFound("PKCS#11 handle not found")

    cka_id = bytes.fromhex(cka_ids[0])

    algorithm = obj.get("cryptographic_algorithm")

    if obj_type == ObjectType.PublicKey:
        key_bytes = shim.get_public_key_der(cka_id)
        fmt       = KeyFormatType.PKCS1 if algorithm == CryptographicAlgorithm.RSA else KeyFormatType.Raw
    else:
        key_bytes = shim.get_private_key_der(cka_id)
        # RSA returns PKCS#1 DER (component encoding); EC/DH return a raw scalar.
        fmt = KeyFormatType.PKCS1 if algorithm == CryptographicAlgorithm.RSA else KeyFormatType.Raw

    key_material = encode_byte_string(Tag.KeyMaterial, key_bytes)
    key_value    = encode_structure(Tag.KeyValue, key_material)
    key_block    = encode_structure(
        Tag.KeyBlock,
        encode_enumeration(Tag.KeyFormatType, fmt)
        + key_value
    )
    key_struct = encode_structure(Tag.ManagedObject, key_block)

    return (
        encode_text_string(Tag.UniqueIdentifier, uid)
        + encode_enumeration(Tag.ObjectType, obj_type)
        + key_struct
    )


def _get_certificate(uid, obj, store) -> bytes:
    from ..core.enums import CertificateType
    raw = obj.get("raw_key_value") or b""
    cert_type_rows = store.get_attribute(uid, "_certificate_type")
    cert_type = cert_type_rows[0] if cert_type_rows else CertificateType.X509
    cert = encode_structure(
        Tag.Certificate,
        encode_enumeration(Tag.CertificateType, cert_type)
        + encode_byte_string(Tag.CertificateValue, raw)
    )
    return (
        encode_text_string(Tag.UniqueIdentifier, uid)
        + encode_enumeration(Tag.ObjectType, ObjectType.Certificate)
        + cert
    )


def _get_split_key(uid, obj, store) -> bytes:
    if not obj["extractable"]:
        raise NotExtractable("Split key part is not extractable")
    raw = obj.get("raw_key_value") or b""
    key_value = encode_structure(
        Tag.KeyValue,
        encode_byte_string(Tag.KeyMaterial, raw)
    )
    key_block = encode_structure(
        Tag.KeyBlock,
        encode_enumeration(Tag.KeyFormatType, KeyFormatType.Raw)
        + key_value
        + encode_integer(Tag.CryptographicLength, obj["cryptographic_length"] or len(raw) * 8)
        + encode_enumeration(Tag.CryptographicAlgorithm, obj["cryptographic_algorithm"] or 0)
    )
    split_key = encode_structure(Tag.ManagedObject, key_block)
    return (
        encode_text_string(Tag.UniqueIdentifier, uid)
        + encode_enumeration(Tag.ObjectType, ObjectType.SplitKey)
        + split_key
    )


def _get_secret_data(uid, obj, store) -> bytes:
    raw = obj.get("raw_key_value") or b""
    key_value = encode_structure(
        Tag.KeyValue,
        encode_byte_string(Tag.KeyMaterial, raw)
    )
    key_block = encode_structure(
        Tag.KeyBlock,
        encode_enumeration(Tag.KeyFormatType, KeyFormatType.Opaque)
        + key_value
    )
    secret = encode_structure(Tag.ManagedObject, key_block)
    return (
        encode_text_string(Tag.UniqueIdentifier, uid)
        + encode_enumeration(Tag.ObjectType, ObjectType.SecretData)
        + secret
    )
