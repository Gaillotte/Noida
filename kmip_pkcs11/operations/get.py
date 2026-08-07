"""Handle KMIP Get operation — retrieve key material from HSM."""

import logging
from ..core.enums import (
    Tag, ObjectType, State, KeyFormatType,
    CryptographicAlgorithm, CryptographicUsageMask, WrappingMethod
)
from ..core.ttlv import (
    encode_text_string, encode_byte_string, encode_structure,
    encode_enumeration, encode_integer
)
from ..core.exceptions import (
    ItemNotFound, NotExtractable, IllegalOperation, MissingData, OperationNotSupported
)
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
    wrap_spec = payload.get(Tag.KeyWrappingSpecification)

    if obj_type == ObjectType.SymmetricKey:
        return _get_symmetric(uid, obj, store, shim, wrap_spec)
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


def _get_symmetric(uid, obj, store, shim, wrap_spec=None) -> bytes:
    if not obj["extractable"]:
        raise NotExtractable("Key is not extractable")

    cka_ids = store.get_attribute(uid, "_pkcs11_cka_id")
    if not cka_ids:
        raise ItemNotFound("PKCS#11 handle not found for object")
    cka_id = bytes.fromhex(cka_ids[0])

    wrapping_data = b""
    if wrap_spec is not None:
        wrapping_uid = _resolve_wrapping_key(wrap_spec, store)
        wrapping_cka_id = _wrapping_key_cka_id(wrapping_uid, store, "encrypt", CryptographicUsageMask.WrapKey)
        key_bytes = shim.wrap_key(wrapping_cka_id, cka_id)
        wrapping_data = encode_structure(
            Tag.KeyWrappingData,
            encode_enumeration(Tag.WrappingMethod, WrappingMethod.Encrypt)
            + encode_structure(
                Tag.EncryptionKeyInformation,
                encode_text_string(Tag.UniqueIdentifier, wrapping_uid)
            )
        )
    else:
        key_bytes = shim.get_key_value(cka_id)

    key_material = encode_byte_string(Tag.KeyMaterial, key_bytes)
    key_value    = encode_structure(Tag.KeyValue, key_material)
    key_block    = encode_structure(
        Tag.KeyBlock,
        encode_enumeration(Tag.KeyFormatType, KeyFormatType.Raw)
        + key_value
        + encode_integer(Tag.CryptographicLength, obj["cryptographic_length"] or len(key_bytes) * 8)
        + encode_enumeration(Tag.CryptographicAlgorithm, obj["cryptographic_algorithm"] or 0)
        + wrapping_data
    )
    sym_key  = encode_structure(Tag.SymmetricKey, key_block)

    return (
        encode_text_string(Tag.UniqueIdentifier, uid)
        + encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
        + sym_key
    )


def _resolve_wrapping_key(wrap_spec, store) -> str:
    """Parse a KeyWrappingSpecification, returning the wrapping key's UniqueIdentifier.
    Only WrappingMethod.Encrypt (via CKM_AES_KEY_WRAP_PAD) is supported."""
    method_item = wrap_spec.get(Tag.WrappingMethod)
    method = method_item.value if method_item else WrappingMethod.Encrypt
    if method != WrappingMethod.Encrypt:
        raise OperationNotSupported(f"KeyWrappingSpecification method {method!r} is not supported (only Encrypt)")

    enc_key_info = wrap_spec.get(Tag.EncryptionKeyInformation)
    if enc_key_info is None:
        raise MissingData("KeyWrappingSpecification/EncryptionKeyInformation is required")
    wrapping_uid_item = enc_key_info.get(Tag.UniqueIdentifier)
    if wrapping_uid_item is None:
        raise MissingData("EncryptionKeyInformation/UniqueIdentifier is required")
    return wrapping_uid_item.value


def _wrapping_key_cka_id(wrapping_uid, store, usage_op: str, required_mask: int) -> bytes:
    """Resolve and validate a wrapping/unwrapping SymmetricKey, returning its cka_id."""
    wrapping_obj = store.get_object(wrapping_uid)
    if wrapping_obj is None:
        raise ItemNotFound(f"Wrapping key '{wrapping_uid}' not found")
    if wrapping_obj["object_type"] != ObjectType.SymmetricKey:
        raise OperationNotSupported("Key wrapping currently only supports a SymmetricKey wrapping key")
    if not (wrapping_obj["usage_mask"] and (wrapping_obj["usage_mask"] & required_mask)):
        raise IllegalOperation(f"Wrapping key '{wrapping_uid}' does not permit the required usage")
    check_usage_allowed(wrapping_obj["state"], usage_op, archived=bool(wrapping_obj.get("archived")))

    wrapping_cka_ids = store.get_attribute(wrapping_uid, "_pkcs11_cka_id")
    if not wrapping_cka_ids:
        raise ItemNotFound("PKCS#11 handle not found for wrapping key")
    return bytes.fromhex(wrapping_cka_ids[0])


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
    wrapper_tag = Tag.PublicKey if obj_type == ObjectType.PublicKey else Tag.PrivateKey
    key_struct = encode_structure(wrapper_tag, key_block)

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
    split_key = encode_structure(Tag.SplitKey, key_block)
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
    secret = encode_structure(Tag.SecretData, key_block)
    return (
        encode_text_string(Tag.UniqueIdentifier, uid)
        + encode_enumeration(Tag.ObjectType, ObjectType.SecretData)
        + secret
    )
