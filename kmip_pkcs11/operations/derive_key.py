"""Handle KMIP DeriveKey operation — derive a symmetric key via DH/ECDH key
agreement between a local private key and a peer's public value."""

import logging
from ..core.enums import (
    Tag, ObjectType, State, CryptographicAlgorithm, CryptographicUsageMask,
    DerivationMethod,
)
from ..core.ttlv import encode_text_string
from ..core.exceptions import ItemNotFound, MissingData, OperationNotSupported
from ..lifecycle.state_machine import check_usage_allowed
from ..lifecycle.access_control import check_owner
from .create import _parse_attributes

log = logging.getLogger(__name__)

_KEY_AGREEMENT_ALGORITHMS = {CryptographicAlgorithm.DH, CryptographicAlgorithm.ECDH}


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("DeriveKey requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required for DeriveKey")
    base_uid = uid_item.value

    obj = store.get_object(base_uid)
    if obj is None:
        raise ItemNotFound(f"Object '{base_uid}' not found")
    check_owner(identity, obj.get("owner_identity"), "DeriveKey")

    base_algorithm = obj.get("cryptographic_algorithm")
    if base_algorithm not in _KEY_AGREEMENT_ALGORITHMS:
        raise OperationNotSupported(
            f"DeriveKey is only supported for DH/ECDH base keys, got algorithm {base_algorithm}"
        )

    check_usage_allowed(obj["state"], "derive", archived=bool(obj.get("archived")))

    method_item = payload.get(Tag.DerivationMethod)
    method = method_item.value if method_item else DerivationMethod.ASYMMETRIC_KEY
    if method != DerivationMethod.ASYMMETRIC_KEY:
        raise OperationNotSupported(f"DerivationMethod {method!r} is not supported")

    deriv_params = payload.get(Tag.DerivationParameters)
    data_item    = deriv_params.get(Tag.DerivationData) if deriv_params else None
    if data_item is None:
        raise MissingData("DerivationParameters/DerivationData (peer public value) is required")
    peer_value = data_item.value

    tmpl        = payload.get(Tag.TemplateAttribute) or payload.get(Tag.Attributes)
    attrs       = _parse_attributes(tmpl)
    algorithm   = attrs.get("algorithm", CryptographicAlgorithm.AES)
    length      = attrs.get("length", 128)
    usage_mask  = attrs.get("usage_mask", CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt)
    names       = attrs.get("names", [])
    extractable = attrs.get("extractable", False)
    sensitive   = attrs.get("sensitive", True)

    cka_ids = store.get_attribute(base_uid, "_pkcs11_cka_id")
    if not cka_ids:
        raise ItemNotFound("PKCS#11 handle not found")
    priv_cka_id = bytes.fromhex(cka_ids[0])

    label = names[0] if names else f"kmip-derived-{algorithm}"
    derived_cka_id = shim.derive_key(
        priv_cka_id,
        base_algorithm,
        peer_value,
        target_algorithm=algorithm,
        target_length_bits=length,
        label=label,
        extractable=extractable,
        sensitive=sensitive,
        encrypt=bool(usage_mask & CryptographicUsageMask.Encrypt),
        decrypt=bool(usage_mask & CryptographicUsageMask.Decrypt),
    )

    uid = store.create_object(
        object_type=ObjectType.SymmetricKey,
        state=State.Active,
        cryptographic_algorithm=algorithm,
        cryptographic_length=length,
        usage_mask=usage_mask,
        sensitive=sensitive,
        extractable=extractable,
        owner_identity=identity,
        names=names,
    )
    store.add_attribute(uid, "_pkcs11_cka_id", derived_cka_id.hex())

    log.info("Derived key uid=%s from base=%s alg=%d len=%d", uid, base_uid, algorithm, length)
    return encode_text_string(Tag.UniqueIdentifier, uid)
