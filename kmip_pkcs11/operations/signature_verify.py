"""Handle KMIP SignatureVerify operation."""

import logging
from pkcs11 import Mechanism
from ..core.enums import Tag, CryptographicAlgorithm, HashingAlgorithm, ValidityIndicator
from ..core.ttlv import encode_text_string, encode_enumeration
from ..core.exceptions import ItemNotFound, MissingData
from ..lifecycle.state_machine import check_usage_allowed
from ..lifecycle.access_control import check_owner

log = logging.getLogger(__name__)

_RSA_HASH_TO_MECH = {
    HashingAlgorithm.SHA_1:   Mechanism.SHA1_RSA_PKCS,
    HashingAlgorithm.SHA_256: Mechanism.SHA256_RSA_PKCS,
    HashingAlgorithm.SHA_384: Mechanism.SHA384_RSA_PKCS,
    HashingAlgorithm.SHA_512: Mechanism.SHA512_RSA_PKCS,
}

_EC_HASH_TO_MECH = {
    HashingAlgorithm.SHA_1:   Mechanism.ECDSA_SHA1,
    HashingAlgorithm.SHA_256: Mechanism.ECDSA_SHA256,
    HashingAlgorithm.SHA_384: Mechanism.ECDSA_SHA384,
    HashingAlgorithm.SHA_512: Mechanism.ECDSA_SHA512,
}

_DSA_HASH_TO_MECH = {
    HashingAlgorithm.SHA_1:   Mechanism.DSA_SHA1,
    HashingAlgorithm.SHA_224: Mechanism.DSA_SHA224,
    HashingAlgorithm.SHA_256: Mechanism.DSA_SHA256,
    HashingAlgorithm.SHA_384: Mechanism.DSA_SHA384,
    HashingAlgorithm.SHA_512: Mechanism.DSA_SHA512,
}

_EC_ALGORITHMS = {CryptographicAlgorithm.EC, CryptographicAlgorithm.ECDSA}


def _select_mechanism(algorithm, hash_alg):
    if algorithm in _EC_ALGORITHMS:
        return _EC_HASH_TO_MECH.get(hash_alg, Mechanism.ECDSA_SHA256)
    if algorithm == CryptographicAlgorithm.DSA:
        return _DSA_HASH_TO_MECH.get(hash_alg, Mechanism.DSA_SHA256)
    return _RSA_HASH_TO_MECH.get(hash_alg, Mechanism.SHA256_RSA_PKCS)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("SignatureVerify requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required")
    uid = uid_item.value

    data_item = payload.get(Tag.Data)
    if data_item is None:
        raise MissingData("Data is required for SignatureVerify")
    data = data_item.value

    sig_item = payload.get(Tag.SignatureData)
    if sig_item is None:
        raise MissingData("SignatureData is required for SignatureVerify")
    signature = sig_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")
    check_owner(identity, obj.get("owner_identity"), "SignatureVerify")

    check_usage_allowed(obj["state"], "verify", archived=bool(obj.get("archived")))

    hash_alg = None
    crypto_params = payload.get(Tag.CryptographicParameters)
    if crypto_params:
        hash_item = crypto_params.get(Tag.HashingAlgorithm)
        if hash_item:
            hash_alg = hash_item.value

    algorithm = obj.get("cryptographic_algorithm")
    mechanism = _select_mechanism(algorithm, hash_alg)

    cka_ids = store.get_attribute(uid, "_pkcs11_cka_id")
    if not cka_ids:
        raise ItemNotFound("PKCS#11 handle not found")
    cka_id = bytes.fromhex(cka_ids[0])

    valid = shim.verify(cka_id, data, signature, mechanism=mechanism)
    indicator = ValidityIndicator.Valid if valid else ValidityIndicator.Invalid

    log.debug("SignatureVerify uid=%s result=%s", uid, indicator.name)
    return (
        encode_text_string(Tag.UniqueIdentifier, uid)
        + encode_enumeration(Tag.ValidityIndicator, indicator)
    )
