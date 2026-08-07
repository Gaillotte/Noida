"""Handle KMIP MAC operation — generate a MAC over data using a symmetric key."""

import logging
from pkcs11 import Mechanism
from ..core.enums import Tag, CryptographicAlgorithm
from ..core.ttlv import encode_byte_string, encode_text_string
from ..core.exceptions import ItemNotFound, MissingData
from ..lifecycle.state_machine import check_usage_allowed

log = logging.getLogger(__name__)

# KMIP HMAC CryptographicAlgorithm → PKCS#11 HMAC sign/verify Mechanism.
# The token always stores generic-secret HMAC keys as CKK_GENERIC_SECRET,
# so the mechanism must come from KMIP-side metadata, not CKA_KEY_TYPE.
HMAC_ALG_TO_MECH = {
    CryptographicAlgorithm.HMACMD5:    Mechanism._MD5_HMAC,
    CryptographicAlgorithm.HMACSHA1:   Mechanism.SHA_1_HMAC,
    CryptographicAlgorithm.HMACSHA224: Mechanism.SHA224_HMAC,
    CryptographicAlgorithm.HMACSHA256: Mechanism.SHA256_HMAC,
    CryptographicAlgorithm.HMACSHA384: Mechanism.SHA384_HMAC,
    CryptographicAlgorithm.HMACSHA512: Mechanism.SHA512_HMAC,
}


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("MAC requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required")
    uid = uid_item.value

    data_item = payload.get(Tag.Data)
    if data_item is None:
        raise MissingData("Data is required for MAC")
    data = data_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")

    check_usage_allowed(obj["state"], "mac", archived=bool(obj.get("archived")))

    algorithm = obj.get("cryptographic_algorithm")
    mechanism = HMAC_ALG_TO_MECH.get(algorithm, Mechanism.SHA256_HMAC)

    cka_ids = store.get_attribute(uid, "_pkcs11_cka_id")
    if not cka_ids:
        raise ItemNotFound("PKCS#11 handle not found")
    cka_id = bytes.fromhex(cka_ids[0])

    mac_value = shim.mac(cka_id, data, mechanism=mechanism)

    log.debug("MAC %d bytes for uid=%s", len(data), uid)
    return (
        encode_text_string(Tag.UniqueIdentifier, uid)
        + encode_byte_string(Tag.MACData, mac_value)
    )
