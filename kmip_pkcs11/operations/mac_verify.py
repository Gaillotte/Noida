"""Handle KMIP MACVerify operation — verify a MAC over data using a symmetric key."""

import logging
from ..core.enums import Tag, ValidityIndicator
from ..core.ttlv import encode_text_string, encode_enumeration
from ..core.exceptions import ItemNotFound, MissingData
from ..lifecycle.state_machine import check_usage_allowed
from .mac import HMAC_ALG_TO_MECH
from pkcs11 import Mechanism

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("MACVerify requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required")
    uid = uid_item.value

    data_item = payload.get(Tag.Data)
    if data_item is None:
        raise MissingData("Data is required for MACVerify")
    data = data_item.value

    mac_item = payload.get(Tag.MACData)
    if mac_item is None:
        raise MissingData("MACData is required for MACVerify")
    mac_value = mac_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")

    check_usage_allowed(obj["state"], "mac_verify", archived=bool(obj.get("archived")))

    algorithm = obj.get("cryptographic_algorithm")
    mechanism = HMAC_ALG_TO_MECH.get(algorithm, Mechanism.SHA256_HMAC)

    cka_ids = store.get_attribute(uid, "_pkcs11_cka_id")
    if not cka_ids:
        raise ItemNotFound("PKCS#11 handle not found")
    cka_id = bytes.fromhex(cka_ids[0])

    valid = shim.mac_verify(cka_id, data, mac_value, mechanism=mechanism)
    indicator = ValidityIndicator.Valid if valid else ValidityIndicator.Invalid

    log.debug("MACVerify uid=%s result=%s", uid, indicator.name)
    return (
        encode_text_string(Tag.UniqueIdentifier, uid)
        + encode_enumeration(Tag.ValidityIndicator, indicator)
    )
