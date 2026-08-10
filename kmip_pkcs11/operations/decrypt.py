"""Handle KMIP Decrypt operation."""

import logging
from ..core.enums import Tag, BlockCipherMode
from ..core.ttlv import encode_byte_string, encode_text_string
from ..core.exceptions import ItemNotFound, MissingData
from ..lifecycle.state_machine import check_usage_allowed
from ..lifecycle.access_control import check_owner

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("Decrypt requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required")
    uid = uid_item.value

    data_item = payload.get(Tag.Data)
    if data_item is None:
        raise MissingData("Data is required for Decrypt")
    ciphertext = data_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")
    check_owner(identity, obj.get("owner_identity"), "Decrypt", store=store, uid=uid)

    check_usage_allowed(obj["state"], "decrypt", archived=bool(obj.get("archived")))

    iv_item  = payload.get(Tag.IVCounterNonce)
    iv       = iv_item.value if iv_item else None

    aad_item = payload.get(Tag.AuthenticatedEncryptionAdditionalData)
    aad      = aad_item.value if aad_item else None

    tag_item = payload.get(Tag.AuthenticatedEncryptionTag)
    auth_tag = tag_item.value if tag_item else None

    crypto_params = payload.get(Tag.CryptographicParameters)
    mode = BlockCipherMode.CBC
    if crypto_params:
        mode_item = crypto_params.get(Tag.CryptographicParameters_BlockCipherMode)
        if mode_item:
            mode = mode_item.value

    cka_ids = store.get_attribute(uid, "_pkcs11_cka_id")
    if not cka_ids:
        raise ItemNotFound("PKCS#11 handle not found")
    cka_id = bytes.fromhex(cka_ids[0])

    plaintext = shim.decrypt(cka_id, ciphertext, mechanism_id=mode, iv=iv, aad=aad, tag=auth_tag)

    log.debug("Decrypted %d bytes for uid=%s", len(ciphertext), uid)

    return (
        encode_text_string(Tag.UniqueIdentifier, uid)
        + encode_byte_string(Tag.Data, plaintext)
    )
