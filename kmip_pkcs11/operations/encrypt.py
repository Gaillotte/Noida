"""Handle KMIP Encrypt operation."""

import logging
import os
from ..core.enums import Tag, BlockCipherMode, CryptographicAlgorithm
from ..core.ttlv import encode_byte_string, encode_structure, encode_text_string
from ..core.exceptions import ItemNotFound, MissingData
from ..lifecycle.state_machine import check_usage_allowed
from ..lifecycle.access_control import check_owner

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("Encrypt requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier is required")
    uid = uid_item.value

    data_item = payload.get(Tag.Data)
    if data_item is None:
        raise MissingData("Data is required for Encrypt")
    plaintext = data_item.value

    obj = store.get_object(uid)
    if obj is None:
        raise ItemNotFound(f"Object '{uid}' not found")
    check_owner(identity, obj.get("owner_identity"), "Encrypt", store=store, uid=uid)

    check_usage_allowed(obj["state"], "encrypt", archived=bool(obj.get("archived")))

    aad_item = payload.get(Tag.AuthenticatedEncryptionAdditionalData)
    aad      = aad_item.value if aad_item else None

    # Mechanism: default to CBC — must be parsed before IV so we can pick the right nonce length
    crypto_params = payload.get(Tag.CryptographicParameters)
    mode = BlockCipherMode.CBC
    if crypto_params:
        mode_item = crypto_params.get(Tag.CryptographicParameters_BlockCipherMode)
        if mode_item:
            mode = mode_item.value

    # IV — pick caller-supplied value, else generate mode-appropriate nonce
    algorithm = obj.get("cryptographic_algorithm")
    iv_item = payload.get(Tag.IVCounterNonce)
    if iv_item:
        iv = iv_item.value
    elif mode in (BlockCipherMode.GCM, BlockCipherMode.CTR, BlockCipherMode.CCM):
        iv = os.urandom(12)   # AEAD/stream modes: 12-byte nonce
    elif algorithm in (CryptographicAlgorithm.DES, CryptographicAlgorithm.TDES):
        iv = os.urandom(8)    # DES/3DES: 64-bit block → 8-byte IV
    else:
        iv = os.urandom(16)   # AES CBC, ECB, CFB, OFB: standard 16-byte IV

    cka_ids = store.get_attribute(uid, "_pkcs11_cka_id")
    if not cka_ids:
        raise ItemNotFound("PKCS#11 handle not found")
    cka_id = bytes.fromhex(cka_ids[0])

    ciphertext, tag = shim.encrypt(cka_id, plaintext, mechanism_id=mode, iv=iv, aad=aad)

    response = encode_text_string(Tag.UniqueIdentifier, uid)
    response += encode_byte_string(Tag.Data, ciphertext)
    response += encode_byte_string(Tag.IVCounterNonce, iv)
    if tag:
        response += encode_byte_string(Tag.AuthenticatedEncryptionTag, tag)

    log.debug("Encrypted %d bytes for uid=%s", len(plaintext), uid)
    return response
