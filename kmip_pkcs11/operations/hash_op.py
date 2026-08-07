"""Handle KMIP Hash operation — compute a digest of provided data (no key involved)."""

import logging
from ..core.enums import Tag
from ..core.ttlv import encode_byte_string
from ..core.exceptions import MissingData

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("Hash requires a request payload")

    data_item = payload.get(Tag.Data)
    if data_item is None:
        raise MissingData("Data is required for Hash")
    data = data_item.value

    crypto_params = payload.get(Tag.CryptographicParameters)
    hash_item = crypto_params.get(Tag.HashingAlgorithm) if crypto_params else None
    if hash_item is None:
        raise MissingData("CryptographicParameters/HashingAlgorithm is required for Hash")
    hash_alg = hash_item.value

    digest = shim.hash_data(data, hash_alg)

    log.debug("Hash %d bytes -> %d bytes (alg=%r)", len(data), len(digest), hash_alg)
    return encode_byte_string(Tag.Data, digest)
