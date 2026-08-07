"""Handle KMIP RNGRetrieve operation — generate random bytes from the HSM."""

import logging
from ..core.enums import Tag
from ..core.ttlv import encode_byte_string
from ..core.exceptions import MissingData

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    length = 32  # KMIP default when DataLength omitted
    if payload is not None:
        dl_item = payload.get(Tag.DataLength)
        if dl_item is not None:
            length = dl_item.value

    if length <= 0 or length > 65536:
        raise MissingData(f"DataLength {length!r} must be in range [1, 65536]")

    data = shim.generate_random(length)
    return encode_byte_string(Tag.Data, data)
