"""Handle KMIP RNGSeed operation — mix client-supplied entropy into the HSM's RNG."""

import logging
from ..core.enums import Tag
from ..core.ttlv import encode_integer
from ..core.exceptions import MissingData

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("RNGSeed requires a request payload")

    data_item = payload.get(Tag.Data)
    if data_item is None:
        raise MissingData("Data (seed material) is required for RNGSeed")
    seed = data_item.value

    shim.seed_random(seed)
    log.debug("Seeded RNG with %d bytes", len(seed))

    return encode_integer(Tag.DataLength, len(seed))
