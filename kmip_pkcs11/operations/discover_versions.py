"""Handle KMIP DiscoverVersions operation."""

import logging
from ..core.enums import Tag
from ..core.ttlv import encode_structure, encode_integer

log = logging.getLogger(__name__)

SUPPORTED_VERSIONS = [(2, 1), (1, 4), (1, 3), (1, 2), (1, 1), (1, 0)]


def handle(payload, identity: str, store, shim) -> bytes:
    response = b""
    for major, minor in SUPPORTED_VERSIONS:
        ver = encode_integer(Tag.ProtocolVersionMajor, major)
        ver += encode_integer(Tag.ProtocolVersionMinor, minor)
        response += encode_structure(Tag.ProtocolVersion, ver)
    return response
