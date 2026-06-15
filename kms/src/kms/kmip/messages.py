"""
KMIP 2.1 message construction and parsing helpers.

Provides functions to build well-formed KMIP request/response messages in
TTLV encoding and to parse incoming request bytes into structured dicts.

All public functions work at the message / batch-item level; lower-level
TTLV encoding is delegated to ttlv.py.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from .enums import (
    ItemType,
    Operation,
    ResultReason,
    ResultStatus,
    Tag,
)
from .ttlv import (
    TlvItem,
    decode_items,
    encode_item,
    find_all_children,
    find_child,
    get_int,
    get_text,
    make_enum,
    make_int,
    make_structure,
    make_text,
    make_datetime,
    make_bytes,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol version constants
# ---------------------------------------------------------------------------

_KMIP_MAJOR = 2
_KMIP_MINOR = 1


# ---------------------------------------------------------------------------
# Header builders
# ---------------------------------------------------------------------------


def build_request_header(
    version_major: int = _KMIP_MAJOR,
    version_minor: int = _KMIP_MINOR,
    batch_count: int = 1,
) -> TlvItem:
    """Build a KMIP Request Header structure.

    ::

        RequestHeader {
            ProtocolVersion {
                ProtocolVersionMajor (Integer)
                ProtocolVersionMinor (Integer)
            }
            BatchCount (Integer)
        }
    """
    protocol_version = make_structure(
        Tag.PROTOCOL_VERSION,
        [
            make_int(Tag.PROTOCOL_VERSION_MAJOR, version_major),
            make_int(Tag.PROTOCOL_VERSION_MINOR, version_minor),
        ],
    )
    return make_structure(
        Tag.REQUEST_HEADER,
        [
            protocol_version,
            make_int(Tag.BATCH_COUNT, batch_count),
        ],
    )


def build_response_header(
    version_major: int = _KMIP_MAJOR,
    version_minor: int = _KMIP_MINOR,
    batch_count: int = 1,
    timestamp: datetime | None = None,
) -> TlvItem:
    """Build a KMIP Response Header structure.

    ::

        ResponseHeader {
            ProtocolVersion {
                ProtocolVersionMajor (Integer)
                ProtocolVersionMinor (Integer)
            }
            TimeStamp (DateTime)
            BatchCount (Integer)
        }
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    protocol_version = make_structure(
        Tag.PROTOCOL_VERSION,
        [
            make_int(Tag.PROTOCOL_VERSION_MAJOR, version_major),
            make_int(Tag.PROTOCOL_VERSION_MINOR, version_minor),
        ],
    )
    return make_structure(
        Tag.RESPONSE_HEADER,
        [
            protocol_version,
            make_datetime(Tag.TIMESTAMP, timestamp),
            make_int(Tag.BATCH_COUNT, batch_count),
        ],
    )


# ---------------------------------------------------------------------------
# Batch item builders
# ---------------------------------------------------------------------------


def build_batch_item(
    operation: Operation,
    request_payload: TlvItem,
    batch_id: bytes | None = None,
) -> TlvItem:
    """Build a single request BatchItem structure.

    ::

        BatchItem {
            Operation (Enumeration)
            [UniqueBatchItemID (ByteString)]
            RequestPayload { ... }
        }
    """
    children: list[TlvItem] = [
        make_enum(Tag.OPERATION, int(operation)),
    ]
    if batch_id is not None:
        children.append(make_bytes(Tag.UNIQUE_BATCH_ITEM_ID, batch_id))
    children.append(request_payload)
    return make_structure(Tag.BATCH_ITEM, children)


def build_response_item(
    operation: Operation,
    status: ResultStatus,
    payload: TlvItem | None = None,
    reason: ResultReason | None = None,
    message: str | None = None,
    batch_id: bytes | None = None,
) -> TlvItem:
    """Build a single response BatchItem structure.

    ::

        BatchItem {
            Operation (Enumeration)
            [UniqueBatchItemID (ByteString)]
            ResultStatus (Enumeration)
            [ResultReason (Enumeration)]   -- on failure
            [ResultMessage (TextString)]   -- on failure
            [ResponsePayload { ... }]      -- on success
        }
    """
    children: list[TlvItem] = [
        make_enum(Tag.OPERATION, int(operation)),
    ]
    if batch_id is not None:
        children.append(make_bytes(Tag.UNIQUE_BATCH_ITEM_ID, batch_id))
    children.append(make_enum(Tag.RESULT_STATUS, int(status)))
    if reason is not None:
        children.append(make_enum(Tag.RESULT_REASON, int(reason)))
    if message is not None:
        children.append(make_text(Tag.RESULT_MESSAGE, message))
    if payload is not None:
        children.append(payload)
    return make_structure(Tag.BATCH_ITEM, children)


def build_error_item(
    operation: Operation,
    reason: ResultReason,
    message: str,
    batch_id: bytes | None = None,
) -> TlvItem:
    """Build a failure BatchItem with ResultStatus=OPERATION_FAILED."""
    return build_response_item(
        operation=operation,
        status=ResultStatus.OPERATION_FAILED,
        payload=None,
        reason=reason,
        message=message,
        batch_id=batch_id,
    )


# ---------------------------------------------------------------------------
# Full message builders
# ---------------------------------------------------------------------------


def build_request_message(batch_items: list[TlvItem]) -> bytes:
    """Encode a complete KMIP RequestMessage.

    ::

        RequestMessage {
            RequestHeader { ... }
            BatchItem { ... }
            ...
        }

    Returns the raw TTLV-encoded bytes ready to write to the wire.
    """
    header = build_request_header(batch_count=len(batch_items))
    msg = make_structure(Tag.REQUEST_MESSAGE, [header, *batch_items])
    return encode_item(msg)


def build_response_message(
    batch_items: list[TlvItem],
    timestamp: datetime | None = None,
) -> bytes:
    """Encode a complete KMIP ResponseMessage.

    ::

        ResponseMessage {
            ResponseHeader { ... }
            BatchItem { ... }
            ...
        }

    Returns the raw TTLV-encoded bytes ready to write to the wire.
    """
    header = build_response_header(
        batch_count=len(batch_items),
        timestamp=timestamp,
    )
    msg = make_structure(Tag.RESPONSE_MESSAGE, [header, *batch_items])
    return encode_item(msg)


# ---------------------------------------------------------------------------
# Request parser
# ---------------------------------------------------------------------------


def parse_request_message(data: bytes) -> dict:
    """Parse a complete KMIP RequestMessage from raw bytes.

    Returns a dict::

        {
            "header": TlvItem,           # REQUEST_HEADER structure
            "version_major": int,
            "version_minor": int,
            "batch_count": int,
            "batch_items": list[TlvItem],  # raw BATCH_ITEM structures
        }

    Raises ``ValueError`` if the message is malformed.
    """
    items = decode_items(data)
    if not items:
        raise ValueError("Empty KMIP message: no items decoded")

    # Top-level must be a RequestMessage structure
    msg = items[0]
    if msg.tag != Tag.REQUEST_MESSAGE:
        raise ValueError(
            f"Expected RequestMessage (tag 0x{Tag.REQUEST_MESSAGE:06X}), "
            f"got tag 0x{msg.tag:06X}"
        )
    if msg.type != ItemType.STRUCTURE:
        raise ValueError("RequestMessage must be a Structure")

    # Extract header
    header = find_child(msg, Tag.REQUEST_HEADER)
    if header is None:
        raise ValueError("RequestMessage missing RequestHeader")

    # Parse protocol version
    pv = find_child(header, Tag.PROTOCOL_VERSION)
    if pv is None:
        raise ValueError("RequestHeader missing ProtocolVersion")

    pv_major_item = find_child(pv, Tag.PROTOCOL_VERSION_MAJOR)
    pv_minor_item = find_child(pv, Tag.PROTOCOL_VERSION_MINOR)
    if pv_major_item is None or pv_minor_item is None:
        raise ValueError("ProtocolVersion missing Major or Minor")

    version_major = get_int(pv_major_item)
    version_minor = get_int(pv_minor_item)

    # Parse batch count
    batch_count_item = find_child(header, Tag.BATCH_COUNT)
    batch_count = get_int(batch_count_item) if batch_count_item is not None else 0

    # Collect batch items
    batch_items = find_all_children(msg, Tag.BATCH_ITEM)

    if len(batch_items) != batch_count:
        logger.warning(
            "BatchCount header says %d but found %d BatchItem(s)",
            batch_count,
            len(batch_items),
        )

    return {
        "header": header,
        "version_major": version_major,
        "version_minor": version_minor,
        "batch_count": batch_count,
        "batch_items": batch_items,
    }


# ---------------------------------------------------------------------------
# KMIP 1.x compatibility: Attribute structure
# ---------------------------------------------------------------------------


def build_attribute_v1(name: str, value_item: TlvItem) -> TlvItem:
    """Build a KMIP 1.x-style Attribute structure.

    ::

        Attribute {
            AttributeName  (TextString) = <name>
            AttributeValue <value_item>
        }

    In KMIP 2.0+ attributes are represented differently (CurrentAttribute /
    NewAttribute), but 1.x-style is needed when talking to legacy clients.
    The *value_item* tag is overridden to Tag.ATTRIBUTE_VALUE.
    """
    # Wrap the value item under the ATTRIBUTE_VALUE tag
    import dataclasses

    value_wrapped = dataclasses.replace(value_item, tag=Tag.ATTRIBUTE_VALUE)
    return make_structure(
        Tag.ATTRIBUTE,
        [
            make_text(Tag.ATTRIBUTE_NAME, name),
            value_wrapped,
        ],
    )


# ---------------------------------------------------------------------------
# Batch item convenience parsers
# ---------------------------------------------------------------------------


def get_batch_item_operation(batch_item: TlvItem) -> Operation:
    """Extract the Operation enumeration from a BatchItem."""
    op_item = find_child(batch_item, Tag.OPERATION)
    if op_item is None:
        raise ValueError("BatchItem missing Operation")
    return Operation(get_int(op_item))


def get_batch_item_id(batch_item: TlvItem) -> bytes | None:
    """Extract the optional UniqueBatchItemID from a BatchItem."""
    id_item = find_child(batch_item, Tag.UNIQUE_BATCH_ITEM_ID)
    if id_item is None:
        return None
    assert isinstance(id_item.value, bytes)
    return id_item.value


def get_request_payload(batch_item: TlvItem) -> TlvItem | None:
    """Extract the RequestPayload from a BatchItem, if present."""
    return find_child(batch_item, Tag.REQUEST_PAYLOAD)
