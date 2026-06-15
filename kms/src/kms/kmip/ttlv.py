"""
TTLV (Tag-Type-Length-Value) encoder and decoder for KMIP 2.1.

Wire format for a single item:
  [3 bytes: Tag, big-endian]
  [1 byte:  Type]
  [4 bytes: Length, big-endian — actual value byte count, NO padding]
  [N bytes: Value]
  [P bytes: zero-padding so that (Length + P) % 8 == 0]

Exceptions:
  - Structure (type 0x01): Length = total byte count of all enclosed items
    (already 8-byte aligned by construction); no extra padding after.
  - Integer / Enumeration / Interval: Length=4, followed by 4 zero-padding
    bytes (totalling 8 bytes for value+pad).
  - Boolean: Length=8, value is 8-byte big-endian 0 or 1.
  - LongInteger / DateTime: Length=8, 8-byte big-endian signed/unsigned int.
  - BigInteger: Length = variable (multiple of 8 already, per spec).
  - TextString / ByteString: Length = byte count; padded up to next 8-byte
    boundary (padding NOT counted in Length).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Union

from .enums import ItemType, Tag


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class TlvItem:
    """One TTLV item.

    For structures, *value* is a list[TlvItem].
    For all other types, *value* is bytes containing the raw encoded value
    (without padding).
    """

    tag: int
    type: ItemType
    value: Union[bytes, list["TlvItem"]]

    def __repr__(self) -> str:
        try:
            tag_name = Tag(self.tag).name
        except ValueError:
            tag_name = f"0x{self.tag:06X}"
        if self.type == ItemType.STRUCTURE:
            assert isinstance(self.value, list)
            return f"TlvItem({tag_name}, STRUCTURE, [{len(self.value)} children])"
        assert isinstance(self.value, bytes)
        return f"TlvItem({tag_name}, {self.type.name}, {self.value.hex()})"


# ---------------------------------------------------------------------------
# Padding helpers
# ---------------------------------------------------------------------------


def _pad_to_8(data: bytes) -> bytes:
    """Return *data* zero-padded so its length is a multiple of 8."""
    remainder = len(data) % 8
    if remainder == 0:
        return data
    return data + b"\x00" * (8 - remainder)


def _padded_length(n: int) -> int:
    """Return the smallest multiple of 8 >= n."""
    remainder = n % 8
    if remainder == 0:
        return n
    return n + (8 - remainder)


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------


def _encode_header(tag: int, item_type: ItemType, length: int) -> bytes:
    """Encode the 8-byte TTLV header: [3-byte tag][1-byte type][4-byte len]."""
    return struct.pack(">I", (tag << 8) | int(item_type)) + struct.pack(">I", length)


def encode_item(item: TlvItem) -> bytes:
    """Encode a single TlvItem into bytes including header and padding."""
    if item.type == ItemType.STRUCTURE:
        assert isinstance(item.value, list)
        # Encode all children first, then wrap
        inner = b"".join(encode_item(child) for child in item.value)
        header = _encode_header(item.tag, ItemType.STRUCTURE, len(inner))
        return header + inner
        # No extra padding for structures (inner content is already aligned)

    assert isinstance(item.value, bytes)
    value = item.value

    if item.type in (ItemType.INTEGER, ItemType.ENUMERATION, ItemType.INTERVAL):
        # Length always 4; value (4 bytes) + 4 zero-padding bytes = 8 bytes total
        assert len(value) == 4, f"Expected 4-byte value for {item.type.name}"
        header = _encode_header(item.tag, item.type, 4)
        return header + value + b"\x00\x00\x00\x00"

    if item.type in (ItemType.LONG_INTEGER, ItemType.DATE_TIME, ItemType.BOOLEAN):
        # Length always 8; value is exactly 8 bytes
        assert len(value) == 8, f"Expected 8-byte value for {item.type.name}"
        header = _encode_header(item.tag, item.type, 8)
        return header + value

    if item.type in (ItemType.TEXT_STRING, ItemType.BYTE_STRING, ItemType.BIG_INTEGER):
        header = _encode_header(item.tag, item.type, len(value))
        return header + _pad_to_8(value)

    raise ValueError(f"Unknown ItemType: {item.type!r}")


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------


def decode_item(data: bytes, offset: int) -> tuple[TlvItem, int]:
    """Decode a single TTLV item starting at *offset* in *data*.

    Returns ``(item, new_offset)`` where *new_offset* is the position in
    *data* after the fully decoded item (including consumed padding).

    Raises ``ValueError`` on malformed input.
    """
    if offset + 8 > len(data):
        raise ValueError(
            f"Insufficient data for TTLV header at offset {offset}: "
            f"need 8 bytes, have {len(data) - offset}"
        )

    # First 4 bytes: [3-byte tag | 1-byte type]
    tag_type_word = struct.unpack_from(">I", data, offset)[0]
    tag = (tag_type_word >> 8) & 0xFFFFFF
    type_byte = tag_type_word & 0xFF

    # Next 4 bytes: length
    length = struct.unpack_from(">I", data, offset + 4)[0]
    offset += 8

    try:
        item_type = ItemType(type_byte)
    except ValueError as exc:
        raise ValueError(f"Unknown TTLV type byte 0x{type_byte:02X} for tag 0x{tag:06X}") from exc

    if item_type == ItemType.STRUCTURE:
        end = offset + length
        if end > len(data):
            raise ValueError(
                f"Structure at tag 0x{tag:06X} claims length {length} "
                f"but only {len(data) - offset} bytes remain"
            )
        children: list[TlvItem] = []
        pos = offset
        while pos < end:
            child, pos = decode_item(data, pos)
            children.append(child)
        return TlvItem(tag=tag, type=item_type, value=children), end

    # Scalar types
    if offset + length > len(data):
        raise ValueError(
            f"Value for tag 0x{tag:06X} type {item_type.name} claims length {length} "
            f"but only {len(data) - offset} bytes remain"
        )

    raw_value = data[offset : offset + length]

    # Advance offset past value + padding
    padded = _padded_length(length)
    offset += padded

    # Validate lengths for fixed-size types
    if item_type in (ItemType.INTEGER, ItemType.ENUMERATION, ItemType.INTERVAL):
        if length != 4:
            raise ValueError(
                f"Expected length=4 for {item_type.name} (tag 0x{tag:06X}), got {length}"
            )
    elif item_type in (ItemType.LONG_INTEGER, ItemType.DATE_TIME, ItemType.BOOLEAN):
        if length != 8:
            raise ValueError(
                f"Expected length=8 for {item_type.name} (tag 0x{tag:06X}), got {length}"
            )

    return TlvItem(tag=tag, type=item_type, value=raw_value), offset


def decode_items(data: bytes) -> list[TlvItem]:
    """Decode all top-level TTLV items from *data*.

    Raises ``ValueError`` if parsing fails.
    """
    items: list[TlvItem] = []
    offset = 0
    while offset < len(data):
        item, offset = decode_item(data, offset)
        items.append(item)
    return items


# ---------------------------------------------------------------------------
# Construction helpers
# ---------------------------------------------------------------------------


def make_structure(tag: int, children: list[TlvItem]) -> TlvItem:
    """Create a Structure TlvItem."""
    return TlvItem(tag=tag, type=ItemType.STRUCTURE, value=list(children))


def make_int(tag: int, value: int) -> TlvItem:
    """Create an Integer TlvItem (signed 32-bit)."""
    return TlvItem(tag=tag, type=ItemType.INTEGER, value=struct.pack(">i", value))


def make_enum(tag: int, value: int) -> TlvItem:
    """Create an Enumeration TlvItem (unsigned 32-bit)."""
    return TlvItem(tag=tag, type=ItemType.ENUMERATION, value=struct.pack(">I", value))


def make_long(tag: int, value: int) -> TlvItem:
    """Create a LongInteger TlvItem (signed 64-bit)."""
    return TlvItem(tag=tag, type=ItemType.LONG_INTEGER, value=struct.pack(">q", value))


def make_text(tag: int, value: str) -> TlvItem:
    """Create a TextString TlvItem."""
    return TlvItem(tag=tag, type=ItemType.TEXT_STRING, value=value.encode("utf-8"))


def make_bytes(tag: int, value: bytes) -> TlvItem:
    """Create a ByteString TlvItem."""
    return TlvItem(tag=tag, type=ItemType.BYTE_STRING, value=value)


def make_datetime(tag: int, dt: datetime) -> TlvItem:
    """Create a DateTime TlvItem from a *datetime* object.

    Naive datetimes are assumed to be UTC.
    """
    if dt.tzinfo is None:
        ts = int(dt.replace(tzinfo=timezone.utc).timestamp())
    else:
        ts = int(dt.timestamp())
    return TlvItem(tag=tag, type=ItemType.DATE_TIME, value=struct.pack(">q", ts))


def make_bool(tag: int, value: bool) -> TlvItem:
    """Create a Boolean TlvItem."""
    return TlvItem(
        tag=tag,
        type=ItemType.BOOLEAN,
        value=struct.pack(">q", 1 if value else 0),
    )


# ---------------------------------------------------------------------------
# Navigation helpers
# ---------------------------------------------------------------------------


def find_child(item: TlvItem, tag: int) -> TlvItem | None:
    """Return the first child of *item* with the given *tag*, or None."""
    if item.type != ItemType.STRUCTURE:
        return None
    assert isinstance(item.value, list)
    for child in item.value:
        if child.tag == tag:
            return child
    return None


def find_all_children(item: TlvItem, tag: int) -> list[TlvItem]:
    """Return all direct children of *item* with the given *tag*."""
    if item.type != ItemType.STRUCTURE:
        return []
    assert isinstance(item.value, list)
    return [child for child in item.value if child.tag == tag]


# ---------------------------------------------------------------------------
# Value extraction helpers
# ---------------------------------------------------------------------------


def get_int(item: TlvItem) -> int:
    """Extract a signed integer from an Integer or Enumeration or Interval item."""
    assert isinstance(item.value, bytes)
    if item.type in (ItemType.INTEGER, ItemType.INTERVAL):
        return struct.unpack(">i", item.value)[0]
    if item.type == ItemType.ENUMERATION:
        return struct.unpack(">I", item.value)[0]
    if item.type == ItemType.LONG_INTEGER:
        return struct.unpack(">q", item.value)[0]
    raise TypeError(f"Cannot extract int from {item.type.name} item")


def get_text(item: TlvItem) -> str:
    """Extract a string from a TextString item."""
    assert isinstance(item.value, bytes)
    if item.type != ItemType.TEXT_STRING:
        raise TypeError(f"Expected TextString, got {item.type.name}")
    return item.value.decode("utf-8")


def get_bytes(item: TlvItem) -> bytes:
    """Extract raw bytes from a ByteString item."""
    assert isinstance(item.value, bytes)
    if item.type != ItemType.BYTE_STRING:
        raise TypeError(f"Expected ByteString, got {item.type.name}")
    return item.value


def get_datetime(item: TlvItem) -> datetime:
    """Extract a UTC-aware datetime from a DateTime item."""
    assert isinstance(item.value, bytes)
    if item.type != ItemType.DATE_TIME:
        raise TypeError(f"Expected DateTime, got {item.type.name}")
    ts = struct.unpack(">q", item.value)[0]
    return datetime.fromtimestamp(ts, tz=timezone.utc)
