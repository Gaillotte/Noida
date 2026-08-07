"""
TTLV (Tag–Type–Length–Value) encoder/decoder for KMIP.

Wire format per KMIP spec:
  [3-byte tag][1-byte type][4-byte length][N-byte value padded to 8-byte boundary]

All integers are big-endian.
"""

import struct
import datetime
from typing import Any, List, Tuple

from .enums import Tag, Type


# ─────────────────────────────── encoding ────────────────────────────────────

def _pad8(n: int) -> int:
    """Round up to the nearest multiple of 8."""
    return (n + 7) & ~7


def encode_item(tag: int, type_: int, value_bytes: bytes) -> bytes:
    """Encode a single TTLV item (header + padded value)."""
    length = len(value_bytes)
    padded = value_bytes + b'\x00' * (_pad8(length) - length)
    # 3-byte tag + 1-byte type packed as big-endian uint32
    header = struct.pack('>I', (tag << 8) | (type_ & 0xFF))
    header += struct.pack('>I', length)   # 4-byte length
    return header + padded


def encode_structure(tag: int, children: bytes) -> bytes:
    return encode_item(tag, Type.Structure, children)


def encode_text_string(tag: int, value: str) -> bytes:
    return encode_item(tag, Type.TextString, value.encode('utf-8'))


def encode_byte_string(tag: int, value: bytes) -> bytes:
    return encode_item(tag, Type.ByteString, value)


def encode_integer(tag: int, value: int) -> bytes:
    return encode_item(tag, Type.Integer, struct.pack('>i', value))


def encode_long_integer(tag: int, value: int) -> bytes:
    return encode_item(tag, Type.LongInteger, struct.pack('>q', value))


def encode_enumeration(tag: int, value: int) -> bytes:
    return encode_item(tag, Type.Enumeration, struct.pack('>I', value))


def encode_boolean(tag: int, value: bool) -> bytes:
    return encode_item(tag, Type.Boolean, struct.pack('>q', int(value)))


def encode_datetime(tag: int, value: datetime.datetime) -> bytes:
    ts = int(value.timestamp())
    return encode_item(tag, Type.DateTime, struct.pack('>q', ts))


def encode_big_integer(tag: int, value: int) -> bytes:
    length = (value.bit_length() + 7) // 8 or 1
    return encode_item(tag, Type.BigInteger, value.to_bytes(length, 'big'))


def encode_interval(tag: int, seconds: int) -> bytes:
    return encode_item(tag, Type.Interval, struct.pack('>I', seconds))


# ─────────────────────────────── decoding ────────────────────────────────────

class TTLVItem:
    __slots__ = ('tag', 'type', 'value', 'children')

    def __init__(self, tag: int, type_: int, value: Any, children=None):
        self.tag      = tag
        self.type     = type_
        self.value    = value
        self.children: List['TTLVItem'] = children or []

    def __repr__(self):
        tag_name = _tag_name(self.tag)
        if self.type == Type.Structure:
            return f"TTLVItem({tag_name}, Structure, [{len(self.children)} children])"
        return f"TTLVItem({tag_name}, {Type(self.type).name}, {self.value!r})"

    def get(self, tag: int) -> 'TTLVItem | None':
        """Return first child with given tag."""
        for c in self.children:
            if c.tag == tag:
                return c
        return None

    def get_all(self, tag: int) -> List['TTLVItem']:
        return [c for c in self.children if c.tag == tag]

    def get_value(self, tag: int, default=None):
        item = self.get(tag)
        return item.value if item is not None else default


def _tag_name(tag: int) -> str:
    try:
        return Tag(tag).name
    except ValueError:
        return f"0x{tag:06X}"


def decode(data: bytes, offset: int = 0) -> Tuple['TTLVItem', int]:
    """Decode one TTLV item from data at offset. Returns (item, new_offset)."""
    if len(data) - offset < 8:
        raise ValueError(f"Truncated TTLV header at offset {offset}")

    raw_tag_type = struct.unpack_from('>I', data, offset)[0]
    tag   = (raw_tag_type >> 8) & 0xFFFFFF
    type_ = raw_tag_type & 0xFF
    offset += 4

    length = struct.unpack_from('>I', data, offset)[0]
    offset += 4

    padded_len = _pad8(length)

    if len(data) - offset < padded_len:
        raise ValueError(f"Truncated TTLV value at offset {offset}, need {padded_len} bytes")

    raw_value = data[offset: offset + length]
    offset += padded_len

    if type_ == Type.Structure:
        children = []
        pos = 0
        raw_child_data = data[offset - padded_len: offset - padded_len + length]
        pos = 0
        while pos < length:
            child, pos = decode(raw_child_data, pos)
            children.append(child)
        item = TTLVItem(tag, type_, None, children)
    elif type_ == Type.TextString:
        item = TTLVItem(tag, type_, raw_value.decode('utf-8'))
    elif type_ == Type.ByteString:
        item = TTLVItem(tag, type_, raw_value)
    elif type_ == Type.Integer:
        item = TTLVItem(tag, type_, struct.unpack('>i', raw_value)[0])
    elif type_ == Type.LongInteger:
        item = TTLVItem(tag, type_, struct.unpack('>q', raw_value)[0])
    elif type_ == Type.Enumeration:
        item = TTLVItem(tag, type_, struct.unpack('>I', raw_value)[0])
    elif type_ == Type.Boolean:
        item = TTLVItem(tag, type_, struct.unpack('>q', raw_value)[0] != 0)
    elif type_ == Type.DateTime:
        ts = struct.unpack('>q', raw_value)[0]
        item = TTLVItem(tag, type_, datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc))
    elif type_ == Type.BigInteger:
        item = TTLVItem(tag, type_, int.from_bytes(raw_value, 'big'))
    elif type_ == Type.Interval:
        item = TTLVItem(tag, type_, struct.unpack('>I', raw_value)[0])
    else:
        item = TTLVItem(tag, type_, raw_value)

    return item, offset


def decode_all(data: bytes) -> List[TTLVItem]:
    """Decode all top-level TTLV items from a byte buffer."""
    items = []
    offset = 0
    while offset < len(data):
        item, offset = decode(data, offset)
        items.append(item)
    return items


def decode_one(data: bytes) -> TTLVItem:
    item, _ = decode(data, 0)
    return item
