"""Unit tests for the TTLV encoder/decoder."""

import datetime
import struct
import pytest

from kmip_pkcs11.core.ttlv import (
    encode_integer, encode_text_string, encode_byte_string,
    encode_enumeration, encode_boolean, encode_datetime, encode_structure,
    encode_long_integer, decode, decode_one, decode_all,
)
from kmip_pkcs11.core.enums import Tag, Type


TAG  = 0x420001
TAG2 = 0x420002


class TestEncodeDecode:
    def _roundtrip(self, encoded: bytes):
        item, consumed = decode(encoded, 0)
        assert consumed == len(encoded)
        return item

    def test_integer_positive(self):
        enc  = encode_integer(TAG, 42)
        item = self._roundtrip(enc)
        assert item.tag   == TAG
        assert item.type  == Type.Integer
        assert item.value == 42

    def test_integer_negative(self):
        enc  = encode_integer(TAG, -1)
        item = self._roundtrip(enc)
        assert item.value == -1

    def test_integer_max(self):
        enc  = encode_integer(TAG, 2**31 - 1)
        item = self._roundtrip(enc)
        assert item.value == 2**31 - 1

    def test_long_integer(self):
        val  = 2**40
        enc  = encode_long_integer(TAG, val)
        item = self._roundtrip(enc)
        assert item.value == val

    def test_enumeration(self):
        enc  = encode_enumeration(TAG, 7)
        item = self._roundtrip(enc)
        assert item.type  == Type.Enumeration
        assert item.value == 7

    def test_boolean_true(self):
        enc  = encode_boolean(TAG, True)
        item = self._roundtrip(enc)
        assert item.type  == Type.Boolean
        assert item.value is True

    def test_boolean_false(self):
        item = self._roundtrip(encode_boolean(TAG, False))
        assert item.value is False

    def test_text_string_ascii(self):
        enc  = encode_text_string(TAG, "hello")
        item = self._roundtrip(enc)
        assert item.type  == Type.TextString
        assert item.value == "hello"

    def test_text_string_unicode(self):
        enc  = encode_text_string(TAG, "héllo wörld")
        item = self._roundtrip(enc)
        assert item.value == "héllo wörld"

    def test_text_string_empty(self):
        item = self._roundtrip(encode_text_string(TAG, ""))
        assert item.value == ""

    def test_byte_string(self):
        data = b"\x00\x01\x02\x03"
        enc  = encode_byte_string(TAG, data)
        item = self._roundtrip(enc)
        assert item.type  == Type.ByteString
        assert item.value == data

    def test_byte_string_empty(self):
        item = self._roundtrip(encode_byte_string(TAG, b""))
        assert item.value == b""

    def test_datetime(self):
        dt  = datetime.datetime(2025, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
        enc = encode_datetime(TAG, dt)
        item = self._roundtrip(enc)
        assert item.value.year  == 2025
        assert item.value.month == 1

    def test_structure_nested(self):
        inner = encode_integer(TAG2, 99)
        outer = encode_structure(TAG, inner)
        item  = decode_one(outer)
        assert item.type          == Type.Structure
        assert len(item.children) == 1
        child = item.children[0]
        assert child.tag   == TAG2
        assert child.value == 99

    def test_structure_multiple_children(self):
        inner = (
            encode_integer(TAG, 1)
            + encode_text_string(TAG2, "two")
            + encode_boolean(0x420003, True)
        )
        outer = encode_structure(0x420010, inner)
        item  = decode_one(outer)
        assert len(item.children) == 3
        assert item.children[0].value == 1
        assert item.children[1].value == "two"
        assert item.children[2].value is True

    def test_decode_all_multiple_items(self):
        data  = encode_integer(TAG, 1) + encode_integer(TAG2, 2)
        items = decode_all(data)
        assert len(items) == 2
        assert items[0].value == 1
        assert items[1].value == 2

    def test_padding_alignment(self):
        # All TTLV values must be padded to 8-byte boundary
        enc = encode_text_string(TAG, "AB")  # 2 bytes → padded to 8
        assert len(enc) == 8 + 8  # 8-byte header + 8-byte padded value

    def test_structure_item_get(self):
        inner  = encode_text_string(TAG2, "found")
        outer  = encode_structure(TAG, inner)
        parent = decode_one(outer)
        child  = parent.get(TAG2)
        assert child is not None
        assert child.value == "found"

    def test_get_returns_none_for_missing_tag(self):
        outer = encode_structure(TAG, encode_integer(TAG2, 0))
        item  = decode_one(outer)
        assert item.get(0x999999) is None

    def test_get_value_default(self):
        outer = encode_structure(TAG, encode_integer(TAG2, 42))
        item  = decode_one(outer)
        assert item.get_value(TAG2) == 42
        assert item.get_value(0x999999, "default") == "default"


class TestTTLVErrorHandling:
    def test_truncated_header_raises(self):
        with pytest.raises(ValueError, match="Truncated"):
            decode(b"\x42\x00\x01", 0)

    def test_truncated_value_raises(self):
        # Header says 8 bytes but we only have 4
        header = struct.pack('>I', (TAG << 8) | Type.Integer)[1:]
        header += struct.pack('>I', 8)  # claims 8-byte value
        with pytest.raises(ValueError, match="Truncated"):
            decode(header + b"\x00\x00\x00", 0)
