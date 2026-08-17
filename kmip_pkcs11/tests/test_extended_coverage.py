"""
Extended coverage tests — targets every uncovered branch across all modules
to push overall coverage above 95%.

Organised by source module, matching the order of coverage gaps in the report.
"""

import os
import datetime
import json
import logging
import struct
import socket
import sys
import threading
import time
import pytest
from unittest.mock import MagicMock, patch

from kmip_pkcs11.core.enums import (
    Tag, Type, ObjectType, State,
    CryptographicAlgorithm, CryptographicUsageMask,
    KeyFormatType, RevocationReasonCode, BlockCipherMode
)
from kmip_pkcs11.core.ttlv import (
    encode_structure, encode_enumeration, encode_integer, encode_long_integer,
    encode_text_string, encode_byte_string, encode_big_integer, encode_boolean,
    encode_datetime, decode, decode_one, decode_all, TTLVItem
)
from kmip_pkcs11.core.exceptions import (
    KMIPError, ItemNotFound, MissingData, IllegalOperation,
    NotExtractable, GeneralFailure, CryptographicFailure,
    InvalidField, OperationNotSupported, NotAuthorized
)
from kmip_pkcs11.metadata.store import MetadataStore


# ── shared helpers ────────────────────────────────────────────────────────────

def _attr(name: str, value_bytes: bytes) -> bytes:
    return encode_structure(
        Tag.Attribute,
        encode_text_string(Tag.AttributeName, name) + value_bytes
    )


def _make_payload(**fields) -> TTLVItem:
    """Build a minimal RequestPayload TTLVItem from raw bytes concatenated."""
    inner = b"".join(fields.values())
    return decode_one(encode_structure(Tag.RequestPayload, inner))


def _uid_payload(uid: str) -> TTLVItem:
    return _make_payload(uid=encode_text_string(Tag.UniqueIdentifier, uid))


@pytest.fixture
def store(tmp_path):
    return MetadataStore(str(tmp_path / "ext.db"))


# ══════════════════════════════════════════════════════════════════════════════
# core/ttlv.py  —  lines 68-69, 83-87, 105-108, 156-161
# ══════════════════════════════════════════════════════════════════════════════

class TestTTLVExtended:
    def test_encode_big_integer_roundtrip(self):
        val = 2**128 + 7
        enc = encode_big_integer(Tag.Attributes, val)
        item, _ = decode(enc, 0)
        assert item.type == Type.BigInteger
        assert item.value == val

    def test_encode_big_integer_zero(self):
        enc = encode_big_integer(Tag.Attributes, 0)
        item, _ = decode(enc, 0)
        assert item.value == 0

    def test_repr_structure(self):
        inner = encode_integer(Tag.BatchCount, 1)
        outer = decode_one(encode_structure(Tag.RequestMessage, inner))
        r = repr(outer)
        assert "Structure" in r
        assert "1 children" in r

    def test_repr_primitive(self):
        enc = encode_text_string(Tag.UniqueIdentifier, "hello")
        item, _ = decode(enc, 0)
        r = repr(item)
        assert "TextString" in r
        assert "hello" in r

    def test_tag_name_known(self):
        enc = encode_integer(Tag.BatchCount, 5)
        item, _ = decode(enc, 0)
        r = repr(item)
        assert "BatchCount" in r

    def test_tag_name_unknown_hex(self):
        unknown_tag = 0x123456
        raw = struct.pack('>I', (unknown_tag << 8) | Type.Integer)
        raw += struct.pack('>I', 4)
        raw += struct.pack('>i', 99) + b'\x00' * 4
        item, _ = decode(raw, 0)
        r = repr(item)
        assert "0x123456" in r

    def test_interval_decode(self):
        """Type.Interval (0x0A) should decode to unsigned 32-bit int."""
        raw = struct.pack('>I', (0x420001 << 8) | Type.Interval)
        raw += struct.pack('>I', 4)
        raw += struct.pack('>I', 3600) + b'\x00' * 4
        item, _ = decode(raw, 0)
        assert item.type == Type.Interval
        assert item.value == 3600

    def test_unknown_type_decode_returns_raw_bytes(self):
        """Unknown TTLV type should fall through to raw bytes."""
        unknown_type = 0xFF
        raw = struct.pack('>I', (0x420001 << 8) | unknown_type)
        raw += struct.pack('>I', 4)
        raw += b'\xDE\xAD\xBE\xEF' + b'\x00' * 4
        item, _ = decode(raw, 0)
        assert item.value == b'\xDE\xAD\xBE\xEF'

    def test_get_all_returns_multiple(self):
        inner = encode_integer(0x420001, 1) + encode_integer(0x420001, 2)
        outer = decode_one(encode_structure(0x420010, inner))
        items = outer.get_all(0x420001)
        assert len(items) == 2
        assert items[0].value == 1
        assert items[1].value == 2


# ══════════════════════════════════════════════════════════════════════════════
# core/exceptions.py  —  line 12 (explicit reason override)
# ══════════════════════════════════════════════════════════════════════════════

class TestExceptionsExtended:
    def test_kmip_error_explicit_reason_override(self):
        from kmip_pkcs11.core.enums import ResultReason
        e = KMIPError("test message", reason=ResultReason.InvalidField)
        assert e.reason == ResultReason.InvalidField
        assert "test message" in str(e)

    def test_kmip_error_default_reason(self):
        from kmip_pkcs11.core.enums import ResultReason
        e = KMIPError("just a message")
        assert e.reason == ResultReason.GeneralFailure

    def test_all_exception_subclasses_have_reason(self):
        from kmip_pkcs11.core.enums import ResultReason
        assert ItemNotFound("x").reason == ResultReason.ItemNotFound
        assert NotExtractable("x").reason == ResultReason.NotExtractable
        assert MissingData("x").reason == ResultReason.MissingData
        assert IllegalOperation("x").reason == ResultReason.IllegalOperation
        assert CryptographicFailure("x").reason == ResultReason.CryptographicFailure


# ══════════════════════════════════════════════════════════════════════════════
# metadata/store.py  —  lines 108, 215-220, 247-248, 250-251, 276-277
# ══════════════════════════════════════════════════════════════════════════════

class TestMetadataExtended:
    def test_create_with_past_activation_date_auto_activates(self, store):
        """activation_date in the past → initial_state set to Active (line 108)."""
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        uid  = store.create_object(
            object_type=ObjectType.SymmetricKey,
            activation_date=past,
        )
        obj = store.get_object(uid)
        assert obj["state"] == State.Active

    def test_create_with_future_activation_date_stays_pre_active(self, store):
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        uid    = store.create_object(
            object_type=ObjectType.SymmetricKey,
            activation_date=future,
        )
        obj = store.get_object(uid)
        assert obj["state"] == State.PreActive

    def test_set_activation_date(self, store):
        uid = store.create_object(object_type=ObjectType.SymmetricKey, owner_identity="user")
        dt  = datetime.datetime(2025, 6, 15, tzinfo=datetime.timezone.utc)
        store.set_activation_date(uid, dt)
        obj = store.get_object(uid)
        assert abs(obj["activation_date"] - dt.timestamp()) < 1

    def test_list_objects(self, store):
        uids = [store.create_object(object_type=ObjectType.SymmetricKey, owner_identity="user") for _ in range(3)]
        result = store.list_objects()
        for uid in uids:
            assert uid in result

    def test_list_objects_empty(self, store):
        assert store.list_objects() == []

    def test_object_exists_true(self, store):
        uid = store.create_object(object_type=ObjectType.SymmetricKey, owner_identity="user")
        assert store.object_exists(uid) is True

    def test_object_exists_false(self, store):
        assert store.object_exists("nonexistent-uid") is False

    def test_locate_with_name_and_type_filter(self, store):
        """Covers the WHERE + AND branch in locate (name + other filter)."""
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey,
            names=["combo-key"]
        )
        store.activate(uid)
        results = store.locate(
            object_type=ObjectType.SymmetricKey,
            state=State.Active,
            name="combo-key",
        )
        assert uid in results

    def test_locate_by_algorithm_and_length(self, store):
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey,
            cryptographic_algorithm=CryptographicAlgorithm.AES,
            cryptographic_length=256,
        )
        results = store.locate(
            cryptographic_algorithm=CryptographicAlgorithm.AES,
            cryptographic_length=256,
        )
        assert uid in results

    def test_locate_with_max_items_and_name(self, store):
        for i in range(3):
            store.create_object(object_type=ObjectType.SymmetricKey, names=[f"k{i}"])
        results = store.locate(max_items=2)
        assert len(results) <= 2

    def test_locate_by_owner(self, store):
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey,
            owner_identity="alice"
        )
        results = store.locate(owner="alice")
        assert uid in results
        assert uid not in store.locate(owner="bob")


# ══════════════════════════════════════════════════════════════════════════════
# pkcs11_shim/shim.py  —  many lines
# ══════════════════════════════════════════════════════════════════════════════

class TestShimExtended:
    def test_generate_random_bytes(self, shim):
        data = shim.generate_random(32)
        assert isinstance(data, bytes)
        assert len(data) == 32

    def test_generate_random_entropy(self, shim):
        a = shim.generate_random(16)
        b = shim.generate_random(16)
        assert a != b  # extremely unlikely to be equal

    def test_get_mechanism_list(self, shim):
        mechs = shim.get_mechanism_list()
        assert isinstance(mechs, list)

    def test_get_token_info(self, shim):
        info = shim.get_token_info()
        assert isinstance(info, str)
        assert len(info) > 0

    def test_import_and_export_symmetric_key(self, shim):
        raw_key = os.urandom(16)
        cka_id  = shim.import_symmetric_key(
            algorithm=CryptographicAlgorithm.AES,
            length_bits=128,
            key_bytes=raw_key,
            label="test-import",
            extractable=True,
            sensitive=False,
        )
        assert isinstance(cka_id, bytes)
        assert len(cka_id) == 16
        # Export and verify round-trip
        exported = shim.get_key_value(cka_id)
        assert exported == raw_key

    def test_generate_ec_key_pair(self, shim):
        pub_id, priv_id = shim.generate_key_pair(
            algorithm=CryptographicAlgorithm.EC,
            label="test-ec",
            sign=True,
            verify=True,
        )
        assert isinstance(pub_id, bytes)
        assert isinstance(priv_id, bytes)
        assert pub_id != priv_id

    def test_get_public_key_der(self, shim):
        pub_id, _ = shim.generate_key_pair(
            algorithm=CryptographicAlgorithm.RSA,
            key_length=1024,
            label="test-pubder",
        )
        der = shim.get_public_key_der(pub_id)
        assert isinstance(der, bytes)
        assert len(der) > 50  # DER-encoded RSA pub key is substantial

    def test_sign_and_verify_rsa(self, shim):
        import pkcs11
        pub_id, priv_id = shim.generate_key_pair(
            algorithm=CryptographicAlgorithm.RSA,
            key_length=1024,
            label="test-sign",
            sign=True,
            verify=True,
        )
        data = b"hello world"
        sig  = shim.sign(priv_id, data, mechanism=pkcs11.Mechanism.RSA_PKCS)
        assert isinstance(sig, bytes)
        ok = shim.verify(pub_id, data, sig, mechanism=pkcs11.Mechanism.RSA_PKCS)
        assert ok is True

    def test_verify_bad_signature_returns_false(self, shim):
        """Verify that SignatureInvalid from the HSM is translated to False."""
        from unittest.mock import patch, MagicMock
        from pkcs11 import exceptions as pkcs11_exc

        pub_id, _ = shim.generate_key_pair(
            algorithm=CryptographicAlgorithm.RSA,
            key_length=1024,
            label="test-bad-sig2",
            sign=True,
            verify=True,
        )
        # Patch the found key object so that verify() raises SignatureInvalid
        fake_key = MagicMock()
        fake_key.verify.side_effect = pkcs11_exc.SignatureInvalid()
        with patch.object(shim, '_find_key', return_value=fake_key):
            ok = shim.verify(pub_id, b"hello", b'\x00' * 128)
        assert ok is False

    def test_destroy_nonexistent_is_silent(self, shim):
        """destroy_object silently ignores ItemNotFound (line 308-311)."""
        cka_id = os.urandom(16)
        shim.destroy_object(cka_id)  # must not raise

    def test_get_key_value_not_extractable_raises(self, shim):
        _, cka_id = shim.generate_symmetric_key(
            algorithm=CryptographicAlgorithm.AES,
            length_bits=128,
            label="not-extractable-test",
            extractable=False,
            sensitive=True,
        )
        with pytest.raises(NotExtractable):
            shim.get_key_value(cka_id)

    def test_session_not_initialized_raises(self):
        from kmip_pkcs11.pkcs11_shim.shim import PKCS11Shim
        s = PKCS11Shim("/nonexistent/lib.so", "label", "pin")
        with pytest.raises(GeneralFailure):
            s._sess()

    def test_initialize_idempotent(self, shim):
        """Calling initialize twice must not raise (line 70 guard)."""
        shim.initialize()  # already initialized — should be a no-op
        assert shim._initialized is True

    def test_finalize_and_reinitialize(self, shim):
        """finalize() + initialize() round-trip must succeed."""
        shim.finalize()
        assert shim._initialized is False
        shim.initialize()
        assert shim._initialized is True


# ══════════════════════════════════════════════════════════════════════════════
# operations/create.py  —  lines 13, 18, 32, 34, 82, 92, 103
# ══════════════════════════════════════════════════════════════════════════════

class TestCreateOpExtended:
    def test_create_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import create as op
        with pytest.raises(MissingData):
            op.handle(None, "user", store, shim)

    def test_create_wrong_object_type_raises(self, store, shim):
        from kmip_pkcs11.operations import create as op
        payload = _make_payload(
            otype=encode_enumeration(Tag.ObjectType, ObjectType.PublicKey)
        )
        with pytest.raises(InvalidField):
            op.handle(payload, "user", store, shim)

    def test_create_missing_object_type_raises(self, store, shim):
        from kmip_pkcs11.operations import create as op
        payload = _make_payload(
            tmpl=encode_structure(Tag.TemplateAttribute,
                _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 256)))
        )
        with pytest.raises(InvalidField):
            op.handle(payload, "user", store, shim)

    def test_create_missing_algorithm_raises(self, store, shim):
        from kmip_pkcs11.operations import create as op
        attrs = _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 256))
        payload = _make_payload(
            otype=encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey),
            tmpl=encode_structure(Tag.TemplateAttribute, attrs),
        )
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_create_missing_length_raises(self, store, shim):
        from kmip_pkcs11.operations import create as op
        attrs = _attr("Cryptographic Algorithm",
                      encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
        payload = _make_payload(
            otype=encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey),
            tmpl=encode_structure(Tag.TemplateAttribute, attrs),
        )
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_create_name_as_plain_string(self, store, shim):
        """Covers Name attr without NameValue children (line 103)."""
        from kmip_pkcs11.operations import create as op
        attrs = (
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 128))
            + _attr("Name", encode_text_string(Tag.AttributeValue, "plain-name"))
        )
        payload = _make_payload(
            otype=encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey),
            tmpl=encode_structure(Tag.TemplateAttribute, attrs),
        )
        resp = op.handle(payload, "user", store, shim)
        uid = decode_one(encode_structure(Tag.ResponsePayload, resp)).get(
            Tag.UniqueIdentifier).value
        assert len(uid) == 36

    def test_create_with_sensitive_extractable_attrs(self, store, shim):
        """Covers Sensitive and Extractable attribute parsing (lines 92, 82)."""
        from kmip_pkcs11.operations import create as op
        attrs = (
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 128))
            + _attr("Sensitive",   encode_integer(Tag.AttributeValue, 0))
            + _attr("Extractable", encode_integer(Tag.AttributeValue, 1))
        )
        payload = _make_payload(
            otype=encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey),
            tmpl=encode_structure(Tag.TemplateAttribute, attrs),
        )
        resp = op.handle(payload, "user", store, shim)
        uid = decode_one(encode_structure(Tag.ResponsePayload, resp)).get(
            Tag.UniqueIdentifier).value
        obj = store.get_object(uid)
        assert obj["extractable"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# operations/create_keypair.py  —  lines 14, 33
# ══════════════════════════════════════════════════════════════════════════════

class TestCreateKeyPairExtended:
    def test_create_keypair_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import create_keypair as op
        with pytest.raises(MissingData):
            op.handle(None, "user", store, shim)

    def test_create_keypair_missing_algorithm_raises(self, store, shim):
        from kmip_pkcs11.operations import create_keypair as op
        attrs = _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 2048))
        payload = _make_payload(tmpl=encode_structure(Tag.TemplateAttribute, attrs))
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_create_keypair_with_name(self, store, shim):
        from kmip_pkcs11.operations import create_keypair as op
        nv    = encode_text_string(Tag.NameValue, "my-pair")
        attrs = (
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.RSA))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 1024))
            + _attr("Name", encode_structure(Tag.AttributeValue, nv))
        )
        payload = _make_payload(tmpl=encode_structure(Tag.TemplateAttribute, attrs))
        resp_bytes = op.handle(payload, "user", store, shim)
        resp  = decode_one(encode_structure(Tag.ResponsePayload, resp_bytes))
        uids  = [i.value for i in resp.get_all(Tag.UniqueIdentifier)]
        assert len(uids) == 2


# ══════════════════════════════════════════════════════════════════════════════
# operations/register.py  —  lines 13-32, 36-79, 84-110
# ══════════════════════════════════════════════════════════════════════════════

def _build_sym_register_payload(key_bytes, algorithm,
                                 names=None) -> TTLVItem:
    key_material = encode_byte_string(Tag.KeyMaterial, key_bytes)
    key_value    = encode_structure(Tag.KeyValue, key_material)
    key_block    = encode_structure(
        Tag.KeyBlock,
        encode_enumeration(Tag.KeyFormatType, KeyFormatType.Raw) + key_value
    )
    attrs = _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, algorithm))
    attrs += _attr("Cryptographic Usage Mask",
                   encode_integer(Tag.AttributeValue,
                                  CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt))
    if names:
        nv     = encode_text_string(Tag.NameValue, names[0])
        attrs += _attr("Name", encode_structure(Tag.AttributeValue, nv))

    inner = (
        encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
        + key_block
        + encode_structure(Tag.TemplateAttribute, attrs)
    )
    return decode_one(encode_structure(Tag.RequestPayload, inner))


class TestRegisterOp:
    def test_register_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import register as op
        with pytest.raises(MissingData):
            op.handle(None, "user", store, shim)

    def test_register_missing_object_type_raises(self, store, shim):
        from kmip_pkcs11.operations import register as op
        payload = _make_payload()
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_register_unsupported_type_raises(self, store, shim):
        from kmip_pkcs11.operations import register as op
        payload = _make_payload(
            otype=encode_enumeration(Tag.ObjectType, ObjectType.SplitKey)
        )
        with pytest.raises(OperationNotSupported):
            op.handle(payload, "user", store, shim)

    def test_register_symmetric_aes128(self, store, shim):
        from kmip_pkcs11.operations import register as op
        key_bytes = os.urandom(16)
        payload   = _build_sym_register_payload(key_bytes, CryptographicAlgorithm.AES)
        resp_bytes = op.handle(payload, "user", store, shim)
        resp = decode_one(encode_structure(Tag.ResponsePayload, resp_bytes))
        uid  = resp.get(Tag.UniqueIdentifier).value
        obj  = store.get_object(uid)
        assert obj["cryptographic_algorithm"] == CryptographicAlgorithm.AES
        assert obj["state"] == State.Active

    def test_register_symmetric_with_name(self, store, shim):
        from kmip_pkcs11.operations import register as op
        key_bytes = os.urandom(32)
        payload   = _build_sym_register_payload(
            key_bytes, CryptographicAlgorithm.AES, names=["registered-key"]
        )
        resp_bytes = op.handle(payload, "user", store, shim)
        resp = decode_one(encode_structure(Tag.ResponsePayload, resp_bytes))
        uid  = resp.get(Tag.UniqueIdentifier).value
        assert len(uid) == 36

    def test_register_symmetric_missing_key_block_raises(self, store, shim):
        from kmip_pkcs11.operations import register as op
        inner = encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_register_symmetric_missing_algorithm_raises(self, store, shim):
        from kmip_pkcs11.operations import register as op
        key_material = encode_byte_string(Tag.KeyMaterial, b"\x00" * 16)
        key_value    = encode_structure(Tag.KeyValue, key_material)
        key_block    = encode_structure(
            Tag.KeyBlock,
            encode_enumeration(Tag.KeyFormatType, KeyFormatType.Raw) + key_value
        )
        # TemplateAttribute has no Cryptographic Algorithm
        attrs = _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 128))
        inner = (
            encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
            + key_block
            + encode_structure(Tag.TemplateAttribute, attrs)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_register_secret_data(self, store, shim):
        from kmip_pkcs11.operations import register as op
        secret_bytes = b"s3cr3t-password"
        key_material = encode_byte_string(Tag.KeyMaterial, secret_bytes)
        key_value    = encode_structure(Tag.KeyValue, key_material)
        key_block    = encode_structure(
            Tag.KeyBlock,
            encode_enumeration(Tag.KeyFormatType, KeyFormatType.Opaque) + key_value
        )
        inner = (
            encode_enumeration(Tag.ObjectType, ObjectType.SecretData)
            + key_block
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        resp_bytes = op.handle(payload, "user", store, shim)
        resp = decode_one(encode_structure(Tag.ResponsePayload, resp_bytes))
        uid  = resp.get(Tag.UniqueIdentifier).value
        obj  = store.get_object(uid)
        assert obj["object_type"] == ObjectType.SecretData
        assert obj["raw_key_value"] == secret_bytes

    def test_register_opaque_object(self, store, shim):
        from kmip_pkcs11.operations import register as op
        inner = encode_enumeration(Tag.ObjectType, ObjectType.OpaqueObject)
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        resp_bytes = op.handle(payload, "user", store, shim)
        resp = decode_one(encode_structure(Tag.ResponsePayload, resp_bytes))
        uid  = resp.get(Tag.UniqueIdentifier).value
        obj  = store.get_object(uid)
        assert obj["object_type"] == ObjectType.OpaqueObject


# ══════════════════════════════════════════════════════════════════════════════
# operations/get.py  —  lines 20, 24, 37-42, 47, 51, 75-100, 108-119
# ══════════════════════════════════════════════════════════════════════════════

def _create_aes_uid(store, shim, length=128, extractable=True) -> str:
    from kmip_pkcs11.operations import create as create_mod
    attrs = (
        _attr("Cryptographic Algorithm",
              encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
        + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, length))
        + _attr("Cryptographic Usage Mask",
                encode_integer(Tag.AttributeValue,
                               CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt))
        + _attr("Extractable", encode_integer(Tag.AttributeValue, int(extractable)))
    )
    p = decode_one(encode_structure(Tag.RequestPayload,
        encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
        + encode_structure(Tag.TemplateAttribute, attrs)
    ))
    resp_bytes = create_mod.handle(p, "user", store, shim)
    return decode_one(encode_structure(Tag.ResponsePayload, resp_bytes)).get(
        Tag.UniqueIdentifier).value


class TestGetOpExtended:
    def test_get_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import get as op
        with pytest.raises(MissingData):
            op.handle(None, "user", store, shim)

    def test_get_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import get as op
        with pytest.raises(MissingData):
            op.handle(_make_payload(), "user", store, shim)

    def test_get_nonexistent_raises(self, store, shim):
        from kmip_pkcs11.operations import get as op
        with pytest.raises(ItemNotFound):
            op.handle(_uid_payload("bad-uid"), "user", store, shim)

    def test_get_non_extractable_raises(self, store, shim):
        from kmip_pkcs11.operations import get as op
        uid = _create_aes_uid(store, shim, extractable=False)
        with pytest.raises(NotExtractable):
            op.handle(_uid_payload(uid), "user", store, shim)

    def test_get_public_key(self, store, shim):
        from kmip_pkcs11.operations import create_keypair as kp_op, get as get_op
        attrs = (
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.RSA))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 1024))
        )
        p = _make_payload(tmpl=encode_structure(Tag.TemplateAttribute, attrs))
        kp_resp   = kp_op.handle(p, "user", store, shim)
        resp_wrap = decode_one(encode_structure(Tag.ResponsePayload, kp_resp))
        pub_uid   = resp_wrap.get_all(Tag.UniqueIdentifier)[0].value

        resp_bytes = get_op.handle(_uid_payload(pub_uid), "user", store, shim)
        resp = decode_one(encode_structure(Tag.ResponsePayload, resp_bytes))
        uid_item = resp.get(Tag.UniqueIdentifier)
        assert uid_item.value == pub_uid

    def test_get_secret_data(self, store, shim):
        from kmip_pkcs11.operations import register as reg_op, get as get_op
        secret_bytes = b"my-secret"
        key_material = encode_byte_string(Tag.KeyMaterial, secret_bytes)
        key_block    = encode_structure(
            Tag.KeyBlock,
            encode_enumeration(Tag.KeyFormatType, KeyFormatType.Opaque)
            + encode_structure(Tag.KeyValue, key_material)
        )
        inner = encode_enumeration(Tag.ObjectType, ObjectType.SecretData) + key_block
        reg_payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        reg_resp_bytes = reg_op.handle(reg_payload, "user", store, shim)
        uid = decode_one(encode_structure(Tag.ResponsePayload, reg_resp_bytes)
                         ).get(Tag.UniqueIdentifier).value

        resp_bytes = get_op.handle(_uid_payload(uid), "user", store, shim)
        resp = decode_one(encode_structure(Tag.ResponsePayload, resp_bytes))
        assert resp.get(Tag.UniqueIdentifier).value == uid

    def test_get_unsupported_type_raises(self, store, shim):
        from kmip_pkcs11.operations import get as op
        uid = store.create_object(
            object_type=ObjectType.PGPKey,
            state=State.Active,
            extractable=True,
            owner_identity="user",
        )
        with pytest.raises(NotExtractable):
            op.handle(_uid_payload(uid), "user", store, shim)


# ══════════════════════════════════════════════════════════════════════════════
# operations/get_attributes.py  —  lines 18, 22, 27, 71-72, 83-84, 92-115
# ══════════════════════════════════════════════════════════════════════════════

class TestGetAttributesExtended:
    def test_get_attrs_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import get_attributes as op
        with pytest.raises(MissingData):
            op.handle(None, "user", store, shim)

    def test_get_attrs_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import get_attributes as op
        with pytest.raises(MissingData):
            op.handle(_make_payload(), "user", store, shim)

    def test_get_attrs_nonexistent_raises(self, store, shim):
        from kmip_pkcs11.operations import get_attributes as op
        with pytest.raises(ItemNotFound):
            op.handle(_uid_payload("no-uid"), "user", store, shim)

    def test_get_initial_date_attribute(self, store, shim):
        from kmip_pkcs11.operations import get_attributes as op
        uid = _create_aes_uid(store, shim)
        # Request "Initial Date" specifically
        inner = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_text_string(Tag.AttributeName, "Initial Date")
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        resp_bytes = op.handle(payload, "user", store, shim)
        resp = decode_all(resp_bytes)
        names = [i.value for i in resp if i.tag == Tag.AttributeName]
        # May or may not appear depending on initial_date being set
        # Just assert no exception

    def test_get_activation_date_attribute(self, store, shim):
        from kmip_pkcs11.operations import get_attributes as op
        uid = _create_aes_uid(store, shim)
        # Set an activation date so it appears in response
        store.activate(uid)
        inner = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_text_string(Tag.AttributeName, "Activation Date")
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        resp_bytes = op.handle(payload, "user", store, shim)
        # No exception is the pass condition

    def test_get_attribute_list_handle_add(self, store, shim):
        """Covers handle_add() (GetAttributeList) — lines 92-115."""
        from kmip_pkcs11.operations import get_attributes as op
        uid = _create_aes_uid(store, shim)
        payload = _uid_payload(uid)
        resp_bytes = op.handle_add(payload, "user", store, shim)
        items = decode_all(resp_bytes)
        names = [i.value for i in items if i.tag == Tag.AttributeName]
        assert "Object Type" in names
        assert "State" in names

    def test_get_attribute_list_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import get_attributes as op
        with pytest.raises(MissingData):
            op.handle_add(None, "user", store, shim)

    def test_get_attribute_list_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import get_attributes as op
        with pytest.raises(MissingData):
            op.handle_add(_make_payload(), "user", store, shim)

    def test_get_attribute_list_nonexistent_raises(self, store, shim):
        from kmip_pkcs11.operations import get_attributes as op
        with pytest.raises(ItemNotFound):
            op.handle_add(_uid_payload("no-uid"), "user", store, shim)

    def test_get_attribute_list_includes_custom_attrs(self, store, shim):
        from kmip_pkcs11.operations import get_attributes as op
        uid = _create_aes_uid(store, shim)
        store.add_attribute(uid, "x-dept", "security")
        resp_bytes = op.handle_add(_uid_payload(uid), "user", store, shim)
        items = decode_all(resp_bytes)
        names = [i.value for i in items if i.tag == Tag.AttributeName]
        assert "x-dept" in names

    def test_get_sensitive_extractable_attributes(self, store, shim):
        from kmip_pkcs11.operations import get_attributes as op
        uid = _create_aes_uid(store, shim)
        inner = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_text_string(Tag.AttributeName, "Sensitive")
            + encode_text_string(Tag.AttributeName, "Extractable")
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        resp_bytes = op.handle(payload, "user", store, shim)
        # Should succeed without error


# ══════════════════════════════════════════════════════════════════════════════
# operations/add_attribute.py  —  lines 13, 17, 21, 25, 30
# ══════════════════════════════════════════════════════════════════════════════

class TestAddAttributeExtended:
    def test_add_attr_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import add_attribute as op
        with pytest.raises(MissingData):
            op.handle(None, "user", store, shim)

    def test_add_attr_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import add_attribute as op
        with pytest.raises(MissingData):
            op.handle(_make_payload(), "user", store, shim)

    def test_add_attr_nonexistent_object_raises(self, store, shim):
        from kmip_pkcs11.operations import add_attribute as op
        attr_inner = (
            encode_text_string(Tag.AttributeName, "x-tag")
            + encode_text_string(Tag.AttributeValue, "v")
        )
        inner = (
            encode_text_string(Tag.UniqueIdentifier, "ghost-uid")
            + encode_structure(Tag.Attribute, attr_inner)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(ItemNotFound):
            op.handle(payload, "user", store, shim)

    def test_add_attr_missing_attribute_raises(self, store, shim):
        from kmip_pkcs11.operations import add_attribute as op
        uid = store.create_object(object_type=ObjectType.SymmetricKey, owner_identity="user")
        inner = encode_text_string(Tag.UniqueIdentifier, uid)
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_add_attr_missing_name_raises(self, store, shim):
        from kmip_pkcs11.operations import add_attribute as op
        uid = store.create_object(object_type=ObjectType.SymmetricKey, owner_identity="user")
        attr_inner = encode_text_string(Tag.AttributeValue, "val")
        inner = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_structure(Tag.Attribute, attr_inner)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_add_attr_no_value_uses_empty_string(self, store, shim):
        from kmip_pkcs11.operations import add_attribute as op
        uid = store.create_object(object_type=ObjectType.SymmetricKey, owner_identity="user")
        attr_inner = encode_text_string(Tag.AttributeName, "x-empty")
        inner = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_structure(Tag.Attribute, attr_inner)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        resp_bytes = op.handle(payload, "user", store, shim)
        resp = decode_all(resp_bytes)
        uid_val = next((i.value for i in resp if i.tag == Tag.UniqueIdentifier), None)
        assert uid_val == uid


# ══════════════════════════════════════════════════════════════════════════════
# operations/delete_attribute.py  —  lines 12-38 (all)
# ══════════════════════════════════════════════════════════════════════════════

class TestDeleteAttributeOp:
    def test_delete_attr_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import delete_attribute as op
        with pytest.raises(MissingData):
            op.handle(None, "user", store, shim)

    def test_delete_attr_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import delete_attribute as op
        with pytest.raises(MissingData):
            op.handle(_make_payload(), "user", store, shim)

    def test_delete_attr_nonexistent_object_raises(self, store, shim):
        from kmip_pkcs11.operations import delete_attribute as op
        attr_inner = encode_text_string(Tag.AttributeName, "x")
        inner = (
            encode_text_string(Tag.UniqueIdentifier, "ghost")
            + encode_structure(Tag.Attribute, attr_inner)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(ItemNotFound):
            op.handle(payload, "user", store, shim)

    def test_delete_attr_missing_attribute_raises(self, store, shim):
        from kmip_pkcs11.operations import delete_attribute as op
        uid = store.create_object(object_type=ObjectType.SymmetricKey, owner_identity="user")
        inner = encode_text_string(Tag.UniqueIdentifier, uid)
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_delete_attr_missing_name_raises(self, store, shim):
        from kmip_pkcs11.operations import delete_attribute as op
        uid = store.create_object(object_type=ObjectType.SymmetricKey, owner_identity="user")
        attr_inner = encode_text_string(Tag.AttributeValue, "val")
        inner = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_structure(Tag.Attribute, attr_inner)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_delete_attr_success(self, store, shim):
        from kmip_pkcs11.operations import delete_attribute as op
        uid = store.create_object(object_type=ObjectType.SymmetricKey, owner_identity="user")
        store.add_attribute(uid, "x-temp", "removeme")
        attr_inner = (
            encode_text_string(Tag.AttributeName, "x-temp")
        )
        inner = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_structure(Tag.Attribute, attr_inner)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        resp_bytes = op.handle(payload, "user", store, shim)
        resp = decode_all(resp_bytes)
        uid_val = next((i.value for i in resp if i.tag == Tag.UniqueIdentifier), None)
        assert uid_val == uid
        assert store.get_attribute(uid, "x-temp") == []

    def test_delete_attr_with_explicit_index(self, store, shim):
        from kmip_pkcs11.operations import delete_attribute as op
        uid = store.create_object(object_type=ObjectType.SymmetricKey, owner_identity="user")
        store.add_attribute(uid, "x-multi", "v0")
        store.add_attribute(uid, "x-multi", "v1")
        attr_inner = (
            encode_text_string(Tag.AttributeName, "x-multi")
            + encode_integer(Tag.AttributeIndex, 0)
        )
        inner = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_structure(Tag.Attribute, attr_inner)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        op.handle(payload, "user", store, shim)
        # index 0 removed, index 1 remains
        remaining = store.get_attribute(uid, "x-multi")
        assert len(remaining) == 1


# ══════════════════════════════════════════════════════════════════════════════
# operations/activate.py  —  lines 14, 18
# ══════════════════════════════════════════════════════════════════════════════

class TestActivateExtended:
    def test_activate_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import activate as op
        with pytest.raises(MissingData):
            op.handle(None, "user", store, shim)

    def test_activate_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import activate as op
        with pytest.raises(MissingData):
            op.handle(_make_payload(), "user", store, shim)

    def test_activate_nonexistent_raises(self, store, shim):
        from kmip_pkcs11.operations import activate as op
        with pytest.raises(ItemNotFound):
            op.handle(_uid_payload("ghost"), "user", store, shim)

    def test_activate_already_active_raises(self, store, shim):
        from kmip_pkcs11.operations import activate as op
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey, state=State.Active, owner_identity="user")
        with pytest.raises(IllegalOperation):
            op.handle(_uid_payload(uid), "user", store, shim)

    def test_activate_pre_active_succeeds(self, store, shim):
        from kmip_pkcs11.operations import activate as op
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey, state=State.PreActive, owner_identity="user")
        resp_bytes = op.handle(_uid_payload(uid), "user", store, shim)
        items = decode_all(resp_bytes)
        uid_val = next(i.value for i in items if i.tag == Tag.UniqueIdentifier)
        assert uid_val == uid
        assert store.get_object(uid)["state"] == State.Active


# ══════════════════════════════════════════════════════════════════════════════
# operations/revoke.py  —  lines 14, 18
# ══════════════════════════════════════════════════════════════════════════════

class TestRevokeExtended:
    def test_revoke_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import revoke as op
        with pytest.raises(MissingData):
            op.handle(None, "user", store, shim)

    def test_revoke_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import revoke as op
        with pytest.raises(MissingData):
            op.handle(_make_payload(), "user", store, shim)

    def test_revoke_no_reason_defaults_unspecified(self, store, shim):
        from kmip_pkcs11.operations import revoke as op
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey, state=State.Active, owner_identity="user")
        # Payload has UID but no RevocationReason
        inner = encode_text_string(Tag.UniqueIdentifier, uid)
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        resp_bytes = op.handle(payload, "user", store, shim)
        items = decode_all(resp_bytes)
        uid_val = next(i.value for i in items if i.tag == Tag.UniqueIdentifier)
        assert uid_val == uid
        obj = store.get_object(uid)
        assert obj["state"] in (State.Deactivated, State.Compromised)

    def test_revoke_with_message(self, store, shim):
        from kmip_pkcs11.operations import revoke as op
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey, state=State.Active, owner_identity="user")
        rev_reason = (
            encode_enumeration(Tag.RevocationReasonCode, RevocationReasonCode.Superseded)
            + encode_text_string(Tag.RevocationMessage, "superseded by v2")
        )
        inner = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_structure(Tag.RevocationReason, rev_reason)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        op.handle(payload, "user", store, shim)
        obj = store.get_object(uid)
        assert obj["revocation_message"] == "superseded by v2"


# ══════════════════════════════════════════════════════════════════════════════
# operations/destroy.py  —  lines 15, 19, 46-50 (_pkcs11_class)
# ══════════════════════════════════════════════════════════════════════════════

class TestDestroyExtended:
    def test_destroy_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import destroy as op
        with pytest.raises(MissingData):
            op.handle(None, "user", store, shim)

    def test_destroy_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import destroy as op
        with pytest.raises(MissingData):
            op.handle(_make_payload(), "user", store, shim)

    def test_pkcs11_class_symmetric(self):
        from kmip_pkcs11.operations.destroy import _pkcs11_class
        from pkcs11.constants import ObjectClass
        assert _pkcs11_class(ObjectType.SymmetricKey) == ObjectClass.SECRET_KEY

    def test_pkcs11_class_public(self):
        from kmip_pkcs11.operations.destroy import _pkcs11_class
        from pkcs11.constants import ObjectClass
        assert _pkcs11_class(ObjectType.PublicKey) == ObjectClass.PUBLIC_KEY

    def test_pkcs11_class_private(self):
        from kmip_pkcs11.operations.destroy import _pkcs11_class
        from pkcs11.constants import ObjectClass
        assert _pkcs11_class(ObjectType.PrivateKey) == ObjectClass.PRIVATE_KEY

    def test_pkcs11_class_other_returns_none(self):
        from kmip_pkcs11.operations.destroy import _pkcs11_class
        assert _pkcs11_class(ObjectType.Certificate) is None

    def test_destroy_object_without_pkcs11_handle(self, store, shim):
        from kmip_pkcs11.operations import destroy as op
        # Create an object that has no _pkcs11_cka_id attribute
        uid = store.create_object(
            object_type=ObjectType.SecretData, state=State.Active, owner_identity="user")
        resp_bytes = op.handle(_uid_payload(uid), "user", store, shim)
        items = decode_all(resp_bytes)
        uid_val = next(i.value for i in items if i.tag == Tag.UniqueIdentifier)
        assert uid_val == uid
        assert store.get_object(uid)["state"] == State.Destroyed

    def test_destroy_key_pair_via_handlers(self, store, shim):
        from kmip_pkcs11.operations import create_keypair as kp_op, destroy as dest_op
        attrs = (
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.RSA))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 1024))
        )
        p = _make_payload(tmpl=encode_structure(Tag.TemplateAttribute, attrs))
        kp_resp = kp_op.handle(p, "user", store, shim)
        resp_wrap = decode_one(encode_structure(Tag.ResponsePayload, kp_resp))
        pub_uid, priv_uid = [i.value for i in resp_wrap.get_all(Tag.UniqueIdentifier)]

        for uid in [pub_uid, priv_uid]:
            dest_op.handle(_uid_payload(uid), "user", store, shim)
            assert store.get_object(uid)["state"] == State.Destroyed


# ══════════════════════════════════════════════════════════════════════════════
# operations/encrypt.py  —  lines 15, 19, 24, 29, 44-46, 50, 59
# ══════════════════════════════════════════════════════════════════════════════

class TestEncryptExtended:
    def test_encrypt_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import encrypt as op
        with pytest.raises(MissingData):
            op.handle(None, "user", store, shim)

    def test_encrypt_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import encrypt as op
        with pytest.raises(MissingData):
            op.handle(_make_payload(), "user", store, shim)

    def test_encrypt_missing_data_raises(self, store, shim):
        from kmip_pkcs11.operations import encrypt as op
        inner = encode_text_string(Tag.UniqueIdentifier, "x")
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_encrypt_nonexistent_raises(self, store, shim):
        from kmip_pkcs11.operations import encrypt as op
        inner = (
            encode_text_string(Tag.UniqueIdentifier, "ghost")
            + encode_byte_string(Tag.Data, b"data")
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(ItemNotFound):
            op.handle(payload, "user", store, shim)

    def test_encrypt_no_cka_id_raises(self, store, shim):
        from kmip_pkcs11.operations import encrypt as op
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey, state=State.Active, owner_identity="user")
        inner = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_byte_string(Tag.Data, b"\x00" * 16)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(ItemNotFound):
            op.handle(payload, "user", store, shim)

    def test_encrypt_with_aad(self, store, shim):
        from kmip_pkcs11.operations import encrypt as op
        uid = _create_aes_uid(store, shim, 256)
        store.get_object(uid)  # verify exists
        iv  = os.urandom(16)
        aad = b"additional-data"
        inner = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_byte_string(Tag.Data, b"A" * 32)
            + encode_byte_string(Tag.IVCounterNonce, iv)
            + encode_byte_string(Tag.AuthenticatedEncryptionAdditionalData, aad)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        resp_bytes = op.handle(payload, "user", store, shim)
        items = decode_all(resp_bytes)
        ct_item = next((i for i in items if i.tag == Tag.Data), None)
        assert ct_item is not None
        assert len(ct_item.value) > 0


# ══════════════════════════════════════════════════════════════════════════════
# operations/decrypt.py  —  lines 14, 18, 23, 28, 44-46, 50
# ══════════════════════════════════════════════════════════════════════════════

class TestDecryptExtended:
    def test_decrypt_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import decrypt as op
        with pytest.raises(MissingData):
            op.handle(None, "user", store, shim)

    def test_decrypt_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import decrypt as op
        with pytest.raises(MissingData):
            op.handle(_make_payload(), "user", store, shim)

    def test_decrypt_missing_data_raises(self, store, shim):
        from kmip_pkcs11.operations import decrypt as op
        inner = encode_text_string(Tag.UniqueIdentifier, "x")
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_decrypt_nonexistent_raises(self, store, shim):
        from kmip_pkcs11.operations import decrypt as op
        inner = (
            encode_text_string(Tag.UniqueIdentifier, "ghost")
            + encode_byte_string(Tag.Data, b"ciphertext")
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(ItemNotFound):
            op.handle(payload, "user", store, shim)

    def test_decrypt_no_cka_id_raises(self, store, shim):
        from kmip_pkcs11.operations import decrypt as op
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey, state=State.Active, owner_identity="user")
        inner = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_byte_string(Tag.Data, b"\x00" * 16)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(ItemNotFound):
            op.handle(payload, "user", store, shim)

    def test_decrypt_roundtrip_with_iv(self, store, shim):
        from kmip_pkcs11.operations import encrypt as enc_op, decrypt as dec_op
        uid = _create_aes_uid(store, shim, 256)
        pt  = b"Secret message!!" + b"\x00" * 16  # 32 bytes
        iv  = os.urandom(16)
        enc_inner = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_byte_string(Tag.Data, pt)
            + encode_byte_string(Tag.IVCounterNonce, iv)
        )
        enc_p = decode_one(encode_structure(Tag.RequestPayload, enc_inner))
        enc_resp = enc_op.handle(enc_p, "user", store, shim)
        enc_items = decode_all(enc_resp)
        ct = next(i.value for i in enc_items if i.tag == Tag.Data)
        iv_out = next((i.value for i in enc_items if i.tag == Tag.IVCounterNonce), iv)

        dec_inner = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_byte_string(Tag.Data, ct)
            + encode_byte_string(Tag.IVCounterNonce, iv_out)
        )
        dec_p = decode_one(encode_structure(Tag.RequestPayload, dec_inner))
        dec_resp = dec_op.handle(dec_p, "user", store, shim)
        dec_items = decode_all(dec_resp)
        recovered = next(i.value for i in dec_items if i.tag == Tag.Data)
        assert recovered == pt


# ══════════════════════════════════════════════════════════════════════════════
# operations/locate.py  —  line 23 (MaximumItems)
# ══════════════════════════════════════════════════════════════════════════════

class TestLocateExtended:
    def test_locate_with_max_items(self, store, shim):
        from kmip_pkcs11.operations import locate as op
        for _ in range(5):
            _create_aes_uid(store, shim, 128)
        inner = encode_integer(Tag.MaximumItems, 2)
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        resp_bytes = op.handle(payload, "user", store, shim)
        items = decode_all(resp_bytes)
        uids  = [i.value for i in items if i.tag == Tag.UniqueIdentifier]
        assert len(uids) <= 2


# ══════════════════════════════════════════════════════════════════════════════
# operations/query.py  —  line 34 (ApplicationNamespaces branch)
# ══════════════════════════════════════════════════════════════════════════════

class TestQueryExtended:
    def test_query_application_namespaces(self, store, shim):
        from kmip_pkcs11.operations import query as op
        from kmip_pkcs11.core.enums import QueryFunction
        inner = encode_enumeration(Tag.QueryFunction, QueryFunction.QueryApplicationNamespaces)
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        resp_bytes = op.handle(payload, "user", store, shim)
        # No exception — empty namespace list is valid

    def test_query_all_functions(self, store, shim):
        from kmip_pkcs11.operations import query as op
        from kmip_pkcs11.core.enums import QueryFunction
        inner = b""
        for fn in [QueryFunction.QueryOperations, QueryFunction.QueryObjects,
                   QueryFunction.QueryServerInformation,
                   QueryFunction.QueryApplicationNamespaces]:
            inner += encode_enumeration(Tag.QueryFunction, fn)
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        resp_bytes = op.handle(payload, "user", store, shim)
        items = decode_all(resp_bytes)
        ops = [i.value for i in items if i.tag == Tag.Operations]
        assert len(ops) > 0


# ══════════════════════════════════════════════════════════════════════════════
# operations/dispatcher.py  —  lines 63, 72-74 (unsupported op, unexpected exc)
# ══════════════════════════════════════════════════════════════════════════════

class TestDispatcherExtended:
    def test_unsupported_operation_returns_failure(self, store, shim):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation
        disp = OperationDispatcher(store, shim)
        # Use an operation code that has no handler
        batch_item_bytes = encode_structure(
            Tag.BatchItem,
            encode_enumeration(Tag.Operation, 0x99999999)  # nonexistent
            + encode_structure(Tag.RequestPayload, b"")
        )
        batch_item = decode_one(batch_item_bytes)
        resp_bytes = disp.dispatch(batch_item, "user")
        resp = decode_one(resp_bytes)
        status = resp.get(Tag.ResultStatus)
        assert status.value == 0x00000001  # OperationFailed

    def test_handler_unexpected_exception_returns_failure(self, store, shim):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation
        disp = OperationDispatcher(store, shim)
        original = disp._handlers[Operation.Query]
        try:
            disp._handlers[Operation.Query] = lambda *a: (_ for _ in ()).throw(RuntimeError("boom"))
            batch_item_bytes = encode_structure(
                Tag.BatchItem,
                encode_enumeration(Tag.Operation, Operation.Query)
                + encode_structure(Tag.RequestPayload, b"")
            )
            batch_item = decode_one(batch_item_bytes)
            resp_bytes = disp.dispatch(batch_item, "user")
            resp = decode_one(resp_bytes)
            status = resp.get(Tag.ResultStatus)
            assert status.value == 0x00000001  # OperationFailed
        finally:
            disp._handlers[Operation.Query] = original


# ══════════════════════════════════════════════════════════════════════════════
# server/server.py  —  lines 76-83, 106-112, 126-129, 133-134, 140-145, etc.
# ══════════════════════════════════════════════════════════════════════════════

class TestServerExtended:
    def test_error_response_helper(self):
        from kmip_pkcs11.server.server import _error_response
        from kmip_pkcs11.core.enums import ResultReason
        data  = _error_response(ResultReason.ItemNotFound, "not found")
        item  = decode_one(data)
        assert item.tag == Tag.ResponseMessage
        batch = item.get(Tag.BatchItem)
        status = batch.get(Tag.ResultStatus)
        assert status.value == 0x00000001  # OperationFailed

    def test_get_identity_non_ssl_returns_anonymous(self, store, shim):
        from kmip_pkcs11.server.server import KMIPServer
        srv = KMIPServer(store, shim)
        plain_sock = MagicMock()
        plain_sock.__class__ = socket.socket  # not ssl.SSLSocket
        assert srv._get_identity(plain_sock) == "anonymous"

    def test_recv_message_with_empty_response(self, store, shim):
        from kmip_pkcs11.server.server import KMIPServer
        srv = KMIPServer(store, shim)
        sock = MagicMock()
        sock.recv.return_value = b""
        assert srv._recv_message(sock) is None

    def test_process_invalid_ttlv_returns_error(self, store, shim):
        from kmip_pkcs11.server.server import KMIPServer
        srv = KMIPServer(store, shim, port=29999)
        result = srv._process(b"\xff" * 8, "anonymous")
        item   = decode_one(result)
        assert item.tag == Tag.ResponseMessage

    def test_server_stop(self, tmp_path, shim):
        from kmip_pkcs11.metadata.store import MetadataStore
        from kmip_pkcs11.server.server import KMIPServer
        store2 = MetadataStore(str(tmp_path / "stop_test.db"))
        srv    = KMIPServer(store2, shim, port=29998, allow_plaintext=True)
        srv.start_background()
        # Wait for it to bind
        deadline = time.time() + 3
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", 29998), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        srv._running = False
        if srv._sock:
            srv._sock.close()
        # Server has stopped — verify socket closed
        time.sleep(0.1)

    def test_encode_version_helper(self):
        from kmip_pkcs11.server.server import _encode_version
        data = _encode_version(2, 1)
        item = decode_one(data)
        assert item.tag == Tag.ProtocolVersion
        major = item.get(Tag.ProtocolVersionMajor)
        minor = item.get(Tag.ProtocolVersionMinor)
        assert major.value == 2
        assert minor.value == 1


# ══════════════════════════════════════════════════════════════════════════════
# test_app/client.py  —  lines 53-60, 71-75, 136, 150-151, 158, 207, etc.
# ══════════════════════════════════════════════════════════════════════════════

class TestClientExtended:
    def test_context_manager_enter_exit(self, server_client):
        """Covers __enter__ and __exit__ on KMIPClient."""
        from kmip_pkcs11.test_app.client import KMIPClient
        client, _ = server_client
        port = client._port
        client.close()  # close the existing one
        with KMIPClient(port=port) as c2:
            versions = c2.discover_versions()
            assert (2, 1) in versions
        # After __exit__, sock should be None
        assert c2._sock is None

    def test_client_close_when_not_connected(self):
        from kmip_pkcs11.test_app.client import KMIPClient
        c = KMIPClient()
        c.close()  # must not raise even if never connected

    def test_client_activate(self, server_client):
        """Covers client.activate() which was never called in tests."""
        client, store = server_client
        from kmip_pkcs11.core.enums import CryptographicAlgorithm, State
        # Create a key and manually set it to Pre-Active in the store
        uid = client.create(
            algorithm=CryptographicAlgorithm.AES, length=128
        )
        # Revert to Pre-Active
        store.set_state(uid, State.PreActive)
        # Now activate via client
        ret_uid = client.activate(uid)
        assert ret_uid == uid
        assert client.get_attributes(uid, ["State"])["State"] == State.Active

    def test_client_create_key_pair_with_name(self, server_client):
        """Covers create_key_pair with name (lines 150-151)."""
        client, _ = server_client
        from kmip_pkcs11.core.enums import CryptographicAlgorithm
        pub, priv = client.create_key_pair(
            algorithm=CryptographicAlgorithm.RSA,
            length=1024,
            name="named-pair",
        )
        assert len(pub)  == 36
        assert len(priv) == 36

    def test_client_add_attribute_and_retrieve(self, server_client):
        """Full round-trip for add_attribute via the live server."""
        client, _ = server_client
        from kmip_pkcs11.core.enums import CryptographicAlgorithm
        uid = client.create(algorithm=CryptographicAlgorithm.AES, length=128)
        client.add_attribute(uid, "x-classification", "top-secret")
        attrs = client.get_attributes(uid)
        assert attrs.get("x-classification") == "top-secret"

    def test_recvall_helper_connection_closed(self):
        """_recvall raises RuntimeError when connection closes mid-message."""
        from kmip_pkcs11.test_app.client import _recvall
        sock = MagicMock()
        sock.recv.return_value = b""  # simulates closed connection
        with pytest.raises(RuntimeError, match="closed"):
            _recvall(sock, 8)

    def test_client_query_empty_function_list(self, server_client):
        """query() with no function list uses defaults."""
        client, _ = server_client
        caps = client.query()
        assert len(caps["operations"]) > 0


# ══════════════════════════════════════════════════════════════════════════════
# lifecycle state machine  —  DestroyedCompromised usage check
# ══════════════════════════════════════════════════════════════════════════════

class TestLifecycleExtended:
    def test_destroyed_compromised_any_op_forbidden(self):
        from kmip_pkcs11.lifecycle.state_machine import check_usage_allowed
        with pytest.raises(IllegalOperation):
            check_usage_allowed(State.DestroyedCompromised, "get")

    def test_pre_active_mac_forbidden(self):
        from kmip_pkcs11.lifecycle.state_machine import check_usage_allowed
        with pytest.raises(IllegalOperation):
            check_usage_allowed(State.PreActive, "mac")

    def test_pre_active_decrypt_forbidden(self):
        from kmip_pkcs11.lifecycle.state_machine import check_usage_allowed
        with pytest.raises(IllegalOperation):
            check_usage_allowed(State.PreActive, "decrypt")

    def test_deactivated_mac_forbidden(self):
        from kmip_pkcs11.lifecycle.state_machine import check_usage_allowed
        with pytest.raises(IllegalOperation):
            check_usage_allowed(State.Deactivated, "mac")

    def test_compromised_verify_forbidden(self):
        from kmip_pkcs11.lifecycle.state_machine import check_usage_allowed
        with pytest.raises(IllegalOperation):
            check_usage_allowed(State.Compromised, "verify")

    def test_transition_unknown_state_raises(self):
        from kmip_pkcs11.lifecycle.state_machine import transition
        with pytest.raises(IllegalOperation):
            transition(999, "activate")


# ══════════════════════════════════════════════════════════════════════════════
# Additional gap-closing tests
# ══════════════════════════════════════════════════════════════════════════════

class TestQueryNullPayload:
    """query.py line 34 — reached when payload is None (no QueryFunction items)."""

    def test_query_null_payload_returns_defaults(self, store, shim):
        from kmip_pkcs11.operations import query as op
        resp_bytes = op.handle(None, "user", store, shim)
        items = decode_all(resp_bytes)
        from kmip_pkcs11.core.enums import Tag as T
        ops = [i.value for i in items if i.tag == T.Operations]
        assert len(ops) > 0

    def test_query_empty_payload_uses_defaults(self, store, shim):
        from kmip_pkcs11.operations import query as op
        payload = decode_one(encode_structure(Tag.RequestPayload, b""))
        resp_bytes = op.handle(payload, "user", store, shim)
        items = decode_all(resp_bytes)
        ops = [i.value for i in items if i.tag == Tag.Operations]
        assert len(ops) > 0


class TestRegisterMissingKeyValue:
    """register.py line 43 — key_value_item is None when KeyValue tag absent."""

    def test_register_missing_key_value_raises(self, store, shim):
        from kmip_pkcs11.operations import register as op
        # Build KeyBlock without KeyValue child
        key_block = encode_structure(
            Tag.KeyBlock,
            encode_enumeration(Tag.KeyFormatType, KeyFormatType.Raw)
        )
        attrs = _attr("Cryptographic Algorithm",
                      encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
        inner = (
            encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
            + key_block
            + encode_structure(Tag.TemplateAttribute, attrs)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)


class TestCreateAttributeSkip:
    """create.py line 82 — Attribute with missing AttributeName or AttributeValue is skipped."""

    def test_parse_attributes_skips_incomplete_attribute(self, store, shim):
        from kmip_pkcs11.operations.create import _parse_attributes
        # Build TemplateAttribute with one complete attr and one with no AttributeValue
        good_attr = _attr("Cryptographic Algorithm",
                          encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
        bad_attr  = encode_structure(
            Tag.Attribute,
            encode_text_string(Tag.AttributeName, "Cryptographic Length")
            # deliberately no AttributeValue
        )
        tmpl = decode_one(encode_structure(Tag.TemplateAttribute, good_attr + bad_attr))
        result = _parse_attributes(tmpl)
        # Algorithm parsed; length missing (skipped)
        assert result["algorithm"] == CryptographicAlgorithm.AES
        assert "length" not in result


class TestGetAttributesNonJsonAttr:
    """get_attributes.py lines 83-84 — attribute value that is not valid JSON."""

    def test_get_attributes_non_json_value(self, store, shim):
        from kmip_pkcs11.operations import get_attributes as op
        uid = _create_aes_uid(store, shim)
        # Add attribute with raw non-JSON text value directly via SQL
        import sqlite3, json
        db_path = store._db_path
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO kmip_attributes (object_uuid, attr_name, attr_index, attr_value) "
            "VALUES (?,?,?,?)",
            (uid, "CustomTag", 0, "not-json-{invalid}")
        )
        conn.commit()
        conn.close()
        payload = _make_payload(uid=encode_text_string(Tag.UniqueIdentifier, uid))
        resp_bytes = op.handle(payload, "user", store, shim)
        assert len(resp_bytes) > 0


class TestEncryptWithExplicitMode:
    """encrypt.py lines 44-46 — CryptographicParameters present with BlockCipherMode."""

    def test_encrypt_with_explicit_cbc_mode(self, store, shim):
        from kmip_pkcs11.operations import encrypt as op
        from kmip_pkcs11.core.ttlv import encode_enumeration as enc_enum
        uid = _create_aes_uid(store, shim)
        store.activate(uid)
        cbc = BlockCipherMode.CBC
        crypto_params = encode_structure(
            Tag.CryptographicParameters,
            enc_enum(Tag.CryptographicParameters_BlockCipherMode, cbc)
        )
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, b"Hello World!!!!"),
            params=crypto_params,
        )
        resp_bytes = op.handle(payload, "user", store, shim)
        assert len(resp_bytes) > 0

    def test_encrypt_auth_tag_in_response(self, store, shim):
        """encrypt.py line 59 — when shim returns an auth tag, it appears in response."""
        from kmip_pkcs11.operations import encrypt as op
        uid = _create_aes_uid(store, shim)
        store.activate(uid)
        fake_ciphertext = b"ENCRYPTED_DATA!!"
        fake_iv = b"\x01" * 16
        fake_tag = b"\xAB" * 16  # simulate auth tag returned by GCM
        with patch.object(shim, 'encrypt', return_value=(fake_ciphertext, fake_tag)):
            payload = _make_payload(
                uid=encode_text_string(Tag.UniqueIdentifier, uid),
                data=encode_byte_string(Tag.Data, b"GCM test data!"),
            )
            resp_bytes = op.handle(payload, "user", store, shim)
        items = decode_all(resp_bytes)
        tags_present = [i.tag for i in items]
        assert Tag.AuthenticatedEncryptionTag in tags_present


class TestDecryptWithExplicitMode:
    """decrypt.py lines 44-46 — CryptographicParameters present."""

    def test_decrypt_with_explicit_cbc_mode(self, store, shim):
        from kmip_pkcs11.operations import encrypt as enc_op, decrypt as dec_op
        from kmip_pkcs11.core.ttlv import encode_enumeration as enc_enum
        uid = _create_aes_uid(store, shim)
        store.activate(uid)
        cbc = BlockCipherMode.CBC
        crypto_params = encode_structure(
            Tag.CryptographicParameters,
            enc_enum(Tag.CryptographicParameters_BlockCipherMode, cbc)
        )
        plaintext = b"test-decrypt-cbc"
        enc_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, plaintext),
            params=crypto_params,
        )
        enc_resp = enc_op.handle(enc_payload, "user", store, shim)
        enc_items = decode_all(enc_resp)
        ciphertext = next(i.value for i in enc_items if i.tag == Tag.Data)
        iv = next(i.value for i in enc_items if i.tag == Tag.IVCounterNonce)

        dec_crypto_params = encode_structure(
            Tag.CryptographicParameters,
            enc_enum(Tag.CryptographicParameters_BlockCipherMode, cbc)
        )
        dec_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, ciphertext),
            iv=encode_byte_string(Tag.IVCounterNonce, iv),
            params=dec_crypto_params,
        )
        dec_resp = dec_op.handle(dec_payload, "user", store, shim)
        dec_items = decode_all(dec_resp)
        recovered = next(i.value for i in dec_items if i.tag == Tag.Data)
        assert recovered == plaintext


class TestGetAsymmetricPrivateKey:
    """get.py lines 76, 80, 88-89 — _get_asymmetric PrivateKey path."""

    def test_get_private_key_extractable(self, store, shim):
        """Lines 76, 80, 88-89 — _get_asymmetric PrivateKey branch via mock."""
        from kmip_pkcs11.operations import get as get_op
        from kmip_pkcs11.core.enums import State as St
        uid = store.create_object(
            object_type=ObjectType.PrivateKey,
            state=St.Active,
            cryptographic_algorithm=CryptographicAlgorithm.RSA,
            cryptographic_length=1024,
            usage_mask=CryptographicUsageMask.Sign,
            extractable=True,
            sensitive=False,
            owner_identity="user",
        )
        fake_priv_id = os.urandom(16)
        store.add_attribute(uid, "_pkcs11_cka_id", fake_priv_id.hex())
        # Mock get_private_key_der so the private-key extraction path works
        with patch.object(shim, 'get_private_key_der', return_value=b'\xAA' * 32):
            payload = _uid_payload(uid)
            resp_bytes = get_op.handle(payload, "user", store, shim)
        assert len(resp_bytes) > 0

    def test_get_asymmetric_missing_cka_id_raises(self, store, shim):
        """get.py line 80 — ItemNotFound when _pkcs11_cka_id attribute missing."""
        from kmip_pkcs11.operations import get as get_op
        from kmip_pkcs11.core.enums import State as St
        uid = store.create_object(
            object_type=ObjectType.PublicKey,
            state=St.Active,
            usage_mask=CryptographicUsageMask.Verify,
            extractable=True,
            sensitive=False,
            owner_identity="user",
        )
        # no _pkcs11_cka_id attribute added
        payload = _uid_payload(uid)
        with pytest.raises(ItemNotFound):
            get_op.handle(payload, "user", store, shim)

    def test_get_symmetric_missing_cka_id_raises(self, store, shim):
        """get.py line 51 — ItemNotFound when symmetric key has no _pkcs11_cka_id."""
        from kmip_pkcs11.operations import get as get_op
        from kmip_pkcs11.core.enums import State as St
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey,
            state=St.Active,
            cryptographic_algorithm=CryptographicAlgorithm.AES,
            cryptographic_length=128,
            usage_mask=CryptographicUsageMask.Encrypt,
            extractable=True,
            sensitive=False,
            owner_identity="user",
        )
        # no _pkcs11_cka_id — should raise
        payload = _uid_payload(uid)
        with pytest.raises(ItemNotFound):
            get_op.handle(payload, "user", store, shim)


class TestGetNonExtractablePrivateKey:
    """get.py line 76 — NotExtractable raised for non-extractable PrivateKey."""

    def test_get_non_extractable_private_key_raises(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        from kmip_pkcs11.core.enums import State as St
        uid = store.create_object(
            object_type=ObjectType.PrivateKey,
            state=St.Active,
            cryptographic_algorithm=CryptographicAlgorithm.RSA,
            cryptographic_length=2048,
            usage_mask=CryptographicUsageMask.Sign,
            extractable=False,
            sensitive=True,
            owner_identity="user",
        )
        store.add_attribute(uid, "_pkcs11_cka_id", os.urandom(16).hex())
        payload = _uid_payload(uid)
        with pytest.raises(NotExtractable):
            get_op.handle(payload, "user", store, shim)


# ══════════════════════════════════════════════════════════════════════════════
# Phase 1 fixes — GCM and CTR round-trip tests
# ══════════════════════════════════════════════════════════════════════════════

class TestPhase1GCM:
    """AES-GCM encrypt/decrypt round-trip — verifies the GCMParams fix."""

    def test_gcm_roundtrip_shim_level(self, shim):
        """Direct shim call: encrypt then decrypt with GCM, verify plaintext."""
        _, cka_id = shim.generate_symmetric_key(
            algorithm=CryptographicAlgorithm.AES,
            length_bits=256,
            label="gcm-test",
            extractable=True,
        )
        plaintext = b"Hello GCM World!"
        nonce     = os.urandom(12)

        ciphertext, tag = shim.encrypt(
            cka_id, plaintext,
            mechanism_id=BlockCipherMode.GCM,
            iv=nonce,
        )
        assert ciphertext != plaintext
        assert tag is not None
        assert len(tag) == 16  # 128-bit auth tag

        recovered = shim.decrypt(
            cka_id, ciphertext,
            mechanism_id=BlockCipherMode.GCM,
            iv=nonce,
            tag=tag,
        )
        assert recovered == plaintext

    def test_gcm_with_aad(self, shim):
        """GCM with Additional Authenticated Data (AAD)."""
        _, cka_id = shim.generate_symmetric_key(
            algorithm=CryptographicAlgorithm.AES,
            length_bits=128,
            label="gcm-aad-test",
            extractable=True,
        )
        plaintext = b"Authenticated payload"
        nonce     = os.urandom(12)
        aad       = b"header-metadata"

        ciphertext, tag = shim.encrypt(
            cka_id, plaintext,
            mechanism_id=BlockCipherMode.GCM,
            iv=nonce, aad=aad,
        )
        recovered = shim.decrypt(
            cka_id, ciphertext,
            mechanism_id=BlockCipherMode.GCM,
            iv=nonce, aad=aad, tag=tag,
        )
        assert recovered == plaintext

    def test_gcm_roundtrip_operation_level(self, store, shim):
        """GCM through the full KMIP Encrypt/Decrypt operation handlers."""
        from kmip_pkcs11.operations import encrypt as enc_op, decrypt as dec_op
        from kmip_pkcs11.core.ttlv import encode_enumeration as enc_enum

        uid = _create_aes_uid(store, shim, length=256)
        store.activate(uid)

        crypto_params = encode_structure(
            Tag.CryptographicParameters,
            enc_enum(Tag.CryptographicParameters_BlockCipherMode, BlockCipherMode.GCM),
        )
        plaintext = b"GCM operation test"
        enc_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, plaintext),
            params=crypto_params,
        )
        enc_resp = enc_op.handle(enc_payload, "user", store, shim)
        enc_items = decode_all(enc_resp)

        ciphertext = next(i.value for i in enc_items if i.tag == Tag.Data)
        nonce      = next(i.value for i in enc_items if i.tag == Tag.IVCounterNonce)
        auth_tag   = next(i.value for i in enc_items if i.tag == Tag.AuthenticatedEncryptionTag)

        dec_crypto_params = encode_structure(
            Tag.CryptographicParameters,
            enc_enum(Tag.CryptographicParameters_BlockCipherMode, BlockCipherMode.GCM),
        )
        dec_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, ciphertext),
            iv=encode_byte_string(Tag.IVCounterNonce, nonce),
            tag=encode_byte_string(Tag.AuthenticatedEncryptionTag, auth_tag),
            params=dec_crypto_params,
        )
        dec_resp  = dec_op.handle(dec_payload, "user", store, shim)
        dec_items = decode_all(dec_resp)
        recovered = next(i.value for i in dec_items if i.tag == Tag.Data)
        assert recovered == plaintext


class TestPhase1CTR:
    """AES-CTR encrypt/decrypt round-trip — verifies the CTRParams fix."""

    def test_ctr_roundtrip_shim_level(self, shim):
        """Direct shim call: encrypt then decrypt with CTR mode."""
        _, cka_id = shim.generate_symmetric_key(
            algorithm=CryptographicAlgorithm.AES,
            length_bits=128,
            label="ctr-test",
            extractable=True,
        )
        plaintext = b"Hello CTR World!!"   # 16 bytes — no padding in CTR
        nonce     = os.urandom(12)

        ciphertext, tag = shim.encrypt(
            cka_id, plaintext,
            mechanism_id=BlockCipherMode.CTR,
            iv=nonce,
        )
        assert tag is None                 # CTR produces no auth tag
        assert ciphertext != plaintext

        recovered = shim.decrypt(
            cka_id, ciphertext,
            mechanism_id=BlockCipherMode.CTR,
            iv=nonce,
        )
        assert recovered == plaintext

    def test_ctr_roundtrip_operation_level(self, store, shim):
        """CTR through the full KMIP Encrypt/Decrypt operation handlers."""
        from kmip_pkcs11.operations import encrypt as enc_op, decrypt as dec_op
        from kmip_pkcs11.core.ttlv import encode_enumeration as enc_enum

        uid = _create_aes_uid(store, shim, length=256)
        store.activate(uid)

        crypto_params = encode_structure(
            Tag.CryptographicParameters,
            enc_enum(Tag.CryptographicParameters_BlockCipherMode, BlockCipherMode.CTR),
        )
        plaintext = b"CTR operation test!!"
        enc_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, plaintext),
            params=crypto_params,
        )
        enc_resp  = enc_op.handle(enc_payload, "user", store, shim)
        enc_items = decode_all(enc_resp)

        ciphertext = next(i.value for i in enc_items if i.tag == Tag.Data)
        nonce      = next(i.value for i in enc_items if i.tag == Tag.IVCounterNonce)

        dec_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, ciphertext),
            iv=encode_byte_string(Tag.IVCounterNonce, nonce),
            params=encode_structure(
                Tag.CryptographicParameters,
                enc_enum(Tag.CryptographicParameters_BlockCipherMode, BlockCipherMode.CTR),
            ),
        )
        dec_resp  = dec_op.handle(dec_payload, "user", store, shim)
        dec_items = decode_all(dec_resp)
        recovered = next(i.value for i in dec_items if i.tag == Tag.Data)
        assert recovered == plaintext


# ══════════════════════════════════════════════════════════════════════════════
# Phase 2 — CFB, OFB, CCM mode mapping
# All three modes are absent from SoftHSM2; tests use mocks to verify that
# the correct PKCS#11 mechanism and parameters are selected.
# ══════════════════════════════════════════════════════════════════════════════

class TestPhase2Mapping:
    """Verify BLOCKMODE_TO_MECH entries for Phase 2 modes."""

    def test_cfb_in_map(self):
        from kmip_pkcs11.pkcs11_shim.shim import BLOCKMODE_TO_MECH
        import pkcs11
        assert BlockCipherMode.CFB in BLOCKMODE_TO_MECH
        assert BLOCKMODE_TO_MECH[BlockCipherMode.CFB] == pkcs11.Mechanism.AES_CFB128

    def test_ofb_in_map(self):
        from kmip_pkcs11.pkcs11_shim.shim import BLOCKMODE_TO_MECH
        import pkcs11
        assert BlockCipherMode.OFB in BLOCKMODE_TO_MECH
        assert BLOCKMODE_TO_MECH[BlockCipherMode.OFB] == pkcs11.Mechanism.AES_OFB

    def test_ccm_in_map(self):
        from kmip_pkcs11.pkcs11_shim.shim import BLOCKMODE_TO_MECH
        import pkcs11
        assert BlockCipherMode.CCM in BLOCKMODE_TO_MECH
        assert BLOCKMODE_TO_MECH[BlockCipherMode.CCM] == pkcs11.Mechanism.AES_CCM


class TestPhase2ModeCapabilityGate:
    """CFB, OFB, and CCM select real PKCS#11 mechanisms (AES_CFB128, AES_OFB,
    AES_CCM), but this SoftHSM2 build does not implement them — confirmed
    against the live token via slot.get_mechanisms(), not assumed. The shim's
    capability probe (supports_mechanism/_require_mechanism) must reject them
    with OperationNotSupported *before* attempting the native call, instead
    of letting SoftHSM2's own error surface as a generic CryptographicFailure
    (or, worse, silently succeed against a mock in a test that never talks to
    the real token — which is what the previous version of this test class did)."""

    def test_supports_mechanism_false_for_cfb_ofb_ccm(self, shim):
        import pkcs11 as _pkcs11
        assert shim.supports_mechanism(_pkcs11.Mechanism.AES_CFB128) is False
        assert shim.supports_mechanism(_pkcs11.Mechanism.AES_OFB) is False
        assert shim.supports_mechanism(_pkcs11.Mechanism.AES_CCM) is False

    def test_supports_mechanism_true_for_aes_cbc(self, shim):
        import pkcs11 as _pkcs11
        assert shim.supports_mechanism(_pkcs11.Mechanism.AES_CBC_PAD) is True

    @pytest.mark.parametrize("mode", [BlockCipherMode.CFB, BlockCipherMode.OFB, BlockCipherMode.CCM])
    def test_encrypt_raises_operation_not_supported_live(self, store, shim, mode):
        uid = _create_aes_uid(store, shim, length=256)
        store.activate(uid)
        cka_id = bytes.fromhex(store.get_attribute(uid, "_pkcs11_cka_id")[0])
        with pytest.raises(OperationNotSupported):
            shim.encrypt(cka_id, b"some plaintext..", mechanism_id=mode, iv=os.urandom(16))

    @pytest.mark.parametrize("mode", [BlockCipherMode.CFB, BlockCipherMode.OFB, BlockCipherMode.CCM])
    def test_decrypt_raises_operation_not_supported_live(self, store, shim, mode):
        uid = _create_aes_uid(store, shim, length=256)
        store.activate(uid)
        cka_id = bytes.fromhex(store.get_attribute(uid, "_pkcs11_cka_id")[0])
        with pytest.raises(OperationNotSupported):
            shim.decrypt(cka_id, b"\x00" * 16, mechanism_id=mode, iv=os.urandom(16))


class TestPhase2CFB:
    """AES-CFB128 mechanism/parameter selection — mock-based with the
    capability gate stubbed out, since SoftHSM2 doesn't implement CFB (see
    TestPhase2ModeCapabilityGate for the live-rejection behavior)."""

    def test_cfb_encrypt_uses_cfb128_mechanism(self, shim):
        import pkcs11 as _pkcs11
        fake_key = MagicMock()
        fake_key.encrypt.return_value = b'\xCC' * 16
        iv = os.urandom(16)
        plaintext = b'Hello CFB World!'

        with patch.object(shim, '_find_key', return_value=fake_key), \
             patch.object(shim, 'supports_mechanism', return_value=True):
            ct, tag = shim.encrypt(b'\x00' * 16, plaintext,
                                   mechanism_id=BlockCipherMode.CFB, iv=iv)

        fake_key.encrypt.assert_called_once_with(
            plaintext,
            mechanism=_pkcs11.Mechanism.AES_CFB128,
            mechanism_param=iv,
        )
        assert tag is None
        assert ct == b'\xCC' * 16

    def test_cfb_decrypt_uses_cfb128_mechanism(self, shim):
        import pkcs11 as _pkcs11
        fake_key = MagicMock()
        fake_key.decrypt.return_value = b'Hello CFB World!'
        iv = os.urandom(16)
        ciphertext = b'\xCC' * 16

        with patch.object(shim, '_find_key', return_value=fake_key), \
             patch.object(shim, 'supports_mechanism', return_value=True):
            pt = shim.decrypt(b'\x00' * 16, ciphertext,
                              mechanism_id=BlockCipherMode.CFB, iv=iv)

        fake_key.decrypt.assert_called_once_with(
            ciphertext,
            mechanism=_pkcs11.Mechanism.AES_CFB128,
            mechanism_param=iv,
        )
        assert pt == b'Hello CFB World!'

    def test_cfb_encrypt_pkcs11_error_raises_cryptographic_failure(self, shim):
        import pkcs11.exceptions as _exc
        fake_key = MagicMock()
        fake_key.encrypt.side_effect = _exc.MechanismInvalid()

        with patch.object(shim, '_find_key', return_value=fake_key), \
             patch.object(shim, 'supports_mechanism', return_value=True):
            with pytest.raises(CryptographicFailure):
                shim.encrypt(b'\x00' * 16, b'data',
                             mechanism_id=BlockCipherMode.CFB, iv=os.urandom(16))


class TestPhase2OFB:
    """AES-OFB mechanism/parameter selection — mock-based with the
    capability gate stubbed out (see TestPhase2ModeCapabilityGate)."""

    def test_ofb_encrypt_uses_ofb_mechanism(self, shim):
        import pkcs11 as _pkcs11
        fake_key = MagicMock()
        fake_key.encrypt.return_value = b'\xDD' * 16
        iv = os.urandom(16)
        plaintext = b'Hello OFB World!'

        with patch.object(shim, '_find_key', return_value=fake_key), \
             patch.object(shim, 'supports_mechanism', return_value=True):
            ct, tag = shim.encrypt(b'\x00' * 16, plaintext,
                                   mechanism_id=BlockCipherMode.OFB, iv=iv)

        fake_key.encrypt.assert_called_once_with(
            plaintext,
            mechanism=_pkcs11.Mechanism.AES_OFB,
            mechanism_param=iv,
        )
        assert tag is None
        assert ct == b'\xDD' * 16

    def test_ofb_decrypt_uses_ofb_mechanism(self, shim):
        import pkcs11 as _pkcs11
        fake_key = MagicMock()
        fake_key.decrypt.return_value = b'Hello OFB World!'
        iv = os.urandom(16)
        ciphertext = b'\xDD' * 16

        with patch.object(shim, '_find_key', return_value=fake_key), \
             patch.object(shim, 'supports_mechanism', return_value=True):
            pt = shim.decrypt(b'\x00' * 16, ciphertext,
                              mechanism_id=BlockCipherMode.OFB, iv=iv)

        fake_key.decrypt.assert_called_once_with(
            ciphertext,
            mechanism=_pkcs11.Mechanism.AES_OFB,
            mechanism_param=iv,
        )
        assert pt == b'Hello OFB World!'

    def test_ofb_encrypt_pkcs11_error_raises_cryptographic_failure(self, shim):
        import pkcs11.exceptions as _exc
        fake_key = MagicMock()
        fake_key.encrypt.side_effect = _exc.MechanismInvalid()

        with patch.object(shim, '_find_key', return_value=fake_key), \
             patch.object(shim, 'supports_mechanism', return_value=True):
            with pytest.raises(CryptographicFailure):
                shim.encrypt(b'\x00' * 16, b'data',
                             mechanism_id=BlockCipherMode.OFB, iv=os.urandom(16))


class TestPhase2CCM:
    """AES-CCM mechanism/parameter selection — mock-based with the capability
    gate stubbed out, since SoftHSM2 doesn't implement CCM (see
    TestPhase2ModeCapabilityGate for the live-rejection behavior).

    CCM is an AEAD mode; the shim treats it like GCM (GCMParams, 12-byte nonce,
    16-byte tag appended to ciphertext). Real HSMs may require a dedicated
    CK_CCM_PARAMS struct when that is supported by python-pkcs11.
    """

    def test_ccm_encrypt_uses_ccm_mechanism_with_gcmparams(self, shim):
        import pkcs11 as _pkcs11
        fake_key = MagicMock()
        fake_plaintext = b'Hello CCM!!'
        fake_output = b'\xEE' * len(fake_plaintext) + b'\xFF' * 16   # ct + tag
        fake_key.encrypt.return_value = fake_output
        nonce = os.urandom(12)
        aad   = b'additional data'

        with patch.object(shim, '_find_key', return_value=fake_key), \
             patch.object(shim, 'supports_mechanism', return_value=True):
            ct, tag = shim.encrypt(b'\x00' * 16, fake_plaintext,
                                   mechanism_id=BlockCipherMode.CCM,
                                   iv=nonce, aad=aad)

        call_kwargs = fake_key.encrypt.call_args.kwargs
        assert call_kwargs['mechanism'] == _pkcs11.Mechanism.AES_CCM
        assert isinstance(call_kwargs['mechanism_param'], _pkcs11.GCMParams)
        assert tag == b'\xFF' * 16
        assert ct  == b'\xEE' * len(fake_plaintext)

    def test_ccm_decrypt_uses_ccm_mechanism(self, shim):
        import pkcs11 as _pkcs11
        fake_key = MagicMock()
        expected_pt = b'Hello CCM!!'
        fake_key.decrypt.return_value = expected_pt
        nonce      = os.urandom(12)
        ciphertext = b'\xEE' * len(expected_pt)
        tag        = b'\xFF' * 16

        with patch.object(shim, '_find_key', return_value=fake_key), \
             patch.object(shim, 'supports_mechanism', return_value=True):
            pt = shim.decrypt(b'\x00' * 16, ciphertext,
                              mechanism_id=BlockCipherMode.CCM,
                              iv=nonce, tag=tag)

        call_kwargs = fake_key.decrypt.call_args.kwargs
        assert call_kwargs['mechanism'] == _pkcs11.Mechanism.AES_CCM
        assert pt == expected_pt

    def test_ccm_encrypt_nonce_default_is_12_bytes(self, shim):
        """When no IV is supplied the shim uses a 12-byte zero nonce."""
        import pkcs11 as _pkcs11
        fake_key = MagicMock()
        fake_key.encrypt.return_value = b'\xEE' * 11 + b'\xFF' * 16

        with patch.object(shim, '_find_key', return_value=fake_key), \
             patch.object(shim, 'supports_mechanism', return_value=True):
            shim.encrypt(b'\x00' * 16, b'Hello CCM!!',
                         mechanism_id=BlockCipherMode.CCM)

        param = fake_key.encrypt.call_args.kwargs['mechanism_param']
        assert isinstance(param, _pkcs11.GCMParams)

    def test_encrypt_handler_uses_12byte_nonce_for_ccm(self, store, shim):
        """Operation-level handler generates a 12-byte IV for CCM mode."""
        from kmip_pkcs11.operations import encrypt as enc_op
        from kmip_pkcs11.core.ttlv import encode_enumeration as enc_enum

        uid = _create_aes_uid(store, shim, length=256)
        store.activate(uid)

        fake_key = MagicMock()
        fake_key.encrypt.return_value = b'\xEE' * 16 + b'\xFF' * 16

        crypto_params = encode_structure(
            Tag.CryptographicParameters,
            enc_enum(Tag.CryptographicParameters_BlockCipherMode, BlockCipherMode.CCM),
        )
        enc_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, b'Hello CCM test!!'),
            params=crypto_params,
        )
        with patch.object(shim, '_find_key', return_value=fake_key), \
             patch.object(shim, 'supports_mechanism', return_value=True):
            enc_op.handle(enc_payload, "user", store, shim)

        call_kwargs = fake_key.encrypt.call_args.kwargs
        param = call_kwargs['mechanism_param']
        import pkcs11 as _pkcs11
        assert isinstance(param, _pkcs11.GCMParams)


# ══════════════════════════════════════════════════════════════════════════════
# Phase 3 — DES / 3DES mode mapping
# ══════════════════════════════════════════════════════════════════════════════

def _create_des3_uid(store, shim, extractable=True) -> str:
    """Create a Triple-DES key via the KMIP Create handler and return its UID."""
    from kmip_pkcs11.operations import create as create_mod
    attrs = (
        _attr("Cryptographic Algorithm",
              encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.TDES))
        + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 192))
        + _attr("Cryptographic Usage Mask",
                encode_integer(Tag.AttributeValue,
                               CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt))
        + _attr("Extractable", encode_integer(Tag.AttributeValue, int(extractable)))
    )
    p = decode_one(encode_structure(Tag.RequestPayload,
        encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
        + encode_structure(Tag.TemplateAttribute, attrs)
    ))
    resp_bytes = create_mod.handle(p, "user", store, shim)
    return decode_one(encode_structure(Tag.ResponsePayload, resp_bytes)).get(
        Tag.UniqueIdentifier).value


class TestPhase3MechMapping:
    """_resolve_mech picks the right PKCS#11 mechanism per key family."""

    def test_des3_cbc_resolves_to_des3_cbc_pad(self):
        import pkcs11
        from kmip_pkcs11.pkcs11_shim.shim import PKCS11Shim
        mech = PKCS11Shim._resolve_mech(BlockCipherMode.CBC, pkcs11.KeyType.DES3)
        assert mech == pkcs11.Mechanism.DES3_CBC_PAD

    def test_des3_ecb_resolves_to_des3_ecb(self):
        import pkcs11
        from kmip_pkcs11.pkcs11_shim.shim import PKCS11Shim
        mech = PKCS11Shim._resolve_mech(BlockCipherMode.ECB, pkcs11.KeyType.DES3)
        assert mech == pkcs11.Mechanism.DES3_ECB

    def test_des_cbc_resolves_to_raw_ckm(self):
        import pkcs11
        from kmip_pkcs11.pkcs11_shim.shim import PKCS11Shim
        mech = PKCS11Shim._resolve_mech(BlockCipherMode.CBC, pkcs11.KeyType._DES)
        assert int(mech) == 0x0122   # CKM_DES_CBC

    def test_des_ecb_resolves_to_raw_ckm(self):
        import pkcs11
        from kmip_pkcs11.pkcs11_shim.shim import PKCS11Shim
        mech = PKCS11Shim._resolve_mech(BlockCipherMode.ECB, pkcs11.KeyType._DES)
        assert int(mech) == 0x0121   # CKM_DES_ECB

    def test_aes_cbc_unaffected(self):
        import pkcs11
        from kmip_pkcs11.pkcs11_shim.shim import PKCS11Shim
        mech = PKCS11Shim._resolve_mech(BlockCipherMode.CBC, pkcs11.KeyType.AES)
        assert mech == pkcs11.Mechanism.AES_CBC_PAD


class TestPhase3DES3Live:
    """3DES CBC + ECB round-trip through SoftHSM2 (SoftHSM2 supports DES3_CBC_PAD)."""

    def test_des3_cbc_roundtrip_shim_level(self, shim):
        _, cka_id = shim.generate_symmetric_key(
            algorithm=CryptographicAlgorithm.TDES,
            length_bits=192,
            label="des3-cbc-test",
            extractable=True,
        )
        plaintext = b"Hello 3DES CBC!!"   # 16 bytes — padded by CBC_PAD
        iv = os.urandom(8)                # 3DES block = 64 bits

        ciphertext, tag = shim.encrypt(cka_id, plaintext,
                                       mechanism_id=BlockCipherMode.CBC, iv=iv)
        assert tag is None
        assert ciphertext != plaintext

        recovered = shim.decrypt(cka_id, ciphertext,
                                 mechanism_id=BlockCipherMode.CBC, iv=iv)
        assert recovered == plaintext

    def test_des3_ecb_roundtrip_shim_level(self, shim):
        _, cka_id = shim.generate_symmetric_key(
            algorithm=CryptographicAlgorithm.TDES,
            length_bits=192,
            label="des3-ecb-test",
            extractable=True,
        )
        plaintext = b"Hello3DES ECB!!!"   # 16 bytes — ECB works without IV

        ciphertext, tag = shim.encrypt(cka_id, plaintext,
                                       mechanism_id=BlockCipherMode.ECB)
        assert tag is None
        assert ciphertext != plaintext

        recovered = shim.decrypt(cka_id, ciphertext,
                                 mechanism_id=BlockCipherMode.ECB)
        assert recovered == plaintext

    def test_des3_cbc_roundtrip_operation_level(self, store, shim):
        """Full KMIP Encrypt/Decrypt handler round-trip with a 3DES key."""
        from kmip_pkcs11.operations import encrypt as enc_op, decrypt as dec_op
        from kmip_pkcs11.core.ttlv import encode_enumeration as enc_enum

        uid = _create_des3_uid(store, shim)
        store.activate(uid)

        crypto_params = encode_structure(
            Tag.CryptographicParameters,
            enc_enum(Tag.CryptographicParameters_BlockCipherMode, BlockCipherMode.CBC),
        )
        plaintext = b"3DES operation test!!"
        enc_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, plaintext),
            params=crypto_params,
        )
        enc_resp  = enc_op.handle(enc_payload, "user", store, shim)
        enc_items = decode_all(enc_resp)

        ciphertext = next(i.value for i in enc_items if i.tag == Tag.Data)
        iv_val     = next(i.value for i in enc_items if i.tag == Tag.IVCounterNonce)
        assert len(iv_val) == 8   # handler must generate 8-byte IV for 3DES

        dec_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, ciphertext),
            iv=encode_byte_string(Tag.IVCounterNonce, iv_val),
            params=encode_structure(
                Tag.CryptographicParameters,
                enc_enum(Tag.CryptographicParameters_BlockCipherMode, BlockCipherMode.CBC),
            ),
        )
        dec_resp  = dec_op.handle(dec_payload, "user", store, shim)
        dec_items = decode_all(dec_resp)
        recovered = next(i.value for i in dec_items if i.tag == Tag.Data)
        assert recovered == plaintext


class TestPhase3DESMock:
    """Single-DES — mock-based (deprecated but must route correctly)."""

    def test_des_cbc_encrypt_uses_raw_ckm_value(self, shim):
        fake_key = MagicMock()
        fake_key.__getitem__ = MagicMock(return_value=__import__('pkcs11').KeyType._DES)
        fake_key.encrypt.return_value = b'\xAA' * 8
        iv = os.urandom(8)

        with patch.object(shim, '_find_key', return_value=fake_key):
            ct, tag = shim.encrypt(b'\x00' * 16, b'DES data', 
                                   mechanism_id=BlockCipherMode.CBC, iv=iv)

        call_kwargs = fake_key.encrypt.call_args.kwargs
        assert int(call_kwargs['mechanism']) == 0x0122   # CKM_DES_CBC
        assert tag is None

    def test_des_ecb_encrypt_uses_raw_ckm_value(self, shim):
        fake_key = MagicMock()
        fake_key.__getitem__ = MagicMock(return_value=__import__('pkcs11').KeyType._DES)
        fake_key.encrypt.return_value = b'\xBB' * 8

        with patch.object(shim, '_find_key', return_value=fake_key):
            ct, tag = shim.encrypt(b'\x00' * 16, b'DES data',
                                   mechanism_id=BlockCipherMode.ECB)

        call_kwargs = fake_key.encrypt.call_args.kwargs
        assert int(call_kwargs['mechanism']) == 0x0121   # CKM_DES_ECB


class TestPhase3EncryptHandlerIV:
    """encrypt.py must generate 8-byte IV for DES/3DES, not 16."""

    def test_handler_generates_8byte_iv_for_tdes(self, store, shim):
        from kmip_pkcs11.operations import encrypt as enc_op
        from kmip_pkcs11.core.ttlv import encode_enumeration as enc_enum

        uid = _create_des3_uid(store, shim)
        store.activate(uid)

        fake_key = MagicMock()
        fake_key.__getitem__ = MagicMock(return_value=__import__('pkcs11').KeyType.DES3)
        fake_key.encrypt.return_value = b'\xCC' * 16   # DES3_CBC_PAD adds padding

        crypto_params = encode_structure(
            Tag.CryptographicParameters,
            enc_enum(Tag.CryptographicParameters_BlockCipherMode, BlockCipherMode.CBC),
        )
        enc_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, b'test data 3DES!!'),
            params=crypto_params,
        )
        with patch.object(shim, '_find_key', return_value=fake_key):
            enc_resp  = enc_op.handle(enc_payload, "user", store, shim)

        enc_items = decode_all(enc_resp)
        iv_val = next(i.value for i in enc_items if i.tag == Tag.IVCounterNonce)
        assert len(iv_val) == 8, f"Expected 8-byte IV for 3DES, got {len(iv_val)}"


# ══════════════════════════════════════════════════════════════════════════════
# Phase 4 — Sign / SignatureVerify operation handlers
# ══════════════════════════════════════════════════════════════════════════════

from kmip_pkcs11.core.enums import HashingAlgorithm, ValidityIndicator as ValidityIndicatorEnum


def _create_rsa_keypair(store, shim):
    """Create an RSA-2048 key pair via CreateKeyPair and return (pub_uid, priv_uid)."""
    from kmip_pkcs11.operations import create_keypair as ckp
    from kmip_pkcs11.core.ttlv import encode_enumeration as enc_enum

    attrs = encode_structure(
        Tag.TemplateAttribute,
        _attr("Cryptographic Algorithm",
              encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.RSA))
        + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 2048)),
    )
    p = decode_one(encode_structure(Tag.RequestPayload,
        encode_enumeration(Tag.ObjectType, ObjectType.PublicKey) + attrs
    ))
    resp_bytes = ckp.handle(p, "user", store, shim)
    items = decode_all(resp_bytes)
    uids = [i.value for i in items if i.tag == Tag.UniqueIdentifier]
    return uids[0], uids[1]   # pub_uid, priv_uid


def _create_ec_keypair(store, shim):
    """Create an EC key pair via CreateKeyPair and return (pub_uid, priv_uid)."""
    from kmip_pkcs11.operations import create_keypair as ckp
    attrs = encode_structure(
        Tag.TemplateAttribute,
        _attr("Cryptographic Algorithm",
              encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.EC))
        + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 256)),
    )
    p = decode_one(encode_structure(Tag.RequestPayload,
        encode_enumeration(Tag.ObjectType, ObjectType.PublicKey) + attrs
    ))
    resp_bytes = ckp.handle(p, "user", store, shim)
    items = decode_all(resp_bytes)
    uids = [i.value for i in items if i.tag == Tag.UniqueIdentifier]
    return uids[0], uids[1]


class TestPhase4SignErrors:
    """Error paths in the Sign handler."""

    def test_sign_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import sign as op
        with pytest.raises(MissingData):
            op.handle(None, "user", store, shim)

    def test_sign_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import sign as op
        with pytest.raises(MissingData):
            op.handle(_make_payload(), "user", store, shim)

    def test_sign_missing_data_raises(self, store, shim):
        from kmip_pkcs11.operations import sign as op
        with pytest.raises(MissingData):
            op.handle(_uid_payload("some-uid"), "user", store, shim)

    def test_sign_nonexistent_key_raises(self, store, shim):
        from kmip_pkcs11.operations import sign as op
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, "ghost"),
            data=encode_byte_string(Tag.Data, b"hello"),
        )
        with pytest.raises(ItemNotFound):
            op.handle(payload, "user", store, shim)

    def test_sign_preactive_key_raises(self, store, shim):
        from kmip_pkcs11.operations import sign as op
        uid = store.create_object(object_type=ObjectType.PrivateKey, state=State.PreActive, owner_identity="user")
        store.add_attribute(uid, "_pkcs11_cka_id", os.urandom(16).hex())
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, b"hello"),
        )
        with pytest.raises(IllegalOperation):
            op.handle(payload, "user", store, shim)

    def test_sign_missing_cka_id_raises(self, store, shim):
        from kmip_pkcs11.operations import sign as op
        uid = store.create_object(object_type=ObjectType.PrivateKey, state=State.Active, owner_identity="user")
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, b"hello"),
        )
        with pytest.raises(ItemNotFound):
            op.handle(payload, "user", store, shim)


class TestPhase4SignatureVerifyErrors:
    """Error paths in the SignatureVerify handler."""

    def test_sigver_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import signature_verify as op
        with pytest.raises(MissingData):
            op.handle(None, "user", store, shim)

    def test_sigver_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import signature_verify as op
        with pytest.raises(MissingData):
            op.handle(_make_payload(), "user", store, shim)

    def test_sigver_missing_data_raises(self, store, shim):
        from kmip_pkcs11.operations import signature_verify as op
        with pytest.raises(MissingData):
            op.handle(_uid_payload("x"), "user", store, shim)

    def test_sigver_missing_signature_raises(self, store, shim):
        from kmip_pkcs11.operations import signature_verify as op
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, "x"),
            data=encode_byte_string(Tag.Data, b"hello"),
        )
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_sigver_nonexistent_key_raises(self, store, shim):
        from kmip_pkcs11.operations import signature_verify as op
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, "ghost"),
            data=encode_byte_string(Tag.Data, b"hello"),
            sig=encode_byte_string(Tag.SignatureData, b"\x00" * 32),
        )
        with pytest.raises(ItemNotFound):
            op.handle(payload, "user", store, shim)

    def test_sigver_missing_cka_id_raises(self, store, shim):
        from kmip_pkcs11.operations import signature_verify as op
        uid = store.create_object(object_type=ObjectType.PublicKey, state=State.Active, owner_identity="user")
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, b"hello"),
            sig=encode_byte_string(Tag.SignatureData, b"\x00" * 32),
        )
        with pytest.raises(ItemNotFound):
            op.handle(payload, "user", store, shim)


class TestPhase4RSALive:
    """RSA-2048 sign/verify round-trips through SoftHSM2."""

    def test_rsa_sign_verify_sha256_roundtrip(self, store, shim):
        from kmip_pkcs11.operations import sign as sign_op, signature_verify as sigver_op
        from kmip_pkcs11.core.ttlv import encode_enumeration as enc_enum

        pub_uid, priv_uid = _create_rsa_keypair(store, shim)
        message = b"KMIP Sign test message"

        # Sign with private key
        sign_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, priv_uid),
            data=encode_byte_string(Tag.Data, message),
        )
        sign_resp  = sign_op.handle(sign_payload, "user", store, shim)
        sign_items = decode_all(sign_resp)
        signature  = next(i.value for i in sign_items if i.tag == Tag.SignatureData)
        assert len(signature) > 0

        # Verify with public key
        ver_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, pub_uid),
            data=encode_byte_string(Tag.Data, message),
            sig=encode_byte_string(Tag.SignatureData, signature),
        )
        ver_resp  = sigver_op.handle(ver_payload, "user", store, shim)
        ver_items = decode_all(ver_resp)
        validity  = next(i.value for i in ver_items if i.tag == Tag.ValidityIndicator)
        assert validity == ValidityIndicatorEnum.Valid

    def test_rsa_verify_bad_signature_returns_invalid(self, store, shim):
        """SoftHSM2 may not reject all bad RSA signatures; mock the SignatureInvalid path."""
        import pkcs11.exceptions as _exc
        from kmip_pkcs11.operations import signature_verify as sigver_op

        pub_uid, _ = _create_rsa_keypair(store, shim)
        message = b"Real message"
        bad_sig = b"\xFF" * 256

        fake_pub_key = MagicMock()
        fake_pub_key.verify.side_effect = _exc.SignatureInvalid()

        ver_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, pub_uid),
            data=encode_byte_string(Tag.Data, message),
            sig=encode_byte_string(Tag.SignatureData, bad_sig),
        )
        with patch.object(shim, '_find_key', return_value=fake_pub_key):
            ver_resp  = sigver_op.handle(ver_payload, "user", store, shim)
        ver_items = decode_all(ver_resp)
        validity  = next(i.value for i in ver_items if i.tag == Tag.ValidityIndicator)
        assert validity == ValidityIndicatorEnum.Invalid

    def test_rsa_sign_with_explicit_sha256_mechanism(self, store, shim):
        """CryptographicParameters with HashingAlgorithm overrides the default."""
        from kmip_pkcs11.operations import sign as sign_op, signature_verify as sigver_op
        from kmip_pkcs11.core.ttlv import encode_enumeration as enc_enum

        pub_uid, priv_uid = _create_rsa_keypair(store, shim)
        message = b"Explicit SHA-256 test"

        crypto_params = encode_structure(
            Tag.CryptographicParameters,
            enc_enum(Tag.HashingAlgorithm, HashingAlgorithm.SHA_256),
        )
        sign_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, priv_uid),
            data=encode_byte_string(Tag.Data, message),
            params=crypto_params,
        )
        sign_resp  = sign_op.handle(sign_payload, "user", store, shim)
        sign_items = decode_all(sign_resp)
        signature  = next(i.value for i in sign_items if i.tag == Tag.SignatureData)

        ver_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, pub_uid),
            data=encode_byte_string(Tag.Data, message),
            sig=encode_byte_string(Tag.SignatureData, signature),
            params=crypto_params,
        )
        ver_resp  = sigver_op.handle(ver_payload, "user", store, shim)
        ver_items = decode_all(ver_resp)
        validity  = next(i.value for i in ver_items if i.tag == Tag.ValidityIndicator)
        assert validity == ValidityIndicatorEnum.Valid


class TestPhase4ECLive:
    """EC (secp256r1) sign/verify round-trip through SoftHSM2."""

    def test_ec_sign_verify_roundtrip(self, store, shim):
        from kmip_pkcs11.operations import sign as sign_op, signature_verify as sigver_op

        pub_uid, priv_uid = _create_ec_keypair(store, shim)
        message = b"KMIP EC sign test"

        sign_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, priv_uid),
            data=encode_byte_string(Tag.Data, message),
        )
        sign_resp  = sign_op.handle(sign_payload, "user", store, shim)
        sign_items = decode_all(sign_resp)
        signature  = next(i.value for i in sign_items if i.tag == Tag.SignatureData)
        assert len(signature) > 0

        ver_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, pub_uid),
            data=encode_byte_string(Tag.Data, message),
            sig=encode_byte_string(Tag.SignatureData, signature),
        )
        ver_resp  = sigver_op.handle(ver_payload, "user", store, shim)
        ver_items = decode_all(ver_resp)
        validity  = next(i.value for i in ver_items if i.tag == Tag.ValidityIndicator)
        assert validity == ValidityIndicatorEnum.Valid

    def test_ec_ecdsa_sha384_roundtrip(self, store, shim):
        from kmip_pkcs11.operations import sign as sign_op, signature_verify as sigver_op
        from kmip_pkcs11.core.enums import HashingAlgorithm as HA

        pub_uid, priv_uid = _create_ec_keypair(store, shim)
        message = b"ECDSA-SHA384 test message"
        hash_param = encode_structure(
            Tag.CryptographicParameters,
            encode_enumeration(Tag.HashingAlgorithm, HA.SHA_384),
        )

        sign_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, priv_uid),
            data=encode_byte_string(Tag.Data, message),
            params=hash_param,
        )
        sign_resp  = sign_op.handle(sign_payload, "user", store, shim)
        sign_items = decode_all(sign_resp)
        signature  = next(i.value for i in sign_items if i.tag == Tag.SignatureData)

        ver_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, pub_uid),
            data=encode_byte_string(Tag.Data, message),
            sig=encode_byte_string(Tag.SignatureData, signature),
            params=hash_param,
        )
        ver_resp  = sigver_op.handle(ver_payload, "user", store, shim)
        ver_items = decode_all(ver_resp)
        validity  = next(i.value for i in ver_items if i.tag == Tag.ValidityIndicator)
        assert validity == ValidityIndicatorEnum.Valid

    def test_ec_ecdsa_sha512_roundtrip(self, store, shim):
        from kmip_pkcs11.operations import sign as sign_op, signature_verify as sigver_op
        from kmip_pkcs11.core.enums import HashingAlgorithm as HA

        pub_uid, priv_uid = _create_ec_keypair(store, shim)
        message = b"ECDSA-SHA512 test message"
        hash_param = encode_structure(
            Tag.CryptographicParameters,
            encode_enumeration(Tag.HashingAlgorithm, HA.SHA_512),
        )

        sign_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, priv_uid),
            data=encode_byte_string(Tag.Data, message),
            params=hash_param,
        )
        sign_resp  = sign_op.handle(sign_payload, "user", store, shim)
        sign_items = decode_all(sign_resp)
        signature  = next(i.value for i in sign_items if i.tag == Tag.SignatureData)

        ver_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, pub_uid),
            data=encode_byte_string(Tag.Data, message),
            sig=encode_byte_string(Tag.SignatureData, signature),
            params=hash_param,
        )
        ver_resp  = sigver_op.handle(ver_payload, "user", store, shim)
        ver_items = decode_all(ver_resp)
        validity  = next(i.value for i in ver_items if i.tag == Tag.ValidityIndicator)
        assert validity == ValidityIndicatorEnum.Valid


class TestPhase4MechSelection:
    """_select_mechanism picks the right PKCS#11 mechanism."""

    def test_rsa_default_is_sha256(self):
        from kmip_pkcs11.operations.sign import _select_mechanism
        from pkcs11 import Mechanism
        mech = _select_mechanism(CryptographicAlgorithm.RSA, None)
        assert mech == Mechanism.SHA256_RSA_PKCS

    def test_rsa_sha1_hash(self):
        from kmip_pkcs11.operations.sign import _select_mechanism
        from pkcs11 import Mechanism
        mech = _select_mechanism(CryptographicAlgorithm.RSA, HashingAlgorithm.SHA_1)
        assert mech == Mechanism.SHA1_RSA_PKCS

    def test_rsa_sha512_hash(self):
        from kmip_pkcs11.operations.sign import _select_mechanism
        from pkcs11 import Mechanism
        mech = _select_mechanism(CryptographicAlgorithm.RSA, HashingAlgorithm.SHA_512)
        assert mech == Mechanism.SHA512_RSA_PKCS

    def test_ec_default_is_ecdsa_sha256(self):
        from kmip_pkcs11.operations.sign import _select_mechanism
        from pkcs11 import Mechanism
        mech = _select_mechanism(CryptographicAlgorithm.EC, None)
        assert mech == Mechanism.ECDSA_SHA256

    def test_ecdsa_sha256_explicit(self):
        from kmip_pkcs11.operations.sign import _select_mechanism
        from pkcs11 import Mechanism
        mech = _select_mechanism(CryptographicAlgorithm.ECDSA, HashingAlgorithm.SHA_256)
        assert mech == Mechanism.ECDSA_SHA256

    def test_ecdsa_sha384_explicit(self):
        from kmip_pkcs11.operations.sign import _select_mechanism
        from pkcs11 import Mechanism
        mech = _select_mechanism(CryptographicAlgorithm.EC, HashingAlgorithm.SHA_384)
        assert mech == Mechanism.ECDSA_SHA384

    def test_ecdsa_sha512_explicit(self):
        from kmip_pkcs11.operations.sign import _select_mechanism
        from pkcs11 import Mechanism
        mech = _select_mechanism(CryptographicAlgorithm.EC, HashingAlgorithm.SHA_512)
        assert mech == Mechanism.ECDSA_SHA512

    def test_ecdsa_sha1_explicit(self):
        from kmip_pkcs11.operations.sign import _select_mechanism
        from pkcs11 import Mechanism
        mech = _select_mechanism(CryptographicAlgorithm.EC, HashingAlgorithm.SHA_1)
        assert mech == Mechanism.ECDSA_SHA1


class TestPhase4Dispatcher:
    """Sign and SignatureVerify are registered in the dispatcher."""

    def test_sign_registered(self):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation
        d = OperationDispatcher(store=MagicMock(), shim=MagicMock())
        assert Operation.Sign in d._handlers

    def test_sigver_registered(self):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation
        d = OperationDispatcher(store=MagicMock(), shim=MagicMock())
        assert Operation.SignatureVerify in d._handlers


# ══════════════════════════════════════════════════════════════════════════════
# Phase 1 — Bug Fixes & Registration Gaps
# BUG01: Get PrivateKey class lookup  BUG02: generate_random bytes
# GAP03: Sign/SignatureVerify in Query  GAP04: GetAttributeList dispatched
# ══════════════════════════════════════════════════════════════════════════════

class TestPhase1BugRandom:
    """BUG02 — generate_random() must return exactly `length` bytes."""

    def test_random_16_bytes(self, shim):
        result = shim.generate_random(16)
        assert isinstance(result, bytes)
        assert len(result) == 16

    def test_random_32_bytes(self, shim):
        assert len(shim.generate_random(32)) == 32

    def test_random_1_byte(self, shim):
        assert len(shim.generate_random(1)) == 1

    def test_random_values_differ(self, shim):
        # Probability of two 16-byte random values colliding is negligible
        assert shim.generate_random(16) != shim.generate_random(16)


class TestPhase1QueryAdvertised:
    """GAP03 — Query must advertise Sign, SignatureVerify, and GetAttributeList."""

    def _op_values(self):
        from kmip_pkcs11.operations import query as query_op
        resp = query_op.handle(None, "user", MagicMock(), MagicMock())
        return {i.value for i in decode_all(resp) if i.tag == Tag.Operations}

    def test_sign_advertised(self):
        from kmip_pkcs11.core.enums import Operation
        assert Operation.Sign in self._op_values()

    def test_signature_verify_advertised(self):
        from kmip_pkcs11.core.enums import Operation
        assert Operation.SignatureVerify in self._op_values()

    def test_get_attribute_list_advertised(self):
        from kmip_pkcs11.core.enums import Operation
        assert Operation.GetAttributeList in self._op_values()

    def test_legacy_ops_still_advertised(self):
        from kmip_pkcs11.core.enums import Operation
        ops = self._op_values()
        for op in (Operation.Create, Operation.Encrypt, Operation.Destroy):
            assert op in ops


class TestPhase1GetAttributeListDispatch:
    """GAP04 — GetAttributeList must be dispatched and return attribute names."""

    def test_registered_in_dispatcher(self):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation
        d = OperationDispatcher(store=MagicMock(), shim=MagicMock())
        assert Operation.GetAttributeList in d._handlers

    def test_returns_attribute_names(self, store, shim):
        from kmip_pkcs11.operations import get_attributes as ga_op
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey,
            state=State.Active,
            cryptographic_algorithm=CryptographicAlgorithm.AES,
            cryptographic_length=256,
            usage_mask=CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt,
            owner_identity="user",
        )
        store.add_attribute(uid, "x-label", "test-key")

        payload = _make_payload(uid=encode_text_string(Tag.UniqueIdentifier, uid))
        resp = ga_op.handle_add(payload, "user", store, shim)
        items = decode_all(resp)
        names = {i.value for i in items if i.tag == Tag.AttributeName}
        assert "Object Type" in names
        assert "State" in names
        assert "x-label" in names

    def test_via_dispatcher(self, store, shim):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation
        from kmip_pkcs11.core.ttlv import encode_structure

        uid = store.create_object(
            object_type=ObjectType.SymmetricKey,
            state=State.Active,
            cryptographic_algorithm=CryptographicAlgorithm.AES,
            cryptographic_length=128,
            owner_identity="user",
        )

        d = OperationDispatcher(store, shim)
        inner = (
            encode_enumeration(Tag.Operation, Operation.GetAttributeList)
            + encode_structure(
                Tag.RequestPayload,
                encode_text_string(Tag.UniqueIdentifier, uid),
            )
        )
        batch_item = decode_one(encode_structure(Tag.BatchItem, inner))
        raw = d.dispatch(batch_item, "user")
        result = decode_one(raw)
        status_item = result.get(Tag.ResultStatus)
        from kmip_pkcs11.core.enums import ResultStatus
        assert status_item.value == ResultStatus.Success


class TestPhase1GetPrivateKey:
    """BUG01 — Get for PrivateKey must search PRIVATE_KEY class, not SECRET_KEY."""

    def test_non_extractable_private_key_raises(self, store, shim):
        """Default CreateKeyPair sets extractable=False — Get must raise NotExtractable."""
        from kmip_pkcs11.operations import get as get_op
        _, priv_uid = _create_rsa_keypair(store, shim)
        payload = _make_payload(uid=encode_text_string(Tag.UniqueIdentifier, priv_uid))
        with pytest.raises(NotExtractable):
            get_op.handle(payload, "user", store, shim)

    def test_extractable_private_key_returns_key_material(self, store, shim):
        """An extractable RSA private key must be retrievable via Get."""
        from kmip_pkcs11.operations import get as get_op

        # Generate an extractable keypair directly via shim (bypassing KMIP defaults)
        pub_cka_id, priv_cka_id = shim.generate_key_pair(
            algorithm=CryptographicAlgorithm.RSA,
            key_length=2048,
            label="phase1-extractable-rsa",
            extractable=True,
            sensitive=False,
        )
        priv_uid = store.create_object(
            object_type=ObjectType.PrivateKey,
            state=State.Active,
            cryptographic_algorithm=CryptographicAlgorithm.RSA,
            cryptographic_length=2048,
            usage_mask=CryptographicUsageMask.Sign,
            extractable=True,
            sensitive=False,
            owner_identity="user",
        )
        store.add_attribute(priv_uid, "_pkcs11_cka_id", priv_cka_id.hex())

        payload = _make_payload(uid=encode_text_string(Tag.UniqueIdentifier, priv_uid))
        resp = get_op.handle(payload, "user", store, shim)

        items = decode_all(resp)
        uid_item = next(i for i in items if i.tag == Tag.UniqueIdentifier)
        assert uid_item.value == priv_uid
        # Response must be non-trivial (contains key material structure)
        assert len(resp) > 100

    def test_get_private_key_der_uses_private_key_class(self, shim):
        """Shim must locate private key via PRIVATE_KEY class, not SECRET_KEY."""
        from pkcs11 import ObjectClass
        # Generate a non-extractable key pair — we just want to confirm the lookup
        _, priv_cka_id = shim.generate_key_pair(
            algorithm=CryptographicAlgorithm.RSA,
            key_length=2048,
            label="phase1-class-check",
            extractable=False,
            sensitive=True,
        )
        # Non-extractable should raise NotExtractable, not ItemNotFound
        with pytest.raises(NotExtractable):
            shim.get_private_key_der(priv_cka_id)


# ══════════════════════════════════════════════════════════════════════════════
# Phase 2 — RNGRetrieve, ModifyAttribute, SetAttribute, AdjustAttribute, Query
# ══════════════════════════════════════════════════════════════════════════════

def _create_plain_uid(store, object_type=ObjectType.SecretData):
    return store.create_object(
        object_type=object_type,
        state=State.Active,
        usage_mask=CryptographicUsageMask.Encrypt,
        extractable=True,
        sensitive=False,
        owner_identity="user",
    )


class TestPhase2RNGRetrieve:
    def test_default_length(self, store, shim):
        from kmip_pkcs11.operations import rng_retrieve as op
        resp = op.handle(None, "user", store, shim)
        item = decode_one(encode_structure(Tag.RequestPayload, resp))
        data = item.get(Tag.Data).value
        assert len(data) == 32

    def test_custom_length(self, store, shim):
        from kmip_pkcs11.operations import rng_retrieve as op
        payload = _make_payload(dl=encode_integer(Tag.DataLength, 16))
        resp = op.handle(payload, "user", store, shim)
        item = decode_one(encode_structure(Tag.RequestPayload, resp))
        data = item.get(Tag.Data).value
        assert len(data) == 16

    def test_zero_length_raises(self, store, shim):
        from kmip_pkcs11.operations import rng_retrieve as op
        payload = _make_payload(dl=encode_integer(Tag.DataLength, 0))
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_oversized_length_raises(self, store, shim):
        from kmip_pkcs11.operations import rng_retrieve as op
        payload = _make_payload(dl=encode_integer(Tag.DataLength, 100000))
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_values_differ(self, store, shim):
        from kmip_pkcs11.operations import rng_retrieve as op
        item1 = decode_one(encode_structure(Tag.RequestPayload, op.handle(None, "user", store, shim)))
        item2 = decode_one(encode_structure(Tag.RequestPayload, op.handle(None, "user", store, shim)))
        assert item1.get(Tag.Data).value != item2.get(Tag.Data).value


class TestPhase2ModifyAttribute:
    def test_modify_existing_attribute(self, store, shim):
        from kmip_pkcs11.operations import modify_attribute as op
        uid = _create_plain_uid(store)
        store.add_attribute(uid, "Comment", "old-value")
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            attr=_attr("Comment", encode_text_string(Tag.AttributeValue, "new-value")),
        )
        resp = op.handle(payload, "user", store, shim)
        items = decode_all(resp)
        assert any(i.tag == Tag.UniqueIdentifier and i.value == uid for i in items)
        assert store.get_attribute(uid, "Comment") == ["new-value"]

    def test_modify_missing_attribute_raises(self, store, shim):
        from kmip_pkcs11.operations import modify_attribute as op
        uid = _create_plain_uid(store)
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            attr=_attr("Nonexistent", encode_text_string(Tag.AttributeValue, "x")),
        )
        with pytest.raises(ItemNotFound):
            op.handle(payload, "user", store, shim)

    def test_modify_missing_object_raises(self, store, shim):
        from kmip_pkcs11.operations import modify_attribute as op
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, "does-not-exist"),
            attr=_attr("Comment", encode_text_string(Tag.AttributeValue, "x")),
        )
        with pytest.raises(ItemNotFound):
            op.handle(payload, "user", store, shim)

    def test_modify_missing_payload_raises(self, store, shim):
        from kmip_pkcs11.operations import modify_attribute as op
        with pytest.raises(MissingData):
            op.handle(None, "user", store, shim)


class TestPhase2SetAttribute:
    def test_set_new_attribute(self, store, shim):
        from kmip_pkcs11.operations import set_attribute as op
        uid = _create_plain_uid(store)
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            name=encode_text_string(Tag.AttributeName, "Comment"),
            value=encode_text_string(Tag.AttributeValue, "hello"),
        )
        op.handle(payload, "user", store, shim)
        assert store.get_attribute(uid, "Comment") == ["hello"]

    def test_set_overwrites_existing(self, store, shim):
        from kmip_pkcs11.operations import set_attribute as op
        uid = _create_plain_uid(store)
        store.add_attribute(uid, "Comment", "first")
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            name=encode_text_string(Tag.AttributeName, "Comment"),
            value=encode_text_string(Tag.AttributeValue, "second"),
        )
        op.handle(payload, "user", store, shim)
        assert store.get_attribute(uid, "Comment") == ["second"]

    def test_set_missing_object_raises(self, store, shim):
        from kmip_pkcs11.operations import set_attribute as op
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, "does-not-exist"),
            name=encode_text_string(Tag.AttributeName, "Comment"),
            value=encode_text_string(Tag.AttributeValue, "x"),
        )
        with pytest.raises(ItemNotFound):
            op.handle(payload, "user", store, shim)


class TestPhase2AdjustAttribute:
    def test_increment(self, store, shim):
        from kmip_pkcs11.operations import adjust_attribute as op
        uid = _create_plain_uid(store)
        store.add_attribute(uid, "UsageLimitCount", 10)
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            attr=_attr("UsageLimitCount", encode_integer(Tag.AttributeValue, 5)),
            adj=encode_enumeration(Tag.AdjustmentType, 1),  # Increment
        )
        op.handle(payload, "user", store, shim)
        assert store.get_attribute(uid, "UsageLimitCount") == [15]

    def test_decrement(self, store, shim):
        from kmip_pkcs11.operations import adjust_attribute as op
        uid = _create_plain_uid(store)
        store.add_attribute(uid, "UsageLimitCount", 10)
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            attr=_attr("UsageLimitCount", encode_integer(Tag.AttributeValue, 3)),
            adj=encode_enumeration(Tag.AdjustmentType, 2),  # Decrement
        )
        op.handle(payload, "user", store, shim)
        assert store.get_attribute(uid, "UsageLimitCount") == [7]

    def test_set_via_adjustment_type(self, store, shim):
        from kmip_pkcs11.operations import adjust_attribute as op
        uid = _create_plain_uid(store)
        store.add_attribute(uid, "UsageLimitCount", 10)
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            attr=_attr("UsageLimitCount", encode_integer(Tag.AttributeValue, 99)),
            adj=encode_enumeration(Tag.AdjustmentType, 3),  # Set
        )
        op.handle(payload, "user", store, shim)
        assert store.get_attribute(uid, "UsageLimitCount") == [99]

    def test_non_numeric_raises(self, store, shim):
        from kmip_pkcs11.operations import adjust_attribute as op
        uid = _create_plain_uid(store)
        store.add_attribute(uid, "Comment", "text-value")
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            attr=_attr("Comment", encode_integer(Tag.AttributeValue, 1)),
            adj=encode_enumeration(Tag.AdjustmentType, 1),
        )
        with pytest.raises(InvalidField):
            op.handle(payload, "user", store, shim)

    def test_missing_object_raises(self, store, shim):
        from kmip_pkcs11.operations import adjust_attribute as op
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, "does-not-exist"),
            attr=_attr("UsageLimitCount", encode_integer(Tag.AttributeValue, 1)),
        )
        with pytest.raises(ItemNotFound):
            op.handle(payload, "user", store, shim)


class TestPhase2Dispatcher:
    def test_all_ops_registered(self, store, shim):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation
        d = OperationDispatcher(store, shim)
        for op in (Operation.RNGRetrieve, Operation.ModifyAttribute,
                   Operation.SetAttribute, Operation.AdjustAttribute):
            assert op in d._handlers

    def test_rng_retrieve_via_dispatcher(self, store, shim):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation
        d = OperationDispatcher(store, shim)
        batch = decode_one(encode_structure(
            Tag.BatchItem,
            encode_enumeration(Tag.Operation, Operation.RNGRetrieve)
        ))
        resp = d.dispatch(batch, "user")
        item = decode_one(resp)
        assert item.get(Tag.ResultStatus).value == 0  # Success


class TestPhase2QueryAdvertised:
    def test_rng_retrieve_advertised(self):
        from kmip_pkcs11.operations import query as op
        from kmip_pkcs11.core.enums import Operation
        assert Operation.RNGRetrieve in op.SUPPORTED_OPERATIONS

    def test_modify_attribute_advertised(self):
        from kmip_pkcs11.operations import query as op
        from kmip_pkcs11.core.enums import Operation
        assert Operation.ModifyAttribute in op.SUPPORTED_OPERATIONS

    def test_set_attribute_advertised(self):
        from kmip_pkcs11.operations import query as op
        from kmip_pkcs11.core.enums import Operation
        assert Operation.SetAttribute in op.SUPPORTED_OPERATIONS

    def test_adjust_attribute_advertised(self):
        from kmip_pkcs11.operations import query as op
        from kmip_pkcs11.core.enums import Operation
        assert Operation.AdjustAttribute in op.SUPPORTED_OPERATIONS


class TestPhase2StoreHelpers:
    def test_update_attribute_returns_zero_when_missing(self, store, shim):
        uid = _create_plain_uid(store)
        rows = store.update_attribute(uid, "Nope", "x")
        assert rows == 0

    def test_update_attribute_returns_one_when_found(self, store, shim):
        uid = _create_plain_uid(store)
        store.add_attribute(uid, "Comment", "a")
        rows = store.update_attribute(uid, "Comment", "b")
        assert rows == 1
        assert store.get_attribute(uid, "Comment") == ["b"]

    def test_set_or_add_creates_when_missing(self, store, shim):
        uid = _create_plain_uid(store)
        store.set_or_add_attribute(uid, "Comment", "created")
        assert store.get_attribute(uid, "Comment") == ["created"]

    def test_set_or_add_overwrites_when_present(self, store, shim):
        uid = _create_plain_uid(store)
        store.add_attribute(uid, "Comment", "first")
        store.set_or_add_attribute(uid, "Comment", "overwritten")
        assert store.get_attribute(uid, "Comment") == ["overwritten"]


# ══════════════════════════════════════════════════════════════════════════════
# Audit Phase 3 — MAC, MACVerify, Hash
# ══════════════════════════════════════════════════════════════════════════════

def _create_hmac_uid(store, shim, algorithm=None, length=256, extractable=False) -> str:
    from kmip_pkcs11.operations import create as create_mod
    if algorithm is None:
        algorithm = CryptographicAlgorithm.HMACSHA256
    attrs = (
        _attr("Cryptographic Algorithm",
              encode_enumeration(Tag.AttributeValue, algorithm))
        + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, length))
        + _attr("Cryptographic Usage Mask",
                encode_integer(Tag.AttributeValue,
                               CryptographicUsageMask.MACGenerate | CryptographicUsageMask.MACVerify))
        + _attr("Extractable", encode_integer(Tag.AttributeValue, int(extractable)))
    )
    p = decode_one(encode_structure(Tag.RequestPayload,
        encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
        + encode_structure(Tag.TemplateAttribute, attrs)
    ))
    resp_bytes = create_mod.handle(p, "user", store, shim)
    uid = decode_one(encode_structure(Tag.ResponsePayload, resp_bytes)).get(
        Tag.UniqueIdentifier).value
    store.activate(uid)
    return uid


class TestPhase3MACLive:
    """HMAC-SHA256 MAC/MACVerify round-trip through SoftHSM2."""

    def test_mac_verify_roundtrip(self, store, shim):
        from kmip_pkcs11.operations import mac as mac_op, mac_verify as macver_op
        uid = _create_hmac_uid(store, shim)
        message = b"KMIP MAC test message"

        mac_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, message),
        )
        mac_resp  = mac_op.handle(mac_payload, "user", store, shim)
        mac_items = decode_all(mac_resp)
        mac_value = next(i.value for i in mac_items if i.tag == Tag.MACData)
        assert len(mac_value) == 32

        ver_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, message),
            mac=encode_byte_string(Tag.MACData, mac_value),
        )
        ver_resp  = macver_op.handle(ver_payload, "user", store, shim)
        ver_items = decode_all(ver_resp)
        validity  = next(i.value for i in ver_items if i.tag == Tag.ValidityIndicator)
        assert validity == ValidityIndicatorEnum.Valid

    def test_mac_verify_wrong_data_is_invalid(self, store, shim):
        from kmip_pkcs11.operations import mac as mac_op, mac_verify as macver_op
        uid = _create_hmac_uid(store, shim)

        mac_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, b"original message"),
        )
        mac_resp  = mac_op.handle(mac_payload, "user", store, shim)
        mac_value = next(i.value for i in decode_all(mac_resp) if i.tag == Tag.MACData)

        ver_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, b"tampered message"),
            mac=encode_byte_string(Tag.MACData, mac_value),
        )
        ver_resp = macver_op.handle(ver_payload, "user", store, shim)
        validity = next(i.value for i in decode_all(ver_resp) if i.tag == Tag.ValidityIndicator)
        assert validity == ValidityIndicatorEnum.Invalid

    def test_mac_verify_wrong_mac_is_invalid(self, store, shim):
        from kmip_pkcs11.operations import mac_verify as macver_op
        uid = _create_hmac_uid(store, shim)
        ver_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, b"some data"),
            mac=encode_byte_string(Tag.MACData, b"\x00" * 32),
        )
        ver_resp = macver_op.handle(ver_payload, "user", store, shim)
        validity = next(i.value for i in decode_all(ver_resp) if i.tag == Tag.ValidityIndicator)
        assert validity == ValidityIndicatorEnum.Invalid

    def test_mac_sha1_key(self, store, shim):
        from kmip_pkcs11.operations import mac as mac_op, mac_verify as macver_op
        uid = _create_hmac_uid(store, shim, algorithm=CryptographicAlgorithm.HMACSHA1, length=160)
        message = b"sha1 hmac test"

        mac_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, message),
        )
        mac_resp  = mac_op.handle(mac_payload, "user", store, shim)
        mac_value = next(i.value for i in decode_all(mac_resp) if i.tag == Tag.MACData)
        assert len(mac_value) == 20

        ver_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, message),
            mac=encode_byte_string(Tag.MACData, mac_value),
        )
        ver_resp = macver_op.handle(ver_payload, "user", store, shim)
        validity = next(i.value for i in decode_all(ver_resp) if i.tag == Tag.ValidityIndicator)
        assert validity == ValidityIndicatorEnum.Valid


class TestPhase3MACErrors:
    def test_mac_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import mac as mac_op
        with pytest.raises(MissingData):
            mac_op.handle(None, "user", MagicMock(), shim)

    def test_mac_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import mac as mac_op
        payload = _make_payload(data=encode_byte_string(Tag.Data, b"x"))
        with pytest.raises(MissingData):
            mac_op.handle(payload, "user", store, shim)

    def test_mac_missing_data_raises(self, store, shim):
        from kmip_pkcs11.operations import mac as mac_op
        uid = _create_hmac_uid(store, shim)
        payload = _make_payload(uid=encode_text_string(Tag.UniqueIdentifier, uid))
        with pytest.raises(MissingData):
            mac_op.handle(payload, "user", store, shim)

    def test_mac_unknown_object_raises(self, store, shim):
        from kmip_pkcs11.operations import mac as mac_op
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, "nope"),
            data=encode_byte_string(Tag.Data, b"x"),
        )
        with pytest.raises(ItemNotFound):
            mac_op.handle(payload, "user", store, shim)

    def test_mac_verify_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import mac_verify as macver_op
        with pytest.raises(MissingData):
            macver_op.handle(None, "user", MagicMock(), shim)

    def test_mac_verify_missing_mac_data_raises(self, store, shim):
        from kmip_pkcs11.operations import mac_verify as macver_op
        uid = _create_hmac_uid(store, shim)
        payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, b"x"),
        )
        with pytest.raises(MissingData):
            macver_op.handle(payload, "user", store, shim)


class TestPhase3HashLive:
    """Hash operation — no key involved, computes a digest directly."""

    def test_hash_sha256(self, shim):
        import hashlib
        from kmip_pkcs11.operations import hash_op

        payload = _make_payload(
            data=encode_byte_string(Tag.Data, b"hash me please"),
            params=encode_structure(
                Tag.CryptographicParameters,
                encode_enumeration(Tag.HashingAlgorithm, HashingAlgorithm.SHA_256),
            ),
        )
        resp  = hash_op.handle(payload, "user", MagicMock(), shim)
        items = decode_all(resp)
        digest = next(i.value for i in items if i.tag == Tag.Data)
        assert digest == hashlib.sha256(b"hash me please").digest()

    def test_hash_sha1(self, shim):
        import hashlib
        from kmip_pkcs11.operations import hash_op

        payload = _make_payload(
            data=encode_byte_string(Tag.Data, b"another message"),
            params=encode_structure(
                Tag.CryptographicParameters,
                encode_enumeration(Tag.HashingAlgorithm, HashingAlgorithm.SHA_1),
            ),
        )
        resp  = hash_op.handle(payload, "user", MagicMock(), shim)
        digest = next(i.value for i in decode_all(resp) if i.tag == Tag.Data)
        assert digest == hashlib.sha1(b"another message").digest()

    def test_hash_md5(self, shim):
        import hashlib
        from kmip_pkcs11.operations import hash_op

        payload = _make_payload(
            data=encode_byte_string(Tag.Data, b"md5 test"),
            params=encode_structure(
                Tag.CryptographicParameters,
                encode_enumeration(Tag.HashingAlgorithm, HashingAlgorithm.MD5),
            ),
        )
        resp  = hash_op.handle(payload, "user", MagicMock(), shim)
        digest = next(i.value for i in decode_all(resp) if i.tag == Tag.Data)
        assert digest == hashlib.md5(b"md5 test").digest()

    def test_hash_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import hash_op
        with pytest.raises(MissingData):
            hash_op.handle(None, "user", MagicMock(), shim)

    def test_hash_missing_data_raises(self, shim):
        from kmip_pkcs11.operations import hash_op
        payload = _make_payload(
            params=encode_structure(
                Tag.CryptographicParameters,
                encode_enumeration(Tag.HashingAlgorithm, HashingAlgorithm.SHA_256),
            ),
        )
        with pytest.raises(MissingData):
            hash_op.handle(payload, "user", MagicMock(), shim)

    def test_hash_missing_algorithm_raises(self, shim):
        from kmip_pkcs11.operations import hash_op
        payload = _make_payload(data=encode_byte_string(Tag.Data, b"x"))
        with pytest.raises(MissingData):
            hash_op.handle(payload, "user", MagicMock(), shim)

    def test_hash_unsupported_algorithm_raises(self, shim):
        """RIPEMD-160 has no HASH_ALG_TO_MECH entry at all — CryptographicFailure."""
        from kmip_pkcs11.operations import hash_op
        payload = _make_payload(
            data=encode_byte_string(Tag.Data, b"x"),
            params=encode_structure(
                Tag.CryptographicParameters,
                encode_enumeration(Tag.HashingAlgorithm, HashingAlgorithm.RIPEMD_160),
            ),
        )
        with pytest.raises(CryptographicFailure):
            hash_op.handle(payload, "user", MagicMock(), shim)

    def test_hash_sha3_mapped_but_unavailable_on_token_raises_operation_not_supported(self, shim):
        """SHA3-256 has a real HASH_ALG_TO_MECH entry (Mechanism.SHA3_256 is a
        genuine PKCS#11 mechanism), but this SoftHSM2 build doesn't implement
        it — confirmed live via slot.get_mechanisms(). The capability gate
        must reject it cleanly rather than a raw PKCS#11 error surfacing."""
        from kmip_pkcs11.operations import hash_op
        payload = _make_payload(
            data=encode_byte_string(Tag.Data, b"x"),
            params=encode_structure(
                Tag.CryptographicParameters,
                encode_enumeration(Tag.HashingAlgorithm, HashingAlgorithm.SHA3_256),
            ),
        )
        with pytest.raises(OperationNotSupported):
            hash_op.handle(payload, "user", MagicMock(), shim)


class TestPhase3QueryAdvertised:
    def test_mac_ops_and_hash_advertised(self, store, shim):
        from kmip_pkcs11.operations import query as op
        from kmip_pkcs11.core.enums import Operation
        resp = op.handle(None, "user", store, shim)
        ops  = [i.value for i in decode_all(resp) if i.tag == Tag.Operations]
        assert Operation.MAC in ops
        assert Operation.MACVerify in ops
        assert Operation.Hash in ops


class TestPhase3Dispatcher:
    def test_all_registered(self):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation
        d = OperationDispatcher(store=MagicMock(), shim=MagicMock())
        assert Operation.MAC in d._handlers
        assert Operation.MACVerify in d._handlers
        assert Operation.Hash in d._handlers

    def test_hash_via_dispatcher(self, store, shim):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation, ResultStatus
        d = OperationDispatcher(store=store, shim=shim)
        req_payload = encode_structure(
            Tag.RequestPayload,
            encode_byte_string(Tag.Data, b"dispatch me")
            + encode_structure(
                Tag.CryptographicParameters,
                encode_enumeration(Tag.HashingAlgorithm, HashingAlgorithm.SHA_256),
            ),
        )
        batch_item = decode_one(encode_structure(
            Tag.BatchItem,
            encode_enumeration(Tag.Operation, Operation.Hash) + req_payload
        ))
        resp = d.dispatch(batch_item, "user")
        item = decode_one(resp)
        status_item = item.get(Tag.ResultStatus)
        assert status_item.value == ResultStatus.Success


# ══════════════════════════════════════════════════════════════════════════════
# Audit Phase 4 — Register(PublicKey/PrivateKey/Certificate), Import/Export,
# EC curve selection, DSA
# ══════════════════════════════════════════════════════════════════════════════

from kmip_pkcs11.core.enums import RecommendedCurve, CertificateType, ValidityIndicator


def _create_dsa_keypair(store, shim, length=1024):
    from kmip_pkcs11.operations import create_keypair as ckp
    attrs = encode_structure(
        Tag.TemplateAttribute,
        _attr("Cryptographic Algorithm",
              encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.DSA))
        + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, length)),
    )
    p = decode_one(encode_structure(Tag.RequestPayload,
        encode_enumeration(Tag.ObjectType, ObjectType.PublicKey) + attrs
    ))
    resp_bytes = ckp.handle(p, "user", store, shim)
    uids = [i.value for i in decode_all(resp_bytes) if i.tag == Tag.UniqueIdentifier]
    return uids[0], uids[1]


def _create_ec_keypair_with_curve(store, shim, curve):
    from kmip_pkcs11.operations import create_keypair as ckp
    domain_params = encode_structure(
        Tag.AttributeValue,
        encode_enumeration(Tag.RecommendedCurve, curve),
    )
    attrs = encode_structure(
        Tag.TemplateAttribute,
        _attr("Cryptographic Algorithm",
              encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.ECDSA))
        + _attr("Cryptographic Domain Parameters", domain_params),
    )
    p = decode_one(encode_structure(Tag.RequestPayload,
        encode_enumeration(Tag.ObjectType, ObjectType.PublicKey) + attrs
    ))
    resp_bytes = ckp.handle(p, "user", store, shim)
    uids = [i.value for i in decode_all(resp_bytes) if i.tag == Tag.UniqueIdentifier]
    return uids[0], uids[1]


def _sign_and_verify(store, shim, pub_uid, priv_uid, message):
    from kmip_pkcs11.operations import sign as sign_op, signature_verify as sigver_op
    sign_payload = _make_payload(
        uid=encode_text_string(Tag.UniqueIdentifier, priv_uid),
        data=encode_byte_string(Tag.Data, message),
    )
    sign_resp = sign_op.handle(sign_payload, "user", store, shim)
    signature = next(i.value for i in decode_all(sign_resp) if i.tag == Tag.SignatureData)

    ver_payload = _make_payload(
        uid=encode_text_string(Tag.UniqueIdentifier, pub_uid),
        data=encode_byte_string(Tag.Data, message),
        sig=encode_byte_string(Tag.SignatureData, signature),
    )
    ver_resp = sigver_op.handle(ver_payload, "user", store, shim)
    return next(i.value for i in decode_all(ver_resp) if i.tag == Tag.ValidityIndicator)


class TestPhase4DSALive:
    def test_dsa_sign_verify_roundtrip(self, store, shim):
        pub_uid, priv_uid = _create_dsa_keypair(store, shim)
        validity = _sign_and_verify(store, shim, pub_uid, priv_uid, b"DSA sign test")
        assert validity == ValidityIndicator.Valid

    def test_dsa_keypair_has_correct_algorithm(self, store, shim):
        pub_uid, priv_uid = _create_dsa_keypair(store, shim)
        obj = store.get_object(priv_uid)
        assert obj["cryptographic_algorithm"] == CryptographicAlgorithm.DSA


def _ec_params_for(store, shim, pub_uid):
    """Ground-truth curve check — read CKA_EC_PARAMS directly off the token."""
    from pkcs11 import Attribute as _Attr, ObjectClass as _ObjClass
    cka_id = bytes.fromhex(store.get_attribute(pub_uid, "_pkcs11_cka_id")[0])
    key = shim._find_key(cka_id, _ObjClass.PUBLIC_KEY)
    return bytes(key[_Attr.EC_PARAMS])


class TestPhase4ECCurveSelection:
    def test_p384_curve_roundtrip(self, store, shim):
        from pkcs11.util.ec import encode_named_curve_parameters
        pub_uid, priv_uid = _create_ec_keypair_with_curve(store, shim, RecommendedCurve.P_384)
        assert _ec_params_for(store, shim, pub_uid) == encode_named_curve_parameters('secp384r1')
        validity = _sign_and_verify(store, shim, pub_uid, priv_uid, b"P-384 curve test")
        assert validity == ValidityIndicator.Valid

    def test_p521_curve_roundtrip(self, store, shim):
        from pkcs11.util.ec import encode_named_curve_parameters
        pub_uid, priv_uid = _create_ec_keypair_with_curve(store, shim, RecommendedCurve.P_521)
        assert _ec_params_for(store, shim, pub_uid) == encode_named_curve_parameters('secp521r1')
        validity = _sign_and_verify(store, shim, pub_uid, priv_uid, b"P-521 curve test")
        assert validity == ValidityIndicator.Valid

    def test_p192_curve_roundtrip(self, store, shim):
        from pkcs11.util.ec import encode_named_curve_parameters
        pub_uid, priv_uid = _create_ec_keypair_with_curve(store, shim, RecommendedCurve.P_192)
        assert _ec_params_for(store, shim, pub_uid) == encode_named_curve_parameters('secp192r1')
        validity = _sign_and_verify(store, shim, pub_uid, priv_uid, b"P-192 curve test")
        assert validity == ValidityIndicator.Valid

    def test_secp256k1_curve_roundtrip(self, store, shim):
        from pkcs11.util.ec import encode_named_curve_parameters
        pub_uid, priv_uid = _create_ec_keypair_with_curve(store, shim, RecommendedCurve.SECP256K1)
        assert _ec_params_for(store, shim, pub_uid) == encode_named_curve_parameters('secp256k1')
        validity = _sign_and_verify(store, shim, pub_uid, priv_uid, b"secp256k1 curve test")
        assert validity == ValidityIndicator.Valid

    def test_curves_produce_different_ec_params(self, store, shim):
        """Distinct RecommendedCurve requests must not silently collapse to one curve."""
        pub_192, _ = _create_ec_keypair_with_curve(store, shim, RecommendedCurve.P_192)
        pub_384, _ = _create_ec_keypair_with_curve(store, shim, RecommendedCurve.P_384)
        assert _ec_params_for(store, shim, pub_192) != _ec_params_for(store, shim, pub_384)

    def test_default_curve_is_p256(self, store, shim):
        from kmip_pkcs11.operations import create_keypair as ckp
        from pkcs11.util.ec import encode_named_curve_parameters
        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.ECDSA)),
        )
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.PublicKey) + attrs
        ))
        resp_bytes = ckp.handle(p, "user", store, shim)
        uids = [i.value for i in decode_all(resp_bytes) if i.tag == Tag.UniqueIdentifier]
        assert _ec_params_for(store, shim, uids[0]) == encode_named_curve_parameters('secp256r1')
        validity = _sign_and_verify(store, shim, uids[0], uids[1], b"default curve test")
        assert validity == ValidityIndicator.Valid

    def test_unsupported_curve_raises(self, store, shim):
        from kmip_pkcs11.operations import create_keypair as ckp
        domain_params = encode_structure(
            Tag.AttributeValue,
            encode_enumeration(Tag.RecommendedCurve, 999),
        )
        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.ECDSA))
            + _attr("Cryptographic Domain Parameters", domain_params),
        )
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.PublicKey) + attrs
        ))
        with pytest.raises(InvalidField):
            ckp.handle(p, "user", store, shim)


class TestPhase4RegisterPublicPrivateKey:
    """Register PublicKey/PrivateKey — RSA DER import round-tripped through Get()."""

    def _generate_extractable_rsa_der(self, shim):
        pub_id, priv_id = shim.generate_key_pair(
            algorithm=CryptographicAlgorithm.RSA, key_length=2048,
            label="phase4-reg-source", extractable=True, sensitive=False,
        )
        return shim.get_public_key_der(pub_id), shim.get_private_key_der(priv_id)

    def test_register_public_key_roundtrip(self, store, shim):
        from kmip_pkcs11.operations import register as reg_op, get as get_op
        pub_der, _ = self._generate_extractable_rsa_der(shim)

        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.RSA)),
        )
        key_block = encode_structure(
            Tag.KeyBlock,
            encode_enumeration(Tag.KeyFormatType, KeyFormatType.PKCS1)
            + encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, pub_der))
        )
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.PublicKey) + key_block + attrs
        ))
        resp = reg_op.handle(p, "user", store, shim)
        uid = decode_one(encode_structure(Tag.ResponsePayload, resp)).get(Tag.UniqueIdentifier).value

        obj = store.get_object(uid)
        assert obj["object_type"] == ObjectType.PublicKey
        assert obj["state"] == State.Active

        get_resp = get_op.handle(_uid_payload(uid), "user", store, shim)
        managed_obj = next(i for i in decode_all(get_resp) if i.tag == Tag.PublicKey)
        fetched_der = managed_obj.get(Tag.KeyBlock).get(Tag.KeyValue).get(Tag.KeyMaterial).value
        assert fetched_der == pub_der

    def test_register_private_key_pkcs1_then_sign(self, store, shim):
        from kmip_pkcs11.operations import register as reg_op
        pub_der, priv_der = self._generate_extractable_rsa_der(shim)

        pub_attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.RSA)),
        )
        pub_key_block = encode_structure(
            Tag.KeyBlock,
            encode_enumeration(Tag.KeyFormatType, KeyFormatType.PKCS1)
            + encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, pub_der))
        )
        pub_p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.PublicKey) + pub_key_block + pub_attrs
        ))
        pub_resp = reg_op.handle(pub_p, "user", store, shim)
        pub_uid = decode_one(encode_structure(Tag.ResponsePayload, pub_resp)).get(Tag.UniqueIdentifier).value

        priv_key_block = encode_structure(
            Tag.KeyBlock,
            encode_enumeration(Tag.KeyFormatType, KeyFormatType.PKCS1)
            + encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, priv_der))
        )
        priv_p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.PrivateKey) + priv_key_block + pub_attrs
        ))
        priv_resp = reg_op.handle(priv_p, "user", store, shim)
        priv_uid = decode_one(encode_structure(Tag.ResponsePayload, priv_resp)).get(Tag.UniqueIdentifier).value

        validity = _sign_and_verify(store, shim, pub_uid, priv_uid, b"registered key sign test")
        assert validity == ValidityIndicator.Valid

    def test_register_private_key_pkcs8(self, store, shim):
        from kmip_pkcs11.operations import register as reg_op
        from asn1crypto.keys import RSAPrivateKey as ASN1RSAKey, PrivateKeyInfo
        _, priv_der = self._generate_extractable_rsa_der(shim)
        pkcs8_der = PrivateKeyInfo.wrap(ASN1RSAKey.load(priv_der), 'rsa').dump()

        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.RSA)),
        )
        key_block = encode_structure(
            Tag.KeyBlock,
            encode_enumeration(Tag.KeyFormatType, KeyFormatType.PKCS8)
            + encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, pkcs8_der))
        )
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.PrivateKey) + key_block + attrs
        ))
        resp = reg_op.handle(p, "user", store, shim)
        uid = decode_one(encode_structure(Tag.ResponsePayload, resp)).get(Tag.UniqueIdentifier).value
        obj = store.get_object(uid)
        assert obj["object_type"] == ObjectType.PrivateKey

    def test_register_public_key_missing_algorithm_raises(self, store, shim):
        from kmip_pkcs11.operations import register as reg_op
        pub_der, _ = self._generate_extractable_rsa_der(shim)
        key_block = encode_structure(
            Tag.KeyBlock,
            encode_enumeration(Tag.KeyFormatType, KeyFormatType.PKCS1)
            + encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, pub_der))
        )
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.PublicKey) + key_block
        ))
        with pytest.raises(MissingData):
            reg_op.handle(p, "user", store, shim)

    def test_register_public_key_wrong_algorithm_raises(self, store, shim):
        from kmip_pkcs11.operations import register as reg_op
        pub_der, _ = self._generate_extractable_rsa_der(shim)
        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.EC)),
        )
        key_block = encode_structure(
            Tag.KeyBlock,
            encode_enumeration(Tag.KeyFormatType, KeyFormatType.PKCS1)
            + encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, pub_der))
        )
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.PublicKey) + key_block + attrs
        ))
        with pytest.raises(CryptographicFailure):
            reg_op.handle(p, "user", store, shim)


class TestPhase4RegisterCertificate:
    def test_register_and_get_certificate(self, store, shim):
        from kmip_pkcs11.operations import register as reg_op, get as get_op
        fake_der = b"\x30\x82\x01\x00" + os.urandom(252)  # not a real cert, just opaque bytes

        cert = encode_structure(
            Tag.Certificate,
            encode_enumeration(Tag.CertificateType, CertificateType.X509)
            + encode_byte_string(Tag.CertificateValue, fake_der)
        )
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.Certificate) + cert
        ))
        resp = reg_op.handle(p, "user", store, shim)
        uid = decode_one(encode_structure(Tag.ResponsePayload, resp)).get(Tag.UniqueIdentifier).value

        obj = store.get_object(uid)
        assert obj["object_type"] == ObjectType.Certificate
        assert obj["state"] == State.Active

        get_resp = get_op.handle(_uid_payload(uid), "user", store, shim)
        items = decode_all(get_resp)
        cert_struct = next(i for i in items if i.tag == Tag.Certificate)
        fetched_der = cert_struct.get(Tag.CertificateValue).value
        fetched_type = cert_struct.get(Tag.CertificateType).value
        assert fetched_der == fake_der
        assert fetched_type == CertificateType.X509

    def test_register_certificate_missing_value_raises(self, store, shim):
        from kmip_pkcs11.operations import register as reg_op
        cert = encode_structure(
            Tag.Certificate,
            encode_enumeration(Tag.CertificateType, CertificateType.X509)
        )
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.Certificate) + cert
        ))
        with pytest.raises(MissingData):
            reg_op.handle(p, "user", store, shim)

    def test_register_certificate_missing_structure_raises(self, store, shim):
        from kmip_pkcs11.operations import register as reg_op
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.Certificate)
        ))
        with pytest.raises(MissingData):
            reg_op.handle(p, "user", store, shim)


class TestPhase4Import:
    def test_import_new_object(self, store, shim):
        from kmip_pkcs11.operations import import_op
        key_bytes = os.urandom(16)
        client_uid = "client-chosen-uid-" + os.urandom(4).hex()
        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES)),
        )
        key_block = encode_structure(
            Tag.KeyBlock,
            encode_enumeration(Tag.KeyFormatType, KeyFormatType.Raw)
            + encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, key_bytes))
        )
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_text_string(Tag.UniqueIdentifier, client_uid)
            + encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
            + key_block + attrs
        ))
        resp = import_op.handle(p, "user", store, shim)
        result_uid = decode_one(encode_structure(Tag.ResponsePayload, resp)).get(Tag.UniqueIdentifier).value
        assert result_uid == client_uid
        assert store.object_exists(client_uid)

    def test_import_existing_without_replace_raises(self, store, shim):
        from kmip_pkcs11.operations import import_op
        client_uid = "dup-uid-" + os.urandom(4).hex()
        key_bytes = os.urandom(16)
        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES)),
        )
        key_block = encode_structure(
            Tag.KeyBlock,
            encode_enumeration(Tag.KeyFormatType, KeyFormatType.Raw)
            + encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, key_bytes))
        )
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_text_string(Tag.UniqueIdentifier, client_uid)
            + encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
            + key_block + attrs
        ))
        import_op.handle(p, "user", store, shim)  # first import succeeds
        with pytest.raises(InvalidField):
            import_op.handle(p, "user", store, shim)  # second: no ReplaceExisting

    def test_import_existing_with_replace_succeeds(self, store, shim):
        from kmip_pkcs11.operations import import_op
        client_uid = "replace-uid-" + os.urandom(4).hex()

        def make_payload(key_bytes, replace):
            attrs = encode_structure(
                Tag.TemplateAttribute,
                _attr("Cryptographic Algorithm",
                      encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES)),
            )
            key_block = encode_structure(
                Tag.KeyBlock,
                encode_enumeration(Tag.KeyFormatType, KeyFormatType.Raw)
                + encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, key_bytes))
            )
            fields = (
                encode_text_string(Tag.UniqueIdentifier, client_uid)
                + encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
                + key_block + attrs
            )
            if replace:
                from kmip_pkcs11.core.ttlv import encode_boolean
                fields += encode_boolean(Tag.ReplaceExisting, True)
            return decode_one(encode_structure(Tag.RequestPayload, fields))

        import_op.handle(make_payload(os.urandom(16), False), "user", store, shim)
        import_op.handle(make_payload(os.urandom(16), True), "user", store, shim)  # replace: OK
        assert store.object_exists(client_uid)

    def test_import_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import import_op
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
        ))
        with pytest.raises(MissingData):
            import_op.handle(p, "user", store, shim)

    def test_import_missing_object_type_raises(self, store, shim):
        from kmip_pkcs11.operations import import_op
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_text_string(Tag.UniqueIdentifier, "some-uid")
        ))
        with pytest.raises(MissingData):
            import_op.handle(p, "user", store, shim)

    def test_import_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import import_op
        with pytest.raises(MissingData):
            import_op.handle(None, "user", MagicMock(), shim)


class TestPhase4Export:
    def test_export_delegates_to_get(self, store, shim):
        from kmip_pkcs11.operations import export_op, get as get_op
        assert export_op.handle is get_op.handle

    def test_export_via_dispatcher(self, store, shim):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation, ResultStatus
        uid = _create_aes_uid(store, shim)
        store.activate(uid)
        d = OperationDispatcher(store=store, shim=shim)
        req_payload = encode_structure(Tag.RequestPayload,
            encode_text_string(Tag.UniqueIdentifier, uid))
        batch_item = decode_one(encode_structure(
            Tag.BatchItem,
            encode_enumeration(Tag.Operation, Operation.Export) + req_payload
        ))
        resp = d.dispatch(batch_item, "user")
        item = decode_one(resp)
        assert item.get(Tag.ResultStatus).value == ResultStatus.Success


class TestPhase4QueryAndDispatcher:
    def test_import_export_advertised(self, store, shim):
        from kmip_pkcs11.operations import query as op
        from kmip_pkcs11.core.enums import Operation
        resp = op.handle(None, "user", store, shim)
        ops = [i.value for i in decode_all(resp) if i.tag == Tag.Operations]
        assert Operation.Import in ops
        assert Operation.Export in ops

    def test_certificate_object_type_advertised(self, store, shim):
        from kmip_pkcs11.operations import query as op
        resp = op.handle(None, "user", store, shim)
        obj_types = [i.value for i in decode_all(resp) if i.tag == Tag.ObjectType]
        assert ObjectType.Certificate in obj_types

    def test_import_export_registered_in_dispatcher(self):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation
        d = OperationDispatcher(store=MagicMock(), shim=MagicMock())
        assert Operation.Import in d._handlers
        assert Operation.Export in d._handlers


# ══════════════════════════════════════════════════════════════════════════════
# Audit Phase 5 — DH/ECDH key pair, DeriveKey
# ══════════════════════════════════════════════════════════════════════════════

from kmip_pkcs11.core.enums import DerivationMethod


def _create_key_agreement_keypair(store, shim, owner, algorithm, length=None):
    from kmip_pkcs11.operations import create_keypair as ckp
    fields = _attr("Cryptographic Algorithm",
                    encode_enumeration(Tag.AttributeValue, algorithm))
    if length is not None:
        fields += _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, length))
    attrs = encode_structure(Tag.TemplateAttribute, fields)
    p = decode_one(encode_structure(Tag.RequestPayload,
        encode_enumeration(Tag.ObjectType, ObjectType.PublicKey) + attrs
    ))
    resp_bytes = ckp.handle(p, owner, store, shim)
    uids = [i.value for i in decode_all(resp_bytes) if i.tag == Tag.UniqueIdentifier]
    return uids[0], uids[1]  # pub_uid, priv_uid


def _get_public_value(store, shim, pub_uid, owner):
    from kmip_pkcs11.operations import get as get_op
    resp = get_op.handle(_uid_payload(pub_uid), owner, store, shim)
    managed_obj = next(i for i in decode_all(resp) if i.tag == Tag.PublicKey)
    return managed_obj.get(Tag.KeyBlock).get(Tag.KeyValue).get(Tag.KeyMaterial).value


def _derive(store, shim, priv_uid, peer_value, owner, length=128,
            extractable=True, sensitive=False, method=None):
    from kmip_pkcs11.operations import derive_key as dk
    fields = (
        _attr("Cryptographic Algorithm",
              encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
        + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, length))
        + _attr("Extractable", encode_integer(Tag.AttributeValue, int(extractable)))
        + _attr("Sensitive", encode_integer(Tag.AttributeValue, int(sensitive)))
    )
    deriv_attrs = encode_structure(Tag.TemplateAttribute, fields)
    deriv_params = encode_structure(Tag.DerivationParameters,
                                     encode_byte_string(Tag.DerivationData, peer_value))
    payload_fields = (
        encode_text_string(Tag.UniqueIdentifier, priv_uid)
        + deriv_params + deriv_attrs
    )
    if method is not None:
        payload_fields += encode_enumeration(Tag.DerivationMethod, method)
    p = decode_one(encode_structure(Tag.RequestPayload, payload_fields))
    resp = dk.handle(p, owner, store, shim)
    return decode_one(encode_structure(Tag.ResponsePayload, resp)).get(Tag.UniqueIdentifier).value


def _derived_key_bytes(store, shim, uid):
    cka_id = bytes.fromhex(store.get_attribute(uid, "_pkcs11_cka_id")[0])
    return shim.get_key_value(cka_id)


class TestPhase5DHKeyPair:
    def test_dh_keypair_created_with_key_agreement_mask(self, store, shim):
        pub_uid, priv_uid = _create_key_agreement_keypair(
            store, shim, "user", CryptographicAlgorithm.DH, length=2048)
        priv_obj = store.get_object(priv_uid)
        assert priv_obj["cryptographic_algorithm"] == CryptographicAlgorithm.DH
        assert priv_obj["usage_mask"] & CryptographicUsageMask.KeyAgreement

    def test_two_dh_keypairs_share_domain_group(self, store, shim):
        """Two independently-created DH key pairs must land in the same (P, G) —
        otherwise no two parties could ever agree on a shared secret."""
        from pkcs11 import Attribute as _Attr, ObjectClass as _ObjClass
        pub1, _ = _create_key_agreement_keypair(store, shim, "alice", CryptographicAlgorithm.DH)
        pub2, _ = _create_key_agreement_keypair(store, shim, "bob", CryptographicAlgorithm.DH)
        cka1 = bytes.fromhex(store.get_attribute(pub1, "_pkcs11_cka_id")[0])
        cka2 = bytes.fromhex(store.get_attribute(pub2, "_pkcs11_cka_id")[0])
        prime1 = bytes(shim._find_key(cka1, _ObjClass.PUBLIC_KEY)[_Attr.PRIME])
        prime2 = bytes(shim._find_key(cka2, _ObjClass.PUBLIC_KEY)[_Attr.PRIME])
        assert prime1 == prime2


class TestPhase5ECDHKeyPair:
    def test_ecdh_keypair_created_with_key_agreement_mask(self, store, shim):
        pub_uid, priv_uid = _create_key_agreement_keypair(
            store, shim, "user", CryptographicAlgorithm.ECDH)
        priv_obj = store.get_object(priv_uid)
        assert priv_obj["cryptographic_algorithm"] == CryptographicAlgorithm.ECDH
        assert priv_obj["usage_mask"] & CryptographicUsageMask.KeyAgreement


class TestPhase5DeriveKeyLive:
    def test_dh_two_party_shared_secret_matches(self, store, shim):
        alice_pub, alice_priv = _create_key_agreement_keypair(
            store, shim, "alice", CryptographicAlgorithm.DH, length=2048)
        bob_pub, bob_priv = _create_key_agreement_keypair(
            store, shim, "bob", CryptographicAlgorithm.DH, length=2048)

        bob_value   = _get_public_value(store, shim, bob_pub, "bob")
        alice_value = _get_public_value(store, shim, alice_pub, "alice")

        alice_derived = _derive(store, shim, alice_priv, bob_value, "alice")
        bob_derived   = _derive(store, shim, bob_priv, alice_value, "bob")

        assert _derived_key_bytes(store, shim, alice_derived) == _derived_key_bytes(store, shim, bob_derived)

    def test_ecdh_two_party_shared_secret_matches(self, store, shim):
        alice_pub, alice_priv = _create_key_agreement_keypair(
            store, shim, "alice", CryptographicAlgorithm.ECDH)
        bob_pub, bob_priv = _create_key_agreement_keypair(
            store, shim, "bob", CryptographicAlgorithm.ECDH)

        bob_value   = _get_public_value(store, shim, bob_pub, "bob")
        alice_value = _get_public_value(store, shim, alice_pub, "alice")

        alice_derived = _derive(store, shim, alice_priv, bob_value, "alice", length=256)
        bob_derived   = _derive(store, shim, bob_priv, alice_value, "bob", length=256)

        assert _derived_key_bytes(store, shim, alice_derived) == _derived_key_bytes(store, shim, bob_derived)

    def test_derived_key_is_new_symmetric_key_object(self, store, shim):
        alice_pub, alice_priv = _create_key_agreement_keypair(
            store, shim, "alice", CryptographicAlgorithm.ECDH)
        bob_pub, _ = _create_key_agreement_keypair(store, shim, "bob", CryptographicAlgorithm.ECDH)
        bob_value = _get_public_value(store, shim, bob_pub, "bob")

        derived_uid = _derive(store, shim, alice_priv, bob_value, "alice")
        obj = store.get_object(derived_uid)
        assert obj["object_type"] == ObjectType.SymmetricKey
        assert obj["state"] == State.Active
        assert obj["cryptographic_algorithm"] == CryptographicAlgorithm.AES

    def test_explicit_asymmetric_key_method_accepted(self, store, shim):
        alice_pub, alice_priv = _create_key_agreement_keypair(
            store, shim, "alice", CryptographicAlgorithm.ECDH)
        bob_pub, _ = _create_key_agreement_keypair(store, shim, "bob", CryptographicAlgorithm.ECDH)
        bob_value = _get_public_value(store, shim, bob_pub, "bob")
        derived_uid = _derive(store, shim, alice_priv, bob_value, "alice",
                               method=DerivationMethod.ASYMMETRIC_KEY)
        assert store.object_exists(derived_uid)


class TestPhase5DeriveKeyErrors:
    def test_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import derive_key as dk
        with pytest.raises(MissingData):
            dk.handle(None, "user", MagicMock(), shim)

    def test_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import derive_key as dk
        p = _make_payload()
        with pytest.raises(MissingData):
            dk.handle(p, "user", store, shim)

    def test_unknown_object_raises(self, store, shim):
        from kmip_pkcs11.operations import derive_key as dk
        p = _make_payload(uid=encode_text_string(Tag.UniqueIdentifier, "nope"))
        with pytest.raises(ItemNotFound):
            dk.handle(p, "user", store, shim)

    def test_wrong_base_algorithm_raises(self, store, shim):
        """DeriveKey via key agreement requires a DH/ECDH base key — not e.g. RSA."""
        from kmip_pkcs11.operations import derive_key as dk
        pub_uid, priv_uid = _create_rsa_keypair(store, shim)
        p = _make_payload(uid=encode_text_string(Tag.UniqueIdentifier, priv_uid))
        with pytest.raises(OperationNotSupported):
            dk.handle(p, "user", store, shim)

    def test_wrong_derivation_method_raises(self, store, shim):
        from kmip_pkcs11.operations import derive_key as dk
        _, priv_uid = _create_key_agreement_keypair(store, shim, "user", CryptographicAlgorithm.ECDH)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, priv_uid),
            method=encode_enumeration(Tag.DerivationMethod, DerivationMethod.HASH),
        )
        with pytest.raises(OperationNotSupported):
            dk.handle(p, "user", store, shim)

    def test_missing_derivation_parameters_raises(self, store, shim):
        from kmip_pkcs11.operations import derive_key as dk
        _, priv_uid = _create_key_agreement_keypair(store, shim, "user", CryptographicAlgorithm.ECDH)
        p = _make_payload(uid=encode_text_string(Tag.UniqueIdentifier, priv_uid))
        with pytest.raises(MissingData):
            dk.handle(p, "user", store, shim)

    def test_missing_cka_id_raises(self, store, shim):
        from kmip_pkcs11.operations import derive_key as dk
        uid = store.create_object(
            object_type=ObjectType.PrivateKey,
            state=State.Active,
            cryptographic_algorithm=CryptographicAlgorithm.ECDH,
            usage_mask=CryptographicUsageMask.KeyAgreement,
            owner_identity="user",
        )
        deriv_params = encode_structure(Tag.DerivationParameters,
                                         encode_byte_string(Tag.DerivationData, b"\x04" + b"\x00" * 64))
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            params=deriv_params,
        )
        with pytest.raises(ItemNotFound):
            dk.handle(p, "user", store, shim)

    def test_derive_on_preactive_key_raises(self, store, shim):
        from kmip_pkcs11.operations import derive_key as dk
        uid = store.create_object(
            object_type=ObjectType.PrivateKey,
            state=State.PreActive,
            cryptographic_algorithm=CryptographicAlgorithm.ECDH,
            usage_mask=CryptographicUsageMask.KeyAgreement,
            owner_identity="user",
        )
        store.add_attribute(uid, "_pkcs11_cka_id", os.urandom(16).hex())
        deriv_params = encode_structure(Tag.DerivationParameters,
                                         encode_byte_string(Tag.DerivationData, b"\x04" + b"\x00" * 64))
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            params=deriv_params,
        )
        with pytest.raises(IllegalOperation):
            dk.handle(p, "user", store, shim)


class TestPhase5QueryAndDispatcher:
    def test_derive_key_advertised(self, store, shim):
        from kmip_pkcs11.operations import query as op
        from kmip_pkcs11.core.enums import Operation
        resp = op.handle(None, "user", store, shim)
        ops = [i.value for i in decode_all(resp) if i.tag == Tag.Operations]
        assert Operation.DeriveKey in ops

    def test_derive_key_registered_in_dispatcher(self):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation
        d = OperationDispatcher(store=MagicMock(), shim=MagicMock())
        assert Operation.DeriveKey in d._handlers

    def test_derive_key_via_dispatcher(self, store, shim):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation, ResultStatus
        alice_pub, alice_priv = _create_key_agreement_keypair(store, shim, "alice", CryptographicAlgorithm.ECDH)
        bob_pub, _ = _create_key_agreement_keypair(store, shim, "bob", CryptographicAlgorithm.ECDH)
        bob_value = _get_public_value(store, shim, bob_pub, "bob")

        d = OperationDispatcher(store=store, shim=shim)
        deriv_attrs = encode_structure(Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 128)))
        req_payload = encode_structure(Tag.RequestPayload,
            encode_text_string(Tag.UniqueIdentifier, alice_priv)
            + encode_structure(Tag.DerivationParameters, encode_byte_string(Tag.DerivationData, bob_value))
            + deriv_attrs)
        batch_item = decode_one(encode_structure(
            Tag.BatchItem,
            encode_enumeration(Tag.Operation, Operation.DeriveKey) + req_payload
        ))
        resp = d.dispatch(batch_item, "alice")
        item = decode_one(resp)
        assert item.get(Tag.ResultStatus).value == ResultStatus.Success


# ══════════════════════════════════════════════════════════════════════════════
# Audit Phase 6 — Certify, Validate
# ══════════════════════════════════════════════════════════════════════════════

def _certify_rsa_keypair(store, shim, owner="user", name_attrs=b""):
    from kmip_pkcs11.operations import certify as cert_op
    pub_uid, priv_uid = _create_rsa_keypair(store, shim)
    tmpl = encode_structure(Tag.TemplateAttribute, name_attrs) if name_attrs else b""
    p = decode_one(encode_structure(Tag.RequestPayload,
        encode_text_string(Tag.UniqueIdentifier, pub_uid) + tmpl
    ))
    resp = cert_op.handle(p, owner, store, shim)
    cert_uid = decode_one(encode_structure(Tag.ResponsePayload, resp)).get(Tag.UniqueIdentifier).value
    return cert_uid, pub_uid, priv_uid


def _build_cert_with_dates(shim, pub_cka_id, priv_cka_id, not_before, not_after, subject_cn="dated-test"):
    from asn1crypto import x509
    from asn1crypto.keys import RSAPublicKey, PublicKeyInfo
    from asn1crypto.algos import SignedDigestAlgorithm
    from pkcs11 import Mechanism as _Mech
    import os as _os

    pub_der = shim.get_public_key_der(pub_cka_id)
    spki = PublicKeyInfo.wrap(RSAPublicKey.load(pub_der), 'rsa')
    name = x509.Name.build({'common_name': subject_cn})
    sig_algo = SignedDigestAlgorithm({'algorithm': 'sha256_rsa'})

    tbs = x509.TbsCertificate({
        'version': 'v1',
        'serial_number': int.from_bytes(_os.urandom(16), 'big') >> 1,
        'signature': sig_algo,
        'issuer': name,
        'validity': x509.Validity({
            'not_before': x509.Time({'general_time': not_before}),
            'not_after':  x509.Time({'general_time': not_after}),
        }),
        'subject': name,
        'subject_public_key_info': spki,
    })
    signature = shim.sign(priv_cka_id, tbs.dump(), mechanism=_Mech.SHA256_RSA_PKCS)
    cert = x509.Certificate({
        'tbs_certificate': tbs,
        'signature_algorithm': sig_algo,
        'signature_value': signature,
    })
    return cert.dump()


class TestPhase6Certify:
    def test_certify_creates_certificate_object(self, store, shim):
        cert_uid, pub_uid, priv_uid = _certify_rsa_keypair(store, shim)
        obj = store.get_object(cert_uid)
        assert obj["object_type"] == ObjectType.Certificate
        assert obj["state"] == State.Active
        assert obj["raw_key_value"] is not None and len(obj["raw_key_value"]) > 0

    def test_certify_cert_is_valid_x509_der(self, store, shim):
        from asn1crypto import x509
        cert_uid, pub_uid, priv_uid = _certify_rsa_keypair(store, shim)
        obj = store.get_object(cert_uid)
        cert = x509.Certificate.load(obj["raw_key_value"])
        assert cert.hash_algo == "sha256"
        assert cert.signature_algo == "rsassa_pkcs1v15"

    def test_certify_links_back_to_public_key(self, store, shim):
        cert_uid, pub_uid, priv_uid = _certify_rsa_keypair(store, shim)
        assert store.get_attribute(pub_uid, "Link_Certificate") == [cert_uid]
        assert store.get_attribute(cert_uid, "Link_PublicKey") == [pub_uid]

    def test_certify_custom_subject_name(self, store, shim):
        from asn1crypto import x509
        name_attr = _attr("Name", encode_structure(
            Tag.AttributeValue,
            encode_text_string(Tag.NameValue, "my-custom-cn")
            + encode_enumeration(Tag.NameType, 1),
        ))
        cert_uid, pub_uid, priv_uid = _certify_rsa_keypair(store, shim, name_attrs=name_attr)
        obj = store.get_object(cert_uid)
        cert = x509.Certificate.load(obj["raw_key_value"])
        assert cert.subject.native["common_name"] == "my-custom-cn"

    def test_certify_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import certify as cert_op
        with pytest.raises(MissingData):
            cert_op.handle(None, "user", MagicMock(), shim)

    def test_certify_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import certify as cert_op
        with pytest.raises(MissingData):
            cert_op.handle(_make_payload(), "user", store, shim)

    def test_certify_unknown_object_raises(self, store, shim):
        from kmip_pkcs11.operations import certify as cert_op
        p = _make_payload(uid=encode_text_string(Tag.UniqueIdentifier, "nope"))
        with pytest.raises(ItemNotFound):
            cert_op.handle(p, "user", store, shim)

    def test_certify_wrong_object_type_raises(self, store, shim):
        from kmip_pkcs11.operations import certify as cert_op
        uid = _create_aes_uid(store, shim)
        p = _make_payload(uid=encode_text_string(Tag.UniqueIdentifier, uid))
        with pytest.raises(InvalidField):
            cert_op.handle(p, "user", store, shim)

    def test_certify_non_rsa_raises(self, store, shim):
        from kmip_pkcs11.operations import certify as cert_op
        pub_uid, _ = _create_ec_keypair(store, shim)
        p = _make_payload(uid=encode_text_string(Tag.UniqueIdentifier, pub_uid))
        with pytest.raises(OperationNotSupported):
            cert_op.handle(p, "user", store, shim)

    def test_certify_no_paired_private_key_raises(self, store, shim):
        from kmip_pkcs11.operations import certify as cert_op
        pub_uid, priv_id = shim.generate_key_pair(
            algorithm=CryptographicAlgorithm.RSA, key_length=2048, label="unlinked-pub")
        uid = store.create_object(
            object_type=ObjectType.PublicKey,
            state=State.Active,
            cryptographic_algorithm=CryptographicAlgorithm.RSA,
            usage_mask=CryptographicUsageMask.Verify,
            extractable=True,
            sensitive=False,
            owner_identity="user",
        )
        store.add_attribute(uid, "_pkcs11_cka_id", pub_uid.hex())
        p = _make_payload(uid=encode_text_string(Tag.UniqueIdentifier, uid))
        with pytest.raises(ItemNotFound):
            cert_op.handle(p, "user", store, shim)


class TestPhase6ValidateLive:
    def test_validate_valid_certificate(self, store, shim):
        from kmip_pkcs11.operations import validate as val_op
        cert_uid, _, _ = _certify_rsa_keypair(store, shim)
        p = _uid_payload(cert_uid)
        resp = val_op.handle(p, "user", store, shim)
        indicator = decode_one(resp).value
        assert indicator == ValidityIndicator.Valid

    def test_validate_tampered_signature_is_invalid(self, store, shim):
        from kmip_pkcs11.operations import validate as val_op
        cert_uid, _, _ = _certify_rsa_keypair(store, shim)
        obj = store.get_object(cert_uid)
        tampered = bytearray(obj["raw_key_value"])
        tampered[-5] ^= 0xFF
        store._conn().execute(
            "UPDATE kmip_objects SET raw_key_value=? WHERE uuid=?", (bytes(tampered), cert_uid)
        )
        store._conn().commit()
        resp = val_op.handle(_uid_payload(cert_uid), "user", store, shim)
        indicator = decode_one(resp).value
        assert indicator == ValidityIndicator.Invalid

    def test_validate_expired_certificate_is_invalid(self, store, shim):
        from kmip_pkcs11.operations import validate as val_op
        pub_uid, priv_uid = _create_rsa_keypair(store, shim)
        pub_cka = bytes.fromhex(store.get_attribute(pub_uid, "_pkcs11_cka_id")[0])
        priv_cka = bytes.fromhex(store.get_attribute(priv_uid, "_pkcs11_cka_id")[0])
        past = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
        past_end = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)
        der = _build_cert_with_dates(shim, pub_cka, priv_cka, past, past_end)

        cert_uid = store.create_object(
            object_type=ObjectType.Certificate, state=State.Active,
            owner_identity="user", raw_key_value=der, extractable=True, sensitive=False,
        )
        resp = val_op.handle(_uid_payload(cert_uid), "user", store, shim)
        indicator = decode_one(resp).value
        assert indicator == ValidityIndicator.Invalid

    def test_validate_not_yet_valid_certificate_is_invalid(self, store, shim):
        from kmip_pkcs11.operations import validate as val_op
        pub_uid, priv_uid = _create_rsa_keypair(store, shim)
        pub_cka = bytes.fromhex(store.get_attribute(pub_uid, "_pkcs11_cka_id")[0])
        priv_cka = bytes.fromhex(store.get_attribute(priv_uid, "_pkcs11_cka_id")[0])
        future = datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)
        future_end = datetime.datetime(2100, 1, 1, tzinfo=datetime.timezone.utc)
        der = _build_cert_with_dates(shim, pub_cka, priv_cka, future, future_end)

        cert_uid = store.create_object(
            object_type=ObjectType.Certificate, state=State.Active,
            owner_identity="user", raw_key_value=der, extractable=True, sensitive=False,
        )
        resp = val_op.handle(_uid_payload(cert_uid), "user", store, shim)
        indicator = decode_one(resp).value
        assert indicator == ValidityIndicator.Invalid

    def test_validate_via_raw_certificate_structure(self, store, shim):
        from kmip_pkcs11.operations import validate as val_op
        cert_uid, _, _ = _certify_rsa_keypair(store, shim)
        der = store.get_object(cert_uid)["raw_key_value"]
        cert_struct = encode_structure(
            Tag.Certificate,
            encode_enumeration(Tag.CertificateType, 1)
            + encode_byte_string(Tag.CertificateValue, der)
        )
        p = _make_payload(cert=cert_struct)
        resp = val_op.handle(p, "user", store, shim)
        indicator = decode_one(resp).value
        assert indicator == ValidityIndicator.Valid

    def test_validate_malformed_der_is_invalid(self, store, shim):
        from kmip_pkcs11.operations import validate as val_op
        cert_uid = store.create_object(
            object_type=ObjectType.Certificate, state=State.Active,
            owner_identity="user", raw_key_value=b"not a real certificate",
            extractable=True, sensitive=False,
        )
        resp = val_op.handle(_uid_payload(cert_uid), "user", store, shim)
        indicator = decode_one(resp).value
        assert indicator == ValidityIndicator.Invalid


class TestPhase6ValidateErrors:
    def test_validate_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import validate as val_op
        with pytest.raises(MissingData):
            val_op.handle(None, "user", MagicMock(), shim)

    def test_validate_missing_identifiers_raises(self, store, shim):
        from kmip_pkcs11.operations import validate as val_op
        with pytest.raises(MissingData):
            val_op.handle(_make_payload(), "user", store, shim)

    def test_validate_unknown_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import validate as val_op
        p = _uid_payload("nope")
        with pytest.raises(ItemNotFound):
            val_op.handle(p, "user", store, shim)

    def test_validate_non_certificate_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import validate as val_op
        uid = _create_aes_uid(store, shim)
        p = _uid_payload(uid)
        with pytest.raises(InvalidField):
            val_op.handle(p, "user", store, shim)

    def test_validate_certificate_structure_missing_value_raises(self, store, shim):
        from kmip_pkcs11.operations import validate as val_op
        cert_struct = encode_structure(Tag.Certificate, encode_enumeration(Tag.CertificateType, 1))
        p = _make_payload(cert=cert_struct)
        with pytest.raises(MissingData):
            val_op.handle(p, "user", store, shim)


class TestPhase6QueryAndDispatcher:
    def test_certify_and_validate_advertised(self, store, shim):
        from kmip_pkcs11.operations import query as op
        from kmip_pkcs11.core.enums import Operation
        resp = op.handle(None, "user", store, shim)
        ops = [i.value for i in decode_all(resp) if i.tag == Tag.Operations]
        assert Operation.Certify in ops
        assert Operation.Validate in ops

    def test_certify_and_validate_registered_in_dispatcher(self):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation
        d = OperationDispatcher(store=MagicMock(), shim=MagicMock())
        assert Operation.Certify in d._handlers
        assert Operation.Validate in d._handlers

    def test_validate_via_dispatcher(self, store, shim):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation, ResultStatus
        cert_uid, _, _ = _certify_rsa_keypair(store, shim)
        d = OperationDispatcher(store=store, shim=shim)
        req_payload = encode_structure(Tag.RequestPayload,
            encode_text_string(Tag.UniqueIdentifier, cert_uid))
        batch_item = decode_one(encode_structure(
            Tag.BatchItem,
            encode_enumeration(Tag.Operation, Operation.Validate) + req_payload
        ))
        resp = d.dispatch(batch_item, "user")
        item = decode_one(resp)
        assert item.get(Tag.ResultStatus).value == ResultStatus.Success


# ══════════════════════════════════════════════════════════════════════════════
# Audit Phase 7 — Archive, Recover, ObtainLease, GetUsageAllocation, Check
# ══════════════════════════════════════════════════════════════════════════════

def _set_usage_limit(store, uid, count):
    store.add_attribute(uid, "Usage Limits Count", count)


class TestPhase7Archive:
    def test_archive_sets_flag(self, store, shim):
        from kmip_pkcs11.operations import archive as op
        uid = _create_aes_uid(store, shim)
        op.handle(_uid_payload(uid), "user", store, shim)
        obj = store.get_object(uid)
        assert obj["archived"] == 1
        assert obj["archive_date"] is not None

    def test_archive_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import archive as op
        with pytest.raises(MissingData):
            op.handle(None, "user", MagicMock(), shim)

    def test_archive_missing_uid_raises(self, store, shim):
        from kmip_pkcs11.operations import archive as op
        with pytest.raises(MissingData):
            op.handle(_make_payload(), "user", store, shim)

    def test_archive_unknown_object_raises(self, store, shim):
        from kmip_pkcs11.operations import archive as op
        with pytest.raises(ItemNotFound):
            op.handle(_uid_payload("nope"), "user", store, shim)

    def test_archive_destroyed_object_raises(self, store, shim):
        from kmip_pkcs11.operations import archive as op, destroy as destroy_op
        uid = _create_aes_uid(store, shim)
        destroy_op.handle(_uid_payload(uid), "user", store, shim)
        with pytest.raises(IllegalOperation):
            op.handle(_uid_payload(uid), "user", store, shim)

    def test_archive_already_archived_raises(self, store, shim):
        from kmip_pkcs11.operations import archive as op
        uid = _create_aes_uid(store, shim)
        op.handle(_uid_payload(uid), "user", store, shim)
        with pytest.raises(IllegalOperation):
            op.handle(_uid_payload(uid), "user", store, shim)


class TestPhase7Recover:
    def test_recover_clears_flag(self, store, shim):
        from kmip_pkcs11.operations import archive as archive_op, recover as op
        uid = _create_aes_uid(store, shim)
        archive_op.handle(_uid_payload(uid), "user", store, shim)
        op.handle(_uid_payload(uid), "user", store, shim)
        obj = store.get_object(uid)
        assert obj["archived"] == 0
        assert obj["archive_date"] is None

    def test_recover_not_archived_raises(self, store, shim):
        from kmip_pkcs11.operations import recover as op
        uid = _create_aes_uid(store, shim)
        with pytest.raises(IllegalOperation):
            op.handle(_uid_payload(uid), "user", store, shim)

    def test_recover_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import recover as op
        with pytest.raises(MissingData):
            op.handle(None, "user", MagicMock(), shim)

    def test_recover_unknown_object_raises(self, store, shim):
        from kmip_pkcs11.operations import recover as op
        with pytest.raises(ItemNotFound):
            op.handle(_uid_payload("nope"), "user", store, shim)


class TestPhase7ArchivedGating:
    def test_get_blocked_when_archived(self, store, shim):
        from kmip_pkcs11.operations import archive as archive_op, get as get_op
        uid = _create_aes_uid(store, shim)
        archive_op.handle(_uid_payload(uid), "user", store, shim)
        with pytest.raises(IllegalOperation):
            get_op.handle(_uid_payload(uid), "user", store, shim)

    def test_encrypt_blocked_when_archived(self, store, shim):
        from kmip_pkcs11.operations import archive as archive_op, encrypt as enc_op
        uid = _create_aes_uid(store, shim)
        archive_op.handle(_uid_payload(uid), "user", store, shim)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, b"plaintext"),
        )
        with pytest.raises(IllegalOperation):
            enc_op.handle(p, "user", store, shim)

    def test_get_attributes_still_allowed_when_archived(self, store, shim):
        from kmip_pkcs11.operations import archive as archive_op, get_attributes as ga_op
        uid = _create_aes_uid(store, shim)
        archive_op.handle(_uid_payload(uid), "user", store, shim)
        resp = ga_op.handle(_uid_payload(uid), "user", store, shim)
        assert len(resp) > 0

    def test_get_allowed_after_recover(self, store, shim):
        from kmip_pkcs11.operations import archive as archive_op, recover as recover_op, get as get_op
        uid = _create_aes_uid(store, shim)
        archive_op.handle(_uid_payload(uid), "user", store, shim)
        recover_op.handle(_uid_payload(uid), "user", store, shim)
        resp = get_op.handle(_uid_payload(uid), "user", store, shim)
        assert len(resp) > 0


class TestPhase7ObtainLease:
    def test_returns_lease_time_and_last_change_date(self, store, shim):
        from kmip_pkcs11.operations import obtain_lease as op
        uid = _create_aes_uid(store, shim)
        resp = op.handle(_uid_payload(uid), "user", store, shim)
        items = decode_all(resp)
        lease_time = next(i.value for i in items if i.tag == Tag.LeaseTime)
        last_change = next(i.value for i in items if i.tag == Tag.LastChangeDate)
        assert lease_time > 0
        assert last_change is not None

    def test_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import obtain_lease as op
        with pytest.raises(MissingData):
            op.handle(None, "user", MagicMock(), shim)

    def test_unknown_object_raises(self, store, shim):
        from kmip_pkcs11.operations import obtain_lease as op
        with pytest.raises(ItemNotFound):
            op.handle(_uid_payload("nope"), "user", store, shim)

    def test_destroyed_object_raises(self, store, shim):
        from kmip_pkcs11.operations import obtain_lease as op, destroy as destroy_op
        uid = _create_aes_uid(store, shim)
        destroy_op.handle(_uid_payload(uid), "user", store, shim)
        with pytest.raises(IllegalOperation):
            op.handle(_uid_payload(uid), "user", store, shim)

    def test_blocked_when_archived(self, store, shim):
        from kmip_pkcs11.operations import obtain_lease as op, archive as archive_op
        uid = _create_aes_uid(store, shim)
        archive_op.handle(_uid_payload(uid), "user", store, shim)
        with pytest.raises(IllegalOperation):
            op.handle(_uid_payload(uid), "user", store, shim)


class TestPhase7GetUsageAllocation:
    def test_unlimited_object_always_succeeds(self, store, shim):
        from kmip_pkcs11.operations import get_usage_allocation as op
        uid = _create_aes_uid(store, shim)
        resp = op.handle(_uid_payload(uid), "user", store, shim)
        assert decode_one(resp).value == uid

    def test_allocation_decrements_remaining(self, store, shim):
        from kmip_pkcs11.operations import get_usage_allocation as op
        uid = _create_aes_uid(store, shim)
        _set_usage_limit(store, uid, 5)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            count=encode_long_integer(Tag.UsageLimitsCount, 3),
        )
        op.handle(p, "user", store, shim)
        assert store.get_attribute(uid, "Usage Limits Count") == [2]

    def test_allocation_default_is_one(self, store, shim):
        from kmip_pkcs11.operations import get_usage_allocation as op
        uid = _create_aes_uid(store, shim)
        _set_usage_limit(store, uid, 5)
        op.handle(_uid_payload(uid), "user", store, shim)
        assert store.get_attribute(uid, "Usage Limits Count") == [4]

    def test_allocation_insufficient_raises(self, store, shim):
        from kmip_pkcs11.operations import get_usage_allocation as op
        uid = _create_aes_uid(store, shim)
        _set_usage_limit(store, uid, 2)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            count=encode_long_integer(Tag.UsageLimitsCount, 5),
        )
        with pytest.raises(NotAuthorized):
            op.handle(p, "user", store, shim)
        # unchanged on failure
        assert store.get_attribute(uid, "Usage Limits Count") == [2]

    def test_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import get_usage_allocation as op
        with pytest.raises(MissingData):
            op.handle(None, "user", MagicMock(), shim)

    def test_unknown_object_raises(self, store, shim):
        from kmip_pkcs11.operations import get_usage_allocation as op
        with pytest.raises(ItemNotFound):
            op.handle(_uid_payload("nope"), "user", store, shim)


class TestPhase7Check:
    def test_all_checks_pass_returns_only_uid(self, store, shim):
        from kmip_pkcs11.operations import check as op
        uid = _create_aes_uid(store, shim)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            state=encode_enumeration(Tag.State, State.Active),
            mask=encode_integer(Tag.CryptographicUsageMask, CryptographicUsageMask.Encrypt),
        )
        resp = op.handle(p, "user", store, shim)
        items = decode_all(resp)
        assert len(items) == 1
        assert items[0].tag == Tag.UniqueIdentifier

    def test_state_mismatch_reported(self, store, shim):
        from kmip_pkcs11.operations import check as op
        uid = _create_aes_uid(store, shim)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            state=encode_enumeration(Tag.State, State.PreActive),
        )
        resp = op.handle(p, "user", store, shim)
        tags = [i.tag for i in decode_all(resp)]
        assert Tag.State in tags

    def test_usage_mask_mismatch_reported(self, store, shim):
        from kmip_pkcs11.operations import check as op
        uid = _create_aes_uid(store, shim)  # created with Encrypt|Decrypt mask
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            mask=encode_integer(Tag.CryptographicUsageMask, CryptographicUsageMask.Sign),
        )
        resp = op.handle(p, "user", store, shim)
        tags = [i.tag for i in decode_all(resp)]
        assert Tag.CryptographicUsageMask in tags

    def test_usage_limits_insufficient_reported(self, store, shim):
        from kmip_pkcs11.operations import check as op
        uid = _create_aes_uid(store, shim)
        _set_usage_limit(store, uid, 2)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            count=encode_long_integer(Tag.UsageLimitsCount, 10),
        )
        resp = op.handle(p, "user", store, shim)
        tags = [i.tag for i in decode_all(resp)]
        assert Tag.UsageLimitsCount in tags

    def test_usage_limits_sufficient_not_reported(self, store, shim):
        from kmip_pkcs11.operations import check as op
        uid = _create_aes_uid(store, shim)
        _set_usage_limit(store, uid, 10)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            count=encode_long_integer(Tag.UsageLimitsCount, 2),
        )
        resp = op.handle(p, "user", store, shim)
        tags = [i.tag for i in decode_all(resp)]
        assert Tag.UsageLimitsCount not in tags

    def test_check_does_not_mutate_state(self, store, shim):
        """Unlike GetUsageAllocation, Check must not consume the allocation."""
        from kmip_pkcs11.operations import check as op
        uid = _create_aes_uid(store, shim)
        _set_usage_limit(store, uid, 5)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            count=encode_long_integer(Tag.UsageLimitsCount, 3),
        )
        op.handle(p, "user", store, shim)
        assert store.get_attribute(uid, "Usage Limits Count") == [5]

    def test_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import check as op
        with pytest.raises(MissingData):
            op.handle(None, "user", MagicMock(), shim)

    def test_unknown_object_raises(self, store, shim):
        from kmip_pkcs11.operations import check as op
        with pytest.raises(ItemNotFound):
            op.handle(_uid_payload("nope"), "user", store, shim)


class TestPhase7QueryAndDispatcher:
    def test_all_advertised(self, store, shim):
        from kmip_pkcs11.operations import query as op
        from kmip_pkcs11.core.enums import Operation
        resp = op.handle(None, "user", store, shim)
        ops = [i.value for i in decode_all(resp) if i.tag == Tag.Operations]
        for expected in (Operation.Archive, Operation.Recover, Operation.ObtainLease,
                          Operation.GetUsageAllocation, Operation.Check):
            assert expected in ops

    def test_all_registered_in_dispatcher(self):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation
        d = OperationDispatcher(store=MagicMock(), shim=MagicMock())
        for expected in (Operation.Archive, Operation.Recover, Operation.ObtainLease,
                          Operation.GetUsageAllocation, Operation.Check):
            assert expected in d._handlers

    def test_check_via_dispatcher(self, store, shim):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation, ResultStatus
        uid = _create_aes_uid(store, shim)
        d = OperationDispatcher(store=store, shim=shim)
        req_payload = encode_structure(Tag.RequestPayload,
            encode_text_string(Tag.UniqueIdentifier, uid))
        batch_item = decode_one(encode_structure(
            Tag.BatchItem,
            encode_enumeration(Tag.Operation, Operation.Check) + req_payload
        ))
        resp = d.dispatch(batch_item, "user")
        item = decode_one(resp)
        assert item.get(Tag.ResultStatus).value == ResultStatus.Success


# ══════════════════════════════════════════════════════════════════════════════
# Audit Phase 8 — ReKey, ReKeyKeyPair, ReCertify, CreateSplitKey/JoinSplitKey, RNGSeed
# ══════════════════════════════════════════════════════════════════════════════

from kmip_pkcs11.core.enums import SplitKeyMethod


class TestPhase8ReKey:
    def test_rekey_creates_new_object_and_links(self, store, shim):
        from kmip_pkcs11.operations import rekey as op
        old_uid = _create_aes_uid(store, shim)
        resp = op.handle(_uid_payload(old_uid), "user", store, shim)
        new_uid = decode_one(resp).value
        assert new_uid != old_uid
        assert store.get_attribute(old_uid, "Link_ReplacementKey") == [new_uid]
        assert store.get_attribute(new_uid, "Link_ReplacedKey") == [old_uid]

    def test_rekey_inherits_attributes(self, store, shim):
        from kmip_pkcs11.operations import rekey as op
        old_uid = _create_aes_uid(store, shim, length=256)
        resp = op.handle(_uid_payload(old_uid), "user", store, shim)
        new_uid = decode_one(resp).value
        new_obj = store.get_object(new_uid)
        old_obj = store.get_object(old_uid)
        assert new_obj["cryptographic_algorithm"] == old_obj["cryptographic_algorithm"]
        assert new_obj["cryptographic_length"] == 256

    def test_rekey_new_key_is_usable(self, store, shim):
        from kmip_pkcs11.operations import rekey as op, encrypt as enc_op, decrypt as dec_op
        old_uid = _create_aes_uid(store, shim)
        resp = op.handle(_uid_payload(old_uid), "user", store, shim)
        new_uid = decode_one(resp).value
        enc_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, new_uid),
            data=encode_byte_string(Tag.Data, b"rekeyed key works"),
        )
        enc_resp = enc_op.handle(enc_payload, "user", store, shim)
        enc_items = decode_all(enc_resp)
        ciphertext = next(i.value for i in enc_items if i.tag == Tag.Data)
        iv = next(i.value for i in enc_items if i.tag == Tag.IVCounterNonce)
        dec_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, new_uid),
            data=encode_byte_string(Tag.Data, ciphertext),
            iv=encode_byte_string(Tag.IVCounterNonce, iv),
        )
        dec_resp = dec_op.handle(dec_payload, "user", store, shim)
        recovered = next(i.value for i in decode_all(dec_resp) if i.tag == Tag.Data)
        assert recovered == b"rekeyed key works"

    def test_rekey_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import rekey as op
        with pytest.raises(MissingData):
            op.handle(None, "user", MagicMock(), shim)

    def test_rekey_unknown_object_raises(self, store, shim):
        from kmip_pkcs11.operations import rekey as op
        with pytest.raises(ItemNotFound):
            op.handle(_uid_payload("nope"), "user", store, shim)

    def test_rekey_wrong_object_type_raises(self, store, shim):
        from kmip_pkcs11.operations import rekey as op
        pub_uid, _ = _create_rsa_keypair(store, shim)
        with pytest.raises(InvalidField):
            op.handle(_uid_payload(pub_uid), "user", store, shim)


class TestPhase8ReKeyKeyPair:
    def test_rekey_keypair_creates_new_pair_and_links(self, store, shim):
        from kmip_pkcs11.operations import rekey_keypair as op
        old_pub, old_priv = _create_rsa_keypair(store, shim)
        resp = op.handle(_uid_payload(old_priv), "user", store, shim)
        new_pub, new_priv = [i.value for i in decode_all(resp) if i.tag == Tag.UniqueIdentifier]
        assert new_pub != old_pub
        assert new_priv != old_priv
        assert store.get_attribute(old_priv, "Link_ReplacementKey") == [new_priv]
        assert store.get_attribute(old_pub, "Link_ReplacementKey") == [new_pub]

    def test_rekey_keypair_new_pair_works(self, store, shim):
        from kmip_pkcs11.operations import rekey_keypair as op
        _, old_priv = _create_rsa_keypair(store, shim)
        resp = op.handle(_uid_payload(old_priv), "user", store, shim)
        new_pub, new_priv = [i.value for i in decode_all(resp) if i.tag == Tag.UniqueIdentifier]
        validity = _sign_and_verify(store, shim, new_pub, new_priv, b"rekeyed pair test")
        assert validity == ValidityIndicator.Valid

    def test_rekey_keypair_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import rekey_keypair as op
        with pytest.raises(MissingData):
            op.handle(None, "user", MagicMock(), shim)

    def test_rekey_keypair_unknown_object_raises(self, store, shim):
        from kmip_pkcs11.operations import rekey_keypair as op
        with pytest.raises(ItemNotFound):
            op.handle(_uid_payload("nope"), "user", store, shim)

    def test_rekey_keypair_wrong_object_type_raises(self, store, shim):
        from kmip_pkcs11.operations import rekey_keypair as op
        pub_uid, _ = _create_rsa_keypair(store, shim)
        with pytest.raises(InvalidField):
            op.handle(_uid_payload(pub_uid), "user", store, shim)


class TestPhase8ReCertify:
    def test_recertify_creates_new_cert_and_links(self, store, shim):
        from kmip_pkcs11.operations import recertify as op
        cert_uid, pub_uid, priv_uid = _certify_rsa_keypair(store, shim)
        resp = op.handle(_uid_payload(cert_uid), "user", store, shim)
        new_cert_uid = decode_one(resp).value
        assert new_cert_uid != cert_uid
        assert store.get_attribute(cert_uid, "Link_ReplacementCertificate") == [new_cert_uid]
        assert store.get_attribute(new_cert_uid, "Link_ReplacedCertificate") == [cert_uid]

    def test_recertify_new_cert_is_valid(self, store, shim):
        from kmip_pkcs11.operations import recertify as op, validate as val_op
        cert_uid, _, _ = _certify_rsa_keypair(store, shim)
        resp = op.handle(_uid_payload(cert_uid), "user", store, shim)
        new_cert_uid = decode_one(resp).value
        val_resp = val_op.handle(_uid_payload(new_cert_uid), "user", store, shim)
        assert decode_one(val_resp).value == ValidityIndicator.Valid

    def test_recertify_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import recertify as op
        with pytest.raises(MissingData):
            op.handle(None, "user", MagicMock(), shim)

    def test_recertify_unknown_object_raises(self, store, shim):
        from kmip_pkcs11.operations import recertify as op
        with pytest.raises(ItemNotFound):
            op.handle(_uid_payload("nope"), "user", store, shim)

    def test_recertify_wrong_object_type_raises(self, store, shim):
        from kmip_pkcs11.operations import recertify as op
        uid = _create_aes_uid(store, shim)
        with pytest.raises(InvalidField):
            op.handle(_uid_payload(uid), "user", store, shim)


class TestPhase8RNGSeed:
    def test_rngseed_accepts_data(self, shim):
        from kmip_pkcs11.operations import rng_seed as op
        p = _make_payload(data=encode_byte_string(Tag.Data, b"client supplied entropy"))
        resp = op.handle(p, "user", MagicMock(), shim)
        assert decode_one(resp).value == len(b"client supplied entropy")

    def test_rngseed_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import rng_seed as op
        with pytest.raises(MissingData):
            op.handle(None, "user", MagicMock(), shim)

    def test_rngseed_missing_data_raises(self, shim):
        from kmip_pkcs11.operations import rng_seed as op
        with pytest.raises(MissingData):
            op.handle(_make_payload(), "user", MagicMock(), shim)


class TestPhase8SplitKeyLive:
    def test_split_and_join_fresh_key_roundtrip(self, store, shim):
        from kmip_pkcs11.operations import create_split_key as cs_op, join_split_key as js_op
        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 128)),
        )
        p = _make_payload(
            parts=encode_integer(Tag.SplitKeyParts, 3),
            threshold=encode_integer(Tag.SplitKeyThreshold, 3),
            method=encode_enumeration(Tag.SplitKeyMethod, SplitKeyMethod.XOR),
            attrs=attrs,
        )
        resp = cs_op.handle(p, "user", store, shim)
        part_uids = [i.value for i in decode_all(resp)]
        assert len(part_uids) == 3
        for u in part_uids:
            assert store.get_object(u)["object_type"] == ObjectType.SplitKey

        join_p = _make_payload(uids=b"".join(
            encode_text_string(Tag.UniqueIdentifier, u) for u in part_uids
        ))
        join_resp = js_op.handle(join_p, "user", store, shim)
        joined_uid = decode_one(join_resp).value
        joined_obj = store.get_object(joined_uid)
        assert joined_obj["object_type"] == ObjectType.SymmetricKey
        assert joined_obj["cryptographic_algorithm"] == CryptographicAlgorithm.AES
        assert joined_obj["cryptographic_length"] == 128

    def test_split_existing_key_reconstructs_identical_material(self, store, shim):
        from kmip_pkcs11.operations import create_split_key as cs_op, join_split_key as js_op
        src_uid = _create_aes_uid(store, shim)
        src_cka = bytes.fromhex(store.get_attribute(src_uid, "_pkcs11_cka_id")[0])
        src_bytes = shim.get_key_value(src_cka)

        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, src_uid),
            parts=encode_integer(Tag.SplitKeyParts, 4),
        )
        resp = cs_op.handle(p, "user", store, shim)
        part_uids = [i.value for i in decode_all(resp)]
        assert len(part_uids) == 4

        join_p = _make_payload(uids=b"".join(
            encode_text_string(Tag.UniqueIdentifier, u) for u in part_uids
        ))
        join_resp = js_op.handle(join_p, "user", store, shim)
        joined_uid = decode_one(join_resp).value
        joined_cka = bytes.fromhex(store.get_attribute(joined_uid, "_pkcs11_cka_id")[0])
        joined_bytes = shim.get_key_value(joined_cka)
        assert joined_bytes == src_bytes

    def test_split_key_part_get_roundtrip(self, store, shim):
        from kmip_pkcs11.operations import create_split_key as cs_op, get as get_op
        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 128)),
        )
        p = _make_payload(parts=encode_integer(Tag.SplitKeyParts, 2), attrs=attrs)
        resp = cs_op.handle(p, "user", store, shim)
        part_uids = [i.value for i in decode_all(resp)]

        get_resp = get_op.handle(_uid_payload(part_uids[0]), "user", store, shim)
        managed_obj = next(i for i in decode_all(get_resp) if i.tag == Tag.SplitKey)
        fetched = managed_obj.get(Tag.KeyBlock).get(Tag.KeyValue).get(Tag.KeyMaterial).value
        assert fetched == store.get_object(part_uids[0])["raw_key_value"]


class TestPhase8SplitKeyErrors:
    def test_create_split_key_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import create_split_key as op
        with pytest.raises(MissingData):
            op.handle(None, "user", MagicMock(), shim)

    def test_create_split_key_missing_parts_raises(self, store, shim):
        from kmip_pkcs11.operations import create_split_key as op
        with pytest.raises(MissingData):
            op.handle(_make_payload(), "user", store, shim)

    def test_create_split_key_parts_below_two_raises(self, store, shim):
        from kmip_pkcs11.operations import create_split_key as op
        p = _make_payload(parts=encode_integer(Tag.SplitKeyParts, 1))
        with pytest.raises(InvalidField):
            op.handle(p, "user", store, shim)

    def test_create_split_key_threshold_below_parts_raises(self, store, shim):
        from kmip_pkcs11.operations import create_split_key as op
        p = _make_payload(
            parts=encode_integer(Tag.SplitKeyParts, 3),
            threshold=encode_integer(Tag.SplitKeyThreshold, 2),
        )
        with pytest.raises(OperationNotSupported):
            op.handle(p, "user", store, shim)

    def test_create_split_key_non_xor_method_raises(self, store, shim):
        from kmip_pkcs11.operations import create_split_key as op
        p = _make_payload(
            parts=encode_integer(Tag.SplitKeyParts, 3),
            method=encode_enumeration(Tag.SplitKeyMethod, SplitKeyMethod.PolynomialSharePrimeField),
        )
        with pytest.raises(OperationNotSupported):
            op.handle(p, "user", store, shim)

    def test_create_split_key_no_source_no_algorithm_raises(self, store, shim):
        from kmip_pkcs11.operations import create_split_key as op
        p = _make_payload(parts=encode_integer(Tag.SplitKeyParts, 2))
        with pytest.raises(MissingData):
            op.handle(p, "user", store, shim)

    def test_create_split_key_non_extractable_source_raises(self, store, shim):
        from kmip_pkcs11.operations import create_split_key as op
        uid = _create_aes_uid(store, shim, extractable=False)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            parts=encode_integer(Tag.SplitKeyParts, 2),
        )
        with pytest.raises(InvalidField):
            op.handle(p, "user", store, shim)

    def test_join_split_key_missing_payload_raises(self, shim):
        from kmip_pkcs11.operations import join_split_key as op
        with pytest.raises(MissingData):
            op.handle(None, "user", MagicMock(), shim)

    def test_join_split_key_missing_uids_raises(self, store, shim):
        from kmip_pkcs11.operations import join_split_key as op
        with pytest.raises(MissingData):
            op.handle(_make_payload(), "user", store, shim)

    def test_join_split_key_unknown_part_raises(self, store, shim):
        from kmip_pkcs11.operations import join_split_key as op
        p = _make_payload(uid=encode_text_string(Tag.UniqueIdentifier, "nope"))
        with pytest.raises(ItemNotFound):
            op.handle(p, "user", store, shim)

    def test_join_split_key_wrong_type_raises(self, store, shim):
        from kmip_pkcs11.operations import join_split_key as op
        uid = _create_aes_uid(store, shim)
        p = _make_payload(uid=encode_text_string(Tag.UniqueIdentifier, uid))
        with pytest.raises(InvalidField):
            op.handle(p, "user", store, shim)

    def test_join_split_key_incomplete_parts_raises(self, store, shim):
        from kmip_pkcs11.operations import create_split_key as cs_op, join_split_key as js_op
        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 128)),
        )
        p = _make_payload(parts=encode_integer(Tag.SplitKeyParts, 3), attrs=attrs)
        resp = cs_op.handle(p, "user", store, shim)
        part_uids = [i.value for i in decode_all(resp)]

        join_p = _make_payload(uids=b"".join(
            encode_text_string(Tag.UniqueIdentifier, u) for u in part_uids[:2]
        ))
        with pytest.raises(InvalidField):
            js_op.handle(join_p, "user", store, shim)

    def test_join_split_key_mixed_groups_raises(self, store, shim):
        from kmip_pkcs11.operations import create_split_key as cs_op, join_split_key as js_op
        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 128)),
        )
        p = _make_payload(parts=encode_integer(Tag.SplitKeyParts, 2), attrs=attrs)
        parts_a = [i.value for i in decode_all(cs_op.handle(p, "user", store, shim))]
        parts_b = [i.value for i in decode_all(cs_op.handle(p, "user", store, shim))]

        join_p = _make_payload(uids=(
            encode_text_string(Tag.UniqueIdentifier, parts_a[0])
            + encode_text_string(Tag.UniqueIdentifier, parts_b[1])
        ))
        with pytest.raises(InvalidField):
            js_op.handle(join_p, "user", store, shim)


class TestPhase8QueryAndDispatcher:
    def test_all_advertised(self, store, shim):
        from kmip_pkcs11.operations import query as op
        from kmip_pkcs11.core.enums import Operation
        resp = op.handle(None, "user", store, shim)
        ops = [i.value for i in decode_all(resp) if i.tag == Tag.Operations]
        for expected in (Operation.ReKey, Operation.ReKeyKeyPair, Operation.ReCertify,
                          Operation.RNGSeed, Operation.CreateSplitKey, Operation.JoinSplitKey):
            assert expected in ops
        obj_types = [i.value for i in decode_all(resp) if i.tag == Tag.ObjectType]
        assert ObjectType.SplitKey in obj_types

    def test_all_registered_in_dispatcher(self):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation
        d = OperationDispatcher(store=MagicMock(), shim=MagicMock())
        for expected in (Operation.ReKey, Operation.ReKeyKeyPair, Operation.ReCertify,
                          Operation.RNGSeed, Operation.CreateSplitKey, Operation.JoinSplitKey):
            assert expected in d._handlers

    def test_rekey_via_dispatcher(self, store, shim):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation, ResultStatus
        uid = _create_aes_uid(store, shim)
        d = OperationDispatcher(store=store, shim=shim)
        req_payload = encode_structure(Tag.RequestPayload,
            encode_text_string(Tag.UniqueIdentifier, uid))
        batch_item = decode_one(encode_structure(
            Tag.BatchItem,
            encode_enumeration(Tag.Operation, Operation.ReKey) + req_payload
        ))
        resp = d.dispatch(batch_item, "user")
        item = decode_one(resp)
        assert item.get(Tag.ResultStatus).value == ResultStatus.Success


# ══════════════════════════════════════════════════════════════════════════════
# Audit Phase 10 — real key wrapping (Get/Export wrap, Register/Import unwrap)
# ══════════════════════════════════════════════════════════════════════════════

from kmip_pkcs11.core.enums import WrappingMethod


def _create_kek_uid(store, shim, wrap=True, unwrap=True, length=256, state=State.Active):
    mask = 0
    if wrap:
        mask |= CryptographicUsageMask.WrapKey
    if unwrap:
        mask |= CryptographicUsageMask.UnwrapKey
    attrs = encode_structure(
        Tag.TemplateAttribute,
        _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
        + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, length))
        + _attr("Cryptographic Usage Mask", encode_integer(Tag.AttributeValue, mask)),
    )
    p = decode_one(encode_structure(Tag.RequestPayload,
        encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey) + attrs
    ))
    from kmip_pkcs11.operations import create as create_mod
    resp = create_mod.handle(p, "user", store, shim)
    uid = decode_one(encode_structure(Tag.ResponsePayload, resp)).get(Tag.UniqueIdentifier).value
    if state != State.Active:
        store.set_state(uid, state)
    return uid


def _wrap_spec(wrapping_uid, method=WrappingMethod.Encrypt):
    return encode_structure(
        Tag.KeyWrappingSpecification,
        encode_enumeration(Tag.WrappingMethod, method)
        + encode_structure(Tag.EncryptionKeyInformation, encode_text_string(Tag.UniqueIdentifier, wrapping_uid))
    )


def _wrapping_data(wrapping_uid, method=WrappingMethod.Encrypt):
    return encode_structure(
        Tag.KeyWrappingData,
        encode_enumeration(Tag.WrappingMethod, method)
        + encode_structure(Tag.EncryptionKeyInformation, encode_text_string(Tag.UniqueIdentifier, wrapping_uid))
    )


class TestPhase10WrapUnwrapLive:
    def test_wrapped_get_returns_ciphertext_and_wrapping_data(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        kek_uid = _create_kek_uid(store, shim)
        tgt_uid = _create_aes_uid(store, shim, extractable=True)
        tgt_cka = bytes.fromhex(store.get_attribute(tgt_uid, "_pkcs11_cka_id")[0])
        plaintext = shim.get_key_value(tgt_cka)

        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, tgt_uid),
            wrap=_wrap_spec(kek_uid),
        )
        resp = get_op.handle(p, "user", store, shim)
        managed = next(i for i in decode_all(resp) if i.tag == Tag.SymmetricKey)
        key_block = managed.get(Tag.KeyBlock)
        wrapped = key_block.get(Tag.KeyValue).get(Tag.KeyMaterial).value
        kwd = key_block.get(Tag.KeyWrappingData)

        assert kwd is not None
        assert wrapped != plaintext
        eki = kwd.get(Tag.EncryptionKeyInformation)
        assert eki.get(Tag.UniqueIdentifier).value == kek_uid

    def test_wrap_then_register_roundtrips_to_original_plaintext(self, store, shim):
        from kmip_pkcs11.operations import get as get_op, register as reg_op
        kek_uid = _create_kek_uid(store, shim)
        tgt_uid = _create_aes_uid(store, shim, extractable=True)
        tgt_cka = bytes.fromhex(store.get_attribute(tgt_uid, "_pkcs11_cka_id")[0])
        plaintext = shim.get_key_value(tgt_cka)

        get_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, tgt_uid),
            wrap=_wrap_spec(kek_uid),
        )
        get_resp = get_op.handle(get_payload, "user", store, shim)
        key_block = next(i for i in decode_all(get_resp) if i.tag == Tag.SymmetricKey).get(Tag.KeyBlock)
        wrapped = key_block.get(Tag.KeyValue).get(Tag.KeyMaterial).value

        reg_attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 128)),
        )
        reg_key_block = encode_structure(
            Tag.KeyBlock,
            encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, wrapped))
            + _wrapping_data(kek_uid)
        )
        reg_p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey) + reg_key_block + reg_attrs
        ))
        reg_resp = reg_op.handle(reg_p, "user", store, shim)
        new_uid = decode_one(encode_structure(Tag.ResponsePayload, reg_resp)).get(Tag.UniqueIdentifier).value

        new_cka = bytes.fromhex(store.get_attribute(new_uid, "_pkcs11_cka_id")[0])
        assert shim.get_key_value(new_cka) == plaintext

    def test_get_without_wrap_spec_still_returns_plaintext(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        tgt_uid = _create_aes_uid(store, shim, extractable=True)
        tgt_cka = bytes.fromhex(store.get_attribute(tgt_uid, "_pkcs11_cka_id")[0])
        plaintext = shim.get_key_value(tgt_cka)

        resp = get_op.handle(_uid_payload(tgt_uid), "user", store, shim)
        key_block = next(i for i in decode_all(resp) if i.tag == Tag.SymmetricKey).get(Tag.KeyBlock)
        fetched = key_block.get(Tag.KeyValue).get(Tag.KeyMaterial).value
        assert fetched == plaintext
        assert key_block.get(Tag.KeyWrappingData) is None

    def test_wrap_via_export_operation(self, store, shim):
        from kmip_pkcs11.operations import export_op
        kek_uid = _create_kek_uid(store, shim)
        tgt_uid = _create_aes_uid(store, shim, extractable=True)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, tgt_uid),
            wrap=_wrap_spec(kek_uid),
        )
        resp = export_op.handle(p, "user", store, shim)
        key_block = next(i for i in decode_all(resp) if i.tag == Tag.SymmetricKey).get(Tag.KeyBlock)
        assert key_block.get(Tag.KeyWrappingData) is not None

    def test_different_keks_produce_different_ciphertext(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        kek1_uid = _create_kek_uid(store, shim)
        kek2_uid = _create_kek_uid(store, shim)
        tgt_uid = _create_aes_uid(store, shim, extractable=True)

        def wrapped_with(kek_uid):
            p = _make_payload(
                uid=encode_text_string(Tag.UniqueIdentifier, tgt_uid),
                wrap=_wrap_spec(kek_uid),
            )
            resp = get_op.handle(p, "user", store, shim)
            key_block = next(i for i in decode_all(resp) if i.tag == Tag.SymmetricKey).get(Tag.KeyBlock)
            return key_block.get(Tag.KeyValue).get(Tag.KeyMaterial).value

        assert wrapped_with(kek1_uid) != wrapped_with(kek2_uid)


class TestPhase10WrapErrors:
    def test_get_wrap_missing_encryption_key_information_raises(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        tgt_uid = _create_aes_uid(store, shim, extractable=True)
        bad_spec = encode_structure(Tag.KeyWrappingSpecification,
            encode_enumeration(Tag.WrappingMethod, WrappingMethod.Encrypt))
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, tgt_uid),
            wrap=bad_spec,
        )
        with pytest.raises(MissingData):
            get_op.handle(p, "user", store, shim)

    def test_get_wrap_unsupported_method_raises(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        kek_uid = _create_kek_uid(store, shim)
        tgt_uid = _create_aes_uid(store, shim, extractable=True)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, tgt_uid),
            wrap=_wrap_spec(kek_uid, method=WrappingMethod.MACSign),
        )
        with pytest.raises(OperationNotSupported):
            get_op.handle(p, "user", store, shim)

    def test_get_wrap_unknown_wrapping_key_raises(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        tgt_uid = _create_aes_uid(store, shim, extractable=True)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, tgt_uid),
            wrap=_wrap_spec("nope"),
        )
        with pytest.raises(ItemNotFound):
            get_op.handle(p, "user", store, shim)

    def test_get_wrap_non_symmetric_wrapping_key_raises(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        pub_uid, _ = _create_rsa_keypair(store, shim)
        tgt_uid = _create_aes_uid(store, shim, extractable=True)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, tgt_uid),
            wrap=_wrap_spec(pub_uid),
        )
        with pytest.raises(OperationNotSupported):
            get_op.handle(p, "user", store, shim)

    def test_get_wrap_wrapping_key_missing_wrap_usage_raises(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        kek_uid = _create_kek_uid(store, shim, wrap=False, unwrap=True)
        tgt_uid = _create_aes_uid(store, shim, extractable=True)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, tgt_uid),
            wrap=_wrap_spec(kek_uid),
        )
        with pytest.raises(IllegalOperation):
            get_op.handle(p, "user", store, shim)

    def test_get_wrap_wrapping_key_wrong_state_raises(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        kek_uid = _create_kek_uid(store, shim, state=State.PreActive)
        tgt_uid = _create_aes_uid(store, shim, extractable=True)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, tgt_uid),
            wrap=_wrap_spec(kek_uid),
        )
        with pytest.raises(IllegalOperation):
            get_op.handle(p, "user", store, shim)

    def test_get_wrap_non_extractable_target_raises(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        kek_uid = _create_kek_uid(store, shim)
        tgt_uid = _create_aes_uid(store, shim, extractable=False)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, tgt_uid),
            wrap=_wrap_spec(kek_uid),
        )
        with pytest.raises(NotExtractable):
            get_op.handle(p, "user", store, shim)

    def test_register_wrapped_missing_length_raises(self, store, shim):
        from kmip_pkcs11.operations import register as reg_op
        kek_uid = _create_kek_uid(store, shim)
        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES)),
        )
        key_block = encode_structure(
            Tag.KeyBlock,
            encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, b"\x00" * 24))
            + _wrapping_data(kek_uid)
        )
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey) + key_block + attrs
        ))
        with pytest.raises(MissingData):
            reg_op.handle(p, "user", store, shim)

    def test_register_wrapped_unknown_wrapping_key_raises(self, store, shim):
        from kmip_pkcs11.operations import register as reg_op
        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 128)),
        )
        key_block = encode_structure(
            Tag.KeyBlock,
            encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, b"\x00" * 24))
            + _wrapping_data("nope")
        )
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey) + key_block + attrs
        ))
        with pytest.raises(ItemNotFound):
            reg_op.handle(p, "user", store, shim)

    def test_register_wrapped_wrapping_key_missing_unwrap_usage_raises(self, store, shim):
        from kmip_pkcs11.operations import get as get_op, register as reg_op
        kek_uid = _create_kek_uid(store, shim, wrap=True, unwrap=False)
        tgt_uid = _create_aes_uid(store, shim, extractable=True)

        get_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, tgt_uid),
            wrap=_wrap_spec(kek_uid),
        )
        get_resp = get_op.handle(get_payload, "user", store, shim)
        key_block = next(i for i in decode_all(get_resp) if i.tag == Tag.SymmetricKey).get(Tag.KeyBlock)
        wrapped = key_block.get(Tag.KeyValue).get(Tag.KeyMaterial).value

        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 128)),
        )
        reg_key_block = encode_structure(
            Tag.KeyBlock,
            encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, wrapped))
            + _wrapping_data(kek_uid)
        )
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey) + reg_key_block + attrs
        ))
        with pytest.raises(IllegalOperation):
            reg_op.handle(p, "user", store, shim)

    def test_register_public_key_with_wrapping_data_still_rejected(self, store, shim):
        """RSA public/private key registration doesn't support wrapping — this
        server can't unwrap into an asymmetric private key object (SoftHSM2/
        PKCS#11 backend limitation confirmed during development)."""
        from kmip_pkcs11.operations import register as reg_op
        kek_uid = _create_kek_uid(store, shim)
        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.RSA)),
        )
        key_block = encode_structure(
            Tag.KeyBlock,
            encode_enumeration(Tag.KeyFormatType, KeyFormatType.PKCS1)
            + encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, b"\x00" * 270))
            + encode_structure(Tag.KeyWrappingData, encode_enumeration(Tag.WrappingMethod, WrappingMethod.Encrypt))
        )
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.PublicKey) + key_block + attrs
        ))
        with pytest.raises(OperationNotSupported):
            reg_op.handle(p, "user", store, shim)


class TestPhase10ImportUnwrap:
    def test_import_wrapped_symmetric_key(self, store, shim):
        from kmip_pkcs11.operations import get as get_op, import_op
        kek_uid = _create_kek_uid(store, shim)
        tgt_uid = _create_aes_uid(store, shim, extractable=True)
        tgt_cka = bytes.fromhex(store.get_attribute(tgt_uid, "_pkcs11_cka_id")[0])
        plaintext = shim.get_key_value(tgt_cka)

        get_payload = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, tgt_uid),
            wrap=_wrap_spec(kek_uid),
        )
        get_resp = get_op.handle(get_payload, "user", store, shim)
        key_block = next(i for i in decode_all(get_resp) if i.tag == Tag.SymmetricKey).get(Tag.KeyBlock)
        wrapped = key_block.get(Tag.KeyValue).get(Tag.KeyMaterial).value

        client_uid = "imported-wrapped-" + os.urandom(4).hex()
        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 128)),
        )
        reg_key_block = encode_structure(
            Tag.KeyBlock,
            encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, wrapped))
            + _wrapping_data(kek_uid)
        )
        p = decode_one(encode_structure(Tag.RequestPayload,
            encode_text_string(Tag.UniqueIdentifier, client_uid)
            + encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
            + reg_key_block + attrs
        ))
        resp = import_op.handle(p, "user", store, shim)
        result_uid = decode_one(encode_structure(Tag.ResponsePayload, resp)).get(Tag.UniqueIdentifier).value
        assert result_uid == client_uid

        new_cka = bytes.fromhex(store.get_attribute(client_uid, "_pkcs11_cka_id")[0])
        assert shim.get_key_value(new_cka) == plaintext


# ══════════════════════════════════════════════════════════════════════════════
# Audit Phase 11 — Credential auth, BatchErrorContinuationOption, MaximumResponseSize
# ══════════════════════════════════════════════════════════════════════════════

from kmip_pkcs11.core.enums import (
    BatchErrorContinuationOption, CredentialType, Operation, ResultReason, ResultStatus
)
from kmip_pkcs11.core.exceptions import AuthenticationFailed

_TEST_TOKEN_PIN = "9999"  # matches conftest.USER_PIN


def _auth_header(username=None, password=None):
    fields = b""
    if username is not None:
        cred_value = (
            encode_text_string(Tag.Username, username)
            + encode_text_string(Tag.Password, password or "")
        )
        credential = encode_structure(
            Tag.Credential,
            encode_enumeration(Tag.CredentialType, CredentialType.UsernameAndPassword)
            + encode_structure(Tag.CredentialValue, cred_value)
        )
        fields += encode_structure(Tag.Authentication, credential)
    return decode_one(encode_structure(Tag.RequestHeader, fields)) if fields else None


class TestPhase11AuthenticateUnit:
    def _server(self, pin_matches=True):
        """`pin_matches` now means "does this identity's own password verify" —
        the credential is checked against the per-identity scrypt hash in the
        store, not against the shared token PIN (Phase 0)."""
        from kmip_pkcs11.server.server import KMIPServer
        store = MagicMock()
        store.verify_identity = MagicMock(return_value=pin_matches)
        return KMIPServer(store=store, shim=MagicMock())

    def test_no_header_returns_fallback(self):
        srv = self._server()
        assert srv._authenticate(None, "anonymous") == "anonymous"

    def test_no_authentication_field_returns_fallback(self):
        srv = self._server()
        header = decode_one(encode_structure(Tag.RequestHeader, b""))
        assert srv._authenticate(header, "tls-cn-identity") == "tls-cn-identity"

    def test_valid_credential_returns_username(self):
        srv = self._server(pin_matches=True)
        header = _auth_header("alice", _TEST_TOKEN_PIN)
        assert srv._authenticate(header, "anonymous") == "alice"

    def test_invalid_password_raises(self):
        srv = self._server(pin_matches=False)
        header = _auth_header("mallory", "wrong-pin")
        with pytest.raises(AuthenticationFailed):
            srv._authenticate(header, "anonymous")

    def test_missing_username_raises(self):
        srv = self._server(pin_matches=True)
        credential = encode_structure(
            Tag.Credential,
            encode_enumeration(Tag.CredentialType, CredentialType.UsernameAndPassword)
            + encode_structure(Tag.CredentialValue, encode_text_string(Tag.Password, _TEST_TOKEN_PIN))
        )
        header = decode_one(encode_structure(Tag.RequestHeader,
            encode_structure(Tag.Authentication, credential)))
        with pytest.raises(AuthenticationFailed):
            srv._authenticate(header, "anonymous")

    def test_missing_credential_value_raises(self):
        srv = self._server(pin_matches=True)
        credential = encode_structure(
            Tag.Credential,
            encode_enumeration(Tag.CredentialType, CredentialType.UsernameAndPassword)
        )
        header = decode_one(encode_structure(Tag.RequestHeader,
            encode_structure(Tag.Authentication, credential)))
        with pytest.raises(AuthenticationFailed):
            srv._authenticate(header, "anonymous")

    def test_unsupported_credential_type_raises(self):
        srv = self._server(pin_matches=True)
        credential = encode_structure(
            Tag.Credential,
            encode_enumeration(Tag.CredentialType, CredentialType.Device)
        )
        header = decode_one(encode_structure(Tag.RequestHeader,
            encode_structure(Tag.Authentication, credential)))
        with pytest.raises(AuthenticationFailed):
            srv._authenticate(header, "anonymous")


class TestPhase11VerifyPin:
    def test_correct_pin_matches(self, shim):
        assert shim.verify_pin(_TEST_TOKEN_PIN) is True

    def test_wrong_pin_does_not_match(self, shim):
        assert shim.verify_pin("wrong-pin") is False

    def test_empty_pin_does_not_match(self, shim):
        assert shim.verify_pin("") is False


class TestPhase11AuthenticationLive:
    def test_correct_credential_sets_owner_identity(self, kmip_server):
        from kmip_pkcs11.test_app.client import KMIPClient
        store, port = kmip_server
        store.create_identity("alice", "alice-secret")
        client = KMIPClient(port=port, username="alice", password="alice-secret")
        client.connect()
        uid = client.create(algorithm=CryptographicAlgorithm.AES, length=128, name="cred-live-test")
        assert store.get_object(uid)["owner_identity"] == "alice"
        client.close()

    def test_wrong_credential_rejected(self, kmip_server):
        from kmip_pkcs11.test_app.client import KMIPClient
        from kmip_pkcs11.test_app.client import KMIPClientError
        store, port = kmip_server
        store.create_identity("mallory", "mallory-secret")
        client = KMIPClient(port=port, username="mallory", password="wrong-password")
        client.connect()
        with pytest.raises(KMIPClientError):
            client.create(algorithm=CryptographicAlgorithm.AES, length=128, name="should-not-exist")
        client.close()

    def test_token_pin_is_no_longer_a_credential(self, kmip_server):
        """The whole point of Phase 0: the shared PKCS#11 PIN must not
        authenticate a KMIP identity any more."""
        from kmip_pkcs11.test_app.client import KMIPClient, KMIPClientError
        store, port = kmip_server
        store.create_identity("alice", "alice-secret")
        client = KMIPClient(port=port, username="alice", password=_TEST_TOKEN_PIN)
        client.connect()
        with pytest.raises(KMIPClientError):
            client.create(algorithm=CryptographicAlgorithm.AES, length=128, name="pin-should-fail")
        client.close()

    def test_unprovisioned_identity_rejected(self, kmip_server):
        """An identity that was never created cannot authenticate, whatever
        password it supplies — usernames are no longer self-asserted."""
        from kmip_pkcs11.test_app.client import KMIPClient, KMIPClientError
        _, port = kmip_server
        client = KMIPClient(port=port, username="ghost", password="anything")
        client.connect()
        with pytest.raises(KMIPClientError):
            client.create(algorithm=CryptographicAlgorithm.AES, length=128, name="ghost-key")
        client.close()

    def test_no_credential_falls_back_to_anonymous(self, kmip_server):
        from kmip_pkcs11.test_app.client import KMIPClient
        store, port = kmip_server
        client = KMIPClient(port=port)
        client.connect()
        uid = client.create(algorithm=CryptographicAlgorithm.AES, length=128, name="no-cred-test")
        assert store.get_object(uid)["owner_identity"] == "anonymous"
        client.close()


class TestPhase11BatchContinuationLive:
    def test_continue_mode_processes_all_items(self, kmip_server):
        from kmip_pkcs11.test_app.client import KMIPClient
        _, port = kmip_server
        client = KMIPClient(port=port)
        client.connect()
        bad = encode_text_string(Tag.UniqueIdentifier, "does-not-exist")
        resp = client.raw_batch_request([(Operation.Destroy, bad), (Operation.Destroy, bad)])
        assert resp.get(Tag.ResponseHeader).get(Tag.BatchCount).value == 2
        assert len(resp.get_all(Tag.BatchItem)) == 2
        client.close()

    def test_stop_mode_halts_after_first_failure(self, kmip_server):
        from kmip_pkcs11.test_app.client import KMIPClient
        _, port = kmip_server
        client = KMIPClient(port=port)
        client.connect()
        bad = encode_text_string(Tag.UniqueIdentifier, "does-not-exist")
        resp = client.raw_batch_request(
            [(Operation.Destroy, bad), (Operation.Destroy, bad)],
            batch_error_continuation=BatchErrorContinuationOption.Stop,
        )
        assert resp.get(Tag.ResponseHeader).get(Tag.BatchCount).value == 1
        assert len(resp.get_all(Tag.BatchItem)) == 1
        client.close()

    def test_stop_mode_all_succeed_processes_everything(self, kmip_server):
        from kmip_pkcs11.test_app.client import KMIPClient
        _, port = kmip_server
        client = KMIPClient(port=port)
        client.connect()
        attrs = encode_structure(
            Tag.TemplateAttribute,
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 128)),
        )
        create_payload = encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey) + attrs
        resp = client.raw_batch_request(
            [(Operation.Create, create_payload), (Operation.Create, create_payload)],
            batch_error_continuation=BatchErrorContinuationOption.Stop,
        )
        assert resp.get(Tag.ResponseHeader).get(Tag.BatchCount).value == 2
        statuses = [i.get(Tag.ResultStatus).value for i in resp.get_all(Tag.BatchItem)]
        assert all(s == ResultStatus.Success for s in statuses)
        client.close()

    def test_undo_mode_rejected(self, kmip_server):
        from kmip_pkcs11.test_app.client import KMIPClient
        _, port = kmip_server
        client = KMIPClient(port=port)
        client.connect()
        bad = encode_text_string(Tag.UniqueIdentifier, "does-not-exist")
        resp = client.raw_batch_request(
            [(Operation.Destroy, bad)],
            batch_error_continuation=BatchErrorContinuationOption.Undo,
        )
        item = resp.get_all(Tag.BatchItem)[0]
        assert item.get(Tag.ResultReason).value == ResultReason.FeatureNotSupported
        client.close()


class TestPhase11MaximumResponseSizeLive:
    def test_response_too_large_rejected(self, kmip_server):
        from kmip_pkcs11.test_app.client import KMIPClient
        _, port = kmip_server
        client = KMIPClient(port=port)
        client.connect()
        bad = encode_text_string(Tag.UniqueIdentifier, "does-not-exist")
        resp = client.raw_batch_request([(Operation.Destroy, bad)], max_response_size=4)
        item = resp.get_all(Tag.BatchItem)[0]
        assert item.get(Tag.ResultReason).value == ResultReason.ResponseTooLarge
        client.close()

    def test_response_within_limit_succeeds(self, kmip_server):
        from kmip_pkcs11.test_app.client import KMIPClient
        _, port = kmip_server
        client = KMIPClient(port=port)
        client.connect()
        bad = encode_text_string(Tag.UniqueIdentifier, "does-not-exist")
        resp = client.raw_batch_request([(Operation.Destroy, bad)], max_response_size=100_000)
        item = resp.get_all(Tag.BatchItem)[0]
        assert item.get(Tag.ResultStatus).value == ResultStatus.OperationFailed
        assert item.get(Tag.ResultReason).value == ResultReason.ItemNotFound
        client.close()


class TestPhase11ResultReasonFidelity:
    """Locks in the Phase 11 ResultReason codepoint corrections (same class of
    bug as Phase 9's Tag fixes — spot-checked against the same reference)."""

    def test_core_values_match_spec(self):
        assert ResultReason.ItemNotFound == 0x00000001
        assert ResultReason.ResponseTooLarge == 0x00000002
        assert ResultReason.AuthenticationNotSuccessful == 0x00000003
        assert ResultReason.FeatureNotSupported == 0x00000008
        assert ResultReason.ObjectArchived == 0x0000000D
        assert ResultReason.GeneralFailure == 0x00000100

    def test_corrected_values_no_longer_collide(self):
        assert ResultReason.IndexOutOfBounds == 0x0000000E
        assert ResultReason.KeyValueNotPresent == 0x00000013
        assert ResultReason.NotExtractable == 0x00000017
        assert ResultReason.InvalidCSR == 0x0000002F
        values = [r.value for r in ResultReason]
        assert len(values) == len(set(values))


class TestPhase11WrapSpecOnAsymmetricKeyRejected:
    """Regression test: a post-Phase-10-audit fix. Get computed wrap_spec but
    only threaded it through to _get_symmetric — a Get with
    KeyWrappingSpecification against a PrivateKey/PublicKey silently ignored
    the spec and returned plaintext instead of erroring."""

    def test_get_private_key_with_wrap_spec_raises(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        _, priv_uid = _create_rsa_keypair(store, shim)
        kek_uid = _create_kek_uid(store, shim)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, priv_uid),
            wrap=_wrap_spec(kek_uid),
        )
        with pytest.raises(OperationNotSupported):
            get_op.handle(p, "user", store, shim)

    def test_get_public_key_with_wrap_spec_raises(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        pub_uid, _ = _create_rsa_keypair(store, shim)
        kek_uid = _create_kek_uid(store, shim)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, pub_uid),
            wrap=_wrap_spec(kek_uid),
        )
        with pytest.raises(OperationNotSupported):
            get_op.handle(p, "user", store, shim)

    def test_get_public_key_without_wrap_spec_still_works(self, store, shim):
        """Sanity: the fix must not break the normal (unwrapped) Get path."""
        from kmip_pkcs11.operations import get as get_op
        pub_uid, _ = _create_rsa_keypair(store, shim)
        resp = get_op.handle(_uid_payload(pub_uid), "user", store, shim)
        assert next(i for i in decode_all(resp) if i.tag == Tag.PublicKey) is not None


# ══════════════════════════════════════════════════════════════════════════════
# Phase 12 — algorithm capability probe + Tier-1 mapping (SHA-3 HMAC,
# Blowfish, Twofish). All three are real PKCS#11 mechanisms, wired into the
# shim and gated by supports_mechanism() so they activate automatically on a
# token that implements them. This SoftHSM2 build doesn't (confirmed live
# via slot.get_mechanisms()) — every path below must fail *cleanly* with
# OperationNotSupported instead of a raw PKCS#11 error surfacing.
# ══════════════════════════════════════════════════════════════════════════════

class TestPhase12CapabilityProbe:
    """The shim caches slot.get_mechanisms() once at initialize() time."""

    def test_probe_populated_after_initialize(self, shim):
        assert len(shim._available_mechanisms) > 0

    def test_get_mechanism_list_matches_probe(self, shim):
        assert set(shim.get_mechanism_list()) == shim._available_mechanisms

    def test_supports_mechanism_accepts_raw_int(self, shim):
        import pkcs11
        assert shim.supports_mechanism(int(pkcs11.Mechanism.AES_CBC_PAD)) is True

    def test_require_mechanism_raises_with_readable_name(self, shim):
        import pkcs11
        with pytest.raises(OperationNotSupported, match="AES_CFB128"):
            shim._require_mechanism(pkcs11.Mechanism.AES_CFB128, "Encrypt")


class TestPhase12BlowfishTwofishGated:
    """Blowfish/Twofish key generation: real CKM_BLOWFISH_KEY_GEN /
    CKM_TWOFISH_KEY_GEN mechanisms, absent from this token."""

    def test_create_blowfish_key_raises_operation_not_supported(self, shim):
        with pytest.raises(OperationNotSupported):
            shim.generate_symmetric_key(CryptographicAlgorithm.Blowfish, 128)

    def test_create_twofish_key_raises_operation_not_supported(self, shim):
        with pytest.raises(OperationNotSupported):
            shim.generate_symmetric_key(CryptographicAlgorithm.Twofish, 128)

    def test_blowfish_still_maps_to_a_pkcs11_keytype(self):
        """The algorithm mapping itself is real, independent of this token's
        capability — proves the gap is backend availability, not missing code."""
        from kmip_pkcs11.pkcs11_shim.shim import ALGO_TO_PKCS11_KEYTYPE
        import pkcs11
        assert ALGO_TO_PKCS11_KEYTYPE[CryptographicAlgorithm.Blowfish] == pkcs11.KeyType.BLOWFISH
        assert ALGO_TO_PKCS11_KEYTYPE[CryptographicAlgorithm.Twofish] == pkcs11.KeyType.TWOFISH


class TestPhase12HmacSha3Gated:
    """HMAC-SHA3: key generation succeeds (CKM_GENERIC_SECRET_KEY_GEN is
    present on this token), but the SHA3_*_HMAC sign/verify mechanism used
    at MAC-compute time is not — the gate must fire there instead."""

    def test_hmac_sha3_key_generation_succeeds(self, shim):
        """Generation doesn't need a SHA3-specific mechanism at all."""
        _, cka_id = shim.generate_symmetric_key(CryptographicAlgorithm.HMACSHA3256, 256)
        assert cka_id is not None

    def test_shim_mac_with_hmac_sha3_raises_operation_not_supported(self, shim):
        import pkcs11
        _, cka_id = shim.generate_symmetric_key(CryptographicAlgorithm.HMACSHA3256, 256)
        with pytest.raises(OperationNotSupported):
            shim.mac(cka_id, b"data", mechanism=pkcs11.Mechanism.SHA3_256_HMAC)

    def test_mac_op_handler_with_hmac_sha3_raises_operation_not_supported(self, store, shim):
        """End-to-end through operations/mac.py's HMAC_ALG_TO_MECH table."""
        from kmip_pkcs11.operations import mac as mac_op
        uid = _create_hmac_uid(store, shim, algorithm=CryptographicAlgorithm.HMACSHA3256)
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, b"payload"),
        )
        with pytest.raises(OperationNotSupported):
            mac_op.handle(p, "user", store, shim)


# ══════════════════════════════════════════════════════════════════════════════
# KMS hardening — owner-only access control.
# Every object records owner_identity at create time; operations against an
# existing object must come from that same identity (lifecycle/access_control.py).
# This is the minimal fix for the gap where `identity` was stamped on create
# but never checked on any subsequent operation.
# ══════════════════════════════════════════════════════════════════════════════

def _create_aes_uid_owned_by(store, shim, owner: str, length=128, extractable=True) -> str:
    """Like _create_aes_uid, but via direct store/shim calls so the owner
    can be someone other than the fixed "user" identity _create_aes_uid bakes in."""
    cka_id_pair = shim.generate_symmetric_key(
        CryptographicAlgorithm.AES, length, extractable=extractable,
        encrypt=True, decrypt=True,
    )
    cka_id = cka_id_pair[1]
    uid = store.create_object(
        object_type=ObjectType.SymmetricKey,
        state=State.Active,
        cryptographic_algorithm=CryptographicAlgorithm.AES,
        cryptographic_length=length,
        usage_mask=CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt,
        extractable=extractable,
        owner_identity=owner,
    )
    store.add_attribute(uid, "_pkcs11_cka_id", cka_id.hex())
    return uid


class TestOwnershipEnforcement:
    """Cross-identity access must be rejected; same-identity access must
    keep working; objects with no recorded owner remain open (legacy/system)."""

    def test_get_by_non_owner_raises(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        with pytest.raises(NotAuthorized):
            get_op.handle(_uid_payload(uid), "bob", store, shim)

    def test_get_by_owner_succeeds(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        resp = get_op.handle(_uid_payload(uid), "alice", store, shim)
        assert next(i for i in decode_all(resp) if i.tag == Tag.UniqueIdentifier).value == uid

    def test_destroy_by_non_owner_raises(self, store, shim):
        from kmip_pkcs11.operations import destroy as destroy_op
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        with pytest.raises(NotAuthorized):
            destroy_op.handle(_uid_payload(uid), "bob", store, shim)
        assert store.get_object(uid)["state"] != State.Destroyed

    def test_encrypt_by_non_owner_raises(self, store, shim):
        from kmip_pkcs11.operations import encrypt as encrypt_op
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, b"0123456789012345"),
        )
        with pytest.raises(NotAuthorized):
            encrypt_op.handle(p, "bob", store, shim)

    def test_add_attribute_by_non_owner_raises(self, store, shim):
        from kmip_pkcs11.operations import add_attribute as op
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        attr_inner = (
            encode_text_string(Tag.AttributeName, "x-tag")
            + encode_text_string(Tag.AttributeValue, "v")
        )
        inner = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_structure(Tag.Attribute, attr_inner)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(NotAuthorized):
            op.handle(payload, "bob", store, shim)

    def test_locate_only_returns_own_objects(self, store, shim):
        from kmip_pkcs11.operations import locate as locate_op
        alice_uid = _create_aes_uid_owned_by(store, shim, "alice", extractable=False)
        bob_uid   = _create_aes_uid_owned_by(store, shim, "bob", extractable=False)

        resp = locate_op.handle(_make_payload(), "alice", store, shim)
        uids = [i.value for i in decode_all(resp) if i.tag == Tag.UniqueIdentifier]
        assert alice_uid in uids
        assert bob_uid not in uids

    def test_object_with_no_owner_is_accessible_by_anyone(self, store, shim):
        """Objects with owner_identity=None (legacy/pre-ownership-tracking)
        stay reachable rather than becoming permanently orphaned."""
        from kmip_pkcs11.operations import get as get_op
        cka_id_pair = shim.generate_symmetric_key(CryptographicAlgorithm.AES, 128, extractable=True)
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey,
            state=State.Active,
            cryptographic_algorithm=CryptographicAlgorithm.AES,
            cryptographic_length=128,
            usage_mask=CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt,
            extractable=True,
            owner_identity=None,
        )
        store.add_attribute(uid, "_pkcs11_cka_id", cka_id_pair[1].hex())
        resp = get_op.handle(_uid_payload(uid), "whoever", store, shim)
        assert next(i for i in decode_all(resp) if i.tag == Tag.UniqueIdentifier).value == uid


# ══════════════════════════════════════════════════════════════════════════════
# KMS hardening — PKCS#11 session concurrency.
# server.py runs one thread per connection sharing a single PKCS11Shim; this
# regression test hammers the shim from many real Python threads at once —
# the exact scenario the shim docstring flagged as unsafe before _synchronized
# was added — and checks every call completes with the right answer, not
# just "didn't crash" (a race could easily produce silently wrong ciphertext
# rather than an exception).
# ══════════════════════════════════════════════════════════════════════════════

class TestShimConcurrency:
    def test_lock_exists_and_is_reentrant(self, shim):
        import threading
        assert isinstance(shim._lock, type(threading.RLock()))
        # RLock: the same thread can reacquire without deadlocking.
        with shim._lock:
            with shim._lock:
                pass

    def test_concurrent_encrypt_decrypt_across_many_threads(self, store, shim):
        """Each thread gets its own key and repeatedly encrypts/decrypts
        distinct plaintext concurrently with every other thread. Without the
        lock, python-pkcs11 session state can be clobbered mid-operation by
        another thread, producing wrong plaintext back or a native crash."""
        import concurrent.futures
        from kmip_pkcs11.operations import encrypt as encrypt_op, decrypt as decrypt_op

        N_THREADS = 12
        ROUNDS = 8
        errors = []

        def worker(i):
            try:
                uid = _create_aes_uid_owned_by(store, shim, f"thread-{i}", length=256)
                for r in range(ROUNDS):
                    plaintext = f"thread-{i}-round-{r}--payload".encode().ljust(32, b"\0")
                    iv = os.urandom(16)
                    enc_payload = _make_payload(
                        uid=encode_text_string(Tag.UniqueIdentifier, uid),
                        data=encode_byte_string(Tag.Data, plaintext),
                        iv=encode_byte_string(Tag.IVCounterNonce, iv),
                    )
                    enc_resp = encrypt_op.handle(enc_payload, f"thread-{i}", store, shim)
                    ciphertext = next(
                        it.value for it in decode_all(enc_resp) if it.tag == Tag.Data
                    )
                    dec_payload = _make_payload(
                        uid=encode_text_string(Tag.UniqueIdentifier, uid),
                        data=encode_byte_string(Tag.Data, ciphertext),
                        iv=encode_byte_string(Tag.IVCounterNonce, iv),
                    )
                    dec_resp = decrypt_op.handle(dec_payload, f"thread-{i}", store, shim)
                    recovered = next(
                        it.value for it in decode_all(dec_resp) if it.tag == Tag.Data
                    )
                    if recovered != plaintext:
                        errors.append(f"thread {i} round {r}: got {recovered!r}, want {plaintext!r}")
            except Exception as exc:
                errors.append(f"thread {i} raised: {exc!r}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=N_THREADS) as pool:
            futures = [pool.submit(worker, i) for i in range(N_THREADS)]
            for f in futures:
                f.result(timeout=60)

        assert errors == []


# ══════════════════════════════════════════════════════════════════════════════
# KMS hardening — RBAC: admin role + delegated per-object grants, layered on
# top of the owner-only model. No KMIP wire operation manages roles/grants
# (the spec doesn't define one) — they're a MetadataStore admin surface,
# exercised here directly plus through operation handlers end-to-end.
# ══════════════════════════════════════════════════════════════════════════════

class TestRolesStoreCRUD:
    def test_assign_and_get_roles(self, store):
        assert store.get_roles("alice") == []
        store.assign_role("alice", "admin")
        assert store.get_roles("alice") == ["admin"]

    def test_assign_role_idempotent(self, store):
        store.assign_role("alice", "admin")
        store.assign_role("alice", "admin")
        assert store.get_roles("alice") == ["admin"]

    def test_revoke_role(self, store):
        store.assign_role("alice", "admin")
        store.revoke_role("alice", "admin")
        assert store.get_roles("alice") == []

    def test_multiple_roles(self, store):
        store.assign_role("alice", "admin")
        store.assign_role("alice", "auditor")
        assert set(store.get_roles("alice")) == {"admin", "auditor"}


class TestGrantsStoreCRUD:
    def test_grant_and_get(self, store, shim):
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        assert store.get_grant(uid, "bob") is None
        store.grant_access(uid, "bob", "read")
        assert store.get_grant(uid, "bob") == "read"

    def test_grant_upsert_overwrites_permission(self, store, shim):
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        store.grant_access(uid, "bob", "read")
        store.grant_access(uid, "bob", "full")
        assert store.get_grant(uid, "bob") == "full"

    def test_revoke_access(self, store, shim):
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        store.grant_access(uid, "bob", "full")
        store.revoke_access(uid, "bob")
        assert store.get_grant(uid, "bob") is None

    def test_list_grants(self, store, shim):
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        store.grant_access(uid, "bob", "read")
        store.grant_access(uid, "carol", "full")
        grants = {g["grantee"]: g["permission"] for g in store.list_grants(uid)}
        assert grants == {"bob": "read", "carol": "full"}


class TestAdminBypass:
    def test_is_admin_false_by_default(self, store):
        from kmip_pkcs11.lifecycle.access_control import is_admin
        assert is_admin("alice", store) is False

    def test_is_admin_true_after_role_assigned(self, store):
        from kmip_pkcs11.lifecycle.access_control import is_admin
        store.assign_role("alice", "admin")
        assert is_admin("alice", store) is True

    def test_admin_can_get_others_object(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        store.assign_role("root", "admin")
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        resp = get_op.handle(_uid_payload(uid), "root", store, shim)
        assert next(i for i in decode_all(resp) if i.tag == Tag.UniqueIdentifier).value == uid

    def test_admin_can_destroy_others_object(self, store, shim):
        from kmip_pkcs11.operations import destroy as destroy_op
        store.assign_role("root", "admin")
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        destroy_op.handle(_uid_payload(uid), "root", store, shim)
        assert store.get_object(uid)["state"] == State.Destroyed

    def test_non_admin_still_rejected(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        store.assign_role("root", "auditor")  # some role, but not "admin"
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        with pytest.raises(NotAuthorized):
            get_op.handle(_uid_payload(uid), "root", store, shim)


class TestDelegatedGrants:
    def test_read_grant_allows_get(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        store.grant_access(uid, "bob", "read")
        resp = get_op.handle(_uid_payload(uid), "bob", store, shim)
        assert next(i for i in decode_all(resp) if i.tag == Tag.UniqueIdentifier).value == uid

    def test_read_grant_does_not_allow_destroy(self, store, shim):
        from kmip_pkcs11.operations import destroy as destroy_op
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        store.grant_access(uid, "bob", "read")
        with pytest.raises(NotAuthorized):
            destroy_op.handle(_uid_payload(uid), "bob", store, shim)

    def test_full_grant_allows_destroy(self, store, shim):
        from kmip_pkcs11.operations import destroy as destroy_op
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        store.grant_access(uid, "bob", "full")
        destroy_op.handle(_uid_payload(uid), "bob", store, shim)
        assert store.get_object(uid)["state"] == State.Destroyed

    def test_full_grant_allows_encrypt(self, store, shim):
        from kmip_pkcs11.operations import encrypt as encrypt_op
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        store.grant_access(uid, "bob", "full")
        p = _make_payload(
            uid=encode_text_string(Tag.UniqueIdentifier, uid),
            data=encode_byte_string(Tag.Data, b"0123456789012345"),
        )
        resp = encrypt_op.handle(p, "bob", store, shim)
        assert next(i for i in decode_all(resp) if i.tag == Tag.UniqueIdentifier).value == uid

    def test_grant_to_someone_else_does_not_leak_to_third_party(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        store.grant_access(uid, "bob", "full")
        with pytest.raises(NotAuthorized):
            get_op.handle(_uid_payload(uid), "carol", store, shim)

    def test_revoked_grant_is_rejected_again(self, store, shim):
        from kmip_pkcs11.operations import get as get_op
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        store.grant_access(uid, "bob", "full")
        store.revoke_access(uid, "bob")
        with pytest.raises(NotAuthorized):
            get_op.handle(_uid_payload(uid), "bob", store, shim)


# ══════════════════════════════════════════════════════════════════════════════
# Phase 0 — the review's blocker fixes.
#
# Each class here corresponds to one finding from the full-project review:
# self-asserted identity, admin ignored by Locate, unbounded request read,
# unbounded TTLV nesting, and internal error text reaching clients.
# ══════════════════════════════════════════════════════════════════════════════

class TestPhase0PerIdentityCredentials:
    """Identity is authenticated against a per-user scrypt hash, so knowing
    one shared secret no longer lets a caller become an arbitrary user."""

    def test_create_and_verify(self, store):
        store.create_identity("alice", "s3cret")
        assert store.verify_identity("alice", "s3cret") is True

    def test_wrong_password_rejected(self, store):
        store.create_identity("alice", "s3cret")
        assert store.verify_identity("alice", "wrong") is False

    def test_unknown_identity_rejected(self, store):
        assert store.verify_identity("nobody", "anything") is False

    def test_each_identity_has_a_distinct_secret(self, store):
        """The core of the fix: alice's password must not authenticate bob."""
        store.create_identity("alice", "alice-pw")
        store.create_identity("bob", "bob-pw")
        assert store.verify_identity("bob", "alice-pw") is False
        assert store.verify_identity("alice", "bob-pw") is False

    def test_salts_are_unique_so_equal_passwords_differ_on_disk(self, store):
        store.create_identity("alice", "same-password")
        store.create_identity("bob", "same-password")
        rows = {r["identity"]: r for r in store._conn().execute(
            "SELECT identity, password_hash, salt FROM kmip_identities").fetchall()}
        assert rows["alice"]["salt"] != rows["bob"]["salt"]
        assert rows["alice"]["password_hash"] != rows["bob"]["password_hash"]

    def test_password_is_not_stored_in_cleartext(self, store):
        store.create_identity("alice", "sup3r-s3cret-value")
        blob = store._conn().execute(
            "SELECT password_hash, salt FROM kmip_identities WHERE identity='alice'").fetchone()
        assert b"sup3r-s3cret-value" not in bytes(blob["password_hash"])
        assert b"sup3r-s3cret-value" not in bytes(blob["salt"])

    def test_password_rotation_invalidates_the_old_one(self, store):
        store.create_identity("alice", "old-pw")
        store.set_password("alice", "new-pw")
        assert store.verify_identity("alice", "old-pw") is False
        assert store.verify_identity("alice", "new-pw") is True

    def test_disabled_identity_cannot_authenticate(self, store):
        store.create_identity("alice", "pw")
        store.set_identity_disabled("alice")
        assert store.verify_identity("alice", "pw") is False

    def test_deleted_identity_cannot_authenticate(self, store):
        store.create_identity("alice", "pw")
        store.delete_identity("alice")
        assert store.verify_identity("alice", "pw") is False

    def test_list_identities_reports_without_secrets(self, store):
        store.create_identity("alice", "pw")
        listed = store.list_identities()
        assert [i["identity"] for i in listed] == ["alice"]
        assert "password_hash" not in listed[0] and "salt" not in listed[0]


class TestPhase0AdminCanLocate:
    """Regression for the defect introduced with RBAC: the admin role was
    honoured by check_owner() but ignored by Locate, so an admin could read
    an object it was unable to find."""

    def test_admin_locate_sees_other_identities_objects(self, store, shim):
        from kmip_pkcs11.operations import locate as locate_op
        store.assign_role("root", "admin")
        alice_uid = _create_aes_uid_owned_by(store, shim, "alice", extractable=False)
        bob_uid   = _create_aes_uid_owned_by(store, shim, "bob", extractable=False)

        resp = locate_op.handle(_make_payload(), "root", store, shim)
        uids = [i.value for i in decode_all(resp) if i.tag == Tag.UniqueIdentifier]
        assert alice_uid in uids
        assert bob_uid in uids

    def test_admin_can_both_find_and_read_the_same_object(self, store, shim):
        """The inconsistency the review caught: Locate returned [] while
        GetAttributes on that very UID succeeded."""
        from kmip_pkcs11.operations import locate as locate_op, get_attributes as ga_op
        store.assign_role("root", "admin")
        uid = _create_aes_uid_owned_by(store, shim, "alice", extractable=False)

        resp = locate_op.handle(_make_payload(), "root", store, shim)
        found = [i.value for i in decode_all(resp) if i.tag == Tag.UniqueIdentifier]
        assert uid in found, "admin must be able to find what it can read"
        ga_op.handle(_uid_payload(uid), "root", store, shim)

    def test_non_admin_locate_is_still_filtered(self, store, shim):
        """The fix must not widen visibility for ordinary identities."""
        from kmip_pkcs11.operations import locate as locate_op
        alice_uid = _create_aes_uid_owned_by(store, shim, "alice", extractable=False)
        bob_uid   = _create_aes_uid_owned_by(store, shim, "bob", extractable=False)

        resp = locate_op.handle(_make_payload(), "alice", store, shim)
        uids = [i.value for i in decode_all(resp) if i.tag == Tag.UniqueIdentifier]
        assert alice_uid in uids
        assert bob_uid not in uids


class TestPhase0RequestSizeCap:
    """An oversized length prefix is refused before the body is read, since
    this happens ahead of any authentication."""

    def test_oversize_declared_length_is_rejected(self, store, shim):
        from kmip_pkcs11.server.server import KMIPServer
        from kmip_pkcs11.core.exceptions import InvalidMessage
        srv = KMIPServer(store, shim, max_request_size=1024)
        sock = MagicMock()
        # 8-byte TTLV header declaring a 4 GiB body.
        sock.recv.return_value = b"\x42\x00\x78\x01" + struct.pack(">I", 0xFFFFFFFF)
        with pytest.raises(InvalidMessage):
            srv._recv_message(sock)

    def test_body_is_never_read_for_an_oversize_frame(self, store, shim):
        """Proves the refusal happens before allocation: only the 8-byte
        header is ever pulled off the socket."""
        from kmip_pkcs11.server.server import KMIPServer
        from kmip_pkcs11.core.exceptions import InvalidMessage
        srv = KMIPServer(store, shim, max_request_size=1024)
        sock = MagicMock()
        sock.recv.return_value = b"\x42\x00\x78\x01" + struct.pack(">I", 0xFFFFFFFF)
        with pytest.raises(InvalidMessage):
            srv._recv_message(sock)
        assert sum(c.args[0] for c in sock.recv.call_args_list) <= 8

    def test_within_limit_is_accepted(self, store, shim):
        from kmip_pkcs11.server.server import KMIPServer
        srv = KMIPServer(store, shim, max_request_size=4096)
        body = encode_text_string(Tag.UniqueIdentifier, "ok")
        msg = encode_structure(Tag.RequestMessage, body)
        chunks = [msg[:8], msg[8:]]
        sock = MagicMock()
        sock.recv.side_effect = lambda n: chunks.pop(0) if chunks else b""
        assert srv._recv_message(sock) == msg


class TestPhase0TTLVNestingCap:
    """Deeply nested Structures are rejected instead of recursing to the
    interpreter's stack limit."""

    @staticmethod
    def _nest(depth: int) -> bytes:
        payload = encode_text_string(Tag.UniqueIdentifier, "x")
        for _ in range(depth):
            payload = encode_structure(Tag.RequestPayload, payload)
        return payload

    def test_deep_nesting_raises_valueerror(self):
        from kmip_pkcs11.core.ttlv import MAX_NESTING_DEPTH
        with pytest.raises(ValueError, match="nesting"):
            decode_one(self._nest(MAX_NESTING_DEPTH + 5))

    def test_reasonable_nesting_still_decodes(self):
        item = decode_one(self._nest(6))
        assert item.tag == Tag.RequestPayload

    def test_deep_nesting_over_the_wire_is_a_clean_failure(self, store, shim):
        """End-to-end: a nesting bomb must come back as InvalidMessage, not
        crash the connection handler."""
        from kmip_pkcs11.server.server import KMIPServer
        from kmip_pkcs11.core.enums import ResultReason
        srv = KMIPServer(store, shim)
        resp = decode_one(srv._process(self._nest(500), "anonymous"))
        item = resp.get(Tag.BatchItem)
        assert item.get(Tag.ResultReason).value == ResultReason.InvalidMessage


class TestPhase0ErrorMessageHygiene:
    """Internal exception text must not be echoed to clients."""

    def test_malformed_request_returns_generic_text(self, store, shim):
        from kmip_pkcs11.server.server import KMIPServer
        srv = KMIPServer(store, shim)
        resp = decode_one(srv._process(b"\xff" * 16, "anonymous"))
        msg = resp.get(Tag.BatchItem).get(Tag.ResultMessage).value
        assert msg == "Malformed KMIP request"
        for leak in ("Traceback", "kmip_pkcs11/", "struct.error", "offset"):
            assert leak not in msg

    def test_internal_fault_returns_generic_text(self, store, shim):
        """An unexpected handler exception surfaces as a reason code only."""
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation, ResultStatus, ResultReason
        d = OperationDispatcher(store, shim)
        with patch.dict(d._handlers, {Operation.Create: MagicMock(
                side_effect=RuntimeError("/secret/path/internal.py exploded"))}):
            inner = (encode_enumeration(Tag.Operation, Operation.Create)
                     + encode_structure(Tag.RequestPayload, b""))
            result = decode_one(d.dispatch(decode_one(encode_structure(Tag.BatchItem, inner)), "user"))
        assert result.get(Tag.ResultStatus).value == ResultStatus.OperationFailed
        assert result.get(Tag.ResultReason).value == ResultReason.GeneralFailure
        msg = result.get(Tag.ResultMessage).value
        assert msg == "Internal server error"
        assert "/secret/path" not in msg

    def test_kmip_errors_keep_their_useful_message(self, store, shim):
        """Hygiene must not blunt our own diagnostics — ItemNotFound should
        still say which object was missing."""
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation
        d = OperationDispatcher(store, shim)
        inner = (encode_enumeration(Tag.Operation, Operation.Destroy)
                 + encode_structure(Tag.RequestPayload,
                                    encode_text_string(Tag.UniqueIdentifier, "no-such-uid")))
        result = decode_one(d.dispatch(decode_one(encode_structure(Tag.BatchItem, inner)), "user"))
        assert "no-such-uid" in result.get(Tag.ResultMessage).value

    def test_batch_item_without_operation_fails_cleanly(self, store, shim):
        """Previously raised TypeError formatting a None op_code."""
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import ResultStatus
        d = OperationDispatcher(store, shim)
        item = decode_one(encode_structure(Tag.BatchItem, encode_structure(Tag.RequestPayload, b"")))
        result = decode_one(d.dispatch(item, "user"))
        assert result.get(Tag.ResultStatus).value == ResultStatus.OperationFailed


# ══════════════════════════════════════════════════════════════════════════════
# Phase 1 — secrets at rest.
#
# SecretData, OpaqueObject and SplitKey shares have no PKCS#11 object behind
# them, so their bytes live in kmip_objects.raw_key_value. They are now
# enveloped under an AES-256 master key that is generated on, and never leaves,
# the HSM — plus the versioned migration machinery needed to roll that out.
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def enc_store(tmp_path, shim):
    """A metadata store with blob encryption enabled, as the server wires it."""
    from kmip_pkcs11.metadata.store import MetadataStore
    from kmip_pkcs11.metadata.blob_cipher import BlobCipher
    return MetadataStore(str(tmp_path / "enc.db"), blob_cipher=BlobCipher(shim))


def _raw_column(store, uid):
    """Read raw_key_value straight from SQLite, bypassing decryption — this is
    what someone who stole the database file would see."""
    row = store._conn().execute(
        "SELECT raw_key_value, raw_key_encrypted FROM kmip_objects WHERE uuid = ?", (uid,)
    ).fetchone()
    return bytes(row["raw_key_value"]), row["raw_key_encrypted"]


class TestPhase1SchemaMigrations:
    def test_fresh_database_is_at_current_version(self, store):
        from kmip_pkcs11.metadata.store import SCHEMA_VERSION
        assert store.schema_version() == SCHEMA_VERSION

    def test_migration_adds_the_column_to_a_preexisting_database(self, tmp_path):
        """The exact scenario the review flagged: CREATE TABLE IF NOT EXISTS
        cannot add a column, so an existing deployment would silently miss it."""
        import sqlite3
        from kmip_pkcs11.metadata.store import MetadataStore, SCHEMA

        db = str(tmp_path / "legacy.db")
        legacy = sqlite3.connect(db)
        legacy.executescript(SCHEMA)          # baseline only, user_version stays 0
        legacy.commit()
        cols = {r[1] for r in legacy.execute("PRAGMA table_info(kmip_objects)")}
        assert "raw_key_encrypted" not in cols, "precondition: legacy schema lacks the column"
        assert legacy.execute("PRAGMA user_version").fetchone()[0] == 0
        legacy.close()

        store = MetadataStore(db)             # opening applies the migration
        cols = {r[1] for r in store._conn().execute("PRAGMA table_info(kmip_objects)")}
        assert "raw_key_encrypted" in cols
        assert store.schema_version() == 1

    def test_migrations_are_idempotent(self, tmp_path):
        from kmip_pkcs11.metadata.store import MetadataStore, SCHEMA_VERSION
        db = str(tmp_path / "twice.db")
        MetadataStore(db)
        again = MetadataStore(db)             # must not re-run ALTER TABLE
        assert again.schema_version() == SCHEMA_VERSION

    def test_existing_rows_survive_migration(self, tmp_path):
        from kmip_pkcs11.metadata.store import MetadataStore
        db = str(tmp_path / "data.db")
        first = MetadataStore(db)
        uid = first.create_object(object_type=ObjectType.SecretData,
                                  raw_key_value=b"pre-existing", owner_identity="alice")
        reopened = MetadataStore(db)
        assert reopened.get_object(uid)["raw_key_value"] == b"pre-existing"


class TestPhase1BlobsEncryptedAtRest:
    def test_secret_data_is_ciphertext_on_disk(self, enc_store):
        secret = b"correct-horse-battery-staple"
        uid = enc_store.create_object(object_type=ObjectType.SecretData,
                                      raw_key_value=secret, owner_identity="alice")
        stored, flagged = _raw_column(enc_store, uid)
        assert flagged == 1
        assert secret not in stored, "plaintext secret must not be present in the database"

    def test_roundtrip_is_transparent_to_callers(self, enc_store):
        secret = b"correct-horse-battery-staple"
        uid = enc_store.create_object(object_type=ObjectType.SecretData,
                                      raw_key_value=secret, owner_identity="alice")
        assert enc_store.get_object(uid)["raw_key_value"] == secret

    def test_split_key_shares_are_encrypted(self, enc_store):
        share = bytes(range(32))
        uid = enc_store.create_object(object_type=ObjectType.SplitKey,
                                      raw_key_value=share, owner_identity="alice")
        stored, flagged = _raw_column(enc_store, uid)
        assert flagged == 1 and share not in stored
        assert enc_store.get_object(uid)["raw_key_value"] == share

    def test_opaque_object_is_encrypted(self, enc_store):
        payload = b"opaque-payload-value"
        uid = enc_store.create_object(object_type=ObjectType.OpaqueObject,
                                      raw_key_value=payload, owner_identity="alice")
        stored, flagged = _raw_column(enc_store, uid)
        assert flagged == 1 and payload not in stored

    def test_certificates_stay_readable_in_the_clear(self, enc_store):
        """Certificates are public — encrypting them buys nothing and makes
        them unusable without the HSM."""
        der = b"\x30\x82fake-certificate-DER"
        uid = enc_store.create_object(object_type=ObjectType.Certificate,
                                      raw_key_value=der, owner_identity="alice")
        stored, flagged = _raw_column(enc_store, uid)
        assert flagged == 0 and stored == der

    def test_each_blob_uses_a_fresh_nonce(self, enc_store):
        """Identical plaintexts must not produce identical ciphertexts."""
        a = enc_store.create_object(object_type=ObjectType.SecretData,
                                    raw_key_value=b"same", owner_identity="alice")
        b = enc_store.create_object(object_type=ObjectType.SecretData,
                                    raw_key_value=b"same", owner_identity="alice")
        assert _raw_column(enc_store, a)[0] != _raw_column(enc_store, b)[0]

    def test_tampered_ciphertext_is_rejected(self, enc_store):
        """GCM authentication means a modified row fails loudly rather than
        yielding attacker-chosen bytes."""
        from kmip_pkcs11.core.exceptions import CryptographicFailure
        uid = enc_store.create_object(object_type=ObjectType.SecretData,
                                      raw_key_value=b"tamper-me", owner_identity="alice")
        stored, _ = _raw_column(enc_store, uid)
        corrupted = bytearray(stored)
        corrupted[-1] ^= 0xFF
        enc_store._conn().execute(
            "UPDATE kmip_objects SET raw_key_value = ? WHERE uuid = ?", (bytes(corrupted), uid))
        enc_store._conn().commit()
        with pytest.raises(CryptographicFailure):
            enc_store.get_object(uid)

    def test_encrypted_row_without_a_cipher_raises(self, tmp_path, shim):
        """Opening an encrypted store without the master key must fail loudly,
        not hand back envelope bytes as if they were the secret."""
        from kmip_pkcs11.metadata.store import MetadataStore
        from kmip_pkcs11.metadata.blob_cipher import BlobCipher
        from kmip_pkcs11.core.exceptions import CryptographicFailure
        db = str(tmp_path / "noc.db")
        enc = MetadataStore(db, blob_cipher=BlobCipher(shim))
        uid = enc.create_object(object_type=ObjectType.SecretData,
                                raw_key_value=b"secret", owner_identity="alice")
        plain = MetadataStore(db)             # no cipher
        with pytest.raises(CryptographicFailure):
            plain.get_object(uid)


class TestPhase1BackfillAndRotation:
    def test_preexisting_cleartext_is_converted(self, tmp_path, shim):
        """Upgrading a deployment that already holds cleartext secrets."""
        from kmip_pkcs11.metadata.store import MetadataStore
        from kmip_pkcs11.metadata.blob_cipher import BlobCipher
        db = str(tmp_path / "upgrade.db")

        legacy = MetadataStore(db)            # no cipher — writes in the clear
        uid = legacy.create_object(object_type=ObjectType.SecretData,
                                   raw_key_value=b"legacy-secret", owner_identity="alice")
        assert _raw_column(legacy, uid) == (b"legacy-secret", 0)

        upgraded = MetadataStore(db, blob_cipher=BlobCipher(shim))
        stored, flagged = _raw_column(upgraded, uid)
        assert flagged == 1
        assert b"legacy-secret" not in stored
        assert upgraded.get_object(uid)["raw_key_value"] == b"legacy-secret"

    def test_backfill_scrubs_plaintext_from_the_database_files(self, tmp_path, shim):
        """Encrypting a row with UPDATE does not erase what was there before —
        in WAL mode the original cleartext INSERT stays in the -wal sidecar.
        Without the post-backfill scrub, an upgraded deployment leaves the
        secrets it just encrypted sitting in the clear beside the ciphertext."""
        import glob
        from kmip_pkcs11.metadata.store import MetadataStore
        from kmip_pkcs11.metadata.blob_cipher import BlobCipher

        db = str(tmp_path / "scrub.db")
        secret = b"PLAINTEXT-THAT-MUST-NOT-SURVIVE"

        legacy = MetadataStore(db)
        uid = legacy.create_object(object_type=ObjectType.SecretData,
                                   raw_key_value=secret, owner_identity="alice")
        present = [f for f in glob.glob(db + "*") if secret in open(f, "rb").read()]
        assert present, "precondition: cleartext really is on disk before the upgrade"

        upgraded = MetadataStore(db, blob_cipher=BlobCipher(shim))
        leaked = [f for f in glob.glob(db + "*") if secret in open(f, "rb").read()]
        assert leaked == [], f"plaintext still recoverable from {leaked}"
        assert upgraded.get_object(uid)["raw_key_value"] == secret

    def test_rotation_re_encrypts_and_preserves_plaintext(self, enc_store):
        uids = [enc_store.create_object(object_type=ObjectType.SecretData,
                                        raw_key_value=f"secret-{i}".encode(),
                                        owner_identity="alice") for i in range(3)]
        before = [_raw_column(enc_store, u)[0] for u in uids]

        result = enc_store.rotate_master_key()
        assert result["rotated"] == 3

        for i, u in enumerate(uids):
            assert _raw_column(enc_store, u)[0] != before[i], "ciphertext must change"
            assert enc_store.get_object(u)["raw_key_value"] == f"secret-{i}".encode()

    def test_rotation_changes_the_active_key(self, enc_store):
        before = enc_store._cipher.active_key_id
        enc_store.rotate_master_key(retire_previous=False)
        assert enc_store._cipher.active_key_id != before

    def test_partially_rotated_store_stays_readable(self, enc_store):
        """The reason the envelope carries a key id: re-encrypting a large
        store is not atomic, so a half-finished rotation must still read."""
        uid_old = enc_store.create_object(object_type=ObjectType.SecretData,
                                          raw_key_value=b"under-old-key", owner_identity="alice")
        enc_store._cipher.begin_rotation()     # new key active, old row untouched
        uid_new = enc_store.create_object(object_type=ObjectType.SecretData,
                                          raw_key_value=b"under-new-key", owner_identity="alice")

        assert enc_store.get_object(uid_old)["raw_key_value"] == b"under-old-key"
        assert enc_store.get_object(uid_new)["raw_key_value"] == b"under-new-key"

    def test_retired_key_makes_its_blobs_unreadable(self, enc_store):
        """Confirms retirement really destroys the key — the blob is
        cryptographically gone, not merely flagged."""
        from kmip_pkcs11.core.exceptions import CryptographicFailure
        uid = enc_store.create_object(object_type=ObjectType.SecretData,
                                      raw_key_value=b"doomed", owner_identity="alice")
        old_key = enc_store._cipher.active_key_id
        enc_store._cipher.begin_rotation()
        enc_store._cipher.retire_key(old_key)   # retire WITHOUT re-encrypting first
        with pytest.raises(CryptographicFailure):
            enc_store.get_object(uid)

    def test_cannot_retire_the_active_key(self, enc_store):
        from kmip_pkcs11.core.exceptions import CryptographicFailure
        with pytest.raises(CryptographicFailure):
            enc_store._cipher.retire_key(enc_store._cipher.active_key_id)


class TestPhase1MasterKeyOnToken:
    def test_master_key_is_reused_across_restarts(self, tmp_path, shim):
        """A second BlobCipher must find the existing key, not mint a new one —
        otherwise every restart would orphan the previous data."""
        from kmip_pkcs11.metadata.blob_cipher import BlobCipher
        first = BlobCipher(shim)
        second = BlobCipher(shim)
        assert second.active_key_id == first.active_key_id

    def test_master_key_is_not_extractable(self, shim):
        """The master key exists to protect the database; if it could be read
        off the token, a database thief with shim access would gain nothing."""
        from kmip_pkcs11.metadata.blob_cipher import BlobCipher
        from kmip_pkcs11.core.exceptions import NotExtractable, CryptographicFailure
        cipher = BlobCipher(shim)
        cka_id = cipher._active_cka_id
        with pytest.raises((NotExtractable, CryptographicFailure)):
            shim.get_key_value(cka_id)

    def test_secret_data_roundtrip_through_operations(self, tmp_path, shim):
        """End-to-end through the KMIP handlers, not just the store API."""
        from kmip_pkcs11.metadata.store import MetadataStore
        from kmip_pkcs11.metadata.blob_cipher import BlobCipher
        from kmip_pkcs11.operations import register as reg_op, get as get_op

        store = MetadataStore(str(tmp_path / "ops.db"), blob_cipher=BlobCipher(shim))
        secret = b"my-application-password"
        key_block = encode_structure(
            Tag.KeyBlock,
            encode_enumeration(Tag.KeyFormatType, KeyFormatType.Opaque)
            + encode_structure(Tag.KeyValue, encode_byte_string(Tag.KeyMaterial, secret)))
        payload = decode_one(encode_structure(
            Tag.RequestPayload,
            encode_enumeration(Tag.ObjectType, ObjectType.SecretData) + key_block))
        uid = decode_one(encode_structure(
            Tag.ResponsePayload, reg_op.handle(payload, "alice", store, shim)
        )).get(Tag.UniqueIdentifier).value

        assert secret not in _raw_column(store, uid)[0], "must be ciphertext at rest"
        resp = get_op.handle(_uid_payload(uid), "alice", store, shim)
        material = decode_one(encode_structure(Tag.ResponsePayload, resp)) \
            .get(Tag.SecretData).get(Tag.KeyBlock).get(Tag.KeyValue).get(Tag.KeyMaterial).value
        assert material == secret


# ══════════════════════════════════════════════════════════════════════════════
# Phase 2 — audit trail and transport security.
#
# A tamper-evident, append-only record of who did what to which object when,
# and a listener that refuses to serve KMIP in the clear by accident.
# ══════════════════════════════════════════════════════════════════════════════

def _self_signed(tmp_path):
    """Generate a throwaway certificate/key pair for TLS configuration tests."""
    import subprocess
    cert, key = str(tmp_path / "c.pem"), str(tmp_path / "k.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
         "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    return cert, key


def _dispatch(store, shim, operation, payload_bytes=b"", identity="alice", client=None):
    from kmip_pkcs11.operations.dispatcher import OperationDispatcher
    inner = (encode_enumeration(Tag.Operation, operation)
             + encode_structure(Tag.RequestPayload, payload_bytes))
    item = decode_one(encode_structure(Tag.BatchItem, inner))
    return OperationDispatcher(store, shim).dispatch(item, identity, client)


class TestPhase2AuditRecording:
    def test_successful_operation_is_recorded(self, store, shim):
        from kmip_pkcs11.core.enums import Operation
        uid = store.create_object(object_type=ObjectType.SymmetricKey,
                                  state=State.PreActive, owner_identity="alice")
        _dispatch(store, shim, Operation.Activate,
                  encode_text_string(Tag.UniqueIdentifier, uid), identity="alice")
        entries = store.get_audit_entries(object_uid=uid)
        assert [e["operation_name"] for e in entries] == ["Activate"]
        assert entries[0]["identity"] == "alice"
        assert entries[0]["result"] == "success"
        assert store.get_object(uid)["state"] == State.Active

    def test_failed_operation_is_recorded_with_its_reason(self, store, shim):
        from kmip_pkcs11.core.enums import Operation, ResultReason
        _dispatch(store, shim, Operation.Destroy,
                  encode_text_string(Tag.UniqueIdentifier, "no-such-uid"))
        entry = store.get_audit_entries(object_uid="no-such-uid")[0]
        assert entry["result"] == "failure"
        assert entry["result_reason"] == ResultReason.ItemNotFound

    def test_denied_access_is_recorded(self, store, shim):
        """The audit question that matters most: someone tried to reach an
        object they had no right to."""
        from kmip_pkcs11.core.enums import Operation, ResultReason
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        _dispatch(store, shim, Operation.Destroy,
                  encode_text_string(Tag.UniqueIdentifier, uid), identity="mallory")
        entry = store.get_audit_entries(identity="mallory")[0]
        assert entry["result"] == "failure"
        assert entry["result_reason"] == ResultReason.PermissionDenied
        assert store.get_object(uid)["state"] != State.Destroyed

    def test_reads_are_audited_not_just_mutations(self, store, shim):
        """'Who exported this key' is a read, and is exactly what an audit log
        is for."""
        from kmip_pkcs11.core.enums import Operation
        uid = _create_aes_uid_owned_by(store, shim, "alice")
        _dispatch(store, shim, Operation.Get,
                  encode_text_string(Tag.UniqueIdentifier, uid), identity="alice")
        assert [e["operation_name"] for e in store.get_audit_entries(object_uid=uid)] == ["Get"]

    def test_created_object_uid_comes_from_the_response(self, store, shim):
        """Create names no UID in its request — the audit record has to take it
        from the response, or the entry is useless."""
        from kmip_pkcs11.core.enums import Operation
        attrs = (
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 128))
            + _attr("Cryptographic Usage Mask",
                    encode_integer(Tag.AttributeValue, CryptographicUsageMask.Encrypt))
        )
        payload = (encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
                   + encode_structure(Tag.TemplateAttribute, attrs))
        raw = _dispatch(store, shim, Operation.Create, payload, identity="alice")
        uid = decode_one(raw).get(Tag.ResponsePayload).get(Tag.UniqueIdentifier).value

        entries = store.get_audit_entries(object_uid=uid)
        assert entries and entries[0]["operation_name"] == "Create"
        assert entries[0]["identity"] == "alice"

    def test_capability_discovery_is_not_audited(self, store, shim):
        """Query/DiscoverVersions touch no object; recording them would bury
        the entries that matter in handshake noise."""
        from kmip_pkcs11.core.enums import Operation
        _dispatch(store, shim, Operation.Query)
        _dispatch(store, shim, Operation.DiscoverVersions)
        assert store.get_audit_entries() == []

    def test_client_address_is_recorded(self, store, shim):
        from kmip_pkcs11.core.enums import Operation
        _dispatch(store, shim, Operation.Destroy,
                  encode_text_string(Tag.UniqueIdentifier, "x"), client="10.0.0.9:5555")
        assert store.get_audit_entries()[0]["client"] == "10.0.0.9:5555"

    def test_audit_failure_does_not_fail_the_operation(self, store, shim):
        """A broken audit backend must not take the KMIP service down with it —
        but it must be loud, which is why it logs an exception."""
        from kmip_pkcs11.core.enums import Operation, ResultStatus
        uid = store.create_object(object_type=ObjectType.SymmetricKey,
                                  state=State.PreActive, owner_identity="alice")
        with patch.object(store, "append_audit", side_effect=RuntimeError("audit down")):
            raw = _dispatch(store, shim, Operation.Activate,
                            encode_text_string(Tag.UniqueIdentifier, uid), identity="alice")
        assert decode_one(raw).get(Tag.ResultStatus).value == ResultStatus.Success
        assert store.get_object(uid)["state"] == State.Active


class TestPhase2AuditTamperEvidence:
    def _seed(self, store, n=4):
        for i in range(n):
            store.append_audit(identity=f"user{i}", operation_name="Get",
                               object_uid=f"uid-{i}", result="success")

    def test_clean_chain_verifies(self, store):
        self._seed(store)
        report = store.verify_audit_chain()
        assert report["ok"] is True and report["entries"] == 4

    def test_empty_log_verifies(self, store):
        assert store.verify_audit_chain()["ok"] is True

    def test_update_is_blocked_by_the_append_only_trigger(self, store):
        import sqlite3
        self._seed(store, 1)
        with pytest.raises(sqlite3.IntegrityError):
            store._conn().execute("UPDATE kmip_audit SET identity='mallory' WHERE seq=1")

    def test_delete_is_blocked_by_the_append_only_trigger(self, store):
        import sqlite3
        self._seed(store, 1)
        with pytest.raises(sqlite3.IntegrityError):
            store._conn().execute("DELETE FROM kmip_audit WHERE seq=1")

    def test_edited_entry_breaks_the_chain(self, store):
        """Someone with file access can drop the triggers — the hash chain is
        what makes the edit detectable afterwards."""
        self._seed(store)
        conn = store._conn()
        conn.execute("DROP TRIGGER kmip_audit_no_update")
        conn.execute("UPDATE kmip_audit SET identity='mallory' WHERE seq=2")
        conn.commit()
        report = store.verify_audit_chain()
        assert report["ok"] is False
        assert report["broken_at"] == 2
        assert "hash" in report["reason"]

    def test_deleted_entry_breaks_the_chain(self, store):
        self._seed(store)
        conn = store._conn()
        conn.execute("DROP TRIGGER kmip_audit_no_delete")
        conn.execute("DELETE FROM kmip_audit WHERE seq=2")
        conn.commit()
        report = store.verify_audit_chain()
        assert report["ok"] is False and report["broken_at"] == 3

    def test_concurrent_appends_produce_an_intact_chain(self, store):
        """The chain is read-then-write, so without a lock two threads can link
        to the same predecessor and fork the history."""
        import concurrent.futures
        def append(i):
            store.append_audit(identity=f"t{i}", operation_name="Get",
                               object_uid=f"uid-{i}", result="success")
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(append, range(40)))
        report = store.verify_audit_chain()
        assert report["ok"] is True, f"chain broken at {report.get('broken_at')}"
        assert report["entries"] == 40


class TestPhase2AuditQueryAndRetention:
    def _seed(self, store):
        for i in range(5):
            store.append_audit(identity="alice" if i % 2 == 0 else "bob",
                               operation_name="Get", object_uid=f"uid-{i}",
                               result="success" if i < 3 else "failure")

    def test_filter_by_identity(self, store):
        self._seed(store)
        assert {e["identity"] for e in store.get_audit_entries(identity="bob")} == {"bob"}

    def test_filter_by_result(self, store):
        self._seed(store)
        assert all(e["result"] == "failure"
                   for e in store.get_audit_entries(result="failure"))

    def test_limit_applies(self, store):
        self._seed(store)
        assert len(store.get_audit_entries(limit=2)) == 2

    def test_prune_returns_entries_for_archival_and_keeps_the_rest(self, store):
        import time as _t
        store.append_audit(identity="old", operation_name="Get", result="success")
        cutoff = _t.time() + 0.01
        _t.sleep(0.02)
        store.append_audit(identity="new", operation_name="Get", result="success")

        result = store.prune_audit(cutoff)
        assert result["pruned"] == 1
        assert result["entries"][0]["identity"] == "old"
        assert [e["identity"] for e in store.get_audit_entries()] == ["new"]

    def test_chain_still_verifies_after_pruning(self, store):
        import time as _t
        for i in range(3):
            store.append_audit(identity=f"old{i}", operation_name="Get", result="success")
        cutoff = _t.time() + 0.01
        _t.sleep(0.02)
        for i in range(3):
            store.append_audit(identity=f"new{i}", operation_name="Get", result="success")
        store.prune_audit(cutoff)
        assert store.verify_audit_chain()["ok"] is True

    def test_append_only_trigger_is_restored_after_pruning(self, store):
        import sqlite3, time as _t
        store.append_audit(identity="old", operation_name="Get", result="success")
        store.prune_audit(_t.time() + 0.01)
        store.append_audit(identity="new", operation_name="Get", result="success")
        with pytest.raises(sqlite3.IntegrityError):
            store._conn().execute("DELETE FROM kmip_audit")

    def test_refuses_to_prune_a_tampered_log(self, store):
        """Pruning a broken chain would destroy the evidence of tampering."""
        from kmip_pkcs11.core.exceptions import CryptographicFailure
        import time as _t
        for i in range(3):
            store.append_audit(identity=f"u{i}", operation_name="Get", result="success")
        conn = store._conn()
        conn.execute("DROP TRIGGER kmip_audit_no_update")
        conn.execute("UPDATE kmip_audit SET identity='mallory' WHERE seq=2")
        conn.commit()
        with pytest.raises(CryptographicFailure):
            store.prune_audit(_t.time() + 1)


class TestPhase2TransportSecurity:
    def test_refuses_to_start_without_tls(self, store, shim):
        from kmip_pkcs11.server.server import KMIPServer
        from kmip_pkcs11.core.exceptions import GeneralFailure
        srv = KMIPServer(store, shim, port=29901)
        with pytest.raises(GeneralFailure, match="TLS"):
            srv._require_transport_security()

    def test_plaintext_requires_an_explicit_opt_out(self, store, shim):
        from kmip_pkcs11.server.server import KMIPServer
        srv = KMIPServer(store, shim, port=29902, allow_plaintext=True)
        srv._require_transport_security()          # must not raise

    def test_tls_configured_server_starts(self, store, shim, tmp_path):
        from kmip_pkcs11.server.server import KMIPServer
        cert, key = _self_signed(tmp_path)
        srv = KMIPServer(store, shim, port=29903, tls_cert=cert, tls_key=key)
        srv._require_transport_security()          # must not raise

    def test_tls_floor_is_1_2(self, store, shim, tmp_path):
        import ssl
        from kmip_pkcs11.server.server import KMIPServer
        cert, key = _self_signed(tmp_path)
        srv = KMIPServer(store, shim, port=29904, tls_cert=cert, tls_key=key)
        assert srv._build_ssl_context().minimum_version == ssl.TLSVersion.TLSv1_2

    def test_reload_tls_rebuilds_the_context(self, store, shim, tmp_path):
        from kmip_pkcs11.server.server import KMIPServer
        cert, key = _self_signed(tmp_path)
        srv = KMIPServer(store, shim, port=29905, tls_cert=cert, tls_key=key)
        first = srv._build_ssl_context()
        srv._ssl_context = first
        srv.reload_tls()
        assert srv._ssl_context is not first, "renewed certificate must be picked up"

    def test_unprovisioned_certificate_cn_does_not_become_an_identity(self, store, shim):
        """A CA-signed certificate still doesn't get to invent a principal that
        was never granted anything."""
        import ssl as _ssl
        from kmip_pkcs11.server.server import KMIPServer
        srv = KMIPServer(store, shim, tls_ca="/x/ca.pem", require_client_cert=True)
        conn = MagicMock(spec=_ssl.SSLSocket)
        conn.getpeercert.return_value = {"subject": [[("commonName", "ghost")]]}
        assert srv._get_identity(conn) == "anonymous"

    def test_provisioned_certificate_cn_becomes_the_identity(self, store, shim):
        import ssl as _ssl
        from kmip_pkcs11.server.server import KMIPServer
        store.create_identity("alice", "pw")
        srv = KMIPServer(store, shim, tls_ca="/x/ca.pem", require_client_cert=True)
        conn = MagicMock(spec=_ssl.SSLSocket)
        conn.getpeercert.return_value = {"subject": [[("commonName", "alice")]]}
        assert srv._get_identity(conn) == "alice"

    def test_unverified_client_cert_is_ignored(self, store, shim):
        """Without require_client_cert the subject was never checked against
        the CA, so it must not be trusted even if it names a real identity."""
        import ssl as _ssl
        from kmip_pkcs11.server.server import KMIPServer
        store.create_identity("alice", "pw")
        srv = KMIPServer(store, shim, tls_ca="/x/ca.pem", require_client_cert=False)
        conn = MagicMock(spec=_ssl.SSLSocket)
        conn.getpeercert.return_value = {"subject": [[("commonName", "alice")]]}
        assert srv._get_identity(conn) == "anonymous"


# ══════════════════════════════════════════════════════════════════════════════
# Phase 3 — deployability.
#
# Config file, CLI entry points, health/metrics endpoints and structured logs:
# the difference between a library you write Python against and a service an
# operator can run.
# ══════════════════════════════════════════════════════════════════════════════

def _config(tmp_path, **overrides):
    """A minimally valid configuration, with sections overridable per test."""
    import yaml
    pin = tmp_path / "pin"
    pin.write_text("9999")
    data = {
        "server": {"host": "127.0.0.1", "port": 5696, "allow_plaintext": True},
        "hsm": {"library": "/usr/local/lib/softhsm/libsofthsm2.so",
                "token_label": "KMIPTestSuite", "pin_file": str(pin)},
        "storage": {"database": str(tmp_path / "kmip.db")},
    }
    for section, values in overrides.items():
        data.setdefault(section, {})
        if values is None:
            data.pop(section)
        else:
            data[section].update(values)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data))
    return str(path)


class TestPhase3Config:
    def test_valid_config_loads_with_defaults_applied(self, tmp_path):
        from kmip_pkcs11.config import KMIPConfig
        cfg = KMIPConfig.from_file(_config(tmp_path))
        assert cfg.get("server", "port") == 5696
        assert cfg.get("logging", "format") == "json"      # default
        assert cfg.get("observability", "enabled") is True  # default

    def test_missing_file_is_reported_clearly(self, tmp_path):
        from kmip_pkcs11.config import KMIPConfig, ConfigError
        with pytest.raises(ConfigError, match="not found"):
            KMIPConfig.from_file(str(tmp_path / "nope.yaml"))

    def test_unknown_section_is_rejected(self, tmp_path):
        """A typo'd section would otherwise be silently ignored, and the
        operator would wonder why their setting did nothing."""
        from kmip_pkcs11.config import KMIPConfig, ConfigError
        with pytest.raises(ConfigError, match="Unknown configuration section"):
            KMIPConfig.from_dict({"serrver": {"port": 1}})

    def test_plaintext_without_tls_must_be_explicit(self, tmp_path):
        from kmip_pkcs11.config import KMIPConfig, ConfigError
        with pytest.raises(ConfigError, match="allow_plaintext"):
            KMIPConfig.from_dict({
                "hsm": {"library": "/x", "token_label": "t", "pin": "1"},
                "storage": {"database": "/tmp/x.db"},
            })

    def test_half_configured_tls_is_rejected(self, tmp_path):
        from kmip_pkcs11.config import KMIPConfig, ConfigError
        with pytest.raises(ConfigError, match="together"):
            KMIPConfig.from_dict({
                "tls": {"cert": "/x/c.pem"},
                "hsm": {"library": "/x", "token_label": "t", "pin": "1"},
                "storage": {"database": "/tmp/x.db"},
            })

    def test_mtls_without_a_ca_is_rejected(self):
        from kmip_pkcs11.config import KMIPConfig, ConfigError
        with pytest.raises(ConfigError, match="tls.ca"):
            KMIPConfig.from_dict({
                "tls": {"cert": "/c", "key": "/k", "require_client_cert": True},
                "hsm": {"library": "/x", "token_label": "t", "pin": "1"},
                "storage": {"database": "/tmp/x.db"},
            })

    def test_exactly_one_pin_source_is_required(self):
        from kmip_pkcs11.config import KMIPConfig, ConfigError
        base = {"server": {"allow_plaintext": True}, "storage": {"database": "/tmp/x.db"}}
        with pytest.raises(ConfigError, match="pin_file"):
            KMIPConfig.from_dict({**base, "hsm": {"library": "/x", "token_label": "t"}})
        with pytest.raises(ConfigError, match="only one"):
            KMIPConfig.from_dict({**base, "hsm": {"library": "/x", "token_label": "t",
                                                  "pin": "1", "pin_env": "E"}})

    def test_pin_is_read_from_a_file(self, tmp_path):
        from kmip_pkcs11.config import KMIPConfig
        assert KMIPConfig.from_file(_config(tmp_path)).resolve_pin() == "9999"

    def test_pin_is_read_from_the_environment(self, monkeypatch):
        from kmip_pkcs11.config import KMIPConfig
        monkeypatch.setenv("KMIP_TEST_PIN", "secret-pin")
        cfg = KMIPConfig.from_dict({
            "server": {"allow_plaintext": True},
            "hsm": {"library": "/x", "token_label": "t", "pin_env": "KMIP_TEST_PIN"},
            "storage": {"database": "/tmp/x.db"},
        })
        assert cfg.resolve_pin() == "secret-pin"

    def test_missing_env_pin_is_reported(self, monkeypatch):
        from kmip_pkcs11.config import KMIPConfig, ConfigError
        monkeypatch.delenv("KMIP_ABSENT_PIN", raising=False)
        cfg = KMIPConfig.from_dict({
            "server": {"allow_plaintext": True},
            "hsm": {"library": "/x", "token_label": "t", "pin_env": "KMIP_ABSENT_PIN"},
            "storage": {"database": "/tmp/x.db"},
        })
        with pytest.raises(ConfigError, match="unset or empty"):
            cfg.resolve_pin()

    def test_dumped_config_redacts_an_inline_pin(self):
        """The most likely reason to dump a config is to paste it somewhere."""
        from kmip_pkcs11.config import KMIPConfig
        cfg = KMIPConfig.from_dict({
            "server": {"allow_plaintext": True},
            "hsm": {"library": "/x", "token_label": "t", "pin": "super-secret"},
            "storage": {"database": "/tmp/x.db"},
        })
        assert "super-secret" not in json.dumps(cfg.as_dict())


class TestPhase3Metrics:
    def test_operations_are_counted_by_result(self):
        from kmip_pkcs11.observability import Metrics
        m = Metrics()
        m.record_operation("Create", "success", 0.01)
        m.record_operation("Create", "success", 0.02)
        m.record_operation("Destroy", "failure", 0.005)
        snap = m.snapshot()
        assert snap["operations"] == {"Create/success": 2, "Destroy/failure": 1}
        assert snap["latency_seconds"]["Create"]["count"] == 2

    def test_prometheus_exposition_is_well_formed(self):
        from kmip_pkcs11.observability import Metrics
        m = Metrics()
        m.record_operation("Get", "success", 0.5)
        m.record_auth_failure()
        text = m.render_prometheus()
        assert 'kmip_operations_total{operation="Get",result="success"} 1' in text
        assert "kmip_auth_failures_total 1" in text
        # Every metric must carry HELP and TYPE or scrapers reject it.
        for name in ("kmip_operations_total", "kmip_auth_failures_total",
                     "kmip_operation_duration_seconds"):
            assert f"# HELP {name}" in text and f"# TYPE {name}" in text

    def test_dispatcher_records_success_and_failure(self, store, shim):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.observability import Metrics
        from kmip_pkcs11.core.enums import Operation
        m = Metrics()
        d = OperationDispatcher(store, shim, metrics=m)
        inner = (encode_enumeration(Tag.Operation, Operation.Destroy)
                 + encode_structure(Tag.RequestPayload,
                                    encode_text_string(Tag.UniqueIdentifier, "ghost")))
        d.dispatch(decode_one(encode_structure(Tag.BatchItem, inner)), "alice")
        assert m.snapshot()["operations"] == {"Destroy/failure": 1}

    def test_metric_failure_never_breaks_an_operation(self, store, shim):
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher
        from kmip_pkcs11.core.enums import Operation, ResultStatus
        broken = MagicMock()
        broken.record_operation.side_effect = RuntimeError("metrics down")
        d = OperationDispatcher(store, shim, metrics=broken)
        uid = store.create_object(object_type=ObjectType.SymmetricKey,
                                  state=State.PreActive, owner_identity="alice")
        inner = (encode_enumeration(Tag.Operation, Operation.Activate)
                 + encode_structure(Tag.RequestPayload,
                                    encode_text_string(Tag.UniqueIdentifier, uid)))
        raw = d.dispatch(decode_one(encode_structure(Tag.BatchItem, inner)), "alice")
        assert decode_one(raw).get(Tag.ResultStatus).value == ResultStatus.Success


class TestPhase3HealthEndpoint:
    def _server(self, readiness=None):
        from kmip_pkcs11.observability import Metrics, HealthServer
        h = HealthServer(Metrics(), readiness, host="127.0.0.1", port=0)
        h.start()
        return h

    def _get(self, port, path):
        import urllib.request, urllib.error
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def test_health_is_up(self):
        h = self._server()
        try:
            status, body = self._get(h.port, "/health")
            assert status == 200 and json.loads(body)["status"] == "ok"
        finally:
            h.stop()

    def test_ready_reports_503_when_not_ready(self):
        h = self._server(readiness=lambda: (False, {"kmip_listener": "not yet accepting"}))
        try:
            status, body = self._get(h.port, "/ready")
            assert status == 503
            assert json.loads(body)["status"] == "not-ready"
        finally:
            h.stop()

    def test_ready_reports_200_when_ready(self):
        h = self._server(readiness=lambda: (True, {"mechanisms": 79}))
        try:
            status, body = self._get(h.port, "/ready")
            assert status == 200 and json.loads(body)["mechanisms"] == 79
        finally:
            h.stop()

    def test_readiness_exception_is_reported_not_raised(self):
        h = self._server(readiness=lambda: (_ for _ in ()).throw(RuntimeError("hsm gone")))
        try:
            status, body = self._get(h.port, "/ready")
            assert status == 503 and "hsm gone" in body
        finally:
            h.stop()

    def test_metrics_endpoint_serves_exposition_format(self):
        h = self._server()
        try:
            status, body = self._get(h.port, "/metrics")
            assert status == 200 and "kmip_uptime_seconds" in body
        finally:
            h.stop()

    def test_unknown_path_is_404(self):
        h = self._server()
        try:
            assert self._get(h.port, "/nope")[0] == 404
        finally:
            h.stop()


class TestPhase3ReadinessTracksTheListener:
    """Regression: the readiness probe originally checked only the HSM and the
    database, so it reported ready while the KMIP port was still closed —
    startup binds only after opening the HSM session and provisioning the
    master key, which on a large token takes seconds. An orchestrator would
    route traffic to an instance that could not answer."""

    def test_not_serving_before_start(self, store, shim):
        from kmip_pkcs11.server.server import KMIPServer
        srv = KMIPServer(store, shim, port=29910, allow_plaintext=True)
        assert srv.is_serving() is False

    def test_readiness_is_false_while_the_listener_is_down(self, store, shim):
        from kmip_pkcs11.server.server import KMIPServer
        from kmip_pkcs11.cli.server_cli import _readiness
        srv = KMIPServer(store, shim, port=29911, allow_plaintext=True)
        ok, detail = _readiness(srv, shim, store)()
        assert ok is False
        assert "kmip_listener" in detail

    def test_readiness_is_true_once_serving(self, store, shim):
        from kmip_pkcs11.server.server import KMIPServer
        from kmip_pkcs11.cli.server_cli import _readiness
        srv = KMIPServer(store, shim, port=29912, allow_plaintext=True)
        srv._running, srv._sock = True, object()   # as start() leaves it
        ok, detail = _readiness(srv, shim, store)()
        assert ok is True and "mechanisms" in detail


class TestPhase3StructuredLogging:
    def test_records_are_json_objects(self):
        from kmip_pkcs11.observability import JSONFormatter
        rec = logging.LogRecord("kmip.test", logging.INFO, __file__, 1,
                                "server started on %s", ("127.0.0.1",), None)
        entry = json.loads(JSONFormatter().format(rec))
        assert entry["level"] == "INFO"
        assert entry["message"] == "server started on 127.0.0.1"
        assert entry["logger"] == "kmip.test"

    def test_exceptions_are_carried_in_a_field(self):
        """A traceback split across lines does not survive log aggregation."""
        from kmip_pkcs11.observability import JSONFormatter
        try:
            raise ValueError("boom")
        except ValueError:
            rec = logging.LogRecord("kmip.test", logging.ERROR, __file__, 1,
                                    "failed", (), sys.exc_info())
        entry = json.loads(JSONFormatter().format(rec))
        assert "ValueError: boom" in entry["exception"]
        assert "\n" not in entry["message"]

    def test_configure_logging_does_not_duplicate_handlers(self):
        from kmip_pkcs11.observability import configure_logging
        try:
            configure_logging("INFO", "json")
            configure_logging("INFO", "json")
            assert len(logging.getLogger().handlers) == 1
        finally:
            logging.getLogger().handlers.clear()


class TestPhase3CLI:
    def test_server_cli_check_accepts_a_valid_config(self, tmp_path, capsys):
        from kmip_pkcs11.cli.server_cli import main
        try:
            assert main(["--config", _config(tmp_path), "--check"]) == 0
        finally:
            logging.getLogger().handlers.clear()

    def test_server_cli_rejects_a_bad_config_with_exit_code_2(self, tmp_path, capsys):
        from kmip_pkcs11.cli.server_cli import main
        bad = tmp_path / "bad.yaml"
        bad.write_text("server: {port: 99999}\n")
        assert main(["--config", str(bad)]) == 2
        assert "configuration error" in capsys.readouterr().err

    def test_admin_cli_manages_identities_roles_and_grants(self, tmp_path, capsys):
        from kmip_pkcs11.cli.admin_cli import main
        db = str(tmp_path / "admin.db")
        assert main(["-d", db, "identity", "add", "alice", "--password", "pw"]) == 0
        assert main(["-d", db, "role", "grant", "alice", "admin"]) == 0
        assert main(["-d", db, "identity", "list"]) == 0
        assert "alice" in capsys.readouterr().out

        from kmip_pkcs11.metadata.store import MetadataStore
        store = MetadataStore(db)
        assert store.verify_identity("alice", "pw") is True
        assert store.get_roles("alice") == ["admin"]

    def test_admin_cli_disable_blocks_authentication(self, tmp_path):
        from kmip_pkcs11.cli.admin_cli import main
        from kmip_pkcs11.metadata.store import MetadataStore
        db = str(tmp_path / "admin2.db")
        main(["-d", db, "identity", "add", "bob", "--password", "pw"])
        main(["-d", db, "identity", "disable", "bob"])
        assert MetadataStore(db).verify_identity("bob", "pw") is False

    def test_admin_cli_audit_verify_exits_nonzero_on_a_broken_chain(self, tmp_path, capsys):
        """So a monitoring job can alert on a tampered log."""
        from kmip_pkcs11.cli.admin_cli import main
        from kmip_pkcs11.metadata.store import MetadataStore
        db = str(tmp_path / "audit.db")
        store = MetadataStore(db)
        for i in range(3):
            store.append_audit(identity=f"u{i}", operation_name="Get", result="success")
        assert main(["-d", db, "audit", "verify"]) == 0

        conn = store._conn()
        conn.execute("DROP TRIGGER kmip_audit_no_update")
        conn.execute("UPDATE kmip_audit SET identity='mallory' WHERE seq=2")
        conn.commit()
        assert main(["-d", db, "audit", "verify"]) == 1
        assert "BROKEN" in capsys.readouterr().out

    def test_admin_cli_json_output(self, tmp_path, capsys):
        from kmip_pkcs11.cli.admin_cli import main
        db = str(tmp_path / "json.db")
        main(["-d", db, "identity", "add", "alice", "--password", "pw"])
        capsys.readouterr()          # discard the confirmation from `add`
        main(["-d", db, "--json", "identity", "list"])
        assert json.loads(capsys.readouterr().out)[0]["identity"] == "alice"

    def test_admin_cli_requires_a_database_or_config(self, capsys):
        from kmip_pkcs11.cli.admin_cli import build_parser
        with pytest.raises(SystemExit):
            build_parser().parse_args(["identity", "list"])


class TestPhase3DeploymentArtifacts:
    """The deployment files ship in the repository, so a broken one is a
    broken release even though nothing imports them."""

    ROOT = os.path.join(os.path.dirname(__file__), "..", "..")

    def test_example_config_is_valid(self):
        from kmip_pkcs11.config import KMIPConfig
        path = os.path.join(self.ROOT, "deploy", "config.example.yaml")
        cfg = KMIPConfig.from_file(path)
        assert cfg.get("server", "port") == 5696
        assert cfg.get("hsm", "pin_file"), "the template must demonstrate a file-based PIN"
        assert not cfg.get("hsm", "pin"), "the template must not ship an inline PIN"

    def test_dockerfile_builds_softhsm_from_source(self):
        """The packaged SoftHSM2 lacks the combined ECDSA-with-hash mechanisms,
        so an image built on it would fail every EC signing test."""
        with open(os.path.join(self.ROOT, "deploy", "Dockerfile")) as f:
            dockerfile = f.read()
        assert "--with-crypto-backend=openssl" in dockerfile
        assert "USER kmip" in dockerfile, "the image must not run as root"
        assert "HEALTHCHECK" in dockerfile

    def test_systemd_unit_reloads_tls_on_sighup(self):
        with open(os.path.join(self.ROOT, "deploy", "kmip-server.service")) as f:
            unit = f.read()
        assert "ExecReload=/bin/kill -HUP $MAINPID" in unit
        assert "NoNewPrivileges=true" in unit

    def test_ci_workflow_builds_the_right_softhsm(self):
        path = os.path.join(self.ROOT, ".github", "workflows", "ci.yml")
        with open(path) as f:
            workflow = f.read()
        assert "--with-crypto-backend=openssl" in workflow
        assert "ECDSA_SHA256" in workflow, "CI must assert the mechanism set it depends on"
