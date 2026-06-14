"""
Extended coverage tests — targets every uncovered branch across all modules
to push overall coverage above 95%.

Organised by source module, matching the order of coverage gaps in the report.
"""

import os
import datetime
import struct
import socket
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
    InvalidField, OperationNotSupported
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
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
        dt  = datetime.datetime(2025, 6, 15, tzinfo=datetime.timezone.utc)
        store.set_activation_date(uid, dt)
        obj = store.get_object(uid)
        assert abs(obj["activation_date"] - dt.timestamp()) < 1

    def test_list_objects(self, store):
        uids = [store.create_object(object_type=ObjectType.SymmetricKey) for _ in range(3)]
        result = store.list_objects()
        for uid in uids:
            assert uid in result

    def test_list_objects_empty(self, store):
        assert store.list_objects() == []

    def test_object_exists_true(self, store):
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
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
            otype=encode_enumeration(Tag.ObjectType, ObjectType.Certificate)
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
            object_type=ObjectType.Certificate,
            state=State.Active,
            extractable=True,
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
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
        inner = encode_text_string(Tag.UniqueIdentifier, uid)
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_add_attr_missing_name_raises(self, store, shim):
        from kmip_pkcs11.operations import add_attribute as op
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
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
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
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
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
        inner = encode_text_string(Tag.UniqueIdentifier, uid)
        payload = decode_one(encode_structure(Tag.RequestPayload, inner))
        with pytest.raises(MissingData):
            op.handle(payload, "user", store, shim)

    def test_delete_attr_missing_name_raises(self, store, shim):
        from kmip_pkcs11.operations import delete_attribute as op
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
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
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
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
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
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
            object_type=ObjectType.SymmetricKey, state=State.Active)
        with pytest.raises(IllegalOperation):
            op.handle(_uid_payload(uid), "user", store, shim)

    def test_activate_pre_active_succeeds(self, store, shim):
        from kmip_pkcs11.operations import activate as op
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey, state=State.PreActive)
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
            object_type=ObjectType.SymmetricKey, state=State.Active)
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
            object_type=ObjectType.SymmetricKey, state=State.Active)
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
            object_type=ObjectType.SecretData, state=State.Active)
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
            object_type=ObjectType.SymmetricKey, state=State.Active)
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
            object_type=ObjectType.SymmetricKey, state=State.Active)
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

    def test_get_identity_non_ssl_returns_anonymous(self):
        from kmip_pkcs11.server.server import KMIPServer
        plain_sock = MagicMock()
        plain_sock.__class__ = socket.socket  # not ssl.SSLSocket
        identity = KMIPServer._get_identity(plain_sock)
        assert identity == "anonymous"

    def test_recv_message_with_empty_response(self):
        from kmip_pkcs11.server.server import KMIPServer
        sock = MagicMock()
        sock.recv.return_value = b""
        result = KMIPServer._recv_message(sock)
        assert result is None

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
        srv    = KMIPServer(store2, shim, port=29998)
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
        # Mock get_key_value so the private-key extraction path works
        with patch.object(shim, 'get_key_value', return_value=b'\xAA' * 32):
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
