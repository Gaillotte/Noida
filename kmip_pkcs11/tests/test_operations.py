"""Integration tests: operations against the live PKCS#11 shim + metadata store."""

import os
import pytest
from kmip_pkcs11.core.enums import (
    CryptographicAlgorithm, ObjectType, State,
    CryptographicUsageMask, RevocationReasonCode
)
from kmip_pkcs11.core.exceptions import (
    ItemNotFound, IllegalOperation, NotExtractable
)


class TestCreate:
    def test_create_aes256(self, store, shim):
        from kmip_pkcs11.operations import create as create_mod
        from kmip_pkcs11.core.enums import Tag
        from kmip_pkcs11.core.ttlv import (
            encode_structure, encode_enumeration, encode_integer, encode_text_string,
            decode_one
        )

        attrs = (
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
            + _attr("Cryptographic Length",
                    encode_integer(Tag.AttributeValue, 256))
            + _attr("Cryptographic Usage Mask",
                    encode_integer(Tag.AttributeValue,
                                   CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt))
            + _attr("Extractable", encode_integer(Tag.AttributeValue, 1))
        )
        tmpl    = encode_structure(Tag.TemplateAttribute, attrs)
        payload_bytes = encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey) + tmpl
        payload = decode_one(encode_structure(Tag.RequestPayload, payload_bytes))

        resp_bytes = create_mod.handle(payload, "test_user", store, shim)
        resp       = decode_one(encode_structure(Tag.ResponsePayload, resp_bytes))
        uid_item   = resp.get(Tag.UniqueIdentifier)
        assert uid_item is not None
        uid = uid_item.value

        obj = store.get_object(uid)
        assert obj is not None
        assert obj["cryptographic_algorithm"] == CryptographicAlgorithm.AES
        assert obj["cryptographic_length"]    == 256
        assert obj["state"]                   == State.Active

    def test_create_aes128(self, store, shim):
        from kmip_pkcs11.operations import create as create_mod
        from kmip_pkcs11.core.enums import Tag
        from kmip_pkcs11.core.ttlv import (
            encode_structure, encode_enumeration, encode_integer, decode_one
        )

        attrs = (
            _attr("Cryptographic Algorithm",
                  encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
            + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, 128))
            + _attr("Cryptographic Usage Mask",
                    encode_integer(Tag.AttributeValue, CryptographicUsageMask.Encrypt))
        )
        payload_bytes = (
            encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
            + encode_structure(Tag.TemplateAttribute, attrs)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, payload_bytes))
        resp_bytes = create_mod.handle(payload, "user", store, shim)
        resp       = decode_one(encode_structure(Tag.ResponsePayload, resp_bytes))
        uid = resp.get(Tag.UniqueIdentifier).value
        assert store.get_object(uid) is not None


class TestDestroy:
    def test_destroy_existing(self, store, shim):
        uid = _create_aes(store, shim, 256)
        store.set_revoke(uid, State.Deactivated, 5)

        from kmip_pkcs11.operations import destroy as dest_mod
        from kmip_pkcs11.core.enums import Tag
        from kmip_pkcs11.core.ttlv import encode_text_string, encode_structure, decode_one

        payload_bytes = encode_text_string(Tag.UniqueIdentifier, uid)
        payload       = decode_one(encode_structure(Tag.RequestPayload, payload_bytes))
        dest_mod.handle(payload, "user", store, shim)

        obj = store.get_object(uid)
        assert obj["state"] == State.Destroyed

    def test_destroy_nonexistent_raises(self, store, shim):
        from kmip_pkcs11.operations import destroy as dest_mod
        from kmip_pkcs11.core.enums import Tag
        from kmip_pkcs11.core.ttlv import encode_text_string, encode_structure, decode_one

        payload_bytes = encode_text_string(Tag.UniqueIdentifier, "bad-uid")
        payload       = decode_one(encode_structure(Tag.RequestPayload, payload_bytes))
        with pytest.raises(ItemNotFound):
            dest_mod.handle(payload, "user", store, shim)


class TestLocateOperation:
    def test_locate_returns_created_key(self, store, shim):
        uid = _create_aes(store, shim, 256, name="locate-test-key")

        from kmip_pkcs11.operations import locate as loc_mod
        from kmip_pkcs11.core.enums import Tag
        from kmip_pkcs11.core.ttlv import (
            encode_enumeration, encode_structure, decode_one, encode_text_string
        )

        name_val  = encode_text_string(Tag.NameValue, "locate-test-key")
        name_attr = _attr("Name", encode_structure(Tag.AttributeValue, name_val))
        payload_bytes = encode_structure(Tag.Attributes, name_attr)
        payload       = decode_one(encode_structure(Tag.RequestPayload, payload_bytes))

        resp_bytes = loc_mod.handle(payload, "user", store, shim)
        # Parse all UniqueIdentifier items
        from kmip_pkcs11.core.ttlv import decode_all
        items = decode_all(resp_bytes)
        uids  = [i.value for i in items if i.tag == Tag.UniqueIdentifier]
        assert uid in uids


class TestEncryptDecrypt:
    def test_aes_cbc_roundtrip(self, store, shim):
        uid  = _create_aes(store, shim, 256)
        data = b"TestData" * 4  # 32 bytes

        from kmip_pkcs11.operations import encrypt as enc_mod, decrypt as dec_mod
        from kmip_pkcs11.core.enums import Tag
        from kmip_pkcs11.core.ttlv import (
            encode_text_string, encode_byte_string, encode_structure, decode_one, decode_all
        )

        iv = os.urandom(16)
        enc_payload_bytes = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_byte_string(Tag.Data, data)
            + encode_byte_string(Tag.IVCounterNonce, iv)
        )
        enc_payload = decode_one(encode_structure(Tag.RequestPayload, enc_payload_bytes))
        enc_resp    = enc_mod.handle(enc_payload, "user", store, shim)

        enc_items  = decode_all(enc_resp)
        ct_item    = next((i for i in enc_items if i.tag == Tag.Data), None)
        iv_out     = next((i for i in enc_items if i.tag == Tag.IVCounterNonce), None)
        assert ct_item is not None
        ct  = ct_item.value
        out_iv = iv_out.value if iv_out else iv

        dec_payload_bytes = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_byte_string(Tag.Data, ct)
            + encode_byte_string(Tag.IVCounterNonce, out_iv)
        )
        dec_payload = decode_one(encode_structure(Tag.RequestPayload, dec_payload_bytes))
        dec_resp    = dec_mod.handle(dec_payload, "user", store, shim)
        dec_items   = decode_all(dec_resp)
        pt_item     = next((i for i in dec_items if i.tag == Tag.Data), None)
        assert pt_item is not None
        assert pt_item.value == data


class TestActivateRevoke:
    def test_activate_pre_active_key(self, store, shim):
        # Create with Pre-Active state manually
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey,
            state=State.PreActive,
            cryptographic_algorithm=CryptographicAlgorithm.AES,
            cryptographic_length=128,
        )
        from kmip_pkcs11.operations import activate as act_mod
        from kmip_pkcs11.core.enums import Tag
        from kmip_pkcs11.core.ttlv import encode_text_string, encode_structure, decode_one

        payload = decode_one(encode_structure(
            Tag.RequestPayload, encode_text_string(Tag.UniqueIdentifier, uid)
        ))
        act_mod.handle(payload, "user", store, shim)
        assert store.get_object(uid)["state"] == State.Active

    def test_revoke_active_key(self, store, shim):
        uid = _create_aes(store, shim, 128)
        from kmip_pkcs11.operations import revoke as rev_mod
        from kmip_pkcs11.core.enums import Tag
        from kmip_pkcs11.core.ttlv import (
            encode_text_string, encode_structure, encode_enumeration, decode_one
        )

        rev_reason = encode_enumeration(Tag.RevocationReasonCode, RevocationReasonCode.Superseded)
        payload_bytes = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_structure(Tag.RevocationReason, rev_reason)
        )
        payload = decode_one(encode_structure(Tag.RequestPayload, payload_bytes))
        rev_mod.handle(payload, "user", store, shim)
        assert store.get_object(uid)["state"] == State.Deactivated


# ── helpers ──────────────────────────────────────────────────────────────────

def _attr(name, value_bytes):
    from kmip_pkcs11.core.enums import Tag
    from kmip_pkcs11.core.ttlv import encode_text_string, encode_structure
    return encode_structure(
        Tag.Attribute,
        encode_text_string(Tag.AttributeName, name) + value_bytes
    )


def _create_aes(store, shim, length, name=None, extractable=True) -> str:
    from kmip_pkcs11.operations import create as create_mod
    from kmip_pkcs11.core.enums import Tag
    from kmip_pkcs11.core.ttlv import (
        encode_structure, encode_enumeration, encode_integer,
        encode_text_string, decode_one
    )
    attrs = (
        _attr("Cryptographic Algorithm",
              encode_enumeration(Tag.AttributeValue, CryptographicAlgorithm.AES))
        + _attr("Cryptographic Length", encode_integer(Tag.AttributeValue, length))
        + _attr("Cryptographic Usage Mask",
                encode_integer(Tag.AttributeValue,
                               CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt))
        + _attr("Extractable", encode_integer(Tag.AttributeValue, int(extractable)))
    )
    if name:
        nv    = encode_text_string(Tag.NameValue, name)
        attrs += _attr("Name", encode_structure(Tag.AttributeValue, nv))

    payload_bytes = (
        encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
        + encode_structure(Tag.TemplateAttribute, attrs)
    )
    payload    = decode_one(encode_structure(Tag.RequestPayload, payload_bytes))
    resp_bytes = create_mod.handle(payload, "test_user", store, shim)
    resp       = decode_one(encode_structure(Tag.ResponsePayload, resp_bytes))
    return resp.get(Tag.UniqueIdentifier).value
