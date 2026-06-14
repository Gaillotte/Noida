"""Unit tests for the MetadataStore."""

import pytest
from kmip_pkcs11.core.enums import ObjectType, State, CryptographicAlgorithm
from kmip_pkcs11.metadata.store import MetadataStore


@pytest.fixture
def store(tmp_path):
    return MetadataStore(str(tmp_path / "meta.db"))


class TestCreateObject:
    def test_create_returns_uuid(self, store):
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
        assert len(uid) == 36
        assert uid.count("-") == 4

    def test_created_object_retrievable(self, store):
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey,
            cryptographic_algorithm=CryptographicAlgorithm.AES,
            cryptographic_length=256,
        )
        obj = store.get_object(uid)
        assert obj is not None
        assert obj["object_type"]            == ObjectType.SymmetricKey
        assert obj["cryptographic_algorithm"] == CryptographicAlgorithm.AES
        assert obj["cryptographic_length"]    == 256

    def test_default_state_is_pre_active(self, store):
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
        obj = store.get_object(uid)
        assert obj["state"] == State.PreActive

    def test_create_with_names(self, store):
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey,
            names=["mykey", "alias"]
        )
        attrs = store.get_attribute(uid, "Name")
        values = [a["value"] for a in attrs]
        assert "mykey" in values
        assert "alias" in values

    def test_nonexistent_object_returns_none(self, store):
        assert store.get_object("does-not-exist") is None


class TestStateTransitions:
    def test_activate(self, store):
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
        store.activate(uid)
        assert store.get_object(uid)["state"] == State.Active

    def test_set_state(self, store):
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
        store.set_state(uid, State.Compromised)
        assert store.get_object(uid)["state"] == State.Compromised

    def test_set_destroy(self, store):
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
        store.set_destroy(uid)
        obj = store.get_object(uid)
        assert obj["state"]        == State.Destroyed
        assert obj["pkcs11_handle"] is None
        assert obj["destroy_date"]  is not None

    def test_revoke_normal(self, store):
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
        store.activate(uid)
        store.set_revoke(uid, State.Deactivated, reason=5)
        obj = store.get_object(uid)
        assert obj["state"]             == State.Deactivated
        assert obj["revocation_reason"] == 5
        assert obj["deactivation_date"] is not None

    def test_revoke_compromise(self, store):
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
        store.set_revoke(uid, State.Compromised, reason=2, message="test")
        obj = store.get_object(uid)
        assert obj["state"]             == State.Compromised
        assert obj["revocation_message"] == "test"
        assert obj["compromise_date"]   is not None


class TestAttributes:
    def test_add_and_get_attribute(self, store):
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
        store.add_attribute(uid, "x-project", "KMIP-Test")
        attrs = store.get_attribute(uid, "x-project")
        assert attrs[0] == "KMIP-Test"

    def test_add_multiple_values(self, store):
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
        store.add_attribute(uid, "tag", "v1")
        store.add_attribute(uid, "tag", "v2")
        attrs = store.get_attribute(uid, "tag")
        assert len(attrs) == 2

    def test_delete_attribute(self, store):
        uid = store.create_object(object_type=ObjectType.SymmetricKey)
        store.add_attribute(uid, "x-tmp", "remove-me")
        store.delete_attribute(uid, "x-tmp", 0)
        assert store.get_attribute(uid, "x-tmp") == []


class TestLocate:
    def test_locate_by_type(self, store):
        uid1 = store.create_object(object_type=ObjectType.SymmetricKey)
        uid2 = store.create_object(object_type=ObjectType.PublicKey)
        results = store.locate(object_type=ObjectType.SymmetricKey)
        assert uid1 in results
        assert uid2 not in results

    def test_locate_by_state(self, store):
        uid1 = store.create_object(object_type=ObjectType.SymmetricKey)
        uid2 = store.create_object(object_type=ObjectType.SymmetricKey)
        store.activate(uid1)
        results = store.locate(state=State.Active)
        assert uid1 in results
        assert uid2 not in results

    def test_locate_by_name(self, store):
        uid = store.create_object(
            object_type=ObjectType.SymmetricKey,
            names=["special-key"]
        )
        results = store.locate(name="special-key")
        assert uid in results

    def test_locate_with_max_items(self, store):
        for _ in range(5):
            store.create_object(object_type=ObjectType.SymmetricKey)
        results = store.locate(
            object_type=ObjectType.SymmetricKey,
            max_items=2
        )
        assert len(results) <= 2

    def test_locate_no_match(self, store):
        results = store.locate(name="nonexistent-xyz-key")
        assert results == []
