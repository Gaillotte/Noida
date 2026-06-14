"""
KMIP Conformance Test Suite.

Based on OASIS KMIP Test Cases specification v2.1.
Tests are organized into conformance levels:
  - CS-AC-M  : Mandatory (must pass for any conformant implementation)
  - CS-AC-O  : Optional capability tests
  - TC-xxx   : OASIS test case identifiers (simplified mapping)

Tests exercise the live server via the KMIPClient (end-to-end over TCP).
"""

import os
import pytest
from kmip_pkcs11.core.enums import (
    CryptographicAlgorithm, ObjectType, State,
    CryptographicUsageMask, RevocationReasonCode,
    Operation, QueryFunction
)
from kmip_pkcs11.test_app.client import KMIPClient, KMIPClientError


# ────────────────────────────────────────────────────────────────────────────
# TC-DISC-001 — DiscoverVersions
# ────────────────────────────────────────────────────────────────────────────

class TestDiscoverVersions:
    """CS-AC-M: Server MUST support DiscoverVersions."""

    def test_discover_returns_list(self, server_client):
        client, _ = server_client
        versions = client.discover_versions()
        assert isinstance(versions, list)
        assert len(versions) >= 1

    def test_discover_includes_v2_1(self, server_client):
        client, _ = server_client
        assert (2, 1) in client.discover_versions()

    def test_discover_includes_v1_x(self, server_client):
        client, _ = server_client
        versions = client.discover_versions()
        majors = [v[0] for v in versions]
        assert 1 in majors

    def test_discover_versions_are_ordered_descending(self, server_client):
        client, _ = server_client
        versions = client.discover_versions()
        # Latest version should come first
        assert versions[0] >= versions[-1]


# ────────────────────────────────────────────────────────────────────────────
# TC-QUERY-001 — Query
# ────────────────────────────────────────────────────────────────────────────

class TestQuery:
    """CS-AC-M: Server MUST support Query."""

    def test_query_returns_operations(self, server_client):
        client, _ = server_client
        caps = client.query([QueryFunction.QueryOperations])
        assert len(caps["operations"]) > 0

    def test_query_includes_create(self, server_client):
        client, _ = server_client
        caps = client.query([QueryFunction.QueryOperations])
        assert Operation.Create in caps["operations"]

    def test_query_includes_destroy(self, server_client):
        client, _ = server_client
        caps = client.query([QueryFunction.QueryOperations])
        assert Operation.Destroy in caps["operations"]

    def test_query_includes_locate(self, server_client):
        client, _ = server_client
        caps = client.query([QueryFunction.QueryOperations])
        assert Operation.Locate in caps["operations"]

    def test_query_object_types(self, server_client):
        client, _ = server_client
        caps = client.query([QueryFunction.QueryObjects])
        assert ObjectType.SymmetricKey in caps["object_types"]

    def test_query_server_info(self, server_client):
        client, _ = server_client
        caps = client.query([QueryFunction.QueryServerInformation])
        assert caps["vendor"] != ""


# ────────────────────────────────────────────────────────────────────────────
# TC-CREATE-001 — Create Symmetric Key (AES-256)
# ────────────────────────────────────────────────────────────────────────────

class TestCreate:
    """CS-AC-M: Server MUST support Create for SymmetricKey."""

    def test_create_aes256_returns_uid(self, server_client):
        client, _ = server_client
        uid = client.create(
            algorithm=CryptographicAlgorithm.AES,
            length=256,
        )
        assert len(uid) == 36

    def test_create_aes128_returns_uid(self, server_client):
        client, _ = server_client
        uid = client.create(
            algorithm=CryptographicAlgorithm.AES,
            length=128,
        )
        assert uid

    def test_create_with_name(self, server_client):
        client, _ = server_client
        uid = client.create(
            algorithm=CryptographicAlgorithm.AES,
            length=256,
            name="conformance-test-key",
        )
        # Locate by name
        found = client.locate(name="conformance-test-key")
        assert uid in found

    def test_create_uids_are_unique(self, server_client):
        client, _ = server_client
        uid1 = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        uid2 = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        assert uid1 != uid2

    def test_create_sets_state_active(self, server_client):
        client, _ = server_client
        uid   = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        attrs = client.get_attributes(uid, ["State"])
        assert attrs.get("State") == State.Active


# ────────────────────────────────────────────────────────────────────────────
# TC-CREATE-KP-001 — CreateKeyPair (RSA)
# ────────────────────────────────────────────────────────────────────────────

class TestCreateKeyPair:
    """CS-AC-O: RSA key pair generation."""

    def test_create_rsa2048_returns_two_uids(self, server_client):
        client, _ = server_client
        pub, priv = client.create_key_pair(
            algorithm=CryptographicAlgorithm.RSA,
            length=2048,
        )
        assert pub  and len(pub)  == 36
        assert priv and len(priv) == 36
        assert pub != priv

    def test_create_rsa_keys_are_active(self, server_client):
        client, _ = server_client
        pub, priv = client.create_key_pair(
            algorithm=CryptographicAlgorithm.RSA, length=2048
        )
        for uid in [pub, priv]:
            attrs = client.get_attributes(uid, ["State"])
            assert attrs.get("State") == State.Active


# ────────────────────────────────────────────────────────────────────────────
# TC-GET-001 — Get
# ────────────────────────────────────────────────────────────────────────────

class TestGet:
    """CS-AC-M: Server MUST support Get."""

    def test_get_extractable_key_succeeds(self, server_client):
        client, _ = server_client
        uid = client.create(
            algorithm=CryptographicAlgorithm.AES,
            length=256,
            extractable=True,
        )
        resp = client.get(uid)
        assert resp is not None

    def test_get_nonexistent_uid_fails(self, server_client):
        client, _ = server_client
        with pytest.raises(KMIPClientError, match="ItemNotFound|not found"):
            client.get("00000000-0000-0000-0000-000000000000")


# ────────────────────────────────────────────────────────────────────────────
# TC-GETATTR-001 — GetAttributes
# ────────────────────────────────────────────────────────────────────────────

class TestGetAttributes:
    """CS-AC-M: Server MUST support GetAttributes."""

    def test_get_object_type(self, server_client):
        client, _ = server_client
        uid   = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        attrs = client.get_attributes(uid, ["Object Type"])
        assert attrs["Object Type"] == ObjectType.SymmetricKey

    def test_get_cryptographic_algorithm(self, server_client):
        client, _ = server_client
        uid   = client.create(algorithm=CryptographicAlgorithm.AES, length=128)
        attrs = client.get_attributes(uid, ["Cryptographic Algorithm"])
        assert attrs["Cryptographic Algorithm"] == CryptographicAlgorithm.AES

    def test_get_cryptographic_length(self, server_client):
        client, _ = server_client
        uid   = client.create(algorithm=CryptographicAlgorithm.AES, length=192)
        attrs = client.get_attributes(uid, ["Cryptographic Length"])
        assert attrs["Cryptographic Length"] == 192

    def test_get_state_attribute(self, server_client):
        client, _ = server_client
        uid   = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        attrs = client.get_attributes(uid, ["State"])
        assert attrs["State"] == State.Active

    def test_get_all_attributes(self, server_client):
        client, _ = server_client
        uid   = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        attrs = client.get_attributes(uid)
        assert "Object Type"             in attrs
        assert "Cryptographic Algorithm" in attrs
        assert "State"                   in attrs


# ────────────────────────────────────────────────────────────────────────────
# TC-LOCATE-001 — Locate
# ────────────────────────────────────────────────────────────────────────────

class TestLocate:
    """CS-AC-M: Server MUST support Locate."""

    def test_locate_all_returns_list(self, server_client):
        client, _ = server_client
        uid    = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        result = client.locate()
        assert uid in result

    def test_locate_by_object_type(self, server_client):
        client, _ = server_client
        uid    = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        result = client.locate(object_type=ObjectType.SymmetricKey)
        assert uid in result

    def test_locate_by_name(self, server_client):
        client, _ = server_client
        uid    = client.create(
            algorithm=CryptographicAlgorithm.AES, length=256, name="tc-locate-name"
        )
        result = client.locate(name="tc-locate-name")
        assert uid in result

    def test_locate_by_state(self, server_client):
        client, _ = server_client
        uid    = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        result = client.locate(state=State.Active)
        assert uid in result

    def test_locate_unknown_name_returns_empty(self, server_client):
        client, _ = server_client
        result = client.locate(name="zzz-does-not-exist-xyzabc")
        assert result == []

    def test_locate_by_algorithm(self, server_client):
        client, _ = server_client
        uid    = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        result = client.locate(algorithm=CryptographicAlgorithm.AES)
        assert uid in result


# ────────────────────────────────────────────────────────────────────────────
# TC-LIFECYCLE-001 — Activate / Revoke / Destroy
# ────────────────────────────────────────────────────────────────────────────

class TestLifecycle:
    """CS-AC-M: Server MUST support Activate, Revoke, Destroy."""

    def test_revoke_transitions_to_deactivated(self, server_client):
        client, _ = server_client
        uid = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        client.revoke(uid, reason=RevocationReasonCode.Superseded)
        attrs = client.get_attributes(uid, ["State"])
        assert attrs["State"] == State.Deactivated

    def test_revoke_compromise_transitions_to_compromised(self, server_client):
        client, _ = server_client
        uid = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        client.revoke(uid, reason=RevocationReasonCode.KeyCompromise)
        attrs = client.get_attributes(uid, ["State"])
        assert attrs["State"] == State.Compromised

    def test_destroy_transitions_to_destroyed(self, server_client):
        client, _ = server_client
        uid = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        client.revoke(uid, reason=RevocationReasonCode.CessationOfOperation)
        client.destroy(uid)
        attrs = client.get_attributes(uid, ["State"])
        assert attrs["State"] == State.Destroyed

    def test_destroy_active_key(self, server_client):
        """KMIP allows destroying an Active key directly."""
        client, _ = server_client
        uid = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        client.destroy(uid)
        attrs = client.get_attributes(uid, ["State"])
        assert attrs["State"] == State.Destroyed

    def test_cannot_destroy_twice(self, server_client):
        client, _ = server_client
        uid = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        client.destroy(uid)
        with pytest.raises(KMIPClientError):
            client.destroy(uid)

    def test_cannot_revoke_destroyed_key(self, server_client):
        client, _ = server_client
        uid = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        client.destroy(uid)
        with pytest.raises(KMIPClientError):
            client.revoke(uid, reason=RevocationReasonCode.Superseded)


# ────────────────────────────────────────────────────────────────────────────
# TC-CRYPT-001 — Encrypt / Decrypt
# ────────────────────────────────────────────────────────────────────────────

class TestEncryptDecrypt:
    """CS-AC-O: Server-side encrypt/decrypt using managed key."""

    def test_encrypt_returns_ciphertext(self, server_client):
        client, _ = server_client
        uid = client.create(
            algorithm=CryptographicAlgorithm.AES, length=256, extractable=True
        )
        plaintext = b"A" * 32
        ct, iv, _ = client.encrypt(uid, plaintext)
        assert ct != plaintext
        assert len(ct) > 0

    def test_decrypt_recovers_plaintext(self, server_client):
        client, _ = server_client
        uid       = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        plaintext = b"Hello Conformance Test!" + b"\x00" * 9  # 32 bytes
        ct, iv, tag = client.encrypt(uid, plaintext)
        recovered   = client.decrypt(uid, ct, iv=iv, auth_tag=tag)
        assert recovered == plaintext

    def test_different_plaintexts_give_different_ciphertexts(self, server_client):
        client, _ = server_client
        uid = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        ct1, _, _ = client.encrypt(uid, b"A" * 32)
        ct2, _, _ = client.encrypt(uid, b"B" * 32)
        assert ct1 != ct2

    def test_encrypt_deactivated_key_fails(self, server_client):
        client, _ = server_client
        uid = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        client.revoke(uid, reason=RevocationReasonCode.Superseded)
        with pytest.raises(KMIPClientError):
            client.encrypt(uid, b"X" * 32)

    def test_decrypt_deactivated_key_succeeds(self, server_client):
        """Deactivated keys can still decrypt (for data recovery)."""
        client, _ = server_client
        uid       = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        plaintext = b"D" * 32
        ct, iv, tag = client.encrypt(uid, plaintext)
        client.revoke(uid, reason=RevocationReasonCode.Superseded)
        recovered = client.decrypt(uid, ct, iv=iv, auth_tag=tag)
        assert recovered == plaintext


# ────────────────────────────────────────────────────────────────────────────
# TC-ATTR-001 — AddAttribute / GetAttributes
# ────────────────────────────────────────────────────────────────────────────

class TestAttributes:
    """CS-AC-M: Server MUST support AddAttribute and GetAttributes."""

    def test_add_custom_attribute(self, server_client):
        client, _ = server_client
        uid = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        client.add_attribute(uid, "x-project", "KMIP-Conformance")
        attrs = client.get_attributes(uid)
        assert attrs.get("x-project") == "KMIP-Conformance"

    def test_add_multiple_custom_attributes(self, server_client):
        client, _ = server_client
        uid = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        client.add_attribute(uid, "x-env",     "production")
        client.add_attribute(uid, "x-owner",   "security-team")
        attrs = client.get_attributes(uid)
        assert attrs.get("x-env")   == "production"
        assert attrs.get("x-owner") == "security-team"


# ────────────────────────────────────────────────────────────────────────────
# TC-ERR-001 — Error handling
# ────────────────────────────────────────────────────────────────────────────

class TestErrorHandling:
    """CS-AC-M: Server MUST return proper error codes."""

    def test_get_nonexistent_returns_item_not_found(self, server_client):
        client, _ = server_client
        with pytest.raises(KMIPClientError, match="ItemNotFound|not found"):
            client.get("deadbeef-dead-beef-dead-beefdeadbeef")

    def test_activate_nonexistent_returns_item_not_found(self, server_client):
        client, _ = server_client
        with pytest.raises(KMIPClientError):
            client.activate("00000000-0000-0000-0000-000000000000")

    def test_destroy_nonexistent_returns_item_not_found(self, server_client):
        client, _ = server_client
        with pytest.raises(KMIPClientError):
            client.destroy("ffffffff-ffff-ffff-ffff-ffffffffffff")

    def test_double_destroy_fails(self, server_client):
        client, _ = server_client
        uid = client.create(algorithm=CryptographicAlgorithm.AES, length=256)
        client.destroy(uid)
        with pytest.raises(KMIPClientError):
            client.destroy(uid)

    def test_revoke_nonexistent_fails(self, server_client):
        client, _ = server_client
        with pytest.raises(KMIPClientError):
            client.revoke("00000000-1111-2222-3333-444444444444")
