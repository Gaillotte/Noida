"""Unit tests for the KMIP key lifecycle state machine."""

import pytest
from kmip_pkcs11.core.enums import State, RevocationReasonCode
from kmip_pkcs11.core.exceptions import IllegalOperation
from kmip_pkcs11.lifecycle.state_machine import (
    transition, revoke_operation, check_usage_allowed
)


class TestTransitions:
    def test_pre_active_to_active(self):
        assert transition(State.PreActive, "activate") == State.Active

    def test_active_to_deactivated(self):
        assert transition(State.Active, "revoke_normal") == State.Deactivated

    def test_pre_active_to_deactivated(self):
        assert transition(State.PreActive, "revoke_normal") == State.Deactivated

    def test_active_to_compromised(self):
        assert transition(State.Active, "revoke_compromise") == State.Compromised

    def test_pre_active_to_compromised(self):
        assert transition(State.PreActive, "revoke_compromise") == State.Compromised

    def test_deactivated_to_compromised(self):
        assert transition(State.Deactivated, "revoke_compromise") == State.Compromised

    def test_pre_active_to_destroyed(self):
        assert transition(State.PreActive, "destroy") == State.Destroyed

    def test_active_to_destroyed(self):
        assert transition(State.Active, "destroy") == State.Destroyed

    def test_deactivated_to_destroyed(self):
        assert transition(State.Deactivated, "destroy") == State.Destroyed

    def test_compromised_to_destroyed_compromised(self):
        assert transition(State.Compromised, "destroy") == State.DestroyedCompromised

    def test_destroyed_cannot_activate(self):
        with pytest.raises(IllegalOperation):
            transition(State.Destroyed, "activate")

    def test_destroyed_cannot_destroy_again(self):
        with pytest.raises(IllegalOperation):
            transition(State.Destroyed, "destroy")

    def test_active_cannot_activate_again(self):
        with pytest.raises(IllegalOperation):
            transition(State.Active, "activate")

    def test_deactivated_cannot_activate(self):
        with pytest.raises(IllegalOperation):
            transition(State.Deactivated, "activate")


class TestRevocationOperation:
    def test_superseded_is_normal(self):
        assert revoke_operation(RevocationReasonCode.Superseded) == "revoke_normal"

    def test_key_compromise_is_compromise(self):
        assert revoke_operation(RevocationReasonCode.KeyCompromise) == "revoke_compromise"

    def test_ca_compromise_is_compromise(self):
        assert revoke_operation(RevocationReasonCode.CACompromise) == "revoke_compromise"

    def test_cessation_is_normal(self):
        assert revoke_operation(RevocationReasonCode.CessationOfOperation) == "revoke_normal"


class TestUsageAllowed:
    def test_active_encrypt_ok(self):
        check_usage_allowed(State.Active, "encrypt")  # no exception

    def test_active_decrypt_ok(self):
        check_usage_allowed(State.Active, "decrypt")

    def test_pre_active_encrypt_forbidden(self):
        with pytest.raises(IllegalOperation):
            check_usage_allowed(State.PreActive, "encrypt")

    def test_deactivated_encrypt_forbidden(self):
        with pytest.raises(IllegalOperation):
            check_usage_allowed(State.Deactivated, "encrypt")

    def test_deactivated_decrypt_ok(self):
        check_usage_allowed(State.Deactivated, "decrypt")  # decrypt still allowed

    def test_destroyed_any_op_forbidden(self):
        with pytest.raises(IllegalOperation):
            check_usage_allowed(State.Destroyed, "get")

    def test_compromised_get_ok(self):
        check_usage_allowed(State.Compromised, "get")

    def test_compromised_encrypt_forbidden(self):
        with pytest.raises(IllegalOperation):
            check_usage_allowed(State.Compromised, "encrypt")
