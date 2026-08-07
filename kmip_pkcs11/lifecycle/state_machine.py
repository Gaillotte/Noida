"""
KMIP key lifecycle state machine.
Enforces legal state transitions per KMIP spec section 4.
"""

from ..core.enums import State, RevocationReasonCode
from ..core.exceptions import IllegalOperation

# Legal transitions: (from_state, operation) → to_state
_TRANSITIONS = {
    # Activate
    (State.PreActive, "activate"):  State.Active,
    # Revoke normal
    (State.Active,    "revoke_normal"):   State.Deactivated,
    (State.PreActive, "revoke_normal"):   State.Deactivated,
    # Revoke compromise
    (State.PreActive,    "revoke_compromise"): State.Compromised,
    (State.Active,       "revoke_compromise"): State.Compromised,
    (State.Deactivated,  "revoke_compromise"): State.Compromised,
    # Destroy
    (State.PreActive,   "destroy"): State.Destroyed,
    (State.Active,      "destroy"): State.Destroyed,
    (State.Deactivated, "destroy"): State.Destroyed,
    (State.Compromised, "destroy"): State.DestroyedCompromised,
}

# Compromise reason codes
_COMPROMISE_REASONS = {
    RevocationReasonCode.KeyCompromise,
    RevocationReasonCode.CACompromise,
}


def transition(current_state: int, operation: str) -> int:
    """
    Return the new state after applying the operation.
    Raises IllegalOperation if the transition is not permitted.
    """
    key = (current_state, operation)
    if key not in _TRANSITIONS:
        state_name = State(current_state).name if current_state in State._value2member_map_ else str(current_state)
        raise IllegalOperation(
            f"Operation '{operation}' is not permitted when object state is '{state_name}'"
        )
    return _TRANSITIONS[key]


def revoke_operation(reason_code: int) -> str:
    """Determine the revoke operation name based on reason code."""
    if reason_code in _COMPROMISE_REASONS:
        return "revoke_compromise"
    return "revoke_normal"


def check_usage_allowed(state: int, operation_name: str):
    """
    Validate that a cryptographic usage operation is allowed in the given state.
    Encrypt/Sign are only allowed in Active state.
    Decrypt/Verify are allowed in Active and Deactivated states.
    """
    if state == State.Destroyed or state == State.DestroyedCompromised:
        raise IllegalOperation(f"Object is destroyed; operation '{operation_name}' not permitted")

    read_ops = {"get", "get_attributes", "get_attribute_list", "export"}
    write_sensitive_ops = {"encrypt", "sign", "mac", "derive"}
    read_sensitive_ops  = {"decrypt", "verify", "mac_verify"}

    if state == State.PreActive:
        if operation_name in write_sensitive_ops or operation_name in read_sensitive_ops:
            raise IllegalOperation(f"Object is Pre-Active; '{operation_name}' not permitted")

    if state == State.Deactivated:
        if operation_name in write_sensitive_ops:
            raise IllegalOperation(
                f"Object is Deactivated; '{operation_name}' is not permitted (read-only)"
            )

    if state == State.Compromised:
        # Only limited usage in compromised state (implementation policy)
        if operation_name not in read_ops:
            raise IllegalOperation(
                f"Object is Compromised; '{operation_name}' is not permitted"
            )
