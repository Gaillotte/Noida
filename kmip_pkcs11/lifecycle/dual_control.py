"""Dual control (M-of-N approval) for destructive operations.

Some operations cannot be undone. Destroy zeroizes key material on the token;
Get and Export hand out key bytes. Under dual control those do not execute on
request: the first attempt records an approval request and fails, and the
operation only runs once enough *other* identities have signed off.

The rule that makes this dual control rather than paperwork is that an
approver may never be the requester — enforced in the store, not here, so it
holds however approvals are submitted. Approvals authorise one operation: the
request is consumed on use rather than becoming a standing permission.

Nothing here is a KMIP wire operation. The specification has no notion of a
pending, out-of-band-approved request, so approvals are granted through
kmip-admin and the requester simply retries.
"""

import logging
from typing import Optional, Set

from ..core.exceptions import NotAuthorized

log = logging.getLogger(__name__)

# Sensible default if a deployment turns dual control on without naming
# operations: the two that lose or disclose key material irreversibly.
DEFAULT_PROTECTED_OPERATIONS = ("Destroy", "Export")
DEFAULT_APPROVALS_REQUIRED = 2
DEFAULT_REQUEST_TTL_SECONDS = 3600.0


class DualControlPolicy:
    """Which operations need approval, how many, and for how long a granted
    approval stays usable."""

    def __init__(self, operations=None, approvals_required: int = DEFAULT_APPROVALS_REQUIRED,
                 ttl_seconds: float = DEFAULT_REQUEST_TTL_SECONDS, enabled: bool = False):
        self.enabled = enabled
        self.operations: Set[str] = set(operations or DEFAULT_PROTECTED_OPERATIONS)
        self.approvals_required = approvals_required
        self.ttl_seconds = ttl_seconds

    @classmethod
    def from_config(cls, config) -> "DualControlPolicy":
        section = config.section("governance") if hasattr(config, "section") else {}
        return cls(
            enabled=bool(section.get("dual_control", False)),
            operations=section.get("dual_control_operations") or DEFAULT_PROTECTED_OPERATIONS,
            approvals_required=section.get("approvals_required", DEFAULT_APPROVALS_REQUIRED),
            ttl_seconds=section.get("approval_ttl_seconds", DEFAULT_REQUEST_TTL_SECONDS),
        )

    def covers(self, operation_name: str) -> bool:
        return self.enabled and operation_name in self.operations


def enforce(policy: DualControlPolicy, store, operation_name: str,
            identity: str, object_uid: Optional[str]):
    """Let the operation through, or raise with the request id to approve.

    Called before the handler runs, so a blocked operation has no effect at
    all — the point of dual control is that the destructive step never happens
    without the second signature."""
    if not policy.covers(operation_name):
        return

    satisfied = store.find_satisfied_request(operation_name, object_uid, identity)
    if satisfied is not None:
        # Consume it here rather than after the handler: an approval must
        # authorise exactly one attempt, and a handler that fails partway
        # should not leave a reusable approval behind.
        store.consume_approval_request(satisfied["request_id"])
        log.info("Dual control satisfied for %s on %s by %s (request %s, approvers %s)",
                 operation_name, object_uid, identity,
                 satisfied["request_id"], satisfied["approvers"])
        return

    # A retry points at the request already waiting for signatures. Opening a
    # fresh one each time would let a client in a retry loop fill the table
    # with requests nobody will ever approve.
    pending = store.find_pending_request(operation_name, object_uid, identity)
    if pending is not None:
        raise NotAuthorized(
            f"{operation_name} is awaiting approval: request {pending['request_id']} has "
            f"{len(pending['approvers'])} of {pending['required']} approval(s)."
        )

    request_id = store.create_approval_request(
        operation_name=operation_name, object_uid=object_uid, requester=identity,
        required=policy.approvals_required, ttl_seconds=policy.ttl_seconds)
    log.warning("Dual control: %s on %s by %s requires %d approval(s) — request %s",
                operation_name, object_uid, identity, policy.approvals_required, request_id)
    raise NotAuthorized(
        f"{operation_name} requires {policy.approvals_required} approval(s) from other "
        f"identities. Approval request {request_id} created; once approved, retry."
    )
