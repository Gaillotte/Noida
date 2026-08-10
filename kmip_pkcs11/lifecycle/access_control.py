"""KMIP access control — object ownership enforcement.

Every managed object records the identity that created it (owner_identity,
set at Create/CreateKeyPair/Register/Certify/JoinSplitKey time). Operations
against an *existing* object must come from that same identity.

This is deliberately a minimal "owner-only" model, not RBAC: there is no
admin/superuser bypass and no delegated/shared access yet. See the KMS
hardening plan for the follow-up that scopes a full role-based model.
"""

from ..core.exceptions import NotAuthorized


def check_owner(identity: str, owner_identity, operation_name: str = "operation"):
    """Raise NotAuthorized unless identity created (owns) the object.

    owner_identity is None only for objects that predate ownership tracking
    (or were inserted outside the normal create path) — those stay reachable
    by any authenticated identity rather than becoming permanently orphaned.
    """
    if owner_identity is None:
        return
    if identity != owner_identity:
        raise NotAuthorized(
            f"Identity '{identity}' is not authorized to perform "
            f"'{operation_name}' on an object it does not own"
        )
