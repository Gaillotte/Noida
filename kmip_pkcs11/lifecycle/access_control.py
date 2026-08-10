"""KMIP access control — ownership, roles, and delegated grants.

Three-tier authorization, checked in this order for every operation against
an existing object:

  1. Admin role — identity has been assigned the reserved "admin" role
     (MetadataStore.assign_role(identity, "admin")): unconditional access to
     every object, regardless of owner.
  2. Ownership — identity == the object's owner_identity, set at
     Create/CreateKeyPair/Register/Certify/JoinSplitKey time.
  3. Delegated grant — an explicit MetadataStore.grant_access() record for
     this (object, identity) pair, at or above the operation's required
     permission level ("read" or "full").

Objects with owner_identity=None (pre-ownership-tracking / system objects)
remain open to any identity — unchanged from the owner-only model this
extends, so nothing pre-existing gets orphaned by adding roles and grants
on top of it.

Role and grant management has no KMIP wire-protocol operation — the spec
doesn't define one. It's a server-admin surface: call
MetadataStore.assign_role()/grant_access() directly from an admin script or
console, not over the network.
"""

from ..core.exceptions import NotAuthorized

ADMIN_ROLE = "admin"

_PERMISSION_RANK = {"read": 0, "full": 1}

# Operations that only need "read" when reached via a delegated grant.
# Everything else (mutating, consuming, or destructive) needs "full".
_READ_OPERATIONS = {
    "Get", "GetAttributes", "GetAttributeList", "Check", "Export", "ObtainLease",
}


def is_admin(identity: str, store) -> bool:
    """True if identity has been assigned the reserved admin role."""
    return ADMIN_ROLE in store.get_roles(identity)


def _required_permission(operation_name: str) -> str:
    return "read" if operation_name in _READ_OPERATIONS else "full"


def check_owner(
    identity: str,
    owner_identity,
    operation_name: str = "operation",
    store=None,
    uid: str = None,
):
    """Raise NotAuthorized unless identity is allowed to perform
    operation_name against the object. See module docstring for the
    three-tier check order.

    `store` and `uid` are optional so existing call sites keep working with
    owner-only semantics if they don't pass them — but every operations/*.py
    handler now does, so admin/grant checks apply everywhere ownership is
    enforced.
    """
    if owner_identity is None:
        return
    if identity == owner_identity:
        return

    if store is not None:
        if is_admin(identity, store):
            return
        if uid is not None:
            granted = store.get_grant(uid, identity)
            if granted is not None:
                required = _required_permission(operation_name)
                if _PERMISSION_RANK.get(granted, -1) >= _PERMISSION_RANK[required]:
                    return

    raise NotAuthorized(
        f"Identity '{identity}' is not authorized to perform "
        f"'{operation_name}' on an object it does not own"
    )
