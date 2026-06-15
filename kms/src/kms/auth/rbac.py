"""Role-based access control definitions."""
from enum import StrEnum
from typing import Literal

# ---------------------------------------------------------------------------
# Roles (ordered least → most privileged for readability)
# ---------------------------------------------------------------------------

class Role(StrEnum):
    READER = "reader"
    AUDITOR = "auditor"
    INTEGRATOR = "integrator"
    OPERATOR = "operator"
    SYS_ADMIN = "sys_admin"
    SEC_ADMIN = "sec_admin"


# ---------------------------------------------------------------------------
# Permission catalogue
# ---------------------------------------------------------------------------

class Permission(StrEnum):
    # Key / object operations
    KEY_READ = "key:read"
    KEY_CREATE = "key:create"
    KEY_ACTIVATE = "key:activate"
    KEY_REVOKE = "key:revoke"
    KEY_DESTROY = "key:destroy"
    KEY_EXPORT = "key:export"
    KEY_ROTATE = "key:rotate"
    KEY_IMPORT = "key:import"

    # Secret data
    SECRET_READ = "secret:read"
    SECRET_CREATE = "secret:create"
    SECRET_DESTROY = "secret:destroy"

    # Certificate
    CERT_READ = "cert:read"
    CERT_CREATE = "cert:create"
    CERT_DESTROY = "cert:destroy"

    # Policy
    POLICY_READ = "policy:read"
    POLICY_WRITE = "policy:write"

    # Client management
    CLIENT_READ = "client:read"
    CLIENT_ENROLL = "client:enroll"
    CLIENT_REVOKE = "client:revoke"

    # User / role management
    USER_READ = "user:read"
    USER_WRITE = "user:write"

    # Audit
    AUDIT_READ = "audit:read"

    # System administration
    SYS_CONFIG = "sys:config"
    SYS_HSM = "sys:hsm"


_ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.READER: frozenset({
        Permission.KEY_READ,
        Permission.SECRET_READ,
        Permission.CERT_READ,
        Permission.POLICY_READ,
        Permission.CLIENT_READ,
    }),
    Role.AUDITOR: frozenset({
        Permission.KEY_READ,
        Permission.SECRET_READ,
        Permission.CERT_READ,
        Permission.POLICY_READ,
        Permission.CLIENT_READ,
        Permission.AUDIT_READ,
        Permission.USER_READ,
    }),
    Role.INTEGRATOR: frozenset({
        Permission.KEY_READ,
        Permission.KEY_CREATE,
        Permission.KEY_ACTIVATE,
        Permission.KEY_EXPORT,
        Permission.SECRET_READ,
        Permission.SECRET_CREATE,
        Permission.CERT_READ,
        Permission.CERT_CREATE,
        Permission.CLIENT_READ,
        Permission.CLIENT_ENROLL,
        Permission.POLICY_READ,
    }),
    Role.OPERATOR: frozenset({
        Permission.KEY_READ,
        Permission.KEY_CREATE,
        Permission.KEY_ACTIVATE,
        Permission.KEY_REVOKE,
        Permission.KEY_ROTATE,
        Permission.KEY_IMPORT,
        Permission.KEY_EXPORT,
        Permission.SECRET_READ,
        Permission.SECRET_CREATE,
        Permission.SECRET_DESTROY,
        Permission.CERT_READ,
        Permission.CERT_CREATE,
        Permission.CERT_DESTROY,
        Permission.CLIENT_READ,
        Permission.CLIENT_ENROLL,
        Permission.POLICY_READ,
        Permission.AUDIT_READ,
        Permission.USER_READ,
    }),
    Role.SYS_ADMIN: frozenset({
        Permission.KEY_READ,
        Permission.CERT_READ,
        Permission.CLIENT_READ,
        Permission.CLIENT_ENROLL,
        Permission.CLIENT_REVOKE,
        Permission.POLICY_READ,
        Permission.AUDIT_READ,
        Permission.USER_READ,
        Permission.USER_WRITE,
        Permission.SYS_CONFIG,
        Permission.SYS_HSM,
    }),
    Role.SEC_ADMIN: frozenset(Permission),  # all permissions
}


def has_permission(role: str, permission: Permission) -> bool:
    try:
        r = Role(role)
    except ValueError:
        return False
    return permission in _ROLE_PERMISSIONS.get(r, frozenset())


def get_permissions(role: str) -> frozenset[Permission]:
    try:
        r = Role(role)
    except ValueError:
        return frozenset()
    return _ROLE_PERMISSIONS.get(r, frozenset())
