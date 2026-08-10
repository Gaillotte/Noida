"""
Bridges portal identities and roles into the KMIP engine.

Before this, the two halves of the system disagreed about who a user is:

* the **portal** had real accounts with per-user passwords and five roles;
* the **KMIP engine** accepted any username presented with the shared token
  PIN, and had its own separate ``admin`` role table.

That meant a KMIP client could claim to be a portal administrator simply by
knowing the PIN, and an administrator demoted in the portal kept engine-level
admin. This module makes ``portal_users`` the single source of both facts.

Two pieces, both injected into ``KMIPServer`` rather than patched into the
engine:

``PortalAuthenticator``
    Verifies a real username/password pair against ``portal_users``.

Role projection
    On each successful authentication, the user's portal role is projected
    into the engine's own ``kmip_identity_roles`` table. The engine's
    three-tier check (admin → owner → grant) is left exactly as it was; it
    simply now reads roles that portal administration controls.
"""

import logging
from typing import Optional

from kmip_pkcs11.metadata.store import MetadataStore

from .portal_store import PortalStore

log = logging.getLogger(__name__)

# Portal roles that carry engine-level administrative authority — unrestricted
# access to every object regardless of owner.
#
# Operator is deliberately excluded. It may create and use keys, which the
# engine already permits through ownership, but it must not reach objects
# belonging to somebody else. Auditor and ReadOnly likewise: read access to
# the audit trail is not read access to every key.
ADMIN_ROLES = {"Administrator", "SecurityOfficer"}

ENGINE_ADMIN_ROLE = "admin"


class PortalAuthenticator:
    """Verifies KMIP credentials against portal user accounts."""

    def __init__(self, portal: PortalStore, metadata: MetadataStore,
                 allow_pin_fallback: bool = False, shim=None):
        self._portal = portal
        self._metadata = metadata
        self._allow_pin_fallback = allow_pin_fallback
        self._shim = shim

    def __call__(self, username: str, password: str) -> bool:
        user = self._portal.verify_password(username, password)

        if user is not None:
            self._project_role(username, user.get("role", "ReadOnly"))
            log.info("KMIP authentication succeeded for '%s' (role %s)",
                     username, user.get("role"))
            return True

        # Optional, off by default. A deployment migrating existing KMIP
        # clients may need the old shared-PIN path to keep working while
        # accounts are created; every use is logged as the weak path it is.
        if self._allow_pin_fallback and self._shim is not None:
            if self._shim.verify_pin(password):
                log.warning(
                    "KMIP client '%s' authenticated with the shared token PIN. "
                    "This proves knowledge of the PIN, not the identity claimed. "
                    "Create a portal account and disable KMIP_ALLOW_PIN_FALLBACK.",
                    username,
                )
                return True

        log.warning("KMIP authentication failed for '%s'", username)
        return False

    def _project_role(self, username: str, portal_role: str) -> None:
        """Mirrors the portal role into the engine's role table.

        Applied on every authentication, including removal, so a demotion in
        the portal takes effect on the user's next connection rather than
        lingering until someone remembers the engine has its own table.
        """
        try:
            has_engine_admin = ENGINE_ADMIN_ROLE in self._metadata.get_roles(username)
            should_be_admin = portal_role in ADMIN_ROLES

            if should_be_admin and not has_engine_admin:
                self._metadata.assign_role(username, ENGINE_ADMIN_ROLE)
                log.info("Granted engine admin to '%s' (portal role %s)", username, portal_role)
            elif not should_be_admin and has_engine_admin:
                self._metadata.revoke_role(username, ENGINE_ADMIN_ROLE)
                log.info("Revoked engine admin from '%s' (portal role %s)", username, portal_role)
        except Exception:                       # noqa: BLE001
            # Never block a valid authentication because the projection
            # failed; the user keeps ownership-based access in the meantime.
            log.exception("Could not project role for '%s'", username)


def make_audit_sink(portal: PortalStore, source_ip: Optional[str] = None):
    """Returns a callable the dispatcher can use to record KMIP operations.

    The KMIP server does not thread the peer address down to the dispatcher,
    so records written here carry the transport rather than a client address.
    Saying "kmip" is honest; inventing an address would not be.
    """
    def sink(record: dict) -> None:
        portal.audit(
            action=record.get("action", "kmip.unknown"),
            result=record.get("result", "UNKNOWN"),
            username=record.get("username"),
            source_ip=source_ip or "kmip-client",
            object_uid=record.get("object_uid"),
            provider=record.get("provider", "KMIP"),
            detail=record.get("detail"),
        )
    return sink
