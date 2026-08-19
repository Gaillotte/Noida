"""
Bridges portal identities and roles into the KMIP engine.

The two halves of the system have to agree about who a user is. The portal has
real accounts with per-user passwords and five roles; the engine has its own
``kmip_identities`` credential table and its own ``kmip_identity_roles``. Left
alone they diverge, and an administrator demoted in the portal keeps
engine-level admin.

**This used to be an injected authenticator.** ``KMIPServer`` accepted an
``authenticator`` callable, and this module passed one that verified against
``portal_users`` on every KMIP request. The engine now authenticates natively —
``MetadataStore.verify_identity`` checks a per-identity scrypt credential, with
a short-lived cache so the derivation cost isn't paid per request — so the hook
is gone and the engine is the authority. What remains is projection: keeping the
engine's identity and role tables in step with portal administration.

Projection has to happen where the **cleartext password exists**. The two sides
hash differently on purpose (the portal uses PBKDF2, the engine scrypt), so an
engine credential cannot be derived from a stored portal hash — there is no
batch job that can retrofit one. The three moments are therefore account
creation, password change, and successful portal login. Login is the safety net:
it provisions an account that predates this bridge.

Role, enable and delete changes need no password and mirror immediately.
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


class KmipIdentityMirror:
    """Projects portal accounts into the engine's identity and role tables.

    Every method is failure-tolerant in the same direction: a projection
    problem is logged but never propagated, so a portal operation that
    succeeded is not reported as failed. The cost of that choice is drift, and
    it is bounded — :meth:`reconcile` re-derives the role side from the portal
    at startup, and the credential side is re-established on the user's next
    password change or portal login.
    """

    def __init__(self, portal: PortalStore, metadata: MetadataStore):
        self._portal = portal
        self._metadata = metadata

    # ── credential projection ────────────────────────────────────────────────

    def on_password_set(self, username: str, password: str,
                        role: Optional[str] = None) -> None:
        """Give the engine a credential for this user, and align their role.

        Called on account creation, password change, and successful portal
        login. ``create_identity`` is an upsert, so re-running it is how a
        rotated password reaches the engine.
        """
        try:
            self._metadata.create_identity(username, password)
        except Exception:                       # noqa: BLE001 - see class docstring
            log.exception("Could not provision the KMIP identity for '%s'. This user's "
                          "KMIP clients will be rejected until their password is set "
                          "again or they log in to the portal", username)
            return

        if role is None:
            user = self._portal.get_user(username)
            role = (user or {}).get("role", "ReadOnly")
        self.on_role_changed(username, role)

    def on_login(self, username: str, password: str,
                 role: Optional[str] = None) -> None:
        """Safety net for accounts created before this bridge existed.

        Skips the scrypt derivation when the engine already knows the identity,
        so the ordinary login path does not pay for it. A password changed
        directly in the database rather than through the portal is the case this
        misses; that is not a supported way to change a password.
        """
        try:
            if self._metadata.identity_exists(username):
                self.on_role_changed(username, role)
                return
        except Exception:                       # noqa: BLE001
            log.exception("Could not check whether '%s' has a KMIP identity", username)
            return
        log.info("Provisioning a KMIP identity for '%s' on first login", username)
        self.on_password_set(username, password, role)

    # ── role, enable and delete projection ──────────────────────────────────

    def on_role_changed(self, username: str, portal_role: Optional[str]) -> None:
        """Mirror the portal role into the engine's role table.

        Applied on every change including removal, so a demotion in the portal
        takes effect rather than lingering until someone remembers the engine
        has its own table.
        """
        if portal_role is None:
            user = self._portal.get_user(username)
            portal_role = (user or {}).get("role", "ReadOnly")
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
            log.exception("Could not project the role for '%s'", username)

    def on_enabled_changed(self, username: str, enabled: bool) -> None:
        """Disable the engine credential alongside the portal account.

        Without this, disabling an account in the portal locks the user out of
        the web UI while leaving their KMIP client working — the half of the
        system that holds the keys.
        """
        try:
            self._metadata.set_identity_disabled(username, disabled=not enabled)
        except Exception:                       # noqa: BLE001
            log.exception("Could not %s the KMIP identity for '%s'",
                          "enable" if enabled else "disable", username)

    def on_deleted(self, username: str) -> None:
        try:
            self._metadata.delete_identity(username)
            self._metadata.revoke_role(username, ENGINE_ADMIN_ROLE)
        except Exception:                       # noqa: BLE001
            log.exception("Could not remove the KMIP identity for '%s'", username)

    # ── startup reconciliation ──────────────────────────────────────────────

    def reconcile(self) -> None:
        """Re-derive the projectable state from the portal at startup.

        Roles and the disabled flag are recomputed for every portal user, and
        engine identities with no portal account behind them are disabled rather
        than deleted — a leftover credential that still authenticates is the
        dangerous outcome, and keeping the row means an accidental removal is
        recoverable.

        Credentials are deliberately not touched: there is no cleartext to
        derive one from. Users the engine does not yet know are reported, since
        the fix is an operator action (a password reset), not something that can
        happen automatically.
        """
        try:
            portal_users = self._portal.list_users()
        except Exception:                       # noqa: BLE001
            log.exception("Could not reconcile KMIP identities with portal users")
            return

        known = set()
        unprovisioned = []
        for user in portal_users:
            username = user["username"]
            known.add(username)
            self.on_role_changed(username, user.get("role"))
            try:
                if not self._metadata.identity_exists(username):
                    unprovisioned.append(username)
                    continue
                self.on_enabled_changed(username, bool(user.get("enabled", True)))
            except Exception:                   # noqa: BLE001
                log.exception("Could not reconcile the KMIP identity for '%s'", username)

        if unprovisioned:
            log.warning(
                "%d portal user(s) have no KMIP credential and cannot use a KMIP "
                "client yet: %s. Each needs a password set through the portal, "
                "which is what provisions it — the stored portal hash cannot be "
                "converted.", len(unprovisioned), ", ".join(sorted(unprovisioned)),
            )

        try:
            orphans = [i["identity"] for i in self._metadata.list_identities()
                       if i["identity"] not in known and not i.get("disabled")]
        except Exception:                       # noqa: BLE001
            log.exception("Could not check for orphaned KMIP identities")
            return
        for identity in orphans:
            log.warning("KMIP identity '%s' has no portal account; disabling it", identity)
            self.on_enabled_changed(identity, enabled=False)
