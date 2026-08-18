"""Phase 5 — governance: cryptoperiod enforcement, dual control, group grants
and per-role operation allowlists.

The gate these tests defend is: key rotation happens without a client asking,
and destructive operations require two people.
"""

import time

import pytest

from kmip_pkcs11.config import KMIPConfig, ConfigError
from kmip_pkcs11.core.enums import (
    CryptographicAlgorithm, CryptographicUsageMask, ObjectType, State,
)
from kmip_pkcs11.core.exceptions import (
    IllegalOperation, ItemNotFound, NotAuthorized,
)
from kmip_pkcs11.lifecycle.access_control import check_operation_allowed, check_owner
from kmip_pkcs11.lifecycle.dual_control import DualControlPolicy, enforce
from kmip_pkcs11.lifecycle.governance import (
    SCHEDULER_IDENTITY, KeyLifecycleScheduler, set_cryptoperiod,
)


def _object(store, owner="alice", state=State.Active):
    uid = store.create_object(
        object_type=ObjectType.SymmetricKey,
        cryptographic_algorithm=CryptographicAlgorithm.AES,
        cryptographic_length=256,
        usage_mask=CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt,
        owner_identity=owner,
    )
    store.set_state(uid, state)
    return uid


# ── cryptoperiod ─────────────────────────────────────────────────────────────

class TestCryptoperiod:
    def test_set_cryptoperiod_records_a_deactivation_date(self, store):
        uid = _object(store)
        deadline = set_cryptoperiod(store, uid, 30)
        assert store.get_object(uid)["deactivation_date"] == pytest.approx(deadline)

    def test_set_cryptoperiod_rejects_an_unknown_object(self, store):
        # A mistyped identifier must not report success having changed nothing.
        with pytest.raises(ItemNotFound):
            set_cryptoperiod(store, "00000000-0000-0000-0000-000000000000", 30)

    def test_elapsed_cryptoperiod_deactivates_without_a_client(self, store):
        uid = _object(store)
        set_cryptoperiod(store, uid, -1)
        result = KeyLifecycleScheduler(store).run_once()
        assert result["deactivated"] == 1
        assert store.get_object(uid)["state"] == State.Deactivated

    def test_approaching_cryptoperiod_warns_but_does_not_deactivate(self, store):
        uid = _object(store)
        set_cryptoperiod(store, uid, 3)
        result = KeyLifecycleScheduler(store, warn_days=7).run_once()
        assert (result["warned"], result["deactivated"]) == (1, 0)
        assert store.get_object(uid)["state"] == State.Active

    def test_a_key_beyond_the_warning_horizon_is_left_alone(self, store):
        uid = _object(store)
        set_cryptoperiod(store, uid, 60)
        assert KeyLifecycleScheduler(store, warn_days=7).run_once() == {
            "deactivated": 0, "warned": 0, "rotated": 0, "failed": 0}
        assert store.get_object(uid)["state"] == State.Active

    def test_a_key_with_no_cryptoperiod_is_never_touched(self, store):
        uid = _object(store)
        KeyLifecycleScheduler(store).run_once()
        assert store.get_object(uid)["state"] == State.Active

    def test_scheduler_actions_are_attributable_in_the_audit_log(self, store):
        uid = _object(store)
        set_cryptoperiod(store, uid, -1)
        KeyLifecycleScheduler(store).run_once()
        entries = store.get_audit_entries(object_uid=uid)
        assert [e["operation_name"] for e in entries] == ["ScheduledDeactivate"]
        assert entries[0]["identity"] == SCHEDULER_IDENTITY
        assert store.verify_audit_chain()["ok"]

    def test_a_second_scan_does_not_re_deactivate(self, store):
        uid = _object(store)
        set_cryptoperiod(store, uid, -1)
        sched = KeyLifecycleScheduler(store)
        assert sched.run_once()["deactivated"] == 1
        assert sched.run_once()["deactivated"] == 0

    def test_expiring_objects_orders_by_deadline(self, store):
        far, near = _object(store), _object(store)
        set_cryptoperiod(store, far, 20)
        set_cryptoperiod(store, near, 2)
        listed = KeyLifecycleScheduler(store).expiring_objects(30)
        assert [o["uuid"] for o in listed] == [near, far]

    def test_rotation_without_an_hsm_fails_but_still_deactivates(self, store):
        # An expired key left Active because rotation failed is the worse
        # outcome, so deactivation happens regardless.
        uid = _object(store)
        set_cryptoperiod(store, uid, -1)
        result = KeyLifecycleScheduler(store, auto_rotate=True).run_once()
        assert (result["failed"], result["deactivated"]) == (1, 1)
        assert store.get_object(uid)["state"] == State.Deactivated

    def test_start_and_stop_are_idempotent(self, store):
        sched = KeyLifecycleScheduler(store, interval_seconds=0.05)
        sched.start()
        sched.start()          # second start must not spawn a second thread
        time.sleep(0.15)
        sched.stop()
        sched.stop()


class TestScheduledRotation:
    """Auto-rotation needs a real token: the replacement is an HSM key."""

    def test_expiring_key_is_replaced_and_cross_linked(self, store, shim):
        from kmip_pkcs11.operations.create import create_symmetric_key
        old = create_symmetric_key(
            CryptographicAlgorithm.AES, 256,
            CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt,
            ["rotate-me"], True, False, "alice", store, shim)
        store.set_state(old, State.Active)
        set_cryptoperiod(store, old, -1)

        result = KeyLifecycleScheduler(store, shim, auto_rotate=True).run_once()
        assert (result["rotated"], result["deactivated"]) == (1, 1)

        new = store.get_attribute(old, "Link_ReplacementKey")[0]
        assert store.get_attribute(new, "Link_ReplacedKey") == [old]

        replacement = store.get_object(new)
        assert replacement["state"] == State.Active
        assert replacement["cryptographic_algorithm"] == CryptographicAlgorithm.AES
        assert replacement["cryptographic_length"] == 256
        assert replacement["owner_identity"] == "alice"
        assert store.get_object(old)["state"] == State.Deactivated

    def test_rotation_opens_the_hsm_session_if_the_server_has_not_yet(self, store):
        # The scheduler starts before the server binds, so the first scan can
        # arrive ahead of the server's own initialize().
        class LateShim:
            initialized = False

            def initialize(self):
                LateShim.initialized = True
                raise RuntimeError("stop here — the ordering is the point")

        uid = _object(store)
        set_cryptoperiod(store, uid, -1)
        KeyLifecycleScheduler(store, LateShim(), auto_rotate=True).run_once()
        assert LateShim.initialized

    def test_rotation_refuses_a_non_symmetric_key(self, store, shim):
        uid = store.create_object(object_type=ObjectType.PublicKey,
                                  cryptographic_algorithm=CryptographicAlgorithm.RSA,
                                  cryptographic_length=2048, owner_identity="alice")
        store.set_state(uid, State.Active)
        set_cryptoperiod(store, uid, -1)
        result = KeyLifecycleScheduler(store, shim, auto_rotate=True).run_once()
        assert result["failed"] == 1
        assert result["rotated"] == 0


# ── dual control ─────────────────────────────────────────────────────────────

def _policy(**kw):
    kw.setdefault("enabled", True)
    kw.setdefault("operations", ["Destroy"])
    kw.setdefault("approvals_required", 2)
    kw.setdefault("ttl_seconds", 600)
    return DualControlPolicy(**kw)


class TestDualControl:
    def test_a_disabled_policy_covers_nothing(self, store):
        enforce(DualControlPolicy(enabled=False), store, "Destroy", "alice", "u")
        assert store.list_approval_requests() == []

    def test_an_uncovered_operation_passes_through(self, store):
        enforce(_policy(), store, "Get", "alice", "u")
        assert store.list_approval_requests() == []

    def test_first_attempt_is_refused_and_opens_a_request(self, store):
        uid = _object(store)
        with pytest.raises(NotAuthorized):
            enforce(_policy(), store, "Destroy", "alice", uid)
        [request] = store.list_approval_requests()
        assert (request["requester"], request["object_uid"]) == ("alice", uid)
        assert request["satisfied"] is False

    def test_retrying_reuses_the_open_request(self, store):
        # Without this a client in a retry loop fills the table with requests
        # nobody will ever approve.
        uid = _object(store)
        for _ in range(5):
            with pytest.raises(NotAuthorized):
                enforce(_policy(), store, "Destroy", "alice", uid)
        assert len(store.list_approval_requests()) == 1

    def test_the_requester_cannot_approve_their_own_request(self, store):
        uid = _object(store)
        with pytest.raises(NotAuthorized):
            enforce(_policy(), store, "Destroy", "alice", uid)
        request_id = store.list_approval_requests()[0]["request_id"]
        with pytest.raises(NotAuthorized):
            store.approve_request(request_id, "alice")

    def test_one_approval_of_two_is_not_enough(self, store):
        uid = _object(store)
        with pytest.raises(NotAuthorized):
            enforce(_policy(), store, "Destroy", "alice", uid)
        request_id = store.list_approval_requests()[0]["request_id"]
        store.approve_request(request_id, "bob")
        with pytest.raises(NotAuthorized):
            enforce(_policy(), store, "Destroy", "alice", uid)

    def test_the_same_approver_twice_still_counts_once(self, store):
        uid = _object(store)
        with pytest.raises(NotAuthorized):
            enforce(_policy(), store, "Destroy", "alice", uid)
        request_id = store.list_approval_requests()[0]["request_id"]
        store.approve_request(request_id, "bob")
        result = store.approve_request(request_id, "bob")
        assert result["approvers"] == ["bob"]
        assert result["satisfied"] is False

    def test_enough_approvals_let_the_retry_through_exactly_once(self, store):
        uid = _object(store)
        with pytest.raises(NotAuthorized):
            enforce(_policy(), store, "Destroy", "alice", uid)
        request_id = store.list_approval_requests()[0]["request_id"]
        store.approve_request(request_id, "bob")
        store.approve_request(request_id, "carol")

        enforce(_policy(), store, "Destroy", "alice", uid)          # allowed
        assert store.get_approval_request(request_id)["consumed_at"] is not None
        with pytest.raises(NotAuthorized):                          # not reusable
            enforce(_policy(), store, "Destroy", "alice", uid)

    def test_an_approval_authorises_only_the_object_it_names(self, store):
        one, two = _object(store), _object(store)
        with pytest.raises(NotAuthorized):
            enforce(_policy(), store, "Destroy", "alice", one)
        request_id = store.list_approval_requests()[0]["request_id"]
        store.approve_request(request_id, "bob")
        store.approve_request(request_id, "carol")
        with pytest.raises(NotAuthorized):
            enforce(_policy(), store, "Destroy", "alice", two)

    def test_an_approval_authorises_only_the_identity_that_asked(self, store):
        uid = _object(store)
        with pytest.raises(NotAuthorized):
            enforce(_policy(), store, "Destroy", "alice", uid)
        request_id = store.list_approval_requests()[0]["request_id"]
        store.approve_request(request_id, "bob")
        store.approve_request(request_id, "carol")
        with pytest.raises(NotAuthorized):
            enforce(_policy(), store, "Destroy", "mallory", uid)

    def test_an_expired_request_cannot_be_approved(self, store):
        request_id = store.create_approval_request("Destroy", "u", "alice", 2, -1)
        with pytest.raises(IllegalOperation):
            store.approve_request(request_id, "bob")

    def test_an_expired_request_does_not_satisfy_a_retry(self, store):
        request_id = store.create_approval_request("Destroy", "u", "alice", 1, 600)
        store.approve_request(request_id, "bob")
        store._conn().execute(
            "UPDATE kmip_approval_requests SET expires_at = 0 WHERE request_id = ?",
            (request_id,))
        store._conn().commit()
        assert store.find_satisfied_request("Destroy", "u", "alice") is None

    def test_a_consumed_request_cannot_be_approved_again(self, store):
        request_id = store.create_approval_request("Destroy", "u", "alice", 2, 600)
        store.consume_approval_request(request_id)
        with pytest.raises(IllegalOperation):
            store.approve_request(request_id, "bob")

    def test_approving_an_unknown_request_is_reported(self, store):
        with pytest.raises(ItemNotFound):
            store.approve_request("no-such-request", "bob")

    def test_list_approval_requests_hides_consumed_ones_by_default(self, store):
        request_id = store.create_approval_request("Destroy", "u", "alice", 2, 600)
        store.consume_approval_request(request_id)
        assert store.list_approval_requests() == []
        assert len(store.list_approval_requests(pending_only=False)) == 1

    def test_policy_reads_the_governance_config(self):
        config = KMIPConfig.from_dict({
            "hsm": {"library": "x", "token_label": "t", "pin": "1"},
            "server": {"allow_plaintext": True},
            "governance": {"dual_control": True, "dual_control_operations": ["Get"],
                           "approvals_required": 3, "approval_ttl_seconds": 60},
        })
        policy = DualControlPolicy.from_config(config)
        assert policy.covers("Get") and not policy.covers("Destroy")
        assert (policy.approvals_required, policy.ttl_seconds) == (3, 60)

    def test_config_rejects_single_signature_dual_control(self):
        with pytest.raises(ConfigError):
            KMIPConfig.from_dict({
                "hsm": {"library": "x", "token_label": "t", "pin": "1"},
                "server": {"allow_plaintext": True},
                "governance": {"dual_control": True, "approvals_required": 1},
            })


class TestDualControlOverTheWire:
    """The whole point is that the destructive step never runs, so this checks
    the key still exists after a refused Destroy."""

    def test_destroy_needs_a_second_signature(self, tmp_path, shim):
        from kmip_pkcs11.metadata.store import MetadataStore
        from kmip_pkcs11.server.server import KMIPServer
        from kmip_pkcs11.test_app.client import KMIPClient, KMIPClientError

        from .conftest import _await_listener, _port_counter

        port = next(_port_counter)
        store = MetadataStore(str(tmp_path / "dc.db"))
        server = KMIPServer(store, shim, port=port, allow_plaintext=True,
                            dual_control=_policy())
        server.start_background()
        _await_listener(server, port)

        client = KMIPClient(port=port)
        client.connect()
        try:
            uid = client.create(name="dual-control-target")
            with pytest.raises(KMIPClientError):
                client.destroy(uid)
            assert store.get_object(uid)["state"] != State.Destroyed

            request_id = store.list_approval_requests()[0]["request_id"]
            store.approve_request(request_id, "bob")
            store.approve_request(request_id, "carol")

            client.destroy(uid)
            assert store.get_object(uid)["state"] == State.Destroyed
        finally:
            client.close()
            # Not server.stop(): it finalizes the PKCS#11 session, and the shim
            # fixture is session-scoped, so the rest of the suite still needs it.
            server._running = False
            if server._sock:
                server._sock.close()


# ── groups and role allowlists ───────────────────────────────────────────────

class TestGroupGrants:
    def test_a_group_grant_reaches_its_members(self, store):
        uid = _object(store, owner="alice")
        store.add_to_group("bob", "crypto-team")
        store.grant_access(uid, "group:crypto-team", "read")
        check_owner("bob", "alice", "Get", store, uid)

    def test_a_read_group_grant_does_not_permit_destroy(self, store):
        uid = _object(store, owner="alice")
        store.add_to_group("bob", "crypto-team")
        store.grant_access(uid, "group:crypto-team", "read")
        with pytest.raises(NotAuthorized):
            check_owner("bob", "alice", "Destroy", store, uid)

    def test_a_full_group_grant_permits_destroy(self, store):
        uid = _object(store, owner="alice")
        store.add_to_group("bob", "crypto-team")
        store.grant_access(uid, "group:crypto-team", "full")
        check_owner("bob", "alice", "Destroy", store, uid)

    def test_a_non_member_gets_nothing(self, store):
        uid = _object(store, owner="alice")
        store.add_to_group("bob", "crypto-team")
        store.grant_access(uid, "group:crypto-team", "read")
        with pytest.raises(NotAuthorized):
            check_owner("carol", "alice", "Get", store, uid)

    def test_leaving_the_group_withdraws_the_access(self, store):
        uid = _object(store, owner="alice")
        store.add_to_group("bob", "crypto-team")
        store.grant_access(uid, "group:crypto-team", "read")
        store.remove_from_group("bob", "crypto-team")
        with pytest.raises(NotAuthorized):
            check_owner("bob", "alice", "Get", store, uid)

    def test_membership_is_listed_both_ways(self, store):
        store.add_to_group("bob", "crypto-team")
        store.add_to_group("bob", "oncall")
        store.add_to_group("carol", "crypto-team")
        assert store.get_groups("bob") == ["crypto-team", "oncall"]
        assert store.list_group_members("crypto-team") == ["bob", "carol"]

    def test_adding_twice_is_harmless(self, store):
        store.add_to_group("bob", "crypto-team")
        store.add_to_group("bob", "crypto-team")
        assert store.get_groups("bob") == ["crypto-team"]


class TestRoleOperationAllowlists:
    def test_an_identity_with_no_role_is_unrestricted(self, store):
        check_operation_allowed("dave", "Destroy", store)

    def test_a_role_with_no_allowlist_restricts_nothing(self, store):
        store.assign_role("dave", "operator")
        check_operation_allowed("dave", "Destroy", store)

    def test_an_allowlist_permits_what_it_names(self, store):
        store.assign_role("dave", "auditor")
        store.allow_role_operation("auditor", "Get")
        check_operation_allowed("dave", "Get", store)

    def test_an_allowlist_refuses_what_it_omits(self, store):
        store.assign_role("dave", "auditor")
        store.allow_role_operation("auditor", "Get")
        with pytest.raises(NotAuthorized):
            check_operation_allowed("dave", "Destroy", store)

    def test_allowlists_across_roles_are_unioned(self, store):
        store.assign_role("dave", "auditor")
        store.assign_role("dave", "operator")
        store.allow_role_operation("auditor", "Get")
        store.allow_role_operation("operator", "Create")
        check_operation_allowed("dave", "Get", store)
        check_operation_allowed("dave", "Create", store)
        with pytest.raises(NotAuthorized):
            check_operation_allowed("dave", "Destroy", store)

    def test_an_unrestricted_role_does_not_widen_a_restricted_one(self, store):
        # Holding a role that defines no allowlist must not dissolve the
        # restriction imposed by another role, or roles would be additive in
        # the wrong direction.
        store.assign_role("dave", "auditor")
        store.assign_role("dave", "bystander")
        store.allow_role_operation("auditor", "Get")
        with pytest.raises(NotAuthorized):
            check_operation_allowed("dave", "Destroy", store)

    def test_admin_is_not_bound_by_an_allowlist(self, store):
        store.assign_role("root", "admin")
        store.allow_role_operation("admin", "Get")
        check_operation_allowed("root", "Destroy", store)

    def test_revoking_the_operation_takes_effect(self, store):
        store.assign_role("dave", "auditor")
        store.allow_role_operation("auditor", "Get")
        store.disallow_role_operation("auditor", "Get")
        check_operation_allowed("dave", "Destroy", store)   # no allowlist left
        assert store.get_role_operations("auditor") == []

    def test_the_dispatcher_enforces_the_allowlist(self, store, shim):
        from kmip_pkcs11.core.enums import Operation, ResultStatus, Tag
        from kmip_pkcs11.core.ttlv import (
            decode_one, encode_enumeration, encode_structure,
        )
        from kmip_pkcs11.operations.dispatcher import OperationDispatcher

        store.assign_role("dave", "auditor")
        store.allow_role_operation("auditor", "Query")

        batch = encode_structure(
            Tag.BatchItem,
            encode_enumeration(Tag.Operation, Operation.Create)
            + encode_structure(Tag.RequestPayload,
                               encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)))
        response = decode_one(
            OperationDispatcher(store, shim).dispatch(decode_one(batch), "dave"))
        assert response.get(Tag.ResultStatus).value == ResultStatus.OperationFailed
        assert "auditor" not in response.get(Tag.ResultMessage).value  # names the identity
        assert "dave" in response.get(Tag.ResultMessage).value
