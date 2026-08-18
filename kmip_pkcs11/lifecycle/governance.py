"""Cryptoperiod enforcement and scheduled key rotation.

Every lifecycle transition in this server has so far been reactive: a key
becomes Deactivated because a client asked, never because its cryptoperiod ran
out. That is the gap between a key server and a key management *service* — a
key with a two-year cryptoperiod stays Active into year five unless somebody
remembers.

This runs a background scan that:

  * deactivates keys whose Deactivation Date has passed,
  * warns while keys approach it, so rotation can be planned rather than
    discovered,
  * optionally rotates them automatically, creating a replacement key linked
    to the old one exactly as a client-driven ReKey would.

Every action it takes is written to the audit log under the identity
"system:scheduler", so an automated deactivation is as attributable as a
human one.
"""

import datetime
import logging
import threading
from typing import Any, Dict, List, Optional

from ..core.enums import ObjectType, State
from ..core.exceptions import ItemNotFound

log = logging.getLogger(__name__)

SCHEDULER_IDENTITY = "system:scheduler"


def set_cryptoperiod(store, uid: str, days: float) -> float:
    """Give an object a cryptoperiod, expressed as a Deactivation Date.

    KMIP has no separate cryptoperiod attribute — Deactivation Date *is* the
    end of the period — so this stays inside the standard attribute model
    rather than inventing a parallel one."""
    if store.get_object(uid) is None:
        # Without this a mistyped identifier updates nothing and reports
        # success, leaving an operator convinced a key has a cryptoperiod it
        # does not have.
        raise ItemNotFound(f"Object '{uid}' not found")
    deadline = (datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=days)).timestamp()
    conn = store._conn()
    conn.execute("UPDATE kmip_objects SET deactivation_date = ? WHERE uuid = ?",
                 (deadline, uid))
    conn.commit()
    return deadline


class KeyLifecycleScheduler:
    """Periodically applies cryptoperiod policy.

    `run_once()` is the whole of the logic and is safe to call directly, which
    is how it gets tested without waiting on wall-clock time.
    """

    def __init__(self, store, shim=None, warn_days: float = 7.0,
                 auto_rotate: bool = False, interval_seconds: float = 300.0,
                 metrics=None):
        self._store = store
        self._shim = shim
        self._warn_days = warn_days
        self._auto_rotate = auto_rotate
        self._interval = interval_seconds
        self._metrics = metrics
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ── scanning ────────────────────────────────────────────────────────────

    def _now(self) -> float:
        return datetime.datetime.now(datetime.timezone.utc).timestamp()

    def expiring_objects(self, within_days: float) -> List[Dict[str, Any]]:
        horizon = self._now() + within_days * 86400
        rows = self._store._conn().execute(
            """SELECT uuid, deactivation_date, owner_identity, cryptographic_algorithm,
                      cryptographic_length, object_type
               FROM kmip_objects
               WHERE state = ? AND deactivation_date IS NOT NULL
                 AND deactivation_date <= ? AND destroy_date IS NULL
               ORDER BY deactivation_date ASC""",
            (State.Active, horizon)).fetchall()
        return [dict(r) for r in rows]

    def run_once(self) -> Dict[str, int]:
        """One scan. Returns what it did, which is also what the tests assert."""
        now = self._now()
        expired, warned, rotated, failed = 0, 0, 0, 0

        for obj in self.expiring_objects(self._warn_days):
            uid = obj["uuid"]
            if obj["deactivation_date"] > now:
                warned += 1
                remaining = (obj["deactivation_date"] - now) / 86400
                log.warning("Key %s reaches the end of its cryptoperiod in %.1f day(s)",
                            uid, remaining)
                self._audit(uid, "CryptoperiodWarning", "success",
                            f"expires in {remaining:.1f} days")
                continue

            # Past its cryptoperiod: rotate first if asked, so a replacement
            # exists before the old key stops being usable.
            if self._auto_rotate:
                try:
                    new_uid = self._rotate(obj)
                    rotated += 1
                    self._audit(uid, "ScheduledReKey", "success",
                                f"replaced by {new_uid}")
                except Exception as e:
                    failed += 1
                    log.exception("Scheduled rotation of %s failed", uid)
                    self._audit(uid, "ScheduledReKey", "failure", str(e)[:200])
                    # Deactivate anyway — an expired key staying Active because
                    # rotation failed is the worse outcome.

            try:
                self._store.set_state(uid, State.Deactivated)
                expired += 1
                log.info("Key %s deactivated: cryptoperiod elapsed", uid)
                self._audit(uid, "ScheduledDeactivate", "success",
                            "cryptoperiod elapsed")
            except Exception as e:
                failed += 1
                log.exception("Scheduled deactivation of %s failed", uid)
                self._audit(uid, "ScheduledDeactivate", "failure", str(e)[:200])

        if self._metrics is not None:
            try:
                for name, count in (("ScheduledDeactivate", expired),
                                    ("ScheduledReKey", rotated)):
                    for _ in range(count):
                        self._metrics.record_operation(name, "success", 0.0)
            except Exception:
                log.debug("Failed to record scheduler metrics", exc_info=True)

        return {"deactivated": expired, "warned": warned,
                "rotated": rotated, "failed": failed}

    def _rotate(self, obj: Dict[str, Any]) -> str:
        """Create a replacement key, cross-linked to the expiring one — the
        same lineage a client-driven ReKey produces, so downstream tooling
        does not need to tell them apart."""
        if self._shim is None:
            raise RuntimeError("automatic rotation needs an HSM session")
        # The scheduler starts before the server binds, so the first scan can
        # arrive ahead of the server's own initialize(). It is idempotent and
        # synchronized, and this thread is in the process that owns the
        # session, so calling it here is safe and stops a first-scan rotation
        # from failing for want of a session that is about to exist anyway.
        self._shim.initialize()
        if obj["object_type"] != ObjectType.SymmetricKey:
            raise RuntimeError(
                f"automatic rotation only supports SymmetricKey, not type {obj['object_type']}")

        from ..operations.create import create_symmetric_key
        from ..core.enums import CryptographicUsageMask

        old_uid = obj["uuid"]
        old = self._store.get_object(old_uid)
        new_uid = create_symmetric_key(
            old["cryptographic_algorithm"], old["cryptographic_length"],
            old["usage_mask"] or (CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt),
            [], bool(old["sensitive"]), bool(old["extractable"]),
            old["owner_identity"] or SCHEDULER_IDENTITY, self._store, self._shim)
        self._store.add_attribute(old_uid, "Link_ReplacementKey", new_uid)
        self._store.add_attribute(new_uid, "Link_ReplacedKey", old_uid)
        return new_uid

    def _audit(self, uid: str, operation: str, result: str, message: str):
        try:
            self._store.append_audit(
                identity=SCHEDULER_IDENTITY, operation_name=operation,
                object_uid=uid, result=result, message=message, client="scheduler")
        except Exception:
            log.exception("Failed to audit scheduler action %s on %s", operation, uid)

    # ── lifecycle ───────────────────────────────────────────────────────────

    def start(self):
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="kmip-key-scheduler")
        self._thread.start()
        log.info("Key lifecycle scheduler started (every %.0fs, warn %.0f day(s), "
                 "auto-rotate %s)", self._interval, self._warn_days, self._auto_rotate)

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                # A scan that throws must not kill the scheduler thread, or
                # policy silently stops being enforced.
                log.exception("Key lifecycle scan failed; will retry")
            self._stop.wait(self._interval)

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
