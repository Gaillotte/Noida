"""
One audit view over two audit logs.

The portal records its own actions (sign-ins, user administration, exports) in
``portal_audit``. KMIP operations are recorded by the engine in ``kmip_audit``,
which is hash-chained and append-only — each row links to its predecessor, so an
edited or deleted entry can be detected.

They used to be one table: the portal injected an ``audit_sink`` into
``KMIPServer`` and every KMIP operation was written to ``portal_audit``. The
engine now writes its own log natively, and that is worth having rather than
working around — the chain is what makes the trail evidence rather than a
convenience, and the engine knows the peer address, which the injected sink
never did (it wrote the literal string "kmip-client" because the dispatcher was
never given one).

So the two logs stay separate, each authoritative for what it records, and this
module merges them on read. Engine rows are projected into the portal's column
names so the existing audit page needs no per-source special-casing.

Merging on read rather than mirroring on write is deliberate: a mirrored copy in
``portal_audit`` would be a second, unchained version of the same event, and
whichever one an auditor happened to read would look equally authoritative.
"""

import datetime
import logging
from typing import Any, Dict, List, Optional

from kmip_pkcs11.metadata import db
from kmip_pkcs11.metadata.store import MetadataStore

from .portal_store import PortalStore, serialise_audit

log = logging.getLogger(__name__)

# The portal writes SUCCESS/FAILURE; the engine writes success/failure. The API
# presents the portal's spelling, because that is what the UI filters on.
_RESULTS = {"success": "SUCCESS", "failure": "FAILURE"}


def _project(row: Dict[str, Any]) -> Dict[str, Any]:
    """Renders one engine audit row in the portal's column names."""
    occurred_at = row.get("timestamp") or 0.0
    operation = row.get("operation_name") or "unknown"
    return {
        "occurred_at": occurred_at,
        "occurred_at_iso": datetime.datetime.fromtimestamp(
            occurred_at, datetime.timezone.utc).isoformat(),
        "username": row.get("identity"),
        # The engine records the actual peer. Falls back rather than inventing
        # an address, for rows written by a path that had none.
        "source_ip": row.get("client") or "kmip",
        "action": f"kmip.{operation}",
        "object_uid": row.get("object_uid"),
        "provider": "KMIP",
        "result": _RESULTS.get(str(row.get("result", "")).lower(),
                               str(row.get("result", "")).upper()),
        "detail": row.get("message"),
        # Lets a reader tell a chained engine row from a portal row, and gives
        # the chain position for anyone checking against verify().
        "source": "kmip",
        "seq": row.get("seq"),
    }


def _engine_entries(metadata: MetadataStore, limit: int,
                    username: Optional[str] = None,
                    action: Optional[str] = None,
                    result: Optional[str] = None,
                    since: Optional[float] = None) -> List[Dict[str, Any]]:
    """Engine rows, newest first, projected and filtered like portal rows.

    Queried here rather than through ``MetadataStore.get_audit_entries``, which
    orders oldest-first: its ``limit`` therefore keeps the *oldest* rows, and
    getting the newest page out of it means reading the whole log and reversing
    it. That is fine for the admin API it was written for and wrong for a page
    that loads on every visit and grows for the life of the deployment.

    ``action`` is matched as a prefix against the projected name, which is what
    makes "kmip." in the page's action box select every engine row. It is
    applied after projection because the engine stores the bare operation name,
    not the prefixed one.
    """
    engine_result = None
    if result:
        # Only these two exist; an unrecognised value would otherwise be sent
        # to the engine and silently match nothing.
        engine_result = {"SUCCESS": "success", "FAILURE": "failure"}.get(result.upper())
        if engine_result is None:
            return []

    clauses, params = [], []
    if username:
        clauses.append("identity = ?")
        params.append(username)
    if engine_result:
        clauses.append("result = ?")
        params.append(engine_result)
    if since is not None:
        clauses.append("timestamp >= ?")
        params.append(since)
    if action and action.startswith("kmip."):
        # Push the prefix match down to SQL when the filter names an operation,
        # so a search for one operation does not scan the whole log.
        clauses.append("operation_name LIKE ?")
        params.append(action[len("kmip."):] + "%")

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)

    try:
        conn = db.get_thread_connection(metadata.dsn)
        rows = conn.execute(
            f"SELECT * FROM kmip_audit {where} ORDER BY seq DESC LIMIT ?", tuple(params),
        ).fetchall()
    except Exception:                           # noqa: BLE001
        # A broken engine log must not blank the portal's own trail.
        log.exception("Could not read the KMIP audit log")
        return []

    entries = [_project(dict(r)) for r in rows]
    if action and not action.startswith("kmip."):
        # An action filter that cannot match a projected engine name — the user
        # is filtering for portal actions.
        return []
    return entries


def _engine_count(metadata: MetadataStore) -> int:
    """Total engine rows.

    Counted in SQL rather than by fetching and measuring: this is read on every
    audit page load, and the log grows for the life of the deployment. Goes
    through :mod:`kmip_pkcs11.metadata.db`, the engine's own dialect layer, so
    it works against SQLite and PostgreSQL alike without duplicating either.
    """
    try:
        conn = db.get_thread_connection(metadata.dsn)
        row = conn.execute("SELECT COUNT(*) AS n FROM kmip_audit").fetchone()
        return int(row["n"]) if row else 0
    except Exception:                           # noqa: BLE001
        log.exception("Could not count KMIP audit entries")
        return 0


def list_events(portal: PortalStore, metadata: MetadataStore,
                limit: int = 200, offset: int = 0,
                username: Optional[str] = None,
                action: Optional[str] = None,
                result: Optional[str] = None) -> Dict[str, Any]:
    """The merged, paged audit trail, newest first.

    Each source is asked for ``offset + limit`` rows before merging. That is
    what makes paging correct: the merged page N is always drawn from the union
    of each source's first N pages, so no row can be skipped by having been
    ranked behind rows from the other log.
    """
    window = offset + limit

    portal_events = portal.list_audit(limit=window, offset=0, username=username,
                                      action=action, result=result)
    for event in portal_events:
        event.setdefault("source", "portal")

    merged = portal_events + _engine_entries(metadata, window, username=username,
                                             action=action, result=result)
    merged.sort(key=lambda e: e.get("occurred_at") or 0.0, reverse=True)

    return {
        # Unfiltered, matching what this endpoint has always reported: the size
        # of the trail, not the size of the current filtered result.
        "total": portal.count_audit() + _engine_count(metadata),
        "events": merged[offset:window],
    }


def export(portal: PortalStore, metadata: MetadataStore, fmt: str,
           limit: int = 100_000, **filters) -> tuple:
    """Exports the merged trail, so a download matches what the page shows.

    Bounded, and the bound is reported by the caller rather than silently
    applied: an export that quietly stops at 100,000 rows looks like a complete
    record of a system that has been running longer than that.
    """
    merged = list_events(portal, metadata, limit=limit, offset=0, **filters)
    return serialise_audit(merged["events"], fmt), merged["total"]


def verify(metadata: MetadataStore) -> Dict[str, Any]:
    """Chain-verification result for the engine log, for display alongside it.

    Reported rather than enforced. A broken chain does not stop the portal from
    showing the trail — an auditor looking at a tampered log needs to see both
    that fact and the rows themselves.
    """
    try:
        report = dict(metadata.verify_audit_chain())
    except Exception as exc:                    # noqa: BLE001
        log.exception("Could not verify the KMIP audit chain")
        return {"ok": None, "detail": f"Verification could not be performed: {exc}"}

    report["detail"] = (
        f"{report.get('entries', 0)} KMIP entries, hash chain intact"
        if report.get("ok") else
        f"Chain broken at entry {report.get('broken_at')}: "
        f"{report.get('reason', 'contents do not match their hash')}"
    )
    return report
