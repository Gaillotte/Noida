"""
Portal-side persistence: users, roles and the audit trail.

Deliberately separate from ``kmip_pkcs11.metadata.store``, which stays the
authoritative KMIP object store and is not modified here. This module adds
only what the portal needs and the KMIP engine never had: real user accounts
with per-user credentials, and a persisted audit trail.

Both live in the same database so a single backup covers the whole system,
and so an audit row can reference a KMIP object by UUID.
"""

import csv
import datetime
import hashlib
import hmac
import io
import json
import logging
import os
import secrets
from typing import Any, Dict, List, Optional

from kmip_pkcs11.metadata import db

log = logging.getLogger(__name__)

# The five roles from the brief. Ordered most to least privileged; the order
# is meaningful because `has_at_least` compares by index.
ROLES = ["Administrator", "SecurityOfficer", "Operator", "Auditor", "ReadOnly"]

ROLE_DESCRIPTIONS = {
    "Administrator": "Full control, including user and role management",
    "SecurityOfficer": "Key lifecycle and policy; cannot manage users",
    "Operator": "Day-to-day key operations; no destructive actions",
    "Auditor": "Read-only, plus full audit access and export",
    "ReadOnly": "Read-only; no audit export",
}

PORTAL_SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS portal_users (
    username      TEXT PRIMARY KEY,
    display_name  TEXT,
    email         TEXT,
    role          TEXT NOT NULL DEFAULT 'ReadOnly',
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    REAL NOT NULL,
    last_login    REAL
);

CREATE TABLE IF NOT EXISTS portal_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at REAL NOT NULL,
    username    TEXT,
    source_ip   TEXT,
    action      TEXT NOT NULL,
    object_uid  TEXT,
    provider    TEXT,
    result      TEXT NOT NULL,
    detail      TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_time ON portal_audit(occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_user ON portal_audit(username);
"""

PORTAL_SCHEMA_POSTGRES = """
CREATE TABLE IF NOT EXISTS portal_users (
    username      TEXT PRIMARY KEY,
    display_name  TEXT,
    email         TEXT,
    role          TEXT NOT NULL DEFAULT 'ReadOnly',
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    DOUBLE PRECISION NOT NULL,
    last_login    DOUBLE PRECISION
);

CREATE TABLE IF NOT EXISTS portal_audit (
    id          BIGSERIAL PRIMARY KEY,
    occurred_at DOUBLE PRECISION NOT NULL,
    username    TEXT,
    source_ip   TEXT,
    action      TEXT NOT NULL,
    object_uid  TEXT,
    provider    TEXT,
    result      TEXT NOT NULL,
    detail      TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_time ON portal_audit(occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_user ON portal_audit(username);
"""


def _now() -> float:
    return datetime.datetime.now(datetime.timezone.utc).timestamp()


class PortalStore:
    """Users, roles and audit records."""

    def __init__(self, dsn: str):
        self._dsn = dsn
        self._init()

    def _init(self) -> None:
        schema = PORTAL_SCHEMA_POSTGRES if db.is_postgres(self._dsn) else PORTAL_SCHEMA_SQLITE
        connection = db.connect(self._dsn)
        try:
            connection.executescript(schema)
            connection.commit()
        finally:
            connection.close()

    def _conn(self):
        return db.get_thread_connection(self._dsn)

    # ── credentials ──────────────────────────────────────────────────────────

    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> tuple:
        """PBKDF2-HMAC-SHA256, 240k iterations.

        Chosen over a bare hash because these are user passwords, not random
        tokens: without a deliberate work factor, a leaked table is a
        wordlist away from every account. bcrypt/argon2 would be preferable
        but would add a native dependency to an image that otherwise needs
        none, and PBKDF2 at this cost is a defensible middle ground.
        """
        salt = salt or secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 240_000)
        return salt, digest.hex()

    def verify_password(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        user = self.get_user(username)
        if not user or not user.get("enabled"):
            # A disabled account and a wrong password are reported the same
            # way to the caller; only the audit trail distinguishes them.
            return None
        _, candidate = self.hash_password(password, user["password_salt"])
        if not hmac.compare_digest(candidate, user["password_hash"]):
            return None
        return user

    # ── users ────────────────────────────────────────────────────────────────

    def create_user(self, username: str, password: str, role: str = "ReadOnly",
                    display_name: str = "", email: str = "") -> Dict[str, Any]:
        if role not in ROLES:
            raise ValueError(f"Unknown role '{role}'")
        salt, digest = self.hash_password(password)
        self._conn().execute(
            """INSERT INTO portal_users
               (username, display_name, email, role, password_salt, password_hash,
                enabled, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 1, ?)""",
            (username, display_name or username, email, role, salt, digest, _now()),
        )
        self._conn().commit()
        return self.get_user(username)

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        row = self._conn().execute(
            "SELECT * FROM portal_users WHERE username = ?", (username,)
        ).fetchone()
        return dict(row) if row else None

    def list_users(self) -> List[Dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT * FROM portal_users ORDER BY username"
        ).fetchall()
        return [self._public_user(dict(r)) for r in rows]

    @staticmethod
    def _public_user(user: Dict[str, Any]) -> Dict[str, Any]:
        """Strips credential material before a user record leaves the store."""
        user.pop("password_hash", None)
        user.pop("password_salt", None)
        return user

    def set_role(self, username: str, role: str) -> None:
        if role not in ROLES:
            raise ValueError(f"Unknown role '{role}'")
        self._conn().execute(
            "UPDATE portal_users SET role = ? WHERE username = ?", (role, username)
        )
        self._conn().commit()

    def set_enabled(self, username: str, enabled: bool) -> None:
        self._conn().execute(
            "UPDATE portal_users SET enabled = ? WHERE username = ?",
            (1 if enabled else 0, username),
        )
        self._conn().commit()

    def set_password(self, username: str, password: str) -> None:
        salt, digest = self.hash_password(password)
        self._conn().execute(
            "UPDATE portal_users SET password_salt = ?, password_hash = ? WHERE username = ?",
            (salt, digest, username),
        )
        self._conn().commit()

    def delete_user(self, username: str) -> None:
        self._conn().execute("DELETE FROM portal_users WHERE username = ?", (username,))
        self._conn().commit()

    def touch_login(self, username: str) -> None:
        self._conn().execute(
            "UPDATE portal_users SET last_login = ? WHERE username = ?", (_now(), username)
        )
        self._conn().commit()

    def count_users(self) -> int:
        row = self._conn().execute("SELECT COUNT(*) AS n FROM portal_users").fetchone()
        return int(row["n"])

    # ── audit ────────────────────────────────────────────────────────────────

    def audit(self, action: str, result: str, username: Optional[str] = None,
              source_ip: Optional[str] = None, object_uid: Optional[str] = None,
              provider: Optional[str] = None, detail: Optional[str] = None) -> None:
        """Appends an audit record.

        Never raises. An audit failure must not turn a successful key
        operation into an error the caller sees — that would make the system
        less reliable the more carefully it was watched. Failures are logged
        instead, which is the one case where the log file is the fallback.
        """
        try:
            self._conn().execute(
                """INSERT INTO portal_audit
                   (occurred_at, username, source_ip, action, object_uid,
                    provider, result, detail)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (_now(), username, source_ip, action, object_uid, provider, result, detail),
            )
            self._conn().commit()
        except Exception as exc:  # noqa: BLE001 - see docstring
            log.error("Audit write failed for action=%s user=%s: %s", action, username, exc)

    def list_audit(self, limit: int = 200, offset: int = 0, username: Optional[str] = None,
                   action: Optional[str] = None, result: Optional[str] = None,
                   since: Optional[float] = None) -> List[Dict[str, Any]]:
        clauses, params = [], []
        if username:
            clauses.append("username = ?")
            params.append(username)
        if action:
            clauses.append("action = ?")
            params.append(action)
        if result:
            clauses.append("result = ?")
            params.append(result)
        if since:
            clauses.append("occurred_at >= ?")
            params.append(since)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.extend([limit, offset])
        rows = self._conn().execute(
            f"SELECT * FROM portal_audit {where} ORDER BY occurred_at DESC LIMIT ? OFFSET ?",
            tuple(params),
        ).fetchall()
        return [self._render_audit(dict(r)) for r in rows]

    def count_audit(self, since: Optional[float] = None) -> int:
        if since:
            row = self._conn().execute(
                "SELECT COUNT(*) AS n FROM portal_audit WHERE occurred_at >= ?", (since,)
            ).fetchone()
        else:
            row = self._conn().execute("SELECT COUNT(*) AS n FROM portal_audit").fetchone()
        return int(row["n"])

    @staticmethod
    def _render_audit(row: Dict[str, Any]) -> Dict[str, Any]:
        row["occurred_at_iso"] = datetime.datetime.fromtimestamp(
            row["occurred_at"], datetime.timezone.utc
        ).isoformat()
        return row

    def export_audit(self, fmt: str, **filters) -> tuple:
        """Exports the audit trail.

        Returns ``(bytes, media_type, filename)``. CSV is emitted for the
        'excel' format too: a real .xlsx would pull in openpyxl for a file
        Excel opens either way, and being honest about the extension is
        better than shipping a CSV named .xlsx.
        """
        records = self.list_audit(limit=filters.pop("limit", 100000), **filters)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")

        if fmt == "json":
            payload = json.dumps(records, indent=2, default=str).encode()
            return payload, "application/json", f"audit-{stamp}.json"

        columns = ["occurred_at_iso", "username", "source_ip", "action",
                   "object_uid", "provider", "result", "detail"]
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
        return buffer.getvalue().encode(), "text/csv", f"audit-{stamp}.csv"
