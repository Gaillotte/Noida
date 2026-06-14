"""
SQLite-backed metadata store for KMIP attributes that PKCS#11 does not hold.
Thread-safe via connection-per-thread using threading.local.
"""

import sqlite3
import threading
import uuid
import datetime
import json
import logging
from typing import Any, Dict, List, Optional

from ..core.enums import State, ObjectType

log = logging.getLogger(__name__)

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS kmip_objects (
    uuid                    TEXT PRIMARY KEY,
    object_type             INTEGER NOT NULL,
    pkcs11_handle           INTEGER,
    pkcs11_slot             INTEGER DEFAULT 0,
    state                   INTEGER NOT NULL DEFAULT 1,
    cryptographic_algorithm INTEGER,
    cryptographic_length    INTEGER,
    usage_mask              INTEGER,
    initial_date            REAL,
    activation_date         REAL,
    deactivation_date       REAL,
    destroy_date            REAL,
    compromise_date         REAL,
    revocation_reason       INTEGER,
    revocation_message      TEXT,
    sensitive               INTEGER DEFAULT 1,
    extractable             INTEGER DEFAULT 0,
    never_extractable       INTEGER DEFAULT 0,
    always_sensitive        INTEGER DEFAULT 1,
    owner_identity          TEXT,
    key_format_type         INTEGER,
    raw_key_value           BLOB,
    created_at              REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS kmip_attributes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    object_uuid TEXT NOT NULL REFERENCES kmip_objects(uuid) ON DELETE CASCADE,
    attr_name   TEXT NOT NULL,
    attr_index  INTEGER DEFAULT 0,
    attr_value  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attr_lookup
    ON kmip_attributes(object_uuid, attr_name);

CREATE INDEX IF NOT EXISTS idx_state
    ON kmip_objects(state);
"""


class MetadataStore:
    def __init__(self, db_path: str = ":memory:"):
        self._db_path = db_path
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(_local, 'conn') or _local.db_path != self._db_path:
            _local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            _local.conn.row_factory = sqlite3.Row
            _local.conn.execute("PRAGMA journal_mode=WAL")
            _local.conn.execute("PRAGMA foreign_keys=ON")
            _local.db_path = self._db_path
        return _local.conn

    def _init_db(self):
        conn = sqlite3.connect(self._db_path)
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()

    # ── create ────────────────────────────────────────────────────────────────

    def create_object(
        self,
        object_type: int,
        pkcs11_handle: Optional[int] = None,
        pkcs11_slot: int = 0,
        state: int = State.PreActive,
        cryptographic_algorithm: Optional[int] = None,
        cryptographic_length: Optional[int] = None,
        usage_mask: Optional[int] = None,
        sensitive: bool = True,
        extractable: bool = False,
        owner_identity: str = "anonymous",
        key_format_type: Optional[int] = None,
        raw_key_value: Optional[bytes] = None,
        names: Optional[List[str]] = None,
        activation_date: Optional[datetime.datetime] = None,
    ) -> str:
        uid = str(uuid.uuid4())
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        act_ts = activation_date.timestamp() if activation_date else None

        initial_state = state
        if activation_date and activation_date <= datetime.datetime.now(datetime.timezone.utc):
            initial_state = State.Active

        conn = self._conn()
        conn.execute(
            """INSERT INTO kmip_objects
               (uuid, object_type, pkcs11_handle, pkcs11_slot, state,
                cryptographic_algorithm, cryptographic_length, usage_mask,
                initial_date, activation_date, sensitive, extractable,
                owner_identity, key_format_type, raw_key_value, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (uid, object_type, pkcs11_handle, pkcs11_slot, initial_state,
             cryptographic_algorithm, cryptographic_length, usage_mask,
             now, act_ts, int(sensitive), int(extractable),
             owner_identity, key_format_type, raw_key_value, now)
        )
        if names:
            for i, name in enumerate(names):
                conn.execute(
                    "INSERT INTO kmip_attributes (object_uuid, attr_name, attr_index, attr_value) VALUES (?,?,?,?)",
                    (uid, "Name", i, json.dumps({"value": name, "type": 1}))
                )
        conn.commit()
        log.debug("Created object %s type=%d state=%d", uid, object_type, initial_state)
        return uid

    # ── read ─────────────────────────────────────────────────────────────────

    def get_object(self, uid: str) -> Optional[Dict[str, Any]]:
        row = self._conn().execute(
            "SELECT * FROM kmip_objects WHERE uuid = ?", (uid,)
        ).fetchone()
        return dict(row) if row else None

    def get_attributes(self, uid: str) -> List[Dict]:
        rows = self._conn().execute(
            "SELECT attr_name, attr_index, attr_value FROM kmip_attributes WHERE object_uuid = ? ORDER BY attr_name, attr_index",
            (uid,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_attribute(self, uid: str, name: str) -> List[Any]:
        rows = self._conn().execute(
            "SELECT attr_value FROM kmip_attributes WHERE object_uuid=? AND attr_name=? ORDER BY attr_index",
            (uid, name)
        ).fetchall()
        return [json.loads(r["attr_value"]) for r in rows]

    # ── update ────────────────────────────────────────────────────────────────

    def set_state(self, uid: str, state: int):
        conn = self._conn()
        conn.execute("UPDATE kmip_objects SET state=? WHERE uuid=?", (state, uid))
        conn.commit()

    def set_destroy(self, uid: str):
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        conn = self._conn()
        conn.execute(
            "UPDATE kmip_objects SET state=?, destroy_date=?, pkcs11_handle=NULL WHERE uuid=?",
            (State.Destroyed, now, uid)
        )
        conn.commit()

    def set_revoke(self, uid: str, state: int, reason: int, message: str = ""):
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        conn = self._conn()
        if state in (State.Compromised, State.DestroyedCompromised):
            conn.execute(
                "UPDATE kmip_objects SET state=?, compromise_date=?, revocation_reason=?, revocation_message=? WHERE uuid=?",
                (state, now, reason, message, uid)
            )
        else:
            conn.execute(
                "UPDATE kmip_objects SET state=?, deactivation_date=?, revocation_reason=?, revocation_message=? WHERE uuid=?",
                (state, now, reason, message, uid)
            )
        conn.commit()

    def activate(self, uid: str):
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        conn = self._conn()
        conn.execute(
            "UPDATE kmip_objects SET state=?, activation_date=? WHERE uuid=?",
            (State.Active, now, uid)
        )
        conn.commit()

    def add_attribute(self, uid: str, name: str, value: Any):
        existing = self._conn().execute(
            "SELECT MAX(attr_index) as mi FROM kmip_attributes WHERE object_uuid=? AND attr_name=?",
            (uid, name)
        ).fetchone()
        idx = (existing["mi"] + 1) if existing and existing["mi"] is not None else 0
        self._conn().execute(
            "INSERT INTO kmip_attributes (object_uuid, attr_name, attr_index, attr_value) VALUES (?,?,?,?)",
            (uid, name, idx, json.dumps(value))
        )
        self._conn().commit()

    def delete_attribute(self, uid: str, name: str, index: int = 0):
        self._conn().execute(
            "DELETE FROM kmip_attributes WHERE object_uuid=? AND attr_name=? AND attr_index=?",
            (uid, name, index)
        )
        self._conn().commit()

    def set_activation_date(self, uid: str, dt: datetime.datetime):
        conn = self._conn()
        conn.execute(
            "UPDATE kmip_objects SET activation_date=? WHERE uuid=?",
            (dt.timestamp(), uid)
        )
        conn.commit()

    # ── locate ────────────────────────────────────────────────────────────────

    def locate(
        self,
        object_type: Optional[int] = None,
        state: Optional[int] = None,
        name: Optional[str] = None,
        cryptographic_algorithm: Optional[int] = None,
        cryptographic_length: Optional[int] = None,
        owner: Optional[str] = None,
        max_items: Optional[int] = None,
    ) -> List[str]:
        clauses = []
        params: list = []

        if object_type is not None:
            clauses.append("o.object_type = ?")
            params.append(object_type)
        if state is not None:
            clauses.append("o.state = ?")
            params.append(state)
        if cryptographic_algorithm is not None:
            clauses.append("o.cryptographic_algorithm = ?")
            params.append(cryptographic_algorithm)
        if cryptographic_length is not None:
            clauses.append("o.cryptographic_length = ?")
            params.append(cryptographic_length)
        if owner is not None:
            clauses.append("o.owner_identity = ?")
            params.append(owner)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        if name is not None:
            sql = f"""
                SELECT DISTINCT o.uuid FROM kmip_objects o
                JOIN kmip_attributes a ON a.object_uuid = o.uuid
                {where + (' AND ' if where else 'WHERE ')} a.attr_name = 'Name'
                  AND json_extract(a.attr_value, '$.value') = ?
                ORDER BY o.created_at DESC
            """
            params.append(name)
        else:
            sql = f"SELECT o.uuid FROM kmip_objects o {where} ORDER BY o.created_at DESC"

        if max_items:
            sql += f" LIMIT {int(max_items)}"

        rows = self._conn().execute(sql, params).fetchall()
        return [r["uuid"] for r in rows]

    # ── list all (for admin/tests) ─────────────────────────────────────────────

    def list_objects(self) -> List[str]:
        rows = self._conn().execute("SELECT uuid FROM kmip_objects ORDER BY created_at").fetchall()
        return [r["uuid"] for r in rows]

    def object_exists(self, uid: str) -> bool:
        row = self._conn().execute(
            "SELECT 1 FROM kmip_objects WHERE uuid=?", (uid,)
        ).fetchone()
        return row is not None
