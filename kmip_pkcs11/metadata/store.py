"""
SQLite-backed metadata store for KMIP attributes that PKCS#11 does not hold.
Thread-safe via connection-per-thread using threading.local.
"""

import hashlib
import hmac
import os
import sqlite3
import threading
import time
import uuid
import datetime
import json
import logging
from typing import Any, Dict, List, Optional

from ..core.enums import State, ObjectType
from ..core.exceptions import CryptographicFailure

log = logging.getLogger(__name__)

_local = threading.local()

# scrypt work factors for password hashing. n=2**14 is the standard
# "interactive" setting — roughly 50ms per hash, which is a meaningful
# brute-force cost without making authentication feel slow.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P, _SCRYPT_DKLEN = 2 ** 14, 8, 1, 32
_SALT_BYTES = 16


def _scrypt(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        (password or "").encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN,
    )

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
    archived                INTEGER DEFAULT 0,
    archive_date            REAL,
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

CREATE TABLE IF NOT EXISTS kmip_identities (
    identity      TEXT PRIMARY KEY,
    password_hash BLOB NOT NULL,
    salt          BLOB NOT NULL,
    algorithm     TEXT NOT NULL DEFAULT 'scrypt',
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS kmip_identity_roles (
    identity TEXT NOT NULL,
    role     TEXT NOT NULL,
    PRIMARY KEY (identity, role)
);

CREATE TABLE IF NOT EXISTS kmip_object_grants (
    object_uuid TEXT NOT NULL REFERENCES kmip_objects(uuid) ON DELETE CASCADE,
    grantee     TEXT NOT NULL,
    permission  TEXT NOT NULL DEFAULT 'full',
    PRIMARY KEY (object_uuid, grantee)
);

CREATE INDEX IF NOT EXISTS idx_grants_object
    ON kmip_object_grants(object_uuid);

CREATE TABLE IF NOT EXISTS kmip_audit (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      REAL NOT NULL,
    identity       TEXT,
    operation      INTEGER,
    operation_name TEXT,
    object_uid     TEXT,
    result         TEXT NOT NULL,
    result_reason  INTEGER,
    message        TEXT,
    client         TEXT,
    prev_hash      TEXT NOT NULL,
    entry_hash     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_object ON kmip_audit(object_uid);
CREATE INDEX IF NOT EXISTS idx_audit_identity ON kmip_audit(identity);
CREATE INDEX IF NOT EXISTS idx_audit_time ON kmip_audit(timestamp);

-- The audit log is append-only. These triggers block UPDATE and DELETE
-- outright, so ordinary application bugs and casual tampering fail loudly
-- rather than quietly rewriting history. They are not a defence against
-- someone with direct file access, who can simply drop them — that is what
-- the hash chain in each row is for. Retention pruning goes through
-- MetadataStore.prune_audit(), which lifts them deliberately.
CREATE TRIGGER IF NOT EXISTS kmip_audit_no_update
BEFORE UPDATE ON kmip_audit
BEGIN SELECT RAISE(ABORT, 'kmip_audit is append-only'); END;

CREATE TRIGGER IF NOT EXISTS kmip_audit_no_delete
BEFORE DELETE ON kmip_audit
BEGIN SELECT RAISE(ABORT, 'kmip_audit is append-only'); END;
"""

# ── schema migrations ────────────────────────────────────────────────────────
# SCHEMA above is the *baseline* and is only ever additive (CREATE ... IF NOT
# EXISTS), so it can be replayed safely against any database. Anything that
# changes an existing table — a new column, an index on it, a backfill — has to
# go here instead, because CREATE TABLE IF NOT EXISTS silently does nothing on
# a database that already has the table, and the change would never land.
#
# Applied in order, gated on PRAGMA user_version. A fresh database runs the
# baseline and then every migration, so both paths converge on the same shape.
_MIGRATIONS = [
    (
        1,
        "add raw_key_encrypted flag",
        [
            "ALTER TABLE kmip_objects "
            "ADD COLUMN raw_key_encrypted INTEGER NOT NULL DEFAULT 0",
        ],
    ),
]

SCHEMA_VERSION = _MIGRATIONS[-1][0] if _MIGRATIONS else 0


class MetadataStore:
    def __init__(self, db_path: str = ":memory:", blob_cipher=None):
        """`blob_cipher` (a metadata.blob_cipher.BlobCipher) encrypts the
        `raw_key_value` payloads of object types that have no PKCS#11 object
        behind them. Without one the store still works, but those payloads are
        written in the clear — so production wiring should always pass it.
        KMIPServer does this for you."""
        self._db_path = db_path
        self._cipher = blob_cipher
        # Appending to the audit log is read-then-write (fetch the previous
        # entry's hash, then insert linking to it). Connections are
        # per-thread, so without this lock two concurrent requests can read the
        # same prev_hash and produce a forked chain that verification would
        # then report as tampering.
        self._audit_lock = threading.Lock()
        # Short-lived cache of *successful* credential verifications. KMIP
        # carries the Credential in every request header, and scrypt costs
        # ~40ms by design, so verifying per request pinned throughput at ~25
        # requests/second per connection and handed any unauthenticated client
        # a way to burn 40ms of CPU per packet. Keyed by a peppered hash of the
        # password, never the password itself; failures are never cached, so
        # guessing still pays the full derivation cost every attempt.
        self._verify_cache = {}
        self._verify_cache_lock = threading.Lock()
        self._verify_pepper = os.urandom(32)
        self._init_db()
        if self._cipher is not None:
            self.encrypt_existing_blobs()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(_local, 'conn') or _local.db_path != self._db_path:
            _local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            _local.conn.row_factory = sqlite3.Row
            _local.conn.execute("PRAGMA journal_mode=WAL")
            _local.conn.execute("PRAGMA foreign_keys=ON")
            # WAL allows one writer at a time. With several worker processes
            # on one database, a writer that arrives mid-write must wait for
            # the lock rather than fail immediately with SQLITE_BUSY.
            _local.conn.execute("PRAGMA busy_timeout=10000")
            _local.db_path = self._db_path
        return _local.conn

    def _init_db(self):
        conn = sqlite3.connect(self._db_path)
        try:
            conn.executescript(SCHEMA)
            self._apply_migrations(conn)
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _apply_migrations(conn: sqlite3.Connection):
        """Bring the database up to SCHEMA_VERSION, running only the
        migrations it hasn't seen. Each one commits with its version bump so an
        interrupted upgrade resumes rather than half-applying."""
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        for version, description, statements in _MIGRATIONS:
            if version <= current:
                continue
            log.info("Applying schema migration %d (%s)", version, description)
            for sql in statements:
                conn.execute(sql)
            # PRAGMA doesn't accept bound parameters; version is an int literal
            # from our own migration table, never external input.
            conn.execute(f"PRAGMA user_version = {int(version)}")
            conn.commit()

    def schema_version(self) -> int:
        return self._conn().execute("PRAGMA user_version").fetchone()[0]

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
        uid: Optional[str] = None,
    ) -> str:
        uid = uid or str(uuid.uuid4())
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        act_ts = activation_date.timestamp() if activation_date else None

        initial_state = state
        if activation_date and activation_date <= datetime.datetime.now(datetime.timezone.utc):
            initial_state = State.Active

        stored_blob, encrypted = self._encrypt_blob(object_type, raw_key_value)

        conn = self._conn()
        conn.execute(
            """INSERT INTO kmip_objects
               (uuid, object_type, pkcs11_handle, pkcs11_slot, state,
                cryptographic_algorithm, cryptographic_length, usage_mask,
                initial_date, activation_date, sensitive, extractable,
                owner_identity, key_format_type, raw_key_value,
                raw_key_encrypted, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (uid, object_type, pkcs11_handle, pkcs11_slot, initial_state,
             cryptographic_algorithm, cryptographic_length, usage_mask,
             now, act_ts, int(sensitive), int(extractable),
             owner_identity, key_format_type, stored_blob,
             int(encrypted), now)
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

    # ── blob encryption ──────────────────────────────────────────────────────
    # Certificates are public by definition and stay readable in the clear so
    # they remain greppable and usable without the HSM. Every other object type
    # that puts bytes in raw_key_value is holding a secret — SecretData,
    # OpaqueObject payloads, SplitKey shares — and gets enveloped. Denylisting
    # certificates rather than allowlisting the secret types means a new object
    # type added later is encrypted by default.

    def _should_encrypt(self, object_type: int) -> bool:
        return self._cipher is not None and object_type != ObjectType.Certificate

    def _encrypt_blob(self, object_type: int, raw: Optional[bytes]):
        """Returns (bytes_to_store, was_encrypted)."""
        if raw is None or not self._should_encrypt(object_type):
            return raw, False
        return self._cipher.encrypt(bytes(raw)), True

    def _decrypt_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Transparently unwrap raw_key_value so callers never handle
        ciphertext. A row flagged encrypted with no cipher configured is an
        error, not something to paper over by returning the envelope bytes."""
        if not row.get("raw_key_encrypted") or row.get("raw_key_value") is None:
            return row
        if self._cipher is None:
            raise CryptographicFailure(
                f"Object '{row.get('uuid')}' has encrypted key material but the "
                f"metadata store was opened without a master key"
            )
        row["raw_key_value"] = self._cipher.decrypt(row["raw_key_value"])
        return row

    # ── read ─────────────────────────────────────────────────────────────────

    def get_object(self, uid: str) -> Optional[Dict[str, Any]]:
        row = self._conn().execute(
            "SELECT * FROM kmip_objects WHERE uuid = ?", (uid,)
        ).fetchone()
        return self._decrypt_row(dict(row)) if row else None

    def get_owner(self, uid: str) -> Optional[str]:
        """Lightweight existence + ownership lookup, for handlers (attribute
        mutation ops) that don't need the full object row. Returns None if
        the object doesn't exist."""
        row = self._conn().execute(
            "SELECT owner_identity FROM kmip_objects WHERE uuid = ?", (uid,)
        ).fetchone()
        return row["owner_identity"] if row else None

    # ── audit log ────────────────────────────────────────────────────────────
    # Every entry carries the hash of the one before it, so removing or
    # editing any row breaks every link after it. Detection, not prevention:
    # combined with the append-only triggers it means tampering requires file
    # access *and* leaves evidence that verify_audit_chain() will find.

    @staticmethod
    def _audit_hash(prev_hash: str, fields: Dict[str, Any]) -> str:
        # json.dumps with sorted keys gives a canonical, unambiguous encoding —
        # concatenating fields with a separator would let a value containing
        # that separator forge a different record with the same hash.
        canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()

    GENESIS_HASH = "0" * 64

    def append_audit(
        self,
        identity: Optional[str],
        operation: Optional[int] = None,
        operation_name: Optional[str] = None,
        object_uid: Optional[str] = None,
        result: str = "success",
        result_reason: Optional[int] = None,
        message: Optional[str] = None,
        client: Optional[str] = None,
    ) -> int:
        """Append one tamper-evident audit record. Returns its sequence number."""
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        fields = {
            "timestamp": round(now, 6),
            "identity": identity,
            "operation": operation,
            "operation_name": operation_name,
            "object_uid": object_uid,
            "result": result,
            "result_reason": result_reason,
            "message": message,
            "client": client,
        }
        # The thread lock keeps same-process contention cheap; BEGIN IMMEDIATE
        # is what actually makes this correct. Appending is read-then-write
        # (fetch the previous hash, insert linking to it), and a plain
        # transaction takes its write lock only at the INSERT — leaving room
        # for two *processes* to read the same predecessor and fork the chain.
        # IMMEDIATE takes the write lock up front, so the read and the write
        # are one atomic step across every process on the database.
        with self._audit_lock:
            conn = self._conn()
            if conn.in_transaction:
                conn.commit()
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT entry_hash FROM kmip_audit ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                prev_hash = row["entry_hash"] if row else self.GENESIS_HASH
                entry_hash = self._audit_hash(prev_hash, fields)
                cur = conn.execute(
                    """INSERT INTO kmip_audit
                         (timestamp, identity, operation, operation_name, object_uid,
                          result, result_reason, message, client, prev_hash, entry_hash)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (fields["timestamp"], identity, operation, operation_name, object_uid,
                     result, result_reason, message, client, prev_hash, entry_hash),
                )
                conn.commit()
                return cur.lastrowid
            except Exception:
                conn.rollback()
                raise

    def get_audit_entries(
        self,
        identity: Optional[str] = None,
        object_uid: Optional[str] = None,
        result: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Query the audit log. This is the 'who did what to which object when'
        surface — deliberately a server-admin API, not a KMIP operation."""
        clauses, params = [], []
        for column, value in (("identity", identity), ("object_uid", object_uid),
                              ("result", result)):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        if until is not None:
            clauses.append("timestamp <= ?")
            params.append(until)

        sql = "SELECT * FROM kmip_audit"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq ASC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        return [dict(r) for r in self._conn().execute(sql, params).fetchall()]

    def verify_audit_chain(self) -> Dict[str, Any]:
        """Recompute the chain and report the first row that doesn't match.

        `ok` False means the log has been altered: a row was edited, deleted,
        or inserted out of band. `chain_start_prev_hash` is the hash the first
        remaining row links back to — after pruning it refers to an archived
        entry, so an operator can confirm continuity against that archive."""
        rows = self._conn().execute("SELECT * FROM kmip_audit ORDER BY seq ASC").fetchall()
        if not rows:
            return {"ok": True, "entries": 0, "broken_at": None,
                    "chain_start_prev_hash": None}

        expected_prev = rows[0]["prev_hash"]
        for row in rows:
            fields = {
                "timestamp": row["timestamp"],
                "identity": row["identity"],
                "operation": row["operation"],
                "operation_name": row["operation_name"],
                "object_uid": row["object_uid"],
                "result": row["result"],
                "result_reason": row["result_reason"],
                "message": row["message"],
                "client": row["client"],
            }
            if row["prev_hash"] != expected_prev:
                return {"ok": False, "entries": len(rows), "broken_at": row["seq"],
                        "reason": "chain link does not match previous entry",
                        "chain_start_prev_hash": rows[0]["prev_hash"]}
            if self._audit_hash(row["prev_hash"], fields) != row["entry_hash"]:
                return {"ok": False, "entries": len(rows), "broken_at": row["seq"],
                        "reason": "entry contents do not match their hash",
                        "chain_start_prev_hash": rows[0]["prev_hash"]}
            expected_prev = row["entry_hash"]

        return {"ok": True, "entries": len(rows), "broken_at": None,
                "chain_start_prev_hash": rows[0]["prev_hash"]}

    def prune_audit(self, before_timestamp: float) -> Dict[str, Any]:
        """Retention: drop entries older than a cutoff, returning them so the
        caller can archive them first.

        This is the one sanctioned way past the append-only triggers, and it
        refuses to run on a log that already fails verification — pruning a
        tampered log would destroy the evidence. Entries after the cutoff keep
        their links, so the chain stays verifiable from the cut point; the
        returned rows carry the hashes needed to prove continuity with what
        came before."""
        report = self.verify_audit_chain()
        if not report["ok"]:
            raise CryptographicFailure(
                f"Refusing to prune: audit chain is broken at seq {report['broken_at']}"
            )

        with self._audit_lock:
            conn = self._conn()
            doomed = [dict(r) for r in conn.execute(
                "SELECT * FROM kmip_audit WHERE timestamp < ? ORDER BY seq ASC",
                (before_timestamp,)).fetchall()]
            if not doomed:
                return {"pruned": 0, "entries": []}

            conn.execute("DROP TRIGGER IF EXISTS kmip_audit_no_delete")
            try:
                conn.execute("DELETE FROM kmip_audit WHERE timestamp < ?", (before_timestamp,))
                conn.commit()
            finally:
                conn.execute(
                    "CREATE TRIGGER IF NOT EXISTS kmip_audit_no_delete "
                    "BEFORE DELETE ON kmip_audit "
                    "BEGIN SELECT RAISE(ABORT, 'kmip_audit is append-only'); END"
                )
                conn.commit()

        log.info("Pruned %d audit entries older than %s", len(doomed), before_timestamp)
        return {"pruned": len(doomed), "entries": doomed}

    # ── master-key operations ────────────────────────────────────────────────

    def encrypt_existing_blobs(self) -> int:
        """Envelope any secret blob still stored in the clear. Runs at startup
        whenever a cipher is configured, so upgrading an existing deployment
        converts its data without an operator step. Returns rows converted."""
        if self._cipher is None:
            return 0
        conn = self._conn()
        rows = conn.execute(
            "SELECT uuid, object_type, raw_key_value FROM kmip_objects "
            "WHERE raw_key_encrypted = 0 AND raw_key_value IS NOT NULL"
        ).fetchall()

        converted = 0
        for row in rows:
            if not self._should_encrypt(row["object_type"]):
                continue
            conn.execute(
                "UPDATE kmip_objects SET raw_key_value = ?, raw_key_encrypted = 1 WHERE uuid = ?",
                (self._cipher.encrypt(bytes(row["raw_key_value"])), row["uuid"]),
            )
            converted += 1
        if converted:
            conn.commit()
            self._scrub_freed_pages(conn)
            log.info("Encrypted %d previously-cleartext key blob(s)", converted)
        return converted

    @staticmethod
    def _scrub_freed_pages(conn: sqlite3.Connection):
        """Remove superseded cleartext from the database files after a backfill.

        Encrypting a row with UPDATE does not erase what was there before: in
        WAL mode the original plaintext INSERT stays in the -wal sidecar, and
        after a checkpoint it can linger in pages the main file has freed but
        not overwritten. Without this, upgrading a deployment leaves the very
        secrets we just encrypted sitting in the clear next to the ciphertext —
        verified by grepping the sidecar after a backfill.

        Checkpointing with TRUNCATE resets the WAL; VACUUM rebuilds the main
        file so freed pages are dropped rather than merely unreferenced.

        This scrubs the *database files*. It cannot reach copies that already
        left them — filesystem snapshots, prior backups, or blocks retained by
        a wear-levelling SSD — so a store that ever held cleartext secrets
        should be treated as exposed until those are rotated too.
        """
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.execute("VACUUM")   # cannot run inside a transaction
            conn.commit()
        except sqlite3.Error as e:
            # Never fail the upgrade over this — the data is encrypted either
            # way; loudly flag that the old plaintext may still be recoverable.
            log.warning(
                "Could not scrub superseded cleartext from the database files "
                "(%s); previously-stored secrets may remain recoverable from "
                "the -wal sidecar or freed pages", e
            )

    def rotate_master_key(self, retire_previous: bool = True) -> Dict[str, int]:
        """Re-encrypt every enveloped blob under a freshly generated master key.

        Rows are converted and committed one at a time. That is deliberate: the
        envelope records which key encrypted it, so an interrupted rotation
        leaves a mix of old and new that is still entirely readable, and simply
        re-running this finishes the job. The old key is destroyed only after
        every row has moved off it — and only if `retire_previous`."""
        if self._cipher is None:
            raise CryptographicFailure("Cannot rotate: no master key configured")

        previous_key_id = self._cipher.begin_rotation()
        conn = self._conn()
        rows = conn.execute(
            "SELECT uuid, raw_key_value FROM kmip_objects WHERE raw_key_encrypted = 1"
        ).fetchall()

        rotated = 0
        for row in rows:
            plaintext = self._cipher.decrypt(row["raw_key_value"])
            conn.execute(
                "UPDATE kmip_objects SET raw_key_value = ? WHERE uuid = ?",
                (self._cipher.encrypt(plaintext), row["uuid"]),
            )
            conn.commit()
            rotated += 1

        retired = 0
        if retire_previous and previous_key_id != self._cipher.active_key_id:
            self._cipher.retire_key(previous_key_id)
            retired = 1

        log.info("Master key rotation complete: %d blob(s) re-encrypted", rotated)
        return {"rotated": rotated, "retired_keys": retired}

    # ── identities (authentication) ──────────────────────────────────────────
    # Per-user credentials. Each identity gets its own random salt and an
    # independently revocable password — replacing the previous model, where
    # every caller authenticated with the single shared PKCS#11 token PIN and
    # could therefore claim any username. Like roles and grants, this is a
    # server-admin surface: KMIP defines no wire operation for it.

    def create_identity(self, identity: str, password: str) -> None:
        """Create (or replace the password of) an identity."""
        salt = os.urandom(_SALT_BYTES)
        digest = _scrypt(password, salt)
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        conn = self._conn()
        conn.execute(
            """INSERT INTO kmip_identities
                 (identity, password_hash, salt, algorithm, disabled, created_at)
               VALUES (?,?,?,'scrypt',0,?)
               ON CONFLICT(identity) DO UPDATE SET
                 password_hash = excluded.password_hash,
                 salt          = excluded.salt,
                 algorithm     = excluded.algorithm""",
            (identity, digest, salt, now),
        )
        conn.commit()
        self._invalidate_verify_cache(identity)
        log.info("Identity '%s' credentials set", identity)

    # Password rotation is the same operation as creation; the alias exists so
    # calling code can say what it means.
    set_password = create_identity

    VERIFY_CACHE_TTL = 30.0        # seconds a successful verification is reused
    VERIFY_CACHE_MAX = 1024        # bound, so this cannot grow without limit

    def _verify_cache_key(self, identity: str, password: str) -> bytes:
        return hmac.new(self._verify_pepper,
                        f"{identity}\x00{password}".encode("utf-8"),
                        hashlib.sha256).digest()

    def _invalidate_verify_cache(self, identity: str = None):
        """Drop cached verifications so a password change, disable or delete
        takes effect immediately rather than after the TTL."""
        with self._verify_cache_lock:
            if identity is None:
                self._verify_cache.clear()
            else:
                for key in [k for k, v in self._verify_cache.items() if v[1] == identity]:
                    del self._verify_cache[key]

    def verify_identity(self, identity: str, password: str) -> bool:
        """Constant-time password check. False for unknown or disabled
        identities — callers must not distinguish those cases."""
        now = time.monotonic()
        cache_key = self._verify_cache_key(identity, password)
        with self._verify_cache_lock:
            hit = self._verify_cache.get(cache_key)
            if hit and hit[0] > now:
                return True
            if hit:
                del self._verify_cache[cache_key]

        ok = self._verify_identity_uncached(identity, password)
        if ok:
            with self._verify_cache_lock:
                if len(self._verify_cache) >= self.VERIFY_CACHE_MAX:
                    # Evict anything already expired; failing that, the entry
                    # closest to expiry.
                    expired = [k for k, v in self._verify_cache.items() if v[0] <= now]
                    for k in expired:
                        del self._verify_cache[k]
                    if len(self._verify_cache) >= self.VERIFY_CACHE_MAX:
                        oldest = min(self._verify_cache, key=lambda k: self._verify_cache[k][0])
                        del self._verify_cache[oldest]
                self._verify_cache[cache_key] = (now + self.VERIFY_CACHE_TTL, identity)
        return ok

    def _verify_identity_uncached(self, identity: str, password: str) -> bool:
        row = self._conn().execute(
            "SELECT password_hash, salt, disabled FROM kmip_identities WHERE identity = ?",
            (identity,),
        ).fetchone()

        if row is None:
            # Hash anyway against a throwaway salt so an unknown identity costs
            # the same wall-clock time as a known one — otherwise the response
            # latency enumerates valid usernames.
            _scrypt(password, b"\x00" * _SALT_BYTES)
            return False
        if row["disabled"]:
            _scrypt(password, bytes(row["salt"]))
            return False

        return hmac.compare_digest(bytes(row["password_hash"]), _scrypt(password, bytes(row["salt"])))

    def delete_identity(self, identity: str) -> None:
        conn = self._conn()
        conn.execute("DELETE FROM kmip_identities WHERE identity = ?", (identity,))
        conn.commit()
        self._invalidate_verify_cache(identity)

    def set_identity_disabled(self, identity: str, disabled: bool = True) -> None:
        conn = self._conn()
        conn.execute(
            "UPDATE kmip_identities SET disabled = ? WHERE identity = ?",
            (int(disabled), identity),
        )
        conn.commit()
        self._invalidate_verify_cache(identity)

    def identity_exists(self, identity: str) -> bool:
        row = self._conn().execute(
            "SELECT 1 FROM kmip_identities WHERE identity = ?", (identity,)
        ).fetchone()
        return row is not None

    def list_identities(self) -> List[Dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT identity, disabled, created_at FROM kmip_identities ORDER BY identity"
        ).fetchall()
        return [dict(r) for r in rows]

    # ── roles ────────────────────────────────────────────────────────────────
    # No KMIP wire operation manages these (the spec doesn't define one) —
    # they're a server-admin surface, called directly against MetadataStore.

    def assign_role(self, identity: str, role: str):
        self._conn().execute(
            "INSERT OR IGNORE INTO kmip_identity_roles (identity, role) VALUES (?, ?)",
            (identity, role),
        )
        self._conn().commit()

    def revoke_role(self, identity: str, role: str):
        self._conn().execute(
            "DELETE FROM kmip_identity_roles WHERE identity = ? AND role = ?",
            (identity, role),
        )
        self._conn().commit()

    def get_roles(self, identity: str) -> List[str]:
        rows = self._conn().execute(
            "SELECT role FROM kmip_identity_roles WHERE identity = ?", (identity,)
        ).fetchall()
        return [r["role"] for r in rows]

    # ── delegated object grants ─────────────────────────────────────────────
    # Also admin-surface-only; see lifecycle/access_control.py for how these
    # are consulted (after ownership, before falling through to NotAuthorized).

    def grant_access(self, uid: str, grantee: str, permission: str = "full"):
        self._conn().execute(
            """INSERT INTO kmip_object_grants (object_uuid, grantee, permission)
               VALUES (?, ?, ?)
               ON CONFLICT(object_uuid, grantee) DO UPDATE SET permission = excluded.permission""",
            (uid, grantee, permission),
        )
        self._conn().commit()

    def revoke_access(self, uid: str, grantee: str):
        self._conn().execute(
            "DELETE FROM kmip_object_grants WHERE object_uuid = ? AND grantee = ?",
            (uid, grantee),
        )
        self._conn().commit()

    def get_grant(self, uid: str, grantee: str) -> Optional[str]:
        row = self._conn().execute(
            "SELECT permission FROM kmip_object_grants WHERE object_uuid = ? AND grantee = ?",
            (uid, grantee),
        ).fetchone()
        return row["permission"] if row else None

    def list_grants(self, uid: str) -> List[Dict]:
        rows = self._conn().execute(
            "SELECT grantee, permission FROM kmip_object_grants WHERE object_uuid = ?", (uid,)
        ).fetchall()
        return [dict(r) for r in rows]

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

    def delete_object(self, uid: str):
        """Permanently remove an object and its attributes (used by Import/ReplaceExisting)."""
        conn = self._conn()
        conn.execute("DELETE FROM kmip_objects WHERE uuid=?", (uid,))
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

    def archive_object(self, uid: str):
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        conn = self._conn()
        conn.execute(
            "UPDATE kmip_objects SET archived=1, archive_date=? WHERE uuid=?",
            (now, uid)
        )
        conn.commit()

    def recover_object(self, uid: str):
        conn = self._conn()
        conn.execute(
            "UPDATE kmip_objects SET archived=0, archive_date=NULL WHERE uuid=?",
            (uid,)
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

    def update_attribute(self, uid: str, name: str, value: Any, index: int = 0) -> int:
        cur = self._conn().execute(
            "UPDATE kmip_attributes SET attr_value=? WHERE object_uuid=? AND attr_name=? AND attr_index=?",
            (json.dumps(value), uid, name, index)
        )
        self._conn().commit()
        return cur.rowcount

    def set_or_add_attribute(self, uid: str, name: str, value: Any, index: int = 0):
        rows = self.update_attribute(uid, name, value, index)
        if rows == 0:
            self._conn().execute(
                "INSERT INTO kmip_attributes (object_uuid, attr_name, attr_index, attr_value) VALUES (?,?,?,?)",
                (uid, name, index, json.dumps(value))
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
