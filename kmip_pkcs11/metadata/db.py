"""
Database dialect layer for the metadata store.

The store was written against SQLite and is covered by 624 tests that run
against it. CryptoHub Lite needs PostgreSQL. Rather than rewrite 34 SQL
statements and risk that test asset, this module adapts the small number of
places where the two dialects actually differ and leaves the SQL in
``store.py`` untouched.

Selection is by connection string:

* ``postgresql://user:pass@host/db`` -> PostgreSQL
* anything else                      -> SQLite, treated as a file path

SQLite therefore remains the default and the test path stays byte-for-byte
what it was.

What actually differs, and is handled here:

======================  ==========================  ==========================
Concern                 SQLite                      PostgreSQL
======================  ==========================  ==========================
Placeholder             ``?``                       ``%s``
Upsert-ignore           ``INSERT OR IGNORE``        ``ON CONFLICT DO NOTHING``
Auto id                 ``INTEGER AUTOINCREMENT``   ``BIGSERIAL``
Float timestamps        ``REAL``                    ``DOUBLE PRECISION``
Binary                  ``BLOB`` (bytes)            ``BYTEA`` (memoryview)
Tuning                  ``PRAGMA``                  n/a
======================  ==========================  ==========================

``ON CONFLICT (...) DO UPDATE SET x = excluded.x`` is deliberately *not* in
that list: PostgreSQL originated the ``excluded`` pseudo-table and SQLite
adopted the same spelling, so the one statement using it is already portable.
"""

import logging
import re
import sqlite3
import threading
from typing import Any, Optional, Sequence

log = logging.getLogger(__name__)

_local = threading.local()

POSTGRES_PREFIXES = ("postgresql://", "postgres://")


def is_postgres(dsn: str) -> bool:
    return bool(dsn) and dsn.startswith(POSTGRES_PREFIXES)


# ── schema ───────────────────────────────────────────────────────────────────

SQLITE_SCHEMA = """
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
"""

# Column types are the SQLite ones translated, and nothing more: the point is
# that a row means the same thing in both engines, so the migration tool can
# copy values across without interpreting them.
POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS kmip_objects (
    uuid                    TEXT PRIMARY KEY,
    object_type             INTEGER NOT NULL,
    pkcs11_handle           BIGINT,
    pkcs11_slot             BIGINT DEFAULT 0,
    state                   INTEGER NOT NULL DEFAULT 1,
    cryptographic_algorithm INTEGER,
    cryptographic_length    INTEGER,
    usage_mask              BIGINT,
    initial_date            DOUBLE PRECISION,
    activation_date         DOUBLE PRECISION,
    deactivation_date       DOUBLE PRECISION,
    destroy_date            DOUBLE PRECISION,
    compromise_date         DOUBLE PRECISION,
    revocation_reason       INTEGER,
    revocation_message      TEXT,
    sensitive               INTEGER DEFAULT 1,
    extractable             INTEGER DEFAULT 0,
    never_extractable       INTEGER DEFAULT 0,
    always_sensitive        INTEGER DEFAULT 1,
    owner_identity          TEXT,
    key_format_type         INTEGER,
    raw_key_value           BYTEA,
    archived                INTEGER DEFAULT 0,
    archive_date            DOUBLE PRECISION,
    created_at              DOUBLE PRECISION NOT NULL
);

CREATE TABLE IF NOT EXISTS kmip_attributes (
    id          BIGSERIAL PRIMARY KEY,
    object_uuid TEXT NOT NULL REFERENCES kmip_objects(uuid) ON DELETE CASCADE,
    attr_name   TEXT NOT NULL,
    attr_index  INTEGER DEFAULT 0,
    attr_value  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attr_lookup
    ON kmip_attributes(object_uuid, attr_name);

CREATE INDEX IF NOT EXISTS idx_state
    ON kmip_objects(state);

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
"""


def schema_for(dsn: str) -> str:
    return POSTGRES_SCHEMA if is_postgres(dsn) else SQLITE_SCHEMA


# ── SQL translation ──────────────────────────────────────────────────────────

_PLACEHOLDER = re.compile(r"\?")
_INSERT_OR_IGNORE = re.compile(r"INSERT\s+OR\s+IGNORE\s+INTO", re.IGNORECASE)
# SQLite's json_extract(col, '$.path') -> PostgreSQL's col::jsonb ->> 'path'.
# Only single-level '$.key' paths are matched, which is all the store uses;
# a deeper path would not match and would fail loudly rather than silently
# returning the wrong column.
_JSON_EXTRACT = re.compile(
    r"json_extract\(\s*([A-Za-z_][\w.]*)\s*,\s*'\$\.([A-Za-z_]\w*)'\s*\)",
    re.IGNORECASE,
)


def translate(sql: str) -> str:
    """Rewrites SQLite SQL for PostgreSQL.

    Only the three constructs the store actually uses are handled. A general
    SQL translator would be far more code and far more ways to be subtly
    wrong; this stays honest about its scope, and every statement it has to
    cover lives in one file.

    The json_extract case is the one that is easy to miss: attribute values
    are stored as JSON text, and Locate-by-name reaches inside them. SQLite
    and PostgreSQL spell that completely differently, and PostgreSQL fails
    with "function json_extract does not exist" rather than misbehaving - so
    it surfaces immediately, but only if Locate-by-name is exercised.
    """
    if _INSERT_OR_IGNORE.search(sql):
        sql = _INSERT_OR_IGNORE.sub("INSERT INTO", sql)
        # Appended rather than inserted mid-statement: every such statement in
        # the store ends with its VALUES list.
        sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"

    sql = _JSON_EXTRACT.sub(r"(\1::jsonb ->> '\2')", sql)

    return _PLACEHOLDER.sub("%s", sql)


def _normalise(value: Any) -> Any:
    """psycopg returns BYTEA as memoryview; callers expect bytes."""
    return bytes(value) if isinstance(value, memoryview) else value


class _PgCursor:
    """Cursor wrapper giving psycopg rows the shape sqlite3.Row has."""

    def __init__(self, cursor):
        self._cursor = cursor

    def fetchone(self):
        row = self._cursor.fetchone()
        return None if row is None else {k: _normalise(v) for k, v in row.items()}

    def fetchall(self):
        return [{k: _normalise(v) for k, v in row.items()} for row in self._cursor.fetchall()]

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    @property
    def lastrowid(self):
        return None


class _PgConnection:
    """Presents a psycopg connection through sqlite3's connection API.

    ``store.py`` calls ``conn.execute(sql, params).fetchone()`` throughout -
    a sqlite3 convenience that psycopg does not offer - so this supplies it
    rather than requiring the store to manage cursors.
    """

    def __init__(self, connection):
        self._connection = connection

    def execute(self, sql: str, params: Sequence = ()) -> _PgCursor:
        cursor = self._connection.cursor()
        cursor.execute(translate(sql), tuple(params))
        return _PgCursor(cursor)

    def executescript(self, script: str) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(script)
        self._connection.commit()

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()

    def close(self) -> None:
        self._connection.close()


def connect(dsn: str):
    """Opens a connection appropriate to the DSN.

    Connections are per-thread for both engines. SQLite requires it; for
    PostgreSQL it keeps the KMIP server's thread-per-connection model working
    without introducing a pool the store would have to manage.
    """
    if not is_postgres(dsn):
        connection = sqlite3.connect(dsn, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    import psycopg2
    import psycopg2.extras

    connection = psycopg2.connect(dsn, cursor_factory=psycopg2.extras.RealDictCursor)
    # The store commits explicitly after each write, matching how it behaved
    # on SQLite; leaving autocommit off preserves that.
    connection.autocommit = False
    return _PgConnection(connection)


def get_thread_connection(dsn: str):
    """Per-thread connection cache, keyed by DSN."""
    if getattr(_local, "dsn", None) != dsn or getattr(_local, "conn", None) is None:
        _local.conn = connect(dsn)
        _local.dsn = dsn
    return _local.conn


def initialise(dsn: str) -> None:
    """Creates the schema if it is not already present."""
    connection = connect(dsn)
    try:
        if is_postgres(dsn):
            connection.executescript(schema_for(dsn))
        else:
            connection.executescript(schema_for(dsn))
            connection.commit()
    finally:
        connection.close()
