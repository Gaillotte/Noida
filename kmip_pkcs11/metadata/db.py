"""
Database dialect layer for the metadata store.

The store was written against SQLite and is covered by the upstream test suite,
which runs against it. CryptoHub Lite needs PostgreSQL. Rather than rewrite the
store's SQL and risk that test asset, this module adapts the small number of
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
JSON field read         ``json_extract(c,'$.k')``   ``(c::jsonb ->> 'k')``
Auto id                 ``INTEGER AUTOINCREMENT``   ``BIGSERIAL``
Float timestamps        ``REAL``                    ``DOUBLE PRECISION``
Binary                  ``BLOB`` (bytes)            ``BYTEA`` (memoryview)
Schema version          ``PRAGMA user_version``     ``kmip_schema_version``
Append-only guard       ``RAISE(ABORT, ...)``       trigger function
Serialised append       ``BEGIN IMMEDIATE``         ``pg_advisory_xact_lock``
Inserted row id         ``cursor.lastrowid``        ``lastval()``
Reclaiming free pages   ``VACUUM``                  ``VACUUM``/no WAL sidecar
Tuning                  ``PRAGMA``                  n/a
======================  ==========================  ==========================

``ON CONFLICT (...) DO UPDATE SET x = excluded.x`` is deliberately *not* in
that list: PostgreSQL originated the ``excluded`` pseudo-table and SQLite
adopted the same spelling, so the one statement using it is already portable.

**The PostgreSQL schema is derived, not maintained.** This module used to carry
a second hand-written copy of the DDL. It silently went stale the moment the
component branch added a table, and a store method would then fail at runtime
on PostgreSQL only — which is precisely what happened across phases 0-5, where
six new tables appeared. :func:`translate_ddl` now generates the PostgreSQL DDL
from the SQLite DDL in ``store.py``, so there is one schema and new tables
arrive on both engines together. Anything the translator does not recognise
raises :class:`UnsupportedDDL` at import-time rather than producing a schema
that is quietly missing a table.
"""

import logging
import re
import sqlite3
import threading
from typing import Any, Iterable, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

_local = threading.local()

POSTGRES_PREFIXES = ("postgresql://", "postgres://")


def is_postgres(dsn: str) -> bool:
    return bool(dsn) and dsn.startswith(POSTGRES_PREFIXES)


class UnsupportedDDL(RuntimeError):
    """A DDL construct the PostgreSQL translation does not cover.

    Raised rather than skipped. A dropped ``CREATE TABLE`` would surface much
    later as a missing-relation error from whichever store method happened to
    touch it first, on PostgreSQL only.
    """


# ── DDL translation ──────────────────────────────────────────────────────────

# Columns that hold values wider than a 32-bit int on the SQLite side, where
# INTEGER is really a variable-width integer. PKCS#11 object handles and the
# KMIP usage mask both reach past int32, so they need BIGINT rather than the
# INTEGER a literal translation would produce.
_WIDE_COLUMNS = ("pkcs11_handle", "pkcs11_slot", "usage_mask")

# `CREATE TRIGGER ... BEGIN ... END;` — matched whole, because the body holds
# semicolons and would otherwise break statement splitting.
_TRIGGER_BLOCK = re.compile(
    r"CREATE\s+TRIGGER\s+(?:IF\s+NOT\s+EXISTS\s+)?(?P<name>\w+)\s+"
    r"(?P<timing>BEFORE|AFTER)\s+(?P<event>INSERT|UPDATE|DELETE)\s+"
    r"ON\s+(?P<table>\w+)\s*"
    r"BEGIN\s*(?P<body>.*?)\s*END\s*;",
    re.IGNORECASE | re.DOTALL,
)

# The only trigger body shape in use: an unconditional abort, which is how the
# audit log is made append-only.
_RAISE_ABORT = re.compile(
    r"^SELECT\s+RAISE\s*\(\s*ABORT\s*,\s*'(?P<message>[^']*)'\s*\)\s*;?$",
    re.IGNORECASE,
)

_SQL_COMMENT = re.compile(r"--[^\n]*")

# Left in the translated DDL, these mean a construct slipped through.
_SQLITE_ONLY_TOKENS = ("AUTOINCREMENT", "PRAGMA", "RAISE(", "RAISE (",
                       " BLOB", " REAL", "WITHOUT ROWID")

# One fixed advisory-lock key standing in for SQLite's database-wide write
# lock. Any constant works as long as every process agrees on it; this is
# "kmipaud" as ASCII, which makes it recognisable in pg_locks.
_AUDIT_LOCK_KEY = 0x6B6D69_70617564 & 0x7FFFFFFFFFFFFFFF

# PostgreSQL has no `PRAGMA user_version`, so the schema version lives in a
# table. Appended to the translated DDL rather than added to store.SCHEMA,
# which would put a PostgreSQL-only table into the SQLite path.
_PG_VERSION_TABLE = """
CREATE TABLE IF NOT EXISTS kmip_schema_version (
    version INTEGER NOT NULL
);
"""


def _translate_column_types(statement: str) -> str:
    """Rewrites SQLite column types for PostgreSQL."""
    # Ordered: the AUTOINCREMENT form has to go before the bare-type rules,
    # which would otherwise rewrite the INTEGER inside it.
    statement = re.sub(
        r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b",
        "BIGSERIAL PRIMARY KEY", statement, flags=re.IGNORECASE,
    )
    for column in _WIDE_COLUMNS:
        statement = re.sub(
            rf"(^\s*{column}\s+)INTEGER\b",
            r"\1BIGINT", statement, flags=re.IGNORECASE | re.MULTILINE,
        )
    statement = re.sub(r"\bBLOB\b", "BYTEA", statement, flags=re.IGNORECASE)
    statement = re.sub(r"\bREAL\b", "DOUBLE PRECISION", statement, flags=re.IGNORECASE)
    return statement


def _translate_trigger(match: "re.Match") -> str:
    """Rewrites a SQLite abort-trigger as a PostgreSQL trigger function.

    PostgreSQL has no ``CREATE TRIGGER IF NOT EXISTS``, so this drops and
    recreates — which is also what makes the DDL replayable at every startup,
    the way the ``IF NOT EXISTS`` statements around it are.
    """
    name, table = match.group("name"), match.group("table")
    timing, event = match.group("timing").upper(), match.group("event").upper()

    body = _SQL_COMMENT.sub("", match.group("body")).strip()
    abort = _RAISE_ABORT.match(body)
    if abort is None:
        raise UnsupportedDDL(
            f"Trigger {name!r} has a body this translation does not cover: "
            f"{body!r}. Only an unconditional RAISE(ABORT, '...') is handled."
        )
    message = abort.group("message").replace("'", "''")

    # Dollar-quoted with the trigger name as the tag, so the body's own
    # semicolons and quotes need no escaping. Note the tag takes single
    # dollars: `$$tag$$` would be an empty-tag quote around the literal
    # string "tag", which PostgreSQL accepts and then uses as the body.
    return (
        f"CREATE OR REPLACE FUNCTION {name}_fn() RETURNS trigger AS ${name}$\n"
        f"BEGIN RAISE EXCEPTION '{message}'; END;\n"
        f"${name}$ LANGUAGE plpgsql;\n"
        f"DROP TRIGGER IF EXISTS {name} ON {table};\n"
        f"CREATE TRIGGER {name} {timing} {event} ON {table}\n"
        f"    FOR EACH ROW EXECUTE PROCEDURE {name}_fn();"
    )


def translate_ddl(ddl: str) -> str:
    """Derives PostgreSQL DDL from the SQLite DDL in ``store.py``.

    Deliberately narrow. It covers the constructs the store's schema actually
    uses and raises :class:`UnsupportedDDL` on anything else, so a new
    construct fails at import rather than producing a schema missing a table.
    """
    triggers = []

    def _capture(match):
        triggers.append(_translate_trigger(match))
        return ""

    remainder = _TRIGGER_BLOCK.sub(_capture, ddl)
    translated = _translate_column_types(remainder)

    # Check the statement bodies only. A comment mentioning PRAGMA or REAL is
    # documentation, not DDL, and must not trip the guard.
    for token in _SQLITE_ONLY_TOKENS:
        for statement in _SQL_COMMENT.sub("", translated).split(";"):
            if token.upper() in statement.upper():
                raise UnsupportedDDL(
                    f"Untranslated SQLite construct {token.strip()!r} in: "
                    f"{statement.strip()[:160]!r}"
                )

    return "\n".join([translated, _PG_VERSION_TABLE] + triggers)


def schema_for(dsn: str, sqlite_ddl: str) -> str:
    return translate_ddl(sqlite_ddl) if is_postgres(dsn) else sqlite_ddl


# ── DML translation ──────────────────────────────────────────────────────────

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
        """The id the preceding INSERT generated.

        ``lastval()`` reports the last value produced by any sequence in this
        session, and connections are per-thread, so after an INSERT on this
        cursor it is that row's id. Valid only immediately after an INSERT into
        a table with a serial column — which is the sole way the store uses
        ``lastrowid``. Returning None on failure matches what this property did
        before, where it was always None and silently made
        ``append_audit`` return nothing.
        """
        try:
            self._cursor.execute("SELECT lastval() AS id")
            row = self._cursor.fetchone()
            return None if row is None else row["id"]
        except Exception:                       # noqa: BLE001 - see docstring
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

    @property
    def in_transaction(self) -> bool:
        """Mirrors ``sqlite3.Connection.in_transaction``.

        The store checks this before opening its own transaction for an audit
        append. With autocommit off, psycopg opens one on the first statement,
        so this has to report the real backend state rather than always False.
        """
        import psycopg2.extensions
        return (self._connection.get_transaction_status()
                != psycopg2.extensions.TRANSACTION_STATUS_IDLE)

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()

    def close(self) -> None:
        self._connection.close()

    def backup(self, target):
        """Refuse SQLite's online backup API with an explanation.

        ``metadata/backup.py`` — and so ``kmip-admin backup`` — takes its
        snapshot by calling this on the store's connection. There is no
        PostgreSQL equivalent to supply here: a consistent snapshot of a
        PostgreSQL database is taken by the server, not by the client holding a
        connection to it.

        Without this the call reaches psycopg and fails with a bare
        ``AttributeError: 'psycopg2.extensions.connection' object has no
        attribute 'backup'``, which tells an operator following the backup
        documentation nothing about what to do instead.
        """
        raise NotImplementedError(
            "The online backup API is SQLite-only, and this store is "
            "PostgreSQL. Back it up with pg_dump (or a snapshot of the "
            "chl_pgdata volume), together with the HSM token — the two are one "
            "unit, since objects reference key material by CKA_ID and secret "
            "blobs are encrypted under a master key held on the token."
        )


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
        # WAL allows one writer at a time. With several worker processes on one
        # database, a writer that arrives mid-write must wait for the lock
        # rather than fail immediately with SQLITE_BUSY.
        connection.execute("PRAGMA busy_timeout=10000")
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


# ── schema version and migrations ────────────────────────────────────────────

def schema_version(conn, dsn: str) -> int:
    if not is_postgres(dsn):
        return conn.execute("PRAGMA user_version").fetchone()[0]
    row = conn.execute("SELECT version FROM kmip_schema_version").fetchone()
    return row["version"] if row else 0


def _set_schema_version(conn, dsn: str, version: int) -> None:
    if not is_postgres(dsn):
        # PRAGMA doesn't accept bound parameters; version is an int literal
        # from our own migration list, never external input.
        conn.execute(f"PRAGMA user_version = {int(version)}")
        return
    if conn.execute("SELECT version FROM kmip_schema_version").fetchone() is None:
        conn.execute("INSERT INTO kmip_schema_version (version) VALUES (?)", (int(version),))
    else:
        conn.execute("UPDATE kmip_schema_version SET version = ?", (int(version),))


def apply_migrations(conn, dsn: str, migrations: Iterable[Tuple[int, str, Sequence[str]]]) -> None:
    """Bring the database up to date, running only the migrations it hasn't
    seen. Each one commits with its version bump so an interrupted upgrade
    resumes rather than half-applying.

    Migration statements go through the DDL translation, so an ``ALTER TABLE``
    naming a SQLite type lands with the PostgreSQL equivalent.
    """
    current = schema_version(conn, dsn)
    for version, description, statements in migrations:
        if version <= current:
            continue
        log.info("Applying schema migration %d (%s)", version, description)
        for sql in statements:
            conn.execute(_translate_column_types(sql) if is_postgres(dsn) else sql)
        _set_schema_version(conn, dsn, version)
        conn.commit()


def initialise(dsn: str, sqlite_ddl: str,
               migrations: Iterable[Tuple[int, str, Sequence[str]]] = ()) -> None:
    """Creates the schema if it is not already present, then migrates it.

    Uses its own connection rather than the thread-cached one: DDL and the
    VACUUM a migration might need cannot run inside a transaction the
    application already opened.
    """
    connection = connect(dsn)
    try:
        connection.executescript(schema_for(dsn, sqlite_ddl))
        connection.commit()
        apply_migrations(connection, dsn, migrations)
    finally:
        connection.close()


# ── audit-log support ────────────────────────────────────────────────────────

def begin_immediate(conn, dsn: str) -> None:
    """Start a transaction that already holds its write lock.

    The audit append is read-then-write (fetch the previous entry's hash, then
    insert linking to it). A transaction that takes its write lock only at the
    INSERT lets two *processes* read the same predecessor and fork the chain,
    which verification then reports as tampering.

    SQLite spells this ``BEGIN IMMEDIATE``. PostgreSQL has no equivalent
    isolation trick, so a transaction-scoped advisory lock does the same job
    directly: the first statement opens the transaction and takes the lock, and
    it is released on commit or rollback with no unlock to forget.
    """
    if not is_postgres(dsn):
        conn.execute("BEGIN IMMEDIATE")
        return
    conn.execute("SELECT pg_advisory_xact_lock(?)", (_AUDIT_LOCK_KEY,))


def drop_append_only_guard(conn, dsn: str, trigger: str, table: str) -> None:
    """Lift the append-only trigger, for the one sanctioned deletion path."""
    if not is_postgres(dsn):
        conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        return
    conn.execute(f"DROP TRIGGER IF EXISTS {trigger} ON {table}")


def create_append_only_guard(conn, dsn: str, trigger: str, table: str,
                             event: str, message: str) -> None:
    """Restore a trigger lifted by :func:`drop_append_only_guard`."""
    if not is_postgres(dsn):
        conn.execute(
            f"CREATE TRIGGER IF NOT EXISTS {trigger} "
            f"BEFORE {event} ON {table} "
            f"BEGIN SELECT RAISE(ABORT, '{message}'); END"
        )
        return
    # The function is created by the schema DDL and survives the DROP TRIGGER,
    # so only the trigger itself has to come back.
    conn.execute(
        f"CREATE TRIGGER {trigger} BEFORE {event} ON {table} "
        f"FOR EACH ROW EXECUTE PROCEDURE {trigger}_fn()"
    )


def scrub_freed_pages(conn, dsn: str) -> None:
    """Remove superseded cleartext from the database files after a backfill.

    Encrypting a row with UPDATE does not erase what was there before. On
    SQLite in WAL mode the original plaintext INSERT stays in the -wal sidecar,
    and after a checkpoint it can linger in pages the main file has freed but
    not overwritten. PostgreSQL has no sidecar, but the pre-UPDATE row version
    remains in the heap page as dead tuples until a rewrite, so it needs the
    same treatment.

    Checkpointing with TRUNCATE resets the SQLite WAL; VACUUM (FULL, on
    PostgreSQL) rebuilds the file so freed space is dropped rather than merely
    unreferenced.

    This scrubs the *database files*. It cannot reach copies that already left
    them - filesystem snapshots, prior backups, replicas, WAL archives, or
    blocks retained by a wear-levelling SSD - so a store that ever held
    cleartext secrets should be treated as exposed until those are rotated too.
    """
    try:
        if is_postgres(dsn):
            # VACUUM cannot run inside a transaction, and psycopg has one open
            # from the preceding writes.
            conn.commit()
            conn.execute("VACUUM FULL kmip_objects")
            conn.commit()
            return
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")   # cannot run inside a transaction
        conn.commit()
    except Exception as e:                      # noqa: BLE001 - see docstring
        # Never fail the upgrade over this — the data is encrypted either way;
        # loudly flag that the old plaintext may still be recoverable.
        log.warning(
            "Could not scrub superseded cleartext from the database files "
            "(%s); previously-stored secrets may remain recoverable from "
            "the -wal sidecar, dead tuples or freed pages", e
        )
