#!/usr/bin/env python3
"""
Copies an existing SQLite metadata store into PostgreSQL.

    python cryptohub_lite/tools/migrate_sqlite_to_postgres.py \
        --sqlite kmip_metadata.db \
        --postgres postgresql://cryptohub:devpass@localhost:5432/cryptohub

Both engines use the same column names and the same value encodings, so this
copies rows rather than interpreting them — the less this tool understands
about KMIP, the fewer ways it has to corrupt the data it moves.

Safety properties, in order of how much they matter:

* **Refuses to run against a non-empty target** unless ``--force`` is given.
  Merging two object stores would silently reassign ownership of keys.
* **Preserves UUIDs.** They are KMIP Unique Identifiers; a client holding one
  must still find its object afterwards.
* **Order respects foreign keys** — objects before attributes and grants.
* **Verifies row counts** afterwards and exits non-zero on any mismatch, so a
  partial copy fails loudly rather than looking like success.
"""

import argparse
import sqlite3
import sys
from typing import List, Tuple

# Parents first: attributes and grants reference kmip_objects(uuid), and
# approvals reference kmip_approval_requests(request_id).
#
# Columns are declared, not discovered, so a column added upstream is copied
# only once it has been considered here — silently copying an unknown column
# would move data whose meaning nobody has checked. Columns absent from the
# *source* are dropped per table at run time, since a store predating a given
# release will not have them.
TABLES: List[Tuple[str, List[str]]] = [
    ("kmip_objects", [
        "uuid", "object_type", "pkcs11_handle", "pkcs11_slot", "state",
        "cryptographic_algorithm", "cryptographic_length", "usage_mask",
        "initial_date", "activation_date", "deactivation_date", "destroy_date",
        "compromise_date", "revocation_reason", "revocation_message",
        "sensitive", "extractable", "never_extractable", "always_sensitive",
        "owner_identity", "key_format_type", "raw_key_value",
        "raw_key_encrypted",
        "archived", "archive_date", "created_at",
    ]),
    ("kmip_identities", [
        "identity", "password_hash", "salt", "algorithm", "disabled", "created_at",
    ]),
    ("kmip_identity_roles", ["identity", "role"]),
    ("kmip_identity_groups", ["identity", "group_name"]),
    ("kmip_role_permissions", ["role", "operation_name"]),
    ("kmip_attributes", ["object_uuid", "attr_name", "attr_index", "attr_value"]),
    ("kmip_object_grants", ["object_uuid", "grantee", "permission"]),
    ("kmip_approval_requests", [
        "request_id", "operation_name", "object_uid", "requester", "required",
        "created_at", "expires_at", "consumed_at",
    ]),
    ("kmip_approvals", ["request_id", "approver", "approved_at"]),
    # seq is copied rather than regenerated. The audit log is a hash chain
    # verified in seq order, so renumbering would reorder the chain and make an
    # intact log verify as broken. The sequence behind the column is corrected
    # afterwards — see _resync_sequences.
    ("kmip_audit", [
        "seq", "timestamp", "identity", "operation", "operation_name",
        "object_uid", "result", "result_reason", "message", "client",
        "prev_hash", "entry_hash",
    ]),
]

# Tables whose primary key came from a SQLite AUTOINCREMENT and is a PostgreSQL
# sequence in the target. Copying explicit ids leaves the sequence at 1, so the
# next insert collides with row 1.
SEQUENCES: List[Tuple[str, str]] = [("kmip_audit", "seq")]


def source_columns(connection: sqlite3.Connection, table: str) -> List[str]:
    return [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]


def source_rows(connection: sqlite3.Connection, table: str, columns: List[str]):
    cursor = connection.execute(f"SELECT {', '.join(columns)} FROM {table}")
    while True:
        batch = cursor.fetchmany(500)
        if not batch:
            return
        yield batch


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate the KMIP metadata store to PostgreSQL")
    parser.add_argument("--sqlite", required=True, help="Path to the existing SQLite database")
    parser.add_argument("--postgres", required=True, help="Target postgresql:// DSN")
    parser.add_argument("--force", action="store_true",
                        help="Write into a target that already contains objects")
    parser.add_argument("--dry-run", action="store_true", help="Report only; change nothing")
    args = parser.parse_args()

    sys.path.insert(0, ".")
    from kmip_pkcs11.metadata import db

    if not db.is_postgres(args.postgres):
        print(f"error: --postgres must be a postgresql:// DSN, got {args.postgres}")
        return 2

    source = sqlite3.connect(args.sqlite)
    source.row_factory = sqlite3.Row

    print(f"Source : {args.sqlite}")
    print(f"Target : {args.postgres}")

    counts = {}
    columns_for = {}
    for table, declared in TABLES:
        try:
            counts[table] = source.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except sqlite3.OperationalError:
            # A store predating the access-control, identity or audit work has
            # no such table; that is a valid source, not an error.
            counts[table] = 0
            print(f"  note: source has no table {table}; skipping")
            continue

        present = source_columns(source, table)
        columns_for[table] = [c for c in declared if c in present]
        missing = [c for c in declared if c not in present]
        if missing:
            # Named rather than passed over. The target's own defaults apply,
            # and for raw_key_encrypted that default (0, "stored in the clear")
            # is the truth for a source that predates encryption at rest.
            print(f"  note: {table} has no {', '.join(missing)} in the source; "
                  f"the target default applies")

    print("\nRows to copy:")
    for table, count in counts.items():
        print(f"  {table:<24} {count}")

    if args.dry_run:
        print("\nDry run - nothing written.")
        return 0

    from kmip_pkcs11.metadata.store import SCHEMA, _MIGRATIONS
    db.initialise(args.postgres, SCHEMA, _MIGRATIONS)
    target = db.connect(args.postgres)

    existing = target.execute("SELECT COUNT(*) AS n FROM kmip_objects").fetchone()["n"]
    if existing and not args.force:
        print(f"\nerror: target already holds {existing} object(s). "
              f"Merging two stores would reassign key ownership silently. "
              f"Re-run with --force only if you are certain.")
        return 1

    print()
    for table, _declared in TABLES:
        if not counts.get(table):
            continue
        columns = columns_for[table]
        placeholders = ", ".join(["%s"] * len(columns))
        statement = (f"INSERT INTO {table} ({', '.join(columns)}) "
                     f"VALUES ({placeholders}) ON CONFLICT DO NOTHING")

        copied = 0
        for batch in source_rows(source, table, columns):
            for row in batch:
                values = []
                for column in columns:
                    value = row[column]
                    # sqlite3 hands back bytes for BLOB, which psycopg maps to
                    # BYTEA directly; everything else is a scalar already.
                    values.append(value)
                target.execute(statement, tuple(values))
            copied += len(batch)
            target.commit()
        print(f"  copied {copied:>6} -> {table}")

    _resync_sequences(target, counts)

    print("\nVerifying...")
    failures = 0
    for table, _ in TABLES:
        if not counts.get(table):
            continue
        actual = target.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
        status = "ok" if actual >= counts[table] else "MISMATCH"
        if status == "MISMATCH":
            failures += 1
        print(f"  {table:<24} source={counts[table]:<6} target={actual:<6} {status}")

    # The chain is what makes the audit log evidence, so a migration that
    # produced an unverifiable one has to say so — the rows arriving is not the
    # same as the log still being trustworthy.
    if counts.get("kmip_audit"):
        from kmip_pkcs11.metadata.store import MetadataStore
        report = MetadataStore(args.postgres).verify_audit_chain()
        if report["ok"]:
            print(f"  audit chain             {report['entries']} entries, intact")
        else:
            failures += 1
            print(f"  audit chain             BROKEN at seq {report['broken_at']}: "
                  f"{report.get('reason')}")

    target.close()
    source.close()

    if failures:
        print(f"\n{failures} check(s) did not pass.")
        return 1

    print("\nMigration complete. Point CRYPTOHUB_DB at the PostgreSQL DSN.")
    return 0


def _resync_sequences(target, counts) -> None:
    """Advance each copied table's sequence past the ids that were inserted.

    Explicit ids bypass the sequence, which stays at 1 — so without this the
    first row written after a migration collides with the oldest migrated row.
    For the audit log that surfaces as a duplicate-key error on the next KMIP
    operation, long after the migration looked successful.
    """
    for table, column in SEQUENCES:
        if not counts.get(table):
            continue
        target.execute(
            f"SELECT setval(pg_get_serial_sequence('{table}', '{column}'), "
            f"COALESCE((SELECT MAX({column}) FROM {table}), 1))"
        )
        target.commit()
        print(f"  sequence for {table}.{column} advanced past the copied rows")


if __name__ == "__main__":
    sys.exit(main())
