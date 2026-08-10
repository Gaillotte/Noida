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

# Parents first: attributes and grants reference kmip_objects(uuid).
TABLES: List[Tuple[str, List[str]]] = [
    ("kmip_objects", [
        "uuid", "object_type", "pkcs11_handle", "pkcs11_slot", "state",
        "cryptographic_algorithm", "cryptographic_length", "usage_mask",
        "initial_date", "activation_date", "deactivation_date", "destroy_date",
        "compromise_date", "revocation_reason", "revocation_message",
        "sensitive", "extractable", "never_extractable", "always_sensitive",
        "owner_identity", "key_format_type", "raw_key_value",
        "archived", "archive_date", "created_at",
    ]),
    ("kmip_identity_roles", ["identity", "role"]),
    ("kmip_attributes", ["object_uuid", "attr_name", "attr_index", "attr_value"]),
    ("kmip_object_grants", ["object_uuid", "grantee", "permission"]),
]


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
    for table, _ in TABLES:
        try:
            counts[table] = source.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except sqlite3.OperationalError:
            # A store predating the access-control work has no roles or
            # grants tables; that is a valid source, not an error.
            counts[table] = 0
            print(f"  note: source has no table {table}; skipping")

    print("\nRows to copy:")
    for table, count in counts.items():
        print(f"  {table:<22} {count}")

    if args.dry_run:
        print("\nDry run - nothing written.")
        return 0

    db.initialise(args.postgres)
    target = db.connect(args.postgres)

    existing = target.execute("SELECT COUNT(*) AS n FROM kmip_objects").fetchone()["n"]
    if existing and not args.force:
        print(f"\nerror: target already holds {existing} object(s). "
              f"Merging two stores would reassign key ownership silently. "
              f"Re-run with --force only if you are certain.")
        return 1

    print()
    for table, columns in TABLES:
        if not counts.get(table):
            continue
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

    print("\nVerifying...")
    failures = 0
    for table, _ in TABLES:
        if not counts.get(table):
            continue
        actual = target.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
        status = "ok" if actual >= counts[table] else "MISMATCH"
        if status == "MISMATCH":
            failures += 1
        print(f"  {table:<22} source={counts[table]:<6} target={actual:<6} {status}")

    target.close()
    source.close()

    if failures:
        print(f"\n{failures} table(s) did not migrate completely.")
        return 1

    print("\nMigration complete. Point CRYPTOHUB_DB at the PostgreSQL DSN.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
