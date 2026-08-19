"""Backup and restore for the metadata database.

The single most important thing to understand about backing up this system:
**the metadata database and the HSM token are one unit.** Objects reference
keys by CKA_ID, and SecretData/OpaqueObject/SplitKey blobs are encrypted under
a master key that lives on the token. A database restored next to a different
token is not a degraded backup — it is unreadable, and every UID in it points
at a key that no longer exists.

So a backup here captures the database *and* records which token it belongs
to, and restore refuses to proceed against a token that cannot decrypt it
unless explicitly forced. Verifying the pairing at restore time is the whole
point: discovering the mismatch during an incident is too late.

The database copy uses SQLite's online backup API rather than a file copy —
`cp` of a live WAL database can capture a torn state, and the resulting file
may be missing the most recent commits or fail to open at all.
"""

import datetime
import json
import logging
import os
import sqlite3
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

MANIFEST_NAME = "manifest.json"
DATABASE_NAME = "kmip.db"
BACKUP_FORMAT_VERSION = 1


class BackupError(Exception):
    pass


def create_backup(store, destination: str, token_label: Optional[str] = None,
                  note: Optional[str] = None) -> Dict[str, Any]:
    """Write a consistent snapshot of `store` into the directory `destination`.

    Safe to run against a live server: the online backup API takes a
    transactionally consistent copy while writers continue."""
    os.makedirs(destination, exist_ok=True)
    db_path = os.path.join(destination, DATABASE_NAME)

    source = store._conn()
    target = sqlite3.connect(db_path)
    try:
        source.backup(target)
        target.commit()
    finally:
        target.close()

    # Recorded so restore can check the pairing, and so an operator staring at
    # a directory of backups can tell what each one is.
    audit = store.verify_audit_chain()
    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "schema_version": store.schema_version(),
        "token_label": token_label,
        "master_key_ids": sorted(k.hex() for k in store._cipher.known_key_ids())
                          if getattr(store, "_cipher", None) else [],
        "object_count": _count(source, "kmip_objects"),
        "identity_count": _count(source, "kmip_identities"),
        "audit_entries": audit["entries"],
        "audit_chain_ok": audit["ok"],
        "note": note,
    }
    with open(os.path.join(destination, MANIFEST_NAME), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    if not audit["ok"]:
        # Worth backing up anyway — but the operator must know the log was
        # already compromised before this snapshot was taken.
        log.warning("Backup taken from a database whose audit chain is BROKEN at seq %s",
                    audit["broken_at"])
    log.info("Backup written to %s (%d objects, %d audit entries)",
             destination, manifest["object_count"], manifest["audit_entries"])
    return manifest


def read_manifest(source: str) -> Dict[str, Any]:
    path = os.path.join(source, MANIFEST_NAME)
    if not os.path.exists(path):
        raise BackupError(f"No {MANIFEST_NAME} in {source} — not a backup directory")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def inspect_backup(source: str) -> Dict[str, Any]:
    """Report what a backup contains without restoring it."""
    manifest = read_manifest(source)
    db_path = os.path.join(source, DATABASE_NAME)
    if not os.path.exists(db_path):
        raise BackupError(f"No {DATABASE_NAME} in {source}")
    manifest["database_bytes"] = os.path.getsize(db_path)
    return manifest


def restore_backup(source: str, target_db: str, shim=None,
                   token_label: Optional[str] = None,
                   force: bool = False, overwrite: bool = False) -> Dict[str, Any]:
    """Restore a backup to `target_db`.

    When `shim` is supplied the restore is verified against the live token
    before it is accepted: the master key that encrypted the data must still
    be present, and a stored secret must actually decrypt. A restore that
    "succeeds" onto the wrong token would look fine until the first client
    asked for a key, so this check is not optional unless `force` is set.
    """
    manifest = read_manifest(source)
    db_path = os.path.join(source, DATABASE_NAME)
    if not os.path.exists(db_path):
        raise BackupError(f"No {DATABASE_NAME} in {source}")

    if os.path.exists(target_db) and not overwrite:
        raise BackupError(
            f"{target_db} already exists — pass overwrite=True to replace it")

    if (token_label and manifest.get("token_label")
            and token_label != manifest["token_label"] and not force):
        raise BackupError(
            f"Backup was taken from token {manifest['token_label']!r} but this host "
            f"has {token_label!r}. The database references keys on the original "
            f"token; restoring it here will not recover them. Pass force=True only "
            f"if you know the token was migrated."
        )

    # Copy through SQLite so a corrupt backup fails here rather than at the
    # first query after cutover.
    try:
        src = sqlite3.connect(db_path)
        dst = sqlite3.connect(target_db)
        try:
            src.backup(dst)
            dst.commit()
        finally:
            dst.close()
            src.close()
    except sqlite3.Error as e:
        raise BackupError(f"Backup database is unreadable: {e}") from e

    report = {"restored_to": target_db, "manifest": manifest}

    if shim is not None:
        report["verification"] = verify_restore(target_db, shim)
        if not report["verification"]["ok"] and not force:
            raise BackupError(
                f"Restore verification failed: {report['verification']['reason']}. "
                f"The database was written to {target_db} but this token cannot "
                f"read it — check you restored against the right HSM."
            )

    log.info("Restored %s to %s", source, target_db)
    return report


def verify_restore(db_path: str, shim) -> Dict[str, Any]:
    """Prove a restored database is actually usable with this token.

    Checks in order: the schema is current, the audit chain verifies, the
    master key is present, and — the one that really matters — an encrypted
    secret decrypts. Anything short of that last step can pass against a token
    holding the wrong keys."""
    from .store import MetadataStore, SCHEMA_VERSION
    from .blob_cipher import BlobCipher
    from ..core.enums import ObjectType

    try:
        store = MetadataStore(db_path)
    except Exception as e:
        return {"ok": False, "reason": f"database will not open: {e}"}

    if store.schema_version() != SCHEMA_VERSION:
        return {"ok": False,
                "reason": f"schema version {store.schema_version()} != {SCHEMA_VERSION}"}

    audit = store.verify_audit_chain()
    if not audit["ok"]:
        return {"ok": False, "reason": f"audit chain broken at seq {audit['broken_at']}"}

    try:
        cipher = BlobCipher(shim, auto_provision=False)
    except Exception as e:
        return {"ok": False,
                "reason": f"no master key on this token — it cannot decrypt this "
                          f"database ({e})"}
    store._cipher = cipher

    encrypted = store._conn().execute(
        "SELECT uuid FROM kmip_objects WHERE raw_key_encrypted = 1 LIMIT 1"
    ).fetchone()
    decrypted_ok = None
    if encrypted:
        try:
            store.get_object(encrypted["uuid"])
            decrypted_ok = True
        except Exception as e:
            return {"ok": False,
                    "reason": f"stored secret does not decrypt with this token's "
                              f"master key ({e})"}

    return {
        "ok": True,
        "schema_version": store.schema_version(),
        "audit_entries": audit["entries"],
        "objects": _count(store._conn(), "kmip_objects"),
        "identities": _count(store._conn(), "kmip_identities"),
        "decryption_verified": decrypted_ok,
    }


def _count(conn: sqlite3.Connection, table: str) -> int:
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    except sqlite3.Error:
        return 0
