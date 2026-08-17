"""`kmip-admin` — manage identities, roles, grants and the audit log.

None of this has a KMIP wire representation: the specification defines no
operation for provisioning a user or granting access to an object, so it has
to be an out-of-band administrative surface. Previously that meant writing
Python against MetadataStore; this is that surface as a command.

Operates directly on the metadata database, so it runs on the server host
(or anywhere the database is reachable) and needs no running server. Commands
that only touch metadata need no HSM; `rotate-master-key` does, and says so.
"""

import argparse
import datetime
import getpass
import json
import sys

from ..config import KMIPConfig, ConfigError
from ..metadata.store import MetadataStore


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kmip-admin",
        description="Administer a KMIP server's identities, roles, grants and audit log.",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-c", "--config", metavar="PATH",
                     help="read the database path from this configuration file")
    src.add_argument("-d", "--database", metavar="PATH",
                     help="operate on this metadata database directly")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a table")

    sub = p.add_subparsers(dest="command", required=True)

    ident = sub.add_parser("identity", help="manage identities").add_subparsers(
        dest="subcommand", required=True)
    add = ident.add_parser("add", help="create an identity or reset its password")
    add.add_argument("name")
    add.add_argument("--password", help="read from a prompt if omitted")
    ident.add_parser("list", help="list identities")
    for name, helptext in (("delete", "remove an identity"),
                           ("disable", "block authentication without deleting"),
                           ("enable", "re-enable a disabled identity")):
        sp = ident.add_parser(name, help=helptext)
        sp.add_argument("name")

    role = sub.add_parser("role", help="manage roles").add_subparsers(
        dest="subcommand", required=True)
    for name in ("grant", "revoke"):
        sp = role.add_parser(name, help=f"{name} a role")
        sp.add_argument("identity")
        sp.add_argument("role")
    show = role.add_parser("show", help="show an identity's roles")
    show.add_argument("identity")

    access = sub.add_parser("access", help="manage per-object grants").add_subparsers(
        dest="subcommand", required=True)
    ga = access.add_parser("grant", help="grant an identity access to one object")
    ga.add_argument("uid")
    ga.add_argument("identity")
    ga.add_argument("--permission", choices=("read", "full"), default="full")
    ra = access.add_parser("revoke", help="revoke a grant")
    ra.add_argument("uid")
    ra.add_argument("identity")
    la = access.add_parser("list", help="list grants on an object")
    la.add_argument("uid")

    audit = sub.add_parser("audit", help="inspect the audit log").add_subparsers(
        dest="subcommand", required=True)
    al = audit.add_parser("list", help="list audit entries")
    al.add_argument("--identity")
    al.add_argument("--object-uid")
    al.add_argument("--result", choices=("success", "failure"))
    al.add_argument("--limit", type=int, default=50)
    audit.add_parser("verify", help="verify the audit hash chain")
    ap = audit.add_parser("prune", help="delete entries older than N days")
    ap.add_argument("--older-than-days", type=int, required=True)
    ap.add_argument("--archive", metavar="PATH",
                    help="write the removed entries here as JSON before deleting")

    bk = sub.add_parser("backup", help="write a consistent snapshot").add_subparsers(
        dest="subcommand", required=True)
    bc = bk.add_parser("create", help="back up the metadata database")
    bc.add_argument("destination", help="directory to write the backup into")
    bc.add_argument("--note", help="free-text note stored in the manifest")
    bi = bk.add_parser("inspect", help="show what a backup contains")
    bi.add_argument("source")
    br = bk.add_parser("restore", help="restore a backup")
    br.add_argument("source")
    br.add_argument("--to", metavar="PATH",
                    help="target database (defaults to the configured one)")
    br.add_argument("--overwrite", action="store_true",
                    help="replace the target database if it exists")
    br.add_argument("--force", action="store_true",
                    help="proceed even if the backup does not match this token "
                         "(the restored data will be unreadable)")
    bv = bk.add_parser("verify", help="check a database is usable with this token")
    bv.add_argument("--database", metavar="PATH")

    mk = sub.add_parser("rotate-master-key",
                        help="re-encrypt stored secrets under a new HSM master key")
    mk.add_argument("--keep-previous-key", action="store_true",
                    help="do not destroy the superseded key (verify first, retire later)")

    return p


def _open_store(args) -> MetadataStore:
    if args.database:
        return MetadataStore(args.database)
    config = KMIPConfig.from_file(args.config)
    return MetadataStore(config.get("storage", "database"))


def _emit(args, rows, columns):
    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return
    if not rows:
        print("(none)")
        return
    widths = {c: max(len(c), max(len(str(r.get(c, ""))) for r in rows)) for c in columns}
    print("  ".join(c.upper().ljust(widths[c]) for c in columns))
    for r in rows:
        print("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in columns))


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    cmd, sub = args.command, getattr(args, "subcommand", None)

    # Opening a MetadataStore creates the database if it is absent, so commands
    # that operate on a database that should NOT exist yet — restore, chiefly —
    # must not open one first, or restore would always report its own freshly
    # created target as "already exists".
    needs_store = not (cmd == "backup" and sub in ("restore", "inspect"))
    store = None
    if needs_store:
        try:
            store = _open_store(args)
        except ConfigError as e:
            print(f"kmip-admin: {e}", file=sys.stderr)
            return 2

    if cmd == "identity":
        if sub == "add":
            password = args.password or getpass.getpass(f"Password for {args.name}: ")
            if not password:
                print("kmip-admin: password must not be empty", file=sys.stderr)
                return 2
            store.create_identity(args.name, password)
            print(f"identity '{args.name}' saved")
        elif sub == "list":
            rows = store.list_identities()
            for r in rows:
                r["created_at"] = datetime.datetime.fromtimestamp(
                    r["created_at"]).isoformat(timespec="seconds")
                r["disabled"] = bool(r["disabled"])
            _emit(args, rows, ["identity", "disabled", "created_at"])
        elif sub == "delete":
            store.delete_identity(args.name)
            print(f"identity '{args.name}' deleted")
        elif sub in ("disable", "enable"):
            store.set_identity_disabled(args.name, sub == "disable")
            print(f"identity '{args.name}' {sub}d")

    elif cmd == "role":
        if sub == "grant":
            store.assign_role(args.identity, args.role)
            print(f"granted role '{args.role}' to '{args.identity}'")
        elif sub == "revoke":
            store.revoke_role(args.identity, args.role)
            print(f"revoked role '{args.role}' from '{args.identity}'")
        elif sub == "show":
            roles = store.get_roles(args.identity)
            _emit(args, [{"identity": args.identity, "role": r} for r in roles],
                  ["identity", "role"])

    elif cmd == "access":
        if sub == "grant":
            store.grant_access(args.uid, args.identity, args.permission)
            print(f"granted {args.permission} on {args.uid} to '{args.identity}'")
        elif sub == "revoke":
            store.revoke_access(args.uid, args.identity)
            print(f"revoked access on {args.uid} from '{args.identity}'")
        elif sub == "list":
            _emit(args, store.list_grants(args.uid), ["grantee", "permission"])

    elif cmd == "audit":
        if sub == "list":
            rows = store.get_audit_entries(
                identity=args.identity, object_uid=args.object_uid,
                result=args.result, limit=args.limit)
            for r in rows:
                r["timestamp"] = datetime.datetime.fromtimestamp(
                    r["timestamp"]).isoformat(timespec="seconds")
            _emit(args, rows,
                  ["seq", "timestamp", "identity", "operation_name",
                   "object_uid", "result", "client"])
        elif sub == "verify":
            report = store.verify_audit_chain()
            if args.json:
                print(json.dumps(report, indent=2))
            elif report["ok"]:
                print(f"audit chain OK ({report['entries']} entries)")
            else:
                print(f"AUDIT CHAIN BROKEN at seq {report['broken_at']}: {report['reason']}")
            # Non-zero exit so a monitoring job can alert on a tampered log.
            return 0 if report["ok"] else 1
        elif sub == "prune":
            cutoff = (datetime.datetime.now(datetime.timezone.utc)
                      - datetime.timedelta(days=args.older_than_days)).timestamp()
            result = store.prune_audit(cutoff)
            if args.archive and result["entries"]:
                with open(args.archive, "w", encoding="utf-8") as f:
                    json.dump(result["entries"], f, indent=2, default=str)
                print(f"archived {result['pruned']} entries to {args.archive}")
            print(f"pruned {result['pruned']} entries older than {args.older_than_days} days")

    elif cmd == "backup":
        from ..metadata import backup as backup_mod

        def _shim_if_possible():
            """Backup/restore verification needs the token. Available only
            with --config, since that is what carries the HSM settings."""
            if not args.config:
                return None, None
            cfg = KMIPConfig.from_file(args.config)
            from ..pkcs11_shim.shim import PKCS11Shim
            s = PKCS11Shim(cfg.get("hsm", "library"),
                           cfg.get("hsm", "token_label"), cfg.resolve_pin())
            s.initialize()
            return s, cfg

        if sub == "create":
            shim, cfg = _shim_if_possible()
            if shim is not None:
                from ..metadata.blob_cipher import BlobCipher
                store._cipher = BlobCipher(shim)
            manifest = backup_mod.create_backup(
                store, args.destination,
                token_label=cfg.get("hsm", "token_label") if cfg else None,
                note=args.note)
            if args.json:
                print(json.dumps(manifest, indent=2))
            else:
                print(f"backup written to {args.destination}: "
                      f"{manifest['object_count']} objects, "
                      f"{manifest['audit_entries']} audit entries, "
                      f"audit chain {'OK' if manifest['audit_chain_ok'] else 'BROKEN'}")
                if not manifest["audit_chain_ok"]:
                    return 1

        elif sub == "inspect":
            info = backup_mod.inspect_backup(args.source)
            if args.json:
                print(json.dumps(info, indent=2))
            else:
                for key in ("created_at", "schema_version", "token_label",
                            "object_count", "identity_count", "audit_entries",
                            "audit_chain_ok", "note"):
                    print(f"  {key:16s} {info.get(key)}")

        elif sub == "restore":
            shim, cfg = _shim_if_possible()
            target = args.to or (cfg.get("storage", "database") if cfg else None)
            if not target:
                print("kmip-admin: --to is required without --config", file=sys.stderr)
                return 2
            try:
                report = backup_mod.restore_backup(
                    args.source, target, shim=shim,
                    token_label=cfg.get("hsm", "token_label") if cfg else None,
                    force=args.force, overwrite=args.overwrite)
            except backup_mod.BackupError as e:
                print(f"kmip-admin: restore failed: {e}", file=sys.stderr)
                return 1
            print(f"restored {args.source} -> {target}")
            v = report.get("verification")
            if v:
                print(f"  verification: {'OK' if v['ok'] else 'FAILED'} "
                      f"({v.get('objects', '?')} objects, "
                      f"decryption verified: {v.get('decryption_verified')})")
                if not v["ok"]:
                    # Reached only with --force, which waives the refusal but
                    # must not turn a broken restore into a success exit code —
                    # a script driving this needs to notice.
                    print(f"  reason: {v['reason']}", file=sys.stderr)
                    return 1

        elif sub == "verify":
            shim, cfg = _shim_if_possible()
            if shim is None:
                print("kmip-admin: backup verify needs --config (it must reach the HSM)",
                      file=sys.stderr)
                return 2
            db = args.database or cfg.get("storage", "database")
            report = backup_mod.verify_restore(db, shim)
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                print(f"{db}: {'OK' if report['ok'] else 'FAILED — ' + report['reason']}")
            return 0 if report["ok"] else 1

    elif cmd == "rotate-master-key":
        # The only command that needs the HSM: re-encrypting means decrypting
        # under the old key and encrypting under the new one, both on-token.
        if not args.config:
            print("kmip-admin: rotate-master-key needs --config (it must reach the HSM)",
                  file=sys.stderr)
            return 2
        from ..metadata.blob_cipher import BlobCipher
        from ..pkcs11_shim.shim import PKCS11Shim
        config = KMIPConfig.from_file(args.config)
        shim = PKCS11Shim(config.get("hsm", "library"),
                          config.get("hsm", "token_label"), config.resolve_pin())
        shim.initialize()
        store._cipher = BlobCipher(shim)
        result = store.rotate_master_key(retire_previous=not args.keep_previous_key)
        print(f"re-encrypted {result['rotated']} blob(s); "
              f"retired {result['retired_keys']} old key(s)")

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
