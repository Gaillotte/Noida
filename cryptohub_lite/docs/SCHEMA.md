# PostgreSQL Schema Reference

The database holds two groups of tables:

| Group | Owner | Tables |
|---|---|---|
| **KMIP metadata** | the existing `kmip_pkcs11` package | `kmip_objects`, `kmip_attributes`, `kmip_identity_roles`, `kmip_object_grants` |
| **Portal** | CryptoHub Lite | `portal_users`, `portal_audit` |

They share one database so a single backup covers the whole system and an
audit row can reference a KMIP object by UUID. The KMIP tables keep their
original names and columns — the PostgreSQL port translated types, not
meaning, so a row means the same thing in either engine.

---

## KMIP metadata

### `kmip_objects`

One row per KMIP managed object. Key material never appears here; it stays in
the HSM, and `pkcs11_handle` is the reference to it.

| Column | Type | Notes |
|---|---|---|
| `uuid` | TEXT PK | KMIP Unique Identifier. Preserved across migration — clients hold these |
| `object_type` | INTEGER | `ObjectType` enum: 2=SymmetricKey, 3=PublicKey, 4=PrivateKey, 1=Certificate |
| `pkcs11_handle` | BIGINT | HSM object handle |
| `pkcs11_slot` | BIGINT | Slot the object lives in |
| `state` | INTEGER | 1=PreActive, 2=Active, 3=Deactivated, 4=Compromised, 5=Destroyed, 6=DestroyedCompromised |
| `cryptographic_algorithm` | INTEGER | `CryptographicAlgorithm` enum |
| `cryptographic_length` | INTEGER | Key size in bits |
| `usage_mask` | BIGINT | `CryptographicUsageMask` bit field |
| `initial_date` … `compromise_date` | DOUBLE PRECISION | Unix epoch seconds |
| `revocation_reason` | INTEGER | `RevocationReasonCode` |
| `sensitive`, `extractable`, `never_extractable`, `always_sensitive` | INTEGER | 0/1 |
| `owner_identity` | TEXT | Creating identity. **NULL means any identity may reach the object** — see below |
| `raw_key_value` | BYTEA | Certificates, secret data and split-key parts only |
| `archived`, `archive_date` | INTEGER / DOUBLE PRECISION | Orthogonal to `state` |
| `created_at` | DOUBLE PRECISION NOT NULL | |

> **`owner_identity IS NULL` is not an ordinary value.** The access-control
> layer treats an unowned object as reachable by anyone. That was deliberate,
> so adding ownership did not orphan objects created before it existed — but
> it means a NULL introduced later silently makes an object world-readable.
> Rows written through the normal Create/Register path always carry an owner.

### `kmip_attributes`

KMIP attributes that do not have a dedicated column. `attr_value` is JSON text.

| Column | Type | Notes |
|---|---|---|
| `id` | BIGSERIAL PK | `INTEGER AUTOINCREMENT` under SQLite |
| `object_uuid` | TEXT FK → `kmip_objects(uuid)` ON DELETE CASCADE | |
| `attr_name` | TEXT | `Name`, `Link`, `x-custom`, … |
| `attr_index` | INTEGER | KMIP allows repeated attributes |
| `attr_value` | TEXT | JSON-encoded |

Locate-by-name reaches inside this JSON. The two engines spell that
differently and the dialect layer rewrites it:

```sql
-- SQLite
json_extract(a.attr_value, '$.value') = ?
-- PostgreSQL
(a.attr_value::jsonb ->> 'value') = %s
```

### `kmip_identity_roles` / `kmip_object_grants`

The KMIP engine's own authorization model, checked in order: admin role →
ownership → delegated grant.

| Table | Columns | Notes |
|---|---|---|
| `kmip_identity_roles` | `identity`, `role` (PK both) | `admin` is the only role the engine special-cases |
| `kmip_object_grants` | `object_uuid`, `grantee`, `permission` (PK first two) | `read` or `full` |

These are **not** the portal's five roles. The engine's model governs KMIP
wire operations; `portal_users.role` governs the REST API and UI. They are
separate on purpose — a KMIP client authenticates differently from a portal
user — and a future consolidation is noted in the assessment.

---

## Portal tables

### `portal_users`

| Column | Type | Notes |
|---|---|---|
| `username` | TEXT PK | |
| `display_name`, `email` | TEXT | |
| `role` | TEXT NOT NULL | Administrator, SecurityOfficer, Operator, Auditor, ReadOnly |
| `password_salt` | TEXT NOT NULL | Per-user, 16 random bytes hex |
| `password_hash` | TEXT NOT NULL | PBKDF2-HMAC-SHA256, 240 000 iterations |
| `enabled` | INTEGER NOT NULL | Disabled accounts fail login and invalidate live tokens |
| `created_at`, `last_login` | DOUBLE PRECISION | |

Passwords are never stored or logged in the clear, and the salt is per-user so
one rainbow table cannot cover the estate.

### `portal_audit`

Append-only. Nothing in the application updates or deletes a row.

| Column | Type | Notes |
|---|---|---|
| `id` | BIGSERIAL PK | |
| `occurred_at` | DOUBLE PRECISION NOT NULL | Unix epoch seconds, UTC |
| `username` | TEXT | NULL for pre-authentication events |
| `source_ip` | TEXT | From `X-Forwarded-For` when behind the portal |
| `action` | TEXT NOT NULL | `auth.login`, `user.create`, `audit.export`, … |
| `object_uid` | TEXT | KMIP UUID where one applies. Not a FK — an audit record must outlive the object it describes |
| `provider` | TEXT | |
| `result` | TEXT NOT NULL | `SUCCESS` / `FAILURE` |
| `detail` | TEXT | |

> `object_uid` is deliberately **not** a foreign key. A `Destroy` audit record
> is most valuable precisely when the object is gone; a cascade or a
> constraint violation would delete or block the evidence.

Indexes: `occurred_at`, `username`.

---

## Migration from SQLite

```bash
python cryptohub_lite/tools/migrate_sqlite_to_postgres.py \
    --sqlite kmip_metadata.db \
    --postgres postgresql://cryptohub:devpass@localhost:5432/cryptohub \
    --dry-run       # report first
```

The tool refuses a non-empty target unless `--force`, preserves UUIDs, copies
parents before children, and verifies row counts, exiting non-zero on any
shortfall.

## Type mapping

| Concern | SQLite | PostgreSQL |
|---|---|---|
| Auto id | `INTEGER AUTOINCREMENT` | `BIGSERIAL` |
| Epoch timestamps | `REAL` | `DOUBLE PRECISION` |
| Binary | `BLOB` (bytes) | `BYTEA` (memoryview → converted to bytes) |
| Placeholder | `?` | `%s` |
| Upsert-ignore | `INSERT OR IGNORE` | `ON CONFLICT DO NOTHING` |
| JSON path | `json_extract(c,'$.k')` | `(c::jsonb ->> 'k')` |

`ON CONFLICT (...) DO UPDATE SET x = excluded.x` needs no translation —
PostgreSQL originated `excluded` and SQLite adopted the same spelling.
