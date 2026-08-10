# Administrator Guide

Operating IDEMIA CryptoHub Lite.

## First run

A bootstrap administrator (`admin` / `admin`) is created **only when the user
table is empty**, so it cannot silently reappear on a running system. Change
it before anything else:

1. Sign in at http://localhost:8081
2. Administration → Users
3. Create a named administrator for yourself
4. Sign in as that account and disable `admin`

You cannot disable or delete your own account — locking yourself out is easy
and tedious to undo.

## Roles

Roles are enforced by the API on every request. The interface hides actions a
role cannot perform, but that is a courtesy: the check is server-side.

| Role | read | audit | audit.export | key.create | key.lifecycle | key.destroy | user.manage |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Administrator | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| SecurityOfficer | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | |
| Operator | ✔ | | | ✔ | ✔ | | |
| Auditor | ✔ | ✔ | ✔ | | | | |
| ReadOnly | ✔ | | | | | | |

**Operator deliberately lacks `key.destroy`.** Day-to-day key operations
should not include an irreversible one.

### Roles reach KMIP too

A portal role is projected into the KMIP engine's own authorization on each
authentication: Administrator and SecurityOfficer receive engine-level admin
(unrestricted access to every object); the others rely on ownership and
delegated grants. Demoting someone in the portal removes their engine admin on
their next connection.

## Users and KMIP clients are the same accounts

A KMIP client authenticates with a portal username and password. There is no
separate client credential store.

```python
KMIPClient(host="cryptohub", port=5696, username="svc-payments", password="...")
```

Create a dedicated account per client, give it the least role that works —
usually **Operator** — and disable it to revoke access immediately.

> Previously any username presented with the shared token PIN was accepted as
> that username, which made every identity forgeable by anyone holding the
> PIN. That path is off by default. `KMIP_ALLOW_PIN_FALLBACK=true` re-enables
> it for migration only, and logs a warning on every use.

## Audit

Every portal action and every KMIP operation is recorded: user, timestamp,
source IP, action, object, provider, result.

* **Portal** — Audit page, with filters by user, action and result.
* **Export** — CSV, Excel (CSV-compatible) or JSON. Exporting is itself
  audited; the one action that copies the whole record out of the system
  should not be the one that leaves no trace.
* **Retention** — none is implemented. `portal_audit` grows without bound;
  schedule your own archival.

The trail is append-only by construction: nothing in the application updates
or deletes a row. It is not cryptographically tamper-evident — anyone with
direct database access can alter it. Restrict PostgreSQL accordingly.

### Events worth alerting on

| Action | Why |
|---|---|
| `kmip.Authenticate` FAILURE | Repeated failures against one username is a brute-force attempt |
| `auth.login` FAILURE | Same, for the portal |
| `kmip.Destroy` | Irreversible |
| `audit.export` | Bulk copy of the audit record |
| `user.create` / `user.update` | Privilege change |

## Key lifecycle

States follow KMIP: PreActive → Active → Deactivated / Compromised →
Destroyed.

| Action | Effect |
|---|---|
| Activate | Permits the key to protect data |
| Re-Key | Generates a replacement and links it to the original |
| Revoke | Deactivates, or marks compromised depending on the reason |
| Destroy | **Removes key material from the HSM. Irreversible.** |

Revoking with a compromise reason is not the same as ordinary retirement: it
means data protected by that key should be re-encrypted.

Destroying is irreversible and unrecoverable — anything encrypted under the
key becomes unreadable. The portal confirms with those consequences named.

## Certificates

The Certificates page parses each stored X.509 and sorts by remaining
validity, so the ones nearest expiry are first. Expired and expiring-within-30-
days are counted separately and called out in a banner.

There is **no automatic renewal or alerting** — the page shows the state, it
does not act on it. Check it, or export the CSV into whatever does alert.

## Backup and restore

One PostgreSQL database holds KMIP metadata *and* portal data, so a single
dump covers the system:

```bash
docker compose -f cryptohub_lite/docker-compose.yml exec postgres \
    pg_dump -U cryptohub cryptohub > cryptohub-$(date +%F).sql
```

**A database backup is not a key backup.** Key material lives in the HSM. For
SoftHSM2 that is the `chl_tokens` volume; for a vendor HSM, follow the
vendor's backup procedure. Restoring metadata against a token that no longer
holds the corresponding keys leaves rows describing keys that do not exist —
and there is no automated reconciliation for that today.

```bash
docker run --rm -v cryptohub-lite_chl_tokens:/tokens -v "$PWD":/backup alpine \
    tar czf /backup/tokens-$(date +%F).tar.gz -C /tokens .
```

## Production hardening

The development defaults are chosen to make a first run work. Before
production:

| Setting | Development | Production |
|---|---|---|
| `KMIP_ALLOW_PLAINTEXT` | `true` | **remove**; set `KMIP_TLS_CERT` / `KMIP_TLS_KEY` |
| `KMIP_REQUIRE_CLIENT_CERT` | `false` | `true` where clients have certificates |
| `JWT_SECRET` | `dev-only-change-me` | a strong random value from a secrets manager |
| `POSTGRES_PASSWORD` | `devpass` | strong, from a secrets manager |
| `BOOTSTRAP_PASSWORD` | `admin` | changed at first sign-in |
| `PKCS11_PIN` | `1234` | from a secrets manager |
| Portal | HTTP on 8081 | behind TLS termination |

The KMIP listener **refuses to start without TLS** unless
`KMIP_ALLOW_PLAINTEXT=true` is set explicitly. Removing that line is the
single most important production change.

## Known limitations

Carried forward honestly from the platform assessment:

* **Concurrency** — all HSM work is serialised through one PKCS#11 session.
  Throughput is bounded regardless of hardware. See
  [PKCS11_INTEGRATION.md](PKCS11_INTEGRATION.md).
* **No HA** — single API, single KMIP process, single token.
* **No metadata/HSM reconciliation** — divergence is undetected.
* **Batch operations are not atomic** — a partial batch does not roll back.
* **No cryptoperiod enforcement** — rotation is manual.
* **Audit is not tamper-evident**.

## Troubleshooting

| Symptom | Check |
|---|---|
| HSM Status offline | `docker compose logs api`; the token may not be initialised |
| KMIP container exits at start | TLS not configured and plaintext not permitted |
| Portal "Cannot reach the CryptoHub API" | `docker compose ps` — is `api` *healthy*? |
| KMIP client rejected | The client needs a portal account; check `kmip.Authenticate` in the audit trail |
| EC operations unsupported | SoftHSM2 built against Botan — see [SOFTHSM2_SETUP.md](SOFTHSM2_SETUP.md) |
