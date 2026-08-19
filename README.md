# IDEMIA CryptoHub Lite

A web-based cryptographic management platform built on an **OASIS KMIP 2.1**
server that delegates all key storage and cryptography to a **PKCS#11 HSM**.

Manage KMIP objects, PKCS#11 tokens, certificates, keys, users and audit
records through an IDEMIA-branded portal — or drive the same objects over the
KMIP wire protocol. Both are views of one system, not two systems kept in step.

Cryptographic material never leaves the HSM. The KMIP layer manages object
lifecycle, metadata, access control and protocol framing; every key operation
happens on the token.

---

## Contents

1. [Quick start](#quick-start)
2. [Container services](#container-services)
3. [First run](#first-run)
4. [Using the portal](#using-the-portal)
5. [Connecting a KMIP client](#connecting-a-kmip-client)
6. [Security model](#security-model)
7. [Governance](#governance)
8. [Operating](#operating)
9. [Configuration](#configuration)
10. [Architecture at a glance](#architecture-at-a-glance)
11. [Known limitations](#known-limitations)
12. [Further documentation](#further-documentation)

---

## Quick start

**Prerequisite:** a container engine — **Docker Desktop or Rancher Desktop**,
running. Nothing else: Python, PostgreSQL and SoftHSM2 all come from the
images. See [Running on Rancher Desktop](#running-on-rancher-desktop) if
Docker Desktop is not available to you.

Clone, then run the launcher for your shell **from the repository root**:

```bat
REM Windows (cmd.exe or PowerShell)
setup.cmd
```

```bash
# Linux, macOS, Git Bash
./setup.sh
```

> `setup.sh` will not run in `cmd.exe` — Windows cannot execute a `.sh` file
> and reports *"is not recognized as an internal or external command"*. Use
> `setup.cmd` there. Both are thin launchers for the real scripts in
> `cryptohub_lite\scripts\`.

| Service | Address | Credentials |
|---|---|---|
| **Portal (the UI)** | http://localhost:8081 | `admin` / `admin123` |
| REST API | http://localhost:8000/api/docs | bearer token from `/api/auth/login` |
| KMIP | `localhost:5696` | a portal account with a KMIP credential |
| PostgreSQL | not published — reachable only inside the stack | `cryptohub` / `devpass` |

> The first build takes several minutes: SoftHSM2 is **compiled from source**,
> deliberately. See [SoftHSM2 setup](cryptohub_lite/docs/SOFTHSM2_SETUP.md).

---

## Container services

Four containers, no orchestration layer. All of them must be running for the
system to work as described — the portal renders nothing useful without the
API, and the API answers but cannot create keys without the token.

| Container | Image | Published port | What it does |
|---|---|---|---|
| `chl-postgres` | `postgres:16-alpine` | none | Holds **everything persistent**: portal accounts, the portal audit trail, and all KMIP object metadata. Deliberately not published to the host — nothing outside the stack has any business connecting to it. |
| `chl-api` | `cryptohub-lite/api:dev` | `8000:8000` | The REST API the portal calls, and the only service that talks to the HSM for portal-driven operations. |
| `chl-kmip` | `cryptohub-lite/api:dev` | `5696:5696` | The KMIP 2.1 wire server, for external KMIP clients. **Same image as the API**, started with `SERVICE=kmip`. |
| `chl-portal` | `cryptohub-lite/portal:dev` | `8081:80` | Server-rendered PHP. Holds no state and does no crypto; every page is a call to the API. |

`chl-api` and `chl-kmip` being one image is the point, not a shortcut: they
share the same SoftHSM2 token volume and the same database, which is what makes
the portal and a KMIP client two views of one system instead of two systems
that have to be reconciled.

### Start order

Not arbitrary, and enforced by health checks rather than by sleeping:

```
chl-postgres  (healthy: pg_isready)
     └── chl-api  (healthy: GET /api/health)
              ├── chl-kmip
              └── chl-portal
```

`chl-api` waits for a *healthy* database, not merely a started one, and both
`chl-kmip` and `chl-portal` wait for a healthy API. Starting `chl-portal`
on its own therefore starts the whole chain.

### Checking they are running

```bash
C=cryptohub_lite/docker-compose.yml

docker compose -f $C ps                    # all four, with health state
docker compose -f $C logs -f api           # follow one service
docker compose -f $C logs --tail=50 kmip
```

`docker compose ps` is the one to trust. A container in `running` state is not
necessarily working — `chl-api` reports `starting` for up to 20 seconds while
it opens the HSM session and provisions the master key, and `chl-kmip` refuses
to start at all if TLS is unconfigured and `KMIP_ALLOW_PLAINTEXT` is not set.
Expect all four `running`, with `chl-postgres` and `chl-api` also `(healthy)`.

If a container is missing from the list it never started; check
`docker compose -f $C logs <service>` rather than restarting blindly.

If the portal loads but shows *"Cannot reach the CryptoHub API"*, the portal is
fine and the API is not — check `ps` and `logs api`.

### Everyday commands

```bash
docker compose -f $C up -d                 # start everything
docker compose -f $C up -d --build         # rebuild changed images first
docker compose -f $C restart api kmip      # after changing API code
docker compose -f $C restart portal        # after editing a .php file
docker compose -f $C stop                  # stop, keep the data
docker compose -f $C down                  # remove containers, keep the volumes
```

`down` keeps the two volumes, which is what you want: `chl_pgdata` holds the
database and `chl_tokens` holds the **actual key material**. Neither can be
rebuilt from source. `down -v` destroys both — see
[Backup and restore](#backup-and-restore) before you ever reach for it.

### Changing a published port

`8081:80` in the compose file maps host to container. Change the left number if
8081 is taken; nothing inside the container needs to change. `KMIP_HOST_PORT`
does the same for KMIP, which always listens on 5696 internally.

---

## First run

A first run has one administrator and no keys. Five steps take it to a working
system.

The portal prompts for the first two itself: a red banner appears on every page
while the account still uses the default password, and the dashboard shows a
**Getting Started** card until the first managed object exists. Both disappear
on their own once the work is done, so you can follow the UI instead of this
section if you prefer.

### 1. Sign in and secure the administrator

Sign in as `admin` / `admin123`, then click **your name in the top-right**
→ *Change Password*.

The bootstrap account is created **only when the user table is empty**, so it
cannot silently reappear — but until you change it, the password is one that
is published in this file.

### 2. Create real accounts

**Administration → Add User.** Give each person the least role that works:

| Role | Give it to |
|---|---|
| Administrator | Platform owners; the only role that manages users |
| SecurityOfficer | Key custodians — full lifecycle, no user management |
| Operator | Applications and day-to-day use. **Cannot destroy keys** |
| Auditor | Compliance — read plus audit export, no key operations |
| ReadOnly | Dashboards and reporting |

Every user can change their own password from **My Account**; only an
Administrator can reset someone else's, from **Administration → Users →
Reset**.

### 3. Create a KMIP client account

KMIP clients sign in with the *same* accounts — there is no separate client
credential store to administer. Create one account per client (for example
`svc-payments`, role **Operator**) so that disabling it revokes exactly that
client.

The engine keeps its own credential for each account, hashed separately from
the portal's, and a KMIP client is checked against that. It is written whenever
the portal has the password in hand — when the account is created, when the
password is changed, and on a successful portal sign-in — so creating the
account through the portal is all that is required.

> **An account whose password was only ever set outside the portal cannot use
> a KMIP client.** The engine's credential cannot be derived from the stored
> portal hash, so there is nothing to convert. Set the password once through
> the portal and it is provisioned. The API logs a warning naming any account
> in this state at startup.
>
> There is no shared-PIN fallback. A client used to be able to present the
> token PIN with any username it liked, and the username was believed; since
> authorization keys off that username, anyone holding the PIN could claim to
> be an administrator.

### 4. Create your first key

**Keys → Generate key.** Pick an algorithm, give it a label, and generate.
The same card also appears on the **KMIP** page — one form, two entry points.

| Algorithm | Sizes | Produces |
|---|---|---|
| AES | 256 / 192 / 128 | one SymmetricKey |
| 3DES | 192 / 128 | one SymmetricKey |
| RSA | 2048 / 3072 / 4096 | a `_priv` / `_pub` pair |
| ECC | P-256, P-384, P-521, P-224, P-192, secp256k1 | a `_priv` / `_pub` pair |
| DSA | 2048 / 1024 | a `_priv` / `_pub` pair |

The **key usage attributes** are the PKCS#11 flags the engine sets on the
token, and they change with the algorithm. A secret key offers
`CKA_ENCRYPT`, `CKA_DECRYPT`, `CKA_WRAP`, `CKA_UNWRAP`, `CKA_SENSITIVE` and
`CKA_EXTRACTABLE`; a key pair offers `CKA_SIGN`, `CKA_VERIFY` and
`CKA_DERIVE`. Leaving all of them unticked is refused rather than producing a
key that can do nothing.

Two things the form deliberately does not offer, because the engine decides
them and a control the system ignores is worse than none:

* **`CKA_ID`** is 16 random bytes generated inside the shim. It cannot be
  supplied — it is shown in the key list once the key exists.
* **Sensitive and extractable on a key pair.** The private half is always
  sensitive and never extractable, the public half is neither.

Then check it landed in the hardware: **PKCS#11 → Token Objects** shows the
same key with its raw `CKA_*` attributes. For a symmetric key created with
the defaults that includes `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false`
— the material cannot leave the HSM.

### 5. Confirm the audit trail

**Audit** should already show your sign-in, the user you created and the key
you generated. If it does not, nothing else on this list is trustworthy.

The page shows one list drawn from two logs: the portal's own record of
sign-ins, user administration and exports, and the engine's record of every
KMIP operation. The engine's half is a **hash chain** — each entry links to the
one before it — so the page can state whether it verifies, and does. A banner
reading *Integrity verified* means no entry has been altered or removed since it
was written. A warning there is an incident, not a display problem.

### Verifying the whole path

To prove the portal and KMIP are one system, create a key over the wire and
watch it appear in the UI:

```bash
docker compose -f cryptohub_lite/docker-compose.yml exec api python - <<'PY'
from kmip_pkcs11.test_app.client import KMIPClient
from kmip_pkcs11.core.enums import CryptographicAlgorithm
c = KMIPClient(host="kmip", port=5696, username="admin", password="admin123")
c.connect()
uid = c.create(algorithm=CryptographicAlgorithm.AES, length=256, name="wire-test")
c.close()
print("created", uid)
PY
```

Refresh **KMIP** in the portal — `wire-test` is there, Active, and the Audit
page records it as `kmip.Create` by `admin`.

> **Create yields an Active key.** This engine sets `State.Active` at creation
> rather than `PreActive`, so calling `activate()` afterwards fails with
> *"not permitted when object state is 'Active'"*. That is why the portal's
> **Activate** button only appears for objects that are genuinely PreActive —
> which, for keys made through Create, is none of them. Objects registered by
> other paths can still start PreActive.

---

## Using the portal

**Dashboard** — key, certificate, KMIP and PKCS#11 object counts, HSM status,
audit volume, system health, with state and algorithm charts.

**Key Management** — generate AES, 3DES, RSA, ECC and DSA keys with the
PKCS#11 usage attributes chosen per key, beside a list showing class, label,
type, size, `CKA_ID`, state and usage. Search, filter, CSV export.

**KMIP Explorer** — managed objects with types, states and attributes. Create,
Activate, Revoke, Re-Key and Destroy from the interface; all 41 operations
available over the wire.

**PKCS#11 Explorer** — slots, tokens and objects with raw `CKA_*` attributes
exactly as the token reports them. Secret-bearing attributes are never
requested.

**Audit** — user, timestamp, source IP, action, object, provider and result for
every portal action *and* every KMIP operation, including failed
authentications. KMIP entries are hash-chained and append-only, and the page
reports whether the chain verifies. Export to CSV, Excel or JSON.

**Administration** — users, five roles, capability matrix.

### Roles

| Role | read | audit | export | create | lifecycle | destroy | users |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Administrator | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| SecurityOfficer | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | |
| Operator | ✔ | | | ✔ | ✔ | | |
| Auditor | ✔ | ✔ | ✔ | | | | |
| ReadOnly | ✔ | | | | | | |

Enforced by the API on every request. The interface hides what a role cannot
do, but that is a courtesy — the check is server-side.

---

## Connecting a KMIP client

Clients authenticate with a portal account, as set up in
[step 3](#3-create-a-kmip-client-account):

```python
from kmip_pkcs11.test_app.client import KMIPClient
from kmip_pkcs11.core.enums import CryptographicAlgorithm

client = KMIPClient(host="localhost", port=5696,
                    username="svc-payments", password="...")
client.connect()
uid = client.create(algorithm=CryptographicAlgorithm.AES, length=256,
                    name="payments-2026")
ct, iv, tag = client.encrypt(uid, b"Hello KMIP!")
pt = client.decrypt(uid, ct, iv=iv, auth_tag=tag)
```

Create one account per client and give it the least role that works — usually
**Operator**. Disabling the account revokes access immediately.

### Supported operations

**41 of 53** KMIP 2.1 operations. The remaining 12 are a deliberate scope
decision: they are session, async and vendor operations that do not fit a
synchronous, per-request-authenticated server.

| Category | Operations |
|---|---|
| **Object lifecycle** | Create, CreateKeyPair, Register, ReKey, ReKeyKeyPair, DeriveKey, Certify, ReCertify, CreateSplitKey, JoinSplitKey, Import, Export, Activate, Revoke, Destroy, Archive, Recover, Check |
| **Retrieval & discovery** | Get, GetAttributes, GetAttributeList, Locate, Query, DiscoverVersions, ObtainLease, GetUsageAllocation |
| **Attributes** | AddAttribute, ModifyAttribute, DeleteAttribute, SetAttribute, AdjustAttribute |
| **Cryptographic** | Encrypt, Decrypt, Sign, SignatureVerify, MAC, MACVerify, Hash, RNGRetrieve, RNGSeed, Validate |
| **Not implemented** (12) | Cancel, Poll, Notify, Put, Log, Login, Logout, DelegatedLogin, SetEndpointRole, PKCS11, Interop, ReProvision |

The wire protocol itself is complete: full TTLV binary encoding and decoding,
batching, `BatchErrorContinuationOption` and `MaximumResponseSize`.

### Algorithm coverage

**15 of 40** `CryptographicAlgorithm` values map to a working mechanism on this
SoftHSM2 build: AES, DES, TDES, RSA, EC, ECDSA, ECDH, DSA, DH, and
HMAC-MD5/SHA1/224/256/384/512.

The shim probes the token's actual mechanism list at startup and gates every
dispatch on it, so an unsupported request fails cleanly with
`OperationNotSupported` rather than a raw PKCS#11 error. SHA-3 HMAC and
hashing, Blowfish and Twofish are wired in but inactive on *this* token — point
the shim at a token that implements them and they activate with no code change.
The remaining twelve (RC2/RC4/RC5, IDEA, CAST5, Camellia, ChaCha20/Poly1305,
SKIPJACK, MARS, OneTimePad, SHAKE128/256) have no PKCS#11 mechanism in any
backend tested here, or — for SKIPJACK, MARS and OneTimePad — none was ever
standardized at all.

### Key lifecycle states

```
           ┌──────────────┐
           │  Pre-Active  │──activate──►┌────────┐
           └──────────────┘             │ Active │
                  │                     └────────┘
                  │ revoke(normal)          │ revoke(normal)
                  ▼                         ▼
           ┌─────────────────────────────────────┐
           │            Deactivated              │
           └─────────────────────────────────────┘
                  │ revoke(compromise)      │ revoke(compromise)
                  ▼                         │
           ┌────────────┐◄─────────────────┘
           │ Compromised│
           └────────────┘
                  │ destroy
                  ▼
        ┌──────────────────────┐
        │ DestroyedCompromised │
        └──────────────────────┘
```

All states except DestroyedCompromised can transition to Destroyed. A
Deactivated key still **decrypts** (data recovery) but will not encrypt.
Archive/Recover is orthogonal to state: an archived object keeps its state but
is unusable for anything but metadata reads until recovered.

---

## Security model

### Authentication

Every identity has its own credential, stored as a per-identity salted
**scrypt** hash. A KMIP client authenticates with a `UsernameAndPassword`
Credential and the password is verified against *that identity's* hash. An
identity that was never provisioned cannot authenticate, whatever password it
supplies; requests with no Credential are treated as `anonymous`.

The PKCS#11 token PIN authenticates the **server to the HSM** and is not a user
credential. It previously was the only password, which meant any caller holding
it could claim any username — including one carrying the admin role, and every
ownership and access decision downstream inherited that.

A client certificate's Common Name becomes the identity only when mTLS is
configured *and* client certificates are required, so the subject has actually
been verified against the CA — and only if it names a **provisioned** identity.
A CA-signed certificate does not get to invent a principal.

### Authorization

Every managed object records the identity that created it. Operations against an
*existing* object are authorized in this order:

1. **Admin role** — unconditional access to every object.
2. **Ownership** — the identity that created it.
3. **Delegated grant** — a named identity reaches a specific object without
   owning it. `read` covers Get, GetAttributes, GetAttributeList, Check, Export
   and ObtainLease; everything else (Encrypt, Destroy, ReKey, …) needs `full`.
4. **Group grant** — a grantee named `group:<name>` reaches every member, so
   access follows team membership instead of being re-granted per person.
   Leaving the group withdraws it.

Separately, and *before* any of the above, a role may carry an operation
allowlist: if any role an identity holds names a set of permitted operations,
that identity can perform only the union of those sets. It is opt-in, so
introducing roles never silently locks anyone out, and it only ever narrows what
an identity may do. Admin is exempt.

`Locate` results are filtered to the caller's own objects — a non-admin identity
cannot enumerate what it does not own.

In this deployment, portal administration drives all of this: a portal role of
Administrator or SecurityOfficer projects to the engine's admin role, and a
demotion takes effect on the engine too.

### Key material at rest

Most object types keep their secret bytes on the HSM, and the metadata store
holds only a reference. Three do not — `SecretData`, `OpaqueObject` and
`SplitKey` shares are raw payloads with no PKCS#11 object behind them.

Those blobs are encrypted with **AES-256-GCM** under a master key that is
generated on, and never leaves, the HSM. A copy of the database yields
ciphertext only. Certificates are deliberately left in the clear — they are
public, and encrypting them would make them unreadable without the HSM for no
benefit.

The master key is provisioned on first start, and any pre-existing cleartext
rows are converted automatically, so upgrading needs no operator step. The
conversion also scrubs the superseded plaintext, because encrypting a row with
`UPDATE` does not erase what was there before.

> **That scrub reaches the database files only.** Copies that already left them
> — filesystem snapshots, backups taken before the upgrade, replicas, WAL
> archives, or blocks retained by a wear-levelling SSD — are out of its reach.
> Treat any store that once held cleartext secrets as exposed, and rotate those
> secrets rather than relying on the upgrade alone.

Each envelope records which master key wrote it, so rotation is safe to
interrupt: an interrupted rotation leaves a mix of both keys that stays fully
readable, and re-running finishes the job.

```bash
kmip-admin -d "$CRYPTOHUB_DB" rotate-master-key
```

Once a key is retired, blobs still under it are unrecoverable by design.

### Audit log

Every operation except `Query` and `DiscoverVersions` — reads included, since
"who exported this key" is the question an audit log most needs to answer —
writes a record with identity, operation, object, result and reason, client
address and timestamp.

The log is append-only, enforced two ways. Database triggers block `UPDATE` and
`DELETE` outright, so application bugs and casual tampering fail loudly. And
each row carries the SHA-256 of the previous one, so an attacker with direct
database access who drops the triggers still leaves a broken chain behind. The
portal's Audit page reports the result of that check.

Retention pruning is the one sanctioned way past the triggers, and it refuses to
run on a log that already fails verification — pruning a tampered log would
destroy the evidence. It returns the removed entries so they can be archived
first, and the remaining rows stay verifiable from the cut point.

An audit write that fails never fails the KMIP operation, but it is logged as an
exception — a silently unrecorded operation is exactly what an attacker would
want.

### Transport security

**The KMIP listener refuses to start without TLS** unless
`KMIP_ALLOW_PLAINTEXT=true` is set explicitly. Removing that line is the single
most important production change. TLS 1.2 is the minimum version, and the
certificate and key can be reloaded after renewal without dropping established
connections.

#### Mutual TLS

Client certificates are supported, and can carry the identity. Three settings,
in `cryptohub_lite/docker-compose.yml`:

```yaml
  kmip:
    environment:
      KMIP_ALLOW_PLAINTEXT: "false"       # remove the dev opt-out
      KMIP_TLS_CERT: /certs/server.pem
      KMIP_TLS_KEY:  /certs/server.key
      KMIP_TLS_CA:   /certs/ca.pem        # CA that signed the client certs
      KMIP_REQUIRE_CLIENT_CERT: "true"
    volumes:
      - ./certs:/certs:ro
```

With both a CA and `KMIP_REQUIRE_CLIENT_CERT=true`, the handshake demands a
certificate and verifies it (`CERT_REQUIRED`); a client without one is rejected
at the TLS layer, before any KMIP message is read. Supplying `KMIP_TLS_CA`
*without* requiring client certificates configures the trust store but enforces
nothing — the certificate becomes optional, which is rarely what is intended.

The verified certificate's **Common Name becomes the connection identity**, so a
client can authenticate by certificate instead of sending a password. Two
conditions both apply, and the second is the one worth knowing:

* the certificate must have been genuinely required and verified against the
  configured CA — otherwise the subject is as self-asserted as an
  unauthenticated username;
* **the CN must name an identity that already exists.** A certificate signed by
  your CA does not get to invent a principal that was never granted anything. A
  CN with no matching account is logged and the connection continues as
  `anonymous` rather than being silently promoted.

So create the portal account first, naming it exactly as the certificate's CN.
A `UsernameAndPassword` credential in the request still takes precedence when
present, which lets one client hold a certificate for transport and a separate
identity for authorization.

---

## Governance

Everything above is reactive: a key becomes Deactivated because a client asked,
and a Destroy runs because one identity was authorized to ask for it. Governance
is the part that acts without being asked, and the part that stops one person
acting alone.

> **Both are engine-level features and neither is switched on in this
> deployment.** The cryptoperiod scheduler is enabled in the engine's YAML
> configuration, and dual control additionally needs a policy object passed to
> the KMIP server, which `app/kmip_server_main.py` does not currently pass. As
> shipped, destructive operations execute on first request and nothing
> deactivates on a schedule. Enabling them is a wiring change, not a setting.

### Cryptoperiods

KMIP has no separate cryptoperiod attribute — the Deactivation Date *is* the end
of the period — so a cryptoperiod is that standard attribute plus something that
acts on it. Without a scheduler, a key with a two-year cryptoperiod stays Active
into year five unless somebody remembers.

```bash
kmip-admin -d "$CRYPTOHUB_DB" cryptoperiod set <uid> --days 365
kmip-admin -d "$CRYPTOHUB_DB" cryptoperiod expiring --within-days 30
kmip-admin -d "$CRYPTOHUB_DB" cryptoperiod scan     # one scan now
```

When enabled, a background scan deactivates keys whose Deactivation Date has
passed, warns as keys approach it so rotation is planned rather than discovered,
and — with `auto_rotate` — creates a cross-linked replacement key first, so a
replacement exists before the old key stops being usable. If rotation fails the
key is deactivated anyway, because an expired key left Active is the worse
outcome. Every action is audited under the identity `system:scheduler`, so an
automated deactivation is as attributable as a human one.

### Dual control

Destroy zeroizes key material; Export hands out key bytes. Under dual control
those do not execute on request:

1. The first attempt is **refused** and records an approval request. The handler
   never runs, so nothing has happened to the key.
2. Enough *other* identities approve it out of band.
3. The requester retries, and it goes through.

```bash
kmip-admin -d "$CRYPTOHUB_DB" approval list
kmip-admin -d "$CRYPTOHUB_DB" approval approve <request-id> --as bob
```

The rules that make this dual control rather than paperwork: the requester can
never approve their own request; an approval authorises exactly one attempt on
one object by one identity and is consumed *before* the handler runs; approvals
expire; a retry reuses the open request rather than filling the table; and at
least two approvals are required, with the configuration rejected otherwise.

KMIP defines no wire operation for an out-of-band-approved request, so the
refusal reaches the client as `OperationFailed / PermissionDenied` with the
request id in the message, and the client simply retries.

---

## Operating

### kmip-admin

Identities, roles, grants, groups, operation allowlists, cryptoperiods,
approvals and the audit log have **no KMIP wire operation** — the specification
defines none — so they are managed with `kmip-admin`. Run it inside `chl-kmip`,
which has the package installed and the database DSN in its environment:

```bash
C=cryptohub_lite/docker-compose.yml
K="docker compose -f $C exec kmip kmip-admin -d $CRYPTOHUB_DB"

$K identity list
$K role grant alice admin
$K group add bob crypto-team
$K access grant <uid> group:crypto-team --permission read
$K permission allow auditor Get
$K audit verify                     # exits non-zero if the chain is broken
```

In this deployment most identity and role work should go through the **portal**
instead, so the two halves stay in step. `kmip-admin` is for what the portal
does not expose: groups, operation allowlists, cryptoperiods, approvals and
master-key rotation.

### Backup and restore

**Back up volumes, not images.** `docker save` captures images only, so a folder
full of `.tar` files is not a backup of anything that matters — images rebuild
from this source tree in minutes, and the two volumes cannot be rebuilt from
anything:

| Volume | Holds |
|---|---|
| `chl_pgdata` | user accounts, audit trail, KMIP metadata |
| `chl_tokens` | the SoftHSM2 token — the actual key material |

```bat
backup.cmd                 REM write both volumes to C:\Internal_Idemia\Docker_bkup
backup.cmd --list          REM show what is there
backup.cmd --restore       REM restore (stack must be down)
```

Stop the stack first (`docker compose -f $C down`). A copy taken while
PostgreSQL is writing may not restore cleanly; the script warns but does not
refuse, because a torn backup still beats none.

**The database and the HSM token are one unit.** Objects reference key material
by `CKA_ID`, and secret blobs are encrypted under a master key that lives on the
token. A database restored beside a *different* token is not a degraded backup —
it is unreadable. That is why `backup.cmd` handles both volumes together, and
why restoring recovers a *usable* key rather than merely a listed one.

> `kmip-admin backup` is **not** the tool for this deployment. It uses SQLite's
> online backup API and this store is PostgreSQL; it fails with an explanation
> rather than producing a broken archive. Use `backup.cmd`, or `pg_dump`
> together with a copy of the token volume.

### Starting from scratch

```bash
docker compose -f cryptohub_lite/docker-compose.yml down -v
```

Destroys the database **and the HSM token**, so every key is gone. The next
`up` recreates the bootstrap administrator. Run `backup.cmd` first if you might
want any of it back.

> **This repository is one compose project, `cryptohub-lite`.** If a container
> list shows a second project named `idemia-cryptohub`, that is a separate Java
> prototype — a different code base, with its own network and volumes. Nothing
> here depends on it, and it can be stopped without affecting this stack.

### Migrating an existing SQLite store

```bash
python cryptohub_lite/tools/migrate_sqlite_to_postgres.py \
    --sqlite kmip_metadata.db \
    --postgres postgresql://cryptohub:devpass@localhost:5432/cryptohub \
    --dry-run
```

Preserves KMIP Unique Identifiers, refuses a non-empty target without `--force`,
verifies row counts afterwards, and re-verifies the audit hash chain in the
target — the rows arriving is not the same as the log still being trustworthy.
Columns a older store lacks are named and skipped rather than passed over
silently.

### Upgrades

The database carries a schema version, and the store applies any migrations it
has not yet seen when it opens. Upgrading is therefore just deploying the new
image: an existing database is converted in place rather than needing to be
recreated, and each migration commits with its version bump so an interrupted
upgrade resumes instead of half-applying.

The first start after an upgrade also provisions the HSM master key and converts
any secret blob still stored in the clear. That is why `chl-api` can report
`starting` for a while on a large token — it is doing real work before it binds.

### Health and metrics

The compose health checks use `pg_isready` and the API's `GET /api/health`. That
endpoint is the supported way to ask whether this stack is up, and it is what
`docker compose ps` reflects.

> The engine additionally implements `/health`, `/ready` and `/metrics` in
> Prometheus format, plus structured JSON logging and the multi-process worker
> pool described below — but all of those are started by the `kmip-server` CLI
> from its YAML configuration, and this stack runs `app.kmip_server_main`
> instead. **They are not available on `chl-kmip` as shipped.** Wiring them up
> means either running the engine through `kmip-server` with a config file, or
> starting the `HealthServer` from the entry point.

### Scaling

The engine can fork multiple worker processes, each with its own PKCS#11
session, which is the only way past the single-session ceiling. **This stack
runs a single process**; the worker pool is a `kmip-server` feature, as above.
Measured on 4 cores, AES encrypt through the full stack:

| | 1 worker | 4 workers |
|---|---|---|
| 4 clients | 605 ops/sec | 887 ops/sec |
| 8 clients | 546 ops/sec | 829 ops/sec |

About 1.5×, not 4×. The limit is the audit log: a hash chain is inherently
serial, so every audited operation serialises on one database write lock. That
is the cost of tamper-evidence, and it is a deliberate trade.

### Running the tests

```bash
docker compose -f cryptohub_lite/docker-compose.yml exec api \
    sh -c 'cd /app && python -m pytest kmip_pkcs11/tests -q'
```

Expect **811 passed**, run live against a real SoftHSM2 token. Fewer than that
on a distribution SoftHSM2 is an environment difference, not a defect —
[SoftHSM2 setup](cryptohub_lite/docs/SOFTHSM2_SETUP.md) explains exactly why.

### Running on Rancher Desktop

Where Docker Desktop is restricted, Rancher Desktop runs this stack unchanged.
Set its container engine to **`moby` (dockerd)** in *Preferences → Container
Engine* — the same daemon Docker Desktop uses, so `docker` and `docker compose`
behave identically and the compose file needs no edits. Nothing here is
Docker-specific: the images are plain OCI.

Kubernetes can be switched off. The stack is four containers on one Docker
network and never touches it.

```bash
rdctl list-settings                   # confirm "containerEngine": {"name": "moby"}
docker compose version                # the bundled v2 plugin
```

The `containerd` engine also works, via `nerdctl compose` — but `moby` costs
nothing and keeps every command in this README literally correct, so prefer it.

#### When the engine will not come up

Rancher Desktop's Linux VM can wedge, usually showing `/sbin/init exited with
status 1` in `%LOCALAPPDATA%\rancher-desktop\logs\wsl.log`. The app window
opens, but `docker` reports *"cannot find the file specified"* on
`npipe:////./pipe/docker_engine` — there is no daemon behind the pipe.

```bash
rdctl shutdown
wsl --shutdown                        # then relaunch Rancher Desktop
```

Give it two minutes. Restarting the app alone does not fix it; the WSL
distribution has to be cycled. `wsl -l -v` should end with `rancher-desktop`
in state `Running`.

---

## Configuration

Set in `cryptohub_lite/docker-compose.yml` or the environment.

| Variable | Default | Notes |
|---|---|---|
| `POSTGRES_PASSWORD` | `devpass` | |
| `JWT_SECRET` | `dev-only-change-me` | **Change for production** |
| `BOOTSTRAP_ADMIN` / `BOOTSTRAP_PASSWORD` | `admin` / `admin123` | Used only when no users exist |
| `PKCS11_TOKEN` / `PKCS11_PIN` | `CryptoHubLite` / `1234` | Authenticates this server to the HSM, and nothing else — not a user credential |
| `KMIP_HOST_PORT` | `5696` | Change if another KMIP server holds the port |
| `KMIP_ALLOW_PLAINTEXT` | `true` (dev) | **Remove for production** |
| `KMIP_TLS_CERT` / `KMIP_TLS_KEY` | — | Required unless plaintext is permitted |
| `KMIP_REQUIRE_CLIENT_CERT` | `false` | mTLS |
| `CRYPTOHUB_DB` | `postgresql://…` | One DSN for portal and KMIP metadata alike |

`KMIP_ALLOW_PIN_FALLBACK` no longer exists. It allowed a client to authenticate
with the shared token PIN under any username it chose, which meant the identity
every access decision rests on was never actually proven. There is no setting to
re-enable it: a client without its own credential is refused.

### Governance options

For a deployment that enables governance, these live in the engine's YAML
configuration — see `deploy/config.example.yaml` for the annotated template.

| Key | Default | Purpose |
|---|---|---|
| `enabled` | `false` | run the cryptoperiod scheduler |
| `scan_interval_seconds` | `300` | how often it scans |
| `warn_days` | `7` | how far ahead expiry is announced |
| `auto_rotate` | `false` | create a cross-linked replacement key on expiry |
| `dual_control` | `false` | require M-of-N approval for the operations below |
| `dual_control_operations` | `[Destroy, Export]` | which operations need approval |
| `approvals_required` | `2` | how many *other* identities must approve |
| `approval_ttl_seconds` | `3600` | how long an unused approval stays valid |

---

## Architecture at a glance

| Layer | Technology | Responsibility |
|---|---|---|
| Portal | PHP 8.3, Bootstrap 5, Chart.js | Presentation only |
| API | FastAPI (Python 3.11) | Authentication, RBAC, audit, aggregation |
| Engine | `kmip_pkcs11` | KMIP 2.1 — 41 of 53 operations |
| Store | PostgreSQL 16 | KMIP metadata + portal data, one database |
| HSM | SoftHSM2 (source build) | Key storage and cryptography |

```
Browser ──HTTPS──► PHP portal ──REST+JWT──► FastAPI ──in-process──► kmip_pkcs11
                                                │                        │
KMIP client ──TTLV/5696──────────────────► KMIP server ──────────────────┘
                                                │                        │
                                          PostgreSQL              PKCS#11 / HSM
```

**KMIP logic lives in `kmip_pkcs11/` and nowhere else.** The REST API calls the
engine's own operation handlers in-process; the PHP tier calls the REST API and
holds no cryptographic or KMIP knowledge at all. The shim is the only module
that imports `pkcs11`, so swapping in a different — for example FIPS-validated
— token needs no change above it.

---

## Known limitations

Stated plainly rather than discovered later.

| Limitation | Detail |
|---|---|
| **Concurrency is capped per process** | All HSM work in one process is serialised through a single PKCS#11 session. A session pool was built, load-tested and rejected: `python-pkcs11` calls `C_Initialize(NULL)`, so the library's own thread safety is never enabled and separate sessions crash the binding. Multiple worker processes are the supported way past it. |
| **Worker scaling is ~1.5×, not linear** | The hash-chained audit log serialises every audited operation on one write lock. Higher scaling needs a different audit design. The pool is also a `kmip-server` feature and this stack runs a single process — see [Scaling](#scaling). |
| **Health, metrics and JSON logging are not wired here** | The engine implements `/health`, `/ready`, `/metrics` and structured logging, but only the `kmip-server` CLI starts them; this stack uses its own entry point. The API's `/api/health` is what the health checks use. |
| **No high availability** | Single API process, single KMIP process, single token. Backup and restore are point-in-time, not continuous. |
| **No metadata/HSM reconciliation** | Divergence between the database and the token is not detected automatically. |
| **Batch operations are not atomic** | A failure in one `BatchItem` does not roll back earlier items in the same batch. |
| **The audit chain is local and unanchored** | Tampering is detectable, but the chain is not anchored anywhere external — an attacker who rewrites the whole log consistently leaves no trace. Ship entries to an external collector for stronger guarantees. Note also that only the KMIP half of the trail is chained; the portal's own action log is not. |
| **Governance is available but not wired here** | See [Governance](#governance). |
| **`kmip-admin backup` does not work against PostgreSQL** | It uses SQLite's online backup API. Use `backup.cmd` or `pg_dump` plus the token volume. |
| **No multi-tenancy** | Groups and role allowlists partition *access*, not the namespace: object names, `Locate` queries and quotas are global. Isolation today means one deployment per tenant. |
| **No ACME / automated certificate issuance** | TLS is enforced and certificates reload without dropping connections, but obtaining and renewing them is left to the operator. |
| **Not FIPS/CC validated** | SoftHSM2 is not a validated HSM. The PKCS#11 boundary means a validated token can be swapped in with no code change above the shim, but that swap has not happened here. |
| **Algorithm coverage** | 15 of 40 `CryptographicAlgorithm` values work against this token — see [Algorithm coverage](#algorithm-coverage). |
| **SoftHSM2 SENSITIVE quirk** | `SENSITIVE=True AND EXTRACTABLE=True` blocks reading `CKA_VALUE`; the shim downgrades sensitivity automatically when extractability is explicitly requested. |

---

## Further documentation

| Document | Covers |
|---|---|
| [Developer onboarding](cryptohub_lite/docs/DEVELOPER_ONBOARDING.md) | Clone to running, layout, debugging, common problems |
| [Administrator guide](cryptohub_lite/docs/ADMINISTRATOR_GUIDE.md) | Roles, audit, lifecycle, backup, hardening |
| [PKCS#11 integration](cryptohub_lite/docs/PKCS11_INTEGRATION.md) | The shim, concurrency, moving to a vendor HSM |
| [SoftHSM2 setup](cryptohub_lite/docs/SOFTHSM2_SETUP.md) | Why it is built from source; token management |
| [Database schema](cryptohub_lite/docs/SCHEMA.md) | Every table, and SQLite → PostgreSQL migration |

### References

- [OASIS KMIP Specification v2.1](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html)
- [OASIS KMIP Test Cases v2.1](https://docs.oasis-open.org/kmip/kmip-testcases/v2.1/)
- [PKCS #11 Specification v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.0/)
- [SoftHSM2](https://github.com/opendnssec/SoftHSMv2)
- [python-pkcs11](https://python-pkcs11.readthedocs.io/)
