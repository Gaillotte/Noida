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
    - [What each part is responsible for](#what-each-part-is-responsible-for)
    - [How REST becomes TTLV](#how-rest-becomes-ttlv)
11. [Known limitations](#known-limitations)
12. [Further documentation](#further-documentation)

---

## Quick start

**Prerequisite:** a container engine — **Rancher Desktop** (what this is
developed against) or **Docker Desktop**, running. Nothing else: Python,
PostgreSQL and SoftHSM2 all come from the images. Either works without
configuration; see [Container engines](#container-engines) for the detail.

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

Five containers, no orchestration layer. All of them must be running for the
system to work as described — the portal renders nothing useful without the
API, and no key can be created without the KMIP client service and the token
behind it.

| Container | Image | Published port | What it does |
|---|---|---|---|
| `chl-postgres` | `postgres:16-alpine` | none | Holds **everything persistent**: portal accounts, the portal audit trail, and all KMIP object metadata. Deliberately not published to the host — nothing outside the stack has any business connecting to it. |
| `chl-api` | `cryptohub-lite/api:dev` | `8000:8000` | Sign-in and JWTs, users and roles, audit reads, dashboard totals, PKCS#11 slot information. **Speaks no KMIP** — it opens no socket to 5696. |
| `chl-client-app` | `cryptohub-lite/api:dev` | `8002:8002` | The **only** service that speaks KMIP. Stateless: REST in, TTLV out. No database, no token, no PKCS#11. **Same image**, started with `SERVICE=client-app`. |
| `chl-kmip` | `cryptohub-lite/api:dev` | `5696:5696` | The KMIP 2.1 wire server — for `chl-client-app` and for external KMIP clients alike. **Same image**, started with `SERVICE=kmip`. |
| `chl-portal` | `cryptohub-lite/portal:dev` | `8081:80` | Server-rendered PHP. Holds no state and does no crypto; every page is a call to the API. |

Three services from one image is the point, not a shortcut. `chl-api` and
`chl-kmip` share the same SoftHSM2 token volume and the same database, which is
what makes the portal and a KMIP client two views of one system instead of two
systems that have to be reconciled. `chl-client-app` shares neither — it holds
nothing at all, and only needs the image because the KMIP client library lives
in it.

### Start order

Not arbitrary, and enforced by health checks rather than by sleeping:

```
chl-postgres  (healthy: pg_isready)
     └── chl-api  (healthy: GET /api/health)
              └── chl-kmip
                       └── chl-client-app  (healthy: GET /api/health)
                                └── chl-portal
```

`chl-api` waits for a *healthy* database, not merely a started one, and the
portal waits for both `chl-api` and `chl-client-app` to be healthy — it needs
one for sign-in and the other for every key operation. Starting `chl-portal`
on its own therefore starts the whole chain.

### Checking they are running

```bat
setup status               REM all five, with health state
setup logs api             REM follow one service
setup logs                 REM follow everything
```

`setup status` is the one to trust. A container in `running` state is not
necessarily working — `chl-api` reports `starting` for up to 20 seconds while
it opens the HSM session and provisions the master key, and `chl-kmip` refuses
to start at all if TLS is unconfigured and `KMIP_ALLOW_PLAINTEXT` is not set.
Expect all five `running`, with `chl-postgres`, `chl-api` and
`chl-client-app` also `(healthy)`.

If a container is missing from the list it never started; check
`setup logs <service>` rather than restarting blindly.

If the portal loads but shows *"Cannot reach the CryptoHub API"*, the portal is
fine and the API is not — check `ps` and `logs api`.

### Everyday commands

One script drives the whole stack, on either engine. Run it from the repository
root; `setup.sh` is the same thing for Git Bash, macOS and Linux.

```bat
setup                      REM build, start, wait until it is serving
setup up                   REM same
setup start                REM start without building - after a 'setup stop'
setup restart api          REM after changing API code
setup restart portal       REM after editing a .php file
setup stop                 REM stop, keep the containers
setup down                 REM remove containers, keep the volumes
setup status               REM what is running
setup logs [service]       REM follow logs
setup test                 REM run the KMIP engine test suite
setup shell [service]      REM a shell inside a container (default: api)
setup backup               REM copy both volumes somewhere safe
setup help                 REM all of the above
```

`down` keeps the two volumes, which is what you want: `chl_pgdata` holds the
database and `chl_tokens` holds the **actual key material**. Neither can be
rebuilt from source. `setup destroy` removes them — see
[Backup and restore](#backup-and-restore) before you ever reach for it.

Under the hood these are `docker compose` (or `nerdctl compose`) against
`cryptohub_lite/docker-compose.yml`, so the raw commands still work if you
prefer them. What `setup` adds is resolving *which* engine is present, and
refusing with an explanation instead of a socket error when none is.

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
This is the one place keys are created in the UI; the **KMIP** page links to it.

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

**Keys and KMIP** are two views of the same objects, and the split is worth
knowing because both pages list the same managed objects — there is no separate
"key store" and "KMIP store". A key on the token *is* a KMIP managed object.

* **Keys** — *what material exists, and make more.* Generate AES, 3DES, RSA, ECC
  and DSA keys with the PKCS#11 usage attributes chosen per key, beside a list
  showing class, label, type, size, `CKA_ID`, state and usage. Search, filter,
  CSV export. **Manage →** on any row opens that object on the KMIP page.
* **KMIP Explorer** — *govern the life of what exists.* Managed objects by KMIP
  identifier and owner, with a detail panel for lifecycle dates, KMIP attributes
  and delegated access, and the lifecycle actions: Activate, Re-Key, Revoke and
  Destroy. All 41 operations are available over the wire.

Generation lives on Keys alone. `Create` and `CreateKeyPair` are genuine KMIP
operations, so the form was not out of place on the KMIP page — but having it in
both made the pages read as interchangeable and pushed the KMIP-specific content
below the fold. The two link to each other instead.

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

**41 of 53** KMIP 2.1 operations. The count is not a claim — it is the size of
the dispatcher's handler table, which is also what decides whether an operation
runs, so `GET /api/kmip/operations` reports it and the **KMIP page** displays
exactly this grouping from that endpoint.

| Category | | Operations |
|---|--:|---|
| **Object lifecycle**<br><sub>bring an object into existence, move it through its states, end it</sub> | 19 | Create, CreateKeyPair, Register, DeriveKey, ReKey, ReKeyKeyPair, Certify, ReCertify, CreateSplitKey, JoinSplitKey, Import, Export, Activate, Revoke, Destroy, Archive, Recover, Check, ObtainLease |
| **Retrieval and discovery**<br><sub>find objects, ask what the server supports</sub> | 7 | Get, GetAttributes, GetAttributeList, Locate, Query, DiscoverVersions, GetUsageAllocation |
| **Attribute management**<br><sub>the metadata KMIP keeps, rather than the key</sub> | 5 | AddAttribute, ModifyAttribute, DeleteAttribute, SetAttribute, AdjustAttribute |
| **Cryptographic services**<br><sub>the server does the work, so the key never leaves</sub> | 10 | Encrypt, Decrypt, Sign, SignatureVerify, MAC, MACVerify, Hash, RNGRetrieve, RNGSeed, Validate |
| **Not implemented** | 12 | Cancel, Poll, Notify, Put, Log, Login, Logout, DelegatedLogin, SetEndpointRole, PKCS11, Interop, ReProvision |

The fourth group is the one that explains this architecture. KMIP is usually
described as key *management*, and groups 1 to 3 are that. But since KMIP 1.2 the
protocol also lets a client ask the **server** to encrypt, sign or MAC on its
behalf: the client sends data and a key identifier and gets the result back,
and the key itself is never transmitted. Without those operations a client would
have to `Get` the key material and do the work itself, which would defeat the
point of holding keys in an HSM.

The 12 that are not implemented fit none of those jobs — `Login`/`Logout`/
`DelegatedLogin`/`SetEndpointRole` assume a session model this server does not
use, since it authenticates every request; `Poll`/`Cancel` are for asynchronous
operations; `Notify`/`Put` are server-to-client push; and the rest are
specialised extensions. A client calling one gets `OperationNotSupported`
rather than a silent failure.

The wire protocol itself is complete: full TTLV binary encoding and decoding,
batching, `BatchErrorContinuationOption` and `MaximumResponseSize`.

### Why only 6 have a screen of their own

**All 41 implemented operations can be run from the portal**, on the
[KMIP Client](#how-rest-becomes-ttlv) page, and all of them travel the same
way: TTLV on 5696, through the dispatcher, into the hash-chained audit log.
There is no second, lesser route any more.

What differs is the *interface*. **Six** have purpose-built controls — the ones
the KMIP page marks with a solid green dot:

`Create` · `CreateKeyPair` · `Activate` · `Revoke` · `ReKey` · `Destroy`

Those are the everyday lifecycle, and they earn a form with valid key sizes, a
curve picker, `CKA_` names and sensible defaults. The other 35 are driven from
the generic form, which asks for raw enum values and a KMIP password each time.

That split is not one decision. It is four, and they deserve different
treatment if you are deciding what to build next.

**Deliberate — data-plane, not control-plane (10 operations)**

`Encrypt` · `Decrypt` · `Sign` · `SignatureVerify` · `MAC` · `MACVerify` ·
`Hash` · `RNGRetrieve` · `RNGSeed` · `Validate`

These *use* keys rather than manage them. A dedicated page would mean routing
application plaintext through a browser and a PHP tier that have no business
seeing it. Humans manage keys; applications use them, by connecting to 5696
themselves. This boundary is worth keeping.

The KMIP Client page is a deliberate exception: it *will* run `Encrypt` from a
browser, because proving the engine works is worth more than the purity of the
rule — which is why it asks for a KMIP password every time and is not the route
for routine work.

**Deliberate — they return key material (2 operations)**

`Get` · `Export`

A "download this key" button is a poor affordance even when it is safe, and
here it *is* safe: every key this system creates is non-extractable, so the
token refuses with `Key is not extractable`. Leaving these to the generic form
means retrieving material takes a deliberate act and a deliberately extractable
key.

**Displayed without being performed (4 operations)**

`GetAttributes` · `GetAttributeList` · `Locate` · `Query`

The Keys and KMIP pages show exactly what these return — object lists,
attributes, engine capabilities — but they do not perform the operations. They
read the metadata store directly, because listing objects for a table needs no
protocol round trip and would otherwise write an audit entry per row on every
page view. The KMIP page marks these with a hollow dot.

**These are the last part of the portal not on the KMIP path.** Moving them
needs attribute-name translation and batched requests; until then, the hollow
dot is the honest marker.

**Not deliberate — simply not built (19 operations)**

`Register` · `Import` · `DeriveKey` · `ReKeyKeyPair` · `Certify` · `ReCertify` ·
`CreateSplitKey` · `JoinSplitKey` · `Archive` · `Recover` · `Check` ·
`ObtainLease` · `DiscoverVersions` · `GetUsageAllocation` · and all five
attribute operations

A UI gap, not a design position. The portal was built around the common path
and these were never given controls — though every one of them is runnable
today from the KMIP Client page. Three groups stand out as candidates:

* **The five attribute operations** (`AddAttribute`, `ModifyAttribute`,
  `DeleteAttribute`, `SetAttribute`, `AdjustAttribute`) are the clearest
  omission. The Inspect panel *reads* KMIP attributes but offers no way to
  change one — an asymmetry that is hard to defend.
* **`Archive` and `Recover`** are ordinary lifecycle actions and would sit
  naturally beside the existing Activate, Revoke and Destroy buttons.
* **`Register` and `Import`** bring external key material *in*, so they need
  upload handling and a security review. Closer in character to the second
  group than the fourth.

So of the 35: roughly **16 by design, 19 by omission**. Anything in the last
list can be given a screen without argument; anything in the first two should
not be without one.

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
setup backup               REM both volumes -> C:\Internal_Idemia\Docker_bkup
setup backup D:\elsewhere  REM ...or somewhere else
setup backups              REM show what is there
setup restore              REM restore (stack must be down)
```

Stop the stack first (`setup down`). A copy taken while PostgreSQL is writing
may not restore cleanly; the script warns but does not refuse, because a torn
backup still beats none.

**The database and the HSM token are one unit.** Objects reference key material
by `CKA_ID`, and secret blobs are encrypted under a master key that lives on the
token. A database restored beside a *different* token is not a degraded backup —
it is unreadable. That is why `setup backup` always copies both volumes
together, and why restoring recovers a *usable* key rather than merely a listed
one.

> `kmip-admin backup` is **not** the tool for this deployment. It uses SQLite's
> online backup API and this store is PostgreSQL; it fails with an explanation
> rather than producing a broken archive. Use `setup backup`, or `pg_dump`
> together with a copy of the token volume.

> Volumes belong to the engine that created them. If you switch between Rancher
> Desktop and Docker Desktop, the other engine's stack starts empty — the data
> is not lost, it is simply under the engine you were using before. `setup
> backup` under one and `setup restore` under the other is the way to move it.

### Starting from scratch

```bat
setup destroy
```

Destroys the database **and the HSM token**, so every key is gone. The next
`up` recreates the bootstrap administrator. Run `setup backup` first if you
might want any of it back.

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

Expect **816 passed**, run live against a real SoftHSM2 token. Fewer than that
on a distribution SoftHSM2 is an environment difference, not a defect —
[SoftHSM2 setup](cryptohub_lite/docs/SOFTHSM2_SETUP.md) explains exactly why.

### Container engines

**Rancher Desktop is what this is developed against**, and Docker Desktop works
identically. Nothing here is specific to either: the images are plain OCI and
the compose file uses no vendor extensions.

`setup` resolves the engine at run time rather than assuming `docker`, so the
same commands work on both:

| Setup | Engine used | Compose |
|---|---|---|
| Rancher Desktop, `moby (dockerd)` — **recommended** | `docker` | `docker compose` |
| Docker Desktop | `docker` | `docker compose` |
| Rancher Desktop, `containerd` | `nerdctl` | `nerdctl compose` |

`moby` is worth preferring on Rancher: it is the same daemon Docker Desktop
uses, so every `docker …` command in this README is literally correct. The
`containerd` setting works too and `setup` will find it, but the raw commands
then need `nerdctl`. Force a choice with `CHL_ENGINE=nerdctl` if both are live.

**Kubernetes can be switched off** — and should be, unless you need it for
something else. The stack is five containers on one network and never touches
it; disabling it makes Rancher start faster and use noticeably less memory.

```bash
rdctl list-settings                   # confirm "containerEngine": {"name": "moby"}
setup status                          # confirms the engine and the stack at once
```

> **Volumes belong to the engine that created them.** Switching between Rancher
> and Docker Desktop makes the stack look empty — the data is not gone, it is
> under the other engine. Move it with `setup backup` on one and `setup restore`
> on the other.

#### When the engine wedges

Rancher Desktop on Windows intermittently loses the Hyper-V (AF_VSOCK) channel
between the host and the WSL VM. Two symptoms, one fault:

* every command fails because `\\.\pipe\docker_engine` has no listener — the
  *Win32 socket proxy* crash-loops in `background.log`;
* a command dies mid-flight with
  `failed to connect to the backend: timed out dialing Hyper-V socket`.

It is Rancher's network tunnel (`host-switch` ↔ `vm-switch`), not this stack.
Rancher 1.24 removed the setting that used to disable the tunnel, and neither
`rdctl set` nor the settings file offers a replacement, so it cannot be
configured away. Two things worth trying if it happens often: **Preferences →
Application → Administrative Access**, and an antivirus exclusion for
`%LOCALAPPDATA%\Programs\Rancher Desktop` — a networking helper exiting with
status 1 immediately and repeatedly is a common signature of endpoint security
on a managed machine.

`setup` handles it two ways:

* **`setup up` retries** up to three times. `compose up -d` is idempotent, so a
  half-finished attempt needs no cleanup.
* **The engine is revived automatically** when it is unreachable — `rdctl
  shutdown`, cycle WSL, relaunch, wait — because restarting the app alone does
  not clear it.

> **Auto-heal refuses while containers are running**, and that guard matters.
> Cycling WSL under a live PostgreSQL and SoftHSM2 token once brought the stack
> back against different storage, with an empty database and a freshly
> initialised token. If you hit a *partial* wedge — engine answering some calls,
> stack still up — `setup` tells you to `setup backup` and `setup down` first
> rather than doing it for you.

| Variable | Effect |
|---|---|
| `CHL_NO_AUTOHEAL=1` | Never cycle the VM; just print the recovery steps |
| `CHL_FORCE_HEAL=1` | Heal even with containers running — only if the volumes are expendable |
| `CHL_ENGINE=docker`&nbsp;\|&nbsp;`nerdctl` | Force one engine when both are present |

#### Doing it by hand

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
| API | FastAPI (Python 3.11) | Authentication, RBAC, audit, aggregation — **no KMIP** |
| KMIP client | `chl-client-app`, FastAPI | The only service that speaks KMIP. Stateless: REST in, TTLV out |
| Engine | `kmip_pkcs11` | KMIP 2.1 — 41 of 53 operations |
| Store | PostgreSQL 16 | KMIP metadata + portal data, one database |
| HSM | SoftHSM2 (source build) | Key storage and cryptography |
| Client app | `test_app.client` + `core.ttlv` | Drives all 41 operations over real TTLV |

```
                       ┌──► chl-api :8000 ───────────────► PostgreSQL
                       │    accounts, roles, audit,        (portal data)
Browser ──► chl-portal ┤    dashboard — no KMIP
            :8081      │
                       └──► chl-client-app :8002 ──TTLV/5696──┐
                            the only KMIP client              ▼
KMIP client ──────────────────TTLV/5696──────────────► chl-kmip :5696
                                                              │
                                                       kmip_pkcs11
                                                      ┌───────┴───────┐
                                                 PostgreSQL     PKCS#11 / HSM
```

**Every managed-object operation takes one path.** Generating a key from the
portal and creating one from a third-party client produce the same request, the
same per-request authentication, and the same entry in the hash-chained audit
log. `chl-api` never opens a socket to 5696.

The one thing still on the old route: the portal's *reads* — the Keys and KMIP
tables — are served by `chl-api` reading the metadata store directly. Those are
the last endpoints not yet on the KMIP path.

**KMIP logic lives in `kmip_pkcs11/` and nowhere else.** `chl-client-app`
imports only the *client* side of it — `test_app.client` and `core.ttlv` — and
speaks to the engine over the wire like any other client. The PHP tier calls
REST and holds no cryptographic or KMIP knowledge at all. The shim is the only
module that imports `pkcs11`, so swapping in a different — for example
FIPS-validated — token needs no change above it.

An editable diagram of all of this is at
[`cryptohub_lite/docs/architecture.drawio`](cryptohub_lite/docs/architecture.drawio)
— open it at [app.diagrams.net](https://app.diagrams.net) or with the *Draw.io
Integration* extension in VS Code. Three tabs:

| Tab | For | Shows |
|---|---|---|
| **Overview (non-technical)** | briefings, management | What the product is, in plain words — no protocols, no container names |
| **Components** | engineers | Containers, the three routes in, and where REST becomes TTLV |
| **Technology stack** | engineers | One row per layer, plus the toolchain and local paths |

### What each part is responsible for

Four pieces do most of the work, and they are easy to conflate. They answer
four different questions.

```
Request ─► OperationDispatcher ─► handler ─┬─► MetadataStore ─► db.py ─► PostgreSQL
           (who are you,                   │                            facts, audit
            may you, record it)            │
                                           └─► PKCS11Shim ─► SoftHSM2 token
                                                             the secret itself
```

| Part | Answers | Source |
|---|---|---|
| `OperationDispatcher` | *Are you allowed, and is it recorded?* | [`kmip_pkcs11/server/`](kmip_pkcs11/server/) |
| `MetadataStore` + `db.py` | *What do we know about this key?* | [`metadata/store.py`](kmip_pkcs11/metadata/store.py), [`metadata/db.py`](kmip_pkcs11/metadata/db.py) |
| PostgreSQL | Stores that knowledge durably — and never the secret | container `chl-postgres` |
| SoftHSM2 token | *Holds the secret, and does the maths so it never has to leave* | volume `chl_tokens` |

#### SoftHSM2 token — holds the secrets

Key *material* lives here: the actual bytes of an AES or RSA key. It is a
software stand-in for a hardware security module, and it enforces the rule that
matters — **a key created inside it never comes out**. Plaintext goes in,
ciphertext comes out; the key itself never travels.

This is why `Get` on a key generated by this system refuses with
`NotExtractable (23)`. That is the product working, not failing. In production
the token is swapped for a real HSM, and because
[`kmip_pkcs11/pkcs11_shim/shim.py`](kmip_pkcs11/pkcs11_shim/shim.py) is the only module that imports
`pkcs11`, that swap touches nothing above it.

#### PostgreSQL — holds everything *about* the keys

Names, algorithms, sizes, states, ownership, grants, and the audit trail. A
stolen copy of this database reveals that a key called `payments-2026` exists
and is Active — and not one byte of the key.

**The one exception**, because it has bitten us: a few KMIP object types
(`SecretData`, `OpaqueObject`, split-key shares) are raw payloads with no
PKCS#11 object behind them, so their bytes *do* land in `kmip_objects`. Those
are enveloped under a master key that lives on the token — see
[Key material at rest](#key-material-at-rest). The database alone is still
useless, but both containers that open it must agree on that encryption, or the
one without the master key cannot read what the other wrote.

#### MetadataStore + db.py — the only way to reach PostgreSQL

`MetadataStore` is the single gate to the database. Nothing else issues SQL. It
owns the schema, transactions, the envelope encryption above, and the
hash-chaining of the audit log.

`db.py` sits underneath it as the **dialect layer**. The engine was written
against SQLite; this deployment runs PostgreSQL. Rather than maintain two
schemas that drift, `db.translate_ddl()` *derives* the PostgreSQL schema from
the engine's own `store.SCHEMA` and raises `UnsupportedDDL` on any construct it
does not recognise. A column added upstream either translates or fails loudly —
it never silently diverges. Never hand-write that schema.

#### OperationDispatcher — the checkpoint every KMIP request passes

It sits between the network and the 41 handlers and does the cross-cutting
work: authenticate *this request* against `kmip_identities`, check the identity
may perform this operation on this object, enforce dual control where
configured, and write the hash-chained audit entry.

**Nothing bypasses it any more.** The portal's own pages used to: clicking
*Generate key* had the API call the handler as a Python function, so the key
was created with no per-request authentication and left no entry in the
hash-chained log — invisible to an auditor verifying that chain, while an
identical key from a KMIP client was not.

Those pages now go through `chl-client-app` like any other client, and the
six REST endpoints that allowed the shortcut have been removed rather than
deprecated: an unused bypass is still a bypass.

#### Why both routes produce the same object

Not because one calls the other. Because both write the same PostgreSQL rows
and use the same token. **That shared state is the whole of the coupling** —
which is also its sharp edge: two containers sharing one database have to agree
on how it is encrypted, or one of them cannot read what the other wrote.

### KMIP is not the REST API

Worth stating plainly, because the endpoint names invite the opposite
conclusion. Three ports, and only one of them carries KMIP:

| | Port | Protocol | Goes through |
|---|---|---|---|
| **KMIP** | `5696` | **TTLV binary frames over TCP/TLS** — the OASIS wire format, not HTTP at all | `KMIPServer` → `OperationDispatcher` → handlers |
| **KMIP client service** | `8002` | JSON over HTTP in, TTLV out | `chl-client-app` → **5696**, as a real client |
| **REST API** | `8000` | Ordinary JSON over HTTP, with a JWT | `chl-api` → portal data. Reads KMIP metadata; performs no KMIP operation |

So `http://localhost:8000/api/kmip/objects` is **not** KMIP. It is a JSON
endpoint named after the objects it returns; a KMIP client cannot talk to it,
and `curl` cannot talk to 5696. A real client connects to 5696 and sends
encoded TTLV, as in [Connecting a KMIP client](#connecting-a-kmip-client).

What changed, and why it matters: every operation that *does* something to a
managed object now reaches the engine the same way — through the dispatcher,
authenticated per request, into `kmip_audit`. The portal is a KMIP client with
a friendlier face, not a privileged insider. A key generated from the Keys page
and one created by `svc-payments` are indistinguishable in the audit trail.

`chl-api` still answers `GET /api/keys` and `GET /api/kmip/objects` by reading
the metadata store, because listing objects for a table needs no protocol round
trip and would otherwise write an audit entry per row on every page view. Those
reads are the remaining exception, and the only one.

### How REST becomes TTLV

This is the path every managed-object operation takes — whether you clicked
*Generate key* on the Keys page or drove `Create` from the KMIP Client page. A
browser form goes out as REST, and `chl-client-app` turns it into genuine TTLV
on 5696. This is the sequence, and where each step lives.

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant P as chl-portal<br/>inc/kmip.php
    participant A as chl-client-app<br/>app/kmip_client.py
    participant C as KMIPClient<br/>kmip_pkcs11.test_app.client
    participant T as TTLV codec<br/>kmip_pkcs11.core.ttlv
    participant K as chl-kmip:5696<br/>KMIPServer

    B->>P: POST form (operation, args, credential)
    P->>A: POST /api/kmip/client/execute<br/>JSON over HTTP + Bearer JWT
    Note over A: still REST here
    A->>A: _coerce() each field to the type<br/>the client method declares
    A->>C: getattr(client, method)(**kwargs)
    C->>T: encode_enumeration / encode_integer /<br/>encode_text_string / encode_structure
    T-->>C: TTLV bytes (tag·type·length·value)
    C->>C: _build_batch_request()<br/>adds ProtocolVersion + Credential + BatchItem
    C->>K: socket.sendall(request)
    Note over C,K: no longer HTTP — binary TTLV over TCP
    K->>K: OperationDispatcher → handler<br/>per-request auth, hash-chained audit
    K-->>C: TTLV ResponseMessage
    C->>T: decode_one(raw)
    T-->>C: TTLVItem tree
    C-->>A: Python return value
    A->>A: _jsonable() + _readable()<br/>decode enums against the engine's own
    A-->>P: JSON result + both wire hops
    P-->>B: rendered result, decoded view, and the frames
```

Only steps 1 to 3 are ours. Everything from `KMIPClient` down is `kmip_pkcs11`
— the same modules the test suite and any third-party Python client import — so
nothing about the encoding is specific to this portal. That is the whole point
of the page: the claim is checkable rather than asserted.

| # | Source | Package | Does |
|---|---|---|---|
| 1 | [`portal/inc/kmip.php`](cryptohub_lite/portal/inc/kmip.php) — `kmip_run()` | portal | The single place the portal speaks KMIP. Every page goes through it |
| 2 | [`api/app/client_app_main.py`](cryptohub_lite/api/app/client_app_main.py) — `execute()` | client-app | REST endpoint on `:8002`, JWT check. Stateless |
| 3 | [`api/app/kmip_client.py`](cryptohub_lite/api/app/kmip_client.py) — `execute()`, `_coerce()` | client-app | Bridges JSON to the client's signature. **Encodes nothing** |
| 4 | [`kmip_pkcs11/test_app/client.py`](kmip_pkcs11/test_app/client.py) — e.g. `create()` | engine | Builds the operation payload from KMIP attributes |
| 5 | `client.py` — `_build_batch_request()` | engine | Wraps it: ProtocolVersion, Credential, BatchItem |
| 6 | [`kmip_pkcs11/core/ttlv.py`](kmip_pkcs11/core/ttlv.py) — `encode_item()` | engine | **The actual bytes.** Tag, type, length, value, padded to 8 |
| 7 | `client.py` — `_send()` / `_recv()` | engine | `socket.sendall()` to 5696 and back |
| 8 | `core/ttlv.py` — `decode_one()` | engine | Parses the response into a `TTLVItem` tree |

Every encoder bottoms out in nine lines:

```python
def encode_item(tag: int, type_: int, value_bytes: bytes) -> bytes:
    """Encode a single TTLV item (header + padded value)."""
    length = len(value_bytes)
    padded = value_bytes + b'\x00' * (_pad8(length) - length)
    # 3-byte tag + 1-byte type packed as big-endian uint32
    header = struct.pack('>I', (tag << 8) | (type_ & 0xFF))
    header += struct.pack('>I', length)   # 4-byte length
    return header + padded
```

#### What actually goes on the wire

`Create(algorithm=3, length=256, usage_mask=12, name="ttlv-demo")` submitted
through the portal produces 440 bytes out and 184 back. Decoded:

```
RequestMessage             Structure
  RequestHeader              Structure
    ProtocolVersion            Structure
      ProtocolVersionMajor       Integer      2
      ProtocolVersionMinor       Integer      1
    Authentication             Structure
      Credential                 Structure
        CredentialType             Enumeration  1
        CredentialValue            Structure
          Username                   TextString   'admin'
          Password                   TextString   '********'
    BatchCount                 Integer      1
  BatchItem                  Structure
    Operation                  Enumeration  1          <- Create
    UniqueBatchItemID          ByteString   b'\x00\x00\x00\x01'
    RequestPayload             Structure
      ObjectType                 Enumeration  2        <- SymmetricKey
      TemplateAttribute          Structure
        Attribute … 'Cryptographic Algorithm'   Enumeration  3
        Attribute … 'Cryptographic Length'      Integer      256
        Attribute … 'Cryptographic Usage Mask'  Integer      12
        Attribute … 'Name' -> NameValue         TextString   'ttlv-demo'
```

Two things this makes plain. The credential travels in **every** request rather
than being established once at connect — which is why the page asks for a
password each time. And the JSON field `"algorithm": 3` is carried as
`Enumeration 3`: the numbers are the protocol, which is why the page decodes
them back to `AES (3)` and `Encrypt, Decrypt (12)` for display.

The page shows both hops live, under *What actually happened on the network*.

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
| **`kmip-admin backup` does not work against PostgreSQL** | It uses SQLite's online backup API. Use `setup backup` or `pg_dump` plus the token volume. |
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
| [Architecture diagram](cryptohub_lite/docs/architecture.drawio) | Editable draw.io source, two tabs — **Components** (both request paths, storage) and **Technology stack** (layers, versions, toolchain, local paths) |

### Generated engine documents

Six Word documents cover the KMIP engine in depth. Each is produced by the
script beside it, so regenerating is the way to update one — editing the `.docx`
by hand puts it out of step with the generator that will overwrite it.

| Document | Generated by | Covers |
|---|---|---|
| `KMIP_PKCS11_Feature_Specification.docx` | `generate_feature_spec.py` | Every supported feature and all 41 operations, with request/response fields and a worked example for each |
| `KMIP_PKCS11_Install_Test_Guide.docx` | `generate_install_guide.py` | Bare machine to a running TLS-protected server: prerequisites, SoftHSM2, tokens, TLS, configuration, systemd, containers, upgrades, backup, hardening, troubleshooting |
| `KMIP_PKCS11_Design_Document.docx` | `generate_kmip_design_doc.py` | Architecture and design rationale, including designs that were rejected and why |
| `KMIP_PKCS11_Project_Documentation.docx` | `generate_docs.py` | Module-by-module reference and the full test specification |
| `KMIP_PKCS11_Phase_Report.docx` | `generate_phase_report.py` | How the system reached its current state, phase by phase |
| `KMIP_PKCS11_KMS_Gap_Matrix.docx` | `generate_kms_gap_matrix.py` | 74 features a high-end commercial KMS is expected to have, whether this project covers them, and the route for every gap — including the 19 that cannot be closed by writing more KMIP |

Generating them needs `python-docx` (and `matplotlib` for the design document):

```bash
pip install python-docx matplotlib

for g in generate_feature_spec generate_install_guide generate_kmip_design_doc \
         generate_docs generate_phase_report generate_kms_gap_matrix; do
  python "$g.py"
done
```

The gap matrix is the one to read before promising a customer a feature: it is
explicit that 19 gaps are **outside KMIP** — identity federation, tenancy, REST,
cloud key import and SIEM export have no wire representation, so they are not
waiting on more protocol work.

These describe the engine as a standalone service — a config file, the
`kmip-server` CLI, systemd. Read them for the protocol and the engine's own
behaviour; for how this stack actually runs it, the sections above are the
authority, since they differ (see [Health and metrics](#health-and-metrics)).

### References

- [OASIS KMIP Specification v2.1](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html)
- [OASIS KMIP Test Cases v2.1](https://docs.oasis-open.org/kmip/kmip-testcases/v2.1/)
- [PKCS #11 Specification v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.0/)
- [SoftHSM2](https://github.com/opendnssec/SoftHSMv2)
- [python-pkcs11](https://python-pkcs11.readthedocs.io/)
