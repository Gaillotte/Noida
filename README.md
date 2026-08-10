# IDEMIA CryptoHub Lite

A web-based cryptographic management platform built on a KMIP 2.1 server that
delegates all key storage and cryptography to a PKCS#11 HSM.

Manage KMIP objects, PKCS#11 tokens, certificates, keys, users and audit
records through an IDEMIA-branded portal — or drive the same objects over the
KMIP wire protocol. Both are views of one system, not two systems kept in step.

---

## Quick start

**Prerequisite:** Docker Desktop, running. Nothing else — Python, PostgreSQL
and SoftHSM2 are all provided by the images.

```bash
git clone <repo> && cd Kmip
./cryptohub_lite/scripts/setup.sh          # Windows: cryptohub_lite\scripts\setup.cmd
```

In VS Code, `Ctrl+Shift+B` runs the same thing.

| Service | Address | Credentials |
|---|---|---|
| **Portal** | http://localhost:8081 | `admin` / `admin` |
| REST API | http://localhost:8000/api/docs | bearer token from `/api/auth/login` |
| KMIP | `localhost:5696` | any portal account |
| PostgreSQL | `localhost:5432` | `cryptohub` / `devpass` |

**Change the bootstrap password first** — Administration → Users. It is created
only when the user table is empty, so it cannot silently reappear, but it
starts as a published default.

> The first build takes several minutes: SoftHSM2 is **compiled from source**,
> deliberately. See [SoftHSM2 setup](cryptohub_lite/docs/SOFTHSM2_SETUP.md).

---

## Code structure

```
Kmip/
├── kmip_pkcs11/                  KMIP engine — the authoritative implementation
│   ├── core/                     TTLV codec, enums, exceptions
│   ├── operations/               41 KMIP operations, one module each
│   │   └── dispatcher.py         routes every operation; audit hook lives here
│   ├── pkcs11_shim/shim.py       PKCS#11 binding — one session behind one lock
│   ├── metadata/
│   │   ├── store.py              KMIP metadata persistence
│   │   └── db.py                 SQLite / PostgreSQL dialect layer
│   ├── lifecycle/                state machine, access control
│   ├── server/server.py          KMIP TCP listener
│   └── tests/                    624 tests, run against a live token
│
├── cryptohub_lite/               the management platform
│   ├── api/app/
│   │   ├── main.py               FastAPI routes
│   │   ├── security.py           JWT, five roles, capability model
│   │   ├── portal_store.py       users and audit trail
│   │   ├── kmip_service.py       façade over the engine (no KMIP logic)
│   │   ├── kmip_identity.py      portal identity + roles for KMIP clients
│   │   └── kmip_server_main.py   runnable entry point for the KMIP server
│   ├── portal/
│   │   ├── public/               pages: dashboard, keys, certificates,
│   │   │                         KMIP, PKCS#11, audit, administration
│   │   ├── inc/                  API client, layout, session handling
│   │   └── assets/css/           IDEMIA design tokens
│   ├── docker/                   Dockerfiles + entrypoint
│   ├── docs/                     guides (listed below)
│   ├── scripts/                  setup.sh / setup.cmd
│   └── tools/                    SQLite → PostgreSQL migration
│
├── .vscode/                      launch, tasks, settings, extensions
└── PHASE1_ASSESSMENT.md          architecture and production-readiness review
```

### The rule that keeps it maintainable

**KMIP logic lives in `kmip_pkcs11/` and nowhere else.**

The REST API calls the engine's own operation handlers in-process; the PHP
tier calls the REST API and holds no cryptographic or KMIP knowledge at all.
If a lifecycle rule seems to belong in `cryptohub_lite/`, it belongs in the
engine instead — otherwise the portal and KMIP clients will eventually
disagree about what an operation does.

```
Browser ──HTTPS──► PHP portal ──REST+JWT──► FastAPI ──in-process──► kmip_pkcs11
                                                │                        │
KMIP client ──TTLV/5696──────────────────► KMIP server ──────────────────┘
                                                │                        │
                                          PostgreSQL              PKCS#11 / HSM
```

---

## Architecture at a glance

| Layer | Technology | Responsibility |
|---|---|---|
| Portal | PHP 8.3, Bootstrap 5, Chart.js | Presentation only |
| API | FastAPI (Python 3.11) | Authentication, RBAC, audit, aggregation |
| Engine | `kmip_pkcs11` | KMIP 2.1 — 41 of 53 operations |
| Store | PostgreSQL 16 | KMIP metadata + portal data, one database |
| HSM | SoftHSM2 2.7.0 (source build) | Key storage and cryptography |

Four containers: `chl-postgres`, `chl-api`, `chl-kmip`, `chl-portal`. The API
and KMIP services share one image, one token and one database — which is why a
key created over KMIP appears in the portal immediately.

---

## Features

**Dashboard** — key, certificate, KMIP and PKCS#11 object counts, HSM status,
audit volume, system health, with state and algorithm charts.

**Key Explorer** — symmetric, RSA, ECC and certificates; search, filter, CSV
export.

**KMIP Explorer** — managed objects with types, states and attributes. Create,
Activate, Revoke, Re-Key and Destroy from the interface; all 41 operations
available over the wire.

**PKCS#11 Explorer** — slots, tokens and objects with raw `CKA_*` attributes
exactly as the token reports them. Secret-bearing attributes are never
requested.

**Audit** — user, timestamp, source IP, action, object, provider and result for
every portal action *and* every KMIP operation, including failed
authentications. Export to CSV, Excel or JSON.

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

## Running and operating

```bash
C=cryptohub_lite/docker-compose.yml

docker compose -f $C up -d --build     # start / rebuild
docker compose -f $C ps                # status
docker compose -f $C logs -f api       # follow logs
docker compose -f $C down              # stop
docker compose -f $C down -v           # stop and DESTROY all data and keys
```

The same actions are bound as VS Code tasks.

### Tests

```bash
docker compose -f cryptohub_lite/docker-compose.yml exec api \
    sh -c 'cd /app && python -m pytest kmip_pkcs11/tests -q'
```

Expect **624 passed**. Fewer than that on a distribution SoftHSM2 is an
environment difference, not a defect —
[SoftHSM2 setup](cryptohub_lite/docs/SOFTHSM2_SETUP.md) explains exactly why.

### Connecting a KMIP client

Clients authenticate with a portal account — there is no separate client
credential store:

```python
from kmip_pkcs11.test_app.client import KMIPClient
from kmip_pkcs11.core.enums import CryptographicAlgorithm

client = KMIPClient(host="localhost", port=5696,
                    username="svc-payments", password="...")
client.connect()
uid = client.create(algorithm=CryptographicAlgorithm.AES, length=256,
                    name="payments-2026")
client.activate(uid)
```

Create one account per client and give it the least role that works — usually
**Operator**. Disabling the account revokes access immediately.

---

## Configuration

Set in `cryptohub_lite/docker-compose.yml` or the environment.

| Variable | Default | Notes |
|---|---|---|
| `POSTGRES_PASSWORD` | `devpass` | |
| `JWT_SECRET` | `dev-only-change-me` | **Change for production** |
| `BOOTSTRAP_ADMIN` / `BOOTSTRAP_PASSWORD` | `admin` / `admin` | Used only when no users exist |
| `PKCS11_TOKEN` / `PKCS11_PIN` | `CryptoHubLite` / `1234` | HSM credential only |
| `KMIP_HOST_PORT` | `5696` | Change if another KMIP server holds the port |
| `KMIP_ALLOW_PLAINTEXT` | `true` (dev) | **Remove for production** |
| `KMIP_TLS_CERT` / `KMIP_TLS_KEY` | — | Required unless plaintext is permitted |
| `KMIP_REQUIRE_CLIENT_CERT` | `false` | mTLS |
| `KMIP_ALLOW_PIN_FALLBACK` | `false` | Migration only; warns on every use |

**The KMIP listener refuses to start without TLS** unless
`KMIP_ALLOW_PLAINTEXT=true` is set explicitly. Removing that line is the single
most important production change.

---

## Documentation

| Document | Covers |
|---|---|
| [Developer onboarding](cryptohub_lite/docs/DEVELOPER_ONBOARDING.md) | Clone to running, layout, debugging, common problems |
| [Administrator guide](cryptohub_lite/docs/ADMINISTRATOR_GUIDE.md) | Roles, audit, lifecycle, backup, hardening |
| [PKCS#11 integration](cryptohub_lite/docs/PKCS11_INTEGRATION.md) | The shim, concurrency, moving to a vendor HSM |
| [SoftHSM2 setup](cryptohub_lite/docs/SOFTHSM2_SETUP.md) | Why it is built from source; token management |
| [Database schema](cryptohub_lite/docs/SCHEMA.md) | Every table, and SQLite → PostgreSQL migration |
| [Phase 1 assessment](PHASE1_ASSESSMENT.md) | Architecture, production readiness, security review |
| [KMIP engine reference](README_KMIP.md) | The engine's own documentation |

---

## Known limitations

Stated plainly rather than discovered later:

* **Concurrency is capped.** All HSM work is serialised through one PKCS#11
  session. A session pool was built, load-tested and rejected — `python-pkcs11`
  calls `C_Initialize(NULL)`, so the library's own thread safety is never
  enabled and separate sessions crash the binding. Lifting this needs a
  different binding or a multi-process pool.
* **No high availability** — single API process, single KMIP process, single
  token.
* **No metadata/HSM reconciliation** — divergence between the database and the
  token is not detected automatically.
* **Batch operations are not atomic** — a partial batch does not roll back.
* **No cryptoperiod enforcement** — rotation is a manual action.
* **The audit trail is append-only but not tamper-evident** — anyone with
  direct database access can alter it.
* **SoftHSM2 is not FIPS 140-2/3 or Common Criteria validated.** It is correct
  for development; production needs validated hardware, which is a
  configuration change.

---

## Migrating an existing SQLite store

```bash
python cryptohub_lite/tools/migrate_sqlite_to_postgres.py \
    --sqlite kmip_metadata.db \
    --postgres postgresql://cryptohub:devpass@localhost:5432/cryptohub \
    --dry-run
```

Preserves KMIP Unique Identifiers, refuses a non-empty target without
`--force`, and verifies row counts afterwards.
