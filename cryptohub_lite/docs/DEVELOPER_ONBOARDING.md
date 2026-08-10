# Developer Onboarding

Getting from a clone to a working CryptoHub Lite.

## Prerequisites

| Tool | Version | Why |
|---|---|---|
| Docker Desktop | 4.x | Everything runs in containers; nothing else is required to *run* the stack |
| VS Code | current | Workspace config is committed |
| Git | any | |

Python, PostgreSQL and SoftHSM2 are **not** prerequisites — the images provide
them. You only need Python locally if you want to run the KMIP engine's test
suite outside Docker.

## Five steps

```bash
git clone <repo> && cd Kmip
code .                       # VS Code offers the recommended extensions
```

Then either run the task **Setup: bootstrap everything** (`Ctrl+Shift+B`), or:

```bash
./cryptohub_lite/scripts/setup.sh      # Windows: cryptohub_lite\scripts\setup.cmd
```

The script checks Docker is running, builds the images, starts the stack and
waits until the API actually answers — not merely until the container starts.

| Service | URL | Credentials |
|---|---|---|
| Portal | http://localhost:8081 | `admin` / `admin` |
| REST API docs | http://localhost:8000/api/docs | bearer token from `/api/auth/login` |
| KMIP | `localhost:5697` | a portal account |
| PostgreSQL | `localhost:5432` | `cryptohub` / `devpass` |

**Change the bootstrap password immediately** — Administration → Users. It is
created only when the user table is empty, so it cannot silently reappear, but
it starts as a published default.

> The first build takes several minutes because **SoftHSM2 is compiled from
> source**. That is deliberate, not an oversight — see
> [SOFTHSM2_SETUP.md](SOFTHSM2_SETUP.md).

## Layout

```
kmip_pkcs11/           the existing KMIP engine — authoritative, minimally touched
  core/                TTLV codec, enums, exceptions
  operations/          41 KMIP operations, one module each
  pkcs11_shim/         PKCS#11 binding, single locked session
  metadata/            store.py (KMIP metadata) + db.py (SQLite/PostgreSQL dialects)
  lifecycle/           state machine, access control
  tests/               624 tests, run against a live token

cryptohub_lite/        everything new
  api/app/             FastAPI: auth, RBAC, audit, KMIP façade
  portal/              PHP 8 + Bootstrap 5 + Chart.js
  docker/              Dockerfiles and entrypoint
  tools/               SQLite -> PostgreSQL migration
  docs/                these guides
```

### The rule that matters

**KMIP logic lives in `kmip_pkcs11/` and nowhere else.** The API calls the
engine's own operation handlers in-process; the PHP tier calls the API. If you
find yourself about to implement a lifecycle rule in `cryptohub_lite/`, it
belongs in the engine instead — otherwise the REST API and KMIP clients will
eventually disagree about what an operation does.

## Everyday tasks

Bound as VS Code tasks, or run directly:

```bash
docker compose -f cryptohub_lite/docker-compose.yml up -d --build   # rebuild
docker compose -f cryptohub_lite/docker-compose.yml logs -f api     # follow logs
docker compose -f cryptohub_lite/docker-compose.yml down            # stop
docker compose -f cryptohub_lite/docker-compose.yml down -v         # stop and wipe data
```

## Debugging

`.vscode/launch.json` has three configurations. **API (FastAPI, reload)** and
**KMIP server** run on the host against the containerised database and token,
so breakpoints work without rebuilding an image. Stop the corresponding
container first, or they will contend for the port.

## Running the engine test suite

```bash
docker compose -f cryptohub_lite/docker-compose.yml exec api python -m pytest /app -q
```

Expect **624 tests**. Running them against a distribution SoftHSM2 instead of
the source build produces 8 EC failures — an environment difference, not a
defect. Again: [SOFTHSM2_SETUP.md](SOFTHSM2_SETUP.md).

## Where things are stored

Both KMIP metadata and portal data share one PostgreSQL database, so one
backup covers the system. Schema: [SCHEMA.md](SCHEMA.md).

To bring an existing SQLite store across:

```bash
python cryptohub_lite/tools/migrate_sqlite_to_postgres.py \
    --sqlite kmip_metadata.db \
    --postgres postgresql://cryptohub:devpass@localhost:5432/cryptohub \
    --dry-run
```

## Common problems

**Port already allocated (5696).** Another KMIP server is running. Lite
publishes on **5697** by default for this reason; override with
`KMIP_HOST_PORT`.

**KMIP container exits immediately.** It now refuses to start without TLS
unless plaintext is named explicitly. Compose sets `KMIP_ALLOW_PLAINTEXT=true`
for development; remove it and supply certificates for anything else.

**HSM Status shows Offline.** `docker compose logs api` — usually the token
was not initialised. The entrypoint creates it idempotently on start.

**Portal shows "Cannot reach the CryptoHub API".** The API container is down
or still starting. `docker compose ps` and check `api` is *healthy*, not just
*up*.
