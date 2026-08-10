# IDEMIA CryptoHub Lite — Phase 1 Assessment

Repository review, design-document review, architecture assessment, production
readiness and security assessment for the existing Python KMIP/PKCS#11
implementation at `C:\dev\Kmip`.

**Date:** 10 August 2026
**Reviewed:** `kmip_pkcs11/` (67 Python modules, ~13,700 lines),
`KMIP_PKCS11_Design_Document.docx` (v1.0), `README_KMIP.md`, `setup.py`
**Method:** static review of all modules, full extraction of the design
document, and a **live execution of the test suite** against SoftHSM2 in a
clean container.

---

## 1. Executive summary

The existing implementation is **substantially better than a prototype** and is
a sound basis for CryptoHub Lite. It is a real KMIP 2.1 server: 41 of 53
operations, a genuine TTLV codec, a lifecycle state machine, and 624 automated
tests that execute against a live HSM token rather than mocks.

The design document is unusually honest — it documents what was built, what was
rejected and why, and what is still missing. It is a reliable reference and I
have treated it as the architectural baseline, as instructed.

Three findings materially affect the Phase 2 plan:

1. **Authentication does not establish identity** (Section 6.1). Any username
   presented with the shared token PIN is accepted *as that username*. Because
   `admin` is a role attached to an identity, any caller who knows the PIN can
   claim an admin identity and reach every object. The three-tier access
   control model is sound in design but rests on an unauthenticated claim.
2. **Three assumptions in the brief do not hold.** There is no PostgreSQL
   schema (the store is SQLite), no Docker artifacts, and no existing REST API.
   Each is new build, not reuse.
3. **Concurrency is capped by design.** Every PKCS#11 call is serialized
   through one session behind a global lock. This is documented as permanent,
   and it conflicts directly with the multi-user scalability requirement.

None of these blocks Phase 2. All three change what Phase 2 must contain.

---

## 2. What was verified, not assumed

| Claim | Source | Verified? |
|---|---|---|
| 624 automated tests | `README_KMIP.md` | **Yes** — 624 collected (616 passed, 8 failed) |
| 100% pass rate | `README_KMIP.md` | **Only on a source-built SoftHSM2** (see 2.1) |
| 41 of 53 KMIP operations | Design doc §14.1 | **Yes** — 41 dispatcher entries, 42 operation modules |
| SQLite metadata store | Design doc §11 | **Yes** — `sqlite3`, WAL, `threading.local` |
| No PostgreSQL | (brief assumed one) | **Confirmed absent** — no `postgres`/`psycopg` anywhere |
| Single locked PKCS#11 session | Design doc §13 | **Yes** — `threading.RLock`, `@_synchronized` |
| TLS optional, off by default | Design doc §9 | **Yes** — `_wrap_tls()` returns the raw socket if no cert |
| No audit logging | Design doc §13 | **Confirmed** — no audit code outside tests |
| No Docker artifacts | (brief assumed maybe) | **Confirmed absent** |
| No REST/HTTP API | (brief assumed maybe) | **Confirmed absent** — raw TCP TTLV only |

### 2.1 The test suite is real, and its environment is fragile

Executed in a clean `python:3.11-slim` container with SoftHSM2 and
python-pkcs11 0.9.5:

```
616 passed, 8 failed in 57.90s
```

All 8 failures are EC signing and curve-selection tests. They fail because
SoftHSM2 **2.6.1 does not implement** `CKM_ECDSA_SHA256/384/512` — in either
crypto backend. Verified by building both and comparing mechanism lists:
2.6.1 offers `ECDSA` only; **2.7.0 (master) adds `ECDSA-SHA1/224/256/384/512`**.

`tests/conftest.py` defaults to `/usr/local/lib/softhsm/libsofthsm2.so` with
the comment *"OpenSSL build — supports ECDSA_SHA*"*. The path is right and the
stated reason is wrong: what a source build supplied was a newer *version*,
not a different backend.

This is not a code defect — the capability probe behaves correctly, refusing a
mechanism the token lacks. It is an **onboarding and CI risk**: the documented
100% pass rate is unreproducible from `apt install softhsm2`, or from a 2.6.1
source build, and the brief requires the whole solution to work without a
physical HSM. Phase 2 therefore builds SoftHSM2 from master in the image and
pins the ref.

---

## 3. Architecture assessment

### 3.1 Strengths — reuse these unchanged

| Component | Why it is worth keeping |
|---|---|
| `core/ttlv.py` | Compact, correct TTLV codec. The hard part of KMIP, already done. |
| `operations/` (42 modules) | One module per operation, uniform shape, individually testable. Adding an operation is additive. |
| `pkcs11_shim/shim.py` | Capability probe at startup rejects unsupported mechanisms *before* the native call — this is why errors are legible instead of raw PKCS#11 codes. |
| `lifecycle/state_machine.py` | Full KMIP state machine including Archive/Recover. |
| `lifecycle/access_control.py` | Clean three-tier model (admin → owner → grant). The *model* is right; only its identity input is weak. |
| Test suite | 624 live-HSM tests is a genuine asset and the main reason this is modernization rather than a rewrite. |

The operation-per-module layout is the single most important structural
strength: a REST layer can call these directly, in-process, without
reimplementing any KMIP semantics. That satisfies the "do not duplicate KMIP
business logic" requirement cleanly.

### 3.2 Risks

| # | Risk | Severity | Evidence |
|---|---|---|---|
| R1 | Identity is self-asserted; PIN is the only secret | **Critical** | `server.py` `_authenticate()` |
| R2 | No audit trail of any kind | **Critical** | No audit code; design doc §13 |
| R3 | TLS optional and off by default | **High** | `_wrap_tls()` early return |
| R4 | Global lock serializes all HSM work | **High** | `@_synchronized` on every session method |
| R5 | SQLite single file — no HA, no backup tooling, not encrypted | **High** | `store.py`; design doc §11, §14.3 |
| R6 | Metadata/HSM divergence undetectable | **Medium** | Design doc §13 |
| R7 | Batch items not atomic | **Medium** | Design doc §13 |
| R8 | Test environment needs a source-built SoftHSM2 | **Medium** | Verified above |
| R9 | Dependency floor too low (`python-pkcs11>=0.7.0`, tested on 0.9.5) | **Low** | `setup.py`; no lockfile |
| R10 | No cryptoperiod enforcement or expiry alerting | **Medium** | Design doc §14.3 |

### 3.3 Two findings not in the design document

**A. mTLS identity is discarded when a Credential is present.**
`_get_identity()` *does* map an mTLS client certificate's `commonName` to an
identity — the design document (§10.1) says it does not, so the code is better
than documented here. But that identity is only a **fallback**: if the request
carries a `UsernameAndPassword` credential, `_authenticate()` returns the
client-supplied username instead. The cryptographically authenticated identity
is therefore overridden by the weaker self-asserted one. This is the most
direct route to fixing R1, because the strong identity is already available.

**B. The PIN is doing three jobs.** It is the HSM user PIN, the KMIP
credential, and — transitively — the admin authorization secret. Rotating it
means simultaneously re-PINning the token, reconfiguring every client, and
changing the administrative credential. These should be separated in Phase 2.

---

## 4. Production readiness assessment

Scored against the brief's own criteria. **Not ready** does not mean *bad* — it
means not yet safe for production without the listed work.

### Security — **Not ready**

| Control | State |
|---|---|
| TLS | Supported, optional, off by default; static cert path, no rotation |
| Certificate validation | mTLS available; CN extracted but overridable (3.3A) |
| Authentication | Shared PIN; username unverified |
| Authorization | Three-tier model, correct in design, weak input |
| Secret management | PIN passed as a constructor argument; no vault integration |
| Input validation | Good — TTLV parsing and capability probing both reject early |
| Audit logging | **Absent** |

### Scalability — **Not ready for concurrency; adequate for volume**

Multi-threaded accept loop, but **all HSM work is serialized**. A session pool
was built, load-tested and rejected for sound reasons (python-pkcs11 calls
`C_Initialize(NULL)`, disabling the library's own thread safety). Throughput is
therefore bounded by one HSM session regardless of hardware. SQLite with WAL and
connection-per-thread is fine for a single node and is not the bottleneck.

### Maintainability — **Good**

Clear package boundaries, one concern per module, 624 live tests, and a design
document that matches the code. The main gaps are dependency pinning, no
lockfile, no CI definition, and `logging` used in place of an audit trail.

---

## 5. Gap analysis against the CryptoHub Lite brief

| Brief requirement | Exists today | Phase 2 work |
|---|---|---|
| Reuse existing KMIP logic | Yes — importable Python package | Wrap, do not reimplement |
| PostgreSQL, reuse schema | **No** — SQLite | Port schema; dual-write or migrate |
| Docker Compose deployment | **No** | Build from scratch |
| REST API for the UI | **No** | Build (FastAPI recommended) |
| Audit module (user/IP/action/result) | **No** | Build; needs identity first (R1) |
| RBAC: 5 named roles | Partial — `admin` only | Extend to Administrator / Security Officer / Auditor / Operator / Read Only |
| JWT authentication | **No** | Build |
| PKCS#11 Explorer (slots/tokens/objects/attrs) | Shim can supply the data | Expose via REST + UI |
| KMIP Explorer + operations | Operations exist | Expose via REST + UI |
| Dashboard metrics | Data exists in store | Aggregate endpoints |
| SoftHSM2 without physical HSM | Yes | Pin the OpenSSL build (R8) |
| Multi-HSM provider support | Shim is single-token | Provider abstraction |

---

## 6. Recommendations, prioritized

### 6.1 Immediate — before any production exposure

1. **Separate identity from the PIN (R1).** Stop accepting a client-supplied
   username as identity. Order of preference: mTLS certificate subject (already
   parsed), then a real per-user credential store with per-user secrets. Keep
   the PIN for HSM login only. *Without this, RBAC and audit are decorative —
   both describe an identity nobody verified.*
2. **Enforce TLS by default (R3).** Refuse to start without a certificate
   unless an explicit `--insecure` flag is passed, and log loudly when it is.
3. **Add an append-only audit table (R2)** capturing identity, timestamp,
   source IP, operation, object UID, provider and result — the brief's exact
   fields. Write it in the dispatcher so no operation can bypass it.
4. **Pin dependencies** and add a lockfile; raise the `python-pkcs11` floor to
   the tested 0.9.5.

### 6.2 Phase 1 of the build

5. FastAPI service wrapping the existing package **in-process** (not over KMIP
   TCP), so REST and KMIP share one implementation.
6. PostgreSQL migration of the four metadata tables, with the SQLite schema as
   the starting point.
7. JWT authentication and the five roles, mapped onto the existing tier check.
8. Docker Compose: PostgreSQL, SoftHSM2 (source-built, OpenSSL backend), KMIP
   service, REST API, web portal.

### 6.3 Phase 2 enhancements

9. Multi-process worker pool to lift the concurrency ceiling (R4) — the design
   document already identifies this as the viable route.
10. Metadata/HSM reconciliation job (R6).
11. Cryptoperiod enforcement, auto-rotation, expiry alerting (R10).
12. Backup/restore tooling and encryption at rest for the metadata store (R5).

### 6.4 Future roadmap

13. LDAP / Active Directory / OIDC federation.
14. Dual control / M-of-N approval for destructive operations.
15. HA: replicated PostgreSQL, multiple KMIP nodes, shared HSM partition.
16. Validated HSM (Luna, nShield, Utimaco, CloudHSM) via provider config.

---

## 7. Recommended Phase 2 architecture

Consistent with the brief's stack constraints and the reuse requirement:

```
   Browser
      │  HTTPS
┌─────▼──────────────────┐
│  PHP 8.x + Bootstrap 5 │   presentation only; no crypto, no direct DB
│  Chart.js              │
└─────┬──────────────────┘
      │  REST + JWT
┌─────▼──────────────────┐
│  FastAPI (Python)      │   auth, RBAC, audit, aggregation
│                        │
│  imports ▼ in-process  │
│  kmip_pkcs11 package   │   ← unchanged; the authoritative KMIP logic
└─────┬────────────┬─────┘
      │            │
┌─────▼─────┐ ┌────▼──────────┐
│ PostgreSQL│ │ PKCS#11 shim  │──► SoftHSM2 / HSM
└───────────┘ └───────────────┘
                    ▲
      KMIP clients ─┘  (existing TCP 5696 server, unchanged)
```

The KMIP TCP server and the REST API become two front doors onto **one**
`kmip_pkcs11` package and one metadata store. The PHP tier holds no business
logic, which keeps the "do not duplicate KMIP logic" rule enforceable by
structure rather than by discipline.

---

## 8. Decisions required before Phase 2 build

These change the work materially and are listed in the covering message rather
than assumed here:

1. Relationship to the existing Java **IDEMIA CryptoHub** platform.
2. PostgreSQL migration strategy (cut over vs. dual-run).
3. Whether identity/auth hardening (6.1) is in scope now or deferred.
4. Target for the PKCS#11 concurrency ceiling.
