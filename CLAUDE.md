# CLAUDE.md

Orientation for anyone — human or Claude — picking this repository up cold.
Read the first three sections before changing anything; the history below is
the record of how the project got here and why several things are the way they
are.

---

## 1. What this is

A KMIP 2.1 server implemented in Python on top of a PKCS#11 HSM. Key material
is generated inside the token and never leaves it; the KMIP layer manages
object lifecycle, metadata, access control, governance and protocol framing,
and delegates every cryptographic operation to PKCS#11.

At `7b56c23`: 41 of 53 KMIP 2.1 operations, 816 tests passing live against a
real SoftHSM2 2.7.0 token, six generated documents.

---

## 2. Working agreements

These emerged from the work and are the reason the project holds together.
Treat them as binding.

**Verify by executing, not by reading.** Nearly every serious defect in this
project's history was invisible in the diff and obvious the moment something
ran: an authentication bypass, plaintext left in a WAL sidecar, a readiness
probe that lied for 18 seconds, a 25× latency defect, a `mode=` argument that
did nothing. Do not report something as working because the code looks right.

**Say what is not done.** The documents state limitations plainly, including
things that were scoped and deliberately not built, and why. Never let
"deferred" quietly read as "done". If something could not be tested in this
environment, say so rather than shipping it as though it had been.

**Documents are generated, never hand-edited.** Each `.docx` has a
`generate_*.py` beside it. Edit the generator and re-run it. A hand edit is
lost on the next regeneration.

**Tests come with the change.** Every phase added regressions for the specific
behaviour it introduced. That suite is why each phase could build on the last
without re-verifying everything by hand.

**One PKCS#11 session per process, serialized.** This is permanent design, not
a stopgap. A session pool was built, tested, and reproducibly segfaulted:
`python-pkcs11` calls `C_Initialize(NULL)`, so the library's own thread safety
is never enabled and separate sessions do not work around it. Scale with
processes (`server.workers`), never with threads. Do not attempt a session
pool again without first fixing the binding.

---

## 3. Environment gotchas

These will waste an hour each if you meet them cold.

| Symptom | Cause and fix |
|---|---|
| EC signing tests fail | SoftHSM2 older than 2.7.0. The packaged 2.6.1 advertises 70 mechanisms without `CKM_ECDSA_SHA256`; a source-built 2.7.0 advertises 79 with it. **The crypto backend is not the differentiator** — the packaged build already links OpenSSL. Build 2.7.0 from source to `/usr/local`. |
| `pip install -e .` fails with `AttributeError: install_layout` | Debian/Ubuntu setuptools interaction. Use `pip install --use-pep517 -e '.[dev]'`. |
| Tests fail in unrelated places | Two pytest processes sharing the SoftHSM token. Run one at a time (`pgrep -fa pytest`). |
| A fresh container looks like a different project | This branch has diverged from `main` — 36 commits here that are not there, 8 there that are not here. If `kmip_pkcs11/` is missing, the checkout is stale: `git fetch origin && git reset --hard origin/claude/kmip-specifications-iprzym`. |
| Generators fail on import | `pip install python-docx matplotlib` — not declared in `setup.py`, since they are documentation-only. |

The test fixtures wipe and re-initialise `/tmp/softhsm2_tests/tokens` every
session. That is deliberate: runs used to leave thousands of keys behind, and
at ~28k objects the master-key lookup outlasted the fixtures' wait and the
suite began failing for reasons unrelated to the code.

---

## 4. Layout

```
kmip_pkcs11/
├── core/           TTLV codec, enums, exception hierarchy
├── pkcs11_shim/    the ONLY file that imports pkcs11 — swap point for a real HSM
├── operations/     one file per KMIP operation (40) + dispatcher.py
├── lifecycle/      state machine, access control, dual control, governance
├── metadata/       SQLite store, backup, envelope encryption
├── server/         TCP server, pre-fork worker pool
├── cli/            kmip-server, kmip-admin
├── test_app/       client and demo
└── tests/          816 tests
```

**Where cross-cutting concerns live.** `OperationDispatcher.dispatch` wraps
every handler with the role allowlist check, dual control, audit and metrics.
Anything that calls the store directly bypasses all four — this is the main
hazard when adding a second transport such as a REST API, and the reason a
service-layer extraction should precede one.

---

## 5. Commands

```bash
pytest                                    # 816 tests, ~50s, needs the token
pytest kmip_pkcs11/tests/test_ttlv.py     # unit tests, no token needed

kmip-server --config PATH --check         # validate configuration and exit
kmip-admin -c PATH identity add alice     # the operator surface

python -m kmip_pkcs11.test_app.demo       # 16-step end-to-end demo

for g in generate_feature_spec generate_install_guide generate_kmip_design_doc \
         generate_docs generate_phase_report generate_kms_gap_matrix; do
  python "$g.py"
done
```

---

## 6. History

Chronological. Commit hashes are the detail — `git show <hash>` carries the
full reasoning, which is deliberately verbose in this repository.

### Prehistory — unrelated content (May 2024 – Apr 2026)

`46c0f23` … `dcbe7e6`. The repository began as something else entirely
(`Wearing.cpp`, an AES CLI in `encrypt.py`). These files still sit at the
root and are not part of the KMIP project. The `main` branch continues that
older line.

### The server takes shape (Jun 2026)

- `ecc51f1` design document with sequence diagrams — written before the code
- `2739d9a` the KMIP 2.1 server and conformance suite
- `a4ae9fd`, `5a96f40`, `e510c37` documentation, extended tests, install guide

### Filling out the protocol (Aug 2026, one day)

Eleven numbered phases, `75bdd40` → `6c9c374`, taking the operation count to
41 of 53: cipher modes, Sign/Verify, MAC/Hash, Register/Import/Export,
DH/ECDH and DeriveKey, Certify/Validate, Archive/Recover/Check, ReKey and
split keys, then Credential authentication and batching.

Two findings worth remembering:

- `cc33d32` — EC signing needed `CKM_ECDSA_SHA*`, which the distribution's
  SoftHSM2 lacks. This is where the source build entered the project.
- `a778392` — several TTLV tag codepoints were simply wrong, found by
  checking them against the real OASIS registry rather than trusting them.
- `db7f526` — the capability probe: read the token's real mechanism list at
  startup and fail unsupported requests cleanly instead of surfacing a raw
  PKCS#11 error from deep inside an operation.

### First hardening pass (10 Aug 2026)

- `c41ae48` owner-only access control, and the session-concurrency decision
- `944eb4e` RBAC — admin role and delegated per-object grants
- `f50a0b1` documentation brought back in line with the code

### The production programme, phases 0–5 (16–18 Aug 2026)

A full review produced twelve findings and a six-phase plan. All six shipped.
`KMIP_PKCS11_Phase_Report.docx` is the narrative; the short version:

| Phase | Commit | What it closed |
|---|---|---|
| 0 | `c8f3de7` | Identity was self-asserted — anyone with the shared token PIN could claim any username, including admin. Per-identity scrypt credentials. Also fixed the admin/`Locate` defect introduced by `944eb4e`, plus transport hardening. 624 → 649 tests. |
| 1 | `02134aa` | Secret blobs sat in the database in the clear. AES-256-GCM envelopes under a non-extractable HSM master key, and the versioned migration mechanism that made rolling it out possible. 649 → 671. |
| 2 | `3d6c746` | No audit trail, TLS optional. Hash-chained append-only log; TLS enforced by default. 671 → 701. |
| 3 | `5b5ffc9` | Not deployable without writing Python. Config file, two CLIs, health/readiness/metrics, JSON logs, systemd unit, Dockerfile, CI. 701 → 739. |
| 4 | `46603ad` | No backup, single-core. Online backup with token pairing and verified restore; pre-fork workers. 739 → 763. |
| 5 | `cf8460b` | Everything was reactive. Cryptoperiod scheduler, dual control, groups, per-role allowlists. 763 → 811. |

Defects each phase found by running the system, not reading it:

- Phase 1 — encrypting rows in place left the original cleartext in the WAL
  sidecar. Found by grepping the database files after the migration.
- Phase 3 — `/ready` reported ready 18 seconds before the KMIP port opened,
  because startup provisions the master key before binding.
- Phase 4 — scrypt ran on every request (KMIP sends a Credential per request),
  capping a connection at ~25 ops/sec. Fixed with a verification cache:
  24 → ~600 ops/sec single-worker.
- Phase 5 — each dual-control retry opened a *new* approval request; five
  retries produced five requests.

Deliberately not built, with reasons recorded: PostgreSQL backend, HSM
failover, multi-tenancy, FIPS validation.

### Documentation and analysis (19 Aug – 7 Sep 2026)

- `483c177` phase execution report
- `87ef635` feature specification (all 41 operations with worked examples) and
  a rewritten installation guide. Writing them found two real bugs: the test
  client's `mode=` argument never encoded `CryptographicParameters`, so asking
  for GCM silently got CBC; and the Dockerfile/CI built SoftHSM **2.6.1** from
  source under the mistaken belief that the crypto backend was the problem —
  it is the version.
- `2964dee` the example config pointed at the distribution SoftHSM (the build
  without `CKM_ECDSA_SHA256`), and the demo had been broken for some time in
  two ways because nothing ever executed it.
- `7b56c23` enterprise KMS gap matrix — 74 features from the commercial
  market, 32 covered, 16 partial, 26 not covered, 19 of which cannot be closed
  by writing more KMIP.

---

## 7. Current state and known gaps

**Solid:** the PKCS#11 boundary, capability probing, the TTLV codec, the
lifecycle state machine, access control, governance, audit, encryption at
rest, backup and restore.

**Known limits** (full list in the gap matrix and `README_KMIP.md`):

- No REST API or web console — the highest-leverage gap, since reporting, the
  console and most integrations are all clients of an API that does not exist.
- No multi-tenancy; isolation today means one deployment per tenant.
- SQLite only, so no clustering or replication.
- Worker scaling ~1.5×, bounded by the serial audit chain — the real cost of
  tamper-evidence, not a misconfiguration.
- No connection or rate limiting: the listener takes a backlog of 16 with no
  throttle. Noted in the original review and never fixed.
- Audit chain is not externally anchored.
- SoftHSM2 is not FIPS/CC validated; the swap is cheap, the validation is not.
- No post-quantum: needs both a PQC token and KMIP 3.0.
- The container image and CI workflow have never been executed — this
  environment blocks Docker Hub and the SoftHSM2 mirror.

---

## 8. Documents

| Document | Generator | Covers |
|---|---|---|
| `README_KMIP.md` | — | The overview. Start here. |
| `KMIP_PKCS11_Feature_Specification.docx` | `generate_feature_spec.py` | Every feature and all 41 operations with examples |
| `KMIP_PKCS11_Install_Test_Guide.docx` | `generate_install_guide.py` | Installation, deployment, operations, troubleshooting |
| `KMIP_PKCS11_Design_Document.docx` | `generate_kmip_design_doc.py` | Architecture and rationale, including rejected designs |
| `KMIP_PKCS11_Project_Documentation.docx` | `generate_docs.py` | Module reference and test specification |
| `KMIP_PKCS11_Phase_Report.docx` | `generate_phase_report.py` | How the system reached its current state |
| `KMIP_PKCS11_KMS_Gap_Matrix.docx` | `generate_kms_gap_matrix.py` | Market requirements vs coverage, with routes for gaps |

When coverage changes, update `ASSESSED_AT` in `generate_kms_gap_matrix.py` so
the matrix still names the commit it describes.

---

## 9. Keeping this file current

Add an entry to the history when a phase or a substantial change lands, and
update section 7 when a gap closes or a new one is found. Keep it compact —
this file is loaded into every session, so it should orient quickly and point
to the documents for detail rather than restating them.
