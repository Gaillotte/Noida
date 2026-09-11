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
real SoftHSM2 2.7.0 token, six generated documents and an overview deck.

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
`generate_*.py` beside it, and the `.pptx` has `generate_overview_deck.js`.
Edit the generator and re-run it. A hand edit is lost on the next
regeneration.

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
| `soffice` says "source file could not be loaded" for every file, even a `.txt` | Only `libreoffice-core` and `-common` are installed, so there are **no document filters**. `apt-get install -y libreoffice-impress libreoffice-writer` fixes it, and conversion then works normally. Worth doing immediately — without it there is no way to see a rendered document, which is how a deck shipped with every diagram missing. |
| Rendering a deck to look at it | `soffice --headless --convert-to pdf --outdir . deck.pptx` then `pdftoppm -jpeg -r 100 deck.pdf slide` (`apt-get install poppler-utils`). `tools/render_pptx.py` is a PIL approximation for when LibreOffice is unavailable — useful, but it under-estimates bullet height and draws block arrows as plain rectangles, so trust the real render when both are available. |
| Building slides | Never use a `line` shape for a connector: pptxgenjs accepts zero width or height and PowerPoint renders nothing. Use `downArrow` / `rightArrow` block shapes. Run `python tools/qa_pptx_geometry.py deck.pptx`, then actually look at the render. |

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

The decks are the generators that are not Python:

```bash
npm install && npm run all         # every checked-in document, in dependency order
npm run deck:all                   # matrix totals, overview deck, its PDF
npm run plan:all                   # plan document, its deck, its PDF
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
  by writing more KMIP. Later widened to 82; see the end of this section.
- `5686868` overview deck — 15 slides covering KMIP, the design on PKCS#11,
  the REST-on-KMIP target architecture, the gap analysis and the roadmap.
  Shipped with every connector invisible: pptxgenjs writes a `line` shape with
  zero width or height into the XML and PowerPoint draws nothing for it, so
  all fifteen arrows were absent and the diagrams read as disconnected boxes.
  A card heading that wrapped to two lines was also overwritten by its body.
  Both were found only once `tools/render_pptx.py` existed to look at the
  slides — the geometric check had passed them. `85c7569` fixed those; a
  further round found that LibreOffice was not broken at all, only missing its
  filter packages, and a real render then showed bullet lists overflowing four
  more cards that the PIL approximation had under-measured. The generator now
  estimates the height of every card's content at build time and prints what
  does not fit.
- `9c18326` requirement provenance — which source evidenced each of the 74
  requirements. Deliberately **not** a capability comparison: the research was
  a handful of published pages per vendor, and filling 74 × 7 cells as though
  it were a comparison would have been fabrication at scale. It reported the
  uncomfortable figure honestly — 20 requirements rested on no source at all.

### Four more products, and what they changed (11 Sep 2026)

Bloombase KeyCastle, Cosmian/Eviden KMS, Securosys CyberVault KMS and
HashiCorp Vault were added to the research. Two results worth keeping:

- **The requirement list was short by eight.** Encryption as a service over a
  data-plane API, KMIP's JSON and XML encodings, an OpenAPI document with
  generated clients, key-bound usage policy enforced inside the HSM,
  certificate discovery and expiry monitoring, confidential-computing
  deployment, distributed tracing, and sealed startup with quorum unseal. 74 →
  82: 32 covered, 18 partial, 32 not covered, 23 outside KMIP's reach.
- **The unsourced residue halved, 20 → 10.** Most of what the category
  baseline was carrying alone — groups, rate limiting, metrics, an
  administrative CLI, mTLS identity, certificate lifecycle, an enterprise
  database backend — turned out to be named by one of the four. Ten
  requirements still rest on nothing but ordinary practice, and the provenance
  document lists them.

Two mechanical findings came out of the same work. The gap figures on the
overview deck were a hand-copied scorecard, so the matrix now writes
`gap_totals.json` and the deck reads it — the same treatment `plan_steps.json`
already gave the plan deck. And the plan deck's fit check was wrong in a way
that mattered: it estimated line height from the font size while `panel()`
pinned spacing at 16pt, so shrinking a font bought no vertical space and the
check passed content the render showed hanging out of its panel.

The plan then absorbed the new requirements. Four went into existing steps —
encryption as a service into step 5, the OpenAPI document and its generated
clients into step 6, distributed tracing and quorum unseal into step 9. Two
became a new **stage E, "Protocol and estate reach"**: step 13 for the KMIP
JSON and XML encodings, step 14 for certificate discovery and expiry
monitoring. Both are additive, independent of stage D, and — unlike the two
that stayed deferred — verifiable in this environment.

Twelve steps became fourteen, four stages became five, and 34 of the 50 open
features are now closed by the plan against 16 deferred. The two new features
that stayed deferred are the honest ones: key-bound policy needs a token
SoftHSM cannot imitate, and confidential-computing deployment needs attested
hardware nothing here can verify.

Note for anyone repeating this research: the network policy in this
environment blocks all four vendors' documentation domains, so they were read
through indexed summaries rather than the pages themselves. Every document
that rests on that research says so.

**Still inconsistent, deliberately left alone:** the overview deck's roadmap
slides describe ten "waves", a structure that predates the fourteen-step plan
and does not map onto it. Reconciling the two is a design decision about which
narrative survives, not a mechanical fix, so it was not made silently.

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
- Named by the four products added in September and absent here: no data-plane
  crypto API over HTTP, no distributed tracing, no operator-quorum unseal (the
  token PIN holder is the whole ceremony), and dual control is enforced by the
  server rather than bound to the key inside the token — own the server and
  you own the policy.

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
| `KMIP_PKCS11_Overview_Deck.pptx` | `generate_overview_deck.js` | 15-slide overview: KMIP, the design, the REST target, gaps, roadmap |
| `KMIP_PKCS11_Overview_Deck.pdf` | `npm run pdf` | The same deck as PDF, for viewing without PowerPoint |
| `KMIP_PKCS11_REST_KMS_Plan.docx` | `generate_rest_kms_plan.py` | Fourteen-step delivery plan to a complete KMS with a REST control plane, closing 34 of the 50 open features. Its arithmetic is checked against the gap matrix at build time, and every step and stage count in it is read from the tables rather than typed |
| `KMIP_PKCS11_REST_KMS_Plan_Deck.pptx` / `.pdf` | `generate_rest_kms_deck.js` | The same plan as 45 slides — three per step: design impact, proposed solution, test strategy. Built from `plan_steps.json`, so it cannot say anything the plan does not, and its layout scales with the stage and step counts |
| `KMIP_PKCS11_Feature_Provenance.docx` / `.pdf` | `generate_feature_provenance.py` | Which of eleven sources evidenced each of the 82 requirements. **Provenance, not a capability comparison** — a mark means a source's documentation named the requirement, never that a product has it |

When coverage changes, update `ASSESSED_AT` in `generate_kms_gap_matrix.py` so
the matrix still names the commit it describes.

`generate_rest_kms_plan.py` refuses to build if a step claims a feature the gap
matrix does not list as open, claims one twice, or leaves an open feature
accounted for by neither the plan nor its deferred list. Close a gap, mark it
`full` in the matrix, and the plan will tell you it no longer reconciles.

The plan and its deck share one source. `generate_rest_kms_plan.py` emits
`plan_steps.json` (gitignored) and `generate_rest_kms_deck.js` reads it, so
`npm run plan:all` rebuilds document, deck and PDF together. Edit the STEPS
table in the Python generator; never the deck.

`generate_feature_provenance.py` reconciles against the matrix the same way and
refuses to build on an invented feature, a missing one, an unknown source code,
a requirement with no source at all, or a "CAT" mark sitting beside a real one.
That last rule is what makes the CAT column mean something: it is the honest
residue, 10 of the 82 requirements that no source named and that rest on
ordinary practice. If the requirement list is ever challenged, those are the
rows to defend first.

The overview deck no longer carries its own copy of the gap figures.
`generate_kms_gap_matrix.py` writes `gap_totals.json` (gitignored) and
`generate_overview_deck.js` reads it, asserting the per-domain columns still
sum to the totals. `npm run all` rebuilds every checked-in document in
dependency order.

---

## 9. Keeping this file current

Add an entry to the history when a phase or a substantial change lands, and
update section 7 when a gap closes or a new one is found. Keep it compact —
this file is loaded into every session, so it should orient quickly and point
to the documents for detail rather than restating them.
