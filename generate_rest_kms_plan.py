"""
Generate the delivery plan for a complete KMS with a REST control plane.

Run: python generate_rest_kms_plan.py

Twelve steps, each with a design deliverable, an implementation scope, a test
plan and a gate that has to be demonstrated before the step is finished — the
same structure that carried phases 0–5, because it worked.

Every step names the features it closes by their entry in the gap matrix, and
the arithmetic at the front is checked against `generate_kms_gap_matrix.py`
at build time: if a feature is invented, renamed or double-counted, this file
refuses to build rather than printing a plan that does not add up.
"""

import datetime
import importlib.util
import json
import os

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

DARK_BLUE = RGBColor(0x1A, 0x3A, 0x5C)
MID_BLUE = RGBColor(0x2E, 0x6D, 0xA4)
DARK_GREY = RGBColor(0x40, 0x40, 0x40)
OK_GREEN = RGBColor(0x1E, 0x80, 0x2E)
WARN_AMBER = RGBColor(0x8F, 0x56, 0x10)
GAP_RED = RGBColor(0xB3, 0x26, 0x1E)

TODAY = datetime.date.today().strftime("%d %B %Y")
BASELINE = "e44a2ef"
BASELINE_TESTS = 816


# ══════════════════════════════════════════════════════════════════════════════
# The plan
# ══════════════════════════════════════════════════════════════════════════════

STAGES = [
    ("A", "Foundation", "No new attack surface. Makes the rest safe to build."),
    ("B", "The REST control plane", "The API, then the console that uses it."),
    ("C", "Enterprise fit", "What an auditor and a security team ask for."),
    ("D", "Scale, availability and tenancy", "Needs infrastructure to verify."),
]

# step, stage, title, objective, design, implementation, tests, gate,
# features closed (must match gap-matrix feature names exactly), size,
# impact on the existing design
STEPS = [
    (1, "A", "Service layer and guard",
     "Make authorization, dual control, audit and metrics impossible to bypass — "
     "before a second transport exists to bypass them.",
     ["A new kmip_pkcs11/service/ package: CallContext (identity, peer address, "
      "transport), a guard() context manager, and KeyService / AdminService "
      "facades over the existing handlers and store.",
      "The guard runs the role allowlist, then dual control, then the operation, "
      "then audit and metrics — the exact order dispatch() uses today.",
      "OperationDispatcher shrinks to: decode TTLV, call the service, encode TTLV."],
     ["Move check_operation_allowed, dual_control_enforce, _audit and "
      "_record_metric out of the dispatcher into the guard. Operation handlers "
      "are not touched.",
      "Every service method takes a CallContext as its first argument, so a "
      "caller cannot forget to say who is asking."],
     ["The existing suite must pass unmodified — this step changes no behaviour, "
      "and a test that needed editing would mean it did.",
      "New: a reflection test that enumerates every public method on the service "
      "classes and asserts each one is guard-wrapped. This is the test that stops "
      "step 5 from quietly reintroducing a bypass.",
      "New: guard writes an audit row on success and on failure; consumes a "
      "dual-control approval before the handler runs, not after; records metrics "
      "on both paths."],
     f"All {BASELINE_TESTS} existing tests pass with no test file modified, and "
     "the reflection test proves no service method escapes the guard.",
     [],
     "~600 lines moved, ~15 new tests. No new dependencies.",
     [
      "OperationDispatcher loses its cross-cutting logic and becomes a codec: decode, call the service, encode.",
      "access_control.py and dual_control.py are invoked from one place instead of being wired into a transport.",
      "No schema change, no configuration change, nothing on the wire changes."]),

    (2, "A", "Query and reporting layer",
     "Let the store answer the questions a console asks, in one query rather "
     "than N+1.",
     ["store.locate_page(filters, sort, cursor, limit) returning full rows, an "
      "opaque cursor and a total — not the bare identifiers Locate returns.",
      "Cursor is (sort key, uid) encoded, not an offset: offset paging over a "
      "table that is being written double-shows rows.",
      "store.inventory_report() and store.algorithm_usage() for the two "
      "reporting gaps."],
     ["Add the new methods beside the existing locate(), which stays exactly as "
      "it is for the KMIP handler.",
      "Indexes to match the sort columns the console offers."],
     ["Paging over a table mutated between pages neither duplicates nor skips a "
      "row — insert and delete between fetches and assert the union.",
      "Sort by each supported column, ascending and descending; total equals a "
      "brute-force count; a tampered cursor is rejected rather than trusted.",
      "Inventory and algorithm counts match a brute-force scan of the same store."],
     "A store holding 12,000 objects returns page one of fifty, sorted by expiry, "
     "in a single query, with the same figures a full scan produces.",
     ["Key inventory and discovery", "Crypto-agility reporting"],
     "~400 lines, ~20 tests.",
     [
      "metadata/store.py gains paged query methods; the existing locate() is untouched, so the KMIP handler is unaffected.",
      "New indexes on the sortable columns — the first schema migration since Phase 1."]),

    (3, "B", "HTTP transport, sessions and service accounts",
     "An authenticated HTTPS listener that shares nothing with the KMIP port, "
     "and cannot be flooded.",
     ["New api: configuration section — own port, TLS mandatory, off by default. "
      "Not the observability port: /metrics and /ready are deliberately "
      "unauthenticated and must stay that way.",
      "Opaque 256-bit tokens stored as SHA-256 hashes, with identity, label, "
      "created / expires / last used / revoked. Not JWTs: revocation matters "
      "more than statelessness, and there is already a database.",
      "Browsers get an httpOnly, Secure, SameSite cookie plus a CSRF token; "
      "machine clients send a bearer header. Long-lived labelled tokens are the "
      "service-account mechanism.",
      "A bounded connection semaphore and a per-identity token bucket."],
     ["kmip_pkcs11/api/ with a small stdlib router on ThreadingHTTPServer — the "
      "project has three runtime dependencies and none of them does "
      "cryptography, which is a property worth keeping.",
      "Middleware order: authenticate, rate limit, route, translate exceptions "
      "into RFC 9457 problem+json.",
      "POST and DELETE /api/v1/session, GET /api/v1/me."],
     ["Login succeeds and fails correctly; a disabled identity is refused; a "
      "deleted identity's live session stops working immediately.",
      "Token revocation takes effect on the next request; absolute and idle "
      "expiry; a cookie request without a CSRF token is refused while a bearer "
      "request is not.",
      "Rate limiting returns 429 and recovers; the connection cap holds under "
      "200 concurrent connections; the KMIP port is unaffected throughout.",
      "Configuration validation refuses api.enabled without TLS.",
      "Every login, logout, token issue and token revoke is an audit row."],
     "Two hundred concurrent connections do not exhaust the listener, a revoked "
     "token is refused on its next use, and the KMIP port serves normally while "
     "the API is under load.",
     ["API keys / service accounts", "Connection and rate limiting",
      "Request bounds and DoS resistance"],
     "~900 lines, ~35 tests.",
     [
      "A second listener and a second authenticated entry point: the security surface roughly doubles.",
      "New config section, new tables for tokens, new failure modes the KMIP path never had (429, CSRF).",
      "observability.py keeps its own unauthenticated port, deliberately separate."]),

    (4, "B", "Read endpoints",
     "Everything a console displays, with authorization identical to KMIP.",
     ["GET /keys (paged, filtered, sorted), /keys/{uid}, /keys/{uid}/attributes, "
      "/audit, /audit/verify, /approvals, /reports/expiring, /reports/inventory.",
      "404 and 403 are chosen deliberately: an object the caller may not see "
      "returns the same answer as one that does not exist, so the API does not "
      "become an existence oracle."],
     ["Read-only handlers calling the services from step 1 — no store access "
      "from the transport layer, which the guard reflection test enforces."],
     ["Authorization parity: for a given identity, GET /keys returns exactly "
      "the set KMIP Locate returns. Parametrised over owner, admin, grantee, "
      "group member and stranger.",
      "The paging contract from step 2 holds through the HTTP layer.",
      "Audit filters by identity, object, result and time range; the approval "
      "queue lists pending requests only.",
      "A read of an object the caller may not see is indistinguishable from a "
      "read of one that does not exist.",
      "Every read is audited — 'who exported this key' is a read."],
     "A read-only console renders key inventory, audit search and the approval "
     "queue against real data, and a test proves no write path is reachable "
     "through any registered route.",
     [],
     "~700 lines, ~40 tests.",
     [
      "Read paths gain an HTTP representation; the KMIP path does not change at all.",
      "The 404-versus-403 decision becomes an API contract every later step must preserve."]),

    (5, "B", "Write endpoints, and the governance gaps",
     "Lifecycle and delegation over REST, with governance applying by "
     "construction rather than by remembering.",
     ["POST /keys; POST /keys/{uid}/activate | revoke | rekey; DELETE "
      "/keys/{uid}; PUT /keys/{uid}/cryptoperiod; grants, groups and role "
      "permissions; POST /approvals/{id}/approve.",
      "A dual-control refusal returns 403 carrying the approval request id and "
      "the count outstanding, so the console can render 'awaiting 2 approvals' "
      "and link to the queue. That falls out of the existing enforcement.",
      "Three matrix gaps are closed here because they are lifecycle work: "
      "asymmetric auto-rotation, Shamir threshold split keys, and batch "
      "atomicity via a service-level transaction."],
     ["All writes go through the guard. Scheduled rotation extends to key pairs "
      "using the existing ReKeyKeyPair handler; CreateSplitKey gains a Shamir "
      "method alongside XOR; the service layer wraps a batch in one transaction "
      "so a mid-batch failure rolls back."],
     ["The dual-control assertion from the KMIP wire test, run verbatim against "
      "REST: the first Destroy is refused, the key survives, two other "
      "identities approve, the retry succeeds, and the approval is spent.",
      "Role allowlists and group grants behave identically over both transports "
      "— parametrised over the transport, one test body.",
      "Asymmetric rotation cross-links both new objects to both old ones.",
      "Shamir: any k of n shares reconstruct, any k-1 fail.",
      "A batch whose third item fails leaves the first two unapplied."],
     "The KMIP dual-control test and the REST dual-control test share one body "
     "and both pass.",
     ["Automatic rotation", "Split knowledge / M-of-N shares",
      "Bulk and batch operations"],
     "~1,100 lines, ~55 tests.",
     [
      "Write paths over HTTP, with governance applied through the guard rather than re-implemented beside it.",
      "lifecycle/governance.py extends to key pairs, create_split_key gains a second method, and the service layer gains transactions."]),

    (6, "B", "Administration, OpenAPI, separation of duties",
     "Complete the API surface and split the administrator so no one role can "
     "both grant access and use it.",
     ["Identity, role and group administration endpoints.",
      "The admin role splits into security-admin (identities, roles, policy) and "
      "key-admin (objects, cryptoperiods), so a key administrator cannot grant "
      "themselves access to what they administer.",
      "An OpenAPI 3.1 document generated from the router's route table, not "
      "hand-written — a hand-written spec drifts within a month."],
     ["Migration assigns both new roles to anyone holding admin today, so an "
      "upgrade changes nobody's access until an operator splits them."],
     ["A key-admin cannot create an identity; a security-admin cannot read key "
      "material; neither can escalate to the other.",
      "The generated OpenAPI document validates against the 3.1 schema, and a "
      "reflection test asserts every registered route appears in it.",
      "Responses for a sample of endpoints match their declared schemas."],
     "openapi.json validates, covers every route the router knows about, and the "
     "two admin roles are provably disjoint in capability.",
     ["REST / JSON API", "Separation of duties"],
     "~800 lines, ~45 tests.",
     [
      "The admin role splits in two — the first change to the authorization model since Phase 5, and the first needing a migration for existing deployments.",
      "An OpenAPI document becomes a build artefact CI has to keep in step with the router."]),

    (7, "B", "Web console and self-service",
     "The interface most of the market considers table stakes, and the reason "
     "the API exists.",
     ["A single-page client of the API. No privileged path: the console can do "
      "nothing the API forbids, and holds no credential the API would not "
      "accept from curl.",
      "Views: key inventory, key detail, approval queue, audit search, expiry "
      "report, identity and role administration.",
      "Self-service: a team member creates and rotates keys within their "
      "group's grants, without an administrator."],
     ["Served by the API listener or a CDN. Strict CSP with no unsafe-inline. "
      "Session in an httpOnly cookie, never in localStorage."],
     ["End-to-end with a headless browser (Playwright is available): log in, "
      "list keys, open the approval queue, approve a request, watch a blocked "
      "Destroy succeed on retry.",
      "The CSP contains no unsafe-inline and no unsafe-eval.",
      "A route the API forbids to this identity is not reachable from the "
      "console by any means, including direct navigation."],
     "An operator completes a full day of routine work — provisioning, "
     "approving, investigating an audit question — without touching the CLI.",
     ["Web console", "Self-service developer portal"],
     "~2,000 lines of front-end, ~30 tests.",
     [
      "A front-end build enters the repository — the first artefact that is neither Python nor documentation tooling.",
      "Content Security Policy and cookie handling become part of the security review surface."]),

    (8, "C", "Enterprise identity and policy",
     "Authenticate against the corporate directory, and express conditions the "
     "role model cannot.",
     ["OIDC: validate the ID token (issuer, audience, expiry, signature) and map "
      "a claim to a provisioned identity. LDAP/AD bind as an alternative.",
      "The mTLS path already proves the pattern — an external assertion resolved "
      "to a provisioned principal, never inventing one.",
      "Attribute-based conditions evaluated in the guard before the allowlist: "
      "time window, source network, purpose. The engine may only narrow."],
     ["Directory group to role mapping, refreshed on login.",
      "Policies stored in the database, versioned, and every evaluation that "
      "denies is audited with the rule that fired."],
     ["An expired, wrong-audience, wrong-issuer or unsigned token is refused; a "
      "valid token for an unprovisioned subject is refused.",
      "Directory group changes take effect on next login.",
      "A policy denies outside its window and permits inside it.",
      "Property test: for any identity and any policy set, the permitted "
      "operation set is a subset of what the role model alone would allow. A "
      "policy that widens access is a bug by construction."],
     "A corporate login yields exactly the roles the directory says, and a "
     "policy denial names the rule that fired in the audit log.",
     ["Enterprise IdP — LDAP/AD, SAML, OIDC", "Attribute or policy-based access"],
     "~900 lines, ~40 tests.",
     [
      "Identity resolution gains a third path beside password and mTLS certificate.",
      "The guard gains a policy evaluation point — the first change to its order of checks since step 1."]),

    (9, "C", "Audit externalisation, compliance and ceremony",
     "Make the audit trail survive an attacker with file access, and produce "
     "the evidence an auditor asks for.",
     ["A shipper emitting audit rows as syslog/CEF, with a persisted cursor so a "
      "restart neither duplicates nor loses entries.",
      "Periodic notarisation of the chain digest to an append-only external "
      "endpoint. This is the one thing the local chain cannot do: detect a "
      "wholesale, internally consistent rewrite.",
      "Compliance report generators over the audit log and key inventory — PCI "
      "DSS key-management evidence, NIST SP 800-57 cryptoperiod evidence.",
      "A key ceremony runbook, and a kmip-admin command that produces a signed "
      "transcript of what was done, by whom, witnessed by whom.",
      "Alerting rules over the metrics already exported."],
     ["The shipper runs in worker 0 alongside the scheduler, with the same "
      "single-instance reasoning."],
     ["The shipper emits every row exactly once across a restart — kill it "
      "mid-stream and assert the union at the collector.",
      "CEF output parses with a standard parser.",
      "Anchoring detects tampering the local chain cannot: rewrite the whole log "
      "consistently, re-chain it so verify_audit_chain passes, and assert the "
      "anchor comparison fails.",
      "Report figures match direct store queries.",
      "A ceremony transcript verifies against its signature and fails after a "
      "single byte is changed."],
     "A rewritten but internally consistent audit log — one that passes local "
     "verification — is caught by the external anchor.",
     ["Formal key ceremony", "External audit anchoring", "SIEM integration",
      "Compliance reporting", "Alerting"],
     "~1,000 lines, ~45 tests.",
     [
      "The audit log stops being purely local: it gains an outbound path and an external dependency.",
      "Worker 0 takes on a third single-instance responsibility beside the scheduler and the metrics endpoint."]),

    (10, "D", "Storage abstraction and PostgreSQL",
     "Remove the single-writer constraint that blocks everything in stage D.",
     ["Extract a Store interface; SQLite becomes one implementation and "
      "PostgreSQL another.",
      "Each SQLite-specific mechanism needs a deliberate equivalent, not a "
      "translation: PRAGMA user_version becomes a schema-version table, "
      "json_extract becomes JSONB operators, RAISE(ABORT) triggers become "
      "PL/pgSQL triggers, and BEGIN IMMEDIATE — which is what keeps the audit "
      "chain from forking — becomes an advisory lock or SERIALIZABLE."],
     ["Both backends ship. SQLite stays the default for single-node "
      "deployments; it is a good answer there and removing it would be a "
      "regression."],
     ["The entire existing store suite runs against both backends from one "
      "parametrised fixture — not a parallel copy that drifts.",
      "The audit chain survives concurrent writers on PostgreSQL: hammer it from "
      "several connections and assert the chain verifies and no sequence number "
      "is reused.",
      "Migrations apply identically on both; backup and restore work on both.",
      "A store dump from one backend restores into the other."],
     f"The full suite — {BASELINE_TESTS} tests plus everything added since — "
     "passes against PostgreSQL as well as SQLite.",
     ["Enterprise database backend"],
     "~1,500 lines, ~60 tests. Needs a PostgreSQL instance in CI.",
     [
      "metadata/store.py stops being SQLite and becomes an interface with two implementations — the largest structural change in the plan.",
      "Every SQLite-specific mechanism needs a deliberate equivalent, including the lock that stops the audit chain forking."]),

    (11, "D", "High availability, failover and deployment",
     "Survive the loss of a node, a token, or a site.",
     ["Several nodes against one PostgreSQL. The scheduler takes a leader lock "
      "so exactly one instance enforces cryptoperiods — the same reasoning that "
      "restricts it to worker 0 today, one level up.",
      "An HSM pool: several tokens, health-checked, with failover. The master "
      "key must exist on each, which makes provisioning part of the design "
      "rather than an afterthought.",
      "Scheduled backup with offsite shipping; Helm chart and manifests; the "
      "container image and CI workflow finally executed."],
     ["Read traffic spreads across nodes; audited writes still serialise on the "
      "chain, so this raises availability more than throughput. Say so rather "
      "than implying linear scaling."],
     ["Kill the leader under load: another takes over within the lease period, "
      "and no key is deactivated twice.",
      "Fail a token mid-operation: the request either completes on another or "
      "fails cleanly, never silently half-applies.",
      "Two nodes serving concurrently produce one intact audit chain.",
      "A scheduled backup taken on one node restores on another.",
      "The container image builds and its health check passes — the first time "
      "this has been executed anywhere."],
     "A node is killed under sustained load: no request is lost, the audit chain "
     "verifies, and cryptoperiod enforcement continues uninterrupted.",
     ["HA clustering", "Multi-site replication and DR", "HSM failover and pooling",
      "Horizontal throughput", "Scheduled and offsite backup",
      "Kubernetes / container deployment"],
     "~1,800 lines, ~55 tests. Needs multiple nodes and a second token.",
     [
      "Single-process assumptions become cluster-wide ones: the scheduler needs a leader lock, not a worker index.",
      "pkcs11_shim gains a pool and health checks — the first change to the shim's contract since the capability probe."]),

    (12, "D", "Multi-tenancy",
     "Let unrelated tenants share one deployment without seeing each other.",
     ["Tenant becomes a first-class column on objects, identities and audit "
      "rows, and every query is scoped by it.",
      "Object names become unique per tenant rather than globally — the change "
      "most likely to surprise an existing deployment.",
      "Quotas: object count, operations per second, storage. Per-tenant audit "
      "views. Tenant administrators who cannot see other tenants.",
      "This is why it is last: the boundary reaches into every query, the audit "
      "log, the CLI and the API, and half of it would be worse than none."],
     ["A migration places every existing object in a default tenant, so a "
      "single-tenant deployment behaves exactly as before."],
     ["Exhaustive isolation: parametrised over all 41 KMIP operations and every "
      "REST route, an identity in tenant B cannot read, modify, locate or "
      "destroy an object in tenant A. This is the test that matters and it "
      "should be generated from the operation table, not hand-written.",
      "Name collisions across tenants are allowed; within a tenant they are not.",
      "Quota enforcement at the boundary, and the audit row that records it.",
      "A tenant administrator cannot escalate out of their tenant.",
      "Audit search returns only the caller's tenant."],
     "A generated test over every operation and every route proves no "
     "cross-tenant reachability exists.",
     ["Multi-tenancy and namespaces", "Per-tenant quotas"],
     "~1,600 lines, ~80 tests.",
     [
      "A tenant column reaches every table, every query, the audit log, the CLI and the API.",
      "Object names stop being globally unique — the change most likely to surprise an existing deployment."]),
]

# Features the twelve steps do not close, with the reason.
REMAINING = [
    ("Cloud BYOK (AWS, Azure, GCP)", "integration",
     "Per-cloud connectors calling each provider's import API. Well understood, "
     "additive, and best done once the REST layer exists to configure it."),
    ("Cloud EKM / XKS / hold-your-own-key", "integration",
     "Implement the AWS XKS proxy or GCP EKM API in front of the same service "
     "layer. A natural extension of stage B."),
    ("Database TDE integration", "validation",
     "Oracle, SQL Server and MongoDB already speak KMIP; the work is profile "
     "conformance and vendor testing, not new protocol."),
    ("Storage, backup and VM integrations", "validation",
     "As above, for VMware, NetApp and Veeam."),
    ("Secrets management", "product scope",
     "Static custody exists as SecretData. A Vault-style engine — dynamic "
     "credentials, leases, templating — is a different product surface."),
    ("Certificate lifecycle", "product scope",
     "Front the deployment with a real CA such as EJBCA. KMIP's Certify was "
     "never a CA and should not become one."),
    ("Algorithm breadth", "supplier",
     "15 of 40 algorithms work on this token. A richer token activates more "
     "with no code change; the shim already probes."),
    ("Post-quantum (ML-KEM, ML-DSA, SLH-DSA)", "supplier",
     "Needs a token that implements the algorithms and KMIP 3.0 to express "
     "them. SoftHSM's ML-DSA work is unreleased; vendor-range enums would "
     "interoperate with nothing."),
    ("KMIP 3.0", "optional step",
     "Enum and operation additions including Encapsulate and Decapsulate. "
     "Entirely in-protocol and schedulable, but only worth doing alongside a "
     "PQC-capable token."),
    ("KMIP interoperability certification", "external",
     "An OASIS interop event. The conformance tests are already mapped; this is "
     "process and scheduling."),
    ("PKCS#11 provider for applications", "demand",
     "A library fronting the KMIP server, so applications that speak PKCS#11 "
     "plug in. Worth building only if asked for."),
    ("Tokenization / format-preserving encryption", "out of scope",
     "Neither a KMIP operation nor a token mechanism. A separate service."),
    ("FIPS 140-2/3 validated HSM", "procurement",
     "Belongs to the token. The PKCS#11 boundary makes the swap cheap; running "
     "the suite against validated hardware is the actual work."),
    ("Common Criteria / eIDAS", "procurement", "As above."),
]


# ══════════════════════════════════════════════════════════════════════════════
# Consistency check against the gap matrix
# ══════════════════════════════════════════════════════════════════════════════

def load_matrix():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(
        "gapmatrix", os.path.join(here, "generate_kms_gap_matrix.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def verify_against_matrix():
    """A plan that closes features the matrix does not list, or that quietly
    drops one, is worse than no plan. Check both directions before building."""
    m = load_matrix()
    open_features = {}
    for d in m.DOMAINS:
        for feat, _expect, status, _route in d["rows"]:
            if status != "full":
                open_features[feat] = status

    claimed = []
    for step in STEPS:
        claimed.extend(step[8])
    deferred = [name for name, _kind, _why in REMAINING]

    unknown = [f for f in claimed + deferred if f not in open_features]
    if unknown:
        raise SystemExit("plan names features the matrix does not list as open:\n  "
                         + "\n  ".join(unknown))

    dupes = sorted({f for f in claimed if claimed.count(f) > 1})
    if dupes:
        raise SystemExit("feature claimed by more than one step:\n  " + "\n  ".join(dupes))

    overlap = sorted(set(claimed) & set(deferred))
    if overlap:
        raise SystemExit("feature both closed and deferred:\n  " + "\n  ".join(overlap))

    missed = sorted(set(open_features) - set(claimed) - set(deferred))
    if missed:
        raise SystemExit("open features the plan does not account for:\n  "
                         + "\n  ".join(missed))

    return open_features, claimed, deferred


# ══════════════════════════════════════════════════════════════════════════════
# Document helpers
# ══════════════════════════════════════════════════════════════════════════════

def set_cell_bg(cell, hex_color):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), hex_color)
    shd.set(qn("w:val"), "clear")
    tcPr.append(shd)


def add_heading(doc, text, level, colour=None):
    h = doc.add_heading(text, level=level)
    if colour:
        for run in h.runs:
            run.font.color.rgb = colour
    return h


def add_para(doc, text="", bold=False, italic=False, size=10, colour=None):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.bold = bold
    run.italic = italic
    run.font.size = Pt(size)
    if colour:
        run.font.color.rgb = colour
    return p


def add_bullet(doc, text, size=10):
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.left_indent = Inches(0.32)
    p.add_run(text).font.size = Pt(size)
    return p


def section_break(doc):
    doc.add_paragraph()


def header_row(table, headers):
    for i, h in enumerate(headers):
        cell = table.rows[0].cells[i]
        cell.text = h
        set_cell_bg(cell, "1A3A5C")
        for para in cell.paragraphs:
            for run in para.runs:
                run.bold = True
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                run.font.size = Pt(8.5)


def make_table(doc, headers, rows, widths=None):
    tbl = doc.add_table(rows=1, cols=len(headers))
    tbl.style = "Table Grid"
    header_row(tbl, headers)
    for i, values in enumerate(rows):
        row = tbl.add_row()
        for j, v in enumerate(values):
            cell = row.cells[j]
            cell.text = str(v)
            set_cell_bg(cell, "EEF4FA" if i % 2 == 0 else "FFFFFF")
            for para in cell.paragraphs:
                for run in para.runs:
                    run.font.size = Pt(8.5)
    if widths:
        for row in tbl.rows:
            for cell, w in zip(row.cells, widths):
                cell.width = Inches(w)
    return tbl


def labelled_block(doc, label, items, colour=MID_BLUE):
    add_para(doc, label, bold=True, size=9.5, colour=colour)
    for item in items:
        add_bullet(doc, item, size=9.5)


# ══════════════════════════════════════════════════════════════════════════════
# Document build
# ══════════════════════════════════════════════════════════════════════════════

def build():
    open_features, claimed, deferred = verify_against_matrix()

    doc = Document()
    for sec in doc.sections:
        sec.top_margin = Inches(0.9)
        sec.bottom_margin = Inches(0.9)
        sec.left_margin = Inches(1.0)
        sec.right_margin = Inches(1.0)
    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(10)

    # ── title ────────────────────────────────────────────────────────────
    doc.add_paragraph()
    doc.add_paragraph()
    t = doc.add_paragraph()
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    tr = t.add_run("KMIP on PKCS#11")
    tr.bold = True
    tr.font.size = Pt(28)
    tr.font.color.rgb = DARK_BLUE

    s = doc.add_paragraph()
    s.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sr = s.add_run("Delivery Plan — a complete KMS with a REST control plane")
    sr.font.size = Pt(16)
    sr.font.color.rgb = MID_BLUE

    s2 = doc.add_paragraph()
    s2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sr2 = s2.add_run("Twelve steps · design, implementation and test coverage for each")
    sr2.font.size = Pt(12)
    sr2.font.color.rgb = DARK_GREY
    doc.add_paragraph()

    info = [
        ("Baseline", f"{BASELINE} — {BASELINE_TESTS} tests green, 41 of 53 KMIP "
                     f"2.1 operations"),
        ("Starting position", f"{len(open_features)} of 74 assessed features are "
                              f"short of full coverage"),
        ("This plan closes", f"{len(claimed)} of those {len(open_features)}, "
                             f"across 12 steps"),
        ("Deliberately not closed", f"{len(deferred)} — supplier, procurement, "
                                    f"external event, or out of product scope"),
        ("Method", "Every step: a design, an implementation, a test plan, and a "
                   "gate that must be demonstrated"),
        ("Date", TODAY),
    ]
    tbl = doc.add_table(rows=len(info), cols=2)
    tbl.style = "Table Grid"
    for i, (k, v) in enumerate(info):
        tbl.rows[i].cells[0].text = k
        tbl.rows[i].cells[1].text = v
        tbl.rows[i].cells[0].width = Inches(1.6)
        tbl.rows[i].cells[1].width = Inches(4.9)
        set_cell_bg(tbl.rows[i].cells[0], "1A3A5C")
        for para in tbl.rows[i].cells[0].paragraphs:
            for run in para.runs:
                run.bold = True
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                run.font.size = Pt(9)
        for para in tbl.rows[i].cells[1].paragraphs:
            for run in para.runs:
                run.font.size = Pt(9)
    doc.add_page_break()

    # ── 1  method ────────────────────────────────────────────────────────
    add_heading(doc, "1  How this plan works", 1, DARK_BLUE)
    add_para(doc,
        "Phases 0 to 5 of this project succeeded because each had a gate — a "
        "condition someone could watch you meet — rather than a checklist. This "
        "plan keeps that structure and adds the two things the request asks for: "
        "a design deliverable before implementation, and a named test plan rather "
        "than a promise of coverage.")
    section_break(doc)

    add_para(doc, "Each step carries five things", bold=True, colour=MID_BLUE)
    make_table(doc,
        ["Part", "What it means"],
        [
            ["Objective", "One sentence. If it needs two, the step is two steps."],
            ["Design", "Written and reviewed before code. Names the interfaces, "
                       "the data, and the decisions that are hard to reverse."],
            ["Implementation", "What changes, and equally what deliberately does "
                               "not."],
            ["Tests", "Named cases, not a coverage percentage. Every step adds "
                      "regressions for the behaviour it introduces, and the "
                      "existing suite must stay green."],
            ["Gate", "A demonstrable condition. The step is finished when the "
                     "gate is shown, not when the code is written."],
        ],
        widths=[1.3, 5.2])
    section_break(doc)

    add_para(doc, "Rules every step inherits", bold=True, colour=MID_BLUE)
    for r in [
        "Tests run live against a real SoftHSM2 token. The token is never mocked "
        "— the defects worth catching are in the boundary.",
        "The suite stays green at every step. A step that leaves it red is not "
        "finished, and the next step does not start.",
        "Anything that could not be tested in this environment is recorded as "
        "untested rather than shipped as though it had been.",
        "Documents are regenerated, not hand-edited, and the gap matrix's "
        "ASSESSED_AT is bumped whenever coverage changes.",
    ]:
        add_bullet(doc, r)
    section_break(doc)

    add_para(doc,
        "The arithmetic in this document is checked at build time against "
        "generate_kms_gap_matrix.py. If a step claims a feature the matrix does "
        "not list as open, claims one twice, or an open feature appears in "
        "neither the plan nor the deferred list, the generator refuses to build. "
        "That is deliberate: a plan whose numbers do not reconcile with the "
        "assessment it derives from is worse than no plan.",
        italic=True, size=9)
    doc.add_page_break()

    # ── 2  what it closes ────────────────────────────────────────────────
    add_heading(doc, "2  What the plan closes", 1, DARK_BLUE)
    add_para(doc,
        f"Of 74 assessed features, {len(open_features)} are short of full "
        f"coverage today — 16 partial and 26 absent. The twelve steps close "
        f"{len(claimed)} of them. The remaining {len(deferred)} are listed in "
        f"section 5 with the reason each is not engineering work this plan can "
        f"schedule.")
    section_break(doc)

    rows = []
    for num, stage, title, *_rest in STEPS:
        closed = _rest[5]
        rows.append([str(num), stage, title, str(len(closed)) if closed else "—"])
    make_table(doc,
        ["Step", "Stage", "Title", "Features closed"],
        rows,
        widths=[0.6, 0.7, 3.9, 1.3])
    section_break(doc)

    add_para(doc, "The four stages", bold=True, colour=MID_BLUE)
    make_table(doc,
        ["Stage", "Name", "Character"],
        [[letter, name, note] for letter, name, note in STAGES],
        widths=[0.7, 2.2, 3.6])
    section_break(doc)

    add_para(doc,
        "Steps 1 and 2 close nothing and are still the two most important. They "
        "are the reason the ten that follow can be built without each one "
        "re-litigating authorization, and the reason a REST endpoint cannot "
        "quietly become a path around dual control.", italic=True, size=9.5)
    doc.add_page_break()

    # ── 3  dependencies ──────────────────────────────────────────────────
    add_heading(doc, "3  Sequence and dependencies", 1, DARK_BLUE)
    add_para(doc,
        "The order is dictated by dependency, not by visibility. Three "
        "constraints fix most of it.")
    section_break(doc)
    for item in [
        "Step 1 precedes every other step. Authorization, dual control and audit "
        "currently live inside the KMIP dispatcher; a REST layer built before "
        "they move would bypass all three, and the bypass would be silent.",
        "Step 10 precedes step 11, which precedes step 12. SQLite has no "
        "multi-writer story, so clustering waits on PostgreSQL, and tenancy is "
        "only worth building on something that can survive a node failure.",
        "Step 3 precedes 4, 5 and 6, which precede 7. The console is a client of "
        "the API; building it earlier means building it twice.",
        "Steps 8 and 9 depend only on stage B and can run in parallel with each "
        "other, or with stage D if there are two teams.",
    ]:
        add_bullet(doc, item)
    section_break(doc)

    add_para(doc, "Where the plan needs infrastructure it does not have",
             bold=True, colour=WARN_AMBER)
    make_table(doc,
        ["Step", "Needs", "If unavailable"],
        [
            ["10", "A PostgreSQL instance in CI",
             "The abstraction can be built and the SQLite path kept green, but "
             "the PostgreSQL implementation cannot be claimed as verified."],
            ["11", "Multiple nodes and a second HSM token",
             "Failover must not be marked done. An untested failover path invites "
             "exactly the reliance it cannot support."],
            ["11", "Network access to a container registry",
             "The image and CI workflow have still never been executed. This step "
             "is the first opportunity to fix that."],
            ["7", "A browser in CI for end-to-end tests",
             "Playwright and Chromium are available in this environment, so this "
             "one is not blocked."],
        ],
        widths=[0.6, 2.2, 3.7])
    doc.add_page_break()

    # ── 4  the steps ─────────────────────────────────────────────────────
    add_heading(doc, "4  The steps", 1, DARK_BLUE)
    add_para(doc,
        "Sizes are estimates for planning, not commitments. The test counts are "
        "the more meaningful figure: they say what the step has to prove.",
        italic=True, size=9)
    section_break(doc)

    for (num, stage, title, objective, design, impl, tests, gate, closes,
         size, impact) in STEPS:
        add_heading(doc, f"Step {num} — {title}", 2, DARK_BLUE)
        p = doc.add_paragraph()
        r = p.add_run(f"Stage {stage}   ·   {size}")
        r.font.name = "Courier New"
        r.font.size = Pt(8.5)
        r.font.color.rgb = MID_BLUE

        add_para(doc, objective, bold=True, size=10.5)
        section_break(doc)

        labelled_block(doc, "Impact on the existing design", impact, WARN_AMBER)
        section_break(doc)
        labelled_block(doc, "Design", design)
        section_break(doc)
        labelled_block(doc, "Implementation", impl)
        section_break(doc)
        labelled_block(doc, "Tests", tests)
        section_break(doc)

        add_para(doc, "Gate", bold=True, size=9.5, colour=OK_GREEN)
        add_para(doc, gate, size=9.5)
        section_break(doc)

        add_para(doc, "Closes", bold=True, size=9.5, colour=MID_BLUE)
        if closes:
            for c in closes:
                add_bullet(doc, c, size=9.5)
        else:
            add_para(doc,
                "Nothing directly — this step exists so that the steps after it "
                "can be built safely.", size=9.5, italic=True)
        doc.add_page_break()

    # ── 5  what remains ──────────────────────────────────────────────────
    add_heading(doc, "5  What the plan does not close", 1, DARK_BLUE)
    add_para(doc,
        f"{len(deferred)} features remain open after step 12. None is an "
        f"oversight; each is here because it depends on something other than "
        f"engineering time, or because it belongs to a different product.")
    section_break(doc)

    kinds = {
        "integration": "Additive work, best done after stage B",
        "validation": "Testing against a vendor, not new code",
        "product scope": "A different product surface",
        "supplier": "Depends on the token",
        "optional step": "Schedulable, but only worth doing with a capable token",
        "external": "Depends on an external event",
        "demand": "Build only if asked for",
        "out of scope": "Deliberately not this product",
        "procurement": "Buying and testing, not building",
    }
    make_table(doc,
        ["Feature", "Why not now", "Detail"],
        [[name, kinds[kind], why] for name, kind, why in REMAINING],
        widths=[1.9, 1.5, 3.1])
    section_break(doc)

    add_para(doc,
        "Six of these — the two cloud integrations, the two vendor validations, "
        "secrets management and certificate lifecycle — are ordinary engineering "
        "and would form a natural stage E once the REST layer exists to "
        "configure them. That would take the total closed to "
        f"{len(claimed) + 6} of {len(open_features)}. The remaining eight depend "
        "on a supplier, a procurement decision, or an OASIS event, and no amount "
        "of planning moves them.", size=9.5)
    doc.add_page_break()

    # ── 6  risks ─────────────────────────────────────────────────────────
    add_heading(doc, "6  Risks worth naming now", 1, DARK_BLUE)
    make_table(doc,
        ["Risk", "Why it matters", "Mitigation"],
        [
            ["A later endpoint bypasses the guard",
             "All governance silently stops applying to that path, and nothing "
             "fails — the worst kind of defect this project has seen.",
             "The reflection test in step 1, kept green forever. It is cheap and "
             "it is the single most valuable test in the plan."],
            ["Two authenticated front doors",
             "The API doubles the authentication surface, and a leaked token is "
             "as good as a password.",
             "Tokens are revocable, expiring, hashed at rest, and every issue and "
             "revoke is audited (step 3)."],
            ["The audit write lock becomes the bottleneck",
             "It already caps worker scaling at about 1.5×; REST traffic contends "
             "for the same lock.",
             "Measure before and after step 11. If it binds, per-shard chains are "
             "the answer, and that is a design change, not a tuning exercise."],
            ["Tenancy migration surprises an existing deployment",
             "Object names become unique per tenant rather than globally.",
             "The step 12 migration places everything in a default tenant so "
             "behaviour is unchanged until a second tenant exists."],
            ["Scope creep into a security product",
             "Tokenization, a CA and a secrets engine are all adjacent and all "
             "tempting.",
             "They are named in section 5 as out of scope. Revisit deliberately, "
             "not by drift."],
            ["The plan outruns the verification environment",
             "Steps 10 and 11 cannot be honestly completed without PostgreSQL, a "
             "second token and a registry.",
             "Section 3 says so up front. A step whose gate cannot be "
             "demonstrated is not finished, whatever the code says."],
        ],
        widths=[1.6, 2.3, 2.6])
    section_break(doc)

    add_para(doc,
        "One further note, from this project's own history: every serious defect "
        "found so far was invisible in the diff and obvious the moment something "
        "ran — an authentication bypass, plaintext in a WAL sidecar, a readiness "
        "probe that lied for eighteen seconds, a 25× latency cost, and a slide "
        "deck whose every diagram was missing. Each step's gate is written to be "
        "executed, not reviewed.", italic=True, size=9.5)

    section_break(doc)
    f = doc.add_paragraph()
    f.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fr = f.add_run(f"KMIP on PKCS#11 — REST KMS delivery plan — {TODAY}")
    fr.font.size = Pt(8)
    fr.font.color.rgb = RGBColor(0x80, 0x80, 0x80)

    out = "KMIP_PKCS11_REST_KMS_Plan.docx"
    doc.save(out)
    print(f"Saved: {out}")

    # The slide deck is built from this same data, so the two cannot drift.
    # generate_rest_kms_deck.js reads it; run this generator first.
    payload = {
        "baseline": BASELINE,
        "baseline_tests": BASELINE_TESTS,
        "generated": TODAY,
        "totals": {"open": len(open_features), "closed": len(claimed),
                   "deferred": len(deferred)},
        "stages": [{"letter": a, "name": b, "note": c} for a, b, c in STAGES],
        "steps": [
            {"n": n, "stage": st, "title": ti, "objective": ob, "design": de,
             "implementation": im, "tests": te, "gate": ga, "closes": cl,
             "size": si, "impact": ip}
            for (n, st, ti, ob, de, im, te, ga, cl, si, ip) in STEPS
        ],
        "remaining": [{"feature": f, "kind": k, "why": w} for f, k, w in REMAINING],
    }
    with open("plan_steps.json", "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1, ensure_ascii=False)
    print("Saved: plan_steps.json  (source for the slide deck)")
    print(f"  {len(open_features)} features open · {len(claimed)} closed by the "
          f"plan · {len(deferred)} deferred · reconciles with the gap matrix")


if __name__ == "__main__":
    build()
