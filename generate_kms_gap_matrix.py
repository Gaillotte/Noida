"""
Generate the enterprise KMS gap matrix — what a high-end key management
platform is expected to do, whether this project covers it, and the route for
every gap.

Run: python generate_kms_gap_matrix.py

The requirement list was assembled from what the leading commercial platforms
ship (Thales CipherTrust Manager, Entrust KeyControl, Fortanix DSM, Utimaco
ESKM, and the cloud KMS services) together with NIST SP 800-57 and SP 800-152.
The coverage column is grounded in this repository at the commit named on the
title page, not in intentions.

The fourth column is the one that earns the document. Many gaps here cannot be
closed by writing more KMIP: the specification standardises key objects and
operations, not the service around them, so federation, tenancy, REST, cloud
key import and SIEM export have no wire representation at all. Those rows are
marked "Outside KMIP" and name the route that would actually work.
"""

import datetime

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

# ── colour palette (matched to the other project documents) ───────────────────
DARK_BLUE  = RGBColor(0x1A, 0x3A, 0x5C)
MID_BLUE   = RGBColor(0x2E, 0x6D, 0xA4)
DARK_GREY  = RGBColor(0x40, 0x40, 0x40)
FULL_GREEN = RGBColor(0x1E, 0x80, 0x2E)
PART_AMBER = RGBColor(0x8F, 0x56, 0x10)
GAP_RED    = RGBColor(0xB3, 0x26, 0x1E)

TODAY = datetime.date.today().strftime("%d %B %Y")

# Commit this assessment was made against. Bump it when the matrix is revised,
# so a reader can tell whether the coverage column still describes the code.
ASSESSED_AT = "2964dee"
TEST_COUNT = "816"

STATUS_LABEL = {"full": "Covered", "partial": "Partial", "gap": "Not covered"}
STATUS_COLOUR = {"full": FULL_GREEN, "partial": PART_AMBER, "gap": GAP_RED}
STATUS_FILL = {"full": "E2F0E7", "partial": "F7EDDC", "gap": "F9E6E4"}

# Marker left by the source data wherever a gap cannot be closed through the
# KMIP protocol itself.
OUT = "@@OUT@@"


# ── the matrix ────────────────────────────────────────────────────────────────
# feature, what the market expects, status, route if not covered here
DOMAINS = [{'name': 'Key lifecycle and cryptography',
  'rows': [['HSM-backed storage, keys never leave',
            'Key material generated and held in a certified token; the KMS holds '
            'references, not secrets.',
            'full',
            'Every key is a PKCS#11 object; only pkcs11_shim/ imports the binding.'],
           ['Full lifecycle state machine',
            'Pre-Active → Active → Deactivated / Compromised → Destroyed, with '
            'state-gated usage.',
            'full',
            'Enforced per operation. Decrypt stays legal on a Deactivated key so '
            'retiring one does not strand data.'],
           ['Cryptoperiod enforcement',
            'Keys deactivate on policy, not when someone remembers (NIST SP 800-57).',
            'full',
            'Background scheduler; every action audited as system:scheduler.'],
           ['Automatic rotation',
            'Expiring keys replaced automatically, with lineage preserved.',
            'partial',
            'Symmetric keys only. Asymmetric rotation would reuse the existing '
            'ReKeyKeyPair handler — in-project, no protocol change.'],
           ['Key lineage and versioning',
            'Replacement keys linked to predecessors so data can be traced to the key '
            'that protected it.',
            'full',
            'Link_ReplacementKey / Link_ReplacedKey, identical for client-driven and '
            'scheduled rotation.'],
           ['Algorithm breadth',
            'AES, RSA, EC, and the curve and hash families an enterprise estate '
            'actually uses.',
            'partial',
            '15 of 40 KMIP algorithms work on this token. The shim probes and gates; a '
            'richer token activates more with no code change.'],
           ['Post-quantum (ML-KEM, ML-DSA, SLH-DSA)',
            'FIPS 203/204/205 support, now the leading procurement question.',
            'gap',
            "Needs both halves: a PQC token (SoftHSM's ML-DSA/ML-KEM work is in the "
            'development tree, not in any release) and KMIP 3.0, whose CSD02 adds the '
            'algorithms plus Encapsulate/Decapsulate. Vendor-range enums would work '
            'but interoperate with nothing.'],
           ['Hardware RNG',
            'Entropy from certified hardware, exposed to clients.',
            'full',
            "RNGRetrieve and RNGSeed draw from the token. Certification is the token's "
            "property, not this code's."],
           ['Key derivation',
            'Derive keys from existing material without exposing either.',
            'full',
            'DeriveKey, performed inside the token.'],
           ['Key wrapping / secure import-export',
            'Move keys between systems without ever seeing plaintext.',
            'full',
            'AES key wrap, and a wrapped Get via KeyWrappingSpecification.'],
           ['Split knowledge / M-of-N shares',
            'Key material split so no one custodian can reconstruct it.',
            'partial',
            'XOR only, and strictly N-of-N. Shamir threshold sharing would slot into '
            'the existing SplitKeyMethod enum — inside KMIP.'],
           ['Formal key ceremony',
            'Scripted, witnessed, attested generation for root keys.',
            'gap',
            '@@OUT@@A ceremony runbook plus signed kmip-admin transcripts. The '
            'cryptographic primitive already exists as dual control; what is missing '
            'is the procedure and its evidence.'],
           ['Bulk and batch operations',
            'Many operations per round trip, for provisioning at scale.',
            'partial',
            'Batching works, atomicity does not — a mid-batch failure leaves earlier '
            'items applied. KMIP defines no rollback, so all-or-nothing would be a '
            'local transaction around the dispatcher.'],
           ['Verifiable destruction',
            'Zeroization on the token, evidenced.',
            'full',
            'Destroy zeroizes the PKCS#11 object; the audit row survives to resolve '
            'the identifier.']]},
 {'name': 'Protocol and ecosystem integration',
  'rows': [['KMIP server',
            'The interoperability baseline every enterprise KMS ships.',
            'full',
            '41 of 53 KMIP 2.1 operations; the other 12 are session, async and vendor '
            'operations.'],
           ['KMIP interoperability certification',
            "Demonstrated interop against other vendors' clients and servers.",
            'gap',
            'OASIS conformance test cases are mapped in the suite, but the project has '
            'never been through an interop event. This is testing and process, not new '
            'code.'],
           ['KMIP 3.0',
            'The current specification line, and where PQC lives.',
            'gap',
            'Enum and operation additions on top of 2.1. Substantial but entirely '
            'in-protocol.'],
           ['PKCS#11 provider for applications',
            'Applications that speak PKCS#11 — databases, Java keystores — plugging '
            'straight in.',
            'gap',
            '@@OUT@@This project consumes PKCS#11; it does not expose it. The route is '
            'a thin PKCS#11 library that fronts the KMIP server, which is how '
            'commercial products serve both interfaces.'],
           ['REST / JSON API',
            'Developer-facing API alongside KMIP; universal in the market.',
            'gap',
            '@@OUT@@KMIP defines no REST binding. An HTTP facade over the existing '
            'dispatcher would reuse identity, RBAC and audit unchanged. This is the '
            'highest-leverage single gap on the page.'],
           ['Cloud BYOK (AWS, Azure, GCP)',
            'Generate on-premise, import into a cloud KMS, keep custody of the source.',
            'gap',
            "@@OUT@@Per-cloud connectors calling each provider's import API. Nothing "
            'in KMIP describes this.'],
           ['Cloud EKM / XKS / hold-your-own-key',
            'Cloud services calling back to your KMS for every operation.',
            'gap',
            '@@OUT@@Implement the AWS XKS proxy API or the GCP EKM API as HTTP '
            'services in front of the same store.'],
           ['Database TDE integration',
            'Oracle, SQL Server, MongoDB, Db2 taking keys from the KMS.',
            'partial',
            'These speak KMIP, so the path exists — but none has been tested against '
            'this server. The work is profile conformance and vendor validation, not '
            'new protocol.'],
           ['Storage, backup and VM integrations',
            'VMware, NetApp, Veeam, tape libraries.',
            'partial',
            'Same position as database TDE: KMIP-capable, unvalidated.'],
           ['Secrets management',
            'Arbitrary secrets with versioning, leases and dynamic issuance.',
            'partial',
            'SecretData objects and ObtainLease cover static custody. @@OUT@@ A '
            'Vault-style secrets engine — dynamic credentials, templating — is a '
            'different product surface.'],
           ['Tokenization / format-preserving encryption',
            'FPE for PAN and PII, common in payments deployments.',
            'gap',
            '@@OUT@@Neither a KMIP operation nor typically a token mechanism. A '
            'separate service implementing FF1/FF3 with keys held here.'],
           ['Certificate lifecycle',
            'CA issuance, CSR handling, renewal, revocation checking.',
            'partial',
            'Certify, ReCertify and Validate exist but issue self-signed certificates '
            'only, with no CRL or OCSP. A real PKI means fronting a CA such as EJBCA; '
            "KMIP's Certify was never a CA."]]},
 {'name': 'Identity and access control',
  'rows': [['Per-identity authentication',
            'Individually revocable credentials; no shared secret.',
            'full',
            'Salted scrypt credentials, verified per request, with a short-lived cache '
            'for successes only.'],
           ['Enterprise IdP — LDAP/AD, SAML, OIDC',
            'Users and services authenticating against the corporate directory.',
            'gap',
            "@@OUT@@KMIP's Credential structure has no federation concept. Map at the "
            'edge: an OIDC-validating front door, or directory-backed identities in '
            'the store. The mTLS path already proves the pattern — an external '
            'assertion resolved to a provisioned identity.'],
           ['mTLS certificate identity',
            'Client certificates as principals.',
            'full',
            'A verified CN is accepted only when it names a provisioned identity — a '
            'CA-signed certificate cannot invent a principal.'],
           ['API keys / service accounts',
            'Long-lived machine credentials distinct from human logins.',
            'gap',
            'A new Credential type, or token identities in the store. Partly '
            'expressible in KMIP, mostly local.'],
           ['Role-based access control',
            'Operations restricted by role.',
            'full',
            'Roles with opt-in per-operation allowlists.'],
           ['Groups',
            'Access following team membership rather than per-person grants.',
            'full',
            'Grants may name group:<name>; leaving the group withdraws access.'],
           ['Per-object access grants',
            'Delegation of one key to one principal.',
            'full',
            'read / full permission levels per object.'],
           ['Attribute or policy-based access',
            'Conditions on time, network, purpose; a policy engine.',
            'gap',
            '@@OUT@@A policy evaluation hook in the dispatcher, before the handler — '
            'the same insertion point dual control already uses.'],
           ['Dual control / quorum approval',
            'Destructive or disclosing operations need M-of-N sign-off.',
            'full',
            'Destroy and Export refuse on first attempt; approval is out of band, the '
            'requester can never self-approve, and an approval is spent by one '
            'attempt.'],
           ['Separation of duties',
            'Key administrators cannot use the keys they administer.',
            'partial',
            'The admin role currently bypasses every check. Splitting it into '
            'security-admin and key-admin is local work with no protocol impact.'],
           ['Multi-tenancy and namespaces',
            'Unrelated tenants sharing a deployment without seeing each other.',
            'gap',
            '@@OUT@@Object names, Locate results, audit and quotas are all global. A '
            'tenant boundary reaches into every query, the audit log and the CLI — a '
            'phase of work, not a flag. Isolation today means one deployment per '
            'tenant.'],
           ['Per-tenant quotas',
            'Caps on objects and operations.',
            'gap',
            '@@OUT@@Follows tenancy; meaningless before it.'],
           ['Connection and rate limiting',
            'Throttling and connection caps as DoS protection.',
            'gap',
            '@@OUT@@The listener takes a backlog of 16 with no throttle. A bounded '
            'connection semaphore plus per-identity rate limiting, or a reverse proxy '
            'in front.']]},
 {'name': 'Audit, compliance and assurance',
  'rows': [['Tamper-evident audit log',
            'Every operation attributable, with tampering detectable.',
            'full',
            'Hash-chained and trigger-protected; the verifier names the exact broken '
            'row. Reads are recorded too.'],
           ['External audit anchoring',
            'Evidence that survives an attacker with file access.',
            'gap',
            '@@OUT@@Ship entries to an append-only collector, or notarize periodic '
            'digests. A consistent rewrite of the whole local log currently leaves no '
            'trace.'],
           ['SIEM integration',
            'Syslog/CEF to Splunk, Sentinel, QRadar.',
            'gap',
            '@@OUT@@A syslog handler, or a shipper reading kmip-admin audit list '
            '--json. Small work, and it is what auditors ask for first.'],
           ['Retention and archival',
            'Aged entries archived, not silently dropped.',
            'full',
            'Pruning returns what it removes and refuses to run on a log that already '
            'fails verification.'],
           ['FIPS 140-2/3 validated HSM',
            'Validated hardware, frequently a procurement gate.',
            'gap',
            'Not an engineering task. SoftHSM2 is not validated; the PKCS#11 boundary '
            'makes swapping in a validated token cheap, but the validation belongs to '
            'the token.'],
           ['Common Criteria / eIDAS',
            'Certification for regulated European deployments.',
            'gap',
            'As above — a property of the chosen token and of a certification '
            'programme.'],
           ['Compliance reporting',
            'PCI DSS, GDPR, HIPAA evidence packs.',
            'gap',
            '@@OUT@@A reporting layer over the audit log and key inventory. Depends on '
            'the REST API to be useful.'],
           ['Key inventory and discovery',
            'What keys exist, who owns them, what state they are in.',
            'partial',
            'Locate answers this over the wire and kmip-admin can list, but there is '
            'no inventory report or export.'],
           ['Cryptoperiod policy alignment',
            'Demonstrable NIST SP 800-57 lifecycle handling.',
            'full',
            'Deactivation Date as the cryptoperiod, enforced and audited.'],
           ['Crypto-agility reporting',
            'Which algorithms are in use and where, for migration planning.',
            'partial',
            'The capability probe knows what the token supports and every object '
            'records its algorithm; nothing surfaces it as a report.']]},
 {'name': 'Availability, scale and recovery',
  'rows': [['HA clustering',
            'Active/active nodes behind a VIP, no single point of failure.',
            'gap',
            '@@OUT@@The blocker is storage, not protocol: SQLite has no multi-writer '
            'story. Postgres plus leader election for the scheduler.'],
           ['Multi-site replication and DR',
            'Geographic redundancy with a defined RPO.',
            'gap',
            '@@OUT@@Follows the storage backend.'],
           ['HSM failover and pooling',
            'Survive the loss of one token; spread load across several.',
            'gap',
            'A pool at the shim layer. Deliberately unbuilt — verifying it needs a '
            'second token, and an untested failover path invites reliance.'],
           ['Horizontal throughput',
            'Scale with cores and nodes.',
            'partial',
            'Pre-fork workers give about 1.5×, bounded by the serial audit chain — the '
            'measured cost of tamper-evidence. Per-shard chains or an external '
            'append-only service would lift it.'],
           ['Enterprise database backend',
            'Postgres or Oracle rather than an embedded file.',
            'gap',
            'The store is heavily SQLite-specific (PRAGMA user_version, json_extract, '
            'RAISE(ABORT) triggers), so this is a persistence-layer rewrite.'],
           ['Scheduled and offsite backup',
            'Automatic snapshots shipped off the box.',
            'partial',
            'Backup and restore are fully tooled and verified; scheduling and shipping '
            'are left to cron and the operator.'],
           ['Restore that proves itself',
            'A restore verified, not assumed.',
            'full',
            'Checks the master key is present, the audit chain verifies, and a stored '
            'secret actually decrypts. Token pairing is enforced.'],
           ['Zero-downtime certificate rotation',
            'Renew TLS material without dropping connections.',
            'full',
            'SIGHUP reload; systemctl reload costs nothing.'],
           ['Rolling upgrades',
            'Version-to-version upgrade without data loss.',
            'full',
            'Versioned migrations gated on PRAGMA user_version, each committing with '
            'its bump so an interrupted upgrade resumes. Single-node only.'],
           ['Kubernetes / container deployment',
            'A supported image and manifests.',
            'partial',
            'A two-stage Dockerfile exists and its inputs are checked, but it has '
            'never been executed — this environment blocks Docker Hub. No Helm chart '
            'or operator.']]},
 {'name': 'Operations and observability',
  'rows': [['Health and readiness probes',
            'Orchestrator-grade liveness and readiness.',
            'full',
            'Readiness gates on the listener as well as the HSM and database, so '
            'traffic is not routed at a port that is not open.'],
           ['Metrics',
            'Prometheus-compatible operational telemetry.',
            'full',
            'Operation counters, latency totals and auth failures. Latency is a '
            'running total rather than histogram buckets, and only worker 0 serves the '
            'endpoint, so quantiles and fleet totals need the collector.'],
           ['Structured logging',
            'Machine-parseable logs that survive aggregation.',
            'full',
            'JSON with tracebacks in a field rather than trailing newlines.'],
           ['Configuration-driven deployment',
            'A config file and a service unit, not a program to maintain.',
            'full',
            'One YAML file, strict validation naming the offending key, and --check to '
            'validate without serving.'],
           ['Administrative CLI',
            'Scriptable administration.',
            'full',
            'kmip-admin covers identities, roles, groups, grants, permissions, '
            'approvals, cryptoperiods, audit, backup and master-key rotation.'],
           ['Web console',
            'A GUI for operators and auditors — universal in commercial products.',
            'gap',
            '@@OUT@@Needs the REST admin API first; the console is then a client of '
            'it.'],
           ['Self-service developer portal',
            'Teams provisioning their own keys within policy.',
            'gap',
            '@@OUT@@Follows the console and tenancy.'],
           ['Alerting',
            'Expiry and anomaly alerts pushed to on-call.',
            'partial',
            'Approaching expiry is logged and audited, and counters are exported, but '
            'nothing pushes. Alertmanager rules over the existing metrics would close '
            'most of it.']]},
 {'name': 'Platform hardening',
  'rows': [['TLS enforced by default',
            'No accidental plaintext.',
            'full',
            'Refuses to start in the clear without an explicit opt-out that warns and '
            'names the address. TLS 1.2 floor.'],
           ['Metadata encrypted at rest',
            'A stolen database yields nothing.',
            'full',
            'AES-256-GCM envelopes under a non-extractable HSM master key, with a '
            'post-upgrade scrub that reaches the WAL sidecar.'],
           ['Master key rotation',
            'Re-key the protection layer without downtime or data loss.',
            'full',
            'Row-by-row re-encryption; a partly rotated store stays readable and the '
            'old key is destroyed only after the last row moves.'],
           ['Non-extractable key enforcement',
            'Keys that cannot be read out, enforced by hardware.',
            'full',
            'Set on the token, so it holds regardless of what this server believes.'],
           ['Request bounds and DoS resistance',
            'Hostile input cannot exhaust the server.',
            'partial',
            'Request size is capped before the body is read, the TLS handshake is off '
            'the accept loop under a timeout, and TTLV nesting is bounded — but there '
            'is still no connection cap or rate limit.'],
           ['Secrets kept out of configuration',
            'Credentials from a secrets manager, not a file in git.',
            'full',
            'PIN from file or environment; inline works, warns at every start, and is '
            'redacted from any config dump.'],
           ['Hardened service',
            'Least privilege at the OS level.',
            'full',
            'systemd unit with no capabilities, strict filesystem protection, syscall '
            'filtering and a dedicated user.']]}]


# ── helpers ───────────────────────────────────────────────────────────────────

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
    p.paragraph_format.left_indent = Inches(0.3)
    run = p.add_run(text)
    run.font.size = Pt(size)
    return p


def section_break(doc):
    doc.add_paragraph()


def header_row(table, headers, bg="1A3A5C"):
    for i, h in enumerate(headers):
        cell = table.rows[0].cells[i]
        cell.text = h
        set_cell_bg(cell, bg)
        for para in cell.paragraphs:
            for run in para.runs:
                run.bold = True
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                run.font.size = Pt(8.5)


def simple_table(doc, headers, rows, widths=None):
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


def route_cell(cell, text):
    """Render a route, lifting the 'Outside KMIP' marker into a coloured lead-in
    so the rows that cannot be solved in-protocol are visible at a glance."""
    para = cell.paragraphs[0]
    if OUT in text:
        lead = para.add_run("Outside KMIP — ")
        lead.bold = True
        lead.font.size = Pt(8.5)
        lead.font.color.rgb = MID_BLUE
        text = text.replace(OUT, "").strip()
    run = para.add_run(text)
    run.font.size = Pt(8.5)


def matrix_table(doc, rows):
    tbl = doc.add_table(rows=1, cols=4)
    tbl.style = "Table Grid"
    header_row(tbl, ["Feature", "What the market expects", "Status",
                     "Route, if not covered here"])
    for i, (feature, expects, status, route) in enumerate(rows):
        row = tbl.add_row()
        shade = "EEF4FA" if i % 2 == 0 else "FFFFFF"

        c0 = row.cells[0]
        r0 = c0.paragraphs[0].add_run(feature)
        r0.bold = True
        r0.font.size = Pt(8.5)
        set_cell_bg(c0, shade)

        c1 = row.cells[1]
        r1 = c1.paragraphs[0].add_run(expects)
        r1.font.size = Pt(8.5)
        set_cell_bg(c1, shade)

        c2 = row.cells[2]
        r2 = c2.paragraphs[0].add_run(STATUS_LABEL[status])
        r2.bold = True
        r2.font.size = Pt(8.5)
        r2.font.color.rgb = STATUS_COLOUR[status]
        set_cell_bg(c2, STATUS_FILL[status])

        c3 = row.cells[3]
        route_cell(c3, route)
        set_cell_bg(c3, shade)

    for row in tbl.rows:
        for cell, w in zip(row.cells, (1.25, 1.85, 0.7, 2.7)):
            cell.width = Inches(w)
    return tbl


def validate():
    """The matrix data is long and was machine-extracted, so a malformed edit is
    easy to make and hard to see in a 74-row literal. Fail loudly here rather
    than emitting a document with a blank cell or a silently dropped row."""
    seen = set()
    for domain in DOMAINS:
        if not domain.get("name") or not domain.get("rows"):
            raise ValueError(f"domain missing a name or rows: {domain!r}")
        for row in domain["rows"]:
            if len(row) != 4:
                raise ValueError(
                    f"{domain['name']}: expected 4 fields, got {len(row)}: {row!r}")
            feature, expects, status, route = row
            if status not in STATUS_LABEL:
                raise ValueError(f"{feature}: unknown status {status!r}")
            if not feature.strip() or not expects.strip() or not route.strip():
                raise ValueError(f"{feature!r}: an empty cell would print blank")
            if status == "full" and OUT in route:
                raise ValueError(
                    f"{feature!r}: marked covered but its route says outside KMIP")
            if feature in seen:
                raise ValueError(f"duplicate feature: {feature!r}")
            seen.add(feature)


def tally(rows):
    counts = {"full": 0, "partial": 0, "gap": 0}
    for r in rows:
        counts[r[2]] += 1
    return counts


def totals():
    counts = {"full": 0, "partial": 0, "gap": 0}
    outside = 0
    for domain in DOMAINS:
        for r in domain["rows"]:
            counts[r[2]] += 1
            if OUT in r[3]:
                outside += 1
    counts["outside"] = outside
    counts["total"] = counts["full"] + counts["partial"] + counts["gap"]
    return counts


# ══════════════════════════════════════════════════════════════════════════════
# Document build
# ══════════════════════════════════════════════════════════════════════════════

def build():
    validate()
    doc = Document()
    for sec in doc.sections:
        sec.top_margin = Inches(0.9)
        sec.bottom_margin = Inches(0.9)
        sec.left_margin = Inches(1.0)
        sec.right_margin = Inches(1.0)
    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(10)

    t = totals()

    # ── title page ───────────────────────────────────────────────────────
    doc.add_paragraph()
    doc.add_paragraph()
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    tr = title.add_run("KMIP on PKCS#11")
    tr.bold = True
    tr.font.size = Pt(28)
    tr.font.color.rgb = DARK_BLUE

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sr = sub.add_run("Enterprise KMS Gap Matrix")
    sr.font.size = Pt(17)
    sr.font.color.rgb = MID_BLUE

    sub2 = doc.add_paragraph()
    sub2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sr2 = sub2.add_run("Market requirements, coverage, and the route for every gap")
    sr2.font.size = Pt(12)
    sr2.font.color.rgb = DARK_GREY
    doc.add_paragraph()

    info = [
        ("Document", "Requirements assessment against the commercial KMS market"),
        ("Assessed at", f"{ASSESSED_AT} — {TEST_COUNT} tests green"),
        ("Requirements from", "Thales CipherTrust Manager, Entrust KeyControl, "
                              "Fortanix DSM, Utimaco ESKM, AWS/Azure/GCP KMS; "
                              "NIST SP 800-57 and SP 800-152"),
        ("Features assessed", f"{t['total']} across {len(DOMAINS)} domains"),
        ("Result", f"{t['full']} covered · {t['partial']} partial · {t['gap']} not "
                   f"covered · {t['outside']} need work outside KMIP"),
        ("Date", TODAY),
    ]
    tbl = doc.add_table(rows=len(info), cols=2)
    tbl.style = "Table Grid"
    for i, (k, v) in enumerate(info):
        tbl.rows[i].cells[0].text = k
        tbl.rows[i].cells[1].text = v
        tbl.rows[i].cells[0].width = Inches(1.4)
        tbl.rows[i].cells[1].width = Inches(5.1)
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

    # ── 1  how to read ───────────────────────────────────────────────────
    add_heading(doc, "1  How to read this document", 1, DARK_BLUE)
    add_para(doc,
        "This is a buy-or-build assessment, not a feature advertisement. Each row names "
        "something a high-end key management platform is expected to do, says whether "
        "this project does it, and — where it does not — names the route that would "
        "actually close the gap.")
    section_break(doc)

    add_para(doc, "The four verdicts", bold=True, colour=MID_BLUE)
    simple_table(doc,
        ["Verdict", "Means"],
        [
            ["Covered", "The capability exists and was demonstrated against a live "
                        "token, with regression tests in the suite. It does not mean "
                        "it matches a commercial product feature-for-feature at "
                        "enterprise scale."],
            ["Partial", "Something real is there, but an enterprise buyer would find a "
                        "named limit. The route column says what the limit is."],
            ["Not covered", "Absent. The route column says what building it would "
                            "involve."],
            ["Outside KMIP", "Not a verdict but a marker on the route: this gap cannot "
                             "be closed by writing more KMIP, because the specification "
                             "defines nothing for it."],
        ],
        widths=[1.2, 5.3])
    section_break(doc)

    add_para(doc,
        "That last marker is the most useful thing on the page. KMIP standardises key "
        "objects and the operations on them — it does not standardise the service "
        "around them. Identity federation, tenancy, quorum workflow, reporting, cloud "
        "key import and SIEM export have no wire representation at all, which is why "
        "every commercial product bolts a REST administration plane onto its KMIP "
        "server. A KMIP layer is an interoperability surface, not a product.")
    section_break(doc)
    add_para(doc,
        "Where a row says a capability belongs to the token rather than to this code — "
        "FIPS validation, certified entropy — that is a procurement decision, not an "
        "engineering backlog item, and is marked as such rather than quietly counted as "
        "a gap this project could close.", italic=True, size=9)
    doc.add_page_break()

    # ── 2  summary ───────────────────────────────────────────────────────
    add_heading(doc, "2  Summary", 1, DARK_BLUE)
    add_para(doc,
        f"{t['total']} features were assessed. {t['full']} are covered, {t['partial']} "
        f"partially, and {t['gap']} are not covered at all. Of everything short of full "
        f"coverage, {t['outside']} cannot be reached through the KMIP protocol.")
    section_break(doc)

    rows = []
    for domain in DOMAINS:
        c = tally(domain["rows"])
        rows.append([domain["name"], str(len(domain["rows"])), str(c["full"]),
                     str(c["partial"]), str(c["gap"])])
    rows.append(["TOTAL", str(t["total"]), str(t["full"]), str(t["partial"]),
                 str(t["gap"])])
    simple_table(doc,
        ["Domain", "Features", "Covered", "Partial", "Not covered"],
        rows,
        widths=[2.9, 0.9, 0.9, 0.9, 0.9])
    section_break(doc)

    add_para(doc, "Where the project is strong", bold=True, colour=MID_BLUE)
    add_para(doc,
        "The cryptographic core and the platform hardening are close to complete, and "
        "several parts are done properly rather than nominally: the restore procedure "
        "proves a stored secret actually decrypts rather than assuming it, dual control "
        "is enforced in the store so the requester cannot self-approve however the "
        "approval arrives, and the audit chain names the exact row when verification "
        "fails.")
    section_break(doc)

    add_para(doc, "Where it is weak", bold=True, colour=MID_BLUE)
    add_para(doc,
        "Everything that makes a key server into a product an enterprise buys: no REST "
        "API, no console, no directory integration, no tenancy, no clustering, and no "
        "validated hardware. None of these are cryptographic shortcomings. They are the "
        "service around the cryptography, and that is a different body of work.")
    doc.add_page_break()

    # ── 3..n  the matrix, one section per domain ─────────────────────────
    for i, domain in enumerate(DOMAINS, start=3):
        c = tally(domain["rows"])
        add_heading(doc, f"{i}  {domain['name']}", 1, DARK_BLUE)
        add_para(doc,
            f"{len(domain['rows'])} features — {c['full']} covered, {c['partial']} "
            f"partial, {c['gap']} not covered.", italic=True, size=9,
            colour=DARK_GREY)
        matrix_table(doc, domain["rows"])
        doc.add_page_break()

    # ── priorities ───────────────────────────────────────────────────────
    n = len(DOMAINS) + 3
    add_heading(doc, f"{n}  What to build first", 1, DARK_BLUE)
    add_para(doc,
        "Ordered by how much each unlocks, not by how visible it is.")
    section_break(doc)

    priorities = [
        ("A REST administration API",
         "The highest-leverage single item on the page. A web console, a self-service "
         "portal, compliance reporting, SIEM-friendly export and most integrations are "
         "all clients of an API that does not exist yet — five separate gaps collapse "
         "into one piece of work. It would reuse the existing identity, RBAC and audit "
         "layers unchanged, because those already sit below the protocol rather than "
         "inside it."),
        ("SIEM export",
         "Small work, and the thing auditors ask for first. A syslog handler, or a "
         "shipper reading the existing JSON audit output. It does not need the REST API "
         "to be useful."),
        ("Connection and rate limiting",
         "The listener still takes a backlog of sixteen with no throttle, which is a "
         "denial-of-service exposure rather than a missing feature. A bounded "
         "connection semaphore and per-identity rate limiting, or a reverse proxy in "
         "front of it."),
        ("A PostgreSQL storage backend",
         "The blocker beneath clustering, replication and disaster recovery — none of "
         "which are protocol problems. SQLite has no multi-writer story, and the store "
         "is heavily SQLite-specific, so this is a persistence-layer rewrite rather than "
         "a driver swap."),
        ("Multi-tenancy",
         "A phase of work, not a flag: object names, Locate results, the audit log, "
         "quotas and the administrative CLI all assume a single tenant. Worth doing only "
         "once there is a second tenant to serve; until then, one deployment per tenant "
         "is a legitimate answer."),
        ("Post-quantum readiness",
         "Needs both halves and neither is here yet. A token that implements ML-KEM and "
         "ML-DSA — SoftHSM2's work is in its development tree, not in any release — and "
         "KMIP 3.0, whose draft adds the algorithms plus Encapsulate and Decapsulate. "
         "Vendor-range enumerations would work locally and interoperate with nothing, "
         "which is worse than waiting."),
    ]
    for title_text, body_text in priorities:
        add_para(doc, title_text, bold=True, colour=MID_BLUE)
        add_para(doc, body_text, size=9.5)
        section_break(doc)

    add_para(doc,
        "Two items are deliberately absent from this list. FIPS 140-3 and Common "
        "Criteria validation belong to the token, so the work is procurement and "
        "testing rather than development. And HSM failover is unbuilt for a reason "
        "already recorded elsewhere in this project's documentation: verifying it needs "
        "a second token, and an untested failover path invites exactly the reliance it "
        "cannot support.", italic=True, size=9)
    doc.add_page_break()

    # ── sources ──────────────────────────────────────────────────────────
    add_heading(doc, f"{n + 1}  Sources", 1, DARK_BLUE)
    add_para(doc,
        "The requirement list was assembled from vendor capability documentation and "
        "the two NIST publications that define what a key management system owes its "
        "operator. The coverage column comes from this repository.")
    section_break(doc)
    simple_table(doc,
        ["Source", "Used for"],
        [
            ["Thales CipherTrust Manager",
             "Clustering, multi-tenancy, REST API, key lifecycle scope."],
            ["Fortanix Data Security Manager",
             "Quorum approval, BYOK, cloud EKM/XKS, tokenization."],
            ["Entrust KeyControl, Utimaco ESKM",
             "Enterprise deployment expectations, HA and DR framing."],
            ["AWS KMS, Azure Key Vault Managed HSM, GCP Cloud KMS",
             "External key store patterns, cloud integration surface."],
            ["OASIS KMIP 2.1 and the KMIP 3.0 draft",
             "Protocol scope, and what the protocol deliberately leaves out."],
            ["NIST SP 800-57 Part 1",
             "Key lifecycle states and cryptoperiod expectations."],
            ["NIST SP 800-152 (CKMS profile)",
             "Backup, recovery and audit requirements."],
            ["This repository at " + ASSESSED_AT,
             "Every entry in the coverage and route columns."],
        ],
        widths=[2.4, 4.1])
    section_break(doc)
    add_para(doc,
        "This document is generated. Re-run generate_kms_gap_matrix.py after closing a "
        "gap, and update ASSESSED_AT at the top of that file so a reader can tell "
        "whether the coverage column still describes the code.", italic=True, size=9)

    section_break(doc)
    f = doc.add_paragraph()
    f.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fr = f.add_run(f"KMIP on PKCS#11 — Enterprise KMS Gap Matrix — {TODAY}")
    fr.font.size = Pt(8)
    fr.font.color.rgb = RGBColor(0x80, 0x80, 0x80)

    out = "KMIP_PKCS11_KMS_Gap_Matrix.docx"
    doc.save(out)
    print(f"Saved: {out}  ({t['total']} features: {t['full']} covered, "
          f"{t['partial']} partial, {t['gap']} gap, {t['outside']} outside KMIP)")


if __name__ == "__main__":
    build()
