"""
Generate the phase execution report — what the production-hardening programme
set out to do, and what phases 0 through 5 actually delivered.

Run: python generate_phase_report.py

Written to be regenerable like the other three project documents, and to be
honest in the same way: each phase records the gate it had to meet, what was
found while meeting it, and what was deliberately left undone.
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
PASS_GREEN = RGBColor(0x1E, 0x80, 0x2E)
WARN_AMBER = RGBColor(0x8F, 0x56, 0x10)

TODAY = datetime.date.today().strftime("%d %B %Y")


# ── helpers ───────────────────────────────────────────────────────────────────

def set_cell_bg(cell, hex_color: str):
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


def add_para(doc, text="", bold=False, italic=False, size=10, colour=None, indent=0):
    p = doc.add_paragraph()
    if indent:
        p.paragraph_format.left_indent = Inches(indent * 0.25)
    run = p.add_run(text)
    run.bold = bold
    run.italic = italic
    run.font.size = Pt(size)
    if colour:
        run.font.color.rgb = colour
    return p


def add_code(doc, text):
    p = doc.add_paragraph(style="No Spacing")
    p.paragraph_format.left_indent = Inches(0.3)
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    run = p.add_run(text)
    run.font.name = "Courier New"
    run.font.size = Pt(8.5)
    run.font.color.rgb = RGBColor(0x00, 0x33, 0x66)
    return p


def add_bullet(doc, text, level=0):
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.left_indent = Inches(0.3 + level * 0.25)
    run = p.add_run(text)
    run.font.size = Pt(10)
    return p


def section_break(doc):
    doc.add_paragraph()


def add_table_header_row(table, headers, bg="1A3A5C"):
    for i, h in enumerate(headers):
        cell = table.rows[0].cells[i]
        cell.text = h
        set_cell_bg(cell, bg)
        for para in cell.paragraphs:
            for run in para.runs:
                run.bold = True
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                run.font.size = Pt(9)


def add_table_row(table, values, alt=False):
    row = table.add_row()
    bg = "EEF4FA" if alt else "FFFFFF"
    for i, v in enumerate(values):
        cell = row.cells[i]
        cell.text = str(v)
        set_cell_bg(cell, bg)
        for para in cell.paragraphs:
            for run in para.runs:
                run.font.size = Pt(8.5)
    return row


def make_table(doc, headers, rows, widths=None):
    tbl = doc.add_table(rows=1, cols=len(headers))
    tbl.style = "Table Grid"
    add_table_header_row(tbl, headers)
    for i, r in enumerate(rows):
        add_table_row(tbl, r, alt=(i % 2 == 0))
    if widths:
        for row in tbl.rows:
            for cell, w in zip(row.cells, widths):
                cell.width = Inches(w)
    return tbl


def phase_banner(doc, number, title, commit, date, tests):
    """One consistent header block per phase, so the document can be skimmed
    phase by phase without reading the prose."""
    add_heading(doc, f"{number} \u2014 {title}", 1, DARK_BLUE)
    p = doc.add_paragraph()
    run = p.add_run(f"Commit {commit}   ·   {date}   ·   {tests}")
    run.font.name = "Courier New"
    run.font.size = Pt(8.5)
    run.font.color.rgb = MID_BLUE


def labelled(doc, label, text, colour=DARK_GREY, size=10):
    p = doc.add_paragraph()
    lr = p.add_run(f"{label}  ")
    lr.bold = True
    lr.font.size = Pt(size)
    lr.font.color.rgb = colour
    tr = p.add_run(text)
    tr.font.size = Pt(size)
    return p


# ══════════════════════════════════════════════════════════════════════════════
# Document build
# ══════════════════════════════════════════════════════════════════════════════

def build():
    doc = Document()

    for sec in doc.sections:
        sec.top_margin = Inches(1.0)
        sec.bottom_margin = Inches(1.0)
        sec.left_margin = Inches(1.2)
        sec.right_margin = Inches(1.2)

    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(10)

    # ══════════════════════════════════════════════════════════════════════
    # TITLE PAGE
    # ══════════════════════════════════════════════════════════════════════
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
    sr = sub.add_run("Production Hardening Programme")
    sr.font.size = Pt(17)
    sr.font.color.rgb = MID_BLUE

    sub2 = doc.add_paragraph()
    sub2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sr2 = sub2.add_run("Phases 0 – 5 · Execution Report")
    sr2.font.size = Pt(13)
    sr2.font.color.rgb = DARK_GREY

    doc.add_paragraph()

    info_lines = [
        ("Document",   "Phase execution report — plan, delivery and residual gaps"),
        ("Project",    "KMIP 2.1 server on PKCS#11 / SoftHSM2"),
        ("Programme",  "6 phases (0–5), all delivered"),
        ("Span",       "c8f3de7 (16 Aug 2026) → cf8460b (18 Aug 2026)"),
        ("Test suite", "624 → 811 tests, 100 % pass rate, live against a real token"),
        ("Date",       TODAY),
    ]
    info = doc.add_table(rows=len(info_lines), cols=2)
    info.style = "Table Grid"
    for i, (k, v) in enumerate(info_lines):
        info.rows[i].cells[0].text = k
        info.rows[i].cells[1].text = v
        info.rows[i].cells[0].width = Inches(1.5)
        info.rows[i].cells[1].width = Inches(4.7)
        set_cell_bg(info.rows[i].cells[0], "1A3A5C")
        for para in info.rows[i].cells[0].paragraphs:
            for run in para.runs:
                run.bold = True
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                run.font.size = Pt(9)
        for para in info.rows[i].cells[1].paragraphs:
            for run in para.runs:
                run.font.size = Pt(9)

    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    # 1. WHAT THIS DOCUMENT IS
    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "1  What this document is", 1, DARK_BLUE)
    add_para(doc,
        "A full review of the project produced twelve findings and a six-phase plan to "
        "take a working KMIP 2.1 server to something that could be run as a professional "
        "key management service. All six phases have now been executed. This document "
        "records, for each phase, the gate it had to meet, what was built, what running "
        "it revealed, and what was deliberately left undone.")
    section_break(doc)
    add_para(doc,
        "It is written to be checkable rather than reassuring. Where a phase found a "
        "defect — including defects introduced earlier in the same programme — that is "
        "recorded here rather than smoothed over, because a hardening report that only "
        "lists successes is not evidence of anything. Where something was scoped and not "
        "built, the reason is stated; \"deferred\" and \"done\" are never blurred together.")
    section_break(doc)

    add_para(doc, "The three governing rules of the programme:", bold=True)
    for rule in [
        "Every claim is verified by executing code, not by reading it. Several findings "
        "in this report exist only because something was run.",
        "A phase is finished when its gate is demonstrated, not when its code is written.",
        "Anything that could not be tested in this environment was not shipped as though "
        "it had been.",
    ]:
        add_bullet(doc, rule)
    section_break(doc)

    add_heading(doc, "1.1  Related documents", 2, MID_BLUE)
    make_table(doc,
        ["Document", "What it covers"],
        [
            ["README.md",
             "Current state of the system: features, access control, governance, "
             "configuration, limitations. The primary reference."],
            ["KMIP_PKCS11_Design_Document.docx",
             "Architecture and design rationale, including designs that were rejected "
             "and why."],
            ["KMIP_PKCS11_Project_Documentation.docx",
             "Module-by-module reference and full test specification."],
            ["KMIP_PKCS11_Install_Test_Guide.docx",
             "Installation, running the suite, and operational troubleshooting."],
            ["This document",
             "How the system got from the review to its current state — the programme "
             "narrative, phase by phase."],
        ],
        widths=[2.1, 4.1])
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    # 2. WHERE THE PROGRAMME STARTED
    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "2  Where the programme started", 1, DARK_BLUE)
    add_para(doc,
        "Before Phase 0 the project was a competent protocol implementation with a "
        "serious hole beneath it. Forty-one of fifty-three KMIP operations worked "
        "against a real token, the lifecycle state machine was complete, and 624 tests "
        "passed. What it did not have was a trustworthy answer to \"who is asking\".")
    section_break(doc)

    add_para(doc, "The two findings that set the shape of the plan:", bold=True)
    section_break(doc)

    labelled(doc, "Blocker —",
        "Identity was self-asserted. The username in a KMIP Credential was taken at "
        "face value and only the password was checked, against the single shared PKCS#11 "
        "token PIN. Any client holding that PIN could present as any user, including one "
        "carrying the admin role, so every ownership and grant decision downstream rested "
        "on an unauthenticated claim. Verified live: a second client claiming another "
        "user's name retrieved that user's keys.",
        colour=RGBColor(0xB3, 0x26, 0x1E))
    section_break(doc)
    labelled(doc, "Blocker —",
        "The admin role was honoured by the ownership check but ignored by Locate, which "
        "filtered on owner = identity unconditionally. An admin could therefore read any "
        "object but could not find one. This was a functional defect in previously "
        "shipped access-control work, not a design limitation.",
        colour=RGBColor(0xB3, 0x26, 0x1E))
    section_break(doc)

    add_para(doc,
        "The remaining findings covered an unbounded message read (an unauthenticated "
        "client could declare a 4 GiB frame), a TLS handshake performed inside the accept "
        "loop, the absence of any schema migration path, and a group of six smaller "
        "defects: no connection limiting, unbounded TTLV recursion, internal exception "
        "text returned to clients, a declared dependency imported nowhere, an under-pinned "
        "one the code could not actually run against, and ten tests that asserted nothing. "
        "Beyond the defects, whole capabilities were simply absent: nothing was encrypted "
        "at rest, there was no audit trail, TLS was optional, there was no way to deploy "
        "the thing without writing Python, and no backup existed.")
    section_break(doc)

    add_para(doc,
        "The plan grouped that work into six phases ordered by dependency, not by "
        "appetite: authentication first, because every later control rests on it; then "
        "secrets at rest; then audit and transport; then deployability; then survival; "
        "then governance. Each phase was given a gate — a demonstrable condition, not a "
        "checklist — and no phase was allowed to start before its predecessor's gate was "
        "met.")
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    # 3. PROGRAMME AT A GLANCE
    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "3  The programme at a glance", 1, DARK_BLUE)

    make_table(doc,
        ["Phase", "Theme", "Commit", "Tests", "Scope"],
        [
            ["0", "Stop the bleeding — authentication and hardening", "c8f3de7",
             "624 → 649", "8 files, +542"],
            ["1", "Make secrets actually secret — encryption at rest", "02134aa",
             "649 → 671", "6 files, +744"],
            ["2", "Audit and transport", "3d6c746",
             "671 → 701", "7 files, +725"],
            ["3", "Make it deployable — config, CLIs, observability", "5b5ffc9",
             "701 → 739", "15 files, +1512"],
            ["4", "Survive production — backup, workers, throughput", "46603ad",
             "739 → 763", "10 files, +1034"],
            ["5", "Governance — cryptoperiods, dual control, RBAC depth", "cf8460b",
             "763 → 811", "19 files, +1867"],
        ],
        widths=[0.5, 2.5, 0.8, 0.9, 1.5])
    section_break(doc)

    add_para(doc,
        "Six phases, 187 new tests, roughly 6,400 lines added. The test count is the more "
        "meaningful number of the two: every phase added regressions for the specific "
        "behaviour it introduced, so the suite is the reason each phase could be built on "
        "top of the last without re-verifying everything by hand.")
    section_break(doc)

    add_heading(doc, "3.1  Gate met, phase by phase", 2, MID_BLUE)
    make_table(doc,
        ["Phase", "The gate", "Demonstrated by"],
        [
            ["0", "An identity cannot be assumed by claiming it.",
             "Two identities with different passwords cannot reach each other's objects; "
             "the token PIN authenticates no one; an admin both finds and reads any "
             "object; a 4 GiB frame is refused before allocation; a stalled TLS client no "
             "longer blocks the listener."],
            ["1", "A stolen database file yields no key material.",
             "A copied .db exposes nothing; an upgraded deployment is scrubbed of its "
             "former cleartext, the -wal sidecar included; rotation preserves plaintext "
             "and a half-finished rotation still reads."],
            ["2", "Every operation is attributable and tampering is detectable.",
             "Every operation bar capability discovery is recorded, reads included; "
             "rewriting a denied Destroy as a success is detected at the exact row; the "
             "server refuses to start without TLS unless told to; an mTLS CN naming no "
             "provisioned identity gets nothing."],
            ["3", "An operator can deploy and run it without writing Python.",
             "kmip-server --config and kmip-admin run end to end; /health, /ready and "
             "/metrics serve real data. The container image and CI workflow are written "
             "but unexecuted — see Section 10."],
            ["4", "It can lose its database and come back.",
             "The database was deleted and restored to a working, decryptable secret; a "
             "mismatched token is refused. Throughput went 24 → 887 ops/sec."],
            ["5", "Rotation happens without a client asking, and destruction takes two "
             "people.",
             "A key past its cryptoperiod deactivates and rotates on a background scan; a "
             "Destroy under dual control is refused, the key survives, and it only "
             "proceeds after two other identities approve — verified over the wire."],
        ],
        widths=[0.5, 1.9, 3.8])
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 0
    # ══════════════════════════════════════════════════════════════════════
    phase_banner(doc, "4  Phase 0", "Stop the bleeding", "c8f3de7", "16 August 2026",
                 "649 tests green")
    section_break(doc)
    labelled(doc, "Objective —",
        "Close the six blocker findings. These were fixes to already-shipped code rather "
        "than new capability, which is why the phase is numbered zero: nothing else in "
        "the plan was worth building on top of an authentication layer that did not "
        "authenticate.")
    section_break(doc)

    add_para(doc, "Delivered", bold=True, colour=MID_BLUE)
    for item in [
        "Per-identity authentication. Identities now carry their own salted scrypt "
        "credential in a kmip_identities table, verified individually. An unprovisioned "
        "identity cannot authenticate at all. The token PIN authenticates the server to "
        "the HSM and nothing else.",
        "mTLS under the same rule: a certificate subject is trusted as an identity only "
        "when the certificate was actually required and verified, and only when it names "
        "a provisioned identity. A CA-signed certificate does not get to invent a "
        "principal that was never granted anything.",
        "The Locate admin defect fixed, with the regression test that should have "
        "existed when the feature was written.",
        "Transport hardening: the declared request size is capped before the body is "
        "read; the TLS handshake moved off the accept loop onto the worker thread under "
        "a timeout; TTLV structure nesting depth bounded.",
        "Error hygiene: internal exception text no longer reaches clients. Typed KMIP "
        "errors keep their useful messages; unexpected faults log a full traceback "
        "server-side and return only a reason code.",
        "Dependency cleanup: PyKCS11 dropped (imported nowhere) and python-pkcs11 pinned "
        "to the 0.9.x line the shim's call signatures actually require.",
    ]:
        add_bullet(doc, item)
    section_break(doc)

    add_para(doc, "Worth recording", bold=True, colour=WARN_AMBER)
    add_para(doc,
        "One of the six blockers was a defect introduced by earlier access-control work "
        "in this same codebase — the admin role honoured in one code path and ignored in "
        "another. It is included here rather than quietly fixed because it is the clearest "
        "argument in the whole programme for the rule that claims are verified by "
        "execution: the feature looked correct in both files, and only failed when an "
        "admin actually tried to find an object.")
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 1
    # ══════════════════════════════════════════════════════════════════════
    phase_banner(doc, "5  Phase 1", "Make secrets actually secret", "02134aa",
                 "17 August 2026", "671 tests green")
    section_break(doc)
    labelled(doc, "Objective —",
        "SecretData, OpaqueObject and SplitKey shares have no PKCS#11 object behind them, "
        "so their bytes sat in the metadata database in the clear. A copy of the database "
        "file exposed them outright, which no amount of access control compensates for.")
    section_break(doc)

    add_para(doc, "Delivered", bold=True, colour=MID_BLUE)
    for item in [
        "AES-256-GCM envelope encryption under a master key generated on, and never "
        "leaving, the HSM (non-extractable). Encryption is transparent — the store seals "
        "on write and unseals on read — so no operation handler changed.",
        "Certificates deliberately excluded: they are public, and encrypting them would "
        "make them unreadable without the token for no gain. Exclusion is by denylist "
        "rather than by allowlisting the secret types, so any object type added later is "
        "encrypted by default.",
        "Each envelope records which master key wrote it, which is what makes rotation "
        "safe: re-encrypting a large store is not atomic, so a partially rotated table "
        "legitimately holds both keys and stays fully readable, and re-running finishes "
        "the job. The superseded key is destroyed only after the last row moves.",
        "Versioned schema migrations, gated on PRAGMA user_version and applied in order, "
        "each committing with its version bump so an interrupted upgrade resumes. "
        "CREATE TABLE IF NOT EXISTS cannot add a column, so without this the new "
        "encryption flag would silently never appear on an existing deployment.",
    ]:
        add_bullet(doc, item)
    section_break(doc)

    add_para(doc, "What running it revealed", bold=True, colour=WARN_AMBER)
    add_para(doc,
        "The first implementation encrypted existing rows with an UPDATE, which does not "
        "erase what was there before. In WAL mode the original cleartext write survives "
        "in the -wal sidecar, so an upgraded deployment kept the very secrets it had just "
        "encrypted sitting in the clear beside the ciphertext. This was found by grepping "
        "the database files after the migration rather than by reasoning about it. The "
        "backfill now follows up with wal_checkpoint(TRUNCATE) and VACUUM, and a "
        "regression test greps every SQLite file for the plaintext.")
    section_break(doc)
    add_para(doc,
        "That scrub reaches the live database files only. Snapshots and backups taken "
        "before the upgrade are outside its reach and must be handled separately — stated "
        "in the documentation rather than left as an assumption.", italic=True, size=9)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 2
    # ══════════════════════════════════════════════════════════════════════
    phase_banner(doc, "6  Phase 2", "Audit and transport", "3d6c746",
                 "17 August 2026", "701 tests green")
    section_break(doc)
    labelled(doc, "Objective —",
        "The two things an auditor asks for first: a record of who did what, and a "
        "guarantee that it crossed the network encrypted.")
    section_break(doc)

    add_para(doc, "Delivered", bold=True, colour=MID_BLUE)
    for item in [
        "An audit record for every operation except Query and DiscoverVersions: identity, "
        "operation, object UID, result and reason, client address, timestamp. Reads are "
        "recorded too — \"who exported this key\" is a read, and is the question an audit "
        "log most needs to answer. Only capability discovery is skipped, because "
        "recording it would bury the entries that matter in handshake noise.",
        "Append-only two ways, because either alone is weak. SQLite triggers block UPDATE "
        "and DELETE outright, so application bugs and casual tampering fail loudly; and "
        "each row carries the SHA-256 of the one before it, so an attacker with file "
        "access who simply drops the triggers still leaves a broken chain that the "
        "verifier locates at the exact row.",
        "Appending takes a lock. The chain is read-then-write, and without the lock two "
        "concurrent requests link to the same predecessor and fork the history. There is "
        "a regression test that hammers it from eight threads.",
        "Retention via prune_audit() — the one sanctioned way past the triggers. It "
        "returns the removed entries so they can be archived, restores the trigger "
        "afterwards, and refuses to run on a log that already fails verification, since "
        "pruning a tampered log would destroy the evidence.",
        "TLS enforced by default: the server refuses to start in the clear unless "
        "explicitly told to, and says so with a warning naming the address when it does. "
        "TLS 1.2 floor, the SSLContext built once rather than per connection, and a "
        "reload that re-reads renewed certificates without disturbing established "
        "connections.",
    ]:
        add_bullet(doc, item)
    section_break(doc)

    add_para(doc, "Design note", bold=True, colour=MID_BLUE)
    add_para(doc,
        "An audit write that fails never fails the KMIP operation — but it logs an "
        "exception loudly. A silently unrecorded operation is exactly what an attacker "
        "would want, so the failure mode is deliberately noisy rather than silent.")
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 3
    # ══════════════════════════════════════════════════════════════════════
    phase_banner(doc, "7  Phase 3", "Make it deployable", "5b5ffc9",
                 "17 August 2026", "739 tests green")
    section_break(doc)
    labelled(doc, "Objective —",
        "Turn the project from a library you write Python against into something an "
        "operator can deploy. A deployment should be a configuration file and a service "
        "unit, not a program somebody has to write and maintain.")
    section_break(doc)

    add_para(doc, "Delivered", bold=True, colour=MID_BLUE)
    for item in [
        "Two console scripts. kmip-server runs from a YAML configuration (--check "
        "validates and exits); kmip-admin manages identities, roles, grants, the audit "
        "log and master-key rotation — none of which KMIP defines a wire operation for, "
        "so they had to be an out-of-band surface and were previously raw store calls.",
        "The token PIN read from a file (secrets manager, systemd LoadCredential) or the "
        "environment. Inline still works, because forbidding it outright just moves it "
        "somewhere worse, but it warns at every start and is redacted from any config "
        "dump.",
        "/health, /ready and /metrics on a separate management port, Prometheus "
        "exposition built from the standard library, operation counters and latency "
        "recorded at the dispatcher, and JSON logs that keep tracebacks in a field rather "
        "than trailing newlines so they survive aggregation.",
        "Deployment artifacts: an annotated config template, a systemd unit (SIGHUP "
        "reloads TLS, so a reload after certificate renewal costs no downtime), a "
        "two-stage Dockerfile, and a CI workflow.",
    ]:
        add_bullet(doc, item)
    section_break(doc)

    add_para(doc, "What running it revealed", bold=True, colour=WARN_AMBER)
    add_para(doc,
        "The readiness check was wrong, and it was wrong in the way that matters. It "
        "verified the HSM and the database but not the listener — and startup opens the "
        "HSM session, provisions the master key and converts cleartext blobs before it "
        "binds, which took 18 seconds on a token holding several thousand keys. /ready "
        "therefore reported ready while the KMIP port was still closed, which is precisely "
        "the moment an orchestrator routes traffic at you. Readiness is now gated on the "
        "listener actually accepting connections, with a regression test.")
    section_break(doc)
    add_para(doc,
        "A second finding, from building the container: the packaged SoftHSM2 build does "
        "not expose CKM_ECDSA_SHA256, so every EC signing test fails against it. The "
        "Dockerfile and CI therefore build SoftHSM2 from source against OpenSSL, and CI "
        "asserts the mechanism set before running the suite.")
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 4
    # ══════════════════════════════════════════════════════════════════════
    phase_banner(doc, "8  Phase 4", "Survive production", "46603ad",
                 "17 August 2026", "763 tests green")
    section_break(doc)
    labelled(doc, "Objective —",
        "Availability and recovery: be able to lose the database and come back, and stop "
        "being limited to one CPU.")
    section_break(doc)

    add_para(doc, "Delivered", bold=True, colour=MID_BLUE)
    for item in [
        "Online backup using SQLite's backup API — a cp of a live WAL database can "
        "capture a torn state — plus a manifest recording which token the snapshot "
        "belongs to. That pairing is the point: objects reference keys by CKA_ID and "
        "secret blobs are encrypted under a master key on the token, so a database "
        "restored beside a different HSM is not a degraded backup, it is unreadable.",
        "Restore refuses a mismatched token unless forced, and when the HSM is reachable "
        "it proves the result rather than assuming it: master key present, audit chain "
        "intact, and a stored secret actually decrypts.",
        "A pre-fork worker pool. A child inheriting an initialized PKCS#11 library is "
        "undefined behaviour, so the parent binds the socket and forks before any PKCS#11 "
        "call, and each child then opens its own session.",
        "Two things that had relied on in-process locks made cross-process safe first: "
        "audit appends now take a SQLite write lock up front (BEGIN IMMEDIATE), since a "
        "plain transaction locks only at the INSERT and left room for two processes to "
        "fork the chain; and master-key provisioning takes a filesystem lock, or every "
        "worker would mint its own key on a fresh token.",
    ]:
        add_bullet(doc, item)
    section_break(doc)

    add_para(doc, "What benchmarking revealed", bold=True, colour=WARN_AMBER)
    add_para(doc,
        "Something far larger than the worker model. KMIP carries the Credential in every "
        "request header, and Phase 0 verified it with scrypt each time — roughly 40 ms by "
        "design, since that cost is the point of scrypt. That capped a connection at about "
        "25 requests per second and let an unauthenticated client burn 40 ms of CPU per "
        "packet. Successful verifications are now cached briefly, keyed by a peppered hash "
        "of the password rather than the password itself; failures are never cached, so "
        "guessing still pays full cost, and password change, disable and delete all "
        "invalidate immediately.")
    section_break(doc)

    make_table(doc,
        ["Measurement", "Before", "After"],
        [
            ["Single worker, AES encrypt through the full stack", "24 ops/sec",
             "~600 ops/sec"],
            ["1 → 4 workers, 4 concurrent clients", "605 ops/sec", "887 ops/sec"],
            ["1 → 4 workers, 8 concurrent clients", "546 ops/sec", "829 ops/sec"],
        ],
        widths=[3.6, 1.3, 1.3])
    section_break(doc)
    add_para(doc,
        "Worker scaling is about 1.5×, not 4×. A hash chain is inherently serial, so every "
        "audited operation serialises on one database write lock. That is the price of the "
        "tamper-evidence bought in Phase 2, and it is documented as such rather than "
        "presented as linear scaling.")
    section_break(doc)
    add_para(doc, "Deliberately not built", bold=True, colour=WARN_AMBER)
    add_para(doc,
        "A PostgreSQL backend and HSM failover were both scoped for this phase and left "
        "out. The store is heavily SQLite-specific — PRAGMA user_version, json_extract, "
        "RAISE(ABORT) triggers — so a second backend is a substantial rewrite that cannot "
        "be tested without a Postgres instance, and failover needs a second token to "
        "verify against. Shipping either untested would have been worse than not shipping "
        "it.")
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 5
    # ══════════════════════════════════════════════════════════════════════
    phase_banner(doc, "9  Phase 5", "Governance and compliance", "cf8460b",
                 "18 August 2026", "811 tests green")
    section_break(doc)
    labelled(doc, "Objective —",
        "What distinguishes a key server from a key management service. Everything up to "
        "this point was reactive: a key became Deactivated because a client asked, and a "
        "Destroy ran because one identity was authorized to ask for it. This phase adds "
        "the part that acts without being asked, and the part that stops one person acting "
        "alone. Both are off by default.")
    section_break(doc)

    add_heading(doc, "9.1  Cryptoperiod enforcement", 2, MID_BLUE)
    add_para(doc,
        "KMIP defines no separate cryptoperiod attribute — the Deactivation Date is the "
        "end of the period — so this stays inside the standard attribute model and adds "
        "something that acts on it. Without that, a key with a two-year cryptoperiod stays "
        "Active into year five unless somebody remembers.")
    section_break(doc)
    for item in [
        "A background scan deactivates keys whose Deactivation Date has passed and warns "
        "as they approach it, so rotation is planned rather than discovered.",
        "With auto-rotation enabled it creates a replacement symmetric key cross-linked to "
        "the old one, exactly the lineage a client-driven ReKey produces, so downstream "
        "tooling does not need to tell them apart.",
        "Rotation runs before deactivation, so a replacement exists before the old key "
        "stops being usable. If rotation fails the key is deactivated anyway — an expired "
        "key left Active is the worse outcome.",
        "Every action is audited under the identity system:scheduler, so an automated "
        "deactivation is as attributable as a human one.",
        "In a multi-worker deployment only worker 0 runs the scan; otherwise workers race "
        "to deactivate the same keys.",
    ]:
        add_bullet(doc, item)
    section_break(doc)

    add_heading(doc, "9.2  Dual control", 2, MID_BLUE)
    add_para(doc,
        "Destroy zeroizes key material on the token; Export hands out key bytes. Under "
        "dual control neither executes on request: the first attempt is refused and "
        "records an approval request, enough other identities approve it out of band, and "
        "the requester retries. The check runs before the handler, so a blocked operation "
        "has no effect at all — the point of dual control is that the destructive step "
        "never happens without the second signature.")
    section_break(doc)
    add_para(doc, "The rules that make this dual control rather than paperwork:", bold=True)
    for item in [
        "An approver may never be the requester. This is enforced in the store rather "
        "than in the policy layer, so it holds however approvals are submitted.",
        "An approval authorises exactly one attempt, on one object, by one identity. It "
        "is consumed on use rather than becoming a standing permission, and consumed "
        "before the handler runs, so a handler that fails partway leaves nothing reusable "
        "behind.",
        "Approvals expire.",
        "A retry reuses the open request rather than opening another — found while "
        "testing, when five retries produced five requests. Without it a client in a "
        "retry loop fills the table with requests nobody will ever approve.",
        "Dual control with fewer than two required approvals is rejected at "
        "configuration load, because a single signature is almost always a "
        "misconfiguration rather than an intent.",
    ]:
        add_bullet(doc, item)
    section_break(doc)

    add_heading(doc, "9.3  Authorization depth", 2, MID_BLUE)
    add_para(doc,
        "A grant may now name a group, so access follows team membership instead of being "
        "re-granted per person, and leaving the group withdraws it. Separately, a role may "
        "carry an operation allowlist. That check is deliberately opt-in: an identity "
        "whose roles define no allowlist is unrestricted at this layer, so introducing "
        "roles never silently locks anyone out of operations they could previously "
        "perform, and holding an unrestricted role alongside a restricted one does not "
        "dissolve the restriction. It narrows what an identity may do; it never widens it.")
    section_break(doc)

    add_para(doc, "Two defects found by testing, not reading", bold=True, colour=WARN_AMBER)
    for item in [
        "Setting a cryptoperiod on a mistyped identifier updated nothing and reported "
        "success, leaving an operator convinced a key had a cryptoperiod it did not have.",
        "The scheduler starts before the server binds, so the first scan could arrive "
        "ahead of the server's own session setup and a first-scan rotation would fail for "
        "want of a session that was about to exist anyway.",
    ]:
        add_bullet(doc, item)
    section_break(doc)

    add_para(doc, "An unrelated regression, worth recording", bold=True, colour=WARN_AMBER)
    add_para(doc,
        "The full suite came back with 12 failures and 52 errors that had nothing to do "
        "with this phase. Each run had been leaving several thousand keys on the shared "
        "test token and nothing removed them; it had reached 28,373 objects, and startup's "
        "token-wide master-key lookup outlasted the fixtures' five-second wait for the "
        "listener. The token is now wiped per session and the fixtures wait on the "
        "listener rather than racing a fixed delay. The suite went from 11 minutes 44 "
        "seconds to 48 seconds.")
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    # 10. WHERE THE SYSTEM STANDS
    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "10  Where the system stands now", 1, DARK_BLUE)
    add_para(doc,
        "By domain, with the residual gap in each stated plainly. \"Done\" here means the "
        "capability exists and was demonstrated, not that nothing more could be built.")
    section_break(doc)

    make_table(doc,
        ["Domain", "Status", "Residual gap"],
        [
            ["Authentication", "Done",
             "Per-identity salted scrypt credentials, individually revocable and "
             "disableable. Open: API-key/token auth, and certificate-to-principal mapping "
             "beyond the verified-CN case."],
            ["Key material at rest", "Done",
             "AES-256-GCM envelopes under a non-extractable HSM master key, with rotation "
             "and a post-upgrade scrub. Open: backups and snapshots taken before the "
             "upgrade."],
            ["Audit", "Done",
             "Append-only, hash-chained log with query and retention. Open: the chain is "
             "not anchored externally, so a wholesale consistent rewrite leaves no trace."],
            ["Transport", "Done",
             "TLS enforced by default, 1.2 floor, hot reload, mTLS identity restricted to "
             "provisioned principals. Open: ACME / automated certificate issuance."],
            ["Deployability", "Done",
             "Config file, two CLIs, systemd unit, Dockerfile, CI workflow. Open: the "
             "image and workflow have not been executed anywhere."],
            ["Observability", "Done",
             "Health, readiness and metrics endpoints plus JSON logs. Open: latency is a "
             "running total rather than histogram buckets."],
            ["Backup & recovery", "Done",
             "Online snapshot with token pairing, and a restore that proves a secret "
             "decrypts. Open: automated scheduling and offsite shipping."],
            ["Key governance", "Done",
             "Scheduled deactivation, expiry warning and optional auto-rotation, all "
             "audited. Open: rotation covers symmetric keys only; alerting is a log line "
             "and an audit record rather than a push to an alerting system."],
            ["Authorization depth", "Done",
             "Group grants, opt-in per-role operation allowlists, M-of-N dual control. "
             "Open: approvals have no wire representation, so a client sees a refusal and "
             "retries after an out-of-band approval."],
            ["HA & scale", "Partial",
             "Multi-process workers break the single-session ceiling, at about 1.5× and "
             "bounded by the serial audit chain. Open: PostgreSQL backend and HSM "
             "failover, both deliberately unbuilt."],
            ["Multi-tenancy", "Not built",
             "Groups and allowlists partition access, not the namespace: object names, "
             "Locate queries and quotas are global. Isolation today means one deployment "
             "per tenant."],
            ["Compliance", "Not closable here",
             "SoftHSM2 is not FIPS 140-2/3 or Common Criteria validated, and no validated "
             "token is available in this environment to run the suite against."],
        ],
        widths=[1.3, 0.9, 4.0])
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    # 11. WHAT WAS DELIBERATELY NOT DELIVERED
    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "11  What was deliberately not delivered", 1, DARK_BLUE)
    add_para(doc,
        "Five items were inside the plan's scope and were not built. Each is recorded here "
        "with its reason, because a programme report that lets deferred work quietly "
        "disappear is not much use to whoever picks it up next.")
    section_break(doc)

    items = [
        ("PostgreSQL backend (Phase 4)",
         "The store is heavily SQLite-specific — PRAGMA user_version, json_extract, "
         "RAISE(ABORT) triggers — so a second backend is a rewrite of the persistence "
         "layer, and it cannot be tested here without a Postgres instance."),
        ("HSM failover (Phase 4)",
         "Needs a second token to verify against. An untested failover path is worse than "
         "a documented single point of failure, because it invites reliance."),
        ("Multi-tenancy (Phase 5)",
         "A tenant boundary reaches into every query, the audit log and the admin CLI. "
         "That is a phase of its own, not a corner of the governance phase, and half of it "
         "would be worse than none."),
        ("FIPS/CC validation (Phase 5)",
         "No validated token is available in this environment. The PKCS#11 boundary keeps "
         "the swap cheap — one file imports pkcs11 — but claiming validation without "
         "executing against validated hardware would be the wrong kind of done."),
        ("Container image and CI execution (Phase 3)",
         "Both are written and their inputs checked, but neither has been run: this "
         "environment's proxy blocks Docker Hub and the SoftHSM2 source mirror. They need "
         "a real execution before being relied on."),
    ]
    for title, why in items:
        labelled(doc, "·", title, colour=DARK_BLUE)
        add_para(doc, why, indent=1.2, size=9.5)
    section_break(doc)

    add_heading(doc, "11.1  If the programme continued", 2, MID_BLUE)
    add_para(doc,
        "In the order the dependencies suggest, rather than by appeal:")
    for item in [
        "Execute the container image and CI workflow somewhere with real network access — "
        "the cheapest way to close a known-unverified item.",
        "Multi-tenancy, as its own phase: namespace, quotas, and per-tenant isolation of "
        "both objects and audit.",
        "An external anchor for the audit chain, so a wholesale rewrite of the local log "
        "is still detectable.",
        "A second storage backend and HSM failover, once infrastructure exists to test "
        "them against.",
        "Run the suite against a FIPS 140-3 token and record the deltas in mechanism "
        "support that the capability probe reports.",
    ]:
        add_bullet(doc, item)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    # 12. HOW THE WORK WAS VERIFIED
    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "12  How the work was verified", 1, DARK_BLUE)
    add_para(doc,
        "Every phase was verified by executing the system, not by reviewing the diff. "
        "This is worth stating explicitly because the most valuable findings in the "
        "programme were invisible to reading:")
    section_break(doc)

    make_table(doc,
        ["Found by", "Finding"],
        [
            ["Running an exploit against a live server",
             "Identity was self-asserted — a second client claiming another user's name "
             "retrieved that user's keys."],
            ["Trying an admin operation end to end",
             "The admin role was honoured by the ownership check and ignored by Locate."],
            ["Grepping the database files after a migration",
             "Encrypting rows in place left the original cleartext in the WAL sidecar."],
            ["Starting the server and polling readiness",
             "/ready reported ready 18 seconds before the KMIP port was open."],
            ["Benchmarking throughput",
             "Credential verification ran scrypt on every request, capping a connection "
             "at ~25 requests/second — a 25× latency defect nobody had noticed."],
            ["Retrying a blocked operation five times",
             "Each dual-control retry opened a new approval request instead of reusing "
             "the open one."],
            ["Running the full suite after the phase was written",
             "The shared test token had accumulated 28,373 objects across runs, breaking "
             "unrelated fixtures."],
        ],
        widths=[2.2, 4.0])
    section_break(doc)

    add_para(doc,
        "The test suite grew from 624 to 811 across the programme, every test running "
        "live against a real SoftHSM2 token rather than against mocks. That is the "
        "mechanism by which each phase could be built on the last without re-verifying "
        "the previous ones by hand, and it is the reason the phases could be executed "
        "quickly without accumulating unexamined risk.")
    section_break(doc)

    make_table(doc,
        ["After phase", "Tests", "Added"],
        [
            ["(baseline)", "624", "—"],
            ["Phase 0", "649", "+25"],
            ["Phase 1", "671", "+22"],
            ["Phase 2", "701", "+30"],
            ["Phase 3", "739", "+38"],
            ["Phase 4", "763", "+24"],
            ["Phase 5", "811", "+48"],
        ],
        widths=[1.6, 1.0, 1.0])
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    # 13. OPERATIONAL SURFACE ADDED
    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "13  Operational surface added by the programme", 1, DARK_BLUE)
    add_para(doc,
        "Before Phase 0 there was no operator surface at all: everything was a Python "
        "call against the store. This is what a deployment now has.")
    section_break(doc)

    add_heading(doc, "13.1  Commands", 2, MID_BLUE)
    for line in [
        "kmip-server --config /etc/kmip/config.yaml           # run from a config file",
        "kmip-server --config /etc/kmip/config.yaml --check   # validate and exit",
        "",
        "kmip-admin identity add|list|delete|disable|enable   # phase 0/3",
        "kmip-admin role grant|revoke|show                    # phase 3",
        "kmip-admin access grant|revoke|list                  # phase 3",
        "kmip-admin audit list|verify|prune                   # phase 2/3",
        "kmip-admin backup create|inspect|restore|verify      # phase 4",
        "kmip-admin rotate-master-key                         # phase 1/3",
        "kmip-admin group add|remove|show|members             # phase 5",
        "kmip-admin permission allow|disallow|show            # phase 5",
        "kmip-admin approval list|approve|show                # phase 5",
        "kmip-admin cryptoperiod set|expiring|scan            # phase 5",
    ]:
        add_code(doc, line)
    section_break(doc)

    add_heading(doc, "13.2  Configuration sections", 2, MID_BLUE)
    make_table(doc,
        ["Section", "Introduced", "Purpose"],
        [
            ["server", "Phase 3",
             "Bind address, port, request-size cap, handshake timeout, plaintext opt-out, "
             "worker count (Phase 4)."],
            ["tls", "Phase 3",
             "Certificate, key, CA, and whether client certificates are required."],
            ["hsm", "Phase 3",
             "Library path, token label, and exactly one PIN source — file, environment, "
             "or inline with a warning."],
            ["storage", "Phase 3", "Metadata database path."],
            ["observability", "Phase 3",
             "Management port serving health, readiness and metrics."],
            ["governance", "Phase 5",
             "Cryptoperiod scanning, warning horizon, auto-rotation, dual control and its "
             "protected operations, approval count and expiry."],
            ["logging", "Phase 3", "Level, and JSON or text format."],
        ],
        widths=[1.1, 0.9, 4.2])
    section_break(doc)
    add_para(doc,
        "Both governance features are off by default. A deployment upgrading into this "
        "release behaves exactly as it did before until an operator turns them on, which "
        "is the correct default for a control that can refuse a client's operation or "
        "deactivate a key on its own.", italic=True, size=9)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    # 14. CONCLUSION
    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "14  Conclusion", 1, DARK_BLUE)
    add_para(doc,
        "All six phases were executed and all six gates were demonstrated. The system "
        "that came out is materially different from the one that went in: an identity can "
        "no longer be assumed by claiming it, a stolen database file yields nothing, every "
        "operation is attributable and tampering is detectable at the row, an operator can "
        "deploy it without writing Python, it can lose its database and come back, keys "
        "rotate on policy without a client asking, and the two operations that destroy or "
        "disclose key material require two people.")
    section_break(doc)
    add_para(doc,
        "What it is not is finished. Multi-tenancy was not built, no validated HSM has "
        "been run against, the container image and CI workflow have never executed, and "
        "worker scaling is bounded at roughly 1.5× by the serial audit chain — a real "
        "cost of a real guarantee, and the kind of trade that should be visible in a "
        "document like this rather than buried.")
    section_break(doc)
    add_para(doc,
        "The most useful thing to carry forward is not any single feature but the working "
        "rule behind them. Seven of the programme's most valuable findings — including a "
        "25× latency defect, a plaintext leak in a WAL sidecar, and an authentication "
        "bypass — were found by running the system and could not have been found by "
        "reading it. Anything added after this should be held to the same standard.",
        italic=True)

    section_break(doc)
    section_break(doc)
    footer = doc.add_paragraph()
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fr = footer.add_run(
        f"KMIP on PKCS#11 — Production Hardening Programme, Phases 0–5 — {TODAY}")
    fr.font.size = Pt(8)
    fr.font.color.rgb = RGBColor(0x80, 0x80, 0x80)

    out = "KMIP_PKCS11_Phase_Report.docx"
    doc.save(out)
    print(f"Saved: {out}")


if __name__ == "__main__":
    build()
