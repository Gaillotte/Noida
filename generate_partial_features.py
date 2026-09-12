"""
Generate the partial-coverage document: the features the gap matrix marks
"Partial", what actually exists behind each one, and why it stopped there.

Run: python generate_partial_features.py
     (needs plan_steps.json — run generate_rest_kms_plan.py first)

"Partial" is the verdict that does the most work in the gap matrix and
explains itself the least. A row marked Covered or Not covered tells a reader
what to expect. Partial tells them something is there without saying how much,
and the difference between "the last ten per cent is scheduled" and "the
remainder belongs to a different product" matters a great deal to anyone
deciding whether to depend on it.

Every entry names what exists, what does not, why the line fell where it did,
and what would move it. The reason codes are the point: they separate work
that is merely unwritten from work that is deliberately declined, blocked by
the token, or built but never demonstrated.

The routing column is not written here — it is read from the delivery plan, so
this document cannot claim a feature is scheduled after the plan has dropped
it, or call one deferred after the plan has picked it up.
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

# Where the claims come from, and when they were last actually demonstrated.
# These are two different things and the document says both.
GROUNDED_AT = "2964dee"          # the commit the gap matrix assesses
VERIFIED_AT = "a013bde"          # the commit the suite was last run against
VERIFIED_RESULT = "816 passed in 43.8s"
VERIFIED_ON = "12 September 2026"


# ── why a feature stopped where it did ───────────────────────────────────────
# Ordered most to least likely to change.
REASONS = {
    "unbuilt": ("Unwritten",
                "The remainder is ordinary work that nobody has done yet. "
                "Nothing blocks it.",
                MID_BLUE),
    "unverified": ("Built, never demonstrated",
                   "The code exists; the proof does not. Until it runs against "
                   "the real thing it is a claim, not a capability.",
                   WARN_AMBER),
    "deliberate": ("Deliberately stopped",
                   "Going further would cost more than it returns, or would "
                   "undo something worth keeping.",
                   DARK_BLUE),
    "token": ("Bounded by the token",
              "The limit belongs to the PKCS#11 device, not to this code. A "
              "different token moves it with no change here.",
              GAP_RED),
    "scope": ("Belongs to another product",
              "What exists is the part that fits a key manager. The rest is a "
              "different thing wearing the same word.",
              DARK_GREY),
}


# feature name (must match the gap matrix exactly) -> the explanation
DETAIL = {

"Automatic rotation": dict(reason="unbuilt",
  exists="A background scheduler in lifecycle/governance.py scans for keys "
         "reaching their cryptoperiod, creates the replacement inside the "
         "token, and cross-links the pair so the lineage is identical to a "
         "client-driven ReKey. Every action is audited as system:scheduler.",
  missing="Key pairs. _rotate() raises on any object that is not a "
          "SymmetricKey (governance.py:157), so an expiring RSA or EC key is "
          "reported and left alone rather than replaced.",
  why="The scheduler was built in Phase 5 against the case that mattered "
      "first — data-encryption keys with short cryptoperiods. Asymmetric "
      "rotation needs no new thinking: ReKeyKeyPair already exists and "
      "produces the same links. It was scope, not difficulty.",
  completes="Call the existing ReKeyKeyPair handler from _rotate() for "
            "key-pair objects and cross-link both new objects to both old "
            "ones. The test that matters is the lineage, not the rotation."),

"Algorithm breadth": dict(reason="token",
  exists="The shim reads the token's real mechanism list once at startup "
         "(pkcs11_shim/shim.py:222) and gates every operation on it "
         "(shim.py:238), so an unsupported request fails cleanly at the edge "
         "instead of surfacing a raw PKCS#11 error from inside an operation.",
  missing="Roughly two-thirds of the KMIP algorithm enum. SoftHSM2 2.7.0 "
          "advertises 79 mechanisms; the packaged 2.6.1 advertises 70 and "
          "lacks CKM_ECDSA_SHA256 entirely, which is why this project builds "
          "2.7.0 from source.",
  why="This is the clearest case in the document of a limit that is not the "
      "code's. Nothing in the KMIP layer refuses an algorithm the token can "
      "perform. The gap is the device.",
  completes="A richer token. The probe activates whatever it finds, so "
            "breadth arrives with the hardware and no code changes. Treat "
            "this row as a procurement line, not a backlog item."),

"Split knowledge / M-of-N shares": dict(reason="unbuilt",
  exists="CreateSplitKey produces XOR shares of key material, and the object "
         "model, state machine and access control treat the parts like any "
         "other managed object.",
  missing="Threshold recovery. The implementation is strictly N-of-N "
          "(create_split_key.py:40) — every share is needed, so losing one "
          "custodian loses the key. Any SplitKeyMethod other than XOR is "
          "refused outright (create_split_key.py:35).",
  why="XOR is the split that takes ten lines and no library. Shamir needs "
      "finite-field arithmetic and a careful implementation, and the value "
      "only appears when there is an operational custodian process to use it.",
  completes="Shamir sharing behind the existing SplitKeyMethod enum — the "
            "protocol already has the vocabulary. The test is the one that "
            "defines the feature: any k of n shares reconstruct, any k-1 do "
            "not."),

"Bulk and batch operations": dict(reason="unbuilt",
  exists="A request carrying many Batch Items is decoded and each item "
         "dispatched in turn (server/server.py:380), with per-item result "
         "status, so the round-trip saving a bulk client wants is real.",
  missing="Atomicity. Each dispatch commits on its own, so an item that fails "
          "halfway through a batch leaves everything before it applied and "
          "everything after it not.",
  why="KMIP defines no rollback — the specification has batch semantics but "
      "no transaction, so there is nothing on the wire to be compliant with. "
      "That made it easy to leave, and it is the kind of gap that stays "
      "invisible until a provisioning run half-succeeds.",
  completes="A transaction around the batch in the service layer rather than "
            "in the protocol, with the boundary chosen explicitly: a batch of "
            "reads should not take a write lock."),

"Database TDE integration": dict(reason="unverified",
  exists="Oracle, SQL Server, MongoDB and Db2 obtain keys over KMIP, and this "
         "server implements the operations their profiles use. The path is "
         "there in the sense that nothing is known to be missing.",
  missing="Evidence. No database has ever been pointed at this server.",
  why="Interoperability is not a property of a specification, it is a "
      "property of two implementations that have met. Every vendor profile "
      "makes assumptions the text does not state, and they surface on first "
      "contact rather than on reading.",
  completes="One vendor at a time: run the database against the server, fix "
            "what the profile assumes, and add the exchange to the "
            "conformance suite so it stays fixed."),

"Storage, backup and VM integrations": dict(reason="unverified",
  exists="The same position as database TDE. VMware, NetApp, Veeam and tape "
         "libraries are KMIP clients and the operations they need are "
         "implemented.",
  missing="The same thing: a demonstration. None has been connected.",
  why="Identical reasoning, and grouped separately only because the buyers "
      "are different. Storage profiles tend to lean on attributes and Locate "
      "filters more heavily than database profiles do, so the first contact "
      "is likely to find different assumptions.",
  completes="Validation against one product in each family, with the "
            "exchanges captured as tests."),

"Secrets management": dict(reason="scope",
  exists="SecretData objects hold arbitrary secrets with the full lifecycle, "
         "access control and audit that keys get, and ObtainLease covers "
         "time-bounded custody.",
  missing="Dynamic issuance. There is no engine that mints a database "
          "credential on request, no templating, and no automatic revocation "
          "when a lease ends.",
  why="Static custody is a key manager's job and it is done. Dynamic secrets "
      "are a different product — the engine has to understand each backend "
      "well enough to create and revoke principals in it, which is an "
      "integration surface, not a cryptographic one.",
  completes="Nothing, in this product. The honest route is to run a secrets "
            "manager beside this server and let it use this one for the keys "
            "it needs. Building a second Vault inside a KMS serves neither."),

"Certificate lifecycle": dict(reason="scope",
  exists="Certify, ReCertify and Validate are implemented, certificates are "
         "first-class managed objects, and the private key never leaves the "
         "token during signing.",
  missing="Everything that makes a CA a CA: no chain to a real issuer, no "
          "CRL, no OCSP, no policy or profile enforcement. What comes out is "
          "self-signed.",
  why="KMIP's Certify was never a certificate authority and should not be "
      "made into one. A CA is a governed, audited, long-lived trust anchor "
      "with its own operational discipline; reimplementing a weak one inside "
      "a key manager would invite exactly the reliance it could not support.",
  completes="Front the deployment with a real CA — EJBCA or equivalent — and "
            "let this server hold the keys. The boundary is the point."),

"Encryption as a service (data-plane API)": dict(reason="unbuilt",
  exists="Encrypt, Decrypt, Sign, MAC and Hash all execute inside the token "
         "over KMIP, so an application can already use the service without "
         "ever holding key material. The hard half is done.",
  missing="The shapes applications actually consume: a data-key call "
          "returning the wrapped and plaintext forms together, re-wrap to a "
          "newer key version, and any of it over HTTP.",
  why="The primitives were built protocol-first, against the KMIP "
      "specification. The convenience operations that make encryption as a "
      "service pleasant to use are conventions of REST key managers, not "
      "KMIP operations, so they never arrived with the protocol work.",
  completes="Data-key and re-wrap in the service layer, exposed on both "
            "transports. The test worth insisting on is cross-transport: "
            "ciphertext from the HTTP endpoint must decrypt over KMIP."),

"Separation of duties": dict(reason="unbuilt",
  exists="Ownership, per-object grants, groups and per-role operation "
         "allowlists are all enforced, and dual control prevents a single "
         "identity completing a Destroy or an Export alone.",
  missing="A split administrator. The reserved admin role short-circuits "
          "every check (lifecycle/access_control.py:53), so one identity can "
          "both grant access to a key and use it.",
  why="The admin role was the first thing built, when the alternative was no "
      "access control at all, and everything since has been layered around "
      "it. Splitting it is not hard — it is a migration, which is why it did "
      "not happen incidentally.",
  completes="Two roles where there is one: security-admin holding identities, "
            "roles and policy, key-admin holding objects and cryptoperiods, "
            "with neither able to become the other. Existing admins get both "
            "on upgrade so nobody's access changes until an operator splits "
            "them deliberately."),

"Key inventory and discovery": dict(reason="unbuilt",
  exists="Locate answers inventory questions over the wire with attribute "
         "filters, and kmip-admin lists objects for an operator.",
  missing="A report. Nothing aggregates, pages, sorts or exports, so "
          "answering \"what expires this quarter\" means a client program.",
  why="Locate is a protocol operation and does what the protocol asks. "
      "Reporting is a console feature, and there is no console — this row is "
      "partial largely because the REST layer it would belong to does not "
      "exist yet.",
  completes="Paged, sortable queries in the store returning whole rows rather "
            "than bare identifiers, with cursors rather than offsets so a "
            "table being written does not double-show rows."),

"Crypto-agility reporting": dict(reason="unbuilt",
  exists="Both halves of the data are present: the capability probe knows "
         "what the token supports, and every managed object records its "
         "algorithm and parameters.",
  missing="The join. Nothing counts algorithms in use, flags the weak ones or "
          "estimates the work in a migration.",
  why="The same reason as inventory reporting, and the same fix. The "
      "information has been sitting in the store since Phase 1 with no "
      "surface to present it on.",
  completes="An aggregate query and a report, once there is somewhere to show "
            "it. This is the row most likely to matter in a post-quantum "
            "migration, which is worth remembering before deprioritising it."),

"Horizontal throughput": dict(reason="deliberate",
  exists="A pre-fork worker pool spreads connections across processes, and "
         "the scrypt verification cache lifted a single worker from about 24 "
         "to roughly 600 operations per second.",
  missing="Linear scaling. Measured gain is about 1.5×, not one per core, and "
          "adding workers past that returns little.",
  why="The bound is the audit chain. Each entry hashes its predecessor, so "
      "entries must be written in order and the write lock serialises them. "
      "That is not a misconfiguration — it is the price of a log that can "
      "prove it has not been edited, and it was accepted knowingly.",
  completes="Per-shard chains with a periodic cross-link, or an external "
            "append-only service. Both trade some of the tamper-evidence "
            "property for throughput, so the honest framing is a choice "
            "rather than a fix.",
  plan_note="Step 11 closes this row without taking that trade: it adds "
            "nodes rather than weakening the chain. Horizontal throughput "
            "arrives through clustering, and the single-node ceiling of "
            "about 1.5× stays exactly where it is. Worth knowing if the "
            "deployment is ever one machine — there, this row does not move."),

"Scheduled and offsite backup": dict(reason="unbuilt",
  exists="Online backup while the server runs, paired to the token that can "
         "decrypt it, with a restore that verifies what it restored rather "
         "than reporting success on exit status.",
  missing="A scheduler and a shipper. When a backup runs and where it lands "
          "are the operator's to arrange.",
  why="The original reasoning was that a KMS growing its own cron and its "
      "own object-store client duplicates what every platform already has. "
      "That holds for a single box and stops holding for a cluster, where a "
      "backup has to be taken somewhere and restorable somewhere else — so "
      "the plan takes the scheduling on rather than leaving it out.",
  completes="A scheduler and an offsite shipper, built alongside the "
            "clustering work because that is what makes them necessary. The "
            "test is the one that matters operationally and is easy to skip: "
            "a backup taken on one node restores on another."),

"Kubernetes / container deployment": dict(reason="unverified",
  exists="A two-stage Dockerfile, a systemd unit, configuration validation "
         "with --check, and health and readiness endpoints suitable for "
         "probes. The inputs are checked at build time.",
  missing="Any evidence it runs, plus a Helm chart or operator. The image has "
          "never been executed: this environment blocks Docker Hub and the "
          "SoftHSM2 mirror the build needs.",
  why="Environment. This is the one row in the document that is unproven "
      "because of where the work happened rather than what was chosen. "
      "Saying so is the point — an unexecuted Dockerfile is a guess with good "
      "syntax.",
  completes="Build and run the image somewhere with network access, then a "
            "chart carrying the PKCS#11 device, the readiness probe and the "
            "single-writer constraint the audit chain imposes."),

"Alerting": dict(reason="unbuilt",
  exists="Approaching expiry is logged and audited, operation counters and "
         "authentication failures are exported for Prometheus, and the JSON "
         "log carries enough structure to alert on.",
  missing="Anything that pushes. Every signal waits to be collected; nothing "
          "reaches a person.",
  why="The signals were built with the metrics endpoint in Phase 3 and the "
      "scheduler in Phase 5, each for its own reason, and nobody joined them "
      "to a notifier. There is no design decision behind this row — it is "
      "simply unfinished.",
  completes="Alertmanager rules over the metrics already exported closes most "
            "of it without new code. What does need writing is expiry "
            "alerting that fires once per key per window rather than on every "
            "scheduler scan."),

"Request bounds and DoS resistance": dict(reason="unbuilt",
  exists="Request size is capped at one mebibyte before the body is read "
         "(server/server.py:38), TTLV nesting is bounded at 32 levels "
         "(core/ttlv.py:19) so a recursive structure cannot exhaust the "
         "stack, and the TLS handshake happens off the accept loop under a "
         "timeout.",
  missing="A cap on how many clients may connect and how fast any one of them "
          "may ask. The listen backlog — 16 in the single-process server, 128 "
          "under the worker pool — is a queue depth, not a limit: it governs "
          "how many connections wait to be accepted, not how many are served "
          "or how often.",
  why="Each existing bound was added against a specific attack — an oversized "
      "body, a nesting bomb, a slow handshake. Nobody added the general one, "
      "and a backlog number sitting in the code reads like a limit without "
      "being one.",
  completes="A bounded connection semaphore and a per-identity token bucket "
            "returning 429 or its KMIP equivalent, tested by holding two "
            "hundred connections open and confirming the server still "
            "serves."),

"Sealed startup with quorum unseal": dict(reason="unbuilt",
  exists="The auto-unseal half, and it is genuine: the metadata store is "
         "encrypted under a non-extractable HSM master key, so a stolen "
         "database file is inert without the token. Master-key rotation is "
         "online and row-by-row.",
  missing="The operator half. There is no quorum — whoever holds the token "
          "PIN starts the service alone — and no ceremony for re-issuing "
          "shares.",
  why="The threat this project designed against was a stolen database, and "
      "against that the token is a complete answer. The threat a quorum "
      "addresses is a single trusted operator, which is an organisational "
      "control, and it was never in scope.",
  completes="Split the PIN into operator-held shares so a quorum starts the "
            "service. The behaviour to get right is the sealed state itself: "
            "a sealed server should answer its health probe and refuse every "
            "operation, not fail obscurely inside the shim."),
}


def load_matrix():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(
        "gapmatrix", os.path.join(here, "generate_kms_gap_matrix.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_plan():
    if not os.path.exists("plan_steps.json"):
        raise SystemExit("plan_steps.json is missing — run: "
                         "python generate_rest_kms_plan.py")
    with open("plan_steps.json", encoding="utf-8") as fh:
        return json.load(fh)


def verify(matrix, plan):
    """This document must describe exactly the rows the matrix calls partial,
    and every one of them must be accounted for by the plan. Anything else and
    it is a document that agrees with nothing."""
    partial = [(d["name"], r[0], r[1], r[3])
               for d in matrix.DOMAINS for r in d["rows"] if r[2] == "partial"]
    names = {p[1] for p in partial}

    unknown = sorted(set(DETAIL) - names)
    if unknown:
        raise SystemExit("explained features the matrix does not call partial:"
                         "\n  " + "\n  ".join(unknown))
    missing = sorted(names - set(DETAIL))
    if missing:
        raise SystemExit("partial features with no explanation:\n  "
                         + "\n  ".join(missing))

    for feat, d in DETAIL.items():
        if d["reason"] not in REASONS:
            raise SystemExit(f"{feat}: unknown reason code {d['reason']!r}")
        for field in ("exists", "missing", "why", "completes"):
            if not d.get(field, "").strip():
                raise SystemExit(f"{feat}: {field} is empty — every row owes "
                                 f"all four answers")

    routing = {}
    for step in plan["steps"]:
        for feat in step["closes"]:
            if feat in names:
                routing[feat] = ("step", step)
    for rem in plan["remaining"]:
        if rem["feature"] in names:
            if rem["feature"] in routing:
                raise SystemExit(f"{rem['feature']}: both scheduled and deferred")
            routing[rem["feature"]] = ("deferred", rem)

    unrouted = sorted(names - set(routing))
    if unrouted:
        raise SystemExit("partial features the plan neither closes nor defers:"
                         "\n  " + "\n  ".join(unrouted))

    # A row cannot be called deliberately stopped, or another product's
    # problem, while the plan schedules a step to close it. Either the reason
    # is wrong or there is something specific to say about how both are true —
    # this check found two rows saying one thing and routing to another.
    for feat, d in DETAIL.items():
        kind, _data = routing[feat]
        if d["reason"] in ("deliberate", "scope") and kind == "step" \
                and not d.get("plan_note", "").strip():
            raise SystemExit(
                f"{feat}: called \"{REASONS[d['reason']][0]}\" but the plan "
                f"schedules a step to close it. Either the reason code is "
                f"wrong, or this row owes a plan_note saying how both are true.")
        if d.get("plan_note") and kind != "step":
            raise SystemExit(f"{feat}: has a plan_note but the plan defers it")
    return partial, routing


# ── document helpers ─────────────────────────────────────────────────────────

def set_cell_bg(cell, hex_color):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), hex_color)
    shd.set(qn("w:val"), "clear")
    tcPr.append(shd)


def fixed_layout(tbl, widths):
    tbl.autofit = False
    layout = OxmlElement("w:tblLayout")
    layout.set(qn("w:type"), "fixed")
    tbl._tbl.tblPr.append(layout)
    grid = tbl._tbl.find(qn("w:tblGrid"))
    if grid is not None:
        for col, w in zip(grid.findall(qn("w:gridCol")), widths):
            col.set(qn("w:w"), str(int(w * 1440)))
    for row in tbl.rows:
        for cell, w in zip(row.cells, widths):
            cell.width = Inches(w)


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
    p.add_run(text).font.size = Pt(size)
    return p


def labelled(doc, label, text, colour):
    """A label and its answer in one paragraph — four of these per feature,
    always in the same order, so the document can be read down a column."""
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(4)
    r = p.add_run(label + "  ")
    r.bold = True
    r.font.size = Pt(9.5)
    r.font.color.rgb = colour
    body = p.add_run(text)
    body.font.size = Pt(9.5)
    return p


def header_row(table, headers, sizes=None):
    for i, h in enumerate(headers):
        cell = table.rows[0].cells[i]
        cell.text = h
        set_cell_bg(cell, "1A3A5C")
        for para in cell.paragraphs:
            for run in para.runs:
                run.bold = True
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                run.font.size = Pt(sizes or 8.5)


def route_text(kind, data):
    if kind == "step":
        return f"Step {data['n']} — {data['title']} (stage {data['stage']})"
    return f"Deferred — {data['kind']}"


def build():
    matrix = load_matrix()
    plan = load_plan()
    partial, routing = verify(matrix, plan)

    doc = Document()
    for sec in doc.sections:
        sec.top_margin = Inches(0.8)
        sec.bottom_margin = Inches(0.8)
        sec.left_margin = Inches(0.9)
        sec.right_margin = Inches(0.9)
    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(10)

    # ── title ────────────────────────────────────────────────────────────
    t = doc.add_paragraph()
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    tr = t.add_run("KMIP on PKCS#11")
    tr.bold = True
    tr.font.size = Pt(26)
    tr.font.color.rgb = DARK_BLUE

    s = doc.add_paragraph()
    s.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sr = s.add_run("Partial coverage — what is there, and why it stopped")
    sr.font.size = Pt(16)
    sr.font.color.rgb = MID_BLUE

    s2 = doc.add_paragraph()
    s2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sr2 = s2.add_run(f"The {len(partial)} features the gap matrix marks Partial, "
                     f"explained one by one")
    sr2.font.size = Pt(11.5)
    sr2.font.color.rgb = DARK_GREY
    doc.add_paragraph()

    counts = {}
    for d in DETAIL.values():
        counts[d["reason"]] = counts.get(d["reason"], 0) + 1
    scheduled = sum(1 for k, _v in routing.values() if k == "step")

    info = [
        ("Document", "Why each partially covered feature is partial"),
        ("Features", f"{len(partial)} of {len(matrix.DOMAINS) and sum(len(d['rows']) for d in matrix.DOMAINS)} "
                     f"assessed, across {len({p[0] for p in partial})} domains"),
        ("Grounded at", f"{GROUNDED_AT} — the commit the gap matrix assesses"),
        ("Last demonstrated", f"{VERIFIED_AT} on {VERIFIED_ON} — "
                              f"{VERIFIED_RESULT}, against a source-built "
                              f"SoftHSM2 2.7.0"),
        ("Reasons", " · ".join(f"{counts[c]} {REASONS[c][0].lower()}"
                               for c in REASONS if c in counts)),
        ("Plan routing", f"{scheduled} closed by the delivery plan, "
                         f"{len(partial) - scheduled} deferred"),
        ("Date", TODAY),
    ]
    tbl = doc.add_table(rows=len(info), cols=2)
    tbl.style = "Table Grid"
    for i, (k, v) in enumerate(info):
        tbl.rows[i].cells[0].text = k
        tbl.rows[i].cells[1].text = v
        set_cell_bg(tbl.rows[i].cells[0], "1A3A5C")
        for para in tbl.rows[i].cells[0].paragraphs:
            for run in para.runs:
                run.bold = True
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                run.font.size = Pt(9)
        for para in tbl.rows[i].cells[1].paragraphs:
            for run in para.runs:
                run.font.size = Pt(9)
    fixed_layout(tbl, [1.5, 5.2])
    doc.add_page_break()

    # ── 1  how to read ───────────────────────────────────────────────────
    add_heading(doc, "1  Why this document exists", 1, DARK_BLUE)
    add_para(doc,
        "Partial is the least informative verdict in the gap matrix. Covered "
        "and Not covered both tell a reader what to expect; Partial says "
        "something is there without saying how much, and hides a distinction "
        "that matters more than the verdict itself. A feature whose last ten "
        "per cent is scheduled and a feature whose remainder belongs to a "
        "different product are not in the same condition, and a buyer, an "
        "auditor and an engineer each need to tell them apart.")
    add_para(doc,
        "So every row below answers the same four questions, always in the "
        "same order:")
    for label, text in [
        ("What exists", "the part that is built, and where it lives in the "
                        "repository."),
        ("What is missing", "the part that is not, stated as a capability "
                            "rather than a task."),
        ("Why it stopped here", "the actual reason — which is sometimes a "
                                "decision, sometimes a device, and sometimes "
                                "nothing more interesting than nobody having "
                                "done it."),
        ("What would complete it", "the work, and the test that would settle "
                                   "it."),
    ]:
        p = doc.add_paragraph(style="List Bullet")
        p.paragraph_format.left_indent = Inches(0.3)
        r = p.add_run(label + " — ")
        r.bold = True
        r.font.size = Pt(10)
        r.font.color.rgb = MID_BLUE
        p.add_run(text).font.size = Pt(10)

    add_para(doc)
    add_para(doc, "A note on how these claims were checked", bold=True,
             colour=MID_BLUE)
    add_para(doc,
        "The coverage verdicts come from the gap matrix, which was assessed "
        f"against the repository at {GROUNDED_AT}. The explanations here were "
        "grounded by reading the code and citing it, and every file and line "
        "reference was checked against the file it names.", size=9.5)
    add_para(doc,
        f"They were also re-verified by execution. SoftHSM2 2.7.0 was built "
        f"from source and the full suite run against a live token at "
        f"{VERIFIED_AT} on {VERIFIED_ON}: {VERIFIED_RESULT}. The token "
        f"advertises 79 mechanisms including CKM_ECDSA_SHA256, which is the "
        f"figure this project's environment notes have claimed since August "
        f"and which had not, until now, been demonstrated in a session that "
        f"wrote about it. The sixteen-step end-to-end demo also completed.",
        size=9.5)
    add_para(doc,
        "Two numbers here remain the gap matrix's rather than this document's. "
        "The algorithm-breadth row quotes 15 of 40: the denominator was "
        "confirmed — the KMIP CryptographicAlgorithm enum has exactly 40 "
        "members — but the numerator depends on how an algorithm is judged "
        "usable on a token, and that method was not re-derived here. It is "
        "flagged rather than restated as though checked.", size=9.5,
        italic=True)
    doc.add_page_break()

    # ── 2  the reasons ───────────────────────────────────────────────────
    add_heading(doc, "2  Five reasons a feature stops", 1, DARK_BLUE)
    add_para(doc,
        "These are the categories the eighteen sort into. They are ordered by "
        "how likely each is to change: the first moves with a week of work, "
        "the last will not move at all.")
    section = doc.add_table(rows=1, cols=4)
    section.style = "Table Grid"
    header_row(section, ["Reason", "Means", "Count", "Outlook"])
    outlook = {
        "unbuilt": "Moves when someone writes it",
        "unverified": "Moves when it is demonstrated",
        "deliberate": "Moves only if the trade-off is revisited",
        "token": "Moves with different hardware",
        "scope": "Does not move; the boundary is the answer",
    }
    for i, (code, (name, means, colour)) in enumerate(REASONS.items()):
        row = section.add_row()
        shade = "EEF4FA" if i % 2 == 0 else "FFFFFF"
        for j, text in enumerate([name, means, str(counts.get(code, 0)),
                                  outlook[code]]):
            cell = row.cells[j]
            r = cell.paragraphs[0].add_run(text)
            r.font.size = Pt(9)
            if j == 0:
                r.bold = True
                r.font.color.rgb = colour
            set_cell_bg(cell, shade)
    fixed_layout(section, [1.45, 2.95, 0.55, 1.75])
    add_para(doc)

    add_para(doc,
        "The distribution is the finding. Most of these features are not "
        "partial because of a hard problem or a considered trade-off — they "
        "are partial because the work stopped at the point where the phase "
        "that introduced them ended. That is worth saying plainly: it means "
        "most of this column is schedulable, and it means the small number of "
        "genuinely immovable rows deserve more attention than their count "
        "suggests.", italic=True, size=9.5)
    doc.add_page_break()

    # ── 3  summary ───────────────────────────────────────────────────────
    add_heading(doc, "3  The eighteen at a glance", 1, DARK_BLUE)
    tbl = doc.add_table(rows=1, cols=4)
    tbl.style = "Table Grid"
    header_row(tbl, ["Feature", "Domain", "Reason", "Where the plan puts it"])
    for i, (domain, feat, _expect, _route) in enumerate(partial):
        d = DETAIL[feat]
        kind, data = routing[feat]
        row = tbl.add_row()
        shade = "EEF4FA" if i % 2 == 0 else "FFFFFF"
        cells = row.cells
        r0 = cells[0].paragraphs[0].add_run(feat)
        r0.bold = True
        r0.font.size = Pt(8.5)
        r1 = cells[1].paragraphs[0].add_run(domain)
        r1.font.size = Pt(8.5)
        r2 = cells[2].paragraphs[0].add_run(REASONS[d["reason"]][0])
        r2.font.size = Pt(8.5)
        r2.bold = True
        r2.font.color.rgb = REASONS[d["reason"]][2]
        r3 = cells[3].paragraphs[0].add_run(route_text(kind, data))
        r3.font.size = Pt(8.5)
        if kind != "step":
            r3.italic = True
            r3.font.color.rgb = DARK_GREY
        for c in cells:
            set_cell_bg(c, shade)
    fixed_layout(tbl, [1.95, 1.55, 1.15, 2.05])
    add_para(doc)
    add_para(doc,
        "The routing column is read from the delivery plan at build time, not "
        "written here. If the plan stops closing one of these, this document "
        "refuses to build rather than continuing to promise it.",
        italic=True, size=9)
    doc.add_page_break()

    # ── 4  one section per feature ───────────────────────────────────────
    add_heading(doc, "4  Feature by feature", 1, DARK_BLUE)
    current_domain = None
    n = 0
    for domain, feat, expect, _route in partial:
        if domain != current_domain:
            add_heading(doc, domain, 2, MID_BLUE)
            current_domain = domain
        n += 1
        d = DETAIL[feat]
        name, _means, colour = REASONS[d["reason"]]

        h = doc.add_heading(f"{n}.  {feat}", level=3)
        for run in h.runs:
            run.font.color.rgb = DARK_BLUE

        tag = doc.add_paragraph()
        tag.paragraph_format.space_after = Pt(6)
        tr = tag.add_run(name.upper())
        tr.bold = True
        tr.font.size = Pt(8.5)
        tr.font.color.rgb = colour
        kind, data = routing[feat]
        sep = tag.add_run("   ·   ")
        sep.font.size = Pt(8.5)
        sep.font.color.rgb = RGBColor(0xA0, 0xA0, 0xA0)
        rr = tag.add_run(route_text(kind, data))
        rr.font.size = Pt(8.5)
        rr.italic = True
        rr.font.color.rgb = DARK_GREY

        labelled(doc, "The market expects", expect, DARK_GREY)
        labelled(doc, "What exists", d["exists"], OK_GREEN)
        labelled(doc, "What is missing", d["missing"], GAP_RED)
        labelled(doc, "Why it stopped here", d["why"], colour)
        labelled(doc, "What would complete it", d["completes"], MID_BLUE)
        if d.get("plan_note"):
            labelled(doc, "How the plan closes it anyway", d["plan_note"],
                     WARN_AMBER)
        add_para(doc)

    doc.add_page_break()

    # ── 5  what to do with this ──────────────────────────────────────────
    add_heading(doc, "5  What to take from it", 1, DARK_BLUE)
    add_para(doc, "If you are deciding whether to depend on this server",
             bold=True, colour=MID_BLUE)
    for text in [
        "The rows marked Belongs to another product will not move, and that "
        "is the answer rather than a shortfall: run a CA and a secrets "
        "manager beside this server rather than expecting it to become them.",
        "The row marked Bounded by the token is a procurement question. "
        "Algorithm breadth arrives with the hardware and needs no change "
        "here.",
        "The rows marked Built, never demonstrated are the ones to ask about "
        "before committing. An untested integration path is a plan, not a "
        "capability, and the project says so rather than counting it.",
    ]:
        add_bullet(doc, text, size=9.5)
    add_para(doc)

    add_para(doc, "If you are planning the work", bold=True, colour=MID_BLUE)
    for text in [
        f"{counts.get('unbuilt', 0)} of the {len(partial)} are simply "
        f"unwritten, and the delivery plan schedules most of them. None needs "
        f"a new design.",
        "Horizontal throughput is the one row where completing it means "
        "giving something up. Lifting it past about 1.5× means weakening the "
        "single serial audit chain, so treat it as a decision to be taken "
        "deliberately rather than a performance bug to be fixed.",
        "Separation of duties is the smallest change with the largest "
        "assurance return: one role becomes two, and the claim that no "
        "administrator can both grant access and use it becomes true.",
    ]:
        add_bullet(doc, text, size=9.5)
    add_para(doc)

    add_para(doc,
        "One thing this document deliberately does not do is round upward. "
        "Every row here could be described as covered with a caveat; none is. "
        "A feature is partial until the thing a reader would assume from the "
        "word \"covered\" is actually true.", italic=True, size=9.5)

    add_para(doc)
    f = doc.add_paragraph()
    f.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fr = f.add_run(f"KMIP on PKCS#11 — partial coverage explained — {TODAY}")
    fr.font.size = Pt(8)
    fr.font.color.rgb = RGBColor(0x80, 0x80, 0x80)

    out = "KMIP_PKCS11_Partial_Features.docx"
    doc.save(out)
    print(f"Saved: {out}")
    print(f"  {len(partial)} partial features · "
          + " · ".join(f"{counts[c]} {c}" for c in REASONS if c in counts))
    print(f"  {scheduled} closed by the plan, {len(partial) - scheduled} deferred")


if __name__ == "__main__":
    build()
