"""
Generate the provenance matrix: which source evidenced each of the 74
requirements in the gap analysis.

Run: python generate_feature_provenance.py

READ THIS BEFORE READING THE TABLE.

A mark says "this source's documentation evidenced this requirement". It does
NOT say "this product has this feature", and a blank does NOT say a product
lacks it. The research behind the gap matrix was a handful of published pages
per vendor — enough to establish what the market expects a KMS to do, nowhere
near enough to compare products feature by feature. A capability comparison
would need a hands-on evaluation of each product and is not what this is.

The "Category" column is the honest residue: requirements that no specific
source in that research named, and that are here because they are ordinary
practice for a networked service handling secrets. Those rows are the ones to
treat with most caution, and the table marks them rather than hiding them
among the sourced ones.
"""

import datetime
import importlib.util
import os

from docx import Document
from docx.enum.section import WD_ORIENT
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

# The sources, in the order they appear as columns.
SOURCES = [
    ("THA", "Thales CipherTrust Manager", "vendor"),
    ("FOR", "Fortanix Data Security Manager", "vendor"),
    ("ENT", "Entrust KeyControl", "vendor"),
    ("UTI", "Utimaco Enterprise Secure Key Manager", "vendor"),
    ("CLD", "AWS KMS / Azure Managed HSM / Google Cloud KMS", "vendor"),
    ("STD", "NIST SP 800-57, SP 800-152, OASIS KMIP 2.1 and 3.0", "standard"),
    ("CAT", "Category baseline — no specific source named it", "residue"),
]

# feature name (must match the gap matrix exactly) -> sources that evidenced it
PROVENANCE = {
    # ── Key lifecycle and cryptography ───────────────────────────────────
    "HSM-backed storage, keys never leave": ["THA", "FOR", "ENT", "UTI", "CLD", "STD"],
    "Full lifecycle state machine": ["THA", "ENT", "STD"],
    "Cryptoperiod enforcement": ["ENT", "CLD", "STD"],
    "Automatic rotation": ["THA", "ENT", "UTI", "CLD"],
    "Key lineage and versioning": ["THA", "CLD"],
    "Algorithm breadth": ["STD", "CAT"],
    "Post-quantum (ML-KEM, ML-DSA, SLH-DSA)": ["STD", "CAT"],
    "Hardware RNG": ["UTI", "STD"],
    "Key derivation": ["STD", "CAT"],
    "Key wrapping / secure import-export": ["THA", "CLD", "STD"],
    "Split knowledge / M-of-N shares": ["FOR", "UTI", "STD"],
    "Formal key ceremony": ["STD", "CAT"],
    "Bulk and batch operations": ["STD", "CAT"],
    "Verifiable destruction": ["THA", "ENT", "STD"],

    # ── Protocol and ecosystem integration ───────────────────────────────
    "KMIP server": ["THA", "ENT", "UTI", "STD"],
    "KMIP interoperability certification": ["STD", "CAT"],
    "KMIP 3.0": ["STD"],
    "PKCS#11 provider for applications": ["UTI", "CAT"],
    "REST / JSON API": ["THA", "FOR", "UTI", "CLD"],
    "Cloud BYOK (AWS, Azure, GCP)": ["THA", "FOR", "CLD"],
    "Cloud EKM / XKS / hold-your-own-key": ["FOR", "CLD"],
    "Database TDE integration": ["THA", "ENT"],
    "Storage, backup and VM integrations": ["ENT", "CAT"],
    "Secrets management": ["THA", "FOR", "ENT"],
    "Tokenization / format-preserving encryption": ["THA", "FOR"],
    "Certificate lifecycle": ["CAT"],

    # ── Identity and access control ──────────────────────────────────────
    "Per-identity authentication": ["THA", "UTI", "CAT"],
    "Enterprise IdP — LDAP/AD, SAML, OIDC": ["UTI", "CAT"],
    "mTLS certificate identity": ["CAT"],
    "API keys / service accounts": ["CLD", "CAT"],
    "Role-based access control": ["THA", "UTI", "CAT"],
    "Groups": ["CAT"],
    "Per-object access grants": ["THA", "CAT"],
    "Attribute or policy-based access": ["THA", "FOR", "ENT"],
    "Dual control / quorum approval": ["FOR", "UTI"],
    "Separation of duties": ["STD", "CAT"],
    "Multi-tenancy and namespaces": ["THA", "ENT"],
    "Per-tenant quotas": ["CAT"],
    "Connection and rate limiting": ["CAT"],

    # ── Audit, compliance and assurance ──────────────────────────────────
    "Tamper-evident audit log": ["THA", "UTI", "STD"],
    "External audit anchoring": ["CAT"],
    "SIEM integration": ["UTI", "CAT"],
    "Retention and archival": ["STD", "CAT"],
    "FIPS 140-2/3 validated HSM": ["FOR", "ENT", "CLD", "CAT"],
    "Common Criteria / eIDAS": ["ENT", "CAT"],
    "Compliance reporting": ["THA", "ENT"],
    "Key inventory and discovery": ["THA", "ENT"],
    "Cryptoperiod policy alignment": ["STD"],
    "Crypto-agility reporting": ["CAT"],

    # ── Availability, scale and recovery ─────────────────────────────────
    "HA clustering": ["THA", "UTI", "CAT"],
    "Multi-site replication and DR": ["ENT", "UTI", "STD"],
    "HSM failover and pooling": ["UTI", "CAT"],
    "Horizontal throughput": ["THA"],
    "Enterprise database backend": ["CAT"],
    "Scheduled and offsite backup": ["THA", "ENT", "STD"],
    "Restore that proves itself": ["STD", "CAT"],
    "Zero-downtime certificate rotation": ["CAT"],
    "Rolling upgrades": ["CAT"],
    "Kubernetes / container deployment": ["THA", "CAT"],

    # ── Operations and observability ─────────────────────────────────────
    "Health and readiness probes": ["CAT"],
    "Metrics": ["CAT"],
    "Structured logging": ["CAT"],
    "Configuration-driven deployment": ["CAT"],
    "Administrative CLI": ["CAT"],
    "Web console": ["THA", "FOR", "ENT"],
    "Self-service developer portal": ["THA", "CAT"],
    "Alerting": ["CAT"],

    # ── Platform hardening ───────────────────────────────────────────────
    "TLS enforced by default": ["CAT"],
    "Metadata encrypted at rest": ["STD", "CAT"],
    "Master key rotation": ["STD", "CAT"],
    "Non-extractable key enforcement": ["CLD", "STD"],
    "Request bounds and DoS resistance": ["CAT"],
    "Secrets kept out of configuration": ["CAT"],
    "Hardened service": ["CAT"],
}

STATUS_LABEL = {"full": "Covered", "partial": "Partial", "gap": "Gap"}
STATUS_COLOUR = {"full": OK_GREEN, "partial": WARN_AMBER, "gap": GAP_RED}


def load_matrix():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(
        "gapmatrix", os.path.join(here, "generate_kms_gap_matrix.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def verify(matrix):
    """Same discipline as the delivery plan: this table must describe the
    matrix it claims to, or it does not get built."""
    listed = [r[0] for d in matrix.DOMAINS for r in d["rows"]]
    keys = set(PROVENANCE)

    unknown = sorted(keys - set(listed))
    if unknown:
        raise SystemExit("provenance names features the matrix does not have:\n  "
                         + "\n  ".join(unknown))
    missing = sorted(set(listed) - keys)
    if missing:
        raise SystemExit("features with no provenance entry:\n  " + "\n  ".join(missing))

    codes = {c for c, _n, _k in SOURCES}
    for feat, marks in PROVENANCE.items():
        bad = [m for m in marks if m not in codes]
        if bad:
            raise SystemExit(f"{feat}: unknown source code(s) {bad}")
        if not marks:
            raise SystemExit(f"{feat}: no source at all — every requirement needs one")
        if len(set(marks)) != len(marks):
            raise SystemExit(f"{feat}: duplicate source code")
    return listed


# ── document helpers ─────────────────────────────────────────────────────────

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


COLS = [c for c, _n, _k in SOURCES]
COL_W = [4.40] + [0.68] * len(COLS) + [0.85]


def matrix_header(tbl):
    hdr = tbl.rows[0]
    labels = ["Requirement"] + COLS + ["Status"]
    for i, text in enumerate(labels):
        cell = hdr.cells[i]
        cell.text = text
        set_cell_bg(cell, "1A3A5C")
        for para in cell.paragraphs:
            para.alignment = WD_ALIGN_PARAGRAPH.LEFT if i == 0 else WD_ALIGN_PARAGRAPH.CENTER
            for run in para.runs:
                run.bold = True
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                run.font.size = Pt(8)


def matrix_row(tbl, feature, marks, status, shade):
    row = tbl.add_row()
    c0 = row.cells[0]
    r0 = c0.paragraphs[0].add_run(feature)
    r0.font.size = Pt(8)
    set_cell_bg(c0, shade)

    for i, code in enumerate(COLS, start=1):
        cell = row.cells[i]
        para = cell.paragraphs[0]
        para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        hit = code in marks
        run = para.add_run("●" if hit else "·")
        run.font.size = Pt(10 if hit else 8)
        # The category column is the residue, not a source; colour it as such
        # so a row carried only by it reads as weaker at a glance.
        run.font.color.rgb = (WARN_AMBER if (hit and code == "CAT")
                              else MID_BLUE if hit
                              else RGBColor(0xC8, 0xD0, 0xD8))
        set_cell_bg(cell, shade)

    cs = row.cells[len(COLS) + 1]
    p = cs.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(STATUS_LABEL[status])
    r.font.size = Pt(7.5)
    r.bold = True
    r.font.color.rgb = STATUS_COLOUR[status]
    set_cell_bg(cs, shade)


def widths(tbl):
    for row in tbl.rows:
        for cell, w in zip(row.cells, COL_W):
            cell.width = Inches(w)


def build():
    matrix = load_matrix()
    verify(matrix)

    doc = Document()
    for sec in doc.sections:
        sec.orientation = WD_ORIENT.LANDSCAPE
        sec.page_width, sec.page_height = Inches(11.69), Inches(8.27)   # A4 landscape
        sec.top_margin = Inches(0.55)
        sec.bottom_margin = Inches(0.5)
        sec.left_margin = Inches(0.55)
        sec.right_margin = Inches(0.55)
    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(10)

    # ── header ───────────────────────────────────────────────────────────
    t = doc.add_paragraph()
    tr = t.add_run("Requirement provenance — where each of the 74 features came from")
    tr.bold = True
    tr.font.size = Pt(19)
    tr.font.color.rgb = DARK_BLUE

    add_para(doc,
        "A mark means the source's published documentation evidenced this "
        "requirement. It does NOT mean the product has the feature, and a blank "
        "does NOT mean it lacks one.", bold=True, size=10, colour=GAP_RED)
    add_para(doc,
        "The research behind the gap matrix was a handful of published pages per "
        "vendor — enough to establish what the market expects a key management "
        "system to do, nowhere near enough to compare products feature by "
        "feature. A capability comparison would need a hands-on evaluation of "
        "each product, and this is not one.", size=9.5)
    section_break(doc)

    # legend
    legend = doc.add_table(rows=1, cols=len(SOURCES))
    legend.style = "Table Grid"
    for i, (code, name, kind) in enumerate(SOURCES):
        cell = legend.rows[0].cells[i]
        cell.width = Inches(10.59 / len(SOURCES))
        set_cell_bg(cell, "FBF3E3" if kind == "residue" else "EEF4FA")
        p = cell.paragraphs[0]
        rc = p.add_run(code + "  ")
        rc.bold = True
        rc.font.size = Pt(9)
        rc.font.color.rgb = WARN_AMBER if kind == "residue" else DARK_BLUE
        rn = p.add_run(name)
        rn.font.size = Pt(8)
        rn.font.color.rgb = DARK_GREY
    section_break(doc)

    add_para(doc,
        "CAT is the honest residue: requirements no specific source in that "
        "research named, present because they are ordinary practice for a "
        "networked service that handles secrets. A row carried only by CAT is "
        "the weakest-sourced kind in the table, and is marked in amber so it "
        "reads that way at a glance rather than hiding among the others.",
        italic=True, size=9, colour=DARK_GREY)
    doc.add_page_break()

    # ── the matrix, one table per domain ─────────────────────────────────
    per_source = {c: 0 for c in COLS}
    cat_only = []

    for domain in matrix.DOMAINS:
        add_heading(doc, domain["name"], 2, DARK_BLUE)
        tbl = doc.add_table(rows=1, cols=len(COLS) + 2)
        tbl.style = "Table Grid"
        matrix_header(tbl)
        for i, (feature, _expect, status, _route) in enumerate(domain["rows"]):
            marks = PROVENANCE[feature]
            for m in marks:
                per_source[m] += 1
            if marks == ["CAT"]:
                cat_only.append(feature)
            matrix_row(tbl, feature, marks, status, "EEF4FA" if i % 2 == 0 else "FFFFFF")
        widths(tbl)
        section_break(doc)

    doc.add_page_break()

    # ── what the columns add up to ───────────────────────────────────────
    add_heading(doc, "What the columns add up to", 1, DARK_BLUE)
    add_para(doc,
        "Read this as a description of the research, not of the market. A source "
        "with few marks is one whose documentation I read less of, not a product "
        "with fewer features.", size=9.5, italic=True)
    section_break(doc)

    tbl = doc.add_table(rows=1, cols=4)
    tbl.style = "Table Grid"
    for i, text in enumerate(["Source", "Requirements evidenced", "Share of 74", "Kind"]):
        cell = tbl.rows[0].cells[i]
        cell.text = text
        set_cell_bg(cell, "1A3A5C")
        for para in cell.paragraphs:
            for run in para.runs:
                run.bold = True
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                run.font.size = Pt(9)
    kind_label = {"vendor": "Vendor documentation", "standard": "Standard",
                  "residue": "Category baseline"}
    for i, (code, name, kind) in enumerate(SOURCES):
        row = tbl.add_row()
        vals = [f"{code} — {name}", str(per_source[code]),
                f"{per_source[code] * 100 // 74} %", kind_label[kind]]
        for j, v in enumerate(vals):
            cell = row.cells[j]
            cell.text = v
            set_cell_bg(cell, "FBF3E3" if kind == "residue" else
                        ("EEF4FA" if i % 2 == 0 else "FFFFFF"))
            for para in cell.paragraphs:
                for run in para.runs:
                    run.font.size = Pt(9)
        row.cells[0].width = Inches(5.2)
        for j, w in enumerate([5.2, 1.8, 1.4, 2.19]):
            row.cells[j].width = Inches(w)
    section_break(doc)

    add_para(doc, f"Requirements carried only by the category baseline: "
                  f"{len(cat_only)} of 74", bold=True, colour=WARN_AMBER)
    add_para(doc,
        "These are the rows to challenge first if the requirement list is ever "
        "disputed. Each is defensible as ordinary practice, but none was named "
        "by a vendor or a standard in the research behind the matrix.", size=9.5)
    for f in cat_only:
        add_bullet(doc, f, size=9)
    section_break(doc)

    add_para(doc, "What would make this stronger", bold=True, colour=MID_BLUE)
    for item in [
        "A hands-on evaluation of one or two products, which would turn this "
        "provenance table into a genuine capability comparison.",
        "The vendors' administration guides rather than their marketing pages — "
        "the former say what a product does, the latter what it advertises.",
        "An analyst grid, which would add an independent view of the category "
        "rather than each vendor's own.",
    ]:
        add_bullet(doc, item, size=9.5)

    section_break(doc)
    f = doc.add_paragraph()
    f.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fr = f.add_run(f"KMIP on PKCS#11 — requirement provenance — {TODAY}")
    fr.font.size = Pt(8)
    fr.font.color.rgb = RGBColor(0x80, 0x80, 0x80)

    out = "KMIP_PKCS11_Feature_Provenance.docx"
    doc.save(out)
    print(f"Saved: {out}")
    print(f"  74 requirements · {len(cat_only)} carried by the category baseline alone")
    for code, _n, _k in SOURCES:
        print(f"  {code}: {per_source[code]}")


if __name__ == "__main__":
    build()
