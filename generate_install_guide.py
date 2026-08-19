#!/usr/bin/env python3
"""Generate KMIP PKCS#11 Installation & Testing Guide (Word format)."""

from docx import Document
from docx.shared import Pt, RGBColor, Cm, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import datetime

# ── colour palette ────────────────────────────────────────────────────────────
DARK_BLUE   = RGBColor(0x1F, 0x39, 0x64)   # headings
MID_BLUE    = RGBColor(0x2E, 0x74, 0xB5)   # subheadings / accent
LIGHT_BLUE  = RGBColor(0xD6, 0xE4, 0xF0)   # table header fill
CODE_BG     = RGBColor(0xF2, 0xF2, 0xF2)   # code block background
GREEN       = RGBColor(0x37, 0x86, 0x44)   # pass indicators
ORANGE      = RGBColor(0xD8, 0x6B, 0x00)   # warning / note
WHITE       = RGBColor(0xFF, 0xFF, 0xFF)

def _rgb_hex(color: RGBColor) -> str:
    """Convert RGBColor to uppercase hex string (no '#')."""
    return str(color).upper()  # RGBColor.__str__ returns e.g. '2E74B5'

CODE_FONT   = "Courier New"
BODY_FONT   = "Calibri"

# ── helpers ───────────────────────────────────────────────────────────────────

def set_cell_bg(cell, rgb: RGBColor):
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd  = OxmlElement('w:shd')
    hex_color = _rgb_hex(rgb)
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), hex_color)
    tcPr.append(shd)


def add_paragraph_shading(para, rgb: RGBColor):
    pPr  = para._p.get_or_add_pPr()
    shd  = OxmlElement('w:shd')
    hex_color = _rgb_hex(rgb)
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), hex_color)
    pPr.append(shd)


def h1(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(18)
    p.paragraph_format.space_after  = Pt(6)
    run = p.add_run(text)
    run.bold      = True
    run.font.size = Pt(18)
    run.font.color.rgb = DARK_BLUE
    run.font.name = BODY_FONT
    # bottom border
    pPr  = p._p.get_or_add_pPr()
    pBdr = OxmlElement('w:pBdr')
    bottom = OxmlElement('w:bottom')
    bottom.set(qn('w:val'), 'single')
    bottom.set(qn('w:sz'), '6')
    bottom.set(qn('w:space'), '1')
    bottom.set(qn('w:color'), _rgb_hex(MID_BLUE))
    pBdr.append(bottom)
    pPr.append(pBdr)
    return p


def h2(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(12)
    p.paragraph_format.space_after  = Pt(3)
    run = p.add_run(text)
    run.bold      = True
    run.font.size = Pt(14)
    run.font.color.rgb = MID_BLUE
    run.font.name = BODY_FONT
    return p


def h3(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after  = Pt(2)
    run = p.add_run(text)
    run.bold      = True
    run.font.size = Pt(12)
    run.font.color.rgb = DARK_BLUE
    run.font.name = BODY_FONT
    return p


def body(doc, text, space_after=4):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after  = Pt(space_after)
    run = p.add_run(text)
    run.font.size = Pt(11)
    run.font.name = BODY_FONT
    return p


def note(doc, text, color=ORANGE):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after  = Pt(6)
    p.paragraph_format.left_indent  = Cm(0.5)
    add_paragraph_shading(p, RGBColor(0xFF, 0xF4, 0xE5))
    run = p.add_run("⚠  " + text)
    run.font.size = Pt(10)
    run.font.color.rgb = color
    run.font.name = BODY_FONT
    return p


def tip(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after  = Pt(6)
    p.paragraph_format.left_indent  = Cm(0.5)
    add_paragraph_shading(p, RGBColor(0xE8, 0xF5, 0xE9))
    run = p.add_run("✔  " + text)
    run.font.size = Pt(10)
    run.font.color.rgb = GREEN
    run.font.name = BODY_FONT
    return p


def code_block(doc, lines, title=None):
    if title:
        tp = doc.add_paragraph()
        tp.paragraph_format.space_before = Pt(6)
        tp.paragraph_format.space_after  = Pt(0)
        tr = tp.add_run(title)
        tr.bold           = True
        tr.font.size      = Pt(9)
        tr.font.color.rgb = RGBColor(0x60, 0x60, 0x60)
        tr.font.name      = BODY_FONT

    for i, line in enumerate(lines):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after  = Pt(0)
        p.paragraph_format.left_indent  = Cm(0.4)
        p.paragraph_format.right_indent = Cm(0.4)
        add_paragraph_shading(p, CODE_BG)
        run = p.add_run(line if line else " ")
        run.font.name  = CODE_FONT
        run.font.size  = Pt(9)
        run.font.color.rgb = RGBColor(0x1A, 0x1A, 0x1A)

    # bottom spacer
    sp = doc.add_paragraph()
    sp.paragraph_format.space_before = Pt(0)
    sp.paragraph_format.space_after  = Pt(6)
    add_paragraph_shading(sp, CODE_BG)
    sp.add_run(" ").font.size = Pt(3)


def bullet(doc, text, level=0):
    p = doc.add_paragraph(style='List Bullet')
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after  = Pt(2)
    p.paragraph_format.left_indent  = Cm(0.6 + level * 0.6)
    run = p.add_run(text)
    run.font.size = Pt(11)
    run.font.name = BODY_FONT
    return p


def table_header_row(table, headers, col_widths_cm=None):
    row = table.rows[0]
    for i, hdr in enumerate(headers):
        cell = row.cells[i]
        set_cell_bg(cell, DARK_BLUE)
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after  = Pt(2)
        run = p.add_run(hdr)
        run.bold           = True
        run.font.color.rgb = WHITE
        run.font.size      = Pt(10)
        run.font.name      = BODY_FONT


def add_table_row(table, values, shade_even=False, idx=0):
    row = table.add_row()
    for j, val in enumerate(values):
        cell = row.cells[j]
        if shade_even and idx % 2 == 0:
            set_cell_bg(cell, RGBColor(0xF5, 0xF8, 0xFF))
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(1)
        p.paragraph_format.space_after  = Pt(1)
        is_code = val.startswith('`') and val.endswith('`')
        text = val[1:-1] if is_code else val
        run = p.add_run(text)
        run.font.size = Pt(10)
        run.font.name = CODE_FONT if is_code else BODY_FONT


def make_table(doc, headers, rows, col_widths=None):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = 'Table Grid'
    t.alignment = WD_TABLE_ALIGNMENT.LEFT
    table_header_row(t, headers)
    for i, row in enumerate(rows):
        add_table_row(t, row, shade_even=True, idx=i)
    if col_widths:
        for i, row in enumerate(t.rows):
            for j, cell in enumerate(row.cells):
                cell.width = Cm(col_widths[j])
    return t


# ═════════════════════════════════════════════════════════════════════════════
# Document assembly
# ═════════════════════════════════════════════════════════════════════════════

def build():
    doc = Document()

    # Page margins
    for section in doc.sections:
        section.top_margin    = Cm(2.0)
        section.bottom_margin = Cm(2.0)
        section.left_margin   = Cm(2.5)
        section.right_margin  = Cm(2.5)

    # ── Cover ────────────────────────────────────────────────────────────────
    doc.add_paragraph()
    title_p = doc.add_paragraph()
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    tr = title_p.add_run("KMIP on PKCS#11")
    tr.bold           = True
    tr.font.size      = Pt(32)
    tr.font.color.rgb = DARK_BLUE
    tr.font.name      = BODY_FONT

    sub_p = doc.add_paragraph()
    sub_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sr = sub_p.add_run("Installation, Compilation & Test Execution Guide")
    sr.font.size      = Pt(16)
    sr.font.color.rgb = MID_BLUE
    sr.font.name      = BODY_FONT

    doc.add_paragraph()
    meta_p = doc.add_paragraph()
    meta_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    mr = meta_p.add_run(
        f"Version 1.0  ·  {datetime.date.today().strftime('%B %d, %Y')}"
    )
    mr.font.size      = Pt(11)
    mr.font.color.rgb = RGBColor(0x60, 0x60, 0x60)
    mr.font.name      = BODY_FONT

    doc.add_paragraph()
    doc.add_paragraph()

    # ── 1  Overview ──────────────────────────────────────────────────────────
    h1(doc, "1  Overview")
    body(doc,
        "This document describes how to install all dependencies, build the "
        "kmip_pkcs11 Python package, initialise a SoftHSM2 token, and execute "
        "the automated test suite (811 tests, 100 % pass rate). The server "
        "implements 41 of the 53 KMIP 2.1 operations (see Known Limitations "
        "in README.md for the 12 deliberately deferred). All steps have "
        "been validated on Ubuntu 22.04 LTS / Debian 12 with Python 3.11.")

    make_table(doc,
        ["Component", "Minimum Version", "Role"],
        [
            ["Python",          "3.9",    "Runtime language"],
            ["SoftHSM2",        "2.6",    "Software PKCS#11 HSM (token storage)"],
            ["python-pkcs11",   "0.9.5",  "PKCS#11 Python bindings"],
            ["PyKCS11",         "1.5.0",  "Alternate PKCS#11 binding (optional, declared in setup.py)"],
            ["pytest",          "7.0",    "Test runner"],
            ["pytest-cov",      "4.0",    "Coverage reporting"],
            ["setuptools",      "40.0",   "Package build tool (standard library)"],
        ],
        col_widths=[5, 4, 9]
    )
    doc.add_paragraph()

    # ── 2  System prerequisites ───────────────────────────────────────────────
    h1(doc, "2  System Prerequisites")

    h2(doc, "2.1  Operating System Packages")
    body(doc,
        "Install SoftHSM2 and the Python 3 development headers using your "
        "distribution package manager. The commands below target Debian/Ubuntu.")
    code_block(doc, [
        "# Update package index",
        "sudo apt update",
        "",
        "# SoftHSM2 — software PKCS#11 token",
        "sudo apt install -y softhsm2",
        "",
        "# Python 3.11 and build tools (if not already present)",
        "sudo apt install -y python3.11 python3.11-venv python3-pip build-essential",
        "",
        "# Verify SoftHSM2 installation",
        "softhsm2-util --version",
        "# Expected output: 2.6.1 (or higher)",
    ], title="Shell — install system packages")

    note(doc,
        "On RHEL / CentOS / Fedora replace 'apt install' with "
        "'dnf install softhsm python3-devel gcc'. The SoftHSM2 library path "
        "will be /usr/lib64/softhsm/libsofthsm2.so on RPM-based systems.")

    h2(doc, "2.2  Locating the PKCS#11 Library")
    body(doc,
        "The test framework auto-detects the SoftHSM2 shared library. "
        "If it is not found at the default path, set the SOFTHSM2_LIB "
        "environment variable.")
    code_block(doc, [
        "# Default path on Debian/Ubuntu x86-64:",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "",
        "# Default path on Debian/Ubuntu aarch64:",
        "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
        "",
        "# Override when needed:",
        "export SOFTHSM2_LIB=/path/to/libsofthsm2.so",
    ], title="Library paths")

    # ── 3  Project installation ───────────────────────────────────────────────
    h1(doc, "3  Project Installation")

    h2(doc, "3.1  Clone the Repository")
    code_block(doc, [
        "git clone https://github.com/Gaillotte/Noida.git",
        "cd Noida",
    ], title="Shell")

    h2(doc, "3.2  Create a Virtual Environment (Recommended)")
    body(doc,
        "Using a virtual environment isolates the project dependencies from the "
        "system Python installation.")
    code_block(doc, [
        "# Create the virtual environment",
        "python3 -m venv .venv",
        "",
        "# Activate it",
        "source .venv/bin/activate          # Linux / macOS",
        r".venv\Scripts\activate            # Windows PowerShell",
        "",
        "# Confirm the Python version",
        "python --version",
        "# Expected: Python 3.11.x (or 3.9+)",
    ], title="Shell — virtual environment setup")

    h2(doc, "3.3  Install the Package in Editable Mode")
    body(doc,
        "Editable mode ('pip install -e') links the source tree directly, so "
        "any code change is picked up immediately without reinstalling.")
    code_block(doc, [
        "# Install the package and ALL dependencies (including dev extras)",
        "pip install -e '.[dev]'",
        "",
        "# Verify that the key packages are present",
        "pip show kmip_pkcs11 python-pkcs11 PyKCS11 pytest pytest-cov",
    ], title="Shell — editable install")
    tip(doc,
        "After a successful install you should see 'kmip_pkcs11' listed in "
        "'pip list'. The version is 1.0.0.")

    h2(doc, "3.4  Installed Dependency Versions (Reference)")
    make_table(doc,
        ["Package", "Installed Version"],
        [
            ["`python-pkcs11`", "0.9.5"],
            ["`PyKCS11`",       "1.5.18"],
            ["`pytest`",        "9.1.0"],
            ["`pytest-cov`",    "7.1.0"],
        ],
        col_widths=[7, 6]
    )
    doc.add_paragraph()

    # ── 4  SoftHSM2 token initialisation ─────────────────────────────────────
    h1(doc, "4  SoftHSM2 Token Initialisation")
    body(doc,
        "The tests create and manage their own temporary SoftHSM2 token "
        "automatically via the conftest.py session fixture. No manual "
        "token initialisation is required before running the test suite. "
        "However, you may initialise a persistent token manually for "
        "interactive development or to run the demo script.")

    h2(doc, "4.1  Automatic (Test Suite)")
    body(doc,
        "The pytest session fixture in conftest.py runs the following "
        "initialisation automatically before any test:")
    code_block(doc, [
        "# Fixture actions (conftest.py — executed automatically)",
        "mkdir -p /tmp/softhsm2_tests/tokens",
        "",
        "# softhsm2.conf is written to /tmp/softhsm2_tests/softhsm2.conf",
        "# SOFTHSM2_CONF is exported to that path",
        "",
        "softhsm2-util --init-token --slot 0 \\",
        "  --label KMIPTestSuite \\",
        "  --pin 9999 \\",
        "  --so-pin 8888",
    ], title="Automatic initialisation (reference — do not run manually)")

    h2(doc, "4.2  Manual (Demo / Development)")
    body(doc,
        "To run the interactive demo or develop against a real token, "
        "initialise a token in a directory of your choice:")
    code_block(doc, [
        "# Create a token directory",
        "mkdir -p ~/kmip_tokens",
        "",
        "# Write a SoftHSM2 config file",
        "cat > ~/softhsm2.conf <<EOF",
        "directories.tokendir = /root/kmip_tokens",
        "objectstore.backend = file",
        "log.level = ERROR",
        "EOF",
        "",
        "# Point SoftHSM2 at this config",
        "export SOFTHSM2_CONF=~/softhsm2.conf",
        "",
        "# Initialise the token",
        "softhsm2-util --init-token --slot 0 \\",
        "  --label KMIPTest --pin 1234 --so-pin 5678",
        "",
        "# Confirm the token is visible",
        "softhsm2-util --show-slots",
    ], title="Shell — manual token initialisation")

    # ── 5  Running the Tests ─────────────────────────────────────────────────
    h1(doc, "5  Running the Tests")

    h2(doc, "5.1  Quick Start — Run Everything")
    code_block(doc, [
        "# From the repository root (with the virtual environment active)",
        "pytest",
        "",
        "# Or explicitly point pytest at the test directory",
        "pytest kmip_pkcs11/tests/",
    ], title="Shell")
    tip(doc, "All 811 tests should pass, at a 100 % pass rate, run live against a real SoftHSM2 token.")

    h2(doc, "5.2  Verbose Output")
    code_block(doc, [
        "pytest -v",
        "",
        "# Example output (excerpt):",
        "# kmip_pkcs11/tests/test_ttlv.py::TestEncodeDecode::test_integer_positive PASSED",
        "# kmip_pkcs11/tests/test_lifecycle.py::TestTransitions::test_activate  PASSED",
        "# ...",
        "# 624 passed",
    ], title="Shell — verbose mode")

    h2(doc, "5.3  Run a Single Test Module")
    code_block(doc, [
        "# TTLV codec unit tests only (no HSM required)",
        "pytest kmip_pkcs11/tests/test_ttlv.py -v",
        "",
        "# Lifecycle state machine tests only",
        "pytest kmip_pkcs11/tests/test_lifecycle.py -v",
        "",
        "# Metadata store unit tests only",
        "pytest kmip_pkcs11/tests/test_metadata.py -v",
        "",
        "# Operation integration tests (requires SoftHSM2)",
        "pytest kmip_pkcs11/tests/test_operations.py -v",
        "",
        "# KMIP conformance tests (requires SoftHSM2)",
        "pytest kmip_pkcs11/tests/test_conformance.py -v",
        "",
        "# Extended coverage tests — every operation, algorithm/mode coverage,",
        "# error paths, access control, session concurrency (requires SoftHSM2)",
        "pytest kmip_pkcs11/tests/test_extended_coverage.py -v",
    ], title="Shell — individual modules")

    h2(doc, "5.4  Run Tests Without a Hardware Token")
    body(doc,
        "Three modules do not require SoftHSM2 and can be run in any environment:")
    code_block(doc, [
        "pytest kmip_pkcs11/tests/test_ttlv.py \\",
        "       kmip_pkcs11/tests/test_lifecycle.py \\",
        "       kmip_pkcs11/tests/test_metadata.py -v",
    ], title="Shell — HSM-free tests")
    note(doc,
        "test_metadata.py uses an in-memory SQLite database — no SoftHSM2 session is opened.")

    h2(doc, "5.5  Run Tests Matching a Keyword")
    code_block(doc, [
        "# Only tests whose name contains 'aes'",
        "pytest -k aes -v",
        "",
        "# Only tests related to encryption / decryption",
        "pytest -k 'encrypt or decrypt' -v",
        "",
        "# Only error-handling tests",
        "pytest -k 'error or raises or missing' -v",
    ], title="Shell — keyword filtering")

    h2(doc, "5.6  Stop on First Failure")
    code_block(doc, [
        "pytest -x          # stop after the first failed test",
        "pytest --lf        # re-run only the tests that failed last time",
    ], title="Shell")

    # ── 6  Coverage Reports ──────────────────────────────────────────────────
    h1(doc, "6  Code Coverage Reports")

    h2(doc, "6.1  Terminal Report")
    code_block(doc, [
        "# Run with per-line coverage, missing lines shown",
        "python -m pytest -p pytest_cov \\",
        "  --cov=kmip_pkcs11 \\",
        "  --cov-report=term-missing \\",
        "  -q",
    ], title="Shell")

    h2(doc, "6.2  HTML Report")
    code_block(doc, [
        "# Generate interactive HTML report in coverage_html/",
        "python -m pytest -p pytest_cov \\",
        "  --cov=kmip_pkcs11 \\",
        "  --cov-report=term-missing \\",
        "  --cov-report=html:coverage_html \\",
        "  -q",
        "",
        "# Open the report in a browser",
        "xdg-open coverage_html/index.html       # Linux",
        "open coverage_html/index.html            # macOS",
        "start coverage_html/index.html           # Windows",
    ], title="Shell — HTML report")

    h2(doc, "6.3  Current Coverage Summary")
    body(doc, "Results from the current test run (811 tests, run live against a real SoftHSM2 token):")
    make_table(doc,
        ["Test Module", "Tests", "Pass Rate", "Notes"],
        [
            ["test_ttlv.py",              "22",  "100 %", "TTLV codec — no HSM needed"],
            ["test_lifecycle.py",          "26",  "100 %", "State machine — no HSM needed"],
            ["test_metadata.py",           "18",  "100 %", "SQLite store — no HSM needed"],
            ["test_operations.py",          "8",  "100 %", "Operation integration"],
            ["test_conformance.py",        "48",  "100 %", "KMIP 2.1 conformance (OASIS TC mapping)"],
            ["test_governance.py",         "48",  "100 %", "Cryptoperiod enforcement, dual control, group grants, per-role operation allowlists"],
            ["test_extended_coverage.py", "641",  "100 %", "Every operation, algorithm/mode coverage, error paths, access control, session concurrency"],
            ["TOTAL",                     "811",  "100 %", "All modules run live against a real SoftHSM2 token"],
        ],
        col_widths=[6, 2.5, 3, 6.5]
    )
    doc.add_paragraph()
    note(doc,
        "demo.py is intentionally excluded from the automated test suite — it "
        "requires a fully running server and an interactive environment and is "
        "exercised manually (see Section 1 / README.md Quick Start).")

    # ── 7  Test Module Reference ─────────────────────────────────────────────
    h1(doc, "7  Test Module Reference")

    h2(doc, "7.1  Module Descriptions")
    make_table(doc,
        ["File", "Description", "HSM Required?"],
        [
            ["test_ttlv.py",
             "22 unit tests for the TTLV binary encoder/decoder: all primitive types "
             "(Integer, Long, BigInteger, Boolean, TextString, ByteString, DateTime, "
             "Interval, Enumeration), structure nesting, padding, tag repr.",
             "No"],
            ["test_lifecycle.py",
             "26 unit tests for the key lifecycle state machine (lifecycle/state_machine.py): "
             "all legal transitions (PreActive→Active→Deactivated→Compromised→Destroyed / "
             "DestroyedCompromised), all forbidden transitions, revoke(normal) vs. "
             "revoke(compromise) branching, and usage-allowed checks per state.",
             "No"],
            ["test_metadata.py",
             "18 unit tests for the SQLite metadata store: create/get/update/delete, "
             "activation-date auto-activation, state transitions, locate filters (name, "
             "type, algorithm, state, owner), attribute CRUD.",
             "No"],
            ["test_operations.py",
             "8 integration tests exercising the operation handlers end-to-end through "
             "a live server/client pair: Create AES-128, Destroy, Locate, AES-CBC "
             "encrypt/decrypt, Activate, Revoke.",
             "Yes"],
            ["test_conformance.py",
             "48 KMIP 2.1 conformance tests organised into 11 test classes matching "
             "OASIS TC identifiers: DiscoverVersions, Query, Create, CreateKeyPair, "
             "Get, GetAttributes, Locate, Lifecycle, Encrypt/Decrypt, "
             "Attributes, ErrorHandling.",
             "Yes"],
            ["test_governance.py",
             "48 tests covering the governance layer: cryptoperiod enforcement (scheduled "
             "deactivation, expiry warnings, auto-rotation cross-linked to the expiring key), "
             "dual control (first attempt refused, the requester barred from approving their "
             "own request, an approval consumed after exactly one use, expiry, retry reusing "
             "the open request), group grants, and per-role operation allowlists. Includes "
             "one end-to-end test over the wire that a refused Destroy leaves the key intact.",
             "Yes"],
            ["test_extended_coverage.py",
             "641 live tests — by far the largest module. Exercises every one of the "
             "41 implemented KMIP operations end-to-end against the live SoftHSM2 token; "
             "full algorithm and block-cipher-mode coverage (GCM/CTR/CFB/OFB/CCM, RSA, "
             "EC/ECDSA/ECDH, DSA, DH, HMAC, MAC, hashing, split-key, derive-key, wrap/"
             "unwrap); capability-gating (mechanisms the token doesn't support must fail "
             "cleanly with OperationNotSupported, never a raw PKCS#11 error); error paths "
             "across every handler; the access-control model (object ownership, the admin "
             "role, and delegated read/full grants — see README.md's Access Control "
             "section); and session-concurrency regression tests that hammer the shared "
             "PKCS#11 session with multiple threads at once, verifying correctness under "
             "the threading.RLock in pkcs11_shim/shim.py.",
             "Yes (nearly all tests)"],
        ],
        col_widths=[4.5, 11, 2.5]
    )
    doc.add_paragraph()

    h2(doc, "7.2  Shared Fixtures (conftest.py)")
    body(doc,
        "All test modules share the fixtures defined in "
        "kmip_pkcs11/tests/conftest.py:")
    make_table(doc,
        ["Fixture", "Scope", "Description"],
        [
            ["softhsm_token", "session (auto-use)",
             "Creates /tmp/softhsm2_tests/ and initialises a SoftHSM2 token "
             "labelled KMIPTestSuite (PIN: 9999, SO-PIN: 8888)."],
            ["store",         "function",
             "Returns a fresh MetadataStore backed by a temporary SQLite file "
             "in pytest's tmp_path directory."],
            ["shim",          "session",
             "Opens and yields an initialised PKCS11Shim connected to the "
             "KMIPTestSuite token. Finalised after all tests complete."],
            ["server_client", "function",
             "Spins up a KMIPServer on a unique port (starting at 15700) backed "
             "by the session-scoped shim, connects a single KMIPClient, and "
             "yields (client, store). Tears down after each test."],
            ["kmip_server",   "function",
             "Spins up a KMIPServer the same way as server_client but without "
             "attaching a client, so a test can connect multiple KMIPClients "
             "(e.g. with different Credentials) against the same running "
             "server — used by the access-control and concurrency tests. "
             "Yields (store, port)."],
        ],
        col_widths=[3.5, 4, 10.5]
    )
    doc.add_paragraph()

    # ── 8  Environment Variables ──────────────────────────────────────────────
    h1(doc, "8  Environment Variables")
    make_table(doc,
        ["Variable", "Default Value", "Effect"],
        [
            ["SOFTHSM2_LIB",
             "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
             "Path to the SoftHSM2 shared library. Override when the library "
             "is installed at a non-standard location."],
            ["SOFTHSM2_CONF",
             "Auto-created by conftest.py at /tmp/softhsm2_tests/softhsm2.conf",
             "SoftHSM2 configuration file path. Set this manually only when "
             "running the demo script or developing interactively."],
        ],
        col_widths=[4, 6, 8]
    )
    doc.add_paragraph()

    # ── 9  Troubleshooting ────────────────────────────────────────────────────
    h1(doc, "9  Troubleshooting")

    problems = [
        ("pkcs11.exceptions.NoSuchToken",
         "The SoftHSM2 token was not initialised, or SOFTHSM2_CONF does not "
         "point to the correct configuration file.",
         ["export SOFTHSM2_CONF=/tmp/softhsm2_tests/softhsm2.conf",
          "softhsm2-util --show-slots"]),
        ("ImportError: No module named 'pkcs11'",
         "python-pkcs11 is not installed in the active Python environment.",
         ["pip install python-pkcs11>=0.7.0"]),
        ("AttributeReadOnly from SoftHSM2 during key import",
         "Fixed in this release: CKA_VALUE_LEN was incorrectly included when "
         "supplying CKA_VALUE. The shim's import_symmetric_key() now omits it.",
         ["# No user action required — the bug is fixed in the current code."]),
        ("generate_random returns fewer bytes than requested",
         "Fixed in this release: python-pkcs11's generate_random() takes bits, "
         "not bytes. The shim now passes length * 8.",
         ["# No user action required — the bug is fixed in the current code."]),
        ("ValueError: asn1crypto does not contain an entry for 'P-256'",
         "Fixed in this release: the EC key generation in the shim now uses "
         "the canonical OID name 'secp256r1'.",
         ["# No user action required — the bug is fixed in the current code."]),
        ("OverflowError: Python int too large to convert to SQLite INTEGER",
         "Fixed in this release: the Register operation now takes only the "
         "low 63 bits of the CKA_ID when storing the pkcs11_handle.",
         ["# No user action required — the bug is fixed in the current code."]),
        ("pytest: unrecognized arguments: --cov",
         "pytest-cov must be loaded explicitly when invoking via 'python -m pytest'.",
         ["python -m pytest -p pytest_cov --cov=kmip_pkcs11 --cov-report=term-missing"]),
        ("Native crash / segfault under concurrent load",
         "This is not a bug to fix — it is the known python-pkcs11 / SoftHSM2 "
         "threading limitation documented in README.md's Known Limitations. "
         "python-pkcs11 0.9.5 calls C_Initialize(NULL), so the library never "
         "enables its own internal thread safety; separate PKCS#11 sessions per "
         "thread do not work around that and reproducibly segfault or corrupt "
         "operations under concurrency. The fix already in place is the single, "
         "shared PKCS#11 session serialized by the threading.RLock in "
         "pkcs11_shim/shim.py (server.py runs one thread per client connection, "
         "but all threads share that one locked session). Do not attempt to add "
         "a session pool as a fix — a real fix would require a PKCS#11 binding "
         "that passes CKF_OS_LOCKING_OK, or a multi-process worker pool.",
         ["# No user action required — the lock in pkcs11_shim/shim.py is the fix."]),
        ("OperationFailed / NotAuthorized or PermissionDenied on an operation that used to work",
         "The calling identity is neither the owner of the object nor holds the "
         "admin role nor has a delegated grant for it. Access control "
         "(lifecycle/access_control.py) checks, in order: admin role, "
         "ownership (set at Create/Register/etc. time), a delegated "
         "'read' or 'full' grant, then a grant to a group the identity belongs to. "
         "A role's operation allowlist is checked before all of these, and can refuse "
         "an operation outright. See the Access Control section of "
         "README.md for the full authorization model.",
         ["# Grant an identity the admin role (unconditional access to every object):",
          "kmip-admin -c config.yaml role grant alice admin",
          "",
          "# Or delegate access to one specific object without transferring ownership:",
          "kmip-admin -c config.yaml access grant <uid> bob --permission read",
          "",
          "# Or grant the whole team, by group:",
          "kmip-admin -c config.yaml group add bob crypto-team",
          "kmip-admin -c config.yaml access grant <uid> group:crypto-team --permission read",
          "",
          "# Check whether a role allowlist is what is refusing the operation:",
          "kmip-admin -c config.yaml permission show <role>"]),
        ("OperationFailed / PermissionDenied saying an operation \"requires N approval(s)\"",
         "Dual control is enabled (governance.dual_control) and this operation is on the "
         "protected list. The operation did not run — the handler is never reached. Have "
         "the required number of OTHER identities approve the request named in the error "
         "message, then retry. The requester can never approve their own request, and an "
         "approval is consumed by a single attempt.",
         ["kmip-admin -c config.yaml approval list",
          "kmip-admin -c config.yaml approval approve <request-id> --as bob",
          "kmip-admin -c config.yaml approval approve <request-id> --as carol",
          "# then the original client retries the operation"]),
        ("A key became Deactivated with nothing in the client logs asking for it",
         "The cryptoperiod scheduler (governance.enabled) deactivated it because its "
         "Deactivation Date had passed. This is recorded in the audit log under the "
         "identity system:scheduler, so it is attributable like any other action.",
         ["kmip-admin -c config.yaml audit list --object-uid <uid>",
          "kmip-admin -c config.yaml cryptoperiod expiring --within-days 30",
          "",
          "# Give a key a new cryptoperiod (or push the existing one out):",
          "kmip-admin -c config.yaml cryptoperiod set <uid> --days 365"]),
    ]

    for title, desc, cmds in problems:
        h3(doc, title)
        body(doc, desc, space_after=2)
        if cmds:
            code_block(doc, cmds)

    # ── 10  Project Structure ─────────────────────────────────────────────────
    h1(doc, "10  Project Structure")
    body(doc, "The layout of all source and test files:")
    code_block(doc, [
        "Noida/",
        "├── setup.py                    # Package definition & dependencies",
        "├── pytest.ini                  # Default pytest configuration",
        "├── README.md              # Project overview",
        "├── generate_docs.py            # Word documentation generator",
        "├── generate_install_guide.py   # This document generator",
        "├── coverage_html/              # HTML coverage report (generated)",
        "└── kmip_pkcs11/",
        "    ├── core/",
        "    │   ├── enums.py            # KMIP enumerations (Tag, Operation, State, …)",
        "    │   ├── ttlv.py             # TTLV encoder / decoder",
        "    │   └── exceptions.py       # KMIP exception hierarchy",
        "    ├── lifecycle/",
        "    │   ├── state_machine.py    # Key lifecycle state transitions",
        "    │   ├── access_control.py   # Owner / admin / grants / groups / role allowlists",
        "    │   ├── dual_control.py     # M-of-N approval for destructive operations",
        "    │   └── governance.py       # Cryptoperiod scan, scheduled deactivation/rotation",
        "    ├── metadata/",
        "    │   ├── store.py            # SQLite store (objects, attrs, identities, roles,",
        "    │   │                       #   groups, grants, approvals, audit chain)",
        "    │   ├── backup.py           # Online backup / restore with token pairing checks",
        "    │   └── blob_cipher.py      # AES-GCM envelope encryption under an HSM master key",
        "    ├── pkcs11_shim/",
        "    │   └── shim.py             # PKCS#11 / SoftHSM2 wrapper, capability probe, session lock",
        "    ├── operations/             # One file per KMIP operation (41 files total) — dispatcher.py routes",
        "    │   ├── dispatcher.py",
        "    │   ├── create.py, create_keypair.py, register.py, import_op.py, export_op.py",
        "    │   ├── get.py, get_attributes.py, get_usage_allocation.py, locate.py",
        "    │   ├── add_attribute.py, modify_attribute.py, delete_attribute.py,",
        "    │   │   set_attribute.py, adjust_attribute.py",
        "    │   ├── activate.py, revoke.py, destroy.py, archive.py, recover.py, check.py",
        "    │   ├── encrypt.py, decrypt.py, sign.py, signature_verify.py",
        "    │   ├── mac.py, mac_verify.py, hash_op.py",
        "    │   ├── rekey.py, rekey_keypair.py, certify.py, recertify.py",
        "    │   ├── derive_key.py, create_split_key.py, join_split_key.py",
        "    │   ├── validate.py, obtain_lease.py, rng_retrieve.py, rng_seed.py",
        "    │   └── query.py, discover_versions.py",
        "    ├── server/",
        "    │   ├── server.py           # TCP server (thread-per-client, auth, TLS, request caps)",
        "    │   └── workers.py          # Pre-fork multi-process worker pool",
        "    ├── config.py               # YAML configuration loading and validation",
        "    ├── observability.py        # Metrics, health endpoints, JSON logging",
        "    ├── cli/",
        "    │   ├── server_cli.py       # kmip-server entry point",
        "    │   └── admin_cli.py        # kmip-admin: identities, roles, groups, grants,",
        "    │                           #   permissions, approvals, cryptoperiods, audit,",
        "    │                           #   backup, master-key rotation",
        "    ├── test_app/",
        "    │   ├── client.py           # Synchronous KMIP 2.1 client",
        "    │   └── demo.py             # End-to-end demo",
        "    └── tests/",
        "        ├── conftest.py         # Shared fixtures",
        "        ├── test_ttlv.py              #  22 TTLV unit tests",
        "        ├── test_lifecycle.py         #  26 lifecycle state-machine tests",
        "        ├── test_metadata.py          #  18 metadata store unit tests",
        "        ├── test_operations.py        #   8 operation integration tests",
        "        ├── test_conformance.py       #  48 OASIS KMIP conformance tests",
        "        ├── test_governance.py        #  48 governance tests: cryptoperiod, dual",
        "        │                             #   control, groups, role allowlists",
        "        └── test_extended_coverage.py # 641 live tests: every operation, algorithm",
        "                                      #  coverage, error paths, access control,",
        "                                      #  session concurrency",
    ], title="Repository layout")

    # ── 11  Quick-Reference Commands ─────────────────────────────────────────
    h1(doc, "11  Quick-Reference Command Summary")
    make_table(doc,
        ["Goal", "Command"],
        [
            ["Install all dependencies",
             "`pip install -e '.[dev]'`"],
            ["Run the full test suite",
             "`pytest`"],
            ["Run with verbose output",
             "`pytest -v`"],
            ["Run unit tests only (no HSM)",
             "`pytest kmip_pkcs11/tests/test_ttlv.py kmip_pkcs11/tests/test_lifecycle.py kmip_pkcs11/tests/test_metadata.py`"],
            ["Run a specific test class",
             "`pytest -k TestCreate -v`"],
            ["Run a specific test method",
             "`pytest kmip_pkcs11/tests/test_conformance.py::TestCreate::test_create_aes256_returns_uid -v`"],
            ["Stop on first failure",
             "`pytest -x`"],
            ["Re-run only last failures",
             "`pytest --lf`"],
            ["Terminal coverage report",
             "`python -m pytest -p pytest_cov --cov=kmip_pkcs11 --cov-report=term-missing`"],
            ["HTML coverage report",
             "`python -m pytest -p pytest_cov --cov=kmip_pkcs11 --cov-report=html:coverage_html`"],
            ["Run the demo script",
             "`python -m kmip_pkcs11.test_app.demo`"],
        ],
        col_widths=[6, 12]
    )
    doc.add_paragraph()

    # ── footer note ───────────────────────────────────────────────────────────
    doc.add_paragraph()
    fp = doc.add_paragraph()
    fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fr = fp.add_run(
        "KMIP on PKCS#11  ·  Installation & Test Guide  ·  "
        f"Generated {datetime.date.today().strftime('%Y-%m-%d')}"
    )
    fr.font.size      = Pt(9)
    fr.font.color.rgb = RGBColor(0x90, 0x90, 0x90)
    fr.font.name      = BODY_FONT

    out = "KMIP_PKCS11_Install_Test_Guide.docx"
    doc.save(out)
    print(f"Saved: {out}")
    return out


if __name__ == "__main__":
    build()
