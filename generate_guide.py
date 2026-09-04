#!/usr/bin/env python3
"""Generate the SoftHSM2 KSP — Complete Developer Guide in Word (.docx) format."""

from docx import Document
from docx.shared import Pt, Cm, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import copy

# ── Colour palette ────────────────────────────────────────────────────────────
C_TITLE      = RGBColor(0x1F, 0x39, 0x64)   # dark navy
C_H1         = RGBColor(0x1F, 0x39, 0x64)   # same dark navy
C_H2         = RGBColor(0x2E, 0x74, 0xB5)   # medium blue
C_H3         = RGBColor(0x2E, 0x74, 0xB5)
C_CODE_BG    = RGBColor(0xF2, 0xF2, 0xF2)   # light grey
C_CODE_FG    = RGBColor(0x1C, 0x1C, 0x1C)   # near-black
C_TBL_HEAD   = RGBColor(0x2E, 0x74, 0xB5)   # blue header
C_TBL_HEAD_T = RGBColor(0xFF, 0xFF, 0xFF)   # white text
C_TBL_ALT    = RGBColor(0xDE, 0xEB, 0xF7)   # light blue alt row
C_NOTE_BG    = RGBColor(0xFF, 0xF0, 0xCC)   # amber note
C_WARN_BG    = RGBColor(0xFF, 0xE0, 0xE0)   # light red warning
C_OK_BG      = RGBColor(0xE2, 0xEF, 0xDA)   # light green success

doc = Document()

# ── Page setup ────────────────────────────────────────────────────────────────
section = doc.sections[0]
section.page_width  = Cm(21)
section.page_height = Cm(29.7)
section.top_margin    = Cm(2.5)
section.bottom_margin = Cm(2.5)
section.left_margin   = Cm(2.5)
section.right_margin  = Cm(2.5)

# ── Style helpers ─────────────────────────────────────────────────────────────
def set_font(run, name="Calibri", size=11, bold=False, italic=False, color=None):
    run.font.name   = name
    run.font.size   = Pt(size)
    run.font.bold   = bold
    run.font.italic = italic
    if color:
        run.font.color.rgb = color

def shade_cell(cell, color: RGBColor):
    """Apply a background shading to a table cell."""
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd  = OxmlElement("w:shd")
    hex_color = str(color)
    shd.set(qn("w:val"),   "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"),  hex_color)
    tcPr.append(shd)

def set_cell_border(cell, top=None, bottom=None, left=None, right=None):
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    tcBorders = OxmlElement("w:tcBorders")
    for side, val in [("top", top), ("bottom", bottom), ("left", left), ("right", right)]:
        if val is not None:
            el = OxmlElement(f"w:{side}")
            el.set(qn("w:val"),   val)
            el.set(qn("w:sz"),    "4")
            el.set(qn("w:space"), "0")
            el.set(qn("w:color"), "auto")
            tcBorders.append(el)
    tcPr.append(tcBorders)

def heading1(doc, text):
    p  = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(18)
    p.paragraph_format.space_after  = Pt(6)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    set_font(run, size=16, bold=True, color=C_H1)
    # Bottom border
    pPr  = p._p.get_or_add_pPr()
    pBdr = OxmlElement("w:pBdr")
    bot  = OxmlElement("w:bottom")
    bot.set(qn("w:val"),   "single")
    bot.set(qn("w:sz"),    "8")
    bot.set(qn("w:space"), "1")
    bot.set(qn("w:color"), "2E74B5")
    pBdr.append(bot)
    pPr.append(pBdr)
    return p

def heading2(doc, text):
    p   = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(12)
    p.paragraph_format.space_after  = Pt(4)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    set_font(run, size=13, bold=True, color=C_H2)
    return p

def heading3(doc, text):
    p   = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after  = Pt(2)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    set_font(run, size=11, bold=True, color=C_H3)
    return p

def body(doc, text="", bold_parts=None):
    """Add a body paragraph. bold_parts is list of (start_idx, end_idx) unused here —
    use inline() for mixed formatting."""
    p   = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after  = Pt(4)
    run = p.add_run(text)
    set_font(run, size=10.5)
    return p

def inline(doc, parts):
    """parts: list of (text, bold, italic, color, mono).
       mono=True → Courier New 10pt."""
    p   = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after  = Pt(4)
    for text, bold, italic, color, mono in parts:
        run = p.add_run(text)
        if mono:
            set_font(run, name="Courier New", size=9.5, bold=bold, italic=italic, color=color or C_CODE_FG)
        else:
            set_font(run, size=10.5, bold=bold, italic=italic, color=color)
    return p

def code_block(doc, lines, caption=None):
    """Render a shaded code block."""
    if caption:
        cp = doc.add_paragraph()
        cp.paragraph_format.space_before = Pt(6)
        cp.paragraph_format.space_after  = Pt(1)
        run = cp.add_run(caption)
        set_font(run, size=9, bold=True, italic=True, color=C_H2)

    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.LEFT
    cell = tbl.cell(0, 0)
    shade_cell(cell, C_CODE_BG)
    cell.width = Cm(16)

    # Remove any existing paragraph
    for existing in cell.paragraphs:
        existing._p.getparent().remove(existing._p)

    for i, line in enumerate(lines):
        cp = cell.add_paragraph()
        cp.paragraph_format.space_before = Pt(0)
        cp.paragraph_format.space_after  = Pt(0)
        cp.paragraph_format.left_indent  = Cm(0.3)
        if i == 0:
            cp.paragraph_format.space_before = Pt(4)
        if i == len(lines) - 1:
            cp.paragraph_format.space_after  = Pt(4)
        run = cp.add_run(line)
        set_font(run, name="Courier New", size=9, color=C_CODE_FG)

    doc.add_paragraph().paragraph_format.space_after = Pt(4)
    return tbl

def note_box(doc, text, label="NOTE", bg=None):
    """Render a coloured note/warning box."""
    bg = bg or C_NOTE_BG
    tbl  = doc.add_table(rows=1, cols=1)
    cell = tbl.cell(0, 0)
    shade_cell(cell, bg)
    for existing in cell.paragraphs:
        existing._p.getparent().remove(existing._p)
    cp  = cell.add_paragraph()
    cp.paragraph_format.space_before = Pt(4)
    cp.paragraph_format.space_after  = Pt(4)
    cp.paragraph_format.left_indent  = Cm(0.3)
    r1 = cp.add_run(f"▶  {label}:  ")
    set_font(r1, size=10, bold=True)
    r2 = cp.add_run(text)
    set_font(r2, size=10)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)

def bullet(doc, text, level=0):
    p   = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.space_before = Pt(1)
    p.paragraph_format.space_after  = Pt(1)
    p.paragraph_format.left_indent  = Cm(0.5 + level * 0.5)
    run = p.add_run(text)
    set_font(run, size=10.5)
    return p

def table_std(doc, headers, rows, col_widths=None):
    """Render a styled table with a blue header row and alternating rows."""
    tbl = doc.add_table(rows=1 + len(rows), cols=len(headers))
    tbl.alignment = WD_TABLE_ALIGNMENT.LEFT
    tbl.style = "Table Grid"

    # Header
    hrow = tbl.rows[0]
    for j, h in enumerate(headers):
        cell = hrow.cells[j]
        shade_cell(cell, C_TBL_HEAD)
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        p   = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        run = p.add_run(h)
        set_font(run, size=10, bold=True, color=C_TBL_HEAD_T)

    # Data rows
    for i, row in enumerate(rows):
        bg = C_TBL_ALT if i % 2 == 1 else RGBColor(0xFF, 0xFF, 0xFF)
        drow = tbl.rows[i + 1]
        for j, cell_text in enumerate(row):
            cell = drow.cells[j]
            shade_cell(cell, bg)
            p    = cell.paragraphs[0]
            mono = False
            text = cell_text
            if isinstance(cell_text, tuple):
                text, mono = cell_text
            run = p.add_run(str(text))
            if mono:
                set_font(run, name="Courier New", size=9, color=C_CODE_FG)
            else:
                set_font(run, size=10)

    # Column widths
    if col_widths:
        for j, w in enumerate(col_widths):
            for row in tbl.rows:
                row.cells[j].width = Cm(w)

    doc.add_paragraph().paragraph_format.space_after = Pt(4)
    return tbl

def page_break(doc):
    doc.add_page_break()

def hr(doc):
    p    = doc.add_paragraph()
    pPr  = p._p.get_or_add_pPr()
    pBdr = OxmlElement("w:pBdr")
    bot  = OxmlElement("w:bottom")
    bot.set(qn("w:val"),   "single")
    bot.set(qn("w:sz"),    "4")
    bot.set(qn("w:space"), "1")
    bot.set(qn("w:color"), "BFBFBF")
    pBdr.append(bot)
    pPr.append(pBdr)
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after  = Pt(4)

# =============================================================================
# COVER PAGE
# =============================================================================
cover = doc.add_paragraph()
cover.alignment = WD_ALIGN_PARAGRAPH.CENTER
cover.paragraph_format.space_before = Pt(60)
cover.paragraph_format.space_after  = Pt(6)
r = cover.add_run("SoftHSM2 CNG KSP")
set_font(r, size=28, bold=True, color=C_TITLE)

sub = doc.add_paragraph()
sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
sub.paragraph_format.space_after = Pt(4)
r2 = sub.add_run("Complete Developer Guide")
set_font(r2, size=18, bold=False, color=C_H2)

sub2 = doc.add_paragraph()
sub2.alignment = WD_ALIGN_PARAGRAPH.CENTER
sub2.paragraph_format.space_after = Pt(4)
r3 = sub2.add_run("Getting the code · Compiling · Running tests · Generating reports")
set_font(r3, size=12, italic=True, color=RGBColor(0x60, 0x60, 0x60))

doc.add_paragraph().paragraph_format.space_after = Pt(30)

meta = doc.add_paragraph()
meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
r4 = meta.add_run("Version 1.0  ·  June 2026  ·  Branch: claude/cng-softhsm2-ksp-ol45af")
set_font(r4, size=10, italic=True, color=RGBColor(0x80, 0x80, 0x80))

page_break(doc)

# =============================================================================
# TABLE OF CONTENTS (manual)
# =============================================================================
heading1(doc, "Table of Contents")

toc_entries = [
    ("1", "Prerequisites",                                     "3"),
    ("1.1", "Software requirements",                           "3"),
    ("1.2", "SoftHSM2 token initialisation",                   "3"),
    ("2", "Getting the source code",                           "4"),
    ("2.1", "Cloning the repository",                          "4"),
    ("2.2", "Repository layout",                               "4"),
    ("3", "Compiling the project",                             "5"),
    ("3.1", "Windows build (Visual Studio / CMake)",           "5"),
    ("3.2", "Linux build (unit tests only, GCC)",              "6"),
    ("3.3", "Build artefacts",                                 "6"),
    ("4", "Registering the KSP",                               "7"),
    ("5", "Running the tests",                                 "8"),
    ("5.1", "Layer 1 — Unit tests (Linux)",                    "8"),
    ("5.2", "Layer 2 — Integration tests (Windows)",           "9"),
    ("5.3", "Layer 3a — Basic PowerShell tests (Windows)",     "10"),
    ("5.4", "Layer 3b — HLK-conformant PowerShell tests",      "10"),
    ("6", "Generating reports",                                "11"),
    ("6.1", "Unit-test coverage report (lcov/genhtml)",        "11"),
    ("6.2", "Integration test console report",                 "12"),
    ("6.3", "PowerShell test report",                          "12"),
    ("7", "Environment variables reference",                   "13"),
    ("8", "Troubleshooting",                                   "14"),
]

tbl_toc = doc.add_table(rows=len(toc_entries), cols=2)
tbl_toc.alignment = WD_TABLE_ALIGNMENT.LEFT
for i, (num, title, page) in enumerate(toc_entries):
    row = tbl_toc.rows[i]
    row.cells[0].width = Cm(13.5)
    row.cells[1].width = Cm(2)
    indent = Cm(0.5) if len(num) > 1 else Cm(0)
    p0 = row.cells[0].paragraphs[0]
    p0.paragraph_format.left_indent = indent
    p0.paragraph_format.space_before = Pt(1)
    p0.paragraph_format.space_after  = Pt(1)
    r_num = p0.add_run(f"{num}  ")
    set_font(r_num, size=10.5, bold=(len(num) == 1))
    r_tit = p0.add_run(title)
    set_font(r_tit, size=10.5, bold=(len(num) == 1))
    p1 = row.cells[1].paragraphs[0]
    p1.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    p1.paragraph_format.space_before = Pt(1)
    p1.paragraph_format.space_after  = Pt(1)
    r_pg = p1.add_run(page)
    set_font(r_pg, size=10.5)

page_break(doc)

# =============================================================================
# 1. PREREQUISITES
# =============================================================================
heading1(doc, "1.  Prerequisites")

heading2(doc, "1.1  Software requirements")

body(doc, "The following software must be installed before cloning or building the project.")

table_std(doc,
    ["Component", "Minimum version", "Notes"],
    [
        ("Windows", "10 / 11  x64", "Required for KSP, integration, and PowerShell tests"),
        ("Visual Studio", "2022 (MSVC v143)", "With \"Desktop development with C++\" workload"),
        ("CMake", "3.20+", "Bundled with Visual Studio 2022 or install separately"),
        ("Windows SDK", "10.0.19041.0+", "Included in VS 2022 installer"),
        ("Git", "2.30+", "Any modern Git client"),
        ("SoftHSM2", "2.6+", "Windows installer from github.com/opendnssec/SoftHSMv2"),
        ("GCC / gcov", "11+", "Linux only — for unit tests and coverage (no Windows SDK needed)"),
        ("lcov", "2.0+", "Linux only — generates HTML coverage report from gcov data"),
        ("PowerShell", "5.1+ or 7+", "Pre-installed on Windows 10/11; needed for Layer 3 tests"),
    ],
    col_widths=[3.5, 3.5, 9.0]
)

note_box(doc,
    "The unit tests (Layer 1) run on Linux with GCC and require NO Windows SDK, "
    "SoftHSM2, or Visual Studio. They use a PKCS#11 mock and are suitable for CI pipelines.",
    label="TIP", bg=C_OK_BG)

heading2(doc, "1.2  SoftHSM2 token initialisation")

body(doc,
    "After installing SoftHSM2, create and initialise a token before running any "
    "integration or functional tests.")

code_block(doc, [
    "# Windows — in a Command Prompt or PowerShell:",
    'softhsm2-util --init-token --slot 0 --label "MyToken" ^',
    "              --so-pin 0000 --pin 1234",
    "",
    "# Verify the token is visible:",
    "softhsm2-util --show-slots",
], caption="Initialise a SoftHSM2 token")

note_box(doc,
    "The PIN '1234' is the default used by the KSP (SOFTHSM2_PIN environment variable). "
    "Change both the token PIN and the environment variable together in production.",
    label="NOTE")

page_break(doc)

# =============================================================================
# 2. GETTING THE SOURCE CODE
# =============================================================================
heading1(doc, "2.  Getting the source code")

heading2(doc, "2.1  Cloning the repository")

code_block(doc, [
    "git clone https://github.com/gaillotte/noida.git",
    "cd noida",
    "",
    "# Switch to the development branch:",
    "git checkout claude/cng-softhsm2-ksp-ol45af",
    "",
    "# Verify your working directory:",
    "git log --oneline -5",
], caption="Clone and check out the branch")

heading2(doc, "2.2  Repository layout")

body(doc,
    "The KSP lives entirely under the softhsm_ksp/ subdirectory. "
    "Key folders are described below.")

table_std(doc,
    ["Path", "Contents"],
    [
        (("softhsm_ksp/src/ksp/", True),     "CNG KSP implementation (ksp_main, provider, key, crypto, properties)"),
        (("softhsm_ksp/src/pkcs11/", True),  "PKCS#11 abstraction layer (context, session pool, utilities)"),
        (("softhsm_ksp/src/common/", True),  "Shared modules: logging, memory, config.h"),
        (("softhsm_ksp/tests/", True),       "Integration test (test_ksp_integration.c) and PKCS#11 layer test"),
        (("softhsm_ksp/tests/unit/", True),  "10 unit test suites with gcov instrumentation (Linux)"),
        (("softhsm_ksp/tests/mock/", True),  "Windows / BCrypt / PKCS#11 mock headers for Linux unit tests"),
        (("softhsm_ksp/tools/", True),       "PowerShell test scripts, KSP registration scripts"),
        (("softhsm_ksp/docs/", True),        "Architecture and reference documentation (Markdown)"),
        (("softhsm_ksp/CMakeLists.txt", True), "Top-level CMake build script (DLL + test executables)"),
        (("softhsm_ksp/softhsm_ksp.def", True), "DLL export definition file (22 CNG functions)"),
    ],
    col_widths=[5.5, 10.5]
)

page_break(doc)

# =============================================================================
# 3. COMPILING
# =============================================================================
heading1(doc, "3.  Compiling the project")

heading2(doc, "3.1  Windows build (Visual Studio / CMake)")

body(doc,
    "Open an 'x64 Native Tools Command Prompt for VS 2022' (found in the Visual Studio "
    "start menu folder). All commands below must be run from this prompt to ensure the "
    "correct MSVC compiler and Windows SDK paths are on the PATH.")

heading3(doc, "Step 1 — Navigate to the KSP directory")

code_block(doc, [
    "cd path\\to\\noida\\softhsm_ksp",
], caption="")

heading3(doc, "Step 2 — Configure with CMake")

code_block(doc, [
    "cmake -B build -G \"Visual Studio 17 2022\" -A x64",
], caption="Generate the Visual Studio solution")

heading3(doc, "Step 3 — Build (Release configuration)")

code_block(doc, [
    "cmake --build build --config Release",
    "",
    "# For a Debug build (larger binary, debug symbols):",
    "cmake --build build --config Debug",
], caption="Build the DLL and test executables")

heading3(doc, "Step 4 — Verify the build")

code_block(doc, [
    "dir build\\Release\\",
    "",
    "# Expected output includes:",
    "#   softhsm_ksp.dll           — the CNG Key Storage Provider",
    "#   softhsm_ksp.lib           — import library",
    "#   test_ksp_integration.exe  — end-to-end integration test",
    "#   test_p11_layer.exe        — PKCS#11 layer smoke test",
], caption="Check build outputs")

note_box(doc,
    "The CMake configuration enforces /W3 /WX (warnings as errors at level 3). "
    "The build must produce zero warnings to succeed.",
    label="NOTE")

heading2(doc, "3.2  Linux build (unit tests only, GCC)")

body(doc,
    "The unit tests in tests/unit/ can be compiled on Linux with GCC. "
    "They use mock headers and do not require the Windows SDK or SoftHSM2.")

code_block(doc, [
    "cd softhsm_ksp/tests/unit",
    "",
    "# Build all 10 test executables with gcov instrumentation:",
    "make",
    "",
    "# Expected binaries:",
    "#   test_p11rv_mapping    test_logging      test_mechanism_resolve",
    "#   test_export_blobs     test_ksp_provider test_ksp_key_ops",
    "#   test_ksp_crypto       test_ksp_key_props test_memory",
    "#   test_ecdsa_decode",
], caption="Build the unit tests on Linux")

heading2(doc, "3.3  Build artefacts summary")

table_std(doc,
    ["Artefact", "Platform", "Location", "Description"],
    [
        (("softhsm_ksp.dll", True),              "Windows", ("build\\Release\\", True), "CNG KSP — registers via regsvr32"),
        (("test_ksp_integration.exe", True),     "Windows", ("build\\Release\\", True), "Integration tests (21 tests)"),
        (("test_p11_layer.exe", True),           "Windows", ("build\\Release\\", True), "PKCS#11 layer smoke tests"),
        (("test_p11rv_mapping", True),           "Linux",   ("tests/unit/", True),      "Unit test: error code mapping"),
        (("test_logging", True),                 "Linux",   ("tests/unit/", True),      "Unit test: logging module"),
        (("test_mechanism_resolve", True),       "Linux",   ("tests/unit/", True),      "Unit test: mechanism resolution"),
        (("test_export_blobs", True),            "Linux",   ("tests/unit/", True),      "Unit test: public key export"),
        (("test_ksp_provider", True),            "Linux",   ("tests/unit/", True),      "Unit test: KSP provider lifecycle"),
        (("test_ksp_key_ops", True),             "Linux",   ("tests/unit/", True),      "Unit test: key CRUD operations"),
        (("test_ksp_crypto", True),              "Linux",   ("tests/unit/", True),      "Unit test: signing and decryption"),
        (("test_ksp_key_props", True),           "Linux",   ("tests/unit/", True),      "Unit test: key property access"),
        (("test_memory", True),                  "Linux",   ("tests/unit/", True),      "Unit test: memory allocation"),
        (("test_ecdsa_decode", True),            "Linux",   ("tests/unit/", True),      "Unit test: DER ECDSA decode"),
    ],
    col_widths=[4.5, 2.5, 3.5, 5.5]
)

page_break(doc)

# =============================================================================
# 4. REGISTERING THE KSP
# =============================================================================
heading1(doc, "4.  Registering the KSP (Windows only)")

body(doc,
    "The KSP must be registered in the Windows registry before Layer 3 (PowerShell) "
    "tests can run. Layer 2 integration tests call KSP functions directly and do "
    "not require registration.")

heading2(doc, "Method A — PowerShell script (recommended)")

code_block(doc, [
    "# Run from an elevated (Administrator) PowerShell:",
    '.\\tools\\register_ksp.ps1 -DllPath "C:\\path\\to\\build\\Release\\softhsm_ksp.dll"',
], caption="Register using the provided script")

heading2(doc, "Method B — Manual registry edit")

body(doc,
    "Edit tools\\register_ksp.reg, replace <ABSOLUTE_PATH> with the full path to "
    "softhsm_ksp.dll (use double backslashes), then double-click the .reg file.")

code_block(doc, [
    "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Providers\\SoftHSM KSP]",
    '"Image"="C:\\\\build\\\\Release\\\\softhsm_ksp.dll"',
], caption="Registry key structure (register_ksp.reg)")

heading2(doc, "Verification")

code_block(doc, [
    "# Should list 'SoftHSM KSP' among the providers:",
    'certutil -csplist | Select-String "SoftHSM"',
], caption="Verify registration")

heading2(doc, "Unregistration")

code_block(doc, [
    'Remove-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Providers\\SoftHSM KSP" `',
    "    -Recurse -Force",
], caption="Remove the KSP from the registry")

note_box(doc,
    "After changing the DLL path (e.g. moving the build folder), re-run the "
    "registration script or update the Image registry value to point to the new location.",
    label="NOTE")

page_break(doc)

# =============================================================================
# 5. RUNNING THE TESTS
# =============================================================================
heading1(doc, "5.  Running the tests")

body(doc,
    "Tests are organised in three layers. Run them in order: "
    "Layer 1 works on Linux without any Windows dependencies; "
    "Layers 2 and 3 require Windows, SoftHSM2, and a live token.")

heading2(doc, "5.1  Layer 1 — Unit tests (Linux, GCC)")

body(doc, "Run each test suite individually or chain them with &&:")

code_block(doc, [
    "cd softhsm_ksp/tests/unit",
    "",
    "# Run all 10 suites in sequence:",
    "./test_p11rv_mapping      && \\",
    "./test_logging            && \\",
    "./test_mechanism_resolve  && \\",
    "./test_export_blobs       && \\",
    "./test_ksp_provider       && \\",
    "./test_ksp_key_ops        && \\",
    "./test_ksp_crypto         && \\",
    "./test_ksp_key_props      && \\",
    "./test_memory             && \\",
    "./test_ecdsa_decode",
    "",
    "echo \"All unit tests passed\"",
], caption="Run all unit test suites")

body(doc, "Expected output format for each suite:")

code_block(doc, [
    "[PASS] P11RvToSecStatus CKR_OK -> ERROR_SUCCESS",
    "[PASS] P11RvToSecStatus CKR_GENERAL_ERROR -> NTE_FAIL",
    "...",
    "Results: PASS=22  FAIL=0",
], caption="Example unit test output")

table_std(doc,
    ["Suite", "Assertions", "Key scenarios tested"],
    [
        ("test_p11rv_mapping",    "22", "All CK_RV error codes → Windows SECURITY_STATUS"),
        ("test_logging",          "9",  "Log_Initialize, Log_Debug, Log_Error, KSP_DEBUG toggle"),
        ("test_mechanism_resolve","18", "P11_ResolveMechanism() for all alg/flag combinations"),
        ("test_export_blobs",     "23", "RSA + EC public key blob generation, label lookup"),
        ("test_ksp_provider",     "27", "KSP_OpenProvider, GetProviderProperty, FreeBuffer"),
        ("test_ksp_key_ops",      "65", "CreatePersistedKey, OpenKey, FinalizeKey, EnumKeys, DeleteKey"),
        ("test_ksp_crypto",       "60", "SignHash (RSA/ECDSA), Decrypt (PKCS1/OAEP), ExportKey"),
        ("test_ksp_key_props",    "25", "GetKeyProperty, SetKeyProperty — all property types"),
        ("test_memory",           "13", "KSP_Alloc, KSP_AllocZero, KSP_Free, KSP_WStrDup"),
        ("test_ecdsa_decode",     "19", "P11_DecodeDerEcdsaSignature DER parsing, P-256/P-384"),
        ("TOTAL",                 "281",""),
    ],
    col_widths=[5.0, 2.5, 8.5]
)

heading2(doc, "5.2  Layer 2 — Integration tests (Windows)")

body(doc,
    "These tests call KSP functions directly (no registry required) against a live "
    "SoftHSM2 token. Set the required environment variables before running.")

code_block(doc, [
    "# Set environment variables (PowerShell):",
    '$env:SOFTHSM2_LIB = "C:\\Program Files\\SoftHSM2\\lib\\softhsm2-x64.dll"',
    '$env:SOFTHSM2_PIN = "1234"',
    '$env:KSP_DEBUG    = "1"   # optional: enables OutputDebugString logging',
    "",
    "# Run the integration test executable:",
    ".\\build\\Release\\test_ksp_integration.exe",
], caption="Run integration tests (Windows)")

body(doc, "The test suite runs 21 tests in two groups:")

table_std(doc,
    ["Test #", "Name", "Category"],
    [
        ("1",  "OpenProvider",                        "Original"),
        ("2",  "GetProviderProperty (Name, Version, ImplType)", "Original"),
        ("3",  "CreatePersistedKey RSA 2048",         "Original"),
        ("4",  "FinalizeKey RSA",                     "Original"),
        ("5",  "GetKeyProperty (ALGORITHM, LENGTH)",  "Original"),
        ("6",  "SignHash RSA PKCS1",                  "Original"),
        ("7",  "ExportKey BCRYPT_RSAPUBLIC_BLOB",     "Original"),
        ("8",  "ExportKey private → NTE_NOT_SUPPORTED","Original"),
        ("9",  "OpenKey (reopen by label)",           "Original"),
        ("10", "CreatePersistedKey ECDSA P-256",      "Original"),
        ("11", "SignHash ECDSA",                      "Original"),
        ("12", "EnumKeys",                            "Original"),
        ("13", "DeleteKey",                           "Original"),
        ("14", "SetKeyProperty NCRYPT_LENGTH",        "Original"),
        ("15", "RSA PSS sign + BCrypt PSS verify",    "HLK"),
        ("16", "RSA PKCS1 BCrypt verify + property coverage", "HLK"),
        ("17", "ECDSA P-256 BCrypt verify",           "HLK"),
        ("18", "ECDSA P-384 (96-byte sig) + BCrypt verify", "HLK"),
        ("19", "RSA 3072 deferred generation + BCrypt verify", "HLK"),
        ("20", "RSA OAEP encrypt/decrypt round-trip", "HLK"),
        ("21", "Error conditions (invalid handles, missing key)", "HLK"),
    ],
    col_widths=[1.8, 8.7, 2.5]
)

page_break(doc)

heading2(doc, "5.3  Layer 3a — Basic PowerShell tests")

body(doc,
    "Requires the KSP registered (see Section 4). "
    "Run from an elevated (Administrator) PowerShell prompt.")

code_block(doc, [
    "# From the softhsm_ksp directory:",
    ".\\tools\\test_ksp.ps1",
], caption="Run the basic functional test script")

body(doc, "This script runs 9 end-to-end scenarios through the official Windows NCrypt API:")

table_std(doc,
    ["Test", "Scenario"],
    [
        ("1", "certutil -csplist finds SoftHSM KSP"),
        ("2", "NCryptCreatePersistedKey RSA 2048 + NCryptFinalizeKey"),
        ("3", "NCryptSignHash RSA PKCS1 (NCRYPT_PAD_PKCS1_FLAG)"),
        ("4", "RSA signature non-empty (implicit verification)"),
        ("5", "NCryptCreatePersistedKey ECDSA_P256 + NCryptFinalizeKey"),
        ("6", "NCryptSignHash ECDSA (no padding)"),
        ("7", "ECDSA signature non-empty"),
        ("8", "NCryptEnumKeys — finds both test keys"),
        ("9", "NCryptDeleteKey — removes RSA and ECDSA test keys"),
    ],
    col_widths=[1.5, 14.5]
)

heading2(doc, "5.4  Layer 3b — HLK-conformant PowerShell tests")

body(doc,
    "Mirrors Microsoft's TPM 2.0 Platform Crypto Provider KSP Test "
    "(HLK ID: 7c938be0-ff4a-44f9-916c-b578f027f0ca). "
    "Run from an elevated PowerShell prompt.")

code_block(doc, [
    ".\\tools\\test_cng_hlk.ps1",
], caption="Run the HLK-conformant test suite")

body(doc, "The script executes 61 tests across 9 sections (S1–S9):")

table_std(doc,
    ["Section", "Description", "Tests"],
    [
        ("S1", "Provider enumeration (certutil) + property queries (Name, Version, ImplType)", "4"),
        ("S2", "RSA 2048 AT_SIGNATURE: PKCS1 + PSS signing with BCrypt verify, 6 property checks, private export rejection", "14"),
        ("S3", "RSA 2048 AT_KEYEXCHANGE: BCrypt OAEP encrypt → NCryptDecrypt round-trip", "6"),
        ("S4", "RSA 3072 deferred creation (SetProperty + FinalizeKey) + BCrypt PKCS1 verify", "6"),
        ("S5", "ECDSA P-256: create, sign, BCrypt verify, ALGORITHM/LENGTH/KEY_USAGE/ALG_GROUP queries", "9"),
        ("S6", "ECDSA P-384: sign SHA-384 (48-byte hash), 96-byte r‖s sig, BCrypt verify", "6"),
        ("S7", "NCryptEnumKeys (all 5 test keys found) + NCryptOpenKey round-trip", "7"),
        ("S8", "Error conditions: invalid handle, private blob, non-existent key, NULL handle", "4"),
        ("S9", "Cleanup: NCryptDeleteKey for all 5 test keys", "5"),
        ("Total", "", "61"),
    ],
    col_widths=[1.5, 12.0, 1.5]
)

page_break(doc)

# =============================================================================
# 6. GENERATING REPORTS
# =============================================================================
heading1(doc, "6.  Generating reports")

heading2(doc, "6.1  Unit-test coverage report (lcov / genhtml)")

body(doc,
    "After building and running the unit tests on Linux, gcov data files "
    "(.gcda) are created in tests/unit/. Use lcov to collect and render them "
    "as an HTML report.")

heading3(doc, "Step 1 — Run all unit tests (regenerates .gcda files)")

code_block(doc, [
    "cd softhsm_ksp/tests/unit",
    "./test_p11rv_mapping && ./test_logging && ./test_mechanism_resolve && \\",
    "./test_export_blobs && ./test_ksp_provider && ./test_ksp_key_ops && \\",
    "./test_ksp_crypto && ./test_ksp_key_props && ./test_memory && ./test_ecdsa_decode",
], caption="")

heading3(doc, "Step 2 — Collect coverage data with lcov")

code_block(doc, [
    "# Collect all .gcda data:",
    "lcov --capture --directory . --output-file coverage.info",
    "",
    "# Strip system headers and test harness files:",
    "lcov --remove coverage.info '/usr/*' '*/tests/unit/*' \\",
    "     --output-file coverage_filtered.info",
], caption="Collect and filter coverage data")

heading3(doc, "Step 3 — Generate HTML report")

code_block(doc, [
    "genhtml coverage_filtered.info \\",
    "    --output-directory coverage_html \\",
    "    --title 'SoftHSM KSP — Coverage Report' \\",
    "    --legend --show-details",
    "",
    "# Open in a browser:",
    "xdg-open coverage_html/index.html   # Linux",
    "start coverage_html/index.html      # Windows (WSL)",
], caption="Render the HTML report")

body(doc, "The report shows coverage per directory and file:")

table_std(doc,
    ["Module", "Lines", "Hit", "Line %", "Functions", "Hit", "Func %"],
    [
        ("common/",  "38",  "33",  "86.8 %", "7",  "7",  "100 %"),
        ("ksp/",     "716", "652", "91.1 %", "27", "27", "100 %"),
        ("pkcs11/",  "193", "177", "91.7 %", "9",  "9",  "100 %"),
        ("Total",    "947", "862", "91.0 %", "43", "43", "100 %"),
    ],
    col_widths=[3.0, 1.8, 1.8, 2.0, 2.5, 1.5, 2.0]
)

note_box(doc,
    "The coverage numbers reflect only unit tests (Layer 1). "
    "The integration and HLK tests exercise additional runtime paths "
    "(RSA 3072/4096 generation, OAEP decrypt, PSS verification, ECDSA P-384) "
    "that are not instrumented by gcov.",
    label="NOTE")

heading2(doc, "6.2  Integration test console report")

body(doc,
    "The integration test executable prints a pass/fail summary directly to the "
    "console. Capture it to a file for archiving:")

code_block(doc, [
    "# Windows — save output to a file:",
    ".\\build\\Release\\test_ksp_integration.exe > test_results.txt 2>&1",
    "type test_results.txt",
    "",
    "# Example tail of output:",
    "══════════════════════════════════════",
    "Results: PASS=91  FAIL=0",
    "══════════════════════════════════════",
], caption="Capture integration test output")

heading2(doc, "6.3  PowerShell test report")

body(doc,
    "Both PowerShell scripts print colour-coded PASS/FAIL lines and a summary. "
    "Use Tee-Object to save the output while also displaying it:")

code_block(doc, [
    "# Basic tests:",
    ".\\tools\\test_ksp.ps1 | Tee-Object -FilePath test_ksp_results.txt",
    "",
    "# HLK tests:",
    ".\\tools\\test_cng_hlk.ps1 | Tee-Object -FilePath test_hlk_results.txt",
    "",
    "# Example tail of HLK output:",
    "[PASS] S2.11 BCryptVerifySignature RSA PKCS1 (SHA-256)",
    "[PASS] S2.12 NCryptSignHash RSA PSS (SHA-256, cbSalt=32)",
    "[PASS] S2.13 BCryptVerifySignature RSA PSS (SHA-256)",
    "...",
    "══════════════════════════════════════════════════════════════════════",
    "HLK Test Results — PASS=61  FAIL=0  SKIP=0",
    "══════════════════════════════════════════════════════════════════════",
], caption="Save PowerShell test results to a file")

body(doc,
    "To produce an XML or JSON report for CI integration, redirect the output "
    "and post-process with ConvertTo-Json or a custom formatter:")

code_block(doc, [
    '$results = .\\tools\\test_cng_hlk.ps1 2>&1',
    '$summary = $results | Select-String "^\\[(PASS|FAIL|SKIP)\\]"',
    "$passCount = ($summary | Select-String 'PASS').Count",
    "$failCount = ($summary | Select-String 'FAIL').Count",
    "",
    "[PSCustomObject]@{",
    "    Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
    "    Pass      = $passCount",
    "    Fail      = $failCount",
    "    Status    = if ($failCount -eq 0) { 'SUCCESS' } else { 'FAILURE' }",
    "} | ConvertTo-Json | Set-Content hlk_report.json",
], caption="Generate a JSON summary report")

page_break(doc)

# =============================================================================
# 7. ENVIRONMENT VARIABLES
# =============================================================================
heading1(doc, "7.  Environment variables reference")

table_std(doc,
    ["Variable", "Default value", "Scope", "Description"],
    [
        (("SOFTHSM2_LIB", True),
         "C:\\Program Files\\SoftHSM2\\lib\\softhsm2-x64.dll",
         "KSP runtime",
         "Full path to the SoftHSM2 DLL. Override if installed in a non-default location."),
        (("SOFTHSM2_PIN", True),
         "1234",
         "KSP runtime",
         "Token user PIN. Read once per session slot; erased from memory immediately after C_Login()."),
        (("KSP_DEBUG", True),
         "0",
         "KSP runtime",
         "Set to 1 to enable OutputDebugString logging. View with DebugView (Sysinternals)."),
    ],
    col_widths=[3.5, 4.5, 2.5, 5.5]
)

note_box(doc,
    "Never store the PIN in an environment variable in production. "
    "Use a secrets manager (Windows DPAPI, Azure Key Vault, CyberArk, etc.) "
    "and inject the value into the process environment at startup.",
    label="SECURITY", bg=C_WARN_BG)

body(doc, "Set environment variables in PowerShell for the current session:")

code_block(doc, [
    '$env:SOFTHSM2_LIB = "C:\\Program Files\\SoftHSM2\\lib\\softhsm2-x64.dll"',
    '$env:SOFTHSM2_PIN = "1234"',
    '$env:KSP_DEBUG    = "1"',
], caption="Set environment variables (PowerShell session)")

body(doc, "Or persist them system-wide (Administrator required):")

code_block(doc, [
    "[System.Environment]::SetEnvironmentVariable(",
    '    "SOFTHSM2_LIB",',
    '    "C:\\Program Files\\SoftHSM2\\lib\\softhsm2-x64.dll",',
    '    "Machine"',
    ")",
], caption="Persist environment variable system-wide")

page_break(doc)

# =============================================================================
# 8. TROUBLESHOOTING
# =============================================================================
heading1(doc, "8.  Troubleshooting")

table_std(doc,
    ["Symptom", "Likely cause", "Resolution"],
    [
        ("NTE_PROVIDER_DLL_FAIL (0x80090011) on NCryptOpenStorageProvider",
         "SOFTHSM2_LIB points to a missing or wrong DLL",
         "Set SOFTHSM2_LIB to the correct path; verify with: Test-Path $env:SOFTHSM2_LIB"),

        ("NTE_NO_KEY: no slot with token present",
         "SoftHSM2 token has not been initialised",
         "Run: softhsm2-util --init-token --slot 0 --label MyToken --so-pin 0000 --pin 1234"),

        ("C_Login fails / CKR_PIN_INCORRECT",
         "SOFTHSM2_PIN does not match the token PIN",
         "Set SOFTHSM2_PIN to the PIN used during softhsm2-util --init-token"),

        ("test_ksp_integration.exe exits with FAIL=N",
         "Leftover test keys from a previous aborted run",
         "Delete stale keys: softhsm2-util --delete-token --label MyToken, then re-init"),

        ("regsvr32 error: DllRegisterServer entry point not found",
         "KSP DLLs don't use regsvr32; they register via the Windows registry directly",
         "Use tools\\register_ksp.ps1 instead of regsvr32"),

        ("certutil -csplist does not show SoftHSM KSP",
         "Registration not performed or registry key is incorrect",
         "Re-run tools\\register_ksp.ps1 as Administrator; check the Image value in HKLM\\...\\SoftHSM KSP"),

        ("test_cng_hlk.ps1 fails: 'Cannot find type [Hlk]'",
         "Add-Type compilation failed (missing bcrypt.dll or ncrypt.dll in PATH)",
         "Run from a machine with the Windows CNG DLLs present (they ship with Windows 10+)"),

        ("BCryptVerifySignature returns STATUS_INVALID_SIGNATURE in test 15/16/17",
         "KSP signature format mismatch (ECDSA DER not converted to r||s)",
         "Check P11_DecodeDerEcdsaSignature in p11_utils.c is being called; enable KSP_DEBUG=1"),

        ("Unit tests: linker error — undefined reference to ncrypt / bcrypt symbols",
         "Tests include windows.h shims but some symbol is missing from the mock headers",
         "Add the missing symbol to tests/mock/ncrypt.h or tests/mock/bcrypt.h"),

        ("make: no rule to make target (Linux unit tests)",
         "Running make outside tests/unit/ directory",
         "cd softhsm_ksp/tests/unit && make"),
    ],
    col_widths=[5.0, 4.5, 6.5]
)

hr(doc)

body(doc, "For additional details, refer to:")

bullet(doc, "docs/01-architecture.md — internal design and data structures")
bullet(doc, "docs/02-initialisation.md — SoftHSM2 loading and session pool lifecycle")
bullet(doc, "docs/07-security-threading.md — thread-safety, handle validation, logging")
bullet(doc, "docs/09-tests.md — complete test reference with assertion tables")

# ── Save ─────────────────────────────────────────────────────────────────────
output_path = "/home/user/Noida/softhsm_ksp/SoftHSM2_KSP_Complete_Developer_Guide.docx"
doc.save(output_path)
print(f"Document saved: {output_path}")
