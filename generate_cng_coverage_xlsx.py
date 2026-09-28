"""Generate the CNG feature coverage workbook from feature-matrix.csv.

Same contract as generate_feature_matrix.py: the CSV is the source of
truth, this only renders it. Every count in the workbook is a COUNTIF or
COUNTIFS over the matrix sheet, so the summary cannot drift from the table.

LibreOffice cannot load any xlsx in the build environment, so the values
are also injected as cached results after being evaluated against the
workbook's own data - see the note in the repository history.
"""
import csv, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'softhsm_ksp', 'docs'))
from coverage_blockers import BLOCKER
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

SRC = '/home/user/Noida/softhsm_ksp/docs/feature-matrix.csv'
OUT = '/home/user/Noida/softhsm_ksp/SoftHSM2_KSP_CNG_Feature_Coverage.xlsx'
ASOF = '2026-09-28'

rows = list(csv.DictReader(open(SRC)))
SUPPORTED = {'Covered': 'Yes', 'Partial': 'Partial', 'Not covered': 'No'}

FONT = 'Arial'
NAVY   = '1F3864'
HDRF   = PatternFill('solid', fgColor=NAVY)
GREEN  = PatternFill('solid', fgColor='C6EFCE')
AMBER  = PatternFill('solid', fgColor='FFEB9C')
RED    = PatternFill('solid', fgColor='FFC7CE')
BAND   = PatternFill('solid', fgColor='F2F2F2')
BOX    = PatternFill('solid', fgColor='FFF2CC')
GREENT, AMBERT, REDT = '006100', '9C5700', '9C0006'
THIN = Side(style='thin', color='BFBFBF')
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)

def hdr(ws, titles, row=1):
    for i, t in enumerate(titles, 1):
        c = ws.cell(row=row, column=i, value=t)
        c.font = Font(name=FONT, bold=True, color='FFFFFF', size=10)
        c.fill = HDRF
        c.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)
        c.border = BORDER
    ws.row_dimensions[row].height = 30

def widths(ws, spec):
    for col, w in spec.items():
        ws.column_dimensions[col].width = w

wb = Workbook()

# ══ Sheet 2 first (Summary references it) ═══════════════════════════════════
ws = wb.active
ws.title = 'CNG Feature Matrix'
COLS = ['ID', 'Category', 'CNG feature', 'What it covers', 'Supported',
        'Matrix status', 'Evidence', 'Why still open', 'Effort',
        'What other CNG KSPs do', 'Detail, reasoning and remedy']
hdr(ws, COLS)

for n, r in enumerate(rows, start=2):
    sup = SUPPORTED[r['status']]
    vals = [r['id'], r['category'], r['feature'], r['detail'], sup, r['status'],
            r['evidence'], BLOCKER.get(r['id'], ''), r['effort'] or '',
            r['market'], r['gap_solution']]
    for i, v in enumerate(vals, 1):
        c = ws.cell(row=n, column=i, value=v)
        c.font = Font(name=FONT, size=9)
        c.alignment = Alignment(vertical='top', wrap_text=(i in (4, 10, 11)))
        c.border = BORDER
        if n % 2 == 0 and i != 5:
            c.fill = BAND
    s = ws.cell(row=n, column=5)
    s.font = Font(name=FONT, size=9, bold=True,
                  color={'Yes': GREENT, 'Partial': AMBERT, 'No': REDT}[sup])
    s.fill = {'Yes': GREEN, 'Partial': AMBER, 'No': RED}[sup]
    s.alignment = Alignment(horizontal='center', vertical='top')

LAST = len(rows) + 1
widths(ws, {'A': 11, 'B': 22, 'C': 34, 'D': 40, 'E': 11, 'F': 13, 'G': 9,
            'H': 34, 'I': 7, 'J': 34, 'K': 95})
ws.freeze_panes = 'C2'
ws.auto_filter.ref = f'A1:K{LAST}'

MX = "'CNG Feature Matrix'"

# ══ Summary ═════════════════════════════════════════════════════════════════
sm = wb.create_sheet('Summary', 0)
widths(sm, {'A': 46, 'B': 14, 'C': 14, 'D': 78})

def put(ws, cell, value, *, bold=False, size=10, color='000000', fill=None,
        wrap=False, fmt=None, italic=False):
    c = ws[cell]; c.value = value
    c.font = Font(name=FONT, bold=bold, size=size, color=color, italic=italic)
    if fill: c.fill = fill
    c.alignment = Alignment(vertical='top', wrap_text=wrap)
    if fmt: c.number_format = fmt
    return c

put(sm, 'A1', 'CNG feature coverage — SoftHSM2 KSP over PKCS#11', bold=True, size=15, color=NAVY)
put(sm, 'A2', 'A Microsoft CNG Key Storage Provider implemented on top of a PKCS#11 v2.40+ layer, '
              'backed by SoftHSM2 and verified against a second, independent PKCS#11 token.',
    size=9, italic=True, wrap=True)
sm.merge_cells('A2:D2'); sm.row_dimensions[2].height = 28
put(sm, 'A3', f'As of {ASOF}   ·   source of truth: softhsm_ksp/docs/feature-matrix.csv', size=9, italic=True)

put(sm, 'A5', 'Headline', bold=True, size=12, color=NAVY)
hdr(sm, ['Measure', 'Count', 'Share', 'What it means'], row=6)

HEAD = [
    ('Capabilities assessed', f'=COUNTA({MX}!A2:A{LAST})', None,
     'One row per capability observed across shipping CNG KSPs (Microsoft, AWS CloudHSM, Utimaco, Thales, Entrust, Securosys).'),
    ('Yes — fully supported', f'=COUNTIF({MX}!E2:E{LAST},"Yes")', '=B8/$B$7',
     'Implemented and exercised by the test suites. No known gap against the surveyed market.'),
    ('Partial — works with a caveat', f'=COUNTIF({MX}!E2:E{LAST},"Partial")', '=B9/$B$7',
     'Implemented and usable, but with a limit that is stated rather than hidden — a non-standard identifier, a deliberate refusal, or one direction of a two-way feature.'),
    ('No — not supported', f'=COUNTIF({MX}!E2:E{LAST},"No")', '=B10/$B$7',
     'Not implemented. Every one carries a recorded reason; none is an oversight.'),
]
for i, (label, cnt, share, note) in enumerate(HEAD):
    r = 7 + i
    put(sm, f'A{r}', label, size=10, bold=(i == 0))
    c = put(sm, f'B{r}', cnt, size=10, bold=True); c.alignment = Alignment(horizontal='center')
    if share:
        c = put(sm, f'C{r}', share, size=10, fmt='0.0%'); c.alignment = Alignment(horizontal='center')
    put(sm, f'D{r}', note, size=9, wrap=True)
    sm.row_dimensions[r].height = 30
    for col in 'ABCD': sm[f'{col}{r}'].border = BORDER
sm['B7'].fill = BAND
sm['B8'].fill, sm['B9'].fill, sm['B10'].fill = GREEN, AMBER, RED

put(sm, 'A12', 'Why the open items are open', bold=True, size=12, color=NAVY)
put(sm, 'A13', 'Every Partial and No row, classified by what actually stands in the way. '
               'This is the question the counts above cannot answer.', size=9, italic=True, wrap=True)
sm.merge_cells('A13:D13')
hdr(sm, ['Reason', 'Count', 'Share of open', 'Reading'], row=14)

OPEN_TOTAL = f'(COUNTIF({MX}!E2:E{LAST},"Partial")+COUNTIF({MX}!E2:E{LAST},"No"))'
REASONS = [
    ('Deliberate position',
     'The provider chose this and the reason is recorded — HSM posture (keys are non-extractable), or a scope decision such as DES and DSA.'),
    ('Blocked: no PKCS#11 mechanism',
     'PKCS#11 offers no mechanism, so a portable provider cannot reach it however much code is written — key attestation, use counters, change notification.'),
    ('Blocked: CNG has no identifier or slot',
     'CNG itself has no algorithm identifier (EdDSA, HMAC, counter mode) or no function-table slot (ML-KEM). Blocked on Microsoft, not on this project.'),
    ('Blocked: hardware / commercial',
     'Needs real hardware, a purchased code-signing certificate, or a formal validation programme. Not an engineering task.'),
    ('Blocked: needs ncrypt_provider.h / Windows',
     'Needs the CPDK header and a Windows machine. THE HIGHEST-VALUE ITEM HERE — see the caveat below.'),
]
for i, (reason, reading) in enumerate(REASONS):
    r = 15 + i
    put(sm, f'A{r}', reason, size=10)
    c = put(sm, f'B{r}', f'=COUNTIF({MX}!H2:H{LAST},A{r})', size=10, bold=True)
    c.alignment = Alignment(horizontal='center')
    c = put(sm, f'C{r}', f'=IFERROR(B{r}/{OPEN_TOTAL},0)', size=10, fmt='0.0%')
    c.alignment = Alignment(horizontal='center')
    put(sm, f'D{r}', reading, size=9, wrap=True)
    sm.row_dimensions[r].height = 32
    for col in 'ABCD': sm[f'{col}{r}'].border = BORDER

r = 20
put(sm, f'A{r}', 'Total open', bold=True, size=10)
c = put(sm, f'B{r}', f'={OPEN_TOTAL}', bold=True, size=10); c.alignment = Alignment(horizontal='center')
c = put(sm, f'C{r}', f'=IFERROR(B20/$B$7,0)', bold=True, size=10, fmt='0.0%'); c.alignment = Alignment(horizontal='center')
put(sm, f'D{r}', 'Sums the five reasons above; it must equal Partial + No.', size=9, italic=True, wrap=True)
for col in 'ABCD': sm[f'{col}{r}'].border = BORDER; sm[f'{col}{r}'].fill = BAND

put(sm, 'A22', 'Read this before quoting any number above', bold=True, size=12, color=NAVY)
CAVEATS = [
 ('The DLL is not built in CI.',
  'MSVC compiles nine of the ten source files clean at /W3 /WX, but ksp_main.c needs ncrypt_provider.h, which does not exist on a hosted Windows runner. '
  'A green CI run does not mean the provider builds. Every other figure in this workbook is measured on Linux against a PKCS#11 token, not on Windows through ncrypt.dll.'),
 ('"Yes" means implemented and tested, not shipped and certified.',
  'Coverage here is functional. It says nothing about FIPS validation, hardware protection or Authenticode signing, all of which are separate rows and all of which are No.'),
 ('The backend is interchangeable, and that is load-bearing.',
  'The provider advertises the intersection of what it maps and what the token reports via C_GetMechanismList. Features marked Yes may go dark on a token that lacks the mechanism — by design, not by failure.'),
 ('A mock agreeing with itself proved several of these wrong.',
  'Running the same sources against a second, independent PKCS#11 token (Kryoptic) found defects in ECDSA, X25519, Ed448, HMAC and AES key wrap that thousands of mock assertions had passed. '
  'Rows carrying evidence grade A for cryptographic operations are the ones proven that way.'),
]
rr = 23
for title, body in CAVEATS:
    put(sm, f'A{rr}', title, bold=True, size=9, fill=BOX)
    c = put(sm, f'B{rr}', body, size=9, wrap=True, fill=BOX)
    sm.merge_cells(f'B{rr}:D{rr}')
    sm.row_dimensions[rr].height = 46
    for col in 'ABCD': sm[f'{col}{rr}'].border = BORDER
    rr += 1

# ══ By category ═════════════════════════════════════════════════════════════
bc = wb.create_sheet('By Category', 2)
widths(bc, {'A': 30, 'B': 10, 'C': 10, 'D': 10, 'E': 10, 'F': 14})
put(bc, 'A1', 'Coverage by capability area', bold=True, size=13, color=NAVY)
hdr(bc, ['Category', 'Yes', 'Partial', 'No', 'Total', '% fully covered'], row=3)
cats = sorted({r['category'] for r in rows})
for i, cat in enumerate(cats):
    r = 4 + i
    put(bc, f'A{r}', cat, size=10)
    for j, sup in enumerate(['Yes', 'Partial', 'No']):
        c = put(bc, f'{get_column_letter(2+j)}{r}',
                f'=COUNTIFS({MX}!B2:B{LAST},$A{r},{MX}!E2:E{LAST},"{sup}")', size=10)
        c.alignment = Alignment(horizontal='center')
    c = put(bc, f'E{r}', f'=SUM(B{r}:D{r})', size=10, bold=True); c.alignment = Alignment(horizontal='center')
    c = put(bc, f'F{r}', f'=IFERROR(B{r}/E{r},0)', size=10, fmt='0.0%'); c.alignment = Alignment(horizontal='center')
    for col in 'ABCDEF': bc[f'{col}{r}'].border = BORDER
tot = 4 + len(cats)
put(bc, f'A{tot}', 'All categories', bold=True, size=10)
for col in 'BCDE':
    c = put(bc, f'{col}{tot}', f'=SUM({col}4:{col}{tot-1})', bold=True, size=10)
    c.alignment = Alignment(horizontal='center'); c.fill = BAND
c = put(bc, f'F{tot}', f'=IFERROR(B{tot}/E{tot},0)', bold=True, size=10, fmt='0.0%')
c.alignment = Alignment(horizontal='center'); c.fill = BAND
for col in 'ABCDEF': bc[f'{col}{tot}'].border = BORDER; bc[f'{col}{tot}'].fill = BAND
bc.freeze_panes = 'A4'

# ══ Gaps ════════════════════════════════════════════════════════════════════
gp = wb.create_sheet('Open Items', 3)
GC = ['ID', 'Category', 'CNG feature', 'Supported', 'Why still open', 'Effort',
      'What would actually close it']
hdr(gp, GC)
order = {'Blocked: needs ncrypt_provider.h / Windows': 0,
         'Blocked: CNG has no identifier or slot': 1,
         'Blocked: no PKCS#11 mechanism': 2,
         'Blocked: hardware / commercial': 3,
         'Deliberate position': 4}
gaps = sorted([r for r in rows if r['status'] != 'Covered'],
              key=lambda r: (order[BLOCKER[r['id']]], r['id']))
for n, r in enumerate(gaps, start=2):
    sup = SUPPORTED[r['status']]
    vals = [r['id'], r['category'], r['feature'], sup, BLOCKER[r['id']],
            r['effort'] or '', r['gap_solution']]
    for i, v in enumerate(vals, 1):
        c = gp.cell(row=n, column=i, value=v)
        c.font = Font(name=FONT, size=9)
        c.alignment = Alignment(vertical='top', wrap_text=(i == 7))
        c.border = BORDER
        if n % 2 == 0 and i != 4: c.fill = BAND
    s = gp.cell(row=n, column=4)
    s.font = Font(name=FONT, size=9, bold=True, color={'Partial': AMBERT, 'No': REDT}[sup])
    s.fill = {'Partial': AMBER, 'No': RED}[sup]
    s.alignment = Alignment(horizontal='center', vertical='top')
widths(gp, {'A': 11, 'B': 22, 'C': 34, 'D': 11, 'E': 34, 'F': 7, 'G': 110})
gp.freeze_panes = 'C2'
gp.auto_filter.ref = f'A1:G{len(gaps)+1}'

# ══ Legend ══════════════════════════════════════════════════════════════════
lg = wb.create_sheet('Legend')
widths(lg, {'A': 22, 'B': 100})
put(lg, 'A1', 'How to read this workbook', bold=True, size=13, color=NAVY)
LEG = [
 ('Supported', None),
 ('Yes', 'Implemented and exercised by the test suites. No known gap against the capabilities observed in shipping CNG KSPs.'),
 ('Partial', 'Implemented and usable with a stated limit: a provider-specific identifier no stock application will ask for, a deliberate refusal, or one working direction of a two-way feature.'),
 ('No', 'Not implemented. Each carries a recorded reason — see "Why still open".'),
 ('', None),
 ('Evidence grade', None),
 ('A', 'Established inside this repository — read from the source, a header, or proven by a test. The strongest grade and the only one used for this provider\'s own behaviour.'),
 ('B', 'Vendor documentation or a documentation mirror. Used for what other products do.'),
 ('C', 'Inference from indirect sources. Used sparingly and never for a claim about this provider.'),
 ('', None),
 ('Effort', None),
 ('S / M / L', 'Rough size of the remedy IF it were unblocked. It is not a schedule, and a small effort behind a hard blocker is still not startable — TABLE-01 is S and needs a Windows machine.'),
 ('(blank)', 'No remedy is planned: the row is a deliberate position or an external blocker.'),
 ('', None),
 ('Test layers behind "Yes"', None),
 ('Layer 1', '22 unit suites, 1623 assertions, Linux/GCC against a controllable PKCS#11 mock. Pins down the provider\'s logic; cannot validate assumptions about real tokens.'),
 ('Layer 1b', 'The same provider sources against Kryoptic, an independent PKCS#11 token in Rust. 230 assertions, run twice against one token so anything left behind is caught. Plus 33 concurrency assertions across 32 threads, and ThreadSanitizer.'),
 ('Layer 2 / 3', 'Windows integration and HLK-conformant PowerShell suites. Written and syntax-checked; they need a Windows machine with SoftHSM2 to execute.'),
 ('', None),
 ('Scope', None),
 ('What this measures', 'The CNG key-storage surface, as observed across Microsoft Software/Platform Crypto, AWS CloudHSM, Utimaco, Thales, Entrust and Securosys, assessed against this provider.'),
 ('What it does not', 'Performance, deployment, packaging, and anything about the SoftHSM2 token itself beyond what the provider depends on.'),
]
r = 3
for k, v in LEG:
    if v is None:
        if k: put(lg, f'A{r}', k, bold=True, size=11, color=NAVY)
    else:
        put(lg, f'A{r}', k, bold=True, size=9)
        c = put(lg, f'B{r}', v, size=9, wrap=True)
        lg.row_dimensions[r].height = 34
    r += 1

wb.save(OUT)
print('wrote', OUT)
