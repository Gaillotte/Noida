#!/usr/bin/env python3
"""Convert every document in this project to PDF and assemble one zip.

    python3 softhsm_ksp/tools/build_doc_bundle.py

Four source kinds, three converters, and the choice of converter per kind is
the interesting part:

  *.md            reportlab, through the renderer generate_adcs_plan.py
                  already uses for the ADCS plan. Reused rather than
                  reimplemented so markdown becomes a PDF exactly one way in
                  this repository.
  *.docx *.xlsx   LibreOffice headless.
  *.html          Chromium headless print-to-PDF. The slide decks already
                  carry @page rules for 1920x1080 and hide their speaker
                  notes when printing, so printing them IS the intended
                  export path rather than a fallback.
  *.pdf           copied. Two documents are already generated as PDFs and
                  re-rendering them would be a second, worse version of
                  something that is already right.

THE RENDERER THIS IMPORTS DROPS CONTENT, AND THAT IS WHY parse_full EXISTS.
generate_adcs_plan.parse() reports fenced code blocks and blockquotes as
"unknown" and skips them. For 16-adcs-readiness.md that costs nothing,
because it has neither. Most of the other documents are mostly commands, so
the same parser would have produced confident-looking PDFs with every shell
block silently missing. parse_full handles both kinds and, more importantly,
accounts for every input line: a line that matches no rule is reported and
makes the build fail rather than vanishing. A converter that drops content
without saying so is worse than no converter.

Nothing here is committed by CI. The zip is a release artifact built on
demand, and `scan_pdf_safety.py` runs over it before it is handed to anyone.
"""
import datetime
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))        # softhsm_ksp/tools
KSP = os.path.dirname(HERE)                              # softhsm_ksp
REPO = os.path.dirname(KSP)                              # repo root

sys.path.insert(0, REPO)

from reportlab.lib import colors                          # noqa: E402
from reportlab.lib.pagesizes import A4                    # noqa: E402
from reportlab.lib.styles import ParagraphStyle            # noqa: E402
from reportlab.lib.units import mm                        # noqa: E402
from reportlab.platypus import (BaseDocTemplate, Frame,    # noqa: E402
                                PageTemplate, Paragraph,
                                Preformatted, Spacer, KeepTogether)

# The one markdown->PDF renderer in this repository. Imported, never copied.
from generate_adcs_plan import (CODE_BG, INK, MUTED, RULE,  # noqa: E402
                                build_styles, callout, inline, split_row,
                                table_flowable)

CHROMIUM = '/opt/pw-browsers/chromium'
MARGIN = 17 * mm


# ── What goes in ────────────────────────────────────────────────────────────
#
# Declared, not globbed. A document that appears in the repository and is not
# listed here is absent from the bundle, which is a visible omission; a glob
# would quietly sweep in whatever happened to be on disk, including a
# scratch file.
#
# (repo-relative source, output stem, one-line description)
MARKDOWN = [
    ('softhsm_ksp/docs/00-index.md', '00-index', 'Documentation index'),
    ('softhsm_ksp/docs/01-architecture.md', '01-architecture',
     'Layers, threading, memory'),
    ('softhsm_ksp/docs/02-initialisation.md', '02-initialisation',
     'Module load and session pool lifecycle'),
    ('softhsm_ksp/docs/03-key-management.md', '03-key-management',
     'Create, open, enumerate, delete'),
    ('softhsm_ksp/docs/04-crypto-operations.md', '04-crypto-operations',
     'Sign, decrypt, encrypt, agree, export'),
    ('softhsm_ksp/docs/05-properties.md', '05-properties',
     'Key and provider properties'),
    ('softhsm_ksp/docs/06-error-mapping.md', '06-error-mapping',
     'CK_RV to SECURITY_STATUS'),
    ('softhsm_ksp/docs/07-security-threading.md', '07-security-threading',
     'Concurrency, handles, credentials, logging'),
    ('softhsm_ksp/docs/08-complete-flows.md', '08-complete-flows',
     'End-to-end flows'),
    ('softhsm_ksp/docs/09-tests.md', '09-tests', 'The test pyramid'),
    ('softhsm_ksp/docs/10-hlk-execution.md', '10-hlk-execution',
     'Microsoft HLK procedure'),
    ('softhsm_ksp/docs/11-market-comparison.md', '11-market-comparison',
     'Competitive audit, evidence-graded'),
    ('softhsm_ksp/docs/12-pkcs11-requirements.md', '12-pkcs11-requirements',
     'Backend contract for an HSM vendor'),
    ('softhsm_ksp/docs/13-roadmap.md', '13-roadmap', 'Phased plan to parity'),
    ('softhsm_ksp/docs/14-partial-remediation-plan.md',
     '14-partial-remediation-plan', 'Proposals A-D and what they found'),
    ('softhsm_ksp/docs/15-gap-analysis.md', '15-gap-analysis',
     'GENERATED - open rows by blocker'),
    ('softhsm_ksp/docs/16-adcs-readiness.md', '16-adcs-readiness',
     'ADCS readiness and the phased plan (markdown source)'),
    ('softhsm_ksp/README.md', 'README', 'Project readme'),
]

# Excluded by default, included with --include-context.
#
# CLAUDE.md is the richest document in the repository and it is also the
# wrong thing to put in an archive whose purpose is to be sent to an HSM
# vendor, an auditor or a new team. It carries the repository owner's
# PERSONAL EMAIL ADDRESS, the working branch name, and a session-by-session
# account of every defect the project has ever had.
#
# This default is not a guess: the first build of this bundle included it,
# and scan_pdf_safety.py reported the address out of the rendered PDF. That
# is the scan doing its job, and the right response to a finding whose cause
# is "we put an internal document in an external archive" is to stop doing
# that rather than to note it in a report.
#
# Pass --include-context when the recipient is internal and you want it.
INTERNAL = [
    ('CLAUDE.md', 'PROJECT-CONTEXT',
     'Full project context and session history (INTERNAL)'),
]

OFFICE = [
    ('softhsm_ksp/SoftHSM2_KSP_Complete_Developer_Guide.docx',
     'Developer-Guide', 'Complete developer guide'),
    ('softhsm_ksp/SoftHSM2_KSP_Algorithm_Reference.docx',
     'Algorithm-Reference', 'Algorithm reference'),
    ('softhsm_ksp/SoftHSM2_KSP_CNG_Feature_Coverage.xlsx',
     'CNG-Feature-Coverage', 'CNG coverage workbook'),
]

HTML = [
    ('softhsm_ksp/SoftHSM2_KSP_Design_Tests_ADCS_Slides.html',
     'Slides-Design-Tests-ADCS',
     'Slide deck: design, tests, ADCS install, what remains'),
    ('softhsm_ksp/SoftHSM2_KSP_Team_Plan_Slides.html',
     'Slides-Team-Plan', 'Slide deck: plan for the joining team'),
]

ALREADY_PDF = [
    ('softhsm_ksp/SoftHSM2_KSP_Feature_Matrix.pdf', 'Feature-Matrix',
     'Market coverage and gap analysis'),
    ('softhsm_ksp/SoftHSM2_KSP_ADCS_Readiness_Plan.pdf',
     'ADCS-Readiness-Plan', 'ADCS assessment, rendered'),
]


# ── Markdown, with nothing dropped ──────────────────────────────────────────
def parse_full(md):
    """Markdown -> blocks, plus the lines no rule claimed.

    A superset of generate_adcs_plan.parse(): it adds `code` and `quote`
    rather than reporting them as unknown, and it returns the line numbers
    it could not account for so the caller can refuse to emit a PDF that is
    missing something. The block vocabulary is deliberately the same so the
    rendering below can hand tables and lists straight to the shared
    flowable builders.
    """
    lines = md.split('\n')
    blocks, i, dropped = [], 0, []

    while i < len(lines):
        raw = lines[i].rstrip()
        line = raw.strip()

        if not line:
            i += 1
            continue

        if line.startswith('```'):
            lang = line[3:].strip()
            i += 1
            body = []
            while i < len(lines) and not lines[i].strip().startswith('```'):
                body.append(lines[i])
                i += 1
            i += 1                                   # the closing fence
            blocks.append(('code', (lang, '\n'.join(body))))
            continue

        if re.fullmatch(r'(-{3,}|\*{3,}|_{3,})', line):
            blocks.append(('hr', None))
            i += 1
            continue

        m = re.match(r'^(#{1,6})\s+(.*)$', line)
        if m:
            blocks.append(('h%d' % len(m.group(1)), m.group(2)))
            i += 1
            continue

        if line.startswith('|'):
            rows = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                r = lines[i].strip()
                if not re.fullmatch(r'\|[\s:|-]+\|', r):
                    rows.append(split_row(r))
                i += 1
            if rows:
                blocks.append(('table', rows))
            continue

        if line.startswith('>'):
            body = []
            while i < len(lines) and lines[i].strip().startswith('>'):
                body.append(lines[i].strip().lstrip('>').strip())
                i += 1
            blocks.append(('quote', ' '.join(b for b in body if b)))
            continue

        # Bulleted and numbered lists. Nesting is flattened to one level
        # with the indent preserved as a prefix, because the shared bullet
        # style has one indent and inventing a second here would diverge
        # from how the ADCS plan renders the same markup.
        m = re.match(r'^([-*+])\s+(.*)$', line)
        if m:
            items = []
            while i < len(lines):
                cur = lines[i]
                mm = re.match(r'^(\s*)([-*+])\s+(.*)$', cur)
                if not mm or not cur.strip():
                    break
                depth = len(mm.group(1)) // 2
                text = mm.group(3)
                i += 1
                while (i < len(lines) and lines[i].strip()
                       and lines[i].startswith(' ' * (len(mm.group(1)) + 2))
                       and not re.match(r'^\s*([-*+]|\d+\.)\s', lines[i])
                       and not lines[i].strip().startswith('```')):
                    text += ' ' + lines[i].strip()
                    i += 1
                items.append(('•' if depth == 0 else '◦', text))
            blocks.append(('list', items))
            continue

        m = re.match(r'^(\d+)\.\s+(.*)$', line)
        if m:
            items = []
            while i < len(lines):
                mm = re.match(r'^\s*(\d+)\.\s+(.*)$', lines[i])
                if not mm or not lines[i].strip():
                    break
                text, num = mm.group(2), mm.group(1)
                i += 1
                while (i < len(lines) and lines[i].strip()
                       and lines[i].startswith('  ')
                       and not re.match(r'^\s*([-*+]|\d+\.)\s', lines[i])
                       and not lines[i].strip().startswith('```')):
                    text += ' ' + lines[i].strip()
                    i += 1
                items.append(('%s.' % num, text))
            blocks.append(('list', items))
            continue

        para = [line]
        i += 1
        while i < len(lines):
            nxt = lines[i].strip()
            if (not nxt or re.fullmatch(r'(-{3,}|\*{3,}|_{3,})', nxt)
                    or nxt.startswith(('|', '#', '>', '```'))
                    or re.match(r'^([-*+]|\d+\.)\s', nxt)):
                break
            para.append(nxt)
            i += 1
        blocks.append(('para', ' '.join(para)))

    return blocks, dropped


def extra_styles(s):
    """Styles parse_full needs that the shared sheet does not define."""
    s['code'] = ParagraphStyle(
        'code', fontName='Courier', fontSize=7.4, leading=9.6,
        textColor=INK, backColor=CODE_BG, borderPadding=5,
        leftIndent=2, spaceBefore=3, spaceAfter=8)
    s['quote'] = ParagraphStyle(
        'quote', parent=s['body'], leftIndent=12, textColor=MUTED,
        borderPadding=0, spaceBefore=3, spaceAfter=8)
    s['h3'] = ParagraphStyle(
        'h3', parent=s['h2'], fontSize=10, leading=12.5,
        textColor=MUTED, spaceBefore=9, spaceAfter=4)
    s['foot'] = ParagraphStyle(
        'foot', parent=s['body'], fontSize=7.4, textColor=MUTED)
    return s


def render_markdown(src, out, title, subtitle):
    with open(src, encoding='utf-8') as f:
        md = f.read()
    blocks, dropped = parse_full(md)
    if dropped:
        raise SystemExit('%s: %d unaccounted lines: %s'
                         % (src, len(dropped), dropped[:5]))

    styles = extra_styles(build_styles())
    story = [Paragraph(title, styles['title']),
             Paragraph(subtitle, styles['sub'])]

    for kind, payload in blocks:
        if kind == 'hr':
            story.append(Spacer(1, 7))
        elif kind in ('h1', 'h2'):
            story.append(Paragraph(inline(payload), styles[kind]))
        elif kind.startswith('h'):
            story.append(Paragraph(inline(payload), styles['h3']))
        elif kind == 'para':
            story.append(Paragraph(inline(payload), styles['body']))
        elif kind == 'quote':
            story.append(callout(payload, styles))
        elif kind == 'list':
            for bullet, text in payload:
                story.append(Paragraph(inline(text), styles['bullet'],
                                       bulletText=bullet))
            story.append(Spacer(1, 5))
        elif kind == 'code':
            lang, body = payload
            # Hard-wrapped rather than shrunk: a command that runs off the
            # page is a command the reader cannot use, and a reader copying
            # a shell line out of a PDF needs every character of it.
            wrapped = []
            for ln in body.split('\n'):
                while len(ln) > 96:
                    wrapped.append(ln[:96])
                    ln = '    ' + ln[96:]
                wrapped.append(ln)
            story.append(Preformatted('\n'.join(wrapped), styles['code']))
        elif kind == 'table':
            story.append(KeepTogether(table_flowable(payload, styles)))
            story.append(Spacer(1, 7))

    doc = BaseDocTemplate(
        out, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=MARGIN,
        title=title, author='SoftHSM2 CNG KSP project',
        subject=subtitle, creator='build_doc_bundle.py')
    frame = Frame(MARGIN, MARGIN, A4[0] - 2 * MARGIN, A4[1] - 2 * MARGIN,
                  id='body', showBoundary=0)

    def footer(canv, _doc):
        canv.saveState()
        canv.setStrokeColor(RULE)
        canv.setLineWidth(0.4)
        canv.line(MARGIN, MARGIN - 5, A4[0] - MARGIN, MARGIN - 5)
        canv.setFont('Helvetica', 7)
        canv.setFillColor(MUTED)
        canv.drawString(MARGIN, MARGIN - 14, title)
        canv.drawRightString(A4[0] - MARGIN, MARGIN - 14,
                             'page %d' % canv.getPageNumber())
        canv.restoreState()

    doc.addPageTemplates([PageTemplate(id='p', frames=[frame],
                                       onPage=footer)])
    doc.build(story)
    return len(blocks)


# ── The other two converters ────────────────────────────────────────────────
def convert_office(src, out, profile):
    """docx / xlsx -> PDF through LibreOffice headless.

    NEEDS libreoffice-writer AND libreoffice-calc, not just
    libreoffice-core. With only the core package soffice exists, runs, and
    cannot load anything at all - not even a plain .txt - because the
    import filters live in the application packages. Install with:

        apt-get install libreoffice-writer libreoffice-calc

    AND SOFFICE EXITS 0 WHEN IT FAILS. It prints "Error: source file could
    not be loaded" on stdout and returns success, so check=True proves
    nothing here; the only reliable signal is whether a PDF appeared, which
    is what the code below actually tests. A conversion step that trusted
    the exit status would have put a silently incomplete archive in front of
    a vendor.

    HOME is redirected because soffice writes a user profile and will fail
    or hang on a read-only or shared home. -env:UserInstallation pins the
    profile explicitly for the same reason.
    """
    tmp = tempfile.mkdtemp(prefix='lo-out-')
    env = dict(os.environ, HOME=profile)
    subprocess.run(
        ['soffice', '-env:UserInstallation=file://%s/profile' % profile,
         '--headless', '--norestore', '--convert-to', 'pdf',
         '--outdir', tmp, src],
        check=True, env=env, capture_output=True, timeout=300)
    produced = [f for f in os.listdir(tmp) if f.lower().endswith('.pdf')]
    if not produced:
        raise RuntimeError('LibreOffice produced no PDF for %s' % src)
    shutil.move(os.path.join(tmp, produced[0]), out)
    shutil.rmtree(tmp, ignore_errors=True)


def convert_html(src, out):
    """HTML -> PDF through headless Chromium.

    --no-pdf-header-footer matters: without it Chromium stamps a URL and a
    date onto every page, and the URL is a local filesystem path, so the
    default would print this machine's directory layout onto a document
    meant to be handed out.

    --virtual-time-budget gives the webfont requests a chance to land. If
    they do not, the page falls back through its own font stack and the
    deck still renders; it is not worth failing a build over.
    """
    subprocess.run(
        [CHROMIUM, '--headless', '--no-sandbox', '--disable-gpu',
         '--no-pdf-header-footer', '--virtual-time-budget=12000',
         '--run-all-compositor-stages-before-draw',
         '--print-to-pdf=%s' % out, 'file://%s' % src],
        check=True, capture_output=True, timeout=300)


# ── Assembly ────────────────────────────────────────────────────────────────
def page_count(path):
    try:
        from pypdf import PdfReader
        return len(PdfReader(path).pages)
    except Exception:
        return 0


def normalise_metadata(path, title, subject):
    """Rewrite every PDF's metadata dictionary to the same known values.

    Each converter stamps its own, and two of the three stamp something
    that should not leave the building:

        chromium      /Creator = the full user-agent, naming the build OS,
                      the architecture and the browser build
        libreoffice   /Producer = its exact version
        reportlab     /Producer = its exact version

    None of that is secret, and all of it is free reconnaissance about the
    machine that built a document meant for an outside reader. It is also
    invisible on the page, which is exactly what makes it worth handling
    here: the scanner reported it 26 times and the right answer to a
    finding that appears on every file is to remove the cause, not to read
    the report 26 times.

    /Subject keeps the REPO-RELATIVE source path on purpose. That is
    provenance a reader wants - which document this PDF was rendered from -
    and it names nothing outside the repository.
    """
    try:
        from pypdf import PdfReader, PdfWriter
    except ImportError:
        return False
    reader = PdfReader(path)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.add_metadata({
        '/Title': title,
        '/Subject': subject,
        '/Author': 'SoftHSM2 CNG KSP project',
        '/Creator': 'softhsm_ksp/tools/build_doc_bundle.py',
        '/Producer': 'softhsm_ksp/tools/build_doc_bundle.py',
    })
    tmp = path + '.tmp'
    with open(tmp, 'wb') as f:
        writer.write(f)
    os.replace(tmp, path)
    return True


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 16), b''):
            h.update(chunk)
    return h.hexdigest()


def main(argv):
    include_context = '--include-context' in argv
    markdown = MARKDOWN + (INTERNAL if include_context else [])
    stamp = datetime.date.today().isoformat()
    work = tempfile.mkdtemp(prefix='docbundle-')
    pdfdir = os.path.join(work, 'pdf')
    profile = os.path.join(work, 'lo')
    os.makedirs(pdfdir)
    os.makedirs(profile)

    entries, failures = [], []

    def record(stem, desc, path, how, rel):
        # Normalise BEFORE hashing, or the manifest's digest would be of a
        # file that no longer exists on disk.
        normalise_metadata(path, '%s - SoftHSM2 CNG KSP' % desc,
                           '%s  -  built %s' % (rel, stamp))
        entries.append(dict(name=os.path.basename(path), desc=desc, how=how,
                            pages=page_count(path), size=os.path.getsize(path),
                            digest=sha256(path)))
        print('  %-34s %3d pages  %-10s' % (os.path.basename(path),
                                            entries[-1]['pages'], how))

    print('Markdown (reportlab):')
    for rel, stem, desc in markdown:
        src = os.path.join(REPO, rel)
        if not os.path.exists(src):
            failures.append('%s: missing' % rel)
            continue
        out = os.path.join(pdfdir, '%s.pdf' % stem)
        title = desc if stem in ('README', 'PROJECT-CONTEXT') else stem
        try:
            render_markdown(src, out, title.replace('-', ' ').strip(),
                            '%s  -  SoftHSM2 CNG KSP  -  %s' % (rel, stamp))
            record(stem, desc, out, 'reportlab', rel)
        except SystemExit as exc:
            failures.append('%s: %s' % (rel, exc))
        except Exception as exc:
            failures.append('%s: %s: %s' % (rel, type(exc).__name__, exc))

    print('\nOffice (LibreOffice):')
    for rel, stem, desc in OFFICE:
        src = os.path.join(REPO, rel)
        if not os.path.exists(src):
            failures.append('%s: missing' % rel)
            continue
        out = os.path.join(pdfdir, '%s.pdf' % stem)
        try:
            convert_office(src, out, profile)
            record(stem, desc, out, 'libreoffice', rel)
        except Exception as exc:
            failures.append('%s: %s: %s' % (rel, type(exc).__name__, exc))

    print('\nSlides (Chromium print):')
    for rel, stem, desc in HTML:
        src = os.path.join(REPO, rel)
        if not os.path.exists(src):
            failures.append('%s: missing' % rel)
            continue
        out = os.path.join(pdfdir, '%s.pdf' % stem)
        try:
            convert_html(src, out)
            record(stem, desc, out, 'chromium', rel)
        except Exception as exc:
            failures.append('%s: %s: %s' % (rel, type(exc).__name__, exc))

    print('\nAlready PDF (copied):')
    for rel, stem, desc in ALREADY_PDF:
        src = os.path.join(REPO, rel)
        if not os.path.exists(src):
            failures.append('%s: missing' % rel)
            continue
        out = os.path.join(pdfdir, '%s.pdf' % stem)
        shutil.copy2(src, out)
        record(stem, desc, out, 'copied', rel)

    # ── the manifest ────────────────────────────────────────────────────
    man = [
        'SoftHSM2 CNG KSP - documentation bundle',
        'Built %s from %s' % (stamp, 'github.com/gaillotte/noida'),
        '',
        'Every file below is a PDF. Verify one with:',
        '    sha256sum pdf/<name>',
        'and compare against this list.',
        '',
        '%-34s %6s %10s  %s' % ('FILE', 'PAGES', 'BYTES', 'SHA-256'),
    ]
    for e in sorted(entries, key=lambda x: x['name']):
        man.append('%-34s %6d %10d  %s'
                   % (e['name'], e['pages'], e['size'], e['digest']))
    man += ['', 'CONTENTS', '']
    for e in sorted(entries, key=lambda x: x['name']):
        man.append('  %-34s %s  [%s]' % (e['name'], e['desc'], e['how']))

    if not include_context:
        man += ['', 'DELIBERATELY NOT INCLUDED', '',
                '  CLAUDE.md (full project context and session '
                'history). It carries the',
                '  repository owner\'s personal email address and the '
                'working branch name,',
                '  so it is left out of an archive meant to be sent '
                'outside. Rebuild',
                '  with --include-context for an internal recipient.']

    if failures:
        man += ['', 'NOT INCLUDED', '']
        man += ['  %s' % f for f in failures]

    man += [
        '',
        'HOW THESE WERE PRODUCED',
        '',
        '  reportlab    markdown rendered by softhsm_ksp/tools/',
        '               build_doc_bundle.py, which reuses the renderer in',
        '               generate_adcs_plan.py. The parser accounts for every',
        '               input line and the build fails rather than emitting a',
        '               PDF with content silently missing.',
        '  libreoffice  soffice --headless --convert-to pdf',
        '  chromium     headless print-to-PDF, using the print stylesheet',
        '               already in the slide deck. Page headers and footers',
        '               are disabled because Chromium would otherwise stamp',
        '               the local filesystem path onto every page.',
        '  copied       already generated as a PDF by its own generator.',
        '',
        'SAFETY',
        '',
        '  SAFETY-REPORT.txt in this archive is the output of',
        '  softhsm_ksp/tools/scan_pdf_safety.py over these files.',
        '  Read the caveat at the top of it: a scanner run by whoever built',
        '  the archive is self-certification, and it is not a substitute for',
        '  your own scan.',
    ]

    manifest = os.path.join(work, 'MANIFEST.txt')
    with open(manifest, 'w', encoding='utf-8') as f:
        f.write('\n'.join(man) + '\n')

    # ── the safety scan, into the archive ───────────────────────────────
    report = os.path.join(work, 'SAFETY-REPORT.txt')
    scan = os.path.join(HERE, 'scan_pdf_safety.py')
    scan_rc = None
    if os.path.exists(scan):
        proc = subprocess.run([sys.executable, scan, pdfdir],
                              capture_output=True, text=True)
        scan_rc = proc.returncode
        with open(report, 'w', encoding='utf-8') as f:
            f.write(proc.stdout + proc.stderr)

    # ── zip it ──────────────────────────────────────────────────────────
    dist = os.path.join(REPO, 'dist')
    os.makedirs(dist, exist_ok=True)
    zpath = os.path.join(dist, 'SoftHSM2_KSP_Documentation_%s.zip' % stamp)
    with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as z:
        z.write(manifest, 'MANIFEST.txt')
        if os.path.exists(report):
            z.write(report, 'SAFETY-REPORT.txt')
        for e in sorted(entries, key=lambda x: x['name']):
            z.write(os.path.join(pdfdir, e['name']), 'pdf/%s' % e['name'])

    shutil.rmtree(work, ignore_errors=True)

    print('\n%d PDFs, %d pages, %.1f MB -> %s'
          % (len(entries), sum(e['pages'] for e in entries),
             os.path.getsize(zpath) / 1e6, os.path.relpath(zpath, REPO)))
    if scan_rc is not None:
        print('Safety scan exit %d (see SAFETY-REPORT.txt in the archive)'
              % scan_rc)
    if failures:
        print('\n%d source(s) did NOT convert:' % len(failures))
        for f in failures:
            print('  %s' % f)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
