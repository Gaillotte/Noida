"""Render docs/16-adcs-readiness.md as a PDF to read away from a terminal.

Derived, not re-typed. The markdown is the source of truth and this only
renders it, for the same reason every other generator in this repository
works that way: a plan maintained in two places becomes two plans, and this
project has already paid for a coverage figure that stayed stale for two
sessions and a document that contradicted the code for six.

The PDF therefore carries a fingerprint of the markdown plus this script,
and tests/check_generated_artifacts.py recomputes it — edit the plan without
regenerating and CI says so.

It parses the small markdown subset the plan actually uses, and nothing
more: ATX headings, paragraphs hard-wrapped across lines, pipe tables with a
header row, horizontal rules, bullet and numbered lists, and inline bold,
italic and code. Anything outside that subset is reported rather than
silently dropped, because a plan with a section missing from the PDF is
worse than a build error.

Portrait A4, unlike the landscape feature matrix: this one is prose to read
rather than a wide table to scan.
"""
import os
import re
import sys
from datetime import date

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether,
                                PageTemplate, Paragraph, Spacer, Table,
                                TableStyle)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'softhsm_ksp', 'docs'))
from matrix_fingerprint import stamp_for   # noqa: E402

SRC = os.path.join(HERE, 'softhsm_ksp', 'docs', '16-adcs-readiness.md')
OUT = os.path.join(HERE, 'softhsm_ksp', 'SoftHSM2_KSP_ADCS_Readiness_Plan.pdf')
DOC_TITLE = 'Running this provider under ADCS'

# Same palette as the feature matrix, so the two read as one family.
INK       = colors.HexColor('#1A1D1C')
MUTED     = colors.HexColor('#5F6664')
ACCENT    = colors.HexColor('#0B5D5A')
ACCENT_BG = colors.HexColor('#E4EFEE')
RULE      = colors.HexColor('#C9CFCD')
ROW_ALT   = colors.HexColor('#F4F6F5')
WARN      = colors.HexColor('#8A5A14')
WARN_BG   = colors.HexColor('#F7EEDD')
CODE_BG   = colors.HexColor('#EEF2F1')


def build_styles():
    ss = getSampleStyleSheet()
    s = {}
    s['title'] = ParagraphStyle(
        'title', parent=ss['Title'], fontName='Helvetica-Bold', fontSize=22,
        leading=26, textColor=INK, alignment=TA_LEFT, spaceAfter=4)
    s['sub'] = ParagraphStyle(
        'sub', parent=ss['Normal'], fontName='Helvetica', fontSize=9.5,
        leading=13, textColor=MUTED, spaceAfter=14)
    s['h1'] = ParagraphStyle(
        'h1', parent=ss['Heading1'], fontName='Helvetica-Bold', fontSize=15,
        leading=18, textColor=ACCENT, spaceBefore=16, spaceAfter=7)
    s['h2'] = ParagraphStyle(
        'h2', parent=ss['Heading2'], fontName='Helvetica-Bold', fontSize=11.5,
        leading=14, textColor=INK, spaceBefore=12, spaceAfter=5)
    s['body'] = ParagraphStyle(
        'body', parent=ss['Normal'], fontName='Helvetica', fontSize=9.3,
        leading=13.4, textColor=INK, spaceAfter=7)
    s['bullet'] = ParagraphStyle(
        'bullet', parent=s['body'], leftIndent=13, bulletIndent=3,
        spaceAfter=3.5)
    s['cell'] = ParagraphStyle(
        'cell', parent=ss['Normal'], fontName='Helvetica', fontSize=8.1,
        leading=10.6, textColor=INK)
    s['cellhdr'] = ParagraphStyle(
        'cellhdr', parent=s['cell'], fontName='Helvetica-Bold',
        textColor=colors.white)
    return s


# ── Inline markup ───────────────────────────────────────────────────────────
def soften(text):
    """Returns text unchanged. Kept as the place the reasoning lives.

    This used to insert a zero-width space after each underscore of a long
    identifier, so reportlab would break NCRYPT_SECURITY_DESCR_PROPERTY at
    an underscore rather than at an arbitrary character. The sibling
    feature-matrix PDF still does that and renders cleanly.

    Here it rendered as visible black .notdef boxes through the middle of
    every identifier. Blamed on Courier first — Helvetica softens cleanly in
    the matrix PDF — but switching the face to Helvetica did not fix it, so
    the difference is something else in this document's run styling and the
    hypothesis was wrong.

    Not worth more investigation: reportlab's own long-word break is
    perfectly readable (the matrix PDF breaks after "DESCR_"), the hint
    lands in the extracted text and corrupts copy-paste, and a document to
    study must not have boxes in it. The function stays so that the next
    person does not reintroduce the trick.
    """
    return text


def inline(md, soft=False, code_bg=True):
    """Markdown inline run -> reportlab mini-HTML.

    `soft` adds the zero-width wrap hints, and is for TABLE CELLS ONLY.
    Those are narrow enough that reportlab would otherwise break
    NCRYPT_SECURITY_DESCR_PROPERTY at an arbitrary character. Prose at this
    measure is wide enough not to need it, and the hint is not free: it is
    invisible on the page but it lands in the extracted text, so an
    identifier copied out of the PDF would carry hidden characters. This is
    a document to study and copy identifiers from, so the hint goes only
    where the layout genuinely needs it.

    Order matters: code spans are extracted FIRST and put back last, so
    `**` inside a code span is never read as emphasis — the plan contains
    identifiers with underscores and asterisks are rare but the rule costs
    nothing and removes a whole class of surprise.
    """
    spans = []

    def stash(m):
        spans.append(m.group(1))
        return '\x00%d\x00' % (len(spans) - 1)

    md = re.sub(r'`([^`]+)`', stash, md)

    md = (md.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'))
    md = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', md)
    md = re.sub(r'(?<!\*)\*([^*]+)\*(?!\*)', r'<i>\1</i>', md)

    def restore(m):
        code = spans[int(m.group(1))]
        code = (code.replace('&', '&amp;').replace('<', '&lt;')
                    .replace('>', '&gt;'))
        body = soften(code) if soft else code
        # Helvetica, NOT Courier, and the reason is worth recording.
        #
        # Courier has no zero-width-space glyph, so a softened identifier
        # inside a Courier run renders as a row of .notdef boxes — visible
        # black rectangles in the middle of every NCRYPT_ name. The sibling
        # feature-matrix PDF softens in Helvetica and renders cleanly, which
        # is the controlled comparison that identified this. Monospace for
        # identifiers is a nice-to-have; boxes through the middle of the
        # document are not a trade worth making, and bold plus a tint keeps
        # code distinct anyway.
        if code_bg:
            return ('<font face="Helvetica-Bold" backColor="#EEF2F1">%s</font>'
                    % body)
        # A header cell is white on teal: the tint would make it unreadable.
        return '<b>%s</b>' % body

    md = re.sub(r'\x00(\d+)\x00', restore, md)
    return soften(md) if soft else md


# ── Block parsing ───────────────────────────────────────────────────────────
def split_row(line):
    """Split a markdown table row, respecting code spans.

    A naive split on '|' broke the one row whose cell contains
    `SILENT|PAD_PKCS1` — a literal pipe inside backticks. That silently gave
    the row a fourth cell and widened the entire table to four columns, one
    of them empty on every other row. Found by looking at the rendered page
    rather than at the text, which is the only way that class of defect
    shows itself.
    """
    cells, buf, in_code = [], [], False
    for ch in line.strip().strip('|'):
        if ch == '`':
            in_code = not in_code
            buf.append(ch)
        elif ch == '|' and not in_code:
            cells.append(''.join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    cells.append(''.join(buf).strip())
    return cells


def parse(md):
    """Markdown -> a list of ('kind', payload) blocks."""
    lines = md.split('\n')
    blocks, i, unknown = [], 0, []

    while i < len(lines):
        raw = lines[i].rstrip()
        line = raw.strip()

        if not line:
            i += 1
            continue

        if line == '---':
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
                # the |---|---| separator carries no content
                if not re.fullmatch(r'\|[\s:|-]+\|', r):
                    rows.append(split_row(r))
                i += 1
            if rows:
                blocks.append(('table', rows))
            continue

        m = re.match(r'^([-*])\s+(.*)$', line)
        if m:
            items = []
            while i < len(lines):
                mm = re.match(r'^([-*])\s+(.*)$', lines[i].strip())
                if not mm:
                    break
                text = mm.group(2)
                i += 1
                # a wrapped continuation line is indented
                while (i < len(lines) and lines[i].startswith('  ')
                       and lines[i].strip()
                       and not re.match(r'^\s*([-*]|\d+\.)\s', lines[i])):
                    text += ' ' + lines[i].strip()
                    i += 1
                items.append(('•', text))
            blocks.append(('list', items))
            continue

        m = re.match(r'^(\d+)\.\s+(.*)$', line)
        if m:
            items = []
            while i < len(lines):
                mm = re.match(r'^(\d+)\.\s+(.*)$', lines[i].strip())
                if not mm:
                    break
                text, num = mm.group(2), mm.group(1)
                i += 1
                while (i < len(lines) and lines[i].startswith('  ')
                       and lines[i].strip()
                       and not re.match(r'^\s*([-*]|\d+\.)\s', lines[i])):
                    text += ' ' + lines[i].strip()
                    i += 1
                items.append(('%s.' % num, text))
            blocks.append(('list', items))
            continue

        if line.startswith('>'):
            # not used by this plan today; reported rather than dropped
            unknown.append('blockquote at line %d' % (i + 1))
            i += 1
            continue

        if line.startswith('```'):
            unknown.append('fenced code block at line %d' % (i + 1))
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('```'):
                i += 1
            i += 1
            continue

        # a paragraph: join hard-wrapped lines until a blank or a new block
        para = [line]
        i += 1
        while i < len(lines):
            nxt = lines[i].strip()
            if (not nxt or nxt == '---' or nxt.startswith(('|', '#', '>', '`'))
                    or re.match(r'^([-*]|\d+\.)\s', nxt)):
                break
            para.append(nxt)
            i += 1
        blocks.append(('para', ' '.join(para)))

    return blocks, unknown


# ── Rendering ───────────────────────────────────────────────────────────────
USABLE = A4[0] - 2 * 17 * mm        # frame width


def table_flowable(rows, styles):
    head, body = rows[0], rows[1:]
    ncol = max(len(r) for r in rows)
    head = head + [''] * (ncol - len(head))

    data = [[Paragraph(inline(c, soft=True, code_bg=False),
                       styles['cellhdr']) for c in head]]
    for r in body:
        r = r + [''] * (ncol - len(r))
        data.append([Paragraph(inline(c, soft=True), styles['cell'])
                     for c in r])

    # Width by the longest cell in each column, then scaled to the frame.
    # A fixed split would squeeze the two-column tables and starve the
    # six-column one; this keeps both readable without hand-tuning each.
    weights = []
    for c in range(ncol):
        longest = max(len(r[c]) if c < len(r) else 0 for r in rows)
        weights.append(max(6.0, min(float(longest), 64.0)))
    total = sum(weights)
    widths = [USABLE * w / total for w in weights]

    cmds = [
        ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
        ('GRID', (0, 0), (-1, -1), 0.4, RULE),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, ROW_ALT]),
    ]
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle(cmds))
    return t


def callout(text, styles):
    """A paragraph that opens in bold gets a tinted box.

    In this plan those are the sentences that carry a verdict or a warning —
    the ones a reader skimming for risk should not be able to miss.
    """
    p = Paragraph(inline(text), styles['body'])
    t = Table([[p]], colWidths=[USABLE])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), WARN_BG),
        ('BOX', (0, 0), (-1, -1), 0.4, WARN),
        ('LEFTPADDING', (0, 0), (-1, -1), 9),
        ('RIGHTPADDING', (0, 0), (-1, -1), 9),
        ('TOPPADDING', (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    return t


def make_decorator(fp):
    def decorate(canvas, doc):
        canvas.saveState()
        w = A4[0]
        canvas.setStrokeColor(RULE)
        canvas.setLineWidth(0.5)
        canvas.line(17 * mm, 12 * mm, w - 17 * mm, 12 * mm)
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(17 * mm, 7.5 * mm,
                          'SoftHSM2 CNG KSP — ADCS readiness · '
                          'generated from docs/16-adcs-readiness.md')
        canvas.drawRightString(w - 17 * mm, 7.5 * mm, 'Page %d' % doc.page)
        canvas.restoreState()
    return decorate


def main():
    md = open(SRC, encoding='utf-8').read()
    blocks, unknown = parse(md)
    fp = stamp_for(os.path.abspath(__file__), (SRC,))
    styles = build_styles()

    doc = BaseDocTemplate(
        OUT, pagesize=A4,
        leftMargin=17 * mm, rightMargin=17 * mm,
        topMargin=15 * mm, bottomMargin=18 * mm,
        title=DOC_TITLE, author='SoftHSM2 CNG KSP project',
        subject='Readiness assessment and phased plan for Microsoft ADCS',
        keywords=fp,
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height,
                  id='main')
    doc.addPageTemplates([PageTemplate(id='all', frames=[frame],
                                       onPage=make_decorator(fp))])

    story = []
    first_h1_seen = False

    for kind, payload in blocks:
        if kind == 'h1' and not first_h1_seen:
            # the document's own title line becomes the cover heading
            first_h1_seen = True
            # Strip the docs-index number: "16 — Running this…" is how the
            # markdown sits in docs/00-index.md, but this PDF travels on its
            # own and the number means nothing away from that index.
            heading = re.sub(r'^\d+\s*[—-]\s*', '', payload)
            story.append(Paragraph(inline(heading), styles['title']))
            story.append(Paragraph(
                'Assessment of this provider against what an Active Directory '
                'Certificate Services certification authority requires, and '
                'the phased plan to close the difference. Generated %s from '
                'the markdown of record.' % date.today().isoformat(),
                styles['sub']))
            continue

        if kind in ('h1', 'h2'):
            story.append(Paragraph(inline(payload), styles[kind]))
        elif kind == 'h3':
            story.append(Paragraph(inline(payload), styles['h2']))
        elif kind == 'para':
            if payload.startswith('**'):
                story.append(callout(payload, styles))
                story.append(Spacer(1, 7))
            else:
                story.append(Paragraph(inline(payload), styles['body']))
        elif kind == 'list':
            for marker, text in payload:
                story.append(Paragraph(inline(text), styles['bullet'],
                                       bulletText=marker))
            story.append(Spacer(1, 5))
        elif kind == 'table':
            t = table_flowable(payload, styles)
            # KeepTogether only for a table short enough to be worth it.
            # Applied to every table it was actively harmful: a long table
            # near the foot of a page jumped to the next one whole, leaving
            # two thirds of a page blank, and a table taller than one page
            # cannot be kept together at all. Long tables split instead,
            # and repeatRows=1 carries the header across the break.
            if len(payload) <= 6:
                story.append(KeepTogether([t, Spacer(1, 9)]))
            else:
                story.append(t)
                story.append(Spacer(1, 9))
        elif kind == 'hr':
            story.append(Spacer(1, 4))

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        '<font face="Courier" size="8">%s</font> &#8212; of the markdown this '
        'was rendered from, plus this script. '
        '<font face="Courier" size="8">tests/check_generated_artifacts.py</font> '
        'recomputes it, so a plan edited without regenerating is a CI failure '
        'rather than a PDF that quietly describes an older plan.' % fp,
        styles['sub']))

    doc.build(story)

    print('Wrote %s' % OUT)
    print('  %d blocks from %s' % (len(blocks), os.path.basename(SRC)))
    print('  %s' % fp)
    if unknown:
        print('  NOT RENDERED (outside the supported subset):')
        for u in unknown:
            print('    - %s' % u)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
