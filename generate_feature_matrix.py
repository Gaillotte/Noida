#!/usr/bin/env python3
"""Generate the CNG KSP Feature Matrix PDF from docs/feature-matrix.csv.

The CSV is the source of truth. To update the matrix — a new market feature
appears, or this project starts covering something — edit one row in the CSV
and re-run this script. Every count and percentage in the PDF is computed
from the data, so the summary can never drift from the table.

    pip install reportlab
    python3 generate_feature_matrix.py

Output: softhsm_ksp/SoftHSM2_KSP_Feature_Matrix.pdf
"""

import csv
import os
import sys
from collections import OrderedDict
from datetime import date

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether,
                               PageTemplate, Paragraph, Spacer, Table,
                               TableStyle)

HERE = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(HERE, 'softhsm_ksp', 'docs', 'feature-matrix.csv')
PDF_PATH = os.path.join(HERE, 'softhsm_ksp', 'SoftHSM2_KSP_Feature_Matrix.pdf')

# ── Palette ─────────────────────────────────────────────────────────────────
INK        = colors.HexColor('#1A1D1C')
MUTED      = colors.HexColor('#5F6664')
ACCENT     = colors.HexColor('#0B5D5A')
ACCENT_BG  = colors.HexColor('#E4EFEE')
RULE       = colors.HexColor('#C9CFCD')
ROW_ALT    = colors.HexColor('#F4F6F5')
CAT_BG     = colors.HexColor('#DDE6E5')

OK         = colors.HexColor('#1F6B3F')
OK_BG      = colors.HexColor('#E6F1E9')
PART       = colors.HexColor('#8A5A14')
PART_BG    = colors.HexColor('#F7EEDD')
GAP        = colors.HexColor('#8C2F2A')
GAP_BG     = colors.HexColor('#F8E9E8')
NA         = colors.HexColor('#5F6664')
NA_BG      = colors.HexColor('#ECEFEE')

STATUS_STYLE = {
    'Covered':     (OK,   OK_BG),
    'Partial':     (PART, PART_BG),
    'Not covered': (GAP,  GAP_BG),
}

DOC_TITLE = 'CNG KSP Feature Matrix'


# ── Styles ──────────────────────────────────────────────────────────────────
def build_styles():
    ss = getSampleStyleSheet()
    s = {}
    s['title'] = ParagraphStyle('title', parent=ss['Title'], fontName='Helvetica-Bold',
                                fontSize=20, leading=24, textColor=INK,
                                alignment=TA_LEFT, spaceAfter=2)
    s['sub'] = ParagraphStyle('sub', parent=ss['Normal'], fontName='Helvetica',
                              fontSize=9.5, leading=13, textColor=MUTED, spaceAfter=10)
    s['h2'] = ParagraphStyle('h2', parent=ss['Heading2'], fontName='Helvetica-Bold',
                             fontSize=11.5, leading=14, textColor=ACCENT,
                             spaceBefore=10, spaceAfter=5)
    s['body'] = ParagraphStyle('body', parent=ss['Normal'], fontName='Helvetica',
                               fontSize=8.5, leading=11, textColor=INK)
    s['note'] = ParagraphStyle('note', parent=ss['Normal'], fontName='Helvetica',
                               fontSize=8.5, leading=11.5, textColor=MUTED)
    s['cell'] = ParagraphStyle('cell', parent=ss['Normal'], fontName='Helvetica',
                               fontSize=6.6, leading=8.2, textColor=INK)
    s['cellb'] = ParagraphStyle('cellb', parent=s['cell'], fontName='Helvetica-Bold')
    s['cellm'] = ParagraphStyle('cellm', parent=s['cell'], textColor=MUTED)
    s['cellmono'] = ParagraphStyle('cellmono', parent=s['cell'], fontName='Courier',
                                   fontSize=6.2)
    s['hdr'] = ParagraphStyle('hdr', parent=ss['Normal'], fontName='Helvetica-Bold',
                              fontSize=6.6, leading=8, textColor=colors.white)
    s['cat'] = ParagraphStyle('cat', parent=ss['Normal'], fontName='Helvetica-Bold',
                              fontSize=7.4, leading=9, textColor=ACCENT)
    return s


# ── Data ────────────────────────────────────────────────────────────────────
def soften(text):
    """Let long CONSTANT_NAMES wrap at underscores.

    ReportLab breaks an over-long unbroken token at an arbitrary character,
    which splits identifiers like NCRYPT_KEY_STORAGE_FUNCTION_TABLE mid-word.
    Inserting a zero-width space after each underscore of a long token gives
    the line breaker a sensible place to wrap. The character is invisible and
    does not affect text extracted from the PDF.
    """
    out = []
    for tok in text.split(' '):
        if len(tok) > 18 and '_' in tok:
            tok = tok.replace('_', '_\u200b')
        out.append(tok)
    return ' '.join(out)


def load_rows(path):
    if not os.path.exists(path):
        sys.exit('Source CSV not found: %s' % path)
    with open(path, newline='', encoding='utf-8') as fh:
        rows = [r for r in csv.DictReader(fh) if r.get('id')]
    if not rows:
        sys.exit('Source CSV has no data rows: %s' % path)
    return rows


def summarise(rows):
    """Every figure in the PDF comes from here, so it cannot drift."""
    counts = OrderedDict((k, 0) for k in
                         ('Covered', 'Partial', 'Not covered'))
    for r in rows:
        st = r['status'].strip()
        counts[st] = counts.get(st, 0) + 1

    # "Actionable" excludes gaps whose effort column is N/A — those are
    # deliberate positions or external blockers, not backlog items.
    actionable = [r for r in rows
                  if r['status'].strip() in ('Partial', 'Not covered')
                  and r['effort'].strip() not in ('N/A', '')]
    effort = OrderedDict((k, 0) for k in ('S', 'M', 'L'))
    for r in actionable:
        e = r['effort'].strip()
        effort[e] = effort.get(e, 0) + 1

    total = len(rows)
    covered = counts.get('Covered', 0)
    return {
        'total': total,
        'counts': counts,
        'pct_covered': (100.0 * covered / total) if total else 0.0,
        'actionable': len(actionable),
        'effort': effort,
        'categories': len(OrderedDict((r['category'], 1) for r in rows)),
    }


# ── Page furniture ──────────────────────────────────────────────────────────
def make_page_decorator(stats):
    def decorate(canvas, doc):
        canvas.saveState()
        w, h = landscape(A4)

        canvas.setStrokeColor(RULE)
        canvas.setLineWidth(0.5)
        canvas.line(14 * mm, 12 * mm, w - 14 * mm, 12 * mm)

        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(14 * mm, 7.5 * mm,
                          'SoftHSM2 CNG KSP — Feature Matrix · '
                          'generated from docs/feature-matrix.csv')
        canvas.drawRightString(w - 14 * mm, 7.5 * mm, 'Page %d' % doc.page)
        canvas.restoreState()
    return decorate


def status_cell(status, styles):
    fg, _ = STATUS_STYLE.get(status, (NA, NA_BG))
    st = ParagraphStyle('s_%s' % status, parent=styles['cell'],
                        fontName='Helvetica-Bold', textColor=fg)
    return Paragraph(status, st)


# ── Document ────────────────────────────────────────────────────────────────
def build(rows, stats, styles):
    doc = BaseDocTemplate(
        PDF_PATH, pagesize=landscape(A4),
        leftMargin=14 * mm, rightMargin=14 * mm,
        topMargin=13 * mm, bottomMargin=16 * mm,
        title=DOC_TITLE,
        author='SoftHSM2 CNG KSP project',
        subject='Market feature coverage and gap analysis',
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height,
                  id='main', showBoundary=0)
    doc.addPageTemplates([PageTemplate(id='all', frames=[frame],
                                       onPage=make_page_decorator(stats))])

    story = []
    story.append(Paragraph(DOC_TITLE, styles['title']))
    story.append(Paragraph(
        'Every capability observed across shipping CNG Key Storage Providers, '
        'with this project&#39;s coverage and — where a gap exists — what closing '
        'it would take.  Generated %s.' % date.today().isoformat(),
        styles['sub']))

    story += summary_block(stats, styles)
    story += legend_block(styles)
    story += matrix_table(rows, styles)
    story += closing_block(stats, styles)

    doc.build(story)


def summary_block(stats, styles):
    c = stats['counts']
    cells = [
        ('%d' % stats['total'],                 'Capabilities tracked'),
        ('%d' % c.get('Covered', 0),            'Covered'),
        ('%d' % c.get('Partial', 0),            'Partial'),
        ('%d' % c.get('Not covered', 0),        'Not covered'),
        ('%.0f%%' % stats['pct_covered'],       'Fully covered'),
        ('%d' % stats['actionable'],            'Actionable gaps'),
    ]
    big = ParagraphStyle('big', parent=styles['body'], fontName='Helvetica-Bold',
                         fontSize=15, leading=17, textColor=ACCENT)
    lbl = ParagraphStyle('lbl', parent=styles['body'], fontSize=6.8,
                         leading=8.5, textColor=MUTED)
    data = [[Paragraph(v, big) for v, _ in cells],
            [Paragraph(l, lbl) for _, l in cells]]
    t = Table(data, colWidths=[44 * mm] * len(cells))
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), ACCENT_BG),
        ('BOX',        (0, 0), (-1, -1), 0.5, RULE),
        ('INNERGRID',  (0, 0), (-1, -1), 0.5, colors.white),
        ('LEFTPADDING',(0, 0), (-1, -1), 7),
        ('TOPPADDING', (0, 0), (-1, 0), 6),
        ('BOTTOMPADDING', (0, 1), (-1, 1), 6),
        ('VALIGN',     (0, 0), (-1, -1), 'TOP'),
    ]))
    return [t, Spacer(1, 9)]


def legend_block(styles):
    out = [Paragraph('How to read this', styles['h2'])]

    rows = [
        ['Status', 'Meaning'],
        ['Covered', 'Implemented and exercised by the test suite.'],
        ['Partial', 'Implemented, but reachable only through a non-standard identifier or with a stated caveat.'],
        ['Not covered', 'Absent. The Gap column says what closing it would take.'],
    ]
    body = [[Paragraph(rows[0][0], styles['hdr']), Paragraph(rows[0][1], styles['hdr'])]]
    for name, meaning in rows[1:]:
        body.append([status_cell(name, styles), Paragraph(meaning, styles['cell'])])
    t1 = Table(body, colWidths=[26 * mm, 108 * mm])
    t1.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, ROW_ALT]),
        ('BOX', (0, 0), (-1, -1), 0.5, RULE),
        ('LINEBELOW', (0, 0), (-1, -2), 0.3, RULE),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))

    ev = [
        ['Ev', 'Evidence for the market claim'],
        ['A', 'Read from source code or an authoritative API reference that enumerates the provider&#39;s own algorithm list.'],
        ['B', 'Stated in vendor or Microsoft documentation surfaced through search; primary page not read in full.'],
        ['C', 'Drawn from HSM datasheets describing the device rather than its KSP. Treat as a lead, not a fact.'],
    ]
    ebody = [[Paragraph(ev[0][0], styles['hdr']), Paragraph(ev[0][1], styles['hdr'])]]
    for g, meaning in ev[1:]:
        ebody.append([Paragraph('<b>%s</b>' % g, styles['cell']),
                      Paragraph(meaning, styles['cell'])])
    t2 = Table(ebody, colWidths=[10 * mm, 124 * mm])
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, ROW_ALT]),
        ('BOX', (0, 0), (-1, -1), 0.5, RULE),
        ('LINEBELOW', (0, 0), (-1, -2), 0.3, RULE),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))

    side = Table([[t1, t2]], colWidths=[136 * mm, 136 * mm])
    side.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'TOP'),
                              ('LEFTPADDING', (0, 0), (-1, -1), 0),
                              ('RIGHTPADDING', (0, 0), (0, 0), 6)]))
    out.append(side)

    out.append(Spacer(1, 5))
    out.append(Paragraph(
        '<b>Effort</b> on gaps: S = a few lines to a day · M = days · '
        'L = a substantial piece of work.  <b>N/A</b> marks a deliberate '
        'position or an external blocker rather than a backlog item — those '
        'are excluded from the actionable-gap count.',
        styles['note']))
    out.append(Spacer(1, 9))
    return out


def matrix_table(rows, styles):
    header = ['ID', 'Feature', 'Detail', 'Market support', 'Ev',
              'Status', 'Gap — what closing it would take', 'Eff']
    widths = [15 * mm, 36 * mm, 36 * mm, 31 * mm, 6 * mm,
              17 * mm, 122 * mm, 8 * mm]

    data = [[Paragraph(h, styles['hdr']) for h in header]]
    cmds = [
        ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOX', (0, 0), (-1, -1), 0.5, RULE),
        ('LINEBELOW', (0, 0), (-1, 0), 0.5, RULE),
        ('LEFTPADDING', (0, 0), (-1, -1), 3),
        ('RIGHTPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]

    current_cat = None
    idx = 0
    for r in rows:
        if r['category'] != current_cat:
            current_cat = r['category']
            idx += 1
            data.append([Paragraph(current_cat.upper(), styles['cat']),
                         '', '', '', '', '', '', ''])
            cmds += [('SPAN', (0, idx), (-1, idx)),
                     ('BACKGROUND', (0, idx), (-1, idx), CAT_BG),
                     ('TOPPADDING', (0, idx), (-1, idx), 4),
                     ('BOTTOMPADDING', (0, idx), (-1, idx), 3)]

        idx += 1
        status = r['status'].strip()
        _, bg = STATUS_STYLE.get(status, (NA, NA_BG))

        gap = r['gap_solution'].strip()
        gap_par = (Paragraph(soften(gap), styles['cell']) if gap
                   else Paragraph('—', styles['cellm']))

        data.append([
            Paragraph(r['id'], styles['cellmono']),
            Paragraph(r['feature'], styles['cellb']),
            Paragraph(soften(r['detail']), styles['cellm']),
            Paragraph(r['market'], styles['cellm']),
            Paragraph(r['evidence'], styles['cell']),
            status_cell(status, styles),
            gap_par,
            Paragraph(r['effort'] or '—', styles['cell']),
        ])
        cmds.append(('BACKGROUND', (5, idx), (5, idx), bg))
        if idx % 2 == 0:
            cmds.append(('BACKGROUND', (0, idx), (4, idx), ROW_ALT))
            cmds.append(('BACKGROUND', (6, idx), (-1, idx), ROW_ALT))

    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle(cmds))
    return [t, Spacer(1, 10)]


def closing_block(stats, styles):
    e = stats['effort']
    out = [Paragraph('Maintaining this document', styles['h2'])]
    out.append(Paragraph(
        'The source of truth is <font face="Courier">softhsm_ksp/docs/feature-matrix.csv</font>. '
        'One row per capability. To record that a gap has been closed, change that row&#39;s '
        '<i>status</i> to Covered and clear its <i>gap_solution</i>; to add a newly observed '
        'market feature, append a row with a fresh ID. Then regenerate:',
        styles['body']))
    out.append(Spacer(1, 3))
    out.append(Paragraph(
        '<font face="Courier">python3 generate_feature_matrix.py</font>',
        styles['body']))
    out.append(Spacer(1, 5))
    out.append(Paragraph(
        'Every number on page 1 is computed from the CSV at generation time, so the '
        'summary cannot fall out of step with the table. Because the CSV is plain text, '
        'a change to coverage shows up as a one-line diff in review rather than an '
        'opaque binary change.',
        styles['note']))
    out.append(Spacer(1, 7))

    out.append(Paragraph(
        'Actionable gaps by effort: <b>%d small</b>, <b>%d medium</b>, <b>%d large</b>. '
        'Rows marked N/A are excluded — they are deliberate positions (private key export '
        'is refused by design) or external blockers (CNG defines no EdDSA identifier; '
        'SoftHSM2 is a software token).'
        % (e.get('S', 0), e.get('M', 0), e.get('L', 0)),
        styles['body']))
    out.append(Spacer(1, 7))
    out.append(Paragraph(
        '<b>A caution on the market columns.</b> An HSM datasheet is not a statement about '
        'its CNG provider. AWS CloudHSM performs AES, DES3 and HMAC in hardware, yet its KSP '
        'answers NCryptIsAlgSupported for exactly four identifiers. Every grade-C cell here '
        'carries that uncertainty. See docs/11-market-comparison.md for the full audit and '
        'its sources.',
        styles['note']))
    return out


def main():
    styles = build_styles()
    rows = load_rows(CSV_PATH)
    stats = summarise(rows)
    build(rows, stats, styles)

    c = stats['counts']
    print('Wrote %s' % PDF_PATH)
    print('  %d capabilities across %d categories'
          % (stats['total'], stats['categories']))
    print('  Covered %d · Partial %d · Not covered %d  (%.0f%% fully covered)'
          % (c.get('Covered', 0), c.get('Partial', 0),
             c.get('Not covered', 0), stats['pct_covered']))
    print('  %d actionable gaps — S:%d M:%d L:%d'
          % (stats['actionable'], stats['effort'].get('S', 0),
             stats['effort'].get('M', 0), stats['effort'].get('L', 0)))


if __name__ == '__main__':
    main()
