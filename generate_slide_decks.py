#!/usr/bin/env python3
"""Build a standalone, openable HTML deck from each slide source in docs/slides.

    python3 generate_slide_decks.py

Why the source is a folder of fragments rather than one file: each slide is
authored as a single <section> on a fixed 1920x1080 canvas with every style
inline, so a slide is reviewable on its own and a diff touching one slide
touches one file. That is the same reason the feature matrix lives in a CSV
rather than inside the PDF generator — a one-slide change should read as a
one-slide diff.

What this adds is the part a fragment cannot have: the document wrapper, the
typeface links, a scale that fits a screen, print rules that put one slide
on one page, and the speaker notes lifted out from inside the canvas to
below it, where they can be read.

The output carries a Content fingerprint of its inputs, so
tests/check_generated_artifacts.py fails if a slide is edited and the deck
is not rebuilt. Without that stamp a committed deck is a generated document
nothing verifies, which is the precise failure this repository keeps
paying for: a summary of a fact, sitting next to the fact, not updated with
it.
"""
import html
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'softhsm_ksp', 'docs'))

from matrix_fingerprint import stamp_for                       # noqa: E402

SLIDE_ROOT = os.path.join('softhsm_ksp', 'docs', 'slides')

# (source folder under docs/slides, output file under softhsm_ksp/, subtitle)
#
# Declared rather than discovered by globbing the folder: a deck that
# appears in the repository without an entry here would be built silently
# and verified by nothing, and a deck removed from here but left on disk is
# a visible diff. check_generated_artifacts.py reads this same list.
DECKS = [
    ('adcs-overview',
     'SoftHSM2_KSP_Design_Tests_ADCS_Slides.html',
     'Design of the solution, the test strategy, installation under '
     'Microsoft ADCS, and what remains'),
    ('joining-team-plan',
     'SoftHSM2_KSP_Team_Plan_Slides.html',
     'The plan for a team joining with the mission to finalise'),
]

# The canvas the slides are authored against, and the width the built page
# renders them at. Scaling rather than reflowing is deliberate: the slides
# position text absolutely in canvas pixels, so reflowing them would move
# things the author placed.
CANVAS_W, CANVAS_H = 1920, 1080
RENDER_W = 1280

ASIDE = re.compile(r'<aside>(.*?)</aside>', re.DOTALL)
HEADING = re.compile(r'<h[12][^>]*>(.*?)</h[12]>', re.DOTALL)
TAGS = re.compile(r'<[^>]+>')

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(title)s</title>
%(fonts)s<style>
*{box-sizing:border-box}
html{background:#20272E}
body{margin:0;padding:48px 0 96px;font-family:'IBM Plex Sans',Arial,sans-serif;color:#F7F7F4}
.wrap{width:%(render_w)spx;margin:0 auto}
header.doc{padding:0 0 40px}
header.doc h1{font-size:34px;font-weight:600;margin:0 0 10px;line-height:1.2}
header.doc p{font-size:17px;line-height:1.5;color:#AFC3D4;margin:0 0 6px}
header.doc .fp{font-family:'JetBrains Mono',monospace;font-size:13px;color:#7E95A8}
nav.outline{border-top:1px solid #39454F;border-bottom:1px solid #39454F;padding:20px 0;margin:0 0 40px}
nav.outline ol{margin:0;padding:0 0 0 22px;font-size:15px;line-height:1.7;color:#AFC3D4}
nav.outline a{color:#AFC3D4;text-decoration:none}
nav.outline a:hover{text-decoration:underline}
article.slide{margin:0 0 44px}
article.slide .num{font-family:'JetBrains Mono',monospace;font-size:13px;color:#7E95A8;padding:0 0 8px}
.frame{width:%(render_w)spx;height:%(render_h)spx;overflow:hidden;position:relative;
       border:1px solid #39454F;box-shadow:0 10px 28px rgba(0,0,0,.35)}
.frame>section{width:%(canvas_w)spx;height:%(canvas_h)spx;position:relative;
       transform:scale(%(scale)s);transform-origin:top left}
.frame>section aside{display:none}
.notes{background:#283038;border-left:4px solid #E08A4A;padding:18px 22px;margin:14px 0 0}
.notes h2{font-size:12px;font-weight:600;letter-spacing:2px;text-transform:uppercase;
       color:#E08A4A;margin:0 0 8px}
.notes p{font-size:15px;line-height:1.6;color:#CFDEE8;margin:0}
@media print{
  @page{size:%(canvas_w)spx %(canvas_h)spx;margin:0}
  html,body{background:#FFF}
  body{padding:0}
  .wrap{width:auto;margin:0}
  header.doc,nav.outline,article.slide .num,.notes{display:none}
  article.slide{margin:0;break-after:page;page-break-after:always}
  .frame{width:%(canvas_w)spx;height:%(canvas_h)spx;border:0;box-shadow:none}
  .frame>section{transform:none}
}
</style>
</head>
<body>
<div class="wrap">
<header class="doc">
<h1>%(title)s</h1>
<p>%(subtitle)s</p>
<p>%(count)s slides. Speaker notes are printed under each slide on screen and
omitted when printing. Built from <code>%(source)s</code> — edit the slide
there, never this file.</p>
<p class="fp">%(stamp)s</p>
</header>
<nav class="outline"><ol>
%(outline)s</ol></nav>
%(slides)s</div>
</body>
</html>
"""


def deck_inputs(folder):
    """Repo-relative inputs of one deck, deck.json first then slides in order.

    Both this generator and the staleness check call it, so the input set
    has exactly one definition. Order follows the deck's own `order`, which
    makes the digest depend on the slide sequence as well as the slide
    contents — reordering a deck is a change to it.
    """
    base = os.path.join(SLIDE_ROOT, folder)
    index = os.path.join(base, 'deck.json')
    with open(os.path.join(HERE, index), encoding='utf-8') as f:
        order = json.load(f)['order']
    return [index] + [os.path.join(base, 'slides', '%s.html' % slide)
                      for slide in order]


def text_of(fragment):
    """Plain text of an HTML fragment, for the outline."""
    return html.unescape(TAGS.sub('', fragment)).strip()


def build(folder, out_name, subtitle):
    index_path = os.path.join(HERE, SLIDE_ROOT, folder, 'deck.json')
    with open(index_path, encoding='utf-8') as f:
        index = json.load(f)

    # One <link> per declared typeface, de-duplicated but order-preserving:
    # a set here would make the output depend on hash iteration order.
    fonts, seen = [], set()
    for face in index.get('faces', {}).values():
        href = face.get('href')
        if href and href not in seen:
            seen.add(href)
            fonts.append('<link rel="stylesheet" href="%s">\n'
                         % html.escape(href, quote=True))

    # Where each outline section begins, so the contents list can show it.
    starts = {s['start']: s['description']
              for s in index.get('sections', {}).values()}

    outline, slides = [], []
    for n, slide_id in enumerate(index['order'], start=1):
        path = os.path.join(HERE, SLIDE_ROOT, folder,
                            'slides', '%s.html' % slide_id)
        with open(path, encoding='utf-8') as f:
            body = f.read().strip()

        note = ASIDE.search(body)
        notes_html = ''
        if note:
            notes_html = ('<div class="notes"><h2>Speaker notes</h2>'
                          '<p>%s</p></div>'
                          % html.escape(note.group(1).strip()))

        head = HEADING.search(body)
        label = text_of(head.group(1)) if head else slide_id
        if slide_id in starts:
            outline.append('<li><b><a href="#%s">%s</a></b> &mdash; %s</li>'
                           % (slide_id, html.escape(label),
                              html.escape(starts[slide_id])))
        else:
            outline.append('<li><a href="#%s">%s</a></li>'
                           % (slide_id, html.escape(label)))

        slides.append(
            '<article class="slide" id="%s">\n'
            '<div class="num">%s / %s</div>\n'
            '<div class="frame">%s</div>\n%s</article>\n'
            % (slide_id, n, len(index['order']), body, notes_html))

    inputs = [os.path.join(HERE, p) for p in deck_inputs(folder)]
    page = PAGE % {
        'title': html.escape(index.get('title', folder)),
        'subtitle': html.escape(subtitle),
        'fonts': ''.join(fonts),
        'count': len(index['order']),
        'source': html.escape(os.path.join(SLIDE_ROOT, folder)),
        'stamp': html.escape(stamp_for(os.path.abspath(__file__), inputs)),
        'outline': '\n'.join(outline) + '\n',
        'slides': ''.join(slides),
        'canvas_w': CANVAS_W,
        'canvas_h': CANVAS_H,
        'render_w': RENDER_W,
        'render_h': round(RENDER_W * CANVAS_H / CANVAS_W),
        'scale': round(RENDER_W / CANVAS_W, 6),
    }

    out_path = os.path.join(HERE, 'softhsm_ksp', out_name)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(page)
    return out_path, len(index['order'])


def main():
    for folder, out_name, subtitle in DECKS:
        path, n = build(folder, out_name, subtitle)
        print('  %-52s %2d slides' % (os.path.relpath(path, HERE), n))
    print('\nOpen either file in a browser; print to PDF for a '
          '16:9 one-slide-per-page export.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
