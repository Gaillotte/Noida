"""Geometric QA for a pptx, standing in for a rendered look.

Checks the defects the skill's visual pass looks for and that can be decided
from geometry: shapes off-slide, thin margins, text boxes overlapping each
other, and text that cannot fit its box.
"""
import sys, math
from pptx import Presentation
from pptx.util import Emu

SLIDE_W, SLIDE_H = 13.333, 7.5
MARGIN_MIN = 0.5

def inches(v): return None if v is None else Emu(v).inches

def text_of(shape):
    if not shape.has_text_frame: return ""
    return "\n".join(p.text for p in shape.text_frame.paragraphs)

def max_font(shape):
    sizes = [r.font.size.pt for p in shape.text_frame.paragraphs
             for r in p.runs if r.font.size]
    return max(sizes) if sizes else 12.0

def fits(shape, w, h):
    """Rough fit estimate: average glyph ~0.5em wide, line box ~1.28em."""
    total = 0.0
    fs = max_font(shape)
    cpl = max(1.0, (w * 72.0) / (fs * 0.58))
    for p in shape.text_frame.paragraphs:
        t = p.text
        if not t: total += 1; continue
        total += math.ceil(len(t) / cpl)
    need = total * fs * 1.28 / 72.0
    return need, need <= h + 0.06        # 0.06" tolerance

prs = Presentation(sys.argv[1])
issues = 0
for n, slide in enumerate(prs.slides, 1):
    boxes = []
    for sh in slide.shapes:
        x, y = inches(sh.left), inches(sh.top)
        w, h = inches(sh.width), inches(sh.height)
        if None in (x, y, w, h): continue

        if x < -0.01 or y < -0.01 or x + w > SLIDE_W + 0.01 or y + h > SLIDE_H + 0.01:
            print(f"  s{n}: OFF-SLIDE {sh.shape_type} at ({x:.2f},{y:.2f}) {w:.2f}x{h:.2f}")
            issues += 1
        if x < MARGIN_MIN - 0.01 or x + w > SLIDE_W - MARGIN_MIN + 0.01:
            print(f"  s{n}: thin side margin: x={x:.2f} right={x+w:.2f}")
            issues += 1
        if y + h > SLIDE_H - 0.18:
            print(f"  s{n}: close to bottom edge: bottom={y+h:.2f}")
            issues += 1

        txt = text_of(sh)
        if txt.strip():
            need, ok = fits(sh, w, h)
            if not ok:
                print(f"  s{n}: OVERFLOW risk ~{need:.2f}\" in {h:.2f}\" box "
                      f"[{txt.strip()[:52]!r}]")
                issues += 1
            boxes.append((x, y, w, h, txt.strip()[:34]))

    for i in range(len(boxes)):
        for j in range(i + 1, len(boxes)):
            ax, ay, aw, ah, at = boxes[i]
            bx, by, bw, bh, bt = boxes[j]
            ox = min(ax + aw, bx + bw) - max(ax, bx)
            oy = min(ay + ah, by + bh) - max(ay, by)
            if ox > 0.06 and oy > 0.06:
                print(f"  s{n}: TEXT OVERLAP {ox*oy:.2f}in^2 — {at!r} / {bt!r}")
                issues += 1

print(f"\n{issues} geometric issue(s) across {len(prs.slides.__iter__.__self__._sldIdLst)} slides"
      if False else f"\n{issues} geometric issue(s)")
