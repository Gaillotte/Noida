// The delivery plan as slides — three per step: design impact, proposed
// solution, test strategy.
//
//   python generate_rest_kms_plan.py     # writes plan_steps.json
//   node generate_rest_kms_deck.js       # reads it
//
// The deck holds no content of its own. Every word comes from plan_steps.json,
// which generate_rest_kms_plan.py emits from the same tuples that build the
// Word document — so the deck cannot say something the plan does not, and the
// plan's reconciliation against the gap matrix covers both.

const fs = require("fs");
const pptxgen = require("pptxgenjs");

const PLAN = "plan_steps.json";
if (!fs.existsSync(PLAN)) {
  console.error(`${PLAN} is missing — run: python generate_rest_kms_plan.py`);
  process.exit(1);
}
const plan = JSON.parse(fs.readFileSync(PLAN, "utf8"));

// ── palette: the project's document identity, gold as the accent ──────────
const NAVY = "1A3A5C";
const DEEP = "102437";
const MID = "2E6DA4";
const ICE = "E8EFF6";
const PAPER = "FFFFFF";
const GOLD = "C8952B";
const SOFT = "4D5A68";
const FAINT = "7B8794";
const OK = "1F7A43";
const WARN = "9A6410";
const GAPC = "B3261E";

const HEAD = "Cambria";
const BODY = "Calibri";

const W = 13.3;
const M = 0.62;
const CW = W - M * 2;

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";
pres.author = "kmip_pkcs11";
pres.title = "REST KMS delivery plan";

const WARNINGS = [];

// ── helpers ───────────────────────────────────────────────────────────────

function shadow() {
  return { type: "outer", color: "8C9AA8", blur: 10, offset: 2, angle: 90, opacity: 0.22 };
}

// Line spacing is set from the font size rather than pinned, so that shrinking
// a panel's font actually buys vertical space. It did not: panel() asked for
// 16pt spacing at every size, which is why an adaptive font still overflowed.
function lineSpacingFor(size) {
  return size * 1.30;
}

// Height of a block of text, calibrated against a LibreOffice render. Bullets
// cost more than they look: the hanging indent narrows the usable width and
// paraSpaceAfter accumulates. 0.62 is the measured average glyph width for
// this font at these sizes — 0.58 was optimistic and let content past the fit
// check that the render then showed hanging out of the panel.
function textHeight(text, size, widthIn, isBullet) {
  const usable = widthIn - (isBullet ? 0.22 : 0);
  const cpl = Math.max(8, (usable * 72) / (size * 0.62));
  return Math.ceil(text.length / cpl) * lineSpacingFor(size) / 72;
}

function checkFit(label, available, needed) {
  if (needed > available + 0.02) {
    WARNINGS.push(`  "${label.slice(0, 44)}" needs ${needed.toFixed(2)}" `
      + `but has ${available.toFixed(2)}"`);
  }
}

function lightSlide(eyebrow, title) {
  const s = pres.addSlide();
  s.background = { color: PAPER };
  s.addText(eyebrow.toUpperCase(), {
    x: M, y: 0.40, w: CW, h: 0.26, isTextBox: true, margin: 0,
    fontFace: BODY, fontSize: 11.5, bold: true, charSpacing: 2.2, color: GOLD,
  });
  s.addText(title, {
    x: M, y: 0.68, w: CW, h: 0.70, isTextBox: true, margin: 0,
    fontFace: HEAD, fontSize: 30, bold: true, color: NAVY,
  });
  return s;
}

function darkSlide(eyebrow, title) {
  const s = pres.addSlide();
  s.background = { color: DEEP };
  if (eyebrow) {
    s.addText(eyebrow.toUpperCase(), {
      x: M, y: 0.40, w: CW, h: 0.26, isTextBox: true, margin: 0,
      fontFace: BODY, fontSize: 11.5, bold: true, charSpacing: 2.2, color: GOLD,
    });
  }
  if (title) {
    s.addText(title, {
      x: M, y: 0.68, w: CW, h: 0.70, isTextBox: true, margin: 0,
      fontFace: HEAD, fontSize: 30, bold: true, color: PAPER,
    });
  }
  return s;
}

// Height a panel needs for its content. Panels are sized to what they hold —
// a fixed height leaves two inches of empty box on the short steps.
function panelHeight(items, size, widthIn, hasTag) {
  const body = items.reduce(
    (a, t) => a + textHeight(t, size, widthIn - 0.56, true) + 7 / 72, 0);
  return 0.24 + (hasTag ? 0.32 : 0) + body + 0.20;
}

// The largest font from `sizes` whose content fits `maxH`, falling back to the
// smallest. Steps differ a lot in how much they carry, and a fixed size means
// either the long steps overflow or the short ones look sparse.
function fitSize(items, widthIn, maxH, sizes) {
  for (const sz of sizes) {
    if (panelHeight(items, sz, widthIn, true) <= maxH) return sz;
  }
  return sizes[sizes.length - 1];
}

// A panel of bullets. Height is measured, never guessed.
function panel(s, o) {
  s.addShape(pres.ShapeType.roundRect, {
    x: o.x, y: o.y, w: o.w, h: o.h, rectRadius: 0.06,
    fill: { color: o.fill || ICE }, line: { color: o.fill || ICE, width: 1 },
    shadow: o.flat ? undefined : shadow(),
  });
  let ty = o.y + 0.24;
  if (o.tag) {
    s.addText(o.tag.toUpperCase(), {
      x: o.x + 0.28, y: ty, w: o.w - 0.56, h: 0.22, isTextBox: true, margin: 0,
      fontFace: BODY, fontSize: 10, bold: true, charSpacing: 1.6,
      color: o.tagColor || MID,
    });
    ty += 0.32;
  }
  const size = o.size || 12.5;
  const needed = o.items.reduce(
    (a, t) => a + textHeight(t, size, o.w - 0.56, true) + 7 / 72, 0);
  checkFit(o.tag || o.items[0], o.y + o.h - ty - 0.20, needed);
  s.addText(o.items.map((t, i) => ({
    text: t, options: { bullet: true, breakLine: i < o.items.length - 1 },
  })), {
    x: o.x + 0.28, y: ty, w: o.w - 0.56, h: o.y + o.h - ty - 0.20,
    isTextBox: true, margin: 0, valign: "top",
    fontFace: BODY, fontSize: size, color: o.color || SOFT,
    paraSpaceAfter: 7, lineSpacing: lineSpacingFor(size),
  });
}

// The band that names the step, carried on all three of its slides so a
// reader who joins mid-deck knows where they are.
function stepBand(s, step) {
  s.addShape(pres.ShapeType.roundRect, {
    x: M, y: 1.52, w: CW, h: 0.52, rectRadius: 0.06,
    fill: { color: NAVY }, line: { color: NAVY, width: 1 },
  });
  s.addText(step.objective, {
    x: M + 0.28, y: 1.52, w: CW - 1.9, h: 0.52, isTextBox: true, margin: 0,
    valign: "middle", fontFace: BODY, fontSize: 12, color: "C9DAEA",
  });
  s.addText(`Stage ${step.stage}`, {
    x: W - M - 1.55, y: 1.52, w: 1.3, h: 0.52, isTextBox: true, margin: 0,
    align: "right", valign: "middle",
    fontFace: BODY, fontSize: 11, bold: true, color: GOLD,
  });
}

function footnote(s, text, colour) {
  s.addText(text, {
    x: M, y: 6.86, w: CW, h: 0.34, isTextBox: true, margin: 0,
    fontFace: BODY, fontSize: 10.5, italic: true, color: colour || FAINT,
  });
}

function arrowRight(s, x, yCentre, w) {
  s.addShape(pres.ShapeType.rightArrow, {
    x: x, y: yCentre - 0.09, w: Math.max(w, 0.18), h: 0.18,
    fill: { color: MID }, line: { color: MID, width: 1 },
  });
}

// ══════════════════════════════════════════════════════════════════════════
// Title
// ══════════════════════════════════════════════════════════════════════════
{
  const s = darkSlide(null, null);
  s.addText("Completing the KMS", {
    x: M, y: 1.85, w: CW, h: 0.95, isTextBox: true, margin: 0,
    fontFace: HEAD, fontSize: 50, bold: true, color: PAPER,
  });
  s.addText(`${plan.steps.length} steps to a REST-fronted key management service`, {
    x: M, y: 2.86, w: CW, h: 0.5, isTextBox: true, margin: 0,
    fontFace: HEAD, fontSize: 22, color: "9DB8D4",
  });
  s.addText("Design impact · proposed solution · test strategy, for every step", {
    x: M, y: 3.46, w: CW, h: 0.4, isTextBox: true, margin: 0,
    fontFace: BODY, fontSize: 14, color: GOLD, charSpacing: 1.2,
  });

  const t = plan.totals;
  const tiles = [
    [String(plan.steps.length), `steps in ${plan.stages.length} stages`],
    [String(t.open), "features short of full coverage"],
    [String(t.closed), "closed by this plan"],
    [String(t.deferred), "deferred, with reasons"],
  ];
  tiles.forEach(([n, l], i) => {
    const x = M + i * 3.05;
    s.addText(n, {
      x: x, y: 4.58, w: 2.8, h: 0.58, isTextBox: true, margin: 0,
      fontFace: HEAD, fontSize: 32, bold: true, color: GOLD,
    });
    s.addText(l, {
      x: x, y: 5.20, w: 2.8, h: 0.6, isTextBox: true, margin: 0,
      fontFace: BODY, fontSize: 11.5, color: "9DB8D4",
    });
  });
  s.addText(`Baseline ${plan.baseline} · ${plan.baseline_tests} tests green · `
    + `${plan.generated}`, {
    x: M, y: 6.64, w: CW, h: 0.3, isTextBox: true, margin: 0,
    fontFace: BODY, fontSize: 10.5, color: "6B8299",
  });
  s.addNotes("Three slides per step: what it does to the existing design, what "
    + "gets built, and how it is proven. Every word in this deck comes from "
    + "plan_steps.json, which the plan generator emits — the deck cannot say "
    + "anything the written plan does not.");
}

// ══════════════════════════════════════════════════════════════════════════
// Overview
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("The plan at a glance",
    `${plan.stages.length} stages, ${plan.steps.length} steps`);

  const byStage = {};
  plan.steps.forEach(st => {
    (byStage[st.stage] = byStage[st.stage] || []).push(st);
  });

  // Column width follows the stage count rather than a number typed once for
  // four of them: a fifth stage used to run 3" off the right edge.
  const GAP = 0.22;
  const colW = (CW - (plan.stages.length - 1) * GAP) / plan.stages.length;
  const narrow = colW < 2.55;
  plan.stages.forEach((stage, i) => {
    const x = M + i * (colW + GAP);
    const steps = byStage[stage.letter] || [];
    s.addShape(pres.ShapeType.roundRect, {
      x: x, y: 1.60, w: colW, h: 0.72, rectRadius: 0.06,
      fill: { color: NAVY }, line: { color: NAVY, width: 1 },
    });
    s.addText(`${stage.letter} · ${stage.name}`, {
      x: x + 0.14, y: 1.60, w: colW - 0.28, h: 0.72, isTextBox: true, margin: 0,
      align: "center", valign: "middle",
      fontFace: HEAD, fontSize: narrow ? 12.5 : 14, bold: true, color: PAPER,
    });
    s.addText(stage.note, {
      x: x + 0.10, y: 2.38, w: colW - 0.20, h: 0.56, isTextBox: true, margin: 0,
      align: "center", fontFace: BODY, fontSize: narrow ? 9 : 10, italic: true,
      color: FAINT,
    });

    let y = 3.00;
    steps.forEach(st => {
      const closes = st.closes.length;
      s.addShape(pres.ShapeType.roundRect, {
        x: x, y: y, w: colW, h: 0.62, rectRadius: 0.05,
        fill: { color: ICE }, line: { color: ICE, width: 1 },
      });
      s.addText(String(st.n), {
        x: x + 0.10, y: y, w: 0.34, h: 0.62, isTextBox: true, margin: 0,
        valign: "middle", fontFace: HEAD, fontSize: narrow ? 13 : 15, bold: true,
        color: GOLD,
      });
      s.addText(st.title, {
        x: x + 0.46, y: y, w: colW - 0.94, h: 0.62, isTextBox: true, margin: 0,
        valign: "middle", fontFace: BODY, fontSize: narrow ? 9 : 10.5, color: NAVY,
      });
      s.addText(closes ? `+${closes}` : "—", {
        x: x + colW - 0.46, y: y, w: 0.34, h: 0.62, isTextBox: true, margin: 0,
        align: "right", valign: "middle",
        fontFace: BODY, fontSize: narrow ? 9.5 : 10.5, bold: true,
        color: closes ? OK : FAINT,
      });
      y += 0.70;
    });

    if (i < plan.stages.length - 1) arrowRight(s, x + colW + 0.03, 1.96, GAP - 0.06);
  });

  footnote(s, "+n is the number of gap-matrix features the step closes. Steps 1 "
    + "and 2 close nothing and are the two the rest depends on.");
  s.addNotes("Order is dictated by dependency. Step 1 must precede everything: "
    + "authorization, dual control and audit currently live inside the KMIP "
    + "dispatcher, and a REST layer built before they move would bypass all "
    + "three silently.");
}

// ══════════════════════════════════════════════════════════════════════════
// Three slides per step
// ══════════════════════════════════════════════════════════════════════════
plan.steps.forEach(step => {

  // ── 1. design impact ────────────────────────────────────────────────
  {
    const s = lightSlide(`Step ${step.n} of ${plan.steps.length} · Design impact`, step.title);
    stepBand(s, step);
    const CAP1 = 4.44;
    const sz1a = fitSize(step.impact, 6.0, CAP1, [12.5, 11.5, 10.5]);
    const sz1b = fitSize(step.design, 5.76, CAP1, [12, 11, 10, 9.5]);
    const h1 = Math.min(CAP1, Math.max(2.10,
      panelHeight(step.impact, sz1a, 6.0, true),
      panelHeight(step.design, sz1b, 5.76, true)));
    panel(s, {
      x: M, y: 2.30, w: 6.0, h: h1, fill: "FBF3E3",
      tag: "What changes in the existing design", tagColor: WARN,
      items: step.impact, size: sz1a,
    });
    panel(s, {
      x: M + 6.3, y: 2.30, w: 5.76, h: h1, fill: ICE,
      tag: "The shape of the solution", items: step.design, size: sz1b,
    });
    s.addNotes(`Objective: ${step.objective}`);
  }

  // ── 2. proposed solution ────────────────────────────────────────────
  {
    const s = lightSlide(`Step ${step.n} of ${plan.steps.length} · Proposed solution`, step.title);
    stepBand(s, step);
    const hasCloses = step.closes.length > 0;
    const implW = hasCloses ? 7.4 : CW;
    const CAP2 = 4.20;
    const sz2a = fitSize(step.implementation, implW, CAP2, [12.5, 11.5, 10.5]);
    const sz2b = hasCloses ? fitSize(step.closes, 4.36, CAP2, [12, 11, 10]) : 12;
    const h2 = Math.min(CAP2, Math.max(2.10,
      panelHeight(step.implementation, sz2a, implW, true),
      hasCloses ? panelHeight(step.closes, sz2b, 4.36, true) : 0));
    panel(s, {
      x: M, y: 2.30, w: implW, h: h2, fill: ICE,
      tag: "What gets built", items: step.implementation, size: sz2a,
    });
    if (hasCloses) {
      panel(s, {
        x: M + 7.7, y: 2.30, w: 4.36, h: h2, fill: "E2F0E7",
        tag: `Closes ${step.closes.length} gap-matrix feature`
             + (step.closes.length > 1 ? "s" : ""),
        tagColor: OK, items: step.closes, size: sz2b, color: NAVY,
      });
    } else {
      s.addShape(pres.ShapeType.roundRect, {
        x: M, y: 2.30 + h2 + 0.28, w: CW, h: 0.92, rectRadius: 0.06,
        fill: { color: NAVY }, line: { color: NAVY, width: 1 },
      });
      s.addText("Closes no gap-matrix feature directly. It exists so that every "
        + "step after it can be built without re-litigating authorization — and "
        + "so a later endpoint cannot silently become a path around dual control.", {
        x: M + 0.28, y: 2.30 + h2 + 0.28, w: CW - 0.56, h: 0.92,
        isTextBox: true, margin: 0,
        valign: "middle", fontFace: BODY, fontSize: 12, color: "C9DAEA",
      });
    }
    if (hasCloses) footnote(s, `Estimated size: ${step.size}`);
    else footnote(s, `Estimated size: ${step.size}`);
    s.addNotes(`Objective: ${step.objective}`);
  }

  // ── 3. test strategy ────────────────────────────────────────────────
  {
    const s = lightSlide(`Step ${step.n} of ${plan.steps.length} · Test strategy`, step.title);
    stepBand(s, step);
    const CAP3 = 3.82;
    const sz3 = fitSize(step.tests, CW, CAP3, [12.5, 11.5, 10.5]);
    const h3 = Math.min(CAP3, Math.max(2.10,
      panelHeight(step.tests, sz3, CW, true)));
    panel(s, {
      x: M, y: 2.30, w: CW, h: h3, fill: ICE,
      tag: "What the tests have to prove", items: step.tests, size: sz3,
    });
    const gateY = 2.30 + h3 + 0.30;
    s.addShape(pres.ShapeType.roundRect, {
      x: M, y: gateY, w: CW, h: 1.00, rectRadius: 0.06,
      fill: { color: "E2F0E7" }, line: { color: "E2F0E7", width: 1 },
      shadow: shadow(),
    });
    s.addText("GATE", {
      x: M + 0.28, y: gateY + 0.16, w: 1.0, h: 0.24, isTextBox: true, margin: 0,
      fontFace: BODY, fontSize: 10, bold: true, charSpacing: 1.6, color: OK,
    });
    const gateNeed = textHeight(step.gate, 12.5, CW - 1.6, false);
    checkFit(`gate for step ${step.n}`, 0.62, gateNeed);
    s.addText(step.gate, {
      x: M + 1.32, y: gateY + 0.12, w: CW - 1.6, h: 0.76, isTextBox: true, margin: 0,
      fontFace: BODY, fontSize: 12.5, color: NAVY,
    });
    s.addNotes("A step is finished when its gate is demonstrated, not when its "
      + "code is written. Tests run live against a real SoftHSM2 token — the "
      + "token is never mocked, because the defects worth catching are at that "
      + "boundary.");
  }
});

// ══════════════════════════════════════════════════════════════════════════
// Closing
// ══════════════════════════════════════════════════════════════════════════
{
  const s = darkSlide("After step 12", "What the plan does not close");
  const t = plan.totals;

  const kinds = {};
  plan.remaining.forEach(r => { (kinds[r.kind] = kinds[r.kind] || []).push(r.feature); });
  const order = ["integration", "validation", "product scope", "supplier",
                 "optional step", "external", "demand", "out of scope",
                 "procurement"];
  const groups = order.filter(k => kinds[k]);

  const perCol = Math.ceil(groups.length / 3);
  groups.forEach((kind, i) => {
    const col = Math.floor(i / perCol);
    const row = i % perCol;
    const x = M + col * 4.12;
    const y = 1.68 + row * 1.36;
    s.addText(kind.toUpperCase(), {
      x: x, y: y, w: 3.85, h: 0.24, isTextBox: true, margin: 0,
      fontFace: BODY, fontSize: 10, bold: true, charSpacing: 1.4, color: GOLD,
    });
    s.addText(kinds[kind].join(" · "), {
      x: x, y: y + 0.28, w: 3.85, h: 0.94, isTextBox: true, margin: 0,
      fontFace: BODY, fontSize: 11.5, color: "9DB8D4", lineSpacing: 15,
    });
  });

  s.addShape(pres.ShapeType.roundRect, {
    x: M, y: 5.66, w: CW, h: 1.08, rectRadius: 0.06,
    fill: { color: "1B3350" }, line: { color: "2A4A6B", width: 1 },
  });
  // Split the deferred list by whether it is work someone could schedule or
  // something outside engineering's reach, rather than by two numbers typed in.
  const SCHEDULABLE = ["integration", "validation", "product scope", "demand",
                       "optional step"];
  const later = plan.remaining.filter(r => SCHEDULABLE.includes(r.kind)).length;
  const blocked = plan.remaining.length - later;
  s.addText(`${t.closed} of ${t.open} closed by the ${plan.steps.length} steps. `
    + `${later} more are work someone could schedule — integration, vendor `
    + `validation, or a product decision. The last ${blocked} depend on a `
    + "supplier, a procurement decision, an OASIS event or hardware this "
    + "project cannot verify; no amount of planning moves them.", {
    x: M + 0.30, y: 5.66, w: CW - 0.60, h: 1.08, isTextBox: true, margin: 0,
    valign: "middle", fontFace: HEAD, fontSize: 13, italic: true, color: PAPER,
    lineSpacing: 19,
  });
  s.addNotes("Close on the honest boundary: the plan says what it cannot do as "
    + "clearly as what it can, and the generator refuses to build if those two "
    + "lists stop adding up to the gap matrix.");
}

pres.writeFile({ fileName: "KMIP_PKCS11_REST_KMS_Plan_Deck.pptx" })
  .then(f => {
    console.log("wrote " + f + `  (${2 + plan.steps.length * 3 + 1} slides)`);
    if (WARNINGS.length) {
      console.log("\n" + WARNINGS.length + " panel(s) too small for their content:");
      WARNINGS.forEach(w => console.log(w));
      process.exitCode = 1;
    } else {
      console.log("all panels fit their content");
    }
  });
