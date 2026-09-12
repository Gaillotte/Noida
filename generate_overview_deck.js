// KMIP on PKCS#11 — 15-slide deck.
//   node generate_overview_deck.js
//
// Every figure quoted here is one this project verified by execution: the
// operation count from the dispatcher, the test count from a run, the gap
// figures from the matrix generator, the throughput from benchmarks.

const fs = require("fs");
const pptxgen = require("pptxgenjs");

// The gap figures come from generate_kms_gap_matrix.py, which writes them out
// rather than leaving this file to copy them. They were copied once, and the
// per-domain table was wrong for as long as nobody re-added the columns.
const TOTALS = "gap_totals.json";
if (!fs.existsSync(TOTALS)) {
  console.error(`${TOTALS} is missing — run: python generate_kms_gap_matrix.py`);
  process.exit(1);
}
const gap = JSON.parse(fs.readFileSync(TOTALS, "utf8"));
const G = gap.totals;

// The roadmap used to be ten "waves" invented in this file, which stopped
// matching the delivery plan the moment the plan existed. It now reads the
// plan's own stages and steps, so the overview and the plan cannot disagree.
const PLAN = "plan_steps.json";
if (!fs.existsSync(PLAN)) {
  console.error(`${PLAN} is missing — run: python generate_rest_kms_plan.py`);
  process.exit(1);
}
const plan = JSON.parse(fs.readFileSync(PLAN, "utf8"));

// ── palette ───────────────────────────────────────────────────────────────
// Navy carries the project's existing document identity; gold is the accent,
// because a key management deck should not be two shades of the same blue.
const NAVY = "1A3A5C";
const DEEP = "102437";
const MID = "2E6DA4";
const ICE = "E8EFF6";
const PAPER = "FFFFFF";
const GOLD = "C8952B";
const INK = "16202B";
const SOFT = "4D5A68";
const FAINT = "7B8794";
const LINE = "D6DEE7";
const OK = "1F7A43";
const WARN = "9A6410";
const GAP = "B3261E";

// Stage palette and lookups for the roadmap slides, which are driven by the
// delivery plan rather than by a list kept here.
const STAGE_FILL = [NAVY, MID, "5A7184", "6B8299", GOLD];
const stageSteps = st => plan.steps.filter(p => p.stage === st);
const stageCloses = st =>
  stageSteps(st).reduce((a, p) => a + p.closes.length, 0);
const stageColour = letter =>
  STAGE_FILL[plan.stages.findIndex(s => s.letter === letter) % STAGE_FILL.length];

const HEAD = "Cambria";
const BODY = "Calibri";

const W = 13.3;
const M = 0.62;                 // side margin
const CW = W - M * 2;           // content width

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";    // must precede addSlide
pres.author = "kmip_pkcs11";
pres.title = "KMIP on PKCS#11";

// ── helpers ───────────────────────────────────────────────────────────────

function shadow() {                          // fresh object every call
  return { type: "outer", color: "8C9AA8", blur: 10, offset: 2, angle: 90, opacity: 0.22 };
}

function lightSlide(eyebrow, title) {
  const s = pres.addSlide();
  s.background = { color: PAPER };
  s.addText(eyebrow.toUpperCase(), {
    x: M, y: 0.40, w: CW, h: 0.26, isTextBox: true, margin: 0,
    fontFace: BODY, fontSize: 11.5, bold: true, charSpacing: 2.2, color: GOLD,
  });
  s.addText(title, {
    x: M, y: 0.68, w: CW, h: 0.72, isTextBox: true, margin: 0,
    fontFace: HEAD, fontSize: 34, bold: true, color: NAVY,
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
      x: M, y: 0.68, w: CW, h: 0.72, isTextBox: true, margin: 0,
      fontFace: HEAD, fontSize: 34, bold: true, color: PAPER,
    });
  }
  return s;
}

// Estimated height of a block of text, calibrated against a LibreOffice
// render. Bullets cost more than they look: the hanging indent narrows the
// usable width, and paraSpaceAfter adds up over three or four items.
function textHeight(text, size, widthIn, isBullet) {
  const usable = widthIn - (isBullet ? 0.22 : 0);
  // 0.58em is the calibrated width for body text; the 0.62 used for headings
  // is a heavier face. The line height is the part that used to be wrong: the
  // card bodies ask for 17pt spacing whatever the font size, so an 11.5pt
  // block is 17pt per line, not 15.
  const cpl = Math.max(8, (usable * 72) / (size * 0.58));
  return Math.ceil(text.length / cpl) * Math.max(size * 1.30, 17) / 72;
}

// Warn at build time when a card cannot hold what it is given, rather than
// discovering it in a render — or worse, not discovering it.
const WARNINGS = [];
function checkFit(o, ty, needed) {
  const available = o.y + o.h - ty - 0.18;
  if (needed > available + 0.02) {
    WARNINGS.push(`  card "${(o.head || o.tag || "").slice(0, 38)}" at `
      + `(${o.x.toFixed(2)}, ${o.y.toFixed(2)}) needs ${needed.toFixed(2)}" `
      + `but has ${available.toFixed(2)}" — grow h by `
      + `${(needed - available).toFixed(2)}"`);
  }
}

// A content block: tinted panel, heading, body. No edge stripes.
function card(s, o) {
  s.addShape(pres.ShapeType.roundRect, {
    x: o.x, y: o.y, w: o.w, h: o.h, rectRadius: 0.06,
    fill: { color: o.fill || ICE }, line: { color: o.line || ICE, width: 1 },
    shadow: o.flat ? undefined : shadow(),
  });
  let ty = o.y + 0.22;
  if (o.tag) {
    s.addText(o.tag.toUpperCase(), {
      x: o.x + 0.26, y: ty, w: o.w - 0.52, h: 0.22, isTextBox: true, margin: 0,
      fontFace: BODY, fontSize: 10, bold: true, charSpacing: 1.6,
      color: o.tagColor || MID,
    });
    ty += 0.30;
  }
  if (o.head) {
    const hs = o.headSize || 16;
    // 0.62em average glyph width, calibrated against the rendered deck: at
    // 0.52 a 27-character heading was predicted to fit one line and took two,
    // and the body was drawn over it.
    const cpl = Math.max(8, ((o.w - 0.52) * 72) / (hs * 0.62));
    const lines = Math.max(1, Math.ceil(o.head.length / cpl));
    const hh = Math.max(o.headH || 0, lines * hs * 1.34 / 72);
    s.addText(o.head, {
      x: o.x + 0.26, y: ty, w: o.w - 0.52, h: hh, isTextBox: true, margin: 0,
      fontFace: HEAD, fontSize: hs, bold: true, color: o.headColor || NAVY,
    });
    ty += hh + 0.08;
  }
  if (o.bullets) {
    checkFit(o, ty, o.bullets.reduce(
      (a, t) => a + textHeight(t, o.size || 13, o.w - 0.52, true) + 6 / 72, 0));
    s.addText(o.bullets.map((t, i) => ({
      text: t, options: { bullet: true, breakLine: i < o.bullets.length - 1 },
    })), {
      x: o.x + 0.26, y: ty, w: o.w - 0.52, h: o.y + o.h - ty - 0.18,
      isTextBox: true, margin: 0, valign: "top",
      fontFace: BODY, fontSize: o.size || 13, color: o.color || SOFT,
      paraSpaceAfter: 6, lineSpacing: 17,
    });
  } else if (o.body) {
    if (!o.bodyH) checkFit(o, ty, textHeight(o.body, o.size || 13, o.w - 0.52, false));
    s.addText(o.body, {
      x: o.x + 0.26, y: ty, w: o.w - 0.52,
      h: o.bodyH || (o.y + o.h - ty - 0.18),
      isTextBox: true, margin: 0, valign: "top",
      fontFace: BODY, fontSize: o.size || 13, color: o.color || SOFT, lineSpacing: 17,
    });
  }
}

// Big-number tile, used only where the figure is the point.
function stat(s, x, y, w, n, label, colour) {
  s.addText(n, {
    x: x, y: y, w: w, h: 0.66, isTextBox: true, margin: 0,
    fontFace: HEAD, fontSize: 40, bold: true, color: colour || NAVY,
  });
  s.addText(label, {
    x: x, y: y + 0.66, w: w, h: 0.44, isTextBox: true, margin: 0,
    fontFace: BODY, fontSize: 11.5, color: FAINT,
  });
}

// Anchored to the bottom of the slide and grown upward, because a footnote
// that wraps to a second line used to run off the page.
function footnote(s, text) {
  const cpl = (CW * 72) / (10 * 0.52);
  const h = Math.max(1, Math.ceil(text.length / cpl)) * 0.17;
  s.addText(text, {
    x: M, y: 7.22 - h, w: CW, h: h, isTextBox: true, margin: 0,
    fontFace: BODY, fontSize: 10, italic: true, color: FAINT,
  });
}

// A labelled box in a flow diagram.
function node(s, o) {
  s.addShape(pres.ShapeType.roundRect, {
    x: o.x, y: o.y, w: o.w, h: o.h, rectRadius: 0.06,
    fill: { color: o.fill }, line: { color: o.line || o.fill, width: 1 },
  });
  s.addText(o.label, {
    x: o.x, y: o.y, w: o.w, h: o.h, isTextBox: true, margin: 0,
    align: "center", valign: "middle",
    fontFace: BODY, fontSize: o.size || 12, bold: o.bold !== false,
    color: o.color || PAPER,
  });
  if (o.sub) {
    s.addText(o.sub, {
      x: o.x, y: o.y + o.h + 0.04, w: o.w, h: 0.26, isTextBox: true, margin: 0,
      align: "center", fontFace: BODY, fontSize: 9.5, color: FAINT,
    });
  }
}

// Block arrows, not lines. pptxgenjs will happily write a line shape with
// zero width or height, and PowerPoint renders exactly nothing for it — the
// first version of this deck had fifteen invisible connectors for that reason.
function arrowDown(s, xCentre, y, h) {
  s.addShape(pres.ShapeType.downArrow, {
    x: xCentre - 0.09, y: y, w: 0.18, h: Math.max(h, 0.18),
    fill: { color: MID }, line: { color: MID, width: 1 },
  });
}

function arrowRight(s, x, yCentre, w) {
  s.addShape(pres.ShapeType.rightArrow, {
    x: x, y: yCentre - 0.09, w: Math.max(w, 0.18), h: 0.18,
    fill: { color: MID }, line: { color: MID, width: 1 },
  });
}

// ══════════════════════════════════════════════════════════════════════════
// 1 — title
// ══════════════════════════════════════════════════════════════════════════
{
  const s = darkSlide(null, null);
  s.addText("KMIP on PKCS#11", {
    x: M, y: 1.95, w: CW, h: 1.0, isTextBox: true, margin: 0,
    fontFace: HEAD, fontSize: 54, bold: true, color: PAPER,
  });
  s.addText("From key server to key management service", {
    x: M, y: 3.00, w: CW, h: 0.5, isTextBox: true, margin: 0,
    fontFace: HEAD, fontSize: 24, color: "9DB8D4",
  });
  s.addText("Design · gap analysis · roadmap", {
    x: M, y: 3.62, w: CW, h: 0.4, isTextBox: true, margin: 0,
    fontFace: BODY, fontSize: 14, color: GOLD, charSpacing: 1.4,
  });

  const tiles = [
    ["41 / 53", "KMIP 2.1 operations"],
    ["816", "tests, live against a token"],
    [String(G.total), "features assessed vs market"],
    [String(G.outside), "gaps outside KMIP's reach"],
  ];
  tiles.forEach(([n, l], i) => {
    const x = M + i * 3.05;
    s.addText(n, {
      x: x, y: 4.75, w: 2.8, h: 0.55, isTextBox: true, margin: 0,
      fontFace: HEAD, fontSize: 30, bold: true, color: GOLD,
    });
    s.addText(l, {
      x: x, y: 5.32, w: 2.8, h: 0.5, isTextBox: true, margin: 0,
      fontFace: BODY, fontSize: 11.5, color: "9DB8D4",
    });
  });

  s.addText("kmip_pkcs11  ·  September 2026", {
    x: M, y: 6.68, w: CW, h: 0.3, isTextBox: true, margin: 0,
    fontFace: BODY, fontSize: 10.5, color: "6B8299",
  });
  s.addNotes("Framing: this deck covers what KMIP is, how this implementation "
    + "is designed on top of PKCS#11, what a full KMS needs beyond it, where "
    + "we stand against the commercial market, and the route forward. Every "
    + "number on this slide was verified by running the system.");
}

// ══════════════════════════════════════════════════════════════════════════
// 2 — what KMIP is
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("What is KMIP · 1 of 3", "One protocol for every key store");
  card(s, {
    x: M, y: 1.72, w: 5.9, h: 2.80, fill: "F7E9E8",
    tag: "Before", tagColor: GAP, head: "N vendors, N integrations",
    bullets: [
      "Every HSM and KMS exposed its own proprietary API",
      "Each database, backup tool and storage array needed bespoke work",
      "Changing vendor meant rewriting every integration",
    ],
  });
  card(s, {
    x: M + 6.2, y: 1.72, w: 5.9, h: 2.80, fill: "E2F0E7",
    tag: "With KMIP", tagColor: OK, head: "One protocol, many products",
    bullets: [
      "A client speaks KMIP once and talks to any compliant server",
      "Oracle TDE, SQL Server, NetApp, VMware and Veeam all speak it",
      "Vendor substitution becomes a configuration change",
    ],
  });
  card(s, {
    x: M, y: 4.72, w: CW, h: 2.32, fill: ICE,
    head: "What the standard actually is",
    bullets: [
      "An OASIS standard: a wire protocol plus an object model, not a product",
      "TTLV — tag, type, length, value — a compact binary encoding carried over TLS",
      "Client/server, request/response, with batching; 53 operations defined in version 2.1",
      "Governs the whole life of a key: create, use, rotate, retire, destroy, and prove what happened",
    ],
    size: 14,
  });
  s.addNotes("The point of KMIP is substitution. Before it, key management was "
    + "a lock-in surface. Note it is a protocol and object model, not a product "
    + "— a distinction that matters again three slides from now.");
}

// ══════════════════════════════════════════════════════════════════════════
// 3 — object model and lifecycle
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("What is KMIP · 2 of 3", "Managed objects, attributes, a lifecycle");

  card(s, {
    x: M, y: 1.72, w: 3.85, h: 3.22, fill: ICE,
    tag: "Object types", head: "What KMIP manages",
    bullets: ["SymmetricKey", "PublicKey / PrivateKey", "Certificate", "SecretData",
      "OpaqueObject", "SplitKey"],
    size: 12.5,
  });
  card(s, {
    x: M + 4.12, y: 1.72, w: 3.85, h: 3.22, fill: ICE,
    tag: "Attributes", head: "What describes them",
    bullets: ["Algorithm and length", "Cryptographic usage mask", "Name and custom x- attributes",
      "Links between keys", "Dates: activation, deactivation", "Owner and state"],
    size: 12.5,
  });
  card(s, {
    x: M + 8.24, y: 1.72, w: 3.86, h: 3.22, fill: "FBF3E3",
    tag: "The subtle one", tagColor: WARN, head: "Cryptoperiod",
    body: "KMIP defines no cryptoperiod attribute. The Deactivation Date is the "
      + "end of the period — so enforcing a cryptoperiod means acting on a "
      + "standard attribute, not inventing a parallel one.",
    size: 12.5,
  });

  // lifecycle flow
  s.addText("Lifecycle", {
    x: M, y: 5.12, w: 3.0, h: 0.28, isTextBox: true, margin: 0,
    fontFace: BODY, fontSize: 10, bold: true, charSpacing: 1.6, color: MID,
  });
  const boxes = [
    ["Pre-Active", MID], ["Active", NAVY], ["Deactivated", "5A7184"], ["Destroyed", "3B4A58"],
  ];
  boxes.forEach(([label, fill], i) => {
    const x = M + i * 2.42;
    node(s, { x: x, y: 5.44, w: 2.08, h: 0.62, fill: fill, label: label, size: 13 });
    if (i < boxes.length - 1) arrowRight(s, x + 2.11, 5.75, 0.28);
  });
  // Set apart from the chain, with no arrow into it: Compromised is entered
  // from any live state, not reached by walking the sequence.
  node(s, {
    x: M + 4 * 2.42 + 0.34, y: 5.44, w: 2.08, h: 0.62, fill: GAP,
    label: "Compromised", size: 13,
  });
  s.addText("from any live state", {
    x: M + 4 * 2.42 + 0.34, y: 6.14, w: 2.08, h: 0.26, isTextBox: true, margin: 0,
    align: "center", fontFace: BODY, fontSize: 9.5, color: FAINT,
  });

  s.addText("Deactivated keys may still decrypt and verify — retiring a key must not strand the data encrypted under it.", {
    x: M, y: 6.52, w: CW, h: 0.36, isTextBox: true, margin: 0,
    fontFace: BODY, fontSize: 13, italic: true, color: NAVY,
  });
  s.addNotes("The Deactivated rule is the one people get wrong: a retired key "
    + "keeps Decrypt and Verify. If it did not, retiring a key would destroy "
    + "access to everything it ever protected.");
}

// ══════════════════════════════════════════════════════════════════════════
// 4 — what KMIP leaves out
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("What is KMIP · 3 of 3", "What the standard deliberately leaves out");

  card(s, {
    x: M, y: 1.72, w: 5.9, h: 2.88, fill: "E2F0E7",
    tag: "KMIP defines", tagColor: OK, head: "Keys, and operations on keys",
    bullets: [
      "Managed objects and their attributes",
      "The lifecycle state machine",
      "Cryptographic operations: encrypt, sign, MAC, derive, wrap",
      "Search over objects (Locate), batching, version negotiation",
    ],
  });
  card(s, {
    x: M + 6.2, y: 1.72, w: 5.9, h: 2.88, fill: "F7E9E8",
    tag: "KMIP does not define", tagColor: GAP, head: "Everything around them",
    bullets: [
      "Identities, roles, groups, grants — no user management at all",
      "Any HTTP or REST binding: TTLV over TCP only",
      "Tenancy, quotas, reporting, dashboards",
      "Administrative operations of any kind",
    ],
  });

  card(s, {
    x: M, y: 4.82, w: 7.5, h: 2.12, fill: NAVY, flat: true,
    head: "The consequence", headColor: PAPER,
    body: "Every commercial KMS bolts an administrative plane onto its KMIP server. "
      + "A KMIP layer is an interoperability surface — it is not, by itself, a product.",
    color: "C9DAEA", size: 13.5,
  });
  card(s, {
    x: M + 7.8, y: 4.82, w: 4.3, h: 2.12, fill: "FBF3E3",
    tag: "Versions", tagColor: WARN, head: "2.1 → 3.0",
    body: "2.1 (2019) is what this project implements. 3.0 CSD02 (May 2026) adds "
      + "ML-KEM, ML-DSA, SLH-DSA and Encapsulate/Decapsulate.",
    size: 12,
  });
  s.addNotes("This slide is the hinge of the deck. Everything we later call a "
    + "gap 'outside KMIP' traces back to the right-hand column — it is not that "
    + "we have not implemented those things, it is that the protocol has no way "
    + "to express them.");
}

// ══════════════════════════════════════════════════════════════════════════
// 5 — architecture
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("The design · 1 of 3", "KMIP 2.1 on a PKCS#11 token");

  const cx = 4.35, cw = 4.6;
  const layers = [
    ["KMIP clients", "6B8299", "Oracle TDE · VMware · NetApp · scripts"],
    ["TLS 1.2+  ·  TCP 5696", MID, "enforced by default; mTLS optional"],
    ["Server  ·  thread per connection", NAVY, "request caps, handshake timeout"],
    ["Dispatcher  ·  41 operations", NAVY, "authorization · dual control · audit · metrics"],
    ["40 operation handlers", MID, "one file per KMIP operation"],
    ["PKCS#11 shim", GOLD, "the only file that imports pkcs11"],
    ["Token  ·  SoftHSM2 2.7.0", DEEP, "79 mechanisms · keys never leave"],
  ];
  let y = 1.66;
  layers.forEach(([label, fill, sub], i) => {
    node(s, { x: cx, y: y, w: cw, h: 0.52, fill: fill, label: label, size: 12.5,
      color: fill === GOLD ? DEEP : PAPER });
    s.addText(sub, {
      x: cx + cw + 0.18, y: y + 0.08, w: 3.55, h: 0.36, isTextBox: true, margin: 0,
      fontFace: BODY, fontSize: 10.5, color: FAINT,
    });
    if (i < layers.length - 1) arrowDown(s, cx + cw / 2, y + 0.53, 0.20);
    y += 0.745;
  });

  card(s, {
    x: M, y: 1.66, w: 3.5, h: 2.35, fill: ICE,
    tag: "Alongside", head: "Metadata store",
    bullets: ["SQLite, WAL mode", "KMIP attributes and state", "Identities, roles, grants",
      "Hash-chained audit log"],
    size: 12,
  });
  card(s, {
    x: M, y: 4.20, w: 3.5, h: 2.52, fill: "FBF3E3",
    tag: "Swap point", tagColor: WARN, head: "Any PKCS#11 HSM",
    body: "One file imports the binding. Pointing it at validated hardware needs "
      + "no change above the shim — the capability probe reports whatever that "
      + "token supports.",
    size: 12,
  });
  s.addNotes("The shape to remember: everything above the shim is protocol and "
    + "policy; everything below is the token. That boundary is what makes a "
    + "validated-HSM swap a procurement decision rather than a rewrite.");
}

// ══════════════════════════════════════════════════════════════════════════
// 6 — two stores
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("The design · 2 of 3", "Two stores, one matched pair");

  card(s, {
    x: M, y: 1.72, w: 5.9, h: 2.5, fill: DEEP, flat: true,
    tag: "In the token", tagColor: GOLD, head: "Key material", headColor: PAPER,
    bullets: [
      "Generated inside the HSM, never leaves it",
      "Non-extractable; the usage mask is enforced by the token",
      "Referenced from the database only by CKA_ID",
    ],
    color: "AFC4D8",
  });
  card(s, {
    x: M + 6.2, y: 1.72, w: 5.9, h: 2.5, fill: ICE,
    tag: "In the database", head: "Everything KMIP needs that PKCS#11 has no room for",
    headSize: 15, headH: 0.5,
    bullets: [
      "Attributes, state, dates, names, links",
      "Owner, grants, groups, role allowlists, approvals",
      "The tamper-evident audit chain",
    ],
  });

  card(s, {
    x: M, y: 4.44, w: 7.5, h: 2.18, fill: "FBF3E3",
    tag: "The exception", tagColor: WARN,
    head: "Objects with no PKCS#11 representation",
    body: "SecretData, OpaqueObject and SplitKey shares have no token object behind "
      + "them, so their bytes would sit in the database in the clear. They are sealed "
      + "with AES-256-GCM under a master key that is generated on, and never leaves, "
      + "the HSM.",
    size: 13,
  });
  card(s, {
    x: M + 7.8, y: 4.44, w: 4.3, h: 2.18, fill: NAVY, flat: true,
    head: "Back them up together", headColor: PAPER,
    body: "A database restored beside a different token is not a degraded backup. "
      + "It is unreadable.",
    color: "C9DAEA", size: 13,
  });
  s.addNotes("The matched-pair point is the one operators get wrong. Restore "
    + "refuses a mismatched token for exactly this reason, and backup verification "
    + "proves a stored secret actually decrypts rather than assuming it.");
}

// ══════════════════════════════════════════════════════════════════════════
// 7 — cross-cutting design
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("The design · 3 of 3", "Where authorization, approval and audit live");

  // pipeline
  const steps = [
    ["Request", "6B8299"], ["Role allowlist", MID], ["Dual control", GOLD],
    ["Handler", NAVY], ["Audit + metrics", "3B4A58"],
  ];
  steps.forEach(([label, fill], i) => {
    const x = M + i * 2.47;
    node(s, { x: x, y: 1.74, w: 2.16, h: 0.66, fill: fill, label: label, size: 12,
      color: fill === GOLD ? DEEP : PAPER });
    if (i < steps.length - 1) arrowRight(s, x + 2.19, 2.07, 0.26);
  });
  s.addText("The dispatcher wraps every one of the 41 operations in this pipeline.", {
    x: M, y: 2.52, w: CW, h: 0.32, isTextBox: true, margin: 0,
    fontFace: BODY, fontSize: 13, italic: true, color: NAVY,
  });

  card(s, {
    x: M, y: 3.02, w: 3.85, h: 3.02, fill: "F7E9E8",
    tag: "The hazard", tagColor: GAP, head: "Bypass",
    body: "Anything that calls the store directly skips all four checks. Add a "
      + "second transport carelessly and dual control silently stops applying to "
      + "it — which is why a shared service layer must come before a REST API.",
    size: 12.5,
  });
  card(s, {
    x: M + 4.12, y: 3.02, w: 3.85, h: 3.02, fill: ICE,
    tag: "Concurrency", head: "One session per process",
    body: "A PKCS#11 session pool was built, tested, and reproducibly segfaulted: "
      + "python-pkcs11 calls C_Initialize(NULL), so the library's own thread safety "
      + "is never enabled. Scale with pre-fork workers, never with threads. This is "
      + "permanent design, not a stopgap.",
    size: 12.5,
  });
  card(s, {
    x: M + 8.24, y: 3.02, w: 3.86, h: 3.02, fill: ICE,
    tag: "Capability probe", head: "Ask the token, don't assume",
    body: "The shim reads the token's real mechanism list at startup and gates every "
      + "dispatch on it. An unsupported algorithm fails cleanly and by name, instead "
      + "of surfacing a raw PKCS#11 error from deep inside an operation.",
    size: 12.5,
  });
  s.addNotes("If one slide from this section survives, it should be this one. "
    + "The left card is the design constraint for the next section; the middle "
    + "card is the answer to 'why not just add threads'.");
}

// ══════════════════════════════════════════════════════════════════════════
// 8 — why REST
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("A full KMS · 1 of 2", "Why a REST layer is not optional");

  const reasons = [
    ["01", "The operations do not exist",
      "Identities, roles, grants, approvals, cryptoperiods, audit search, backups — KMIP defines none of them."],
    ["02", "A browser cannot speak TTLV",
      "Binary over raw TCP. A browser has fetch and WebSocket. Something must translate — and that translator is the API."],
    ["03", "The auth models differ",
      "KMIP re-authenticates every request from a header credential. A console needs login, session, idle timeout, CSRF, revocation."],
    ["04", "The read shapes are wrong",
      "Locate returns bare identifiers with no paging, sort or count. A console table becomes N+1 round trips."],
    ["05", "Not everything is object-centric",
      "Approval queues, audit search, expiry reports, chain verification, health. None is an operation on a managed object."],
  ];
  // Three columns, not five: at 2.14" wide the reasons wrapped to nine lines
  // each and read as a wall. The conclusion takes the sixth grid slot.
  reasons.forEach(([n, head, body], i) => {
    const x = M + (i % 3) * 4.12;
    const y = 1.70 + Math.floor(i / 3) * 2.42;
    card(s, { x: x, y: y, w: 3.85, h: 2.24, fill: ICE, tag: n, head: head,
      headSize: 14, headH: 0.34, body: body, size: 12 });
  });
  card(s, {
    x: M + 2 * 4.12, y: 1.70 + 2.42, w: 3.85, h: 2.66, fill: NAVY, flat: true,
    head: "The division of labour", headColor: PAPER, headSize: 15,
    body: "KMIP stays the data plane — machines creating and using keys. REST becomes "
      + "the control plane — people and CI administering the service. Duplicating crypto "
      + "operations across both gives you two paths to Destroy, and two authorization "
      + "implementations to keep in step.",
    color: "C9DAEA", size: 11.5,
  });
  s.addNotes("The last card is the design discipline. It is tempting to expose "
    + "encrypt/decrypt over REST because it is easy; that is how products end up "
    + "with divergent authorization on two paths to the same key.");
}

// ══════════════════════════════════════════════════════════════════════════
// 9 — target architecture
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("A full KMS · 2 of 2", "One service layer, two transports");

  node(s, { x: M, y: 1.70, w: 5.55, h: 0.58, fill: "6B8299",
    label: "Web console  ·  CLI  ·  CI and scripts", size: 12.5 });
  node(s, { x: M + 6.55, y: 1.70, w: 5.55, h: 0.58, fill: "6B8299",
    label: "KMIP clients  ·  databases, storage, backup", size: 12.5 });

  arrowDown(s, M + 2.77, 2.30, 0.26);
  arrowDown(s, M + 9.32, 2.30, 0.26);

  node(s, { x: M, y: 2.60, w: 5.55, h: 0.72, fill: GOLD, color: DEEP,
    label: "REST admin API  ·  TLS, sessions, tokens", size: 12.5 });
  node(s, { x: M + 6.55, y: 2.60, w: 5.55, h: 0.72, fill: MID,
    label: "KMIP server  ·  TTLV over TLS", size: 12.5 });

  arrowDown(s, M + 2.77, 3.34, 0.30);
  arrowDown(s, M + 9.32, 3.34, 0.30);

  node(s, { x: M, y: 3.70, w: CW, h: 0.66, fill: NAVY,
    label: "Service layer  —  role allowlist · dual control · audit · metrics", size: 14 });
  s.addText("every call, both transports, one implementation", {
    x: M, y: 4.40, w: CW, h: 0.26, isTextBox: true, margin: 0,
    align: "center", fontFace: BODY, fontSize: 11, italic: true, color: FAINT,
  });

  // One arrow per destination: a single centre arrow pointed at the gap
  // between the two boxes and connected neither.
  arrowDown(s, M + 2.77, 4.72, 0.30);
  arrowDown(s, M + 9.32, 4.72, 0.30);
  node(s, { x: M, y: 5.10, w: 5.55, h: 0.58, fill: DEEP,
    label: "Operation handlers  →  PKCS#11 token", size: 12.5 });
  node(s, { x: M + 6.55, y: 5.10, w: 5.55, h: 0.58, fill: DEEP,
    label: "Metadata store  ·  audit chain", size: 12.5 });

  card(s, {
    x: M, y: 5.90, w: 12.06, h: 1.18, fill: ICE, flat: true,
    body: "Endpoints:  sessions and identity  ·  keys and lifecycle  ·  grants, groups, roles  ·  "
      + "approval queue  ·  audit search  ·  cryptoperiod and expiry reports  ·  backups.        "
      + "No encrypt, decrypt or sign over REST in v1 — deliberately.",
    size: 12.5, color: NAVY,
  });
  s.addNotes("Read this as the sequencing argument: the service layer in the "
    + "middle is the first thing to build, and it can be built and shipped "
    + "before any REST endpoint exists, as a pure refactor proven by the "
    + "existing test suite.");
}

// ══════════════════════════════════════════════════════════════════════════
// 10 — gap scorecard
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("Gap analysis · 1 of 3",
    `${G.total} features the market expects`);

  stat(s, M, 1.66, 2.9, String(G.full), "covered", OK);
  stat(s, M + 3.02, 1.66, 2.9, String(G.partial), "partial", WARN);
  stat(s, M + 6.04, 1.66, 2.9, String(G.gap), "not covered", GAP);
  stat(s, M + 9.06, 1.66, 3.0, String(G.outside), "cannot be closed in KMIP", MID);

  const rows = gap.domains.map(d =>
    [d.name, String(d.count), String(d.full), String(d.partial), String(d.gap)]);
  rows.push(["TOTAL", String(G.total), String(G.full), String(G.partial),
             String(G.gap)]);

  // The figures are read, not copied, but a domain that stopped adding up would
  // still print. Check it here rather than in a reader's head.
  ["count", "full", "partial", "gap"].forEach(k => {
    const summed = gap.domains.reduce((a, d) => a + d[k], 0);
    const expected = k === "count" ? G.total : G[k];
    if (summed !== expected) {
      throw new Error(`gap_totals.json: domain ${k} sums to ${summed}, total says ${expected}`);
    }
  });
  s.addTable(
    [[
      { text: "Domain", options: { bold: true, color: PAPER, fill: { color: NAVY } } },
      { text: "Features", options: { bold: true, color: PAPER, fill: { color: NAVY }, align: "center" } },
      { text: "Covered", options: { bold: true, color: PAPER, fill: { color: NAVY }, align: "center" } },
      { text: "Partial", options: { bold: true, color: PAPER, fill: { color: NAVY }, align: "center" } },
      { text: "Gap", options: { bold: true, color: PAPER, fill: { color: NAVY }, align: "center" } },
    ]].concat(rows.map((r, i) => [
      { text: r[0], options: { color: INK } },
      { text: r[1], options: { align: "center", color: SOFT } },
      { text: r[2], options: { align: "center", color: OK, bold: true } },
      { text: r[3], options: { align: "center", color: WARN } },
      { text: r[4], options: { align: "center", color: GAP, bold: true } },
    ].map(c => Object.assign(c, { options: Object.assign(c.options, { fill: { color: i % 2 ? PAPER : ICE } }) })))),
    {
      x: M, y: 3.30, w: CW, colW: [5.26, 1.7, 1.7, 1.7, 1.7],
      fontFace: BODY, fontSize: 12, border: { pt: 0.5, color: LINE },
      rowH: 0.34, valign: "middle",
    }
  );
  footnote(s, "Requirements drawn from Thales CipherTrust, Entrust KeyControl, Fortanix DSM, "
    + "Utimaco ESKM, Bloombase KeyCastle, Cosmian/Eviden, Securosys CyberVault, HashiCorp Vault "
    + "and the cloud KMS services, plus NIST SP 800-57 and SP 800-152.");
  s.addNotes(`The fourth statistic is the one to dwell on: ${G.outside} of the shortfalls `
    + "are not backlog items for the KMIP layer at all. Integration and identity "
    + "are where the concentration of gaps sits.");
}

// ══════════════════════════════════════════════════════════════════════════
// 11 — what holds up
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("Gap analysis · 2 of 3", "What holds up");

  const solid = [
    ["Cryptographic core", "41 of 53 operations, capability-probed against the token; keys never leave the HSM."],
    ["Lifecycle and governance", "State machine, cryptoperiod scheduler, scheduled rotation, dual control on Destroy and Export."],
    ["Access control", "Per-identity scrypt credentials, admin role, ownership, per-object grants, groups, per-role allowlists."],
    ["Audit", "Append-only two ways — triggers and a SHA-256 chain — with retention and a verifier that names the broken row."],
    ["Data at rest", "AES-256-GCM envelopes under a non-extractable HSM master key, with rotation."],
    ["Backup and recovery", "Online snapshot with token pairing, and a restore that proves a stored secret decrypts."],
  ];
  solid.forEach(([head, body], i) => {
    const x = M + (i % 3) * 4.12;
    const y = 1.70 + Math.floor(i / 3) * 2.34;
    card(s, { x: x, y: y, w: 3.85, h: 2.10, fill: "E2F0E7",
      head: head, headSize: 15, headH: 0.34, body: body, size: 12 });
  });

  card(s, {
    x: M, y: 6.20, w: CW, h: 0.98, fill: NAVY, flat: true,
    body: "Several of these are done properly rather than nominally: the restore proves a secret "
      + "decrypts rather than assuming it, and dual control is enforced in the store, so the "
      + "requester cannot self-approve however the approval arrives.",
    color: "C9DAEA", size: 12.5,
  });
  s.addNotes("Evidence for all of it: 816 tests running live against a real "
    + "SoftHSM2 token rather than mocks, built up across phases 0 to 5.");
}

// ══════════════════════════════════════════════════════════════════════════
// 12 — the gaps that matter
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("Gap analysis · 3 of 3", "Where it falls short of a product");

  // Five columns, ten cards. Kept to one short sentence each: this slide is a
  // scan, and the gap matrix is where the detail lives.
  const gaps = [
    ["No REST API or console", "Reporting, the console, self-service and encryption as a service are all clients of it.", GAP],
    ["No multi-tenancy", "Names, searches, quotas and audit are global. Isolation means one deployment per tenant.", GAP],
    ["SQLite only", "No clustering, replication or DR — the storage engine blocks them, not the protocol.", GAP],
    ["No rate limiting", "The listener takes a backlog of 16 with no throttle. Flagged in the first review.", GAP],
    ["Policy lives in the server", "Dual control is enforced here, not inside the token. Own the server and you own the policy.", GAP],
    ["Scaling stops at ~1.5×", "Pre-fork workers help, but every audited operation serialises on one write lock.", WARN],
    ["No SIEM export or anchor", "Auditors ask for both first. A consistent rewrite of the local log leaves no trace.", WARN],
    ["Starts unsealed by one PIN", "The store needs the token, so a stolen database is inert. But one PIN holder is the ceremony.", WARN],
    ["Not FIPS or CC validated", "Belongs to the token, not the code. Procurement, not engineering.", MID],
    ["No post-quantum", "Needs both a PQC token and KMIP 3.0. Neither has shipped in a release.", MID],
  ];
  const GCOLS = 5;
  const GGAP = 0.23;
  const gw = (CW - (GCOLS - 1) * GGAP) / GCOLS;
  gaps.forEach(([head, body, colour], i) => {
    const x = M + (i % GCOLS) * (gw + GGAP);
    const y = 1.70 + Math.floor(i / GCOLS) * 2.60;
    card(s, {
      x: x, y: y, w: gw, h: 2.44,
      fill: colour === GAP ? "F7E9E8" : (colour === WARN ? "FBF3E3" : ICE),
      head: head, headSize: 13, headH: 0.52, headColor: colour === MID ? NAVY : colour,
      body: body, size: 11,
    });
  });
  footnote(s, "Red: absent and material.   Amber: present with a named limit.   Blue: outside this codebase's control.");
  s.addNotes("Group them: the red five are engineering we could start tomorrow "
    + "— except the fifth, which is a reason to prefer a token that binds policy "
    + "to the key. The amber three are trade-offs with known costs. The blue two "
    + "depend on suppliers rather than on us. The last two red and amber cards "
    + "came from reading Securosys and HashiCorp Vault in September.");
}

// ══════════════════════════════════════════════════════════════════════════
// 13 — roadmap overview: the plan's stages, read from plan_steps.json
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("Roadmap · 1 of 3",
    `${plan.stages.length} stages, in dependency order`);

  // Nine stages will not sit in a row: at 2.16" wide the blocks overlap
  // their own gaps. A grid, with each stage's step range and feature count.
  const COLS = 3, GX = 0.26, GY = 0.16;
  const bw = (CW - (COLS - 1) * GX) / COLS;
  const bh = 1.12;
  plan.stages.forEach((stage, i) => {
    const x = M + (i % COLS) * (bw + GX);
    const y = 1.62 + Math.floor(i / COLS) * (bh + GY);
    const steps = stageSteps(stage.letter);
    const gated = steps.filter(p => p.depends).length;
    const allGated = gated === steps.length;
    // Light cards with a coloured spine, matching the plan deck's own
    // at-a-glance. Nine filled cards cycling a five-colour palette put gold
    // stats on mid-grey and repeated A's colour on F.
    s.addShape(pres.ShapeType.roundRect, {
      x: x, y: y, w: bw, h: bh, rectRadius: 0.06,
      fill: { color: ICE }, line: { color: ICE, width: 1 }, shadow: shadow(),
    });
    s.addShape(pres.ShapeType.rect, {
      x: x, y: y, w: 0.10, h: bh,
      fill: { color: allGated ? WARN : NAVY },
      line: { color: allGated ? WARN : NAVY, width: 1 },
    });
    const NS = 13;
    const cpl = Math.max(6, ((bw - 1.10) * 72) / (NS * 0.62));
    const nameH = Math.ceil(stage.name.length / cpl) * NS * 1.34 / 72;
    s.addText(stage.letter, {
      x: x + 0.20, y: y + 0.14, w: 0.58, h: 0.62, isTextBox: true, margin: 0,
      align: "center", fontFace: HEAD, fontSize: 30, bold: true,
      color: allGated ? WARN : MID,
    });
    let ty = y + 0.18;
    s.addText(stage.name, {
      x: x + 0.88, y: ty, w: bw - 1.06, h: nameH, isTextBox: true, margin: 0,
      fontFace: HEAD, fontSize: NS, bold: true, color: NAVY,
    });
    ty += nameH + 0.04;
    s.addText(`Steps ${steps[0].n}–${steps[steps.length - 1].n}  ·  closes `
      + `${stageCloses(stage.letter)}` + (gated ? `  ·  ${gated} gated` : ""), {
      x: x + 0.88, y: ty, w: bw - 1.06, h: 0.22, isTextBox: true, margin: 0,
      fontFace: BODY, fontSize: 9.5, bold: true, color: gated ? WARN : OK,
    });
  });

  card(s, {
    x: M, y: 5.44, w: 5.9, h: 1.40, fill: ICE, flat: true,
    head: "Routed is not schedulable",
    body: `All ${plan.totals.open} open features have a step. `
      + `${plan.totals.steps - plan.totals.gated} of ${plan.totals.steps} `
      + `steps can start now; ${plan.totals.gated} wait on hardware, a `
      + "product or an external event.",
    size: 11, headSize: 14, headH: 0.30,
  });
  card(s, {
    x: M + 6.2, y: 5.44, w: 5.9, h: 1.40, fill: "FBF3E3", flat: true,
    head: "Every step has a demonstrable gate",
    body: "A condition someone can watch you meet, not a checklist. "
      + "Demonstrated, not written.",
    size: 11, headSize: 14, headH: 0.30,
  });
  s.addNotes(`${G.total} assessed features, ${plan.totals.open} short of full `
    + `coverage; these ${plan.steps.length} steps close ${plan.totals.closed}. `
    + "Phases 0 to 5 used exactly this structure and all six gates were met, so "
    + "the format is proven on this codebase rather than borrowed.");
}

// ══════════════════════════════════════════════════════════════════════════
// 14 — every step, in one view
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("Roadmap · 2 of 3", `All ${plan.steps.length} steps`);

  // Two columns held fourteen. Twenty-six need three.
  const NCOL = 3;
  const perCol = Math.ceil(plan.steps.length / NCOL);
  const colGap = 0.26;
  const colW = (CW - (NCOL - 1) * colGap) / NCOL;
  const rowH = 0.46;
  const pitchY = 0.525;
  plan.steps.forEach((st, i) => {
    const x = M + Math.floor(i / perCol) * (colW + colGap);
    const y = 1.58 + (i % perCol) * pitchY;
    const colour = stageColour(st.stage);
    // A coloured spine rather than a repeated stage label: the footnote names
    // the letters, and the rows stay one line each.
    s.addShape(pres.ShapeType.rect, {
      x: x, y: y, w: 0.09, h: rowH,
      fill: { color: colour }, line: { color: colour, width: 1 },
    });
    s.addShape(pres.ShapeType.roundRect, {
      x: x + 0.09, y: y, w: colW - 0.09, h: rowH, rectRadius: 0.04,
      fill: { color: ICE }, line: { color: ICE, width: 1 },
    });
    s.addText(String(st.n), {
      x: x + 0.16, y: y, w: 0.34, h: rowH, isTextBox: true, margin: 0,
      valign: "middle", fontFace: HEAD, fontSize: 12, bold: true, color: GOLD,
    });
    s.addText((st.depends ? "⧗ " : "") + st.title, {
      x: x + 0.54, y: y, w: colW - 1.20, h: rowH, isTextBox: true, margin: 0,
      valign: "middle", fontFace: BODY, fontSize: 9.5,
      color: st.depends ? WARN : NAVY,
    });
    s.addText(st.closes.length ? `+${st.closes.length}` : "—", {
      x: x + colW - 0.62, y: y, w: 0.46, h: rowH, isTextBox: true, margin: 0,
      align: "right", valign: "middle", fontFace: BODY, fontSize: 9.5,
      bold: true, color: st.closes.length ? OK : FAINT,
    });
  });

  // Names as written: lower-casing turned "The REST control plane" into
  // "the rest control plane".
  const legend = plan.stages
    .map(st => `${st.letter} ${st.name}`).join("   ·   ");
  footnote(s, `${legend}\n+n is the gap-matrix features that step closes.  `
    + `⧗ marks a step that cannot start until something outside this project happens.`);
  s.addNotes("Step 1 is the one to insist on. It ships no feature and removes "
    + "the risk that every later endpoint quietly bypasses dual control. If the "
    + "plan gets cut, cut from the end, not from the front.");
}

// ══════════════════════════════════════════════════════════════════════════
// 15 — what the plan waits on (dark closer)
// ══════════════════════════════════════════════════════════════════════════
{
  const s = darkSlide("Roadmap · 3 of 3", "What the plan waits on");

  const gated = plan.steps.filter(p => p.depends);
  const perCol = Math.ceil(gated.length / 2);
  gated.forEach((step, i) => {
    const x = M + (i < perCol ? 0 : 6.16);
    const y = 1.62 + (i % perCol) * 0.88;
    s.addShape(pres.ShapeType.roundRect, {
      x: x, y: y, w: 0.54, h: 0.54, rectRadius: 0.06,
      fill: { color: GOLD }, line: { color: GOLD, width: 1 },
    });
    s.addText(String(step.n), {
      x: x, y: y, w: 0.54, h: 0.54, isTextBox: true, margin: 0,
      align: "center", valign: "middle", fontFace: HEAD, fontSize: 16,
      bold: true, color: DEEP,
    });
    s.addText(step.title, {
      x: x + 0.70, y: y - 0.04, w: 5.2, h: 0.28, isTextBox: true, margin: 0,
      fontFace: HEAD, fontSize: 13, bold: true, color: PAPER,
    });
    s.addText(step.depends, {
      x: x + 0.70, y: y + 0.24, w: 5.2, h: 0.58, isTextBox: true, margin: 0,
      fontFace: BODY, fontSize: 10, color: "9DB8D4", lineSpacing: 12.5,
    });
  });

  s.addShape(pres.ShapeType.roundRect, {
    x: M, y: 5.66, w: CW, h: 1.20, rectRadius: 0.06,
    fill: { color: "1B3350" }, line: { color: "2A4A6B", width: 1 },
  });
  s.addText(`Every one of the ${plan.totals.open} open features now has a `
    + `step — none is deferred. That is not the same as a plan that can be `
    + `executed end to end: ${plan.totals.gated} of ${plan.totals.steps} `
    + "steps wait on hardware to buy, a product to deploy, or an event "
    + "somebody else runs. Two are worth a second look — validated hardware "
    + "is the largest security gain here and among the smallest in code, and "
    + "post-quantum needs only a capable token, because the capability probe "
    + "already gates on what the token advertises.", {
    x: M + 0.30, y: 5.66, w: CW - 0.60, h: 1.20, isTextBox: true, margin: 0,
    valign: "middle", fontFace: HEAD, fontSize: 12.5, italic: true,
    color: PAPER, lineSpacing: 18,
  });
  s.addNotes("Close on the boundary rather than the feature list. The "
    + "previous revision deferred sixteen features; this one routes all of "
    + "them and names what each blocked step is waiting for instead. That is "
    + "a more useful statement and a more demanding one.");
}

pres.writeFile({ fileName: "KMIP_PKCS11_Overview_Deck.pptx" })
  .then(f => {
    console.log("wrote " + f);
    if (WARNINGS.length) {
      console.log("\n" + WARNINGS.length + " card(s) too small for their content:");
      WARNINGS.forEach(w => console.log(w));
    } else {
      console.log("all cards fit their content");
    }
  });
