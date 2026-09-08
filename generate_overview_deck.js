// KMIP on PKCS#11 — 15-slide deck.
//   node generate_overview_deck.js
//
// Every figure quoted here is one this project verified by execution: the
// operation count from the dispatcher, the test count from a run, the gap
// figures from the matrix generator, the throughput from benchmarks.

const pptxgen = require("pptxgenjs");

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
  const cpl = Math.max(8, (usable * 72) / (size * 0.58));
  return Math.ceil(text.length / cpl) * size * 1.30 / 72;
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

function footnote(s, text) {
  s.addText(text, {
    x: M, y: 6.92, w: CW, h: 0.30, isTextBox: true, margin: 0,
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
    ["74", "features assessed vs market"],
    ["19", "gaps outside KMIP's reach"],
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
    x: M, y: 4.82, w: 7.5, h: 2.00, fill: NAVY, flat: true,
    head: "The consequence", headColor: PAPER,
    body: "Every commercial KMS bolts an administrative plane onto its KMIP server. "
      + "A KMIP layer is an interoperability surface — it is not, by itself, a product.",
    color: "C9DAEA", size: 13.5,
  });
  card(s, {
    x: M + 7.8, y: 4.82, w: 4.3, h: 2.00, fill: "FBF3E3",
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
    x: M, y: 4.20, w: 3.5, h: 2.44, fill: "FBF3E3",
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
    x: M + 2 * 4.12, y: 1.70 + 2.42, w: 3.85, h: 2.52, fill: NAVY, flat: true,
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
    x: M, y: 5.90, w: 12.06, h: 1.08, fill: ICE, flat: true,
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
  const s = lightSlide("Gap analysis · 1 of 3", "74 features the market expects");

  stat(s, M, 1.66, 2.9, "32", "covered", OK);
  stat(s, M + 3.02, 1.66, 2.9, "16", "partial", WARN);
  stat(s, M + 6.04, 1.66, 2.9, "26", "not covered", GAP);
  stat(s, M + 9.06, 1.66, 3.0, "19", "cannot be closed in KMIP", MID);

  // Straight from generate_kms_gap_matrix.py — these columns sum to 32/16/26.
  const rows = [
    ["Key lifecycle and cryptography", "14", "8", "4", "2"],
    ["Protocol and ecosystem integration", "12", "1", "4", "7"],
    ["Identity and access control", "13", "6", "1", "6"],
    ["Audit, compliance and assurance", "10", "3", "2", "5"],
    ["Availability, scale and recovery", "10", "3", "3", "4"],
    ["Operations and observability", "8", "5", "1", "2"],
    ["Platform hardening", "7", "6", "1", "0"],
    ["TOTAL", "74", "32", "16", "26"],
  ];
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
    + "Utimaco ESKM and the cloud KMS services, plus NIST SP 800-57 and SP 800-152.");
  s.addNotes("The fourth statistic is the one to dwell on: 19 of the shortfalls "
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

  const gaps = [
    ["No REST API or console", "Highest leverage: reporting, self-service, the console and most integrations are all clients of an API that does not exist.", GAP],
    ["No multi-tenancy", "Names, searches, quotas and audit are global. Isolation today means one deployment per tenant.", GAP],
    ["SQLite only", "No clustering, replication or DR — and the storage engine, not the protocol, is what blocks them.", GAP],
    ["No connection or rate limiting", "The listener takes a backlog of 16 with no throttle. Flagged in the original review and never fixed.", GAP],
    ["Scaling stops at ~1.5×", "Pre-fork workers help, but every audited operation serialises on one write lock. The price of tamper-evidence.", WARN],
    ["No SIEM export, no external anchor", "Auditors ask for both first. A consistent rewrite of the local log leaves no trace.", WARN],
    ["Not FIPS or CC validated", "Belongs to the token, not the code. Procurement, not engineering.", MID],
    ["No post-quantum", "Needs both a PQC token and KMIP 3.0. Neither has shipped in a release yet.", MID],
  ];
  gaps.forEach(([head, body, colour], i) => {
    const x = M + (i % 4) * 3.09;
    const y = 1.70 + Math.floor(i / 4) * 2.42;
    card(s, {
      x: x, y: y, w: 2.86, h: 2.20,
      fill: colour === GAP ? "F7E9E8" : (colour === WARN ? "FBF3E3" : ICE),
      head: head, headSize: 14, headH: 0.62, headColor: colour === MID ? NAVY : colour,
      body: body, size: 11.5,
    });
  });
  footnote(s, "Red: absent and material.   Amber: present with a named limit.   Blue: outside this codebase's control.");
  s.addNotes("Group them: the first four are engineering we could start "
    + "tomorrow, the middle two are design trade-offs with known costs, and the "
    + "last two depend on suppliers rather than on us.");
}

// ══════════════════════════════════════════════════════════════════════════
// 13 — roadmap overview
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("Roadmap · 1 of 3", "Five waves, in dependency order");

  const waves = [
    ["6", "Control plane", "Service layer, REST API, console", NAVY],
    ["7", "Enterprise fit", "Directory identity, service accounts, SIEM, rate limiting", MID],
    ["8", "Scale", "PostgreSQL, HA clustering, DR, HSM failover", "5A7184"],
    ["9", "Tenancy", "Namespaces, quotas, per-tenant audit", "6B8299"],
    ["10", "Compliance", "Validated token, KMIP 3.0, post-quantum", GOLD],
  ];
  waves.forEach(([n, name, detail, fill], i) => {
    const x = M + i * 2.47;
    s.addShape(pres.ShapeType.roundRect, {
      x: x, y: 1.74, w: 2.16, h: 2.10, rectRadius: 0.06,
      fill: { color: fill }, line: { color: fill, width: 1 }, shadow: shadow(),
    });
    s.addText(n, {
      x: x, y: 1.90, w: 2.16, h: 0.62, isTextBox: true, margin: 0, align: "center",
      fontFace: HEAD, fontSize: 34, bold: true, color: fill === GOLD ? DEEP : "9DB8D4",
    });
    s.addText(name, {
      x: x, y: 2.54, w: 2.16, h: 0.36, isTextBox: true, margin: 0, align: "center",
      fontFace: HEAD, fontSize: 15, bold: true, color: fill === GOLD ? DEEP : PAPER,
    });
    s.addText(detail, {
      x: x + 0.16, y: 2.94, w: 1.84, h: 1.26, isTextBox: true, margin: 0, align: "center",
      fontFace: BODY, fontSize: 11, color: fill === GOLD ? "4A3A18" : "C9DAEA",
    });
    if (i < waves.length - 1) arrowRight(s, x + 2.19, 2.79, 0.26);
  });

  card(s, {
    x: M, y: 4.62, w: 5.9, h: 2.28, fill: ICE,
    head: "How the waves are ordered",
    bullets: [
      "By what each unlocks, not by visibility",
      "Wave 6 makes five other gaps addressable at once",
      "Wave 8 is a prerequisite for 9, not a parallel track",
      "Each wave ships independently and is useful alone",
    ],
    size: 12.5,
  });
  card(s, {
    x: M + 6.2, y: 4.62, w: 5.9, h: 2.28, fill: "FBF3E3",
    tag: "The rule that made phases 0–5 work", tagColor: WARN,
    head: "Every wave has a demonstrable gate",
    body: "Not a checklist — a condition someone can watch you meet. A wave is "
      + "finished when its gate is demonstrated, not when its code is written.",
    size: 12.5,
  });
  s.addNotes("Phases 0 to 5 used exactly this structure and all six gates were "
    + "met, so the format is proven on this codebase rather than borrowed.");
}

// ══════════════════════════════════════════════════════════════════════════
// 14 — near-term detail
// ══════════════════════════════════════════════════════════════════════════
{
  const s = lightSlide("Roadmap · 2 of 3", "Wave 6 and 7 — the control plane");

  const items = [
    ["6.1", "Service layer extraction", NAVY,
      "Move authorization, dual control, audit and metrics out of the dispatcher into a guard both transports call.",
      "Gate: pure refactor — all 816 tests pass unchanged, no new surface."],
    ["6.2", "Read-only REST + sessions", NAVY,
      "Login, tokens, key inventory with paging and sort, audit search, approval queue, expiry reports.",
      "Gate: a read-only console renders real data and can change nothing."],
    ["6.3", "Write endpoints", NAVY,
      "Key lifecycle, grants, groups, cryptoperiods — all through the guard, so governance applies automatically.",
      "Gate: a REST Destroy under dual control is refused exactly as the KMIP one is."],
    ["6.4", "Console", MID,
      "A single-page client of the API. No privileged back door; the console can do nothing the API forbids.",
      "Gate: an operator completes a full day's work without the CLI."],
    ["7.1", "Directory identity + service accounts", MID,
      "OIDC or LDAP at the edge resolving to provisioned identities, and revocable machine credentials.",
      "Gate: a user logs in with corporate credentials; a leaked token is revoked in one action."],
    ["7.2", "Hardening and SIEM", MID,
      "Connection caps and per-identity rate limiting; audit shipped as syslog or CEF.",
      "Gate: the listener survives a flood; entries appear in the SIEM within a minute."],
  ];
  items.forEach(([n, head, colour, body, gate], i) => {
    const x = M + (i % 3) * 4.12;
    const y = 1.62 + Math.floor(i / 3) * 2.86;
    card(s, {
      x: x, y: y, w: 3.85, h: 2.72, fill: ICE,
      tag: "Wave " + n, tagColor: colour, head: head, headSize: 15, headH: 0.34,
      body: body, size: 11.5, bodyH: 0.84,
    });
    s.addText(gate, {
      x: x + 0.26, y: y + 2.04, w: 3.33, h: 0.60, isTextBox: true, margin: 0,
      fontFace: BODY, fontSize: 10.5, italic: true, color: OK,
    });
  });
  s.addNotes("6.1 is the one to insist on. It ships no feature and removes the "
    + "risk that every later endpoint quietly bypasses dual control. If the "
    + "roadmap gets cut, cut from the end, not from the front.");
}

// ══════════════════════════════════════════════════════════════════════════
// 15 — longer term (dark closer)
// ══════════════════════════════════════════════════════════════════════════
{
  const s = darkSlide("Roadmap · 3 of 3", "Wave 8 to 10 — and what stays out");

  const later = [
    ["8", "Scale and availability",
      "A PostgreSQL backend is the prerequisite: SQLite has no multi-writer story, so clustering, "
      + "replication and DR all wait behind it. HSM failover follows, once a second token exists to test against."],
    ["9", "Multi-tenancy",
      "A tenant boundary reaches into every query, the audit log and the CLI — a wave of its own, not a flag. "
      + "Worth building when there is a second tenant to serve; until then one deployment per tenant is a real answer."],
    ["10", "Compliance and post-quantum",
      "Swap in a validated token and run the suite against it. Adopt KMIP 3.0 and the PQC algorithms once a "
      + "token ships them in a release — vendor-range enums would work locally and interoperate with nothing."],
  ];
  later.forEach(([n, head, body], i) => {
    const y = 1.72 + i * 1.36;
    s.addShape(pres.ShapeType.roundRect, {
      x: M, y: y, w: 0.72, h: 0.72, rectRadius: 0.08,
      fill: { color: GOLD }, line: { color: GOLD, width: 1 },
    });
    s.addText(n, {
      x: M, y: y, w: 0.72, h: 0.72, isTextBox: true, margin: 0,
      align: "center", valign: "middle", fontFace: HEAD, fontSize: 22, bold: true, color: DEEP,
    });
    s.addText(head, {
      x: M + 1.0, y: y - 0.02, w: 4.2, h: 0.4, isTextBox: true, margin: 0,
      fontFace: HEAD, fontSize: 17, bold: true, color: PAPER,
    });
    s.addText(body, {
      x: M + 5.3, y: y - 0.02, w: 6.8, h: 1.2, isTextBox: true, margin: 0,
      fontFace: BODY, fontSize: 12, color: "9DB8D4", lineSpacing: 16,
    });
  });

  s.addText("Deliberately out of scope", {
    x: M, y: 5.86, w: 5.6, h: 0.32, isTextBox: true, margin: 0,
    fontFace: BODY, fontSize: 10.5, bold: true, charSpacing: 1.6, color: GOLD,
  });
  s.addText([
    { text: "Tokenization and FPE — a separate product, not a KMS feature.", options: { bullet: true, breakLine: true } },
    { text: "Being a certificate authority — front it with a real CA instead.", options: { bullet: true, breakLine: true } },
    { text: "A PKCS#11 provider for applications — only if demand appears.", options: { bullet: true } },
  ], {
    x: M, y: 6.14, w: 6.0, h: 0.98, isTextBox: true, margin: 0,
    fontFace: BODY, fontSize: 11.5, color: "9DB8D4", paraSpaceAfter: 3,
  });

  s.addShape(pres.ShapeType.roundRect, {
    x: M + 6.2, y: 5.80, w: 5.9, h: 1.28, rectRadius: 0.06,
    fill: { color: "1B3350" }, line: { color: "2A4A6B", width: 1 },
  });
  s.addText("Nothing ships that cannot be demonstrated. Where something could not be "
    + "tested here, the roadmap says so rather than counting it as done.", {
    x: M + 6.46, y: 6.02, w: 5.38, h: 0.9, isTextBox: true, margin: 0,
    fontFace: HEAD, fontSize: 13.5, italic: true, color: PAPER, lineSpacing: 18,
  });
  s.addNotes("Close on the discipline rather than the feature list: phases 0 to "
    + "5 earned their credibility by finding real defects through execution, and "
    + "the same standard applies to everything above.");
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
