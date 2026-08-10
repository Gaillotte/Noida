"""
Generator: KMIP on PKCS#11 Design Document
Produces a .docx with embedded sequence diagram images.
"""

import io
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyArrowPatch
from docx import Document
from docx.shared import Inches, Pt, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import datetime

# ──────────────────────────────────────────────────────────────────────────────
# Sequence diagram renderer
# ──────────────────────────────────────────────────────────────────────────────

COLORS = {
    "client":  "#4A90D9",
    "server":  "#27AE60",
    "pkcs11":  "#E67E22",
    "hsm":     "#8E44AD",
    "meta":    "#C0392B",
    "arrow":   "#2C3E50",
    "ret":     "#7F8C8D",
    "lifeline":"#BDC3C7",
    "bg":      "#FAFAFA",
}

def draw_sequence(title, actors, messages, figsize=(12, 7)):
    """
    actors  : list of (id, label, color_key)
    messages: list of (from_id, to_id, label, style)
              style in {"call", "return", "self", "note"}
    Returns PNG bytes.
    """
    n = len(actors)
    fig, ax = plt.subplots(figsize=figsize)
    ax.set_facecolor(COLORS["bg"])
    fig.patch.set_facecolor(COLORS["bg"])
    ax.set_xlim(-0.5, n - 0.5)
    total_rows = len(messages) + 2
    ax.set_ylim(-total_rows, 1)
    ax.axis("off")

    # title
    ax.text(
        (n - 1) / 2, 0.7, title,
        ha="center", va="center", fontsize=13, fontweight="bold", color="#2C3E50"
    )

    actor_x = {a[0]: i for i, a in enumerate(actors)}

    # actor boxes
    box_h = 0.55
    for i, (aid, alabel, acolor) in enumerate(actors):
        c = COLORS.get(acolor, "#555")
        rect = mpatches.FancyBboxPatch(
            (i - 0.3, 0.05), 0.6, box_h,
            boxstyle="round,pad=0.05",
            linewidth=1.5, edgecolor=c, facecolor=c, alpha=0.85,
            zorder=3
        )
        ax.add_patch(rect)
        ax.text(i, 0.33, alabel, ha="center", va="center",
                fontsize=8.5, fontweight="bold", color="white", zorder=4)

    # lifelines
    for i, (aid, alabel, _) in enumerate(actors):
        ax.plot([i, i], [0.05, -(total_rows - 1)],
                color=COLORS["lifeline"], lw=1.2, ls="--", zorder=1)

    # messages
    for row, msg in enumerate(messages, start=1):
        y = -row
        src_id, dst_id, label, style = msg

        sx = actor_x[src_id]
        dx = actor_x[dst_id]

        is_ret = (style == "return")
        is_self = (style == "self")
        color   = COLORS["ret"] if is_ret else COLORS["arrow"]
        ls      = "--" if is_ret else "-"

        if is_self:
            # self-call loop
            ax.annotate(
                "", xy=(sx + 0.25, y - 0.15),
                xytext=(sx + 0.25, y + 0.05),
                arrowprops=dict(
                    arrowstyle="->", color=color, lw=1.3,
                    connectionstyle="arc3,rad=-0.6"
                ), zorder=2
            )
            ax.text(sx + 0.52, y - 0.05, label,
                    ha="left", va="center", fontsize=7.5, color=color)
        else:
            mid = (sx + dx) / 2
            ax.annotate(
                "", xy=(dx, y),
                xytext=(sx, y),
                arrowprops=dict(
                    arrowstyle="->", color=color, lw=1.3,
                    linestyle=ls
                ), zorder=2
            )
            ax.text(mid, y + 0.12, label,
                    ha="center", va="bottom", fontsize=7.5, color=color,
                    bbox=dict(facecolor="white", edgecolor="none",
                              alpha=0.7, pad=1))

    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", dpi=150, bbox_inches="tight",
                facecolor=COLORS["bg"])
    plt.close(fig)
    buf.seek(0)
    return buf


# ──────────────────────────────────────────────────────────────────────────────
# Document helpers
# ──────────────────────────────────────────────────────────────────────────────

def set_cell_bg(cell, hex_color):
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd  = OxmlElement("w:shd")
    shd.set(qn("w:val"),   "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"),  hex_color)
    tcPr.append(shd)

def add_heading(doc, text, level=1):
    h = doc.add_heading(text, level=level)
    h.alignment = WD_ALIGN_PARAGRAPH.LEFT
    run = h.runs[0] if h.runs else h.add_run(text)
    if level == 1:
        run.font.color.rgb = RGBColor(0x1A, 0x53, 0x76)
    elif level == 2:
        run.font.color.rgb = RGBColor(0x1E, 0x73, 0x48)
    return h

def add_para(doc, text, bold=False, italic=False, size=10):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.bold   = bold
    run.italic = italic
    run.font.size = Pt(size)
    return p

def add_code(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Cm(1)
    run = p.add_run(text)
    run.font.name = "Courier New"
    run.font.size = Pt(8.5)
    run.font.color.rgb = RGBColor(0x1A, 0x1A, 0x5E)
    pPr = p._p.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"),   "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"),  "EEF2FF")
    pPr.append(shd)
    return p

def add_table(doc, headers, rows, col_widths=None):
    table = doc.add_table(rows=1 + len(rows), cols=len(headers))
    table.style = "Table Grid"
    # header row
    hdr = table.rows[0]
    for i, h in enumerate(headers):
        cell = hdr.cells[i]
        cell.text = h
        set_cell_bg(cell, "1A5376")
        run = cell.paragraphs[0].runs[0]
        run.font.bold  = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        run.font.size  = Pt(9)
        cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
    # data rows
    for ri, row in enumerate(rows):
        tr = table.rows[ri + 1]
        bg = "EBF5FB" if ri % 2 == 0 else "FFFFFF"
        for ci, val in enumerate(row):
            cell = tr.cells[ci]
            cell.text = val
            set_cell_bg(cell, bg)
            cell.paragraphs[0].runs[0].font.size = Pt(9)
    if col_widths:
        for i, w in enumerate(col_widths):
            for row in table.rows:
                row.cells[i].width = Cm(w)
    return table

def add_diagram(doc, buf, caption, width=6.0):
    doc.add_picture(buf, width=Inches(width))
    p = doc.add_paragraph(caption)
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.runs[0]
    run.italic = True
    run.font.size = Pt(9)
    run.font.color.rgb = RGBColor(0x55, 0x55, 0x55)
    doc.add_paragraph()


# ──────────────────────────────────────────────────────────────────────────────
# All sequence diagrams
# ──────────────────────────────────────────────────────────────────────────────

def diag_init():
    actors = [
        ("cli",  "KMIP Client",    "client"),
        ("srv",  "KMIP Server",    "server"),
        ("p11",  "PKCS#11 Shim",   "pkcs11"),
        ("hsm",  "HSM Hardware",   "hsm"),
        ("meta", "Metadata Store", "meta"),
    ]
    msgs = [
        ("cli", "srv",  "TCP connect (TLS ClientHello only if tls_cert configured)", "call"),
        ("srv", "cli",  "ServerHello + Certificate  [if TLS enabled — off by default]", "return"),
        ("srv", "p11",  "C_Initialize()  [python-pkcs11: NULL args, no OS locking]", "call"),
        ("p11", "hsm",  "HSM Driver Init",                    "call"),
        ("hsm", "p11",  "CKR_OK",                             "return"),
        ("srv", "p11",  "C_OpenSession(slot, CKF_RW_SESSION)  — the ONE shared session","call"),
        ("p11", "hsm",  "Open secure channel to HSM",         "call"),
        ("hsm", "p11",  "hSession",                           "return"),
        ("srv", "p11",  "C_Login(hSession, CKU_USER, PIN)",   "call"),
        ("p11", "hsm",  "Authenticate operator",              "call"),
        ("hsm", "p11",  "CKR_OK",                             "return"),
        ("srv", "p11",  "C_GetMechanismList()  — capability probe, cached",  "call"),
        ("p11", "srv",  "supported mechanism set",             "return"),
        ("srv", "meta", "Open metadata DB",                   "call"),
        ("meta","srv",  "DB ready",                           "return"),
        ("srv", "cli",  "KMIP: Ready (Discover Versions resp)","return"),
    ]
    return draw_sequence("SD-01  System Initialization & HSM Login",
                         actors, msgs, figsize=(13, 9))

def diag_create_key():
    actors = [
        ("cli",  "KMIP Client",    "client"),
        ("srv",  "KMIP Server",    "server"),
        ("p11",  "PKCS#11 Shim",   "pkcs11"),
        ("hsm",  "HSM Hardware",   "hsm"),
        ("meta", "Metadata Store", "meta"),
    ]
    msgs = [
        ("cli", "srv",  "Create(SymmetricKey, AES-256, Encrypt|Decrypt)", "call"),
        ("srv", "srv",  "Validate request + Auth check",                  "self"),
        ("srv", "p11",  "C_GenerateKey(hSession, AES-256, template[])",   "call"),
        ("p11", "hsm",  "Generate 256-bit AES key in HSM",                "call"),
        ("hsm", "p11",  "hKey (handle only, never exported)",              "return"),
        ("p11", "srv",  "hKey",                                            "return"),
        ("srv", "meta", "INSERT object (UUID, hKey, type, attrs, state=Pre-Active)", "call"),
        ("meta","srv",  "UUID assigned",                                   "return"),
        ("srv", "meta", "SET state = Active (if Activation Date = now)",   "call"),
        ("meta","srv",  "OK",                                              "return"),
        ("srv", "cli",  "CreateResponse(UniqueIdentifier=UUID)",           "return"),
    ]
    return draw_sequence("SD-02  Create Symmetric Key",
                         actors, msgs, figsize=(13, 8))

def diag_create_keypair():
    actors = [
        ("cli",  "KMIP Client",  "client"),
        ("srv",  "KMIP Server",  "server"),
        ("p11",  "PKCS#11 Shim","pkcs11"),
        ("hsm",  "HSM Hardware", "hsm"),
        ("meta", "Metadata Store","meta"),
    ]
    msgs = [
        ("cli", "srv", "CreateKeyPair(RSA-2048, Sign|Verify)",           "call"),
        ("srv", "srv", "Validate + Auth",                                 "self"),
        ("srv", "p11", "C_GenerateKeyPair(RSA-2048, pubTpl, privTpl)",   "call"),
        ("p11", "hsm", "Generate RSA key pair in HSM",                   "call"),
        ("hsm", "p11", "hPub, hPriv",                                    "return"),
        ("p11", "srv", "hPub, hPriv",                                    "return"),
        ("srv", "meta","INSERT PublicKey  (UUID_pub,  hPub,  Active)",   "call"),
        ("meta","srv", "UUID_pub",                                        "return"),
        ("srv", "meta","INSERT PrivateKey (UUID_priv, hPriv, Active)",   "call"),
        ("meta","srv", "UUID_priv",                                       "return"),
        ("srv", "cli", "CreateKeyPairResponse(UUID_pub, UUID_priv)",     "return"),
    ]
    return draw_sequence("SD-03  Create Key Pair (Asymmetric)",
                         actors, msgs, figsize=(13, 8))

def diag_get():
    actors = [
        ("cli",  "KMIP Client",   "client"),
        ("srv",  "KMIP Server",   "server"),
        ("p11",  "PKCS#11 Shim",  "pkcs11"),
        ("hsm",  "HSM Hardware",  "hsm"),
        ("meta", "Metadata Store","meta"),
    ]
    msgs = [
        ("cli", "srv",  "Get(UniqueIdentifier=UUID, KeyWrapping?)",       "call"),
        ("srv", "meta", "SELECT hKey, state, extractable, owner WHERE UUID","call"),
        ("meta","srv",  "hKey, state=Active, extractable=True, owner",    "return"),
        ("srv", "srv",  "check_owner(): admin role, or owner, or grant — else PermissionDenied", "self"),
        ("srv", "srv",  "check_usage_allowed(state)",                     "self"),
        ("srv", "p11",  "C_GetAttributeValue(hKey, CKA_VALUE)",           "call"),
        ("p11", "hsm",  "Export key material (if extractable)",           "call"),
        ("hsm", "p11",  "Key bytes (or wrapped)",                         "return"),
        ("p11", "srv",  "Key bytes",                                      "return"),
        ("srv", "cli",  "GetResponse(KeyMaterial, Attributes)",           "return"),
    ]
    return draw_sequence("SD-04  Get (Retrieve Key Material)",
                         actors, msgs, figsize=(13, 8))

def diag_encrypt():
    actors = [
        ("cli",  "KMIP Client",  "client"),
        ("srv",  "KMIP Server",  "server"),
        ("p11",  "PKCS#11 Shim","pkcs11"),
        ("hsm",  "HSM Hardware", "hsm"),
        ("meta", "Metadata Store","meta"),
    ]
    msgs = [
        ("cli", "srv", "Encrypt(UUID, plaintext, AES-GCM, IV)",  "call"),
        ("srv", "meta","SELECT hKey, state, owner WHERE UUID",   "call"),
        ("meta","srv", "hKey, state=Active, owner",              "return"),
        ("srv", "srv", "check_owner() + check_usage_allowed()",  "self"),
        ("srv", "p11", "supports_mechanism(AES_GCM)? — capability probe","self"),
        ("srv", "p11", "C_EncryptInit(hSession, AES-GCM, hKey)  [shared, locked session]", "call"),
        ("p11", "hsm", "Init AES-GCM with HSM-resident key",     "call"),
        ("hsm", "p11", "CKR_OK",                                 "return"),
        ("srv", "p11", "C_Encrypt(plaintext)",                   "call"),
        ("p11", "hsm", "AES-GCM encrypt",                        "call"),
        ("hsm", "p11", "ciphertext + tag",                       "return"),
        ("p11", "srv", "ciphertext + tag",                       "return"),
        ("srv", "cli", "EncryptResponse(ciphertext, IV, tag)",   "return"),
    ]
    return draw_sequence("SD-05  Encrypt Operation",
                         actors, msgs, figsize=(13, 8.5))

def diag_lifecycle():
    actors = [
        ("cli",  "KMIP Client",   "client"),
        ("srv",  "KMIP Server",   "server"),
        ("p11",  "PKCS#11 Shim",  "pkcs11"),
        ("hsm",  "HSM Hardware",  "hsm"),
        ("meta", "Metadata Store","meta"),
    ]
    msgs = [
        ("cli", "srv",  "Activate(UUID)",                                   "call"),
        ("srv", "meta", "SELECT owner, state WHERE UUID",                   "call"),
        ("meta","srv",  "owner, state=Pre-Active",                          "return"),
        ("srv", "srv",  "check_owner() + transition(state,\"activate\")",   "self"),
        ("srv", "meta", "UPDATE state = Active WHERE UUID",                 "call"),
        ("meta","srv",  "OK",                                               "return"),
        ("srv", "cli",  "ActivateResponse()",                               "return"),
        ("cli", "srv",  "Revoke(UUID, reason=Superseded)",                  "call"),
        ("srv", "meta", "SELECT owner, state WHERE UUID",                   "call"),
        ("meta","srv",  "owner, state=Active",                              "return"),
        ("srv", "srv",  "check_owner() + transition(state,\"revoke_normal\")","self"),
        ("srv", "meta", "UPDATE state = Deactivated WHERE UUID  [metadata only — no HSM call]", "call"),
        ("meta","srv",  "OK",                                               "return"),
        ("srv", "cli",  "RevokeResponse()",                                 "return"),
        ("cli", "srv",  "Destroy(UUID)",                                    "call"),
        ("srv", "meta", "SELECT hKey, owner, state WHERE UUID",             "call"),
        ("meta","srv",  "hKey, owner, state",                               "return"),
        ("srv", "srv",  "check_owner() + transition(state,\"destroy\")",    "self"),
        ("srv", "p11",  "C_DestroyObject(hKey)",                            "call"),
        ("p11", "hsm",  "Zeroize key material in HSM",                     "call"),
        ("hsm", "p11",  "CKR_OK",                                          "return"),
        ("srv", "meta", "UPDATE state = Destroyed WHERE UUID",              "call"),
        ("meta","srv",  "OK",                                               "return"),
        ("srv", "cli",  "DestroyResponse()",                                "return"),
    ]
    return draw_sequence("SD-06  Key Lifecycle  (Activate → Revoke → Destroy)",
                         actors, msgs, figsize=(13, 11))

def diag_locate():
    actors = [
        ("cli",  "KMIP Client",   "client"),
        ("srv",  "KMIP Server",   "server"),
        ("meta", "Metadata Store","meta"),
        ("p11",  "PKCS#11 Shim",  "pkcs11"),
        ("hsm",  "HSM Hardware",  "hsm"),
    ]
    msgs = [
        ("cli", "srv",  "Locate(Name='mykey', ObjectType=SymmetricKey, State=Active)", "call"),
        ("srv", "meta", "SELECT UUID WHERE name='mykey' AND type=Sym AND state=Active AND owner=identity","call"),
        ("meta","srv",  "[UUID1, UUID2, ...] — caller's own objects only",             "return"),
        ("srv", "cli",  "LocateResponse([UUID1, UUID2])",                              "return"),
    ]
    return draw_sequence("SD-07  Locate Operation",
                         actors, msgs, figsize=(13, 8))

def diag_auth():
    actors = [
        ("cli",  "KMIP Client",   "client"),
        ("srv",  "KMIP Server",   "server"),
        ("shim", "PKCS#11 Shim",  "pkcs11"),
        ("meta", "Metadata Store","meta"),
    ]
    msgs = [
        ("cli",  "srv",  "TCP connect  (TLS optional — off unless configured)",     "call"),
        ("cli",  "srv",  "KMIP Request + Credential{UsernamePasswordCredential}",   "call"),
        ("srv",  "shim", "verify_pin(password)  — hmac.compare_digest vs token PIN","call"),
        ("shim", "srv",  "True/False",                                             "return"),
        ("srv",  "srv",  "identity = username if match, else AuthenticationFailed; \"anonymous\" if no Credential", "self"),
        ("cli",  "srv",  "e.g. Destroy(UUID)  — identity resolved, not yet authorized for this object", "call"),
        ("srv",  "meta", "SELECT owner_identity WHERE UUID",                        "call"),
        ("meta", "srv",  "owner_identity",                                          "return"),
        ("srv",  "meta", "get_roles(identity)  — tier 1: admin role?",              "call"),
        ("meta", "srv",  "[] or [\"admin\", ...]",                                  "return"),
        ("srv",  "srv",  "tier 2: identity == owner_identity ?",                    "self"),
        ("srv",  "meta", "get_grant(uid, identity)  — tier 3: delegated grant?",    "call"),
        ("meta", "srv",  "None, or \"read\"/\"full\"",                              "return"),
        ("srv",  "cli",  "KMIP Response  OR  ResultReason=PermissionDenied",        "return"),
    ]
    return draw_sequence("SD-08  Authentication & Authorization Flow",
                         actors, msgs, figsize=(13, 11))


# ──────────────────────────────────────────────────────────────────────────────
# Build the Word document
# ──────────────────────────────────────────────────────────────────────────────

def build_document(out_path):
    doc = Document()

    # ── page margins ──
    for section in doc.sections:
        section.top_margin    = Cm(2.0)
        section.bottom_margin = Cm(2.0)
        section.left_margin   = Cm(2.5)
        section.right_margin  = Cm(2.5)

    # ── default style ──
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(10)

    # ════════════════════════════════════════════════════
    # COVER PAGE
    # ════════════════════════════════════════════════════
    doc.add_paragraph()
    doc.add_paragraph()
    title_p = doc.add_paragraph()
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title_p.add_run("KMIP Module Design\non top of a PKCS#11 HSM")
    run.font.size = Pt(26)
    run.font.bold = True
    run.font.color.rgb = RGBColor(0x1A, 0x53, 0x76)

    doc.add_paragraph()
    sub_p = doc.add_paragraph()
    sub_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub_p.add_run("Architecture & Sequence Design Document").font.size = Pt(14)

    doc.add_paragraph()
    meta_p = doc.add_paragraph()
    meta_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    meta_p.add_run(
        f"Version 1.0  ·  {datetime.date.today().strftime('%B %d, %Y')}\n"
        "Classification: Internal"
    ).font.size = Pt(10)

    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # TABLE OF CONTENTS (static)
    # ════════════════════════════════════════════════════
    add_heading(doc, "Table of Contents", 1)
    toc = [
        ("1", "Introduction & Scope"),
        ("2", "Standards Overview"),
        ("3", "High-Level Architecture"),
        ("4", "Component Design"),
        ("5", "KMIP ↔ PKCS#11 Operation Mapping"),
        ("6", "Key Attribute & Metadata Model"),
        ("7", "Key Lifecycle State Machine"),
        ("8", "Sequence Diagrams"),
        ("  8.1", "SD-01 System Initialization & HSM Login"),
        ("  8.2", "SD-02 Create Symmetric Key"),
        ("  8.3", "SD-03 Create Key Pair"),
        ("  8.4", "SD-04 Get (Retrieve Key Material)"),
        ("  8.5", "SD-05 Encrypt Operation"),
        ("  8.6", "SD-06 Key Lifecycle (Activate → Revoke → Destroy)"),
        ("  8.7", "SD-07 Locate Operation"),
        ("  8.8", "SD-08 Authentication & Authorization"),
        ("9", "Transport & TLS Configuration"),
        ("10", "Authentication & Access Control"),
        ("11", "Metadata Store Schema"),
        ("12", "Error Handling & Result Codes"),
        ("13", "Security Considerations"),
        ("14", "Implementation Roadmap"),
        ("15", "References"),
    ]
    for num, name in toc:
        p = doc.add_paragraph(f"  {num}  {name}")
        p.runs[0].font.size = Pt(10)
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 1. INTRODUCTION
    # ════════════════════════════════════════════════════
    add_heading(doc, "1. Introduction & Scope", 1)
    add_para(doc,
        "This document describes the architecture and detailed design for a KMIP "
        "(Key Management Interoperability Protocol) server module built on top of a "
        "PKCS#11-compliant Hardware Security Module (HSM). The goal is to expose a "
        "standards-compliant KMIP interface to any KMIP client while delegating all "
        "cryptographic operations and key storage to a hardware-backed PKCS#11 token.")
    doc.add_paragraph()
    add_para(doc, "Scope:", bold=True)
    for item in [
        "KMIP version covered: 2.1 (OASIS, December 2020) — 41 of 53 operations implemented.",
        "PKCS#11 (Cryptoki) binding: python-pkcs11 0.9.5, tested against SoftHSM2.",
        "Transport: raw TCP on port 5696; TLS 1.3/mTLS supported but optional, not enforced by default.",
        "Authentication: KMIP Credential (UsernameAndPassword, checked against the token PIN).",
        "Access control: owner-only enforcement, an admin role, and delegated per-object grants "
        "(added after the initial design — see Section 10).",
        "Managed objects: Symmetric Keys, Asymmetric Key Pairs, Certificates, Secret Data, "
        "Opaque Objects, Split Key parts.",
    ]:
        p = doc.add_paragraph(item, style="List Bullet")
        p.runs[0].font.size = Pt(10)
    doc.add_paragraph()

    # ════════════════════════════════════════════════════
    # 2. STANDARDS OVERVIEW
    # ════════════════════════════════════════════════════
    add_heading(doc, "2. Standards Overview", 1)

    add_heading(doc, "2.1 KMIP", 2)
    add_para(doc,
        "KMIP is an OASIS standard (first published October 2010) defining a vendor-neutral "
        "wire protocol for creating, registering, retrieving, and destroying cryptographic "
        "objects. Messages are encoded in TTLV (Tag–Type–Length–Value) binary format and "
        "transported over TLS. Current stable version is 2.1 (December 2020); version 3.0 "
        "adds post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA).")

    add_heading(doc, "2.2 PKCS#11 (Cryptoki)", 2)
    add_para(doc,
        "PKCS#11, maintained by OASIS (formerly RSA Labs), defines a C-language API to "
        "hardware and software cryptographic tokens. HSMs expose a PKCS#11 shared library "
        "(.so / .dll). All key material remains inside the HSM boundary; applications "
        "receive only opaque handles (CK_OBJECT_HANDLE).")
    doc.add_paragraph()

    add_table(doc,
        ["Standard", "Body", "Current Version", "Key Concepts"],
        [
            ["KMIP",    "OASIS", "2.1 (3.0 draft)", "TTLV encoding, managed objects, operations, profiles"],
            ["PKCS#11", "OASIS", "3.0",              "Cryptoki API, sessions, slots, tokens, mechanisms"],
            ["TLS",     "IETF",  "1.3 (RFC 8446)",   "mTLS, AEAD cipher suites, perfect forward secrecy"],
            ["X.509",   "IETF",  "RFC 5280",         "Certificate format, chain validation"],
        ],
        col_widths=[3.0, 3.0, 4.0, 8.0]
    )
    doc.add_paragraph()
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 3. HIGH-LEVEL ARCHITECTURE
    # ════════════════════════════════════════════════════
    add_heading(doc, "3. High-Level Architecture", 1)
    add_para(doc,
        "The system is structured as a layered stack. KMIP clients connect over TLS "
        "to the KMIP Server Layer, which translates operations into PKCS#11 calls against "
        "the HSM, and maintains a Metadata Store for KMIP-specific attributes that have "
        "no PKCS#11 equivalent.")
    doc.add_paragraph()

    add_code(doc,
"┌──────────────────────────────────────────────────────┐\n"
"│              KMIP Clients (any vendor)               │\n"
"│   Storage Arrays │ Tape Libraries │ Apps │ Databases │\n"
"└──────────────────────────┬───────────────────────────┘\n"
"                           │  KMIP over TLS 1.3 (port 5696)\n"
"┌──────────────────────────▼───────────────────────────┐\n"
"│                  KMIP Server Layer                   │\n"
"│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐  │\n"
"│  │  TTLV   │ │ Protocol │ │ Lifecycle│ │  Auth  │  │\n"
"│  │ Parser  │ │ Dispatch │ │  Engine  │ │  ACL   │  │\n"
"│  └──────────┘ └──────────┘ └──────────┘ └────────┘  │\n"
"└────────────────────┬─────────────┬────────────────────┘\n"
"                     │ PKCS#11     │ SQL\n"
"          ┌──────────▼──────┐  ┌───▼──────────────────┐\n"
"          │  PKCS#11 Shim   │  │   Metadata Store     │\n"
"          │ (C_GenerateKey  │  │ (UUID, hKey, state,  │\n"
"          │  C_Encrypt …)   │  │  dates, attributes)  │\n"
"          └──────────┬──────┘  └──────────────────────┘\n"
"                     │ HSM Driver\n"
"          ┌──────────▼──────────────────┐\n"
"          │        HSM Hardware         │\n"
"          │  (key gen, crypto, storage) │\n"
"          └─────────────────────────────┘")
    doc.add_paragraph()
    add_para(doc,
        "As built, two details in this diagram are more specific than the generic boxes suggest: "
        "the PKCS#11 Shim wraps exactly one PKCS#11 session, shared by every connection thread and "
        "serialized behind a lock (Section 4, Section 13) rather than a session pool; and the "
        "Auth/ACL block is a two-stage check — Credential authentication against the token PIN, "
        "then per-operation authorization in lifecycle/access_control.py (Section 10).",
        italic=True, size=9)
    doc.add_paragraph()
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 4. COMPONENT DESIGN
    # ════════════════════════════════════════════════════
    add_heading(doc, "4. Component Design", 1)

    components = [
        ("TTLV Parser / Serializer",
         "Encodes and decodes KMIP messages in binary TTLV (Tag–Type–Length–Value) format. "
         "Must handle nested Structures, TextStrings, ByteStrings, Integers, Enumerations, "
         "DateTimes, and BigIntegers. Also supports JSON and XML alternative encodings "
         "(KMIP Additional Message Encodings spec)."),
        ("Protocol Dispatcher",
         "Routes each incoming Batch Item to the correct operation handler based on the "
         "Operation enumeration. Supports batch requests (multiple operations per TLS frame) "
         "and async polling via the Poll operation."),
        ("Lifecycle Engine",
         "Implements the KMIP state machine: Pre-Active → Active → Deactivated → "
         "Compromised → Destroyed. Enforces date-based transitions (Activation Date, "
         "Deactivation Date). Calls the Metadata Store for state persistence."),
        ("Auth / ACL Module",
         "Resolves identity from the KMIP Credential (UsernameAndPassword, checked against "
         "the token PIN — see Section 10); TLS client certificates are supported as an optional "
         "additional transport control but are not mapped to a separate principal today. Every "
         "operation against an existing object is then authorized by lifecycle/access_control.py "
         "in three tiers, checked in order: the admin role (unconditional), ownership "
         "(identity == owner_identity, recorded at create time), and delegated per-object grants "
         "(read or full, assigned independently of ownership). There is no KMIP wire operation for "
         "role/grant management — it's a server-admin surface against the metadata store directly."),
        ("PKCS#11 Shim",
         "Wraps the PKCS#11 shared library via python-pkcs11. Owns exactly one PKCS#11 session, "
         "shared by every connection thread and serialized behind a threading.RLock — a session "
         "pool (one session per thread) was built and evaluated, and rejected: the python-pkcs11 "
         "binding in use calls C_Initialize(NULL), so the library's own thread-safety is never "
         "enabled, and concurrent access from separate sessions reproducibly corrupted operations "
         "or crashed the native extension in testing (Section 13). The shim also probes the "
         "token's actual supported mechanism list once at startup (supports_mechanism() / "
         "_require_mechanism()) and rejects an algorithm or mode the token doesn't implement "
         "before attempting the native call, rather than surfacing a raw PKCS#11 error."),
        ("Metadata Store",
         "Stores KMIP-specific attributes that PKCS#11 does not natively support: "
         "Unique Identifier (UUID), Activation Date, Deactivation Date, State, "
         "Name, Link, Application Specific Information, Revocation Reason, owner identity, "
         "and PKCS#11 handle reference — plus, since the access-control work, identity role "
         "assignments and delegated object grants (Section 11). Implemented as a single SQLite "
         "database (WAL mode, connection-per-thread); there is no multi-node/HA backend today."),
    ]
    for name, desc in components:
        add_heading(doc, name, 2)
        add_para(doc, desc)
        doc.add_paragraph()

    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 5. KMIP ↔ PKCS#11 OPERATION MAPPING
    # ════════════════════════════════════════════════════
    add_heading(doc, "5. KMIP ↔ PKCS#11 Operation Mapping", 1)
    add_para(doc,
        "The following table shows how each of the 41 implemented KMIP operations maps to "
        "PKCS#11 Cryptoki calls (via python-pkcs11) and/or the metadata store. Operations "
        "marked 'Metadata only' require no HSM call at all — this is more common than the "
        "original design anticipated: state transitions in particular (Activate, Revoke, "
        "most of Archive/Recover) turned out not to need a corresponding PKCS#11 attribute "
        "change, since HSM-side usage restriction is enforced at the mechanism-dispatch layer "
        "(the capability-probed shim), not by flipping CKA_ENCRYPT/CKA_DECRYPT on the object.")
    doc.add_paragraph()

    add_table(doc,
        ["KMIP Operation", "PKCS#11 Call(s)", "Notes"],
        [
            ["Create (symmetric)",    "C_GenerateKey",                          "Template built from CryptoAlg + KeyLength"],
            ["CreateKeyPair",         "C_GenerateKeyPair",                      "RSA/EC/DSA/DH; two UIDs returned"],
            ["Register",              "C_CreateObject",                         "Client supplies key material"],
            ["Import (v2.0+)",        "C_CreateObject, or C_UnwrapKey via wrap_key/unwrap_key", "ReplaceExisting requires ownership of the existing UID"],
            ["Export (v2.0+)",        "Same as Get (aliases it)",               ""],
            ["Get",                   "C_GetAttributeValue(CKA_VALUE), or C_WrapKey", "Only if extractable; wrapping scoped to SymmetricKey"],
            ["Locate",                "Metadata only",                          "Filtered by owner_identity — a non-admin caller cannot enumerate objects it doesn't own"],
            ["Destroy",               "C_DestroyObject",                        "HSM zeroizes key material"],
            ["Activate",              "Metadata only",                          "State → Active"],
            ["Revoke",                "Metadata only",                          "State → Deactivated/Compromised per reason code; no PKCS#11 call"],
            ["Archive / Recover",     "Metadata only",                          "Orthogonal to State; blocks all ops but metadata reads until Recovered"],
            ["Check",                 "Metadata only",                          "Reports which requested constraints (usage mask, state, usage limit) fail, without mutating"],
            ["ReKey / ReKeyKeyPair",  "C_GenerateKey / C_GenerateKeyPair",      "New object(s), cross-linked to the old via Link attributes"],
            ["Certify / ReCertify",   "C_Sign (self-signed X.509, built with asn1crypto)", "RSA only"],
            ["CreateSplitKey / JoinSplitKey", "C_GenerateRandom, or none",      "XOR N-of-N sharing only; no threshold (k-of-n) scheme"],
            ["Encrypt / Decrypt",     "C_EncryptInit/C_Encrypt, C_DecryptInit/C_Decrypt", "Mode gated by the capability probe first"],
            ["Sign / SignatureVerify","C_SignInit + C_Sign / C_VerifyInit + C_Verify", "Mechanism = CKM_RSA_PKCS, CKM_ECDSA_*, CKM_DSA_*"],
            ["MAC / MACVerify",       "C_SignInit / C_VerifyInit (HMAC mechanism)", "CKM_SHA256_HMAC etc.; SHA-3 HMAC wired but token-gated"],
            ["Hash",                  "C_DigestInit + C_Digest",                "No key involved"],
            ["Validate",              "C_VerifyInit + C_Verify (ephemeral imported issuer key)", "RSA-signed certificate chains only"],
            ["DeriveKey",             "C_DeriveKey",                            "DH/ECDH key agreement only"],
            ["GetAttributes / GetAttributeList", "Metadata only",               ""],
            ["AddAttribute / ModifyAttribute / DeleteAttribute / SetAttribute / AdjustAttribute", "Metadata only", "AdjustAttribute does atomic increment/decrement/set on numeric attrs"],
            ["ObtainLease / GetUsageAllocation", "Metadata only",               "Lease has no client-tracked expiry enforcement; usage allocation atomically decrements a counter attribute"],
            ["Query / DiscoverVersions", "C_GetMechanismList (for Query's capability probe)", "Advertises 3 of 12 QueryFunction values"],
            ["RNGRetrieve / RNGSeed", "C_GenerateRandom / C_SeedRandom",        ""],
        ],
        col_widths=[5.0, 6.5, 6.5]
    )
    doc.add_paragraph()
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 6. KEY ATTRIBUTE & METADATA MODEL
    # ════════════════════════════════════════════════════
    add_heading(doc, "6. Key Attribute & Metadata Model", 1)
    add_para(doc,
        "PKCS#11 stores a limited set of attributes on the token. The Metadata Store "
        "extends this with KMIP-specific fields. The mapping below shows where each "
        "KMIP attribute lives.")
    doc.add_paragraph()

    add_table(doc,
        ["KMIP Attribute", "Stored in", "PKCS#11 Attribute"],
        [
            ["Unique Identifier",          "Metadata Store",         "CKA_ID (cross-reference)"],
            ["Name",                       "Metadata Store",         "CKA_LABEL (primary name only)"],
            ["Object Type",                "Metadata Store",         "CKA_CLASS"],
            ["Cryptographic Algorithm",    "PKCS#11 Token",          "CKA_KEY_TYPE"],
            ["Cryptographic Length",       "PKCS#11 Token",          "CKA_VALUE_LEN"],
            ["Cryptographic Usage Mask",   "PKCS#11 Token",          "CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN…"],
            ["State",                      "Metadata Store",         "Derived from CKA_ENCRYPT / CKA_DECRYPT"],
            ["Initial Date",               "Metadata Store",         "—"],
            ["Activation Date",            "Metadata Store",         "—"],
            ["Deactivation Date",          "Metadata Store",         "—"],
            ["Destroy Date",               "Metadata Store",         "—"],
            ["Compromise Occurrence Date", "Metadata Store",         "—"],
            ["Revocation Reason",          "Metadata Store",         "—"],
            ["Link",                       "Metadata Store",         "CKA_ID of linked object"],
            ["Sensitive",                  "PKCS#11 Token",          "CKA_SENSITIVE"],
            ["Extractable",                "PKCS#11 Token",          "CKA_EXTRACTABLE"],
            ["Always Sensitive",           "PKCS#11 Token",          "CKA_ALWAYS_SENSITIVE"],
            ["Never Extractable",          "PKCS#11 Token",          "CKA_NEVER_EXTRACTABLE"],
            ["Application Specific Info",  "Metadata Store",         "—"],
            ["Custom Attribute",           "Metadata Store",         "—"],
            ["Owner identity",             "Metadata Store",         "— (Credential username, or \"anonymous\"; not derived from an mTLS DN)"],
        ],
        col_widths=[5.5, 4.5, 8.0]
    )
    doc.add_paragraph()
    add_para(doc,
        "Two more tables exist outside the KMIP attribute model proper, supporting the access-control "
        "layer added after the initial design: identity role assignments and delegated per-object "
        "grants. Neither has a KMIP wire representation — see Section 10 and Section 11.",
        italic=True, size=9)
    doc.add_paragraph()
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 7. KEY LIFECYCLE STATE MACHINE
    # ════════════════════════════════════════════════════
    add_heading(doc, "7. Key Lifecycle State Machine", 1)
    add_para(doc,
        "KMIP defines six lifecycle states. Transitions are triggered by KMIP operations "
        "or by date-based policies evaluated at request time.")
    doc.add_paragraph()

    add_code(doc,
"  [CREATE / REGISTER]\n"
"         │\n"
"         ▼\n"
"    ┌──────────┐   Activate()    ┌──────────┐\n"
"    │Pre-Active│────────────────▶│  Active  │\n"
"    └──────────┘                 └────┬─────┘\n"
"         │                           │\n"
"         │ Revoke(Compromise)        │ Revoke(Normal)\n"
"         │                           ▼\n"
"         │                    ┌─────────────┐\n"
"         │                    │ Deactivated │\n"
"         │                    └──────┬──────┘\n"
"         │                           │\n"
"         ▼         Revoke(Comp.)     │\n"
"    ┌───────────┐◀──────────────────┘\n"
"    │Compromised│\n"
"    └─────┬─────┘\n"
"          │ Destroy()\n"
"          ▼\n"
"  ┌───────────────────┐\n"
"  │Destroyed Compromis│\n"
"  └───────────────────┘\n\n"
"  Any state ──Destroy()──▶ Destroyed")
    doc.add_paragraph()

    add_table(doc,
        ["From State", "KMIP Operation", "To State", "HSM Action"],
        [
            ["(none)",              "Create / Register",       "Pre-Active",           "C_GenerateKey / C_CreateObject"],
            ["Pre-Active",          "Activate",                "Active",               "None (metadata only)"],
            ["Active",              "Revoke(Superseded)",      "Deactivated",          "C_SetAttributeValue(Encrypt=F)"],
            ["Active / Pre-Active", "Revoke(Compromised)",     "Compromised",          "C_SetAttributeValue(all=F)"],
            ["Deactivated",         "Revoke(Compromised)",     "Compromised",          "C_SetAttributeValue(all=F)"],
            ["Any",                 "Destroy",                 "Destroyed",            "C_DestroyObject"],
            ["Compromised",         "Destroy",                 "Destroyed Compromised","C_DestroyObject (record kept)"],
        ],
        col_widths=[4.0, 5.0, 5.0, 5.0]
    )
    doc.add_paragraph()
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 8. SEQUENCE DIAGRAMS
    # ════════════════════════════════════════════════════
    add_heading(doc, "8. Sequence Diagrams", 1)
    add_para(doc,
        "The following sequence diagrams illustrate the message flows between "
        "KMIP Client, KMIP Server, PKCS#11 Shim, HSM Hardware, and Metadata Store "
        "for the most important operations.")
    doc.add_paragraph()

    diagrams = [
        ("8.1 System Initialization & HSM Login",      diag_init,         "SD-01"),
        ("8.2 Create Symmetric Key",                   diag_create_key,   "SD-02"),
        ("8.3 Create Key Pair (Asymmetric)",           diag_create_keypair,"SD-03"),
        ("8.4 Get — Retrieve Key Material",            diag_get,           "SD-04"),
        ("8.5 Encrypt Operation",                      diag_encrypt,       "SD-05"),
        ("8.6 Key Lifecycle (Activate → Revoke → Destroy)", diag_lifecycle,"SD-06"),
        ("8.7 Locate Operation",                       diag_locate,        "SD-07"),
        ("8.8 Authentication & Authorization Flow",    diag_auth,          "SD-08"),
    ]

    for title, fn, code in diagrams:
        add_heading(doc, title, 2)
        buf = fn()
        add_diagram(doc, buf, f"Figure: {code} — {title.split(' ', 1)[1]}", width=6.2)
        doc.add_paragraph()

    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 9. TRANSPORT & TLS
    # ════════════════════════════════════════════════════
    add_heading(doc, "9. Transport & TLS Configuration", 1)
    add_para(doc,
        "TLS is optional, not enforced — this is a tracked known limitation (Section 13), "
        "not the original intent. If no certificate is configured the server accepts plain "
        "TCP; if configured, it wraps the socket via Python's ssl module.", italic=True, size=9)
    doc.add_paragraph()

    add_table(doc,
        ["Parameter", "Value"],
        [
            ["Default TCP port",         "5696 (IANA assigned to KMIP)"],
            ["TLS",                      "Optional — off unless tls_cert/tls_key are configured"],
            ["Client authentication",    "Mutual TLS (mTLS) — optional, only if require_client_cert=True"],
            ["Certificate format",       "X.509 v3, loaded from a static file path (no rotation, no ACME)"],
            ["KMIP over HTTPS",          "Not implemented — this server only speaks raw-TCP TTLV"],
        ],
        col_widths=[6.0, 12.0]
    )
    doc.add_paragraph()
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 10. AUTHENTICATION MECHANISMS
    # ════════════════════════════════════════════════════
    add_heading(doc, "10. Authentication & Access Control", 1)
    add_para(doc,
        "Authentication resolves a request to an identity string. Access control then decides, "
        "per operation and per object, whether that identity may proceed. These are implemented "
        "as two separate, sequential steps — not the combined TLS-plus-credential model originally "
        "envisioned.")
    doc.add_paragraph()

    add_heading(doc, "10.1 Authentication", 2)
    add_para(doc,
        "Only one Credential type is implemented today. The table below also records what was "
        "originally planned but is not built, so the gap is explicit rather than silently dropped.")
    doc.add_paragraph()

    add_table(doc,
        ["Credential Type", "KMIP Structure", "Status"],
        [
            ["UsernameAndPassword", "Credential{UsernamePasswordCredential}", "Implemented — password checked against the token's shared PIN (hmac.compare_digest); any username with the correct PIN is accepted as that identity"],
            ["(no credential)",     "—",                                      "Implemented — identity defaults to \"anonymous\""],
            ["Device Credential",   "Credential{DeviceCredential}",           "Not implemented"],
            ["Attestation",         "Credential{AttestationCredential}",      "Not implemented"],
            ["One-Time Password",   "Credential{OneTimePasswordCredential}",  "Not implemented"],
            ["Hashed Password",     "Credential{HashedPasswordCredential}",   "Not implemented"],
            ["mTLS-derived identity","TLS client certificate (X.509)",        "mTLS itself is supported (Section 9) but the certificate's Subject/SAN is not mapped to a KMIP identity — it isn't a Credential alternative here"],
        ],
        col_widths=[4.5, 6.0, 7.5]
    )
    doc.add_paragraph()

    add_heading(doc, "10.2 Access Control (Authorization)", 2)
    add_para(doc,
        "Every managed object records owner_identity, the identity that created it. Operations "
        "against an existing object are authorized in this order by lifecycle/access_control.py:")
    doc.add_paragraph()
    for i, item in enumerate([
        "Admin role — the reserved role \"admin\", assigned via MetadataStore.assign_role"
        "(identity, \"admin\"): unconditional access to every object, regardless of owner.",
        "Ownership — identity == owner_identity.",
        "Delegated grant — MetadataStore.grant_access(uid, grantee, \"read\"|\"full\") lets a "
        "specific identity reach a specific object it doesn't own. \"read\" covers Get, "
        "GetAttributes, GetAttributeList, Check, Export, ObtainLease; every other operation "
        "requires \"full\".",
    ], start=1):
        p = doc.add_paragraph(f"{i}. {item}", style="List Number")
        p.runs[0].font.size = Pt(10)
    doc.add_paragraph()
    add_para(doc,
        "Objects with no recorded owner (owner_identity = NULL) remain reachable by any identity — "
        "this only applies to objects created outside the normal Create/Register/etc. path, so "
        "nothing already in the store is orphaned by adding this on top of it. Failing all three "
        "checks raises NotAuthorized (ResultReason.PermissionDenied, Section 12).")
    doc.add_paragraph()
    add_para(doc,
        "There is no KMIP wire operation for role or grant management — the specification doesn't "
        "define one. Both are a MetadataStore admin surface, called directly by an admin script or "
        "console, not exposed over the network. There are no groups and no per-role operation "
        "allowlist yet — every non-admin identity is evaluated individually against ownership and "
        "grants (Section 14 — Roadmap).", italic=True, size=9)
    doc.add_paragraph()
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 11. METADATA STORE SCHEMA
    # ════════════════════════════════════════════════════
    add_heading(doc, "11. Metadata Store Schema", 1)
    add_para(doc,
        "The Metadata Store persists KMIP-specific attributes not natively held in PKCS#11, plus "
        "(since the access-control work) role and grant records. It is SQLite (WAL mode, "
        "connection-per-thread) — there is no multi-node/HA backend; that remains future work "
        "(Section 14), not the Postgres-based design originally sketched.")
    doc.add_paragraph()

    add_heading(doc, "Table: kmip_objects", 2)
    add_code(doc,
"CREATE TABLE kmip_objects (\n"
"  uuid                    TEXT PRIMARY KEY,      -- KMIP Unique Identifier\n"
"  object_type             INTEGER NOT NULL,       -- ObjectType enum value\n"
"  pkcs11_handle           INTEGER,\n"
"  pkcs11_slot             INTEGER DEFAULT 0,\n"
"  state                   INTEGER NOT NULL DEFAULT 1,  -- State enum value\n"
"  cryptographic_algorithm INTEGER,\n"
"  cryptographic_length    INTEGER,\n"
"  usage_mask              INTEGER,\n"
"  initial_date            REAL,\n"
"  activation_date         REAL,\n"
"  deactivation_date       REAL,\n"
"  destroy_date            REAL,\n"
"  compromise_date         REAL,\n"
"  revocation_reason       INTEGER,\n"
"  revocation_message      TEXT,\n"
"  sensitive               INTEGER DEFAULT 1,\n"
"  extractable             INTEGER DEFAULT 0,\n"
"  never_extractable       INTEGER DEFAULT 0,\n"
"  always_sensitive        INTEGER DEFAULT 1,\n"
"  owner_identity          TEXT,      -- Credential username, or \"anonymous\" (not an mTLS DN)\n"
"  key_format_type         INTEGER,\n"
"  raw_key_value           BLOB,      -- certificates, split-key parts, secret data\n"
"  archived                INTEGER DEFAULT 0,\n"
"  archive_date            REAL,\n"
"  created_at              REAL NOT NULL\n"
");")

    doc.add_paragraph()
    add_heading(doc, "Table: kmip_attributes", 2)
    add_code(doc,
"CREATE TABLE kmip_attributes (\n"
"  id          INTEGER PRIMARY KEY AUTOINCREMENT,\n"
"  object_uuid TEXT NOT NULL REFERENCES kmip_objects(uuid) ON DELETE CASCADE,\n"
"  attr_name   TEXT NOT NULL,   -- e.g. 'Name', 'Link', 'x-custom'\n"
"  attr_index  INTEGER DEFAULT 0,\n"
"  attr_value  TEXT NOT NULL    -- JSON-encoded\n"
");\n"
"CREATE INDEX idx_attr_lookup ON kmip_attributes(object_uuid, attr_name);")
    doc.add_paragraph()

    add_heading(doc, "Table: kmip_identity_roles  (added with access control)", 2)
    add_code(doc,
"CREATE TABLE kmip_identity_roles (\n"
"  identity TEXT NOT NULL,\n"
"  role     TEXT NOT NULL,      -- \"admin\" is the only role the code special-cases\n"
"  PRIMARY KEY (identity, role)\n"
");")
    doc.add_paragraph()

    add_heading(doc, "Table: kmip_object_grants  (added with access control)", 2)
    add_code(doc,
"CREATE TABLE kmip_object_grants (\n"
"  object_uuid TEXT NOT NULL REFERENCES kmip_objects(uuid) ON DELETE CASCADE,\n"
"  grantee     TEXT NOT NULL,\n"
"  permission  TEXT NOT NULL DEFAULT 'full',   -- \"read\" | \"full\"\n"
"  PRIMARY KEY (object_uuid, grantee)\n"
");\n"
"CREATE INDEX idx_grants_object ON kmip_object_grants(object_uuid);")
    doc.add_paragraph()
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 12. ERROR HANDLING
    # ════════════════════════════════════════════════════
    add_heading(doc, "12. Error Handling & Result Codes", 1)
    add_para(doc,
        "Every KMIP Batch Item response carries a ResultStatus enumeration and, on failure, "
        "a ResultReason and ResultMessage. Most PKCS#11 return codes are mapped to a KMIP "
        "result reason, but two important cases are raised entirely at the KMIP layer, "
        "before any PKCS#11 call is attempted:")
    doc.add_paragraph()

    add_table(doc,
        ["Source", "KMIP Result Reason", "Trigger"],
        [
            ["lifecycle/access_control.py", "PermissionDenied (NotAuthorized)", "check_owner() fails all three tiers — not owner, not admin, no sufficient grant"],
            ["pkcs11_shim capability probe", "OperationNotSupported",           "Algorithm/mode not in the token's live slot.get_mechanisms() list — rejected before the native call, not after it fails"],
        ],
        col_widths=[6.0, 5.5, 6.5]
    )
    doc.add_paragraph()

    add_table(doc,
        ["PKCS#11 Return Code", "KMIP Result Reason", "HTTP Analogy"],
        [
            ["CKR_OK",                       "(success)",                        "200 OK"],
            ["CKR_PIN_INCORRECT",            "AuthenticationNotSuccessful",      "401"],
            ["CKR_OBJECT_HANDLE_INVALID",    "ItemNotFound",                     "404"],
            ["CKR_KEY_HANDLE_INVALID",       "ItemNotFound",                     "404"],
            ["CKR_KEY_SIZE_RANGE",           "InvalidField (key length)",         "400"],
            ["CKR_MECHANISM_INVALID",        "CryptographicFailure",             "400"],
            ["CKR_ATTRIBUTE_READ_ONLY",      "InvalidField",                     "400"],
            ["CKR_DEVICE_ERROR",             "GeneralFailure",                   "500"],
            ["CKR_TOKEN_NOT_PRESENT",        "GeneralFailure",                   "503"],
        ],
        col_widths=[6.0, 6.0, 6.0]
    )
    doc.add_paragraph()
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 13. SECURITY CONSIDERATIONS
    # ════════════════════════════════════════════════════
    add_heading(doc, "13. Security Considerations", 1)
    add_para(doc,
        "The first four items below were part of the original design and remain accurate. "
        "The next two — access control and session concurrency — were the two items found, "
        "during a later hardening pass, to already be unsafe as originally built (not just "
        "\"missing polish\"), and are recorded here with what was actually done about them, "
        "including a rejected approach and why.", italic=True, size=9)
    doc.add_paragraph()

    items = [
        ("Key Material Exposure",
         "Keys with CKA_EXTRACTABLE=FALSE never leave the HSM. Get on such keys raises "
         "NotExtractable. Newly generated keys default to Sensitive=True, Extractable=False "
         "unless the request explicitly asks otherwise."),
        ("PIN / HSM Credential Protection",
         "The HSM SO-PIN and User-PIN should be stored in a secrets manager (e.g., "
         "HashiCorp Vault, AWS Secrets Manager), not a plaintext config file. This is an "
         "operational recommendation — the server itself takes the PIN as a constructor "
         "argument and does no secrets-manager integration of its own."),
        ("Metadata Store Integrity",
         "The metadata store is not encrypted at rest and there is no backup/restore tooling "
         "today (tracked in Section 14). Divergence between PKCS#11 token state and metadata "
         "store state has no automated detection or reconciliation procedure."),
        ("Batch Atomicity",
         "KMIP request batch items are processed independently — a failure partway through "
         "a batch does not roll back items that already succeeded."),
        ("Access Control",
         "Originally out of scope for this document; found later to be a real gap, not a "
         "future nice-to-have — every operation handler received an identity string but "
         "never checked it against anything, and \"authentication\" was one shared PIN "
         "shared by every caller. Fixed with the three-tier model in Section 10.2 "
         "(admin role, ownership, delegated grants). Remaining gap: no groups, no per-role "
         "operation allowlist, no dual-control / M-of-N approval for destructive operations."),
        ("Session Concurrency",
         "The server is multi-threaded (one thread per connection) but PKCS#11 access is not "
         "safe to parallelize casually. A session-pool design (one PKCS#11 session per thread, "
         "no cross-thread lock) was implemented and load-tested; it reproducibly either "
         "segfaulted the native pkcs11 extension or returned GeneralError/MechanismInvalid on "
         "most threads. Root cause: the python-pkcs11 binding calls C_Initialize(NULL), so the "
         "library never enables its own internal thread safety — separate sessions do not work "
         "around that. The fix in place is a single shared session behind a threading.RLock "
         "(pkcs11_shim/shim.py's @_synchronized decorator, applied to every session-touching "
         "method). This is the permanent design, not a stopgap: a real concurrent-session fix "
         "needs either a PKCS#11 binding that passes CKF_OS_LOCKING_OK at C_Initialize, or a "
         "multi-process worker pool — both larger changes than this codebase currently takes on."),
        ("Audit Logging",
         "Not implemented. Operations are recorded via Python's logging module only — nothing "
         "persisted, queryable, or tamper-evident. There is no answer today to \"who exported "
         "this key, and when\" beyond whatever remains in a log file."),
    ]
    for title, body in items:
        add_para(doc, title, bold=True)
        add_para(doc, body)
        doc.add_paragraph()

    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 14. IMPLEMENTATION ROADMAP
    # ════════════════════════════════════════════════════
    add_heading(doc, "14. Implementation Roadmap", 1)
    add_para(doc,
        "The phased plan originally in this section (TTLV parser through PQC extensions) has "
        "been delivered and superseded by actual build history; PQC (KMIP 3.0 / ML-KEM / ML-DSA) "
        "was never pursued and is out of scope. What follows is the current state instead: what's "
        "done, and what's genuinely still missing.")
    doc.add_paragraph()

    add_heading(doc, "14.1 Delivered", 2)
    add_table(doc,
        ["Area", "Status"],
        [
            ["Core protocol", "TTLV encoding/decoding, batching, BatchErrorContinuationOption, MaximumResponseSize"],
            ["Operations", "41 of 53 KMIP operations — the remaining 12 are session/async/vendor operations, a deliberate scope line (14.2)"],
            ["Lifecycle", "Full state machine, Archive/Recover, ReKey/ReKeyKeyPair/ReCertify, split-key XOR sharing"],
            ["Algorithm coverage", "15 of 40 CryptographicAlgorithm values, capability-probed at startup so unsupported ones fail cleanly rather than erroring deep in a PKCS#11 call"],
            ["Access control", "Owner-only enforcement, admin role, delegated per-object grants (Section 10.2)"],
            ["Session concurrency", "Single locked PKCS#11 session — the permanent design, not a stopgap (Section 13)"],
        ],
        col_widths=[4.5, 13.5]
    )
    doc.add_paragraph()

    add_heading(doc, "14.2 Deliberately out of scope", 2)
    add_para(doc,
        "Cancel, Poll, Notify, Put, Log, Login, Logout, DelegatedLogin, SetEndpointRole, PKCS11, "
        "Interop, ReProvision — session/async/vendor operations that don't fit this server's "
        "synchronous, per-request-authenticated model.")
    doc.add_paragraph()

    add_heading(doc, "14.3 Genuinely remaining", 2)
    add_table(doc,
        ["Area", "Gap"],
        [
            ["Audit", "No persisted, queryable, tamper-evident log of who did what to which object when"],
            ["TLS", "Optional, not enforced by default; static cert/key path, no rotation or ACME"],
            ["HSM validation", "SoftHSM2 is not FIPS 140-2/3 or Common Criteria validated"],
            ["RBAC depth", "No groups, no per-role operation allowlist, no dual control / M-of-N approval for destructive operations"],
            ["HA / backup", "Single process, single SQLite file, single HSM token; no clustering, replication, or coordinated backup/restore"],
            ["Key governance", "No cryptoperiod enforcement, auto-rotation, or expiry alerting — every lifecycle transition is reactive to an explicit client call"],
            ["Query surface", "3 of 12 QueryFunction values handled — the rest are narrow capability-discovery variants this server has nothing to report for"],
        ],
        col_widths=[4.5, 13.5]
    )
    doc.add_paragraph()
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 15. REFERENCES
    # ════════════════════════════════════════════════════
    add_heading(doc, "15. References", 1)

    refs = [
        "[1]  OASIS KMIP Specification v2.1 — https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html",
        "[2]  OASIS KMIP Test Cases v2.1 — https://docs.oasis-open.org/kmip/kmip-testcases/v2.1/",
        "[3]  OASIS KMIP Usage Guide v2.1 — https://docs.oasis-open.org/kmip/kmip-ug/v2.1/",
        "[4]  OASIS PKCS#11 Specification v3.0 — https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.0/",
        "[5]  RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3",
        "[6]  SoftHSM2 — https://github.com/opendnssec/SoftHSMv2",
        "[7]  python-pkcs11 — https://python-pkcs11.readthedocs.io/",
        "[8]  cascade-hsm-bridge (NLnet Labs) — https://github.com/NLnetLabs/cascade-hsm-bridge",
        "[9]  P6R KMIP Server Gateway — https://support.p6r.com/p6r/docs/ksg/",
        "[10] OpenKMIP / PyKMIP — https://github.com/OpenKMIP/PyKMIP",
    ]
    for ref in refs:
        p = doc.add_paragraph(ref, style="List Number")
        p.runs[0].font.size = Pt(9)

    doc.add_paragraph()

    # ── save ──
    doc.save(out_path)
    print(f"Document saved: {out_path}")

if __name__ == "__main__":
    out = "/home/user/Noida/KMIP_PKCS11_Design_Document.docx"
    build_document(out)
