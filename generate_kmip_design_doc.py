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
        ("cli", "srv",  "TLS ClientHello",                    "call"),
        ("srv", "cli",  "TLS ServerHello + Certificate",      "return"),
        ("cli", "srv",  "Client Certificate (mTLS)",          "call"),
        ("srv", "p11",  "C_Initialize()",                     "call"),
        ("p11", "hsm",  "HSM Driver Init",                    "call"),
        ("hsm", "p11",  "CKR_OK",                             "return"),
        ("srv", "p11",  "C_OpenSession(slot, CKF_RW_SESSION)","call"),
        ("p11", "hsm",  "Open secure channel to HSM",         "call"),
        ("hsm", "p11",  "hSession",                           "return"),
        ("srv", "p11",  "C_Login(hSession, CKU_USER, PIN)",   "call"),
        ("p11", "hsm",  "Authenticate operator",              "call"),
        ("hsm", "p11",  "CKR_OK",                             "return"),
        ("srv", "meta", "Open metadata DB",                   "call"),
        ("meta","srv",  "DB ready",                           "return"),
        ("srv", "cli",  "KMIP: Ready (Discover Versions resp)","return"),
    ]
    return draw_sequence("SD-01  System Initialization & HSM Login",
                         actors, msgs, figsize=(13, 8))

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
        ("srv", "srv",  "Auth + ACL check",                               "self"),
        ("srv", "meta", "SELECT hKey, state, extractable WHERE UUID",     "call"),
        ("meta","srv",  "hKey, state=Active, extractable=True",           "return"),
        ("srv", "srv",  "Check state == Active",                          "self"),
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
        ("srv", "srv", "Auth + ACL (CryptographicUsageMask)",    "self"),
        ("srv", "meta","SELECT hKey, state WHERE UUID",           "call"),
        ("meta","srv", "hKey, state=Active",                     "return"),
        ("srv", "p11", "C_EncryptInit(hSession, AES-GCM, hKey)", "call"),
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
        ("srv", "meta", "UPDATE state = Active WHERE UUID",                 "call"),
        ("meta","srv",  "OK",                                               "return"),
        ("srv", "cli",  "ActivateResponse()",                               "return"),
        ("cli", "srv",  "Revoke(UUID, reason=Superseded)",                  "call"),
        ("srv", "meta", "UPDATE state = Deactivated WHERE UUID",            "call"),
        ("meta","srv",  "OK",                                               "return"),
        ("srv", "p11",  "C_SetAttributeValue(hKey, CKA_ENCRYPT=False)",     "call"),
        ("p11", "hsm",  "Restrict key usage on HSM",                       "call"),
        ("hsm", "p11",  "CKR_OK",                                          "return"),
        ("srv", "cli",  "RevokeResponse()",                                 "return"),
        ("cli", "srv",  "Destroy(UUID)",                                    "call"),
        ("srv", "meta", "SELECT hKey WHERE UUID",                           "call"),
        ("meta","srv",  "hKey",                                             "return"),
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
        ("srv", "srv",  "Auth + ACL",                                                  "self"),
        ("srv", "meta", "SELECT UUID WHERE name='mykey' AND type=Sym AND state=Active","call"),
        ("meta","srv",  "[UUID1, UUID2, ...]",                                         "return"),
        ("srv", "p11",  "C_FindObjectsInit(attr template) [optional verify]",          "call"),
        ("p11", "hsm",  "Enumerate matching HSM objects",                              "call"),
        ("hsm", "p11",  "hKey list",                                                   "return"),
        ("p11", "srv",  "hKey list",                                                   "return"),
        ("srv", "srv",  "Intersect metadata results + HSM results",                    "self"),
        ("srv", "cli",  "LocateResponse([UUID1, UUID2])",                              "return"),
    ]
    return draw_sequence("SD-07  Locate Operation",
                         actors, msgs, figsize=(13, 8))

def diag_auth():
    actors = [
        ("cli",  "KMIP Client",  "client"),
        ("srv",  "KMIP Server",  "server"),
        ("tls",  "TLS Layer",    "pkcs11"),
        ("acl",  "ACL / AuthN",  "meta"),
    ]
    msgs = [
        ("cli", "tls", "TCP connect",                                              "call"),
        ("tls", "cli", "TLS 1.3 ServerHello",                                     "return"),
        ("cli", "tls", "Client Certificate (X.509)",                              "call"),
        ("tls", "srv", "Client identity (Subject DN / SAN)",                      "call"),
        ("srv", "acl", "Resolve identity → KMIP principal",                       "call"),
        ("acl", "srv", "Principal + permission set",                              "return"),
        ("cli", "srv", "KMIP Request + Authentication{UsernamePassword / Token}","call"),
        ("srv", "acl", "Validate credential",                                     "call"),
        ("acl", "srv", "Combined identity confirmed",                             "return"),
        ("srv", "srv", "Apply ACL to requested operation",                        "self"),
        ("srv", "cli", "KMIP Response (allowed) OR ResultStatus=OperationFailed","return"),
    ]
    return draw_sequence("SD-08  Authentication & Authorization Flow",
                         actors, msgs, figsize=(13, 8))


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
        ("10", "Authentication Mechanisms"),
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
        "KMIP versions covered: 1.4 and 2.1 (with 3.0 PQC extensions noted).",
        "PKCS#11 (Cryptoki) version: 2.40 / 3.0.",
        "Transport: TLS 1.3 over TCP (port 5696).",
        "Authentication: mTLS + KMIP credential (username/password, device credential).",
        "Managed objects: Symmetric Keys, Asymmetric Key Pairs, Certificates, Secret Data, Opaque Objects.",
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
         "Validates mTLS client certificates and KMIP Credential structures "
         "(UsernamePassword, DeviceCredential, AttestationCredential). Maps identities "
         "to KMIP principals and enforces CryptographicUsageMask per operation."),
        ("PKCS#11 Shim",
         "Wraps the vendor PKCS#11 shared library. Manages slot/token enumeration, "
         "session pooling (C_OpenSession / C_CloseSession), login (C_Login), "
         "and provides a clean Go/Rust/C API to the layers above."),
        ("Metadata Store",
         "Stores KMIP-specific attributes that PKCS#11 does not natively support: "
         "Unique Identifier (UUID), Activation Date, Deactivation Date, State, "
         "Name, Link, Application Specific Information, Revocation Reason, and "
         "PKCS#11 handle reference. SQLite for single-node; PostgreSQL for HA."),
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
        "The following table shows how each KMIP operation maps to one or more PKCS#11 "
        "Cryptoki function calls. Operations marked 'Metadata only' require no HSM call.")
    doc.add_paragraph()

    add_table(doc,
        ["KMIP Operation", "PKCS#11 Call(s)", "Notes"],
        [
            ["Create (symmetric)",    "C_GenerateKey",                          "Template built from CryptoAlg + KeyLength"],
            ["Create Key Pair",       "C_GenerateKeyPair",                      "Two handles returned: hPub, hPriv"],
            ["Register",              "C_CreateObject",                         "Client supplies key material"],
            ["Import (v2.0+)",        "C_CreateObject / C_UnwrapKey",          "Optionally unwrap if wrapped"],
            ["Get",                   "C_GetAttributeValue(CKA_VALUE)",         "Only if CKA_EXTRACTABLE = TRUE"],
            ["Export (v2.0+)",        "C_WrapKey or C_GetAttributeValue",       "Wrapping key UUID specified"],
            ["Locate",                "C_FindObjectsInit + C_FindObjects",      "Cross-reference with Metadata Store"],
            ["Destroy",               "C_DestroyObject",                        "HSM zeroizes key material"],
            ["Activate",              "Metadata only",                          "State → Active; no HSM call needed"],
            ["Revoke (deactivate)",   "C_SetAttributeValue(CKA_ENCRYPT=F)",    "Restrict usage on HSM"],
            ["Revoke (compromise)",   "C_SetAttributeValue + C_DestroyObject", "Compromise + optional destroy"],
            ["Encrypt",               "C_EncryptInit + C_Encrypt",             "IV/AAD passed in KMIP request"],
            ["Decrypt",               "C_DecryptInit + C_Decrypt",             "Tag verified for AEAD modes"],
            ["Sign",                  "C_SignInit + C_Sign",                   "Mechanism = CKM_RSA_PKCS, CKM_ECDSA…"],
            ["Signature Verify",      "C_VerifyInit + C_Verify",               ""],
            ["MAC",                   "C_SignInit (HMAC mechanism)",            "CKM_SHA256_HMAC etc."],
            ["MAC Verify",            "C_VerifyInit (HMAC mechanism)",          ""],
            ["Derive Key",            "C_DeriveKey",                            "ECDH, HKDF mechanisms"],
            ["Re-key",                "C_GenerateKey + C_DestroyObject (old)", "New UUID linked to old"],
            ["Get Attributes",        "C_GetAttributeValue",                    "Merge with Metadata Store"],
            ["Set Attribute",         "C_SetAttributeValue",                    "For mutable PKCS#11 attrs only"],
            ["Query",                 "C_GetInfo + C_GetMechanismList",        "Capabilities discovery"],
            ["Discover Versions",     "Metadata only",                          "Returns supported KMIP versions"],
            ["RNG Retrieve",          "C_GenerateRandom",                       "HSM TRNG output"],
            ["RNG Seed",              "C_SeedRandom",                           "Optional on HSMs"],
        ],
        col_widths=[5.0, 6.0, 7.0]
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
        ],
        col_widths=[5.5, 4.5, 8.0]
    )
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

    add_table(doc,
        ["Parameter", "Value"],
        [
            ["Default TCP port",         "5696 (IANA assigned to KMIP)"],
            ["TLS version",              "TLS 1.3 (minimum); TLS 1.2 allowed for legacy clients"],
            ["Client authentication",    "Mutual TLS (mTLS) — mandatory"],
            ["Cipher suites (TLS 1.3)", "TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256"],
            ["Certificate format",       "X.509 v3 with SubjectAltName"],
            ["Session resumption",       "TLS 1.3 session tickets; max lifetime 24 h"],
            ["KMIP over HTTPS",          "Optional — same TTLV payload over HTTPS/443"],
            ["PQC (KMIP 3.0)",          "TLS 1.3 + Kyber/ML-KEM hybrid key exchange"],
        ],
        col_widths=[6.0, 12.0]
    )
    doc.add_paragraph()
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 10. AUTHENTICATION MECHANISMS
    # ════════════════════════════════════════════════════
    add_heading(doc, "10. Authentication Mechanisms", 1)
    add_para(doc,
        "Authentication is two-layered: channel-level (TLS) and application-level "
        "(KMIP Credential). Both layers are evaluated; the server uses the intersection "
        "of identities to determine the effective KMIP principal.")
    doc.add_paragraph()

    add_table(doc,
        ["Credential Type", "KMIP Structure", "Use Case"],
        [
            ["Mutual TLS",          "TLS client certificate (X.509)",              "Machine / service authentication"],
            ["UsernameAndPassword", "Credential{UsernamePasswordCredential}",      "Human operator authentication"],
            ["Device Credential",   "Credential{DeviceCredential}",                "IoT / embedded device authentication"],
            ["Attestation",         "Credential{AttestationCredential}",           "TPM / hardware attestation"],
            ["One-Time Password",   "Credential{OneTimePasswordCredential}",       "MFA scenarios"],
            ["Hashed Password",     "Credential{HashedPasswordCredential}",        "Legacy system integration"],
        ],
        col_widths=[4.5, 7.0, 6.5]
    )
    doc.add_paragraph()
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 11. METADATA STORE SCHEMA
    # ════════════════════════════════════════════════════
    add_heading(doc, "11. Metadata Store Schema", 1)
    add_para(doc,
        "The Metadata Store persists KMIP-specific attributes not natively held "
        "in PKCS#11. Two primary tables are required.")
    doc.add_paragraph()

    add_heading(doc, "Table: kmip_objects", 2)
    add_code(doc,
"CREATE TABLE kmip_objects (\n"
"  uuid              TEXT PRIMARY KEY,   -- KMIP Unique Identifier\n"
"  object_type       TEXT NOT NULL,      -- SymmetricKey | PublicKey | PrivateKey | ...\n"
"  pkcs11_handle     BIGINT,             -- CK_OBJECT_HANDLE (0 = metadata-only)\n"
"  pkcs11_slot       INT,                -- CK_SLOT_ID\n"
"  state             TEXT NOT NULL,      -- PreActive | Active | Deactivated | Compromised | Destroyed\n"
"  cryptographic_algorithm TEXT,\n"
"  cryptographic_length    INT,\n"
"  usage_mask        TEXT,               -- JSON array of allowed operations\n"
"  initial_date      TIMESTAMP,\n"
"  activation_date   TIMESTAMP,\n"
"  deactivation_date TIMESTAMP,\n"
"  destroy_date      TIMESTAMP,\n"
"  compromise_date   TIMESTAMP,\n"
"  revocation_reason TEXT,\n"
"  sensitive         BOOLEAN DEFAULT TRUE,\n"
"  extractable       BOOLEAN DEFAULT FALSE,\n"
"  owner_identity    TEXT,               -- KMIP principal (from mTLS DN)\n"
"  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n"
");")

    doc.add_paragraph()
    add_heading(doc, "Table: kmip_attributes", 2)
    add_code(doc,
"CREATE TABLE kmip_attributes (\n"
"  id          SERIAL PRIMARY KEY,\n"
"  object_uuid TEXT NOT NULL REFERENCES kmip_objects(uuid),\n"
"  attr_name   TEXT NOT NULL,   -- e.g. 'Name', 'Link', 'x-custom'\n"
"  attr_index  INT  DEFAULT 0,  -- for multi-valued attrs\n"
"  attr_value  TEXT NOT NULL\n"
");\n"
"CREATE INDEX idx_attr_lookup ON kmip_attributes(object_uuid, attr_name);")
    doc.add_paragraph()
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 12. ERROR HANDLING
    # ════════════════════════════════════════════════════
    add_heading(doc, "12. Error Handling & Result Codes", 1)
    add_para(doc,
        "Every KMIP Batch Item response carries a ResultStatus enumeration and, on failure, "
        "a ResultReason and ResultMessage. PKCS#11 return codes must be mapped to "
        "KMIP result reasons.")
    doc.add_paragraph()

    add_table(doc,
        ["PKCS#11 Return Code", "KMIP Result Reason", "HTTP Analogy"],
        [
            ["CKR_OK",                       "(success)",                        "200 OK"],
            ["CKR_PIN_INCORRECT",            "AuthenticationNotSuccessful",      "401"],
            ["CKR_USER_NOT_LOGGED_IN",       "NotAuthorized",                    "403"],
            ["CKR_OBJECT_HANDLE_INVALID",    "ItemNotFound",                     "404"],
            ["CKR_KEY_HANDLE_INVALID",       "ItemNotFound",                     "404"],
            ["CKR_KEY_SIZE_RANGE",           "InvalidField (key length)",         "400"],
            ["CKR_MECHANISM_INVALID",        "InvalidMessage",                   "400"],
            ["CKR_ATTRIBUTE_READ_ONLY",      "InvalidField",                     "400"],
            ["CKR_DEVICE_ERROR",             "GeneralFailure",                   "500"],
            ["CKR_TOKEN_NOT_PRESENT",        "GeneralFailure",                   "503"],
            ["CKR_SESSION_COUNT",            "GeneralFailure (session pool full)","503"],
            ["CKR_OPERATION_NOT_INITIALIZED","OperationNotSupported",            "501"],
        ],
        col_widths=[6.0, 6.0, 6.0]
    )
    doc.add_paragraph()
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 13. SECURITY CONSIDERATIONS
    # ════════════════════════════════════════════════════
    add_heading(doc, "13. Security Considerations", 1)

    items = [
        ("Key Material Exposure",
         "Keys with CKA_EXTRACTABLE=FALSE never leave the HSM. The KMIP 'Get' operation "
         "on such keys MUST return ResultReason=PermissionDenied. Sensitive attribute "
         "MUST be set TRUE on all newly generated keys."),
        ("PIN / HSM Credential Protection",
         "The HSM SO-PIN and User-PIN must be stored in a secrets manager (e.g., "
         "HashiCorp Vault, AWS Secrets Manager). Never store in plaintext config files."),
        ("Metadata Store Integrity",
         "The Metadata Store must be encrypted at rest and backed up with integrity "
         "verification. Divergence between PKCS#11 token state and Metadata Store "
         "state must trigger an alert and reconciliation procedure."),
        ("Session Hijacking",
         "TLS 1.3 with mTLS prevents session hijacking. KMIP request batch items "
         "must be validated atomically — partial batch success must not leave "
         "the system in an inconsistent state."),
        ("Audit Logging",
         "Every KMIP operation (success or failure), including operator, timestamp, "
         "operation type, and object UUID, must be written to an immutable audit log."),
        ("KMIP 3.0 PQC Readiness",
         "Plan for ML-KEM and ML-DSA by ensuring the HSM firmware supports FIPS 203/204/205 "
         "mechanisms and the TLS stack supports hybrid key exchange "
         "(X25519Kyber768Draft00 or equivalent)."),
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

    add_table(doc,
        ["Phase", "Deliverable", "Duration"],
        [
            ["Phase 1", "TTLV parser + serializer (all primitive types + structures)",   "3 weeks"],
            ["Phase 2", "PKCS#11 shim: session pool, C_GenerateKey, C_DestroyObject",   "2 weeks"],
            ["Phase 3", "Metadata Store schema + CRUD layer",                            "1 week"],
            ["Phase 4", "Create, Register, Get, Destroy, Locate operations",             "3 weeks"],
            ["Phase 5", "Lifecycle engine (Activate, Revoke, state machine)",            "2 weeks"],
            ["Phase 6", "Encrypt, Decrypt, Sign, Verify, MAC operations",                "2 weeks"],
            ["Phase 7", "TLS 1.3 / mTLS server, Auth module, ACL",                      "2 weeks"],
            ["Phase 8", "KMIP 2.1 compliance testing (OASIS test vectors)",              "2 weeks"],
            ["Phase 9", "Derive Key, Re-key, Import/Export, batch support",              "2 weeks"],
            ["Phase 10","PQC extensions (KMIP 3.0 ML-KEM, ML-DSA, TLS hybrid)",         "3 weeks"],
        ],
        col_widths=[3.0, 12.0, 3.0]
    )
    doc.add_paragraph()
    doc.add_page_break()

    # ════════════════════════════════════════════════════
    # 15. REFERENCES
    # ════════════════════════════════════════════════════
    add_heading(doc, "15. References", 1)

    refs = [
        "[1]  OASIS KMIP Specification v2.1 — https://docs.oasis-open.org/kmip/kmip-spec/v2.1/",
        "[2]  OASIS KMIP Profiles v2.1 — https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/",
        "[3]  OASIS KMIP Usage Guide v2.1 — https://docs.oasis-open.org/kmip/kmip-ug/v2.1/",
        "[4]  KMIP Specification v3.0 CSD01 (August 2024) — https://docs.oasis-open.org/kmip/kmip-spec/v3.0/",
        "[5]  OASIS PKCS#11 v3.0 — https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/",
        "[6]  RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3",
        "[7]  NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)",
        "[8]  NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)",
        "[9]  NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard (SLH-DSA)",
        "[10] cascade-hsm-bridge (NLnet Labs) — https://github.com/NLnetLabs/cascade-hsm-bridge",
        "[11] P6R KMIP Server Gateway — https://support.p6r.com/p6r/docs/ksg/",
        "[12] OpenKMIP / PyKMIP — https://github.com/OpenKMIP/PyKMIP",
        "[13] KMIP Additional Message Encodings v1.0 — https://docs.oasis-open.org/kmip/kmip-addtl-msg-enc/",
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
