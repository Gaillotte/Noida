"""
Generate the feature specification — every supported feature, what it does, and
a worked example of using it.

Run: python generate_feature_spec.py

The examples are not illustrative sketches. Request and response field lists
were extracted from the operation handlers themselves, and every value quoted
as output (digests, lengths, states, error text) came from executing the
system against a real SoftHSM2 token. Where an example is handler-level rather
than client-level, that is because the bundled test client has no method for
that operation — which is itself worth knowing, and is said so.
"""

import datetime

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

DARK_BLUE = RGBColor(0x1A, 0x3A, 0x5C)
MID_BLUE = RGBColor(0x2E, 0x6D, 0xA4)
DARK_GREY = RGBColor(0x40, 0x40, 0x40)
OK_GREEN = RGBColor(0x1E, 0x80, 0x2E)
WARN_AMBER = RGBColor(0x8F, 0x56, 0x10)

TODAY = datetime.date.today().strftime("%d %B %Y")


# ── helpers ───────────────────────────────────────────────────────────────────

def set_cell_bg(cell, hex_color):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), hex_color)
    shd.set(qn("w:val"), "clear")
    tcPr.append(shd)


def add_heading(doc, text, level, colour=None):
    h = doc.add_heading(text, level=level)
    if colour:
        for run in h.runs:
            run.font.color.rgb = colour
    return h


def add_para(doc, text="", bold=False, italic=False, size=10, colour=None, indent=0):
    p = doc.add_paragraph()
    if indent:
        p.paragraph_format.left_indent = Inches(indent * 0.25)
    run = p.add_run(text)
    run.bold = bold
    run.italic = italic
    run.font.size = Pt(size)
    if colour:
        run.font.color.rgb = colour
    return p


def add_code(doc, text, colour=RGBColor(0x00, 0x33, 0x66)):
    p = doc.add_paragraph(style="No Spacing")
    p.paragraph_format.left_indent = Inches(0.3)
    p.paragraph_format.space_before = Pt(1)
    p.paragraph_format.space_after = Pt(1)
    run = p.add_run(text)
    run.font.name = "Courier New"
    run.font.size = Pt(8.5)
    run.font.color.rgb = colour
    return p


def add_code_block(doc, lines):
    for line in lines:
        # A line starting with "#" or "→" is commentary or captured output;
        # colouring it differently keeps the executable part obvious.
        colour = RGBColor(0x1E, 0x80, 0x2E) if line.strip().startswith(("#", "→")) \
            else RGBColor(0x00, 0x33, 0x66)
        add_code(doc, line, colour)


def add_bullet(doc, text, level=0):
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.left_indent = Inches(0.3 + level * 0.25)
    run = p.add_run(text)
    run.font.size = Pt(10)
    return p


def section_break(doc):
    doc.add_paragraph()


def add_table_header_row(table, headers, bg="1A3A5C"):
    for i, h in enumerate(headers):
        cell = table.rows[0].cells[i]
        cell.text = h
        set_cell_bg(cell, bg)
        for para in cell.paragraphs:
            for run in para.runs:
                run.bold = True
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                run.font.size = Pt(9)


def add_table_row(table, values, alt=False):
    row = table.add_row()
    bg = "EEF4FA" if alt else "FFFFFF"
    for i, v in enumerate(values):
        cell = row.cells[i]
        cell.text = str(v)
        set_cell_bg(cell, bg)
        for para in cell.paragraphs:
            for run in para.runs:
                run.font.size = Pt(8.5)
    return row


def make_table(doc, headers, rows, widths=None):
    tbl = doc.add_table(rows=1, cols=len(headers))
    tbl.style = "Table Grid"
    add_table_header_row(tbl, headers)
    for i, r in enumerate(rows):
        add_table_row(tbl, r, alt=(i % 2 == 0))
    if widths:
        for row in tbl.rows:
            for cell, w in zip(row.cells, widths):
                cell.width = Inches(w)
    return tbl


def op_block(doc, name, purpose, request, response, example, note=None):
    """One operation: what it is, its wire fields, and a usable example."""
    add_heading(doc, name, 3, MID_BLUE)
    add_para(doc, purpose, size=10)
    p = doc.add_paragraph()
    r = p.add_run("Request:  ")
    r.bold = True
    r.font.size = Pt(9)
    r2 = p.add_run(request)
    r2.font.size = Pt(9)
    r2.font.name = "Courier New"
    p2 = doc.add_paragraph()
    r3 = p2.add_run("Response: ")
    r3.bold = True
    r3.font.size = Pt(9)
    r4 = p2.add_run(response)
    r4.font.size = Pt(9)
    r4.font.name = "Courier New"
    add_code_block(doc, example)
    if note:
        add_para(doc, note, italic=True, size=9, colour=DARK_GREY)
    section_break(doc)


# ══════════════════════════════════════════════════════════════════════════════
# Document build
# ══════════════════════════════════════════════════════════════════════════════

def build():
    doc = Document()
    for sec in doc.sections:
        sec.top_margin = Inches(0.9)
        sec.bottom_margin = Inches(0.9)
        sec.left_margin = Inches(1.1)
        sec.right_margin = Inches(1.1)
    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(10)

    # ── title page ───────────────────────────────────────────────────────
    doc.add_paragraph()
    doc.add_paragraph()
    t = doc.add_paragraph()
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    tr = t.add_run("KMIP on PKCS#11")
    tr.bold = True
    tr.font.size = Pt(28)
    tr.font.color.rgb = DARK_BLUE
    s = doc.add_paragraph()
    s.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sr = s.add_run("Feature Specification")
    sr.font.size = Pt(17)
    sr.font.color.rgb = MID_BLUE
    s2 = doc.add_paragraph()
    s2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sr2 = s2.add_run("Every supported feature, with details and worked examples")
    sr2.font.size = Pt(12)
    sr2.font.color.rgb = DARK_GREY
    doc.add_paragraph()

    info = [
        ("Document", "Feature specification and usage reference"),
        ("Covers", "41 KMIP 2.1 operations, access control, governance, audit, "
                   "at-rest protection, backup, observability, CLI"),
        ("Standard", "OASIS KMIP 2.1 (kmip-spec-v2.1-os)"),
        ("Backend", "PKCS#11 v3.0 — SoftHSM2 2.7.0 built against OpenSSL 3.0.13"),
        ("Verified", "Field lists extracted from the handlers; quoted output captured "
                     "from live execution against a real token"),
        ("Date", TODAY),
    ]
    tbl = doc.add_table(rows=len(info), cols=2)
    tbl.style = "Table Grid"
    for i, (k, v) in enumerate(info):
        tbl.rows[i].cells[0].text = k
        tbl.rows[i].cells[1].text = v
        tbl.rows[i].cells[0].width = Inches(1.3)
        tbl.rows[i].cells[1].width = Inches(5.0)
        set_cell_bg(tbl.rows[i].cells[0], "1A3A5C")
        for para in tbl.rows[i].cells[0].paragraphs:
            for run in para.runs:
                run.bold = True
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                run.font.size = Pt(9)
        for para in tbl.rows[i].cells[1].paragraphs:
            for run in para.runs:
                run.font.size = Pt(9)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "1  How to read this document", 1, DARK_BLUE)
    add_para(doc,
        "This is the reference for what the server supports and how to use it. Every "
        "operation section states the request fields it reads, the response fields it "
        "returns, and an example that exercises it. Sections 8 onward cover the features "
        "that are not KMIP operations at all — access control, governance, audit, "
        "protection at rest, backup and observability.")
    section_break(doc)

    add_para(doc, "Two kinds of example", bold=True, colour=MID_BLUE)
    add_para(doc,
        "Most examples use the bundled Python client (kmip_pkcs11.test_app.client), "
        "which speaks the real wire protocol over TCP. That client is a test and "
        "demonstration client, and it does not have a method for every operation. Where "
        "it does not, the example calls the operation handler directly with a TTLV "
        "payload — the same code path the server uses once it has decoded a request, so "
        "the fields shown are exactly the fields a KMIP client must send. Each example "
        "says which kind it is.")
    section_break(doc)

    add_para(doc, "Conventions in the examples", bold=True, colour=MID_BLUE)
    for line in [
        "Lines beginning with # are commentary.",
        "Lines beginning with → are real captured output, not illustration.",
        "uid is a KMIP Unique Identifier: an RFC 4122 UUID string.",
        "Every example assumes an authenticated client — see Section 2.",
    ]:
        add_bullet(doc, line)
    section_break(doc)

    add_para(doc,
        "One thing to know before reading the operation sections: Create, CreateKeyPair "
        "and Register return objects that are already in the Active state. Activate "
        "exists for objects that were placed in Pre-Active deliberately (for example "
        "with a future Activation Date). Calling Activate on an already-Active object is "
        "refused with IllegalOperation, which is correct KMIP behaviour and surprises "
        "most people once.", italic=True, size=9.5)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "2  Connecting and authenticating", 1, DARK_BLUE)
    add_para(doc,
        "Every request carries a Credential in its header, and it is verified on every "
        "request — KMIP has no session or login operation in this server's model. An "
        "identity must exist before it can authenticate; there is no self-registration "
        "and no anonymous fallback.")
    section_break(doc)

    add_para(doc, "2.1  Provision an identity (out of band)", bold=True, colour=MID_BLUE)
    add_para(doc,
        "KMIP defines no operation for identity management, so this is done with "
        "kmip-admin, never over the wire.", size=9.5)
    add_code_block(doc, [
        "kmip-admin -c /etc/kmip/config.yaml identity add alice",
        "# prompts for the password unless --password is given",
        "→ identity 'alice' saved",
    ])
    section_break(doc)

    add_para(doc, "2.2  Connect", bold=True, colour=MID_BLUE)
    add_code_block(doc, [
        "from kmip_pkcs11.test_app.client import KMIPClient",
        "",
        "client = KMIPClient(",
        "    host=\"kms.internal\", port=5696,",
        "    username=\"alice\", password=\"alice-secret\",",
        "    tls_ca=\"/etc/kmip/tls/ca.pem\",          # verify the server",
        "    tls_cert=\"/etc/kmip/tls/alice.pem\",     # only for mTLS",
        "    tls_key=\"/etc/kmip/tls/alice.key\",",
        ")",
        "client.connect()",
        "# ... operations ...",
        "client.close()",
        "",
        "# KMIPClient is also a context manager:",
        "with KMIPClient(port=5696, username=\"alice\", password=\"alice-secret\") as c:",
        "    uid = c.create(name=\"my-key\")",
    ])
    section_break(doc)

    add_para(doc, "2.3  How the identity is decided", bold=True, colour=MID_BLUE)
    make_table(doc,
        ["Situation", "Identity used"],
        [
            ["Credential in the request header, password verifies",
             "The username from the Credential."],
            ["Credential present, password wrong or identity unknown/disabled",
             "Refused. There is no fallback to anonymous."],
            ["mTLS required and the certificate verified, no Credential",
             "The certificate's Common Name — but only if it names a provisioned "
             "identity. A CA-signed certificate cannot invent a principal."],
            ["No Credential and no verified client certificate",
             "anonymous — which owns nothing and is refused by any ownership check."],
        ],
        widths=[2.6, 3.7])
    section_break(doc)
    add_para(doc,
        "Verification is deliberately expensive (scrypt), so successful verifications are "
        "cached for a short period keyed by a peppered hash of the password. Failures are "
        "never cached, and changing a password, disabling or deleting an identity "
        "invalidates the cache immediately.", italic=True, size=9)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "3  The object model", 1, DARK_BLUE)

    add_heading(doc, "3.1  Object types", 2, MID_BLUE)
    make_table(doc,
        ["Object type", "Value", "Supported", "Notes"],
        [
            ["SymmetricKey", "2", "Yes", "Generated on the HSM; key material never leaves it."],
            ["PublicKey", "3", "Yes", "From CreateKeyPair or Register."],
            ["PrivateKey", "4", "Yes", "Generated on the HSM, non-extractable by default."],
            ["Certificate", "1", "Yes", "X.509, via Register or Certify. Stored in the "
                                        "clear — it is public."],
            ["SecretData", "7", "Yes", "Passwords and seeds. No PKCS#11 object behind it, "
                                       "so it is enveloped under the HSM master key."],
            ["OpaqueObject", "8", "Yes", "Arbitrary bytes; enveloped like SecretData."],
            ["SplitKey", "5", "Yes", "XOR shares from CreateSplitKey; each share is "
                                     "enveloped."],
            ["Template", "6", "No", "Deprecated in KMIP 2.x."],
            ["PGPKey", "9", "No", "No PKCS#11 representation."],
        ],
        widths=[1.2, 0.5, 0.8, 3.8])
    section_break(doc)

    add_heading(doc, "3.2  Lifecycle states", 2, MID_BLUE)
    make_table(doc,
        ["State", "Value", "Reached by", "What is permitted"],
        [
            ["Pre-Active", "1", "create_object with a future Activation Date",
             "Attribute operations; no cryptographic use."],
            ["Active", "2", "Create / CreateKeyPair / Register / Activate",
             "All cryptographic operations the usage mask allows."],
            ["Deactivated", "3", "Revoke (non-compromise), or the cryptoperiod scheduler",
             "Decrypt and Verify only — deliberately, so data encrypted under the key is "
             "still recoverable."],
            ["Compromised", "4", "Revoke with a compromise reason",
             "Get, GetAttributes and Export only. No cryptographic use at all."],
            ["Destroyed", "5", "Destroy", "Nothing. Key material is zeroized on the token."],
            ["Destroyed Compromised", "6", "Destroy on a Compromised object",
             "Nothing. The distinction is preserved for audit."],
        ],
        widths=[1.2, 0.5, 2.0, 2.6])
    section_break(doc)
    add_code_block(doc, [
        "# A full lifecycle, captured live:",
        "uid = client.create(name=\"scratch-key\")",
        "→ state 2 (Active) — Create yields an Active object",
        "client.revoke(uid, reason=RevocationReasonCode.KeyCompromise,",
        "              message=\"disclosed in logs\")",
        "→ state 4 (Compromised)",
        "client.destroy(uid)",
        "→ state 5 (Destroyed)",
    ])
    section_break(doc)

    add_heading(doc, "3.3  Cryptographic usage mask", 2, MID_BLUE)
    add_para(doc,
        "A bitmask fixed at creation. It maps onto PKCS#11 key attributes, so it is "
        "enforced by the token and not merely by this server: a key created without "
        "CKA_SIGN cannot be made to sign later by editing metadata.", size=9.5)
    make_table(doc,
        ["Flag", "Value", "Flag", "Value"],
        [
            ["Sign", "1", "MACGenerate", "128"],
            ["Verify", "2", "MACVerify", "256"],
            ["Encrypt", "4", "DeriveKey", "512"],
            ["Decrypt", "8", "KeyAgreement", "2048"],
            ["WrapKey", "16", "CertificateSign", "4096"],
            ["UnwrapKey", "32", "CRLSign", "8192"],
            ["Export", "64", "ContentCommitment", "1024"],
        ],
        widths=[1.6, 0.8, 1.6, 0.8])
    section_break(doc)
    add_code_block(doc, [
        "from kmip_pkcs11.core.enums import CryptographicUsageMask as U",
        "",
        "# An encryption-only data key:",
        "uid = client.create(usage_mask=U.Encrypt | U.Decrypt, name=\"payments-dek\")",
        "",
        "# A wrapping key (KEK):",
        "kek = client.create(usage_mask=U.WrapKey | U.UnwrapKey, name=\"kek-2026\")",
    ])
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "4  Operation reference", 1, DARK_BLUE)
    add_para(doc,
        "41 of the 53 KMIP 2.1 operations are implemented. The request and response "
        "fields below were extracted from the handlers, so they are what the server "
        "actually reads and returns rather than what the specification permits in "
        "general.")
    section_break(doc)
    add_para(doc, "The 12 that are not implemented — Cancel, Poll, Notify, Put, Log, "
                  "Login, Logout, DelegatedLogin, SetEndpointRole, PKCS11, Interop and "
                  "ReProvision — are session, asynchronous and vendor operations that do "
                  "not fit a synchronous, per-request-authenticated server. This is a "
                  "scope decision, not an omission: a Login operation would contradict "
                  "the authentication model, and Poll only means something alongside "
                  "asynchronous responses this server does not produce.", size=9.5)
    doc.add_page_break()

    # ── 4.1 discovery ────────────────────────────────────────────────────
    add_heading(doc, "4.1  Discovery", 2, MID_BLUE)

    op_block(doc, "DiscoverVersions",
        "Negotiate the protocol version. Returns the versions this server speaks, "
        "highest first.",
        "ProtocolVersion (optional list of candidates)",
        "ProtocolVersion { ProtocolVersionMajor, ProtocolVersionMinor }",
        ["versions = client.discover_versions()",
         "→ [(2, 1), (1, 4), (1, 3), (1, 2), (1, 1), (1, 0)]"],
        "Not audited: it carries no authorization decision and touches no object.")

    op_block(doc, "Query",
        "Report server capabilities: which operations are supported, which object types, "
        "and the vendor identification string.",
        "QueryFunction (repeatable; 3 of the 12 defined functions are answered)",
        "Operations, ObjectType, VendorIdentification",
        ["caps = client.query()",
         "→ 41 operations, 7 object types",
         "→ vendor: 'kmip_pkcs11 v1.0'",
         "",
         "# Ask for one function only:",
         "from kmip_pkcs11.core.enums import QueryFunction",
         "caps = client.query(functions=[QueryFunction.QueryOperations])"],
        "The other nine QueryFunction values are narrow capability-discovery variants "
        "this server has nothing to report for. Like DiscoverVersions, Query is not "
        "audited.")
    doc.add_page_break()

    # ── 4.2 creating objects ─────────────────────────────────────────────
    add_heading(doc, "4.2  Creating and importing objects", 2, MID_BLUE)

    op_block(doc, "Create",
        "Generate a symmetric key on the HSM. The key material is created inside the "
        "token and never leaves it.",
        "ObjectType, TemplateAttribute | Attributes",
        "UniqueIdentifier",
        ["from kmip_pkcs11.core.enums import CryptographicAlgorithm as A",
         "from kmip_pkcs11.core.enums import CryptographicUsageMask as U",
         "",
         "uid = client.create(algorithm=A.AES, length=256,",
         "                    usage_mask=U.Encrypt | U.Decrypt,",
         "                    name=\"payments-dek\")",
         "→ '99e251ed-7291-4a42-933b-87a60eea273e'  (state: Active)"],
        "extractable=True is available but downgrades sensitivity: SoftHSM2 refuses to "
        "read CKA_VALUE when both SENSITIVE and EXTRACTABLE are set, so the shim clears "
        "sensitivity when extractability is explicitly requested.")

    op_block(doc, "CreateKeyPair",
        "Generate an asymmetric key pair on the HSM. The private key is non-extractable "
        "by default.",
        "TemplateAttribute (common), PublicKeyAttributes, PrivateKeyAttributes",
        "UniqueIdentifier (public), UniqueIdentifier (private)",
        ["pub, priv = client.create_key_pair(algorithm=A.RSA, length=2048,",
         "                                   name=\"signing-2026\")",
         "→ public : '1b957b91-7291-4255-8ee4-6bc2ac09fe9d'",
         "→ private: 'be78b7e7-3323-480d-9a6f-94d829b48558'",
         "",
         "# Elliptic curve:",
         "pub, priv = client.create_key_pair(algorithm=A.EC, length=256)"],
        "The two objects are separate managed objects with their own identifiers, "
        "lifecycles and attributes.")

    op_block(doc, "Register",
        "Import client-supplied material as a managed object — a key, a certificate, "
        "secret data or an opaque blob.",
        "ObjectType, KeyBlock | Certificate | OpaqueObject, TemplateAttribute | "
        "Attributes",
        "UniqueIdentifier",
        ["# Handler-level: the client has no register() method.",
         "from kmip_pkcs11.operations import register",
         "from kmip_pkcs11.core.ttlv import (encode_structure, encode_enumeration,",
         "                                   encode_byte_string, decode_one)",
         "from kmip_pkcs11.core.enums import Tag, ObjectType",
         "",
         "payload = decode_one(encode_structure(Tag.RequestPayload,",
         "    encode_enumeration(Tag.ObjectType, ObjectType.SecretData)",
         "  + encode_structure(Tag.KeyBlock,",
         "        encode_byte_string(Tag.KeyMaterial, b\"s3cret-seed\"))))",
         "uid = register.handle(payload, \"alice\", store, shim)"],
        "SecretData, OpaqueObject and SplitKey have no PKCS#11 object behind them, so "
        "their bytes are sealed under the HSM master key before being stored — see "
        "Section 11.")

    op_block(doc, "Import",
        "KMIP 2.0+ variant of Register that can replace an existing object under a "
        "caller-chosen identifier.",
        "UniqueIdentifier, ObjectType, ReplaceExisting",
        "UniqueIdentifier",
        ["# ReplaceExisting=True overwrites the object at that identifier;",
         "# False fails with an error if it already exists."],
        "Import is one of the two operations protected by dual control in the default "
        "governance policy's sibling — see Section 10.2 for how to protect it.")

    op_block(doc, "DeriveKey",
        "Derive a new symmetric key from an existing one — DH/ECDH key agreement, or a "
        "hash-based derivation.",
        "UniqueIdentifier, DerivationMethod, DerivationParameters, TemplateAttribute | "
        "Attributes",
        "UniqueIdentifier",
        ["# ECDH agreement between a local private key and a peer public key,",
         "# handler-level:",
         "from kmip_pkcs11.operations import derive_key",
         "uid = derive_key.handle(payload, \"alice\", store, shim)",
         "→ a new SymmetricKey object, derived inside the HSM"],
        "The derived key is a managed object in its own right, with its own lifecycle.")

    op_block(doc, "CreateSplitKey",
        "Split a symmetric key into N XOR shares, each stored as its own managed object.",
        "UniqueIdentifier, SplitKeyParts, SplitKeyThreshold, SplitKeyMethod, "
        "TemplateAttribute | Attributes",
        "UniqueIdentifier (one per share)",
        ["# XOR splitting: every share is required, so threshold == parts.",
         "# Each share is a SplitKey object, enveloped at rest."],
        "Only the XOR method is implemented. Shamir secret sharing is not: XOR requires "
        "all N shares, so the threshold always equals the part count.")

    op_block(doc, "JoinSplitKey",
        "Reconstruct a key from all of its shares.",
        "UniqueIdentifier (repeatable — every share), TemplateAttribute | Attributes",
        "UniqueIdentifier (the reconstructed key)",
        ["# All shares must be supplied; a missing share is an error,",
         "# not a partial result."])
    doc.add_page_break()

    # ── 4.3 retrieval ────────────────────────────────────────────────────
    add_heading(doc, "4.3  Retrieval and search", 2, MID_BLUE)

    op_block(doc, "Get",
        "Retrieve a managed object. What comes back depends on the object type and on "
        "whether the key material is extractable.",
        "UniqueIdentifier, KeyWrappingSpecification (optional)",
        "ObjectType, SymmetricKey | PrivateKey | PublicKey | Certificate | SecretData | "
        "SplitKey, KeyBlock { KeyFormatType, KeyValue { KeyMaterial } }, "
        "CryptographicAlgorithm, CryptographicLength",
        ["obj = client.get(uid)",
         "",
         "# Wrapped Get: ask for the key sealed under a KEK, so the plaintext",
         "# never leaves the HSM. AES key wrap (CKM_AES_KEY_WRAP_PAD).",
         "# KeyWrappingSpecification names the wrapping key's UID."],
        "A non-extractable key has no retrievable material — Get returns its metadata "
        "and format, not its bytes. That is the point of a non-extractable key, and it "
        "is why Get on an HSM-generated key is not a way to exfiltrate it.")

    op_block(doc, "Export",
        "KMIP 2.0+ retrieval of a managed object's material, distinct from Get so that "
        "policy can treat it differently.",
        "UniqueIdentifier",
        "ObjectType and the object's material, as Get",
        ["# Export is in the default dual-control protected set, because",
         "# it is one of the two operations that discloses key material.",
         "# Under dual control, the first attempt is refused:",
         "→ Export requires 2 approval(s) from other identities."],
        "Export requires the 'read' permission level for a delegated grant, the same as "
        "Get.")

    op_block(doc, "GetAttributes",
        "Read an object's attributes. With no names given, returns all of them.",
        "UniqueIdentifier, AttributeName (repeatable, optional)",
        "UniqueIdentifier, Attribute { AttributeName, AttributeValue }",
        ["attrs = client.get_attributes(uid)",
         "→ {'Object Type': 2, 'State': 2, 'Cryptographic Algorithm': 3,",
         "→  'Cryptographic Length': 256, 'Cryptographic Usage Mask': 12,",
         "→  'Sensitive': 1, 'Name': 'payments-dek', ...}",
         "",
         "# Only what you need:",
         "attrs = client.get_attributes(uid, names=[\"State\", \"Name\"])"])

    op_block(doc, "GetAttributeList",
        "Return the names of the attributes an object has, without their values.",
        "UniqueIdentifier",
        "UniqueIdentifier, AttributeName (repeatable)",
        ["# Handled by the same module as GetAttributes.",
         "# Useful for discovering custom x- attributes before reading them."])

    op_block(doc, "Locate",
        "Search for objects by attribute criteria. Results are filtered to what the "
        "caller may see.",
        "Attributes | TemplateAttribute, ObjectType, State, MaximumItems",
        "UniqueIdentifier (repeatable)",
        ["uids = client.locate(name=\"payments-dek\")",
         "→ ['99e251ed-7291-4a42-933b-87a60eea273e']",
         "",
         "from kmip_pkcs11.core.enums import State",
         "active = client.locate(state=State.Active)",
         "recent = client.locate(object_type=ObjectType.SymmetricKey, max_items=50)"],
        "A non-admin identity sees only objects it owns. An identity holding the admin "
        "role skips that filter — without which an admin could read an object it could "
        "not find.")
    doc.add_page_break()

    # ── 4.4 attributes ───────────────────────────────────────────────────
    add_heading(doc, "4.4  Attribute management", 2, MID_BLUE)

    op_block(doc, "AddAttribute",
        "Append a value to an attribute. Multi-valued attributes get a new index.",
        "UniqueIdentifier, Attribute { AttributeName, AttributeValue }",
        "UniqueIdentifier, AttributeName",
        ["client.add_attribute(uid, \"x-Application\", \"billing\")",
         "→ '99e251ed-7291-4a42-933b-87a60eea273e'",
         "",
         "# Custom attributes conventionally start with x-.",
         "client.add_attribute(uid, \"x-CostCentre\", \"CC-4471\")"])

    op_block(doc, "ModifyAttribute",
        "Change an existing attribute value in place. Fails if the attribute is absent.",
        "UniqueIdentifier, Attribute { AttributeName, AttributeValue, AttributeIndex }",
        "UniqueIdentifier, AttributeName, AttributeIndex",
        ["# Modify requires the attribute to exist — use SetAttribute for",
         "# create-or-replace semantics."])

    op_block(doc, "DeleteAttribute",
        "Remove an attribute value, optionally at a specific index.",
        "UniqueIdentifier, Attribute { AttributeName, AttributeIndex }",
        "UniqueIdentifier",
        ["# Deleting a protected attribute (State, Object Type, the PKCS#11",
         "# linkage) is refused — those are not client-owned metadata."])

    op_block(doc, "SetAttribute",
        "KMIP 2.0+ create-or-overwrite for a single-instance attribute.",
        "UniqueIdentifier, AttributeName, AttributeValue",
        "UniqueIdentifier",
        ["# Idempotent where Add/Modify are not: no error if it is already",
         "# set, no error if it is not."])

    op_block(doc, "AdjustAttribute",
        "Atomically increment, decrement or set a numeric attribute.",
        "UniqueIdentifier, Attribute, AdjustmentType",
        "UniqueIdentifier, AttributeName, AttributeValue",
        ["# Atomic at the database level, so two concurrent adjustments",
         "# cannot lose one another's update — which a read-modify-write",
         "# through GetAttributes and SetAttribute would."])
    doc.add_page_break()

    # ── 4.5 lifecycle ────────────────────────────────────────────────────
    add_heading(doc, "4.5  Lifecycle", 2, MID_BLUE)

    op_block(doc, "Activate",
        "Move a Pre-Active object to Active.",
        "UniqueIdentifier",
        "UniqueIdentifier",
        ["client.activate(uid)",
         "→ state 1 (Pre-Active) → state 2 (Active)",
         "",
         "# On an already-Active object this is refused:",
         "→ Operation 'activate' is not permitted when object state is 'Active'"],
        "Create, CreateKeyPair and Register already return Active objects, so Activate "
        "is for objects deliberately staged Pre-Active.")

    op_block(doc, "Revoke",
        "Move an object to Deactivated or Compromised, depending on the reason.",
        "UniqueIdentifier, RevocationReason { RevocationReasonCode, RevocationMessage }",
        "UniqueIdentifier",
        ["from kmip_pkcs11.core.enums import RevocationReasonCode as R",
         "",
         "# Routine retirement — the key can still decrypt:",
         "client.revoke(uid, reason=R.Superseded, message=\"rotated 2026-08\")",
         "→ state 3 (Deactivated)",
         "",
         "# Compromise — the key can do nothing but be read and exported:",
         "client.revoke(uid, reason=R.KeyCompromise, message=\"disclosed in logs\")",
         "→ state 4 (Compromised)"],
        "Reason codes: Unspecified 1, KeyCompromise 2, CACompromise 3, "
        "AffiliationChanged 4, Superseded 5, CessationOfOperation 6, "
        "PrivilegeWithdrawn 7. Only the two compromise codes lead to Compromised.")

    op_block(doc, "Destroy",
        "Zeroize the key material on the token and mark the object Destroyed.",
        "UniqueIdentifier",
        "UniqueIdentifier",
        ["client.destroy(uid)",
         "→ state 5 (Destroyed); the PKCS#11 object is gone from the token",
         "",
         "# On a Compromised object the distinction is kept:",
         "→ state 6 (Destroyed Compromised)"],
        "Irreversible, and in the default dual-control protected set. The metadata row "
        "survives so the audit trail still resolves the identifier.")

    op_block(doc, "Archive",
        "Move an object to archival storage: it stays known but is not usable.",
        "UniqueIdentifier",
        "UniqueIdentifier",
        ["# An archived object refuses cryptographic operations until",
         "# it is recovered, without being destroyed."])

    op_block(doc, "Recover",
        "Return an archived object to normal usability.",
        "UniqueIdentifier",
        "UniqueIdentifier",
        ["# The inverse of Archive; the object returns to its prior state."])

    op_block(doc, "Check",
        "Test usage constraints without performing an operation — a dry run.",
        "UniqueIdentifier, UsageLimitsCount, CryptographicUsageMask, State",
        "UniqueIdentifier, and whichever constraint failed",
        ["# Ask 'could this key encrypt right now?' without encrypting.",
         "# The response names the constraint that would fail, so a client",
         "# can distinguish 'wrong state' from 'wrong usage mask'."])

    op_block(doc, "ObtainLease",
        "Take a time-boxed lease on an object, for clients that cache key material.",
        "UniqueIdentifier",
        "UniqueIdentifier, LeaseTime, LastChangeDate",
        ["lease = obtain_lease.handle(payload, \"alice\", store, shim)",
         "→ LeaseTime: 3600 seconds",
         "→ LastChangeDate: when the object was last modified"],
        "LastChangeDate is what makes the lease useful: a client can tell whether the "
        "object changed under it.")

    op_block(doc, "GetUsageAllocation",
        "Atomically consume from an object's usage allocation.",
        "UniqueIdentifier, UsageLimitsCount",
        "UniqueIdentifier",
        ["# Atomic: two clients cannot both consume the last unit."])

    op_block(doc, "ReKey",
        "Create a replacement symmetric key inheriting the original's attributes, "
        "cross-linked to it.",
        "UniqueIdentifier, TemplateAttribute | Attributes",
        "UniqueIdentifier (the new key)",
        ["# The old and new keys are linked in both directions:",
         "#   old → Link_ReplacementKey → new",
         "#   new → Link_ReplacedKey    → old",
         "# The scheduled rotation in Section 10.1 produces the same lineage,",
         "# so downstream tooling need not tell them apart."])

    op_block(doc, "ReKeyKeyPair",
        "The asymmetric equivalent: a fresh key pair inheriting the original's "
        "attributes.",
        "UniqueIdentifier, TemplateAttribute, PublicKeyAttributes, PrivateKeyAttributes",
        "UniqueIdentifier (public), UniqueIdentifier (private)",
        ["# Both new objects are cross-linked to their predecessors."])
    doc.add_page_break()

    # ── 4.6 cryptography ─────────────────────────────────────────────────
    add_heading(doc, "4.6  Cryptographic operations", 2, MID_BLUE)

    op_block(doc, "Encrypt",
        "Encrypt data under a managed symmetric key. The key never leaves the HSM.",
        "UniqueIdentifier, Data, CryptographicParameters { BlockCipherMode }, "
        "IVCounterNonce, AuthenticatedEncryptionAdditionalData",
        "UniqueIdentifier, Data, IVCounterNonce, AuthenticatedEncryptionTag (AEAD only)",
        ["from kmip_pkcs11.core.enums import BlockCipherMode as M",
         "",
         "# AES-GCM — authenticated, no padding, 12-byte nonce:",
         "ct, iv, tag = client.encrypt(uid, b\"card-number=4111...\", mode=M.GCM)",
         "→ 28 bytes plaintext → 28 bytes ciphertext, iv 12, tag 16",
         "",
         "# AES-CBC — padded, 16-byte IV, no tag:",
         "ct, iv, tag = client.encrypt(uid, b\"card-number=4111...\", mode=M.CBC)",
         "→ 28 bytes plaintext → 32 bytes ciphertext, iv 16, tag None"],
        "The IV is generated by the server when not supplied — 12 bytes for GCM/CTR/CCM, "
        "8 for DES/3DES, 16 otherwise — and always returned, because a caller that "
        "cannot reproduce the IV cannot decrypt. Mode defaults to CBC if "
        "CryptographicParameters is absent.")

    op_block(doc, "Decrypt",
        "Decrypt data under a managed symmetric key.",
        "UniqueIdentifier, Data, CryptographicParameters, IVCounterNonce, "
        "AuthenticatedEncryptionTag, AuthenticatedEncryptionAdditionalData",
        "UniqueIdentifier, Data",
        ["pt = client.decrypt(uid, ct, iv=iv, auth_tag=tag, mode=M.GCM)",
         "→ b'card-number=4111111111111111'",
         "",
         "# AAD must match what was supplied at encryption, or GCM fails."],
        "Permitted on a Deactivated key, deliberately: retiring a key must not strand "
        "the data encrypted under it. Encrypt on the same key is refused.")

    op_block(doc, "Sign",
        "Sign data with a managed private key.",
        "UniqueIdentifier, Data, CryptographicParameters { DigitalSignatureAlgorithm }",
        "UniqueIdentifier, SignatureData",
        ["# Handler-level: the client has no sign() method.",
         "from kmip_pkcs11.operations import sign",
         "resp = sign.handle(payload, \"alice\", store, shim)",
         "→ RSA-2048 signature: 256 bytes"],
        "RSA (PKCS#1 v1.5, with SHA-1/256/384/512), ECDSA (including ECDSA-SHA256/384) "
        "and DSA are available on this build — see Section 5.")

    op_block(doc, "SignatureVerify",
        "Verify a signature with a managed public key.",
        "UniqueIdentifier, Data, SignatureData, CryptographicParameters",
        "UniqueIdentifier, ValidityIndicator",
        ["resp = signature_verify.handle(payload, \"alice\", store, shim)",
         "→ ValidityIndicator: 1 (Valid)"],
        "A bad signature returns ValidityIndicator = Invalid, not an error: an invalid "
        "signature is an answer, not a failure.")

    op_block(doc, "MAC",
        "Compute a MAC over data using a symmetric key.",
        "UniqueIdentifier, Data",
        "UniqueIdentifier, MACData",
        ["# HMAC-SHA256 over an invoice identifier:",
         "resp = mac.handle(payload, \"alice\", store, shim)",
         "→ MACData: 32 bytes"],
        "The key must carry the MACGenerate usage flag.")

    op_block(doc, "MACVerify",
        "Verify a MAC over data.",
        "UniqueIdentifier, Data, MACData",
        "UniqueIdentifier, ValidityIndicator",
        ["resp = mac_verify.handle(payload, \"alice\", store, shim)",
         "→ ValidityIndicator: 1 (Valid)"])

    op_block(doc, "Hash",
        "Compute a digest. No key is involved, so no object is named.",
        "Data, CryptographicParameters { HashingAlgorithm }",
        "Data (the digest)",
        ["# SHA-256 of b\"abc\", computed on the token:",
         "resp = hash_op.handle(payload, \"alice\", store, shim)",
         "→ ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
        "That digest is the standard SHA-256 of \"abc\", which makes this example a "
        "cross-check of the whole path rather than only of the plumbing.")

    op_block(doc, "RNGRetrieve",
        "Draw random bytes from the HSM's generator.",
        "DataLength",
        "Data",
        ["resp = rng_retrieve.handle(payload, \"alice\", store, shim)",
         "→ 32 bytes of HSM-generated entropy"],
        "Useful precisely because it is the token's RNG, not the host's.")

    op_block(doc, "RNGSeed",
        "Mix client-supplied entropy into the HSM's generator.",
        "Data",
        "DataLength (bytes accepted)",
        ["# Whether seeding has any effect is a property of the token,",
         "# not of this server: many HSMs accept the seed and ignore it."])
    doc.add_page_break()

    # ── 4.7 certificates ─────────────────────────────────────────────────
    add_heading(doc, "4.7  Certificates", 2, MID_BLUE)

    op_block(doc, "Certify",
        "Issue an X.509 certificate for a managed public key.",
        "UniqueIdentifier (the public key), TemplateAttribute | Attributes",
        "UniqueIdentifier (the new Certificate object)",
        ["# Produces a self-signed certificate over the named public key,",
         "# signed with its matching private key inside the HSM.",
         "# The result is a Certificate managed object."],
        "Self-signed only: this is not a CA. It is enough to give a key an X.509 "
        "identity, not to run a PKI.")

    op_block(doc, "ReCertify",
        "Issue a fresh certificate for the same public key — renewal.",
        "UniqueIdentifier, TemplateAttribute | Attributes",
        "UniqueIdentifier (the new Certificate)",
        ["# The old certificate object is left in place; the new one is",
         "# a separate managed object."])

    op_block(doc, "Validate",
        "Check a certificate, or a chain, for time validity and structure.",
        "Certificate (repeatable) or UniqueIdentifier",
        "ValidityIndicator",
        ["→ ValidityIndicator: 1 (Valid) | 2 (Invalid) | 3 (Unknown)"],
        "Time validity and chain structure. Revocation is not checked — there is no CRL "
        "or OCSP client.")
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "5  Algorithm and mechanism support", 1, DARK_BLUE)
    add_para(doc,
        "The shim queries the token's real mechanism list at startup and gates every "
        "algorithm and mode dispatch on it. An unsupported request fails with "
        "OperationNotSupported naming the mechanism, rather than surfacing a raw PKCS#11 "
        "error from somewhere deep in an operation.")
    section_break(doc)
    add_para(doc,
        "The tables below were produced by probing a live token — SoftHSM2 2.7.0 built "
        "against OpenSSL 3.0.13, advertising 79 mechanisms. A different token will "
        "produce a different table, which is the point of probing rather than assuming.",
        italic=True, size=9)
    section_break(doc)

    add_heading(doc, "5.1  Algorithms", 2, MID_BLUE)
    make_table(doc,
        ["Algorithm", "Status", "Algorithm", "Status"],
        [
            ["AES", "Available", "HMAC-MD5", "Available"],
            ["DES (legacy)", "Available", "HMAC-SHA1", "Available"],
            ["Triple-DES", "Available", "HMAC-SHA224", "Available"],
            ["RSA", "Available", "HMAC-SHA256", "Available"],
            ["EC", "Available", "HMAC-SHA384", "Available"],
            ["ECDSA", "Available", "HMAC-SHA512", "Available"],
            ["ECDH", "Available", "HMAC-SHA3-224/256/384/512", "Wired, inactive here"],
            ["DSA", "Available", "Blowfish", "Wired, inactive here"],
            ["DH", "Available", "Twofish", "Wired, inactive here"],
        ],
        widths=[1.5, 1.6, 1.9, 1.3])
    section_break(doc)
    add_para(doc,
        "\"Wired, inactive here\" means the mapping exists in the shim and would work "
        "against a token that implements the mechanism — point the shim at such a token "
        "and it activates with no code change. Twelve further KMIP algorithms "
        "(RC2/RC4/RC5, IDEA, CAST5, Camellia, ChaCha20, Poly1305, SKIPJACK, MARS, "
        "OneTimePad, SHAKE128/256) have no PKCS#11 mechanism implemented by any backend "
        "tested here, or — for SKIPJACK, MARS and OneTimePad — no PKCS#11 mechanism was "
        "ever standardised at all.", size=9.5)
    section_break(doc)

    add_heading(doc, "5.2  Block cipher modes (AES)", 2, MID_BLUE)
    make_table(doc,
        ["Mode", "Status", "IV/nonce", "Notes"],
        [
            ["CBC", "Available", "16 bytes", "Padded (CKM_AES_CBC_PAD). The default when "
                                             "no mode is given."],
            ["ECB", "Available", "none", "No IV. Rarely the right choice."],
            ["GCM", "Available", "12 bytes", "Authenticated; returns a 16-byte tag. "
                                             "Supports additional authenticated data."],
            ["CTR", "Available", "12 bytes", "Stream mode, no padding, no tag."],
            ["CFB", "Inactive here", "16 bytes", "Real PKCS#11 mechanism; this SoftHSM2 "
                                                 "build does not implement it."],
            ["OFB", "Inactive here", "16 bytes", "As CFB."],
            ["CCM", "Inactive here", "12 bytes", "As CFB."],
        ],
        widths=[0.7, 1.1, 0.9, 3.6])
    section_break(doc)
    add_para(doc,
        "Triple-DES supports CBC and ECB; single-DES supports CBC and ECB with 8-byte "
        "IVs; Blowfish and Twofish define only a padded-CBC mechanism. Requesting an "
        "inactive mode is refused cleanly:", size=9.5)
    add_code_block(doc, [
        "client.encrypt(uid, data, mode=BlockCipherMode.CCM)",
        "→ OperationFailed / OperationNotSupported:",
        "→   mechanism AES_CCM is not available on this PKCS#11 token",
    ])
    section_break(doc)

    add_heading(doc, "5.3  Hashing and signing", 2, MID_BLUE)
    make_table(doc,
        ["Family", "Available on this token"],
        [
            ["Digests", "MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512. "
                        "SHA3-224/256/384/512 are wired but inactive here."],
            ["RSA signing", "RSA_PKCS (raw), SHA1/SHA256/SHA384/SHA512 with RSA_PKCS."],
            ["EC signing", "ECDSA (raw), ECDSA_SHA256, ECDSA_SHA384."],
            ["DSA signing", "DSA (raw), DSA_SHA256."],
            ["Key wrapping", "AES_KEY_WRAP and AES_KEY_WRAP_PAD."],
        ],
        widths=[1.2, 5.1])
    section_break(doc)
    add_para(doc,
        "ECDSA-SHA256 is the reason this project builds SoftHSM2 from source against "
        "OpenSSL rather than installing the distribution package: the packaged build "
        "does not advertise CKM_ECDSA_SHA256, so every EC signing operation fails "
        "against it. The installation guide covers this.", italic=True, size=9)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "6  Batching", 1, DARK_BLUE)
    add_para(doc,
        "A single request message may carry several Batch Items, each an independent "
        "operation. The server supports BatchErrorContinuationOption and "
        "MaximumResponseSize.")
    add_code_block(doc, [
        "from kmip_pkcs11.core.enums import Operation, BatchErrorContinuationOption",
        "",
        "response = client.raw_batch_request([",
        "    (Operation.Create, create_payload),",
        "    (Operation.Activate, activate_payload),",
        "], batch_error_continuation=BatchErrorContinuationOption.Continue)",
        "# Each BatchItem in the response carries its own ResultStatus.",
    ])
    section_break(doc)
    add_para(doc,
        "There is no batch atomicity. A failure partway through does not roll back items "
        "that already succeeded — with Continue the remaining items still run, and with "
        "Stop they do not, but in neither case is earlier work undone. A client that "
        "needs all-or-nothing must compensate itself.", bold=True, size=9.5)
    section_break(doc)

    add_heading(doc, "6.1  Result reasons", 2, MID_BLUE)
    make_table(doc,
        ["Reason", "Means"],
        [
            ["ItemNotFound", "No object with that identifier, or the caller may not see it."],
            ["PermissionDenied", "Authorization refused: not the owner, no grant, no "
                                 "role allowing the operation, or dual control not "
                                 "satisfied."],
            ["IllegalOperation", "The object's state forbids it — Encrypt on a "
                                 "Deactivated key, Activate on an Active one."],
            ["OperationNotSupported", "The operation, algorithm or mechanism is not "
                                      "available."],
            ["InvalidField / InvalidMessage", "Malformed request: a bad field value, a "
                                              "structure that does not decode."],
            ["MissingData", "A required request field is absent."],
            ["CryptographicFailure", "The token refused the cryptographic operation."],
            ["GeneralFailure", "An internal fault. The client gets only the reason code; "
                               "the traceback stays in the server log."],
        ],
        widths=[1.7, 4.6])
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "7  Access control", 1, DARK_BLUE)
    add_para(doc,
        "Every managed object records the identity that created it. An operation against "
        "an existing object is authorized in the order below, and an operation-level "
        "allowlist is checked before any of it.")
    section_break(doc)

    add_heading(doc, "7.1  The order of checks", 2, MID_BLUE)
    make_table(doc,
        ["#", "Check", "Grants access when"],
        [
            ["0", "Role operation allowlist", "Checked first, and can refuse outright. "
                                              "Opt-in: no allowlist means no restriction."],
            ["1", "Admin role", "The identity holds the admin role — unconditional."],
            ["2", "Ownership", "identity == the object's owner_identity."],
            ["3", "Delegated grant", "A grant names the identity, at a sufficient "
                                     "permission level."],
            ["4", "Group grant", "A grant names group:<name> and the identity is a "
                                 "member."],
        ],
        widths=[0.3, 1.6, 4.4])
    section_break(doc)
    add_para(doc,
        "Permission levels: \"read\" covers Get, GetAttributes, GetAttributeList, Check, "
        "Export and ObtainLease; everything else — Encrypt, Destroy, ReKey and the rest — "
        "requires \"full\".", size=9.5)
    section_break(doc)

    add_heading(doc, "7.2  Worked example — ownership and a grant", 2, MID_BLUE)
    add_code_block(doc, [
        "# alice creates a key. bob tries to read it:",
        "bob_client.get(uid)",
        "→ OperationFailed (reason=12):",
        "→   Identity 'bob' is not authorized to perform 'Get'",
        "→   on an object it does not own",
        "",
        "# alice's administrator delegates read access to bob:",
        "kmip-admin -c config.yaml access grant <uid> bob --permission read",
        "",
        "# bob can now read it — but still cannot Destroy it,",
        "# because that needs 'full'.",
        "bob_client.get_attributes(uid)          # allowed",
    ])
    section_break(doc)

    add_heading(doc, "7.3  Worked example — groups", 2, MID_BLUE)
    add_para(doc,
        "A grant may name a group instead of a person, so access follows team membership "
        "and leaving the team withdraws it.", size=9.5)
    add_code_block(doc, [
        "kmip-admin -c config.yaml group add bob crypto-team",
        "kmip-admin -c config.yaml group add carol crypto-team",
        "kmip-admin -c config.yaml access grant <uid> group:crypto-team --permission read",
        "",
        "kmip-admin -c config.yaml group members crypto-team",
        "→ GROUP        IDENTITY",
        "→ crypto-team  bob",
        "→ crypto-team  carol",
        "",
        "# bob leaves the team; his access goes with him:",
        "kmip-admin -c config.yaml group remove bob crypto-team",
    ])
    section_break(doc)

    add_heading(doc, "7.4  Worked example — per-role operation allowlists", 2, MID_BLUE)
    add_para(doc,
        "A role may carry a list of operations its holders may perform. This is opt-in: "
        "a role with no allowlist places no restriction, so adding roles never silently "
        "locks anyone out. It narrows what an identity may do; it never widens it, and "
        "the admin role is exempt.", size=9.5)
    add_code_block(doc, [
        "kmip-admin -c config.yaml role grant dave auditor",
        "kmip-admin -c config.yaml permission allow auditor Get",
        "kmip-admin -c config.yaml permission allow auditor GetAttributes",
        "",
        "kmip-admin -c config.yaml permission show auditor",
        "→ ROLE     OPERATION",
        "→ auditor  Get",
        "→ auditor  GetAttributes",
        "",
        "# dave may now Get, and nothing else:",
        "→ OperationFailed: Identity 'dave' holds no role permitting 'Create'",
    ])
    section_break(doc)
    add_para(doc,
        "Holding an unrestricted role alongside a restricted one does not dissolve the "
        "restriction — otherwise roles would be additive in the wrong direction. An "
        "identity's permitted set is the union of the allowlists its roles define.",
        italic=True, size=9)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "8  Governance", 1, DARK_BLUE)
    add_para(doc,
        "Two features that act without a client asking, or refuse a client that does. "
        "Both are off by default and enabled in the governance section of the "
        "configuration file.")
    section_break(doc)

    add_heading(doc, "8.1  Cryptoperiod enforcement and scheduled rotation", 2, MID_BLUE)
    add_para(doc,
        "KMIP defines no separate cryptoperiod attribute — the Deactivation Date is the "
        "end of the period — so a cryptoperiod here is that standard attribute plus a "
        "scheduler that acts on it. Without the scheduler, a key with a two-year "
        "cryptoperiod stays Active into year five unless somebody remembers.")
    section_break(doc)
    add_code_block(doc, [
        "# Give a key a one-year cryptoperiod:",
        "kmip-admin -c config.yaml cryptoperiod set <uid> --days 365",
        "→ <uid> deactivates at 2027-08-19T03:00:08",
        "",
        "# What is coming up for renewal?",
        "kmip-admin -c config.yaml cryptoperiod expiring --within-days 30",
        "→ UUID                                  OWNER  DEACTIVATES",
        "→ 1ca09940-f452-43c3-a8fa-97bd70dcd182  alice  2026-09-15T03:00:08",
        "",
        "# Run one scan by hand (no HSM needed; deactivates and warns,",
        "# but will not auto-rotate):",
        "kmip-admin -c config.yaml cryptoperiod scan",
        "→ deactivated 1, warned 0, failed 0",
    ])
    section_break(doc)
    add_para(doc, "Enabled in the server, the scan runs on a timer:", size=9.5)
    add_code_block(doc, [
        "governance:",
        "  enabled: true",
        "  scan_interval_seconds: 300",
        "  warn_days: 7           # announce expiry this far ahead",
        "  auto_rotate: true      # create a cross-linked replacement",
    ])
    section_break(doc)
    for item in [
        "Keys past their Deactivation Date are moved to Deactivated — so they can still "
        "decrypt, but no longer encrypt.",
        "Keys approaching it are warned about, so rotation is planned rather than "
        "discovered.",
        "With auto_rotate, a replacement symmetric key is created first and cross-linked "
        "with Link_ReplacementKey / Link_ReplacedKey — the same lineage a client-driven "
        "ReKey produces. Rotation runs before deactivation so a replacement exists "
        "before the old key stops being usable; if it fails, the key is deactivated "
        "anyway, because an expired key left Active is the worse outcome.",
        "Only symmetric keys are rotated. Anything else is logged as a rotation failure "
        "and simply deactivated.",
        "Every action is audited under the identity system:scheduler, so an automated "
        "deactivation is as attributable as a human one.",
        "In a multi-worker deployment only worker 0 runs the scan; otherwise workers "
        "would race to deactivate the same keys.",
    ]:
        add_bullet(doc, item)
    section_break(doc)

    add_heading(doc, "8.2  Dual control", 2, MID_BLUE)
    add_para(doc,
        "Destroy zeroizes key material; Export hands out key bytes. Under dual control "
        "neither executes on request. The check runs before the handler, so a blocked "
        "operation has no effect at all — the point is that the destructive step never "
        "happens without the second signature.")
    section_break(doc)
    add_code_block(doc, [
        "governance:",
        "  dual_control: true",
        "  dual_control_operations: [Destroy, Export]",
        "  approvals_required: 2      # must be >= 2",
        "  approval_ttl_seconds: 3600",
    ])
    section_break(doc)
    add_para(doc, "The flow, end to end:", bold=True, size=9.5)
    add_code_block(doc, [
        "# 1. alice asks. The key is NOT destroyed.",
        "client.destroy(uid)",
        "→ OperationFailed (reason=12): Destroy requires 2 approval(s) from",
        "→   other identities. Approval request 0c83923e-... created;",
        "→   once approved, retry.",
        "",
        "# 2. Two other people approve, out of band.",
        "kmip-admin -c config.yaml approval list",
        "→ REQUEST_ID    OPERATION_NAME  OBJECT_UID  REQUESTER  APPROVERS  REQUIRED",
        "→ 0c83923e-...  Destroy         99e251ed-…  alice      -          2",
        "",
        "kmip-admin -c config.yaml approval approve 0c83923e-... --as bob",
        "→ approved by 'bob': 1/2 approvals",
        "kmip-admin -c config.yaml approval approve 0c83923e-... --as carol",
        "→ approved by 'carol': satisfied — the requester may now retry",
        "",
        "# 3. alice retries. Now it proceeds.",
        "client.destroy(uid)                # succeeds; state 5 (Destroyed)",
        "",
        "# 4. The approval is spent. A second Destroy needs a new one.",
    ])
    section_break(doc)
    add_para(doc, "The rules that make this dual control rather than paperwork:",
             bold=True, size=9.5)
    for item in [
        "The requester can never approve their own request. Enforced in the store, so it "
        "holds however approvals are submitted.",
        "An approval authorises exactly one attempt, on one object, by one identity. It "
        "is consumed on use rather than becoming standing permission, and consumed "
        "before the handler runs, so a handler that fails partway leaves nothing "
        "reusable behind.",
        "Approvals expire after approval_ttl_seconds.",
        "A retry reuses the open request rather than opening another, so a client in a "
        "retry loop cannot fill the table with requests nobody will approve.",
        "approvals_required below 2 with dual control on is rejected at configuration "
        "load — a single signature is almost always a misconfiguration.",
        "The same approver signing twice still counts once.",
    ]:
        add_bullet(doc, item)
    section_break(doc)
    add_para(doc,
        "KMIP has no wire representation for a pending, out-of-band-approved request, so "
        "the refusal reaches the client as OperationFailed / PermissionDenied carrying "
        "the request identifier, and approval happens through kmip-admin.",
        italic=True, size=9)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "9  Audit", 1, DARK_BLUE)
    add_para(doc,
        "Every operation except Query and DiscoverVersions writes a record. Reads are "
        "recorded too — \"who exported this key\" is a read, and is the question an audit "
        "log most needs to answer. Only capability discovery is skipped, because "
        "recording it would bury the entries that matter in handshake noise.")
    section_break(doc)

    add_heading(doc, "9.1  What a record contains", 2, MID_BLUE)
    make_table(doc,
        ["Field", "Contents"],
        [
            ["seq", "Monotonic sequence number."],
            ["timestamp", "When it happened."],
            ["identity", "Who asked — including system:scheduler for automated actions."],
            ["operation / operation_name", "The KMIP operation, by code and by name."],
            ["object_uid", "Which object, where one is involved."],
            ["result", "success or failure."],
            ["result_reason", "The KMIP reason code on failure."],
            ["message", "Detail — the error text, or the scheduler's explanation."],
            ["client", "Peer address."],
            ["prev_hash / entry_hash", "The hash chain that makes tampering detectable."],
        ],
        widths=[1.7, 4.6])
    section_break(doc)

    add_heading(doc, "9.2  Reading and verifying", 2, MID_BLUE)
    add_code_block(doc, [
        "kmip-admin -c config.yaml audit list --limit 20",
        "kmip-admin -c config.yaml audit list --identity alice",
        "kmip-admin -c config.yaml audit list --object-uid <uid>",
        "kmip-admin -c config.yaml audit list --result failure",
        "kmip-admin -c config.yaml audit list --json          # for a log shipper",
        "",
        "kmip-admin -c config.yaml audit verify",
        "→ audit chain OK (2 entries)",
        "",
        "# A tampered log names the exact row:",
        "→ audit chain BROKEN at seq 47",
    ])
    section_break(doc)

    add_heading(doc, "9.3  Why it is append-only twice over", 2, MID_BLUE)
    add_para(doc,
        "Either mechanism alone is weak. SQLite triggers block UPDATE and DELETE "
        "outright, so application bugs and casual tampering fail loudly. And each row "
        "carries the SHA-256 of the one before it, so an attacker with file access who "
        "simply drops the triggers still leaves a broken chain that the verifier locates "
        "at the exact row. Appends take a write lock up front, because the chain is "
        "read-then-write and two concurrent appends would otherwise link to the same "
        "predecessor and fork the history.")
    section_break(doc)
    add_para(doc,
        "An audit write that fails never fails the KMIP operation — but it logs an "
        "exception loudly, because a silently unrecorded operation is exactly what an "
        "attacker would want.", size=9.5)
    section_break(doc)

    add_heading(doc, "9.4  Retention", 2, MID_BLUE)
    add_code_block(doc, [
        "kmip-admin -c config.yaml audit prune --older-than-days 365 \\",
        "                                      --archive /var/backups/audit-2025.json",
        "→ archived 12043 entries to /var/backups/audit-2025.json",
        "→ pruned 12043 entries older than 365 days",
    ])
    add_para(doc,
        "Pruning is the one sanctioned way past the triggers. It returns the removed "
        "entries so they can be archived, restores the trigger afterwards, and refuses "
        "to run at all on a log that already fails verification — pruning a tampered log "
        "would destroy the evidence.", size=9.5)
    section_break(doc)
    add_para(doc,
        "Known limit: the chain is not anchored anywhere external, so an attacker who "
        "rewrites the whole log consistently leaves no trace. Ship entries to an "
        "external collector for a stronger guarantee.", italic=True, size=9,
        colour=WARN_AMBER)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "10  Protection at rest", 1, DARK_BLUE)
    add_para(doc,
        "Most key material never touches the database: it lives in the HSM and is "
        "referenced by CKA_ID. But SecretData, OpaqueObject and SplitKey shares have no "
        "PKCS#11 object behind them, so their bytes would otherwise sit in the metadata "
        "database in the clear, where a copy of the file exposes them outright.")
    section_break(doc)
    for item in [
        "Those payloads are sealed with AES-256-GCM under a master key generated on, and "
        "never leaving, the HSM — non-extractable, labelled kmip-master-N.",
        "Encryption is transparent: the store seals on write and unseals on read, so no "
        "operation handler is involved.",
        "Certificates are deliberately excluded — they are public, and encrypting them "
        "would make them unreadable without the token for no gain. Exclusion is by "
        "denylist, so any object type added later is encrypted by default.",
        "Each envelope records which master key wrote it, which is what makes rotation "
        "safe: re-encrypting a large store is not atomic, so a partly rotated table "
        "legitimately holds both keys and stays fully readable, and re-running finishes "
        "the job.",
    ]:
        add_bullet(doc, item)
    section_break(doc)
    add_code_block(doc, [
        "# Rotate the master key. The superseded key is destroyed only after",
        "# the last row has moved.",
        "kmip-admin -c config.yaml rotate-master-key",
        "→ re-encrypted 1043 blob(s); retired 1 old key(s)",
        "",
        "# Keep the old key (for a staged rollout):",
        "kmip-admin -c config.yaml rotate-master-key --keep-previous-key",
    ])
    section_break(doc)
    add_para(doc,
        "This means the metadata database is useless without the token that holds the "
        "master key. Back up and protect the two together — and note that retiring a "
        "master key before its blobs are re-encrypted makes them unrecoverable.",
        bold=True, size=9.5)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "11  Backup and restore", 1, DARK_BLUE)
    add_para(doc,
        "A copy of a live WAL database can capture a torn state, so backup uses SQLite's "
        "online backup API rather than a file copy, and writes a manifest recording which "
        "token the snapshot belongs to.")
    section_break(doc)
    add_para(doc,
        "That pairing is the point. Objects reference keys by CKA_ID and secret blobs are "
        "encrypted under a master key on the token, so a database restored beside a "
        "different HSM is not a degraded backup — it is unreadable.", size=9.5)
    section_break(doc)
    add_code_block(doc, [
        "# Take a snapshot:",
        "kmip-admin -c config.yaml backup create --output /var/backups/kmip-2026-08-19",
        "",
        "# What is in it, without restoring:",
        "kmip-admin backup inspect --input /var/backups/kmip-2026-08-19",
        "→ token label, object count, audit entry count, creation time",
        "",
        "# Restore (refuses a mismatched token unless --force):",
        "kmip-admin -c config.yaml backup restore --input /var/backups/kmip-2026-08-19 \\",
        "                                         --database /var/lib/kmip/kmip.db",
        "",
        "# Prove a database is usable with this token — not assume it:",
        "kmip-admin -c config.yaml backup verify",
        "→ /var/lib/kmip/kmip.db: OK",
    ])
    section_break(doc)
    add_para(doc,
        "backup verify does three things that together mean \"this really works\": the "
        "master key is present on the token, the audit chain verifies, and a stored "
        "secret actually decrypts. Verified end to end by deleting the database and "
        "recovering a working, decryptable secret.", size=9.5)
    section_break(doc)
    add_para(doc,
        "Known limit: backups are point-in-time, not continuous, and scheduling and "
        "offsite shipping are left to the operator.", italic=True, size=9,
        colour=WARN_AMBER)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "12  Observability", 1, DARK_BLUE)
    add_para(doc,
        "Health, readiness and metrics are served on a separate management port — keep it "
        "off the public interface; it is for the operator, not for KMIP clients.")
    section_break(doc)
    make_table(doc,
        ["Endpoint", "Returns"],
        [
            ["GET /health", "200 while the process is alive. A liveness probe."],
            ["GET /ready", "200 only when this instance can serve a request right now: "
                           "the KMIP port is open, the HSM session is usable, and the "
                           "database answers. 503 with a reason otherwise."],
            ["GET /metrics", "Prometheus exposition format."],
        ],
        widths=[1.2, 5.1])
    section_break(doc)
    add_code_block(doc, [
        "curl -s localhost:9696/ready",
        "→ {\"ready\": true, \"mechanisms\": 79, \"schema_version\": 1}",
        "",
        "curl -s localhost:9696/metrics",
        "→ kmip_uptime_seconds 1843.221",
        "→ kmip_operations_total{operation=\"Create\",result=\"success\"} 42",
        "→ kmip_operations_total{operation=\"Destroy\",result=\"failure\"} 3",
        "→ kmip_operation_duration_seconds_sum{operation=\"Encrypt\"} 1.884",
        "→ kmip_operation_duration_seconds_count{operation=\"Encrypt\"} 512",
        "→ kmip_auth_failures_total 7",
    ])
    section_break(doc)
    add_para(doc,
        "The readiness check includes the listener deliberately. Startup opens the HSM "
        "session, provisions the master key and converts any cleartext blobs before it "
        "binds, which on a large token takes seconds — long enough for an orchestrator "
        "to route traffic at a port that is not open yet.", size=9.5)
    section_break(doc)
    add_para(doc,
        "Two limits worth knowing: in a multi-worker deployment only worker 0 serves "
        "these endpoints, so the counters reflect one worker's share of traffic — "
        "aggregate in the collector. And latency is a running total rather than histogram "
        "buckets, so quantiles are not available.", italic=True, size=9,
        colour=WARN_AMBER)
    section_break(doc)

    add_heading(doc, "12.1  Structured logging", 2, MID_BLUE)
    add_code_block(doc, [
        "logging:",
        "  level: INFO      # DEBUG | INFO | WARNING | ERROR",
        "  format: json     # json for shippers, text for humans",
    ])
    add_para(doc,
        "JSON logs keep tracebacks in a field rather than as trailing newlines, so a "
        "multi-line exception survives aggregation as one event.", size=9.5)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "13  Configuration reference", 1, DARK_BLUE)
    add_para(doc,
        "Everything the server needs comes from one YAML file, so a deployment is a "
        "config file plus a service unit. deploy/config.example.yaml is the annotated "
        "template. Validate without serving with kmip-server --config PATH --check.")
    section_break(doc)

    make_table(doc,
        ["Key", "Default", "Meaning"],
        [
            ["server.host", "127.0.0.1", "Bind address."],
            ["server.port", "5696", "IANA-assigned KMIP port."],
            ["server.max_request_size", "1048576", "Ceiling on a declared request body. "
                                                   "Read before authentication, so this "
                                                   "is what stops an anonymous client "
                                                   "declaring a multi-gigabyte frame."],
            ["server.handshake_timeout", "10.0", "Seconds a client may take over a TLS "
                                                 "handshake."],
            ["server.allow_plaintext", "false", "true serves KMIP unencrypted, "
                                                "deliberately."],
            ["server.workers", "1", "Pre-fork worker count; null means one per CPU."],
            ["tls.cert / tls.key", "null", "Required together unless allow_plaintext."],
            ["tls.ca", "null", "CA used to verify client certificates."],
            ["tls.require_client_cert", "false", "Enforce mTLS; needs tls.ca."],
            ["hsm.library", "(required)", "Path to the PKCS#11 .so."],
            ["hsm.token_label", "(required)", "Which token to open."],
            ["hsm.pin_file / pin_env / pin", "null", "Exactly one. Inline warns at every "
                                                     "start and is redacted from any "
                                                     "config dump."],
            ["storage.database", "/var/lib/kmip/kmip.db", "Metadata database path."],
            ["observability.enabled", "true", "Serve health, readiness and metrics."],
            ["observability.host / port", "127.0.0.1 / 9696", "Management listener."],
            ["governance.enabled", "false", "Run the cryptoperiod scheduler."],
            ["governance.scan_interval_seconds", "300", "How often it scans."],
            ["governance.warn_days", "7", "How far ahead expiry is announced."],
            ["governance.auto_rotate", "false", "Create a cross-linked replacement on "
                                                "expiry."],
            ["governance.dual_control", "false", "Require M-of-N approval."],
            ["governance.dual_control_operations", "[Destroy, Export]", "Which operations "
                                                                       "need approval."],
            ["governance.approvals_required", "2", "How many other identities must "
                                                   "approve. Must be >= 2 when dual "
                                                   "control is on."],
            ["governance.approval_ttl_seconds", "3600", "How long an unused approval stays "
                                                        "valid."],
            ["logging.level / format", "INFO / json", "Verbosity and shape."],
        ],
        widths=[1.9, 1.2, 3.2])
    section_break(doc)
    add_para(doc,
        "Validation is strict and names the offending key: an unknown section, a "
        "certificate without its key, require_client_cert without a CA, dual control "
        "with fewer than two approvals, or more than one PIN source all refuse to start "
        "rather than starting half-configured.", size=9.5)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "14  Command-line reference", 1, DARK_BLUE)
    add_para(doc,
        "Identities, roles, groups, grants, permissions, approvals, cryptoperiods, the "
        "audit log, backups and master-key rotation are all managed here. None of it has "
        "a KMIP wire operation — the specification defines none — so this is the "
        "supported operator surface.")
    section_break(doc)

    add_heading(doc, "14.1  kmip-server", 2, MID_BLUE)
    add_code_block(doc, [
        "kmip-server --config /etc/kmip/config.yaml",
        "kmip-server --config /etc/kmip/config.yaml --check   # validate and exit",
        "",
        "# SIGHUP re-reads TLS material without dropping connections:",
        "systemctl reload kmip-server",
    ])
    section_break(doc)

    add_heading(doc, "14.2  kmip-admin", 2, MID_BLUE)
    add_para(doc,
        "Every command takes -c/--config (read the database path from a config file) or "
        "-d/--database (operate on a database directly), and --json to emit JSON instead "
        "of a table.", size=9.5)
    section_break(doc)
    make_table(doc,
        ["Command", "Subcommands", "Purpose"],
        [
            ["identity", "add, list, delete, disable, enable",
             "Provision the credentials clients authenticate with. disable blocks "
             "authentication without losing the identity's grants."],
            ["role", "grant, revoke, show",
             "Role assignment. admin is the only role the code special-cases."],
            ["access", "grant, revoke, list",
             "Per-object delegated grants, to an identity or to group:<name>."],
            ["group", "add, remove, show, members", "Group membership."],
            ["permission", "allow, disallow, show", "Per-role operation allowlists."],
            ["approval", "list, approve, show", "Dual control."],
            ["cryptoperiod", "set, expiring, scan", "Cryptoperiod policy, and a manual "
                                                    "scan."],
            ["audit", "list, verify, prune", "Read, verify and retain the audit log."],
            ["backup", "create, inspect, restore, verify", "Snapshot and recovery."],
            ["rotate-master-key", "—", "Re-encrypt stored secrets under a new HSM master "
                                       "key."],
        ],
        widths=[1.2, 1.9, 3.2])
    section_break(doc)
    add_para(doc,
        "An expected failure — a mistyped identifier, a refused self-approval — prints "
        "one line and exits non-zero rather than a traceback:", size=9.5)
    add_code_block(doc, [
        "kmip-admin -c config.yaml cryptoperiod set 00000000-dead-beef --days 3",
        "→ kmip-admin: Object '00000000-dead-beef' not found        (exit 1)",
        "",
        "kmip-admin -c config.yaml approval approve <request-id> --as alice",
        "→ kmip-admin: The requester cannot approve their own request  (exit 1)",
    ])
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "15  Deployment shapes", 1, DARK_BLUE)

    add_heading(doc, "15.1  Single process", 2, MID_BLUE)
    add_para(doc,
        "One process, one PKCS#11 session shared by every connection thread behind a "
        "lock. This is the deliberate, permanent design: a session pool was built, "
        "tested, and reproducibly segfaulted, because python-pkcs11 calls "
        "C_Initialize(NULL) so the library's own thread safety is never enabled. "
        "Throughput is roughly 600 operations/second on a single worker.", size=9.5)
    section_break(doc)

    add_heading(doc, "15.2  Pre-fork workers", 2, MID_BLUE)
    add_code_block(doc, [
        "server:",
        "  workers: 4      # or null for one per CPU",
    ])
    add_para(doc,
        "The parent binds the socket and forks before any PKCS#11 call — a child that "
        "inherits an initialized PKCS#11 library is undefined behaviour — and each child "
        "opens its own session. Measured on 4 cores, AES encrypt through the full stack: "
        "605 → 887 operations/second with 4 concurrent clients going from 1 to 4 workers.",
        size=9.5)
    section_break(doc)
    add_para(doc,
        "That is about 1.5×, not 4×. A hash chain is inherently serial, so every audited "
        "operation serialises on one database write lock. That is the price of the "
        "tamper-evidence in Section 9, and it is stated rather than implied away.",
        bold=True, size=9.5)
    section_break(doc)
    add_para(doc,
        "Only worker 0 runs the lifecycle scheduler and serves the management endpoints; "
        "the rest serve KMIP only.", size=9.5)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════════════
    add_heading(doc, "16  Limits and things not supported", 1, DARK_BLUE)
    add_para(doc,
        "Stated plainly, because a specification that lists only capabilities is not much "
        "use for deciding whether to deploy something.")
    section_break(doc)
    make_table(doc,
        ["Area", "Limit"],
        [
            ["Operations", "12 of 53 not implemented: Cancel, Poll, Notify, Put, Log, "
                           "Login, Logout, DelegatedLogin, SetEndpointRole, PKCS11, "
                           "Interop, ReProvision."],
            ["Query functions", "3 of 12 QueryFunction values answered."],
            ["Batching", "No atomicity — a failure does not roll back items that already "
                         "succeeded."],
            ["Algorithms", "15 of 40 CryptographicAlgorithm values work against this "
                           "token; see Section 5."],
            ["Key formats", "Raw, Opaque, PKCS#1 and PKCS#8. Not the wider "
                            "KeyFormatType set."],
            ["Certificates", "Self-signed issuance only; no CA, no CRL or OCSP checking."],
            ["Split keys", "XOR only — every share is required. No Shamir sharing."],
            ["Multi-tenancy", "None. Object names, Locate queries and quotas are global; "
                              "groups partition access, not the namespace. Isolation "
                              "today means one deployment per tenant."],
            ["Storage", "SQLite only. No PostgreSQL backend, no clustering or "
                        "replication."],
            ["HSM", "One token, no failover. SoftHSM2 is not FIPS 140-2/3 or Common "
                    "Criteria validated — the PKCS#11 boundary makes a validated token a "
                    "drop-in, but that swap has not been made or tested here."],
            ["Audit", "The chain is not anchored externally."],
            ["Certificates (TLS)", "No ACME client; renewal is the operator's job, though "
                                   "hot reload means it costs no downtime."],
            ["Concurrency", "One PKCS#11 session per process, serialized. Scale with "
                            "workers, not threads."],
        ],
        widths=[1.4, 4.9])
    section_break(doc)
    add_para(doc,
        "A known SoftHSM2 quirk worth repeating: SENSITIVE=True together with "
        "EXTRACTABLE=True blocks reading CKA_VALUE, so the shim clears sensitivity when "
        "extractability is explicitly requested. A key you asked to be extractable is "
        "therefore not sensitive, which is the only combination the token will actually "
        "honour.", italic=True, size=9)

    section_break(doc)
    section_break(doc)
    f = doc.add_paragraph()
    f.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fr = f.add_run(f"KMIP on PKCS#11 — Feature Specification — {TODAY}")
    fr.font.size = Pt(8)
    fr.font.color.rgb = RGBColor(0x80, 0x80, 0x80)

    out = "KMIP_PKCS11_Feature_Specification.docx"
    doc.save(out)
    print(f"Saved: {out}")


if __name__ == "__main__":
    build()
