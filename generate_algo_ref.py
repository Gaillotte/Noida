#!/usr/bin/env python3
"""Generate SoftHSM2 CNG KSP — Algorithm Reference document."""

from docx import Document
from docx.shared import Pt, RGBColor, Inches, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import copy

# ── colour palette ──────────────────────────────────────────────────────────
C_NAVY    = RGBColor(0x1F, 0x36, 0x64)   # title / heading 1
C_BLUE    = RGBColor(0x2E, 0x74, 0xB5)   # heading 2
C_STEEL   = RGBColor(0x2F, 0x54, 0x96)   # heading 3
C_HEADER  = RGBColor(0x1F, 0x36, 0x64)   # table header bg
C_ROW     = RGBColor(0xD6, 0xE4, 0xF7)   # table alt-row bg
C_WHITE   = RGBColor(0xFF, 0xFF, 0xFF)
C_GREEN   = RGBColor(0x37, 0x86, 0x10)
C_RED     = RGBColor(0xC0, 0x00, 0x00)

# ── helpers ─────────────────────────────────────────────────────────────────

def _set_cell_bg(cell, rgb: RGBColor):
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd  = OxmlElement('w:shd')
    hex6 = str(rgb)          # RGBColor.__str__ returns 6-char hex
    shd.set(qn('w:val'),   'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'),  hex6.upper())
    tcPr.append(shd)


def _set_cell_border(cell, **borders):
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    tcBorders = OxmlElement('w:tcBorders')
    for edge, specs in borders.items():
        tag = OxmlElement(f'w:{edge}')
        for k, v in specs.items():
            tag.set(qn(f'w:{k}'), v)
        tcBorders.append(tag)
    tcPr.append(tcBorders)


def _para_border(para, hex6='1F3664', sz='6'):
    pPr  = para._p.get_or_add_pPr()
    pb   = OxmlElement('w:pBdr')
    for side in ('top', 'left', 'bottom', 'right'):
        el = OxmlElement(f'w:{side}')
        el.set(qn('w:val'),   'single')
        el.set(qn('w:sz'),    sz)
        el.set(qn('w:space'), '4')
        el.set(qn('w:color'), hex6)
        pb.append(el)
    pPr.append(pb)
    pPr_shade = OxmlElement('w:shd')
    pPr_shade.set(qn('w:val'),   'clear')
    pPr_shade.set(qn('w:color'), 'auto')
    pPr_shade.set(qn('w:fill'),  'D6E4F7')
    pPr.append(pPr_shade)


def add_heading(doc, text, level=1):
    p = doc.add_paragraph(style=f'Heading {level}')
    run = p.add_run(text)
    if level == 1:
        run.font.color.rgb = C_NAVY
        run.font.size = Pt(16)
        run.font.bold = True
    elif level == 2:
        run.font.color.rgb = C_BLUE
        run.font.size = Pt(13)
        run.font.bold = True
    else:
        run.font.color.rgb = C_STEEL
        run.font.size = Pt(11)
        run.font.bold = True
    return p


def add_table(doc, headers, rows, col_widths=None):
    n_cols = len(headers)
    table  = doc.add_table(rows=1 + len(rows), cols=n_cols)
    table.style = 'Table Grid'
    table.alignment = WD_TABLE_ALIGNMENT.LEFT

    # header row
    hdr = table.rows[0]
    for i, h in enumerate(headers):
        cell = hdr.cells[i]
        _set_cell_bg(cell, C_HEADER)
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        p = cell.paragraphs[0]
        p.clear()
        run = p.add_run(h)
        run.font.bold = True
        run.font.color.rgb = C_WHITE
        run.font.size = Pt(9)
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER

    # data rows
    for r_idx, row_data in enumerate(rows):
        row = table.rows[r_idx + 1]
        bg  = C_ROW if r_idx % 2 == 0 else C_WHITE
        for c_idx, cell_text in enumerate(row_data):
            cell = row.cells[c_idx]
            _set_cell_bg(cell, bg)
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            p = cell.paragraphs[0]
            p.clear()
            # colour ✓ green, ✗ red
            if '✓' in str(cell_text) or '✗' in str(cell_text):
                for ch in str(cell_text):
                    run = p.add_run(ch)
                    run.font.size = Pt(9)
                    if ch == '✓':
                        run.font.color.rgb = C_GREEN
                        run.font.bold = True
                    elif ch == '✗':
                        run.font.color.rgb = C_RED
                        run.font.bold = True
                    else:
                        run.font.color.rgb = RGBColor(0, 0, 0)
            else:
                run = p.add_run(str(cell_text))
                run.font.size = Pt(9)
                run.font.color.rgb = RGBColor(0, 0, 0)

    # column widths
    if col_widths:
        for row in table.rows:
            for i, w in enumerate(col_widths):
                row.cells[i].width = Cm(w)

    return table


def add_code_block(doc, text):
    p = doc.add_paragraph()
    _para_border(p)
    run = p.add_run(text)
    run.font.name = 'Courier New'
    run.font.size = Pt(8)
    run.font.color.rgb = RGBColor(0x00, 0x00, 0x80)
    return p


def add_note(doc, text):
    p = doc.add_paragraph()
    run = p.add_run('Note: ')
    run.font.bold = True
    run.font.color.rgb = C_BLUE
    run.font.size = Pt(9)
    run2 = p.add_run(text)
    run2.font.size = Pt(9)
    run2.font.color.rgb = RGBColor(0x40, 0x40, 0x40)
    return p


# ── document ─────────────────────────────────────────────────────────────────

def build():
    doc = Document()

    # page margins
    for section in doc.sections:
        section.top_margin    = Cm(2.0)
        section.bottom_margin = Cm(2.0)
        section.left_margin   = Cm(2.5)
        section.right_margin  = Cm(2.0)

    # ── Cover ──────────────────────────────────────────────────────────────
    doc.add_paragraph()
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = title.add_run('SoftHSM2 CNG KSP')
    r.font.size = Pt(24)
    r.font.bold = True
    r.font.color.rgb = C_NAVY

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r2 = sub.add_run('Algorithm Reference — Supported Algorithms, Modes, Key Types & Sizes')
    r2.font.size = Pt(13)
    r2.font.color.rgb = C_BLUE

    doc.add_paragraph()
    meta = doc.add_paragraph()
    meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    for line in [
        'Project: CNG Key Storage Provider (KSP) backed by SoftHSM2 via PKCS#11 v2.40',
        'Platform: Windows 10/11 x64 · Visual Studio 2022 · CMake 3.20+',
        'SoftHSM2: 2.7.0 (OpenSSL backend)',
        'Date: 2026-09-04',
    ]:
        meta.add_run(line + '\n').font.size = Pt(9)

    doc.add_page_break()

    # ── 1. Overview ───────────────────────────────────────────────────────
    add_heading(doc, '1. Overview', 1)
    doc.add_paragraph(
        'This document describes every algorithm, padding / operation mode, key type, '
        'and key size supported by the SoftHSM2 CNG Key Storage Provider (KSP). '
        'The KSP translates Microsoft NCrypt API calls into PKCS#11 v2.40 calls '
        'forwarded to softhsm2-x64.dll at runtime (LoadLibrary — no static link).'
    ).runs[0].font.size = Pt(10)

    add_heading(doc, '1.1 Supported Key Families', 2)
    add_table(doc,
        ['Key Family', 'CNG Algorithm ID', 'Key Type', 'Supported Sizes', 'PKCS#11 Gen Mechanism'],
        [
            ['RSA', 'RSA', 'Asymmetric pair', '2048, 3072, 4096 bits', 'CKM_RSA_PKCS_KEY_PAIR_GEN'],
            ['ECDSA P-256', 'ECDSA_P256', 'Asymmetric pair', '256 bits (fixed)', 'CKM_EC_KEY_PAIR_GEN'],
            ['ECDSA P-384', 'ECDSA_P384', 'Asymmetric pair', '384 bits (fixed)', 'CKM_EC_KEY_PAIR_GEN'],
            ['ECDSA P-521', 'ECDSA_P521', 'Asymmetric pair', '521 bits (fixed)', 'CKM_EC_KEY_PAIR_GEN'],
            ['ECDH P-256', 'ECDH_P256', 'Asymmetric pair', '256 bits (fixed)', 'CKM_EC_KEY_PAIR_GEN'],
            ['ECDH P-384', 'ECDH_P384', 'Asymmetric pair', '384 bits (fixed)', 'CKM_EC_KEY_PAIR_GEN'],
            ['ECDH P-521', 'ECDH_P521', 'Asymmetric pair', '521 bits (fixed)', 'CKM_EC_KEY_PAIR_GEN'],
            ['EdDSA Ed25519', 'EDDSA_ED25519', 'Asymmetric pair', '255 bits (fixed)', 'CKM_EC_EDWARDS_KEY_PAIR_GEN'],
            ['EdDSA Ed448', 'EDDSA_ED448', 'Asymmetric pair', '448 bits (fixed)', 'CKM_EC_EDWARDS_KEY_PAIR_GEN'],
            ['AES', 'AES', 'Symmetric secret', '128, 192, 256 bits', 'CKM_AES_KEY_GEN'],
            ['HMAC', 'HMAC_SHA1/256/384/512', 'Symmetric secret', '160 / 256 / 384 / 512 bits', 'CKM_GENERIC_SECRET_KEY_GEN'],
        ],
        col_widths=[3.0, 3.5, 3.0, 4.0, 5.5]
    )
    doc.add_paragraph()

    add_note(doc,
        'Default RSA key size is 2048 bits. EC sizes are fixed by curve. '
        'RSA key sizes other than 2048 / 3072 / 4096 are rejected with NTE_BAD_LEN.'
    )

    # ── 2. Key Generation ─────────────────────────────────────────────────
    doc.add_paragraph()
    add_heading(doc, '2. Key Generation', 1)

    add_heading(doc, '2.1 RSA Key Generation', 2)
    doc.add_paragraph(
        'RSA key pairs are generated with CKM_RSA_PKCS_KEY_PAIR_GEN. '
        'The public exponent is always 65537 (0x010001). '
        'Deferred generation (NCRYPT_PERSIST_ONLY_FLAG) is supported: the key structure '
        'is allocated without generating the pair; NCryptSetProperty(LENGTH) then sets '
        'the modulus size; NCryptFinalizeKey triggers actual generation.'
    ).runs[0].font.size = Pt(10)

    add_table(doc,
        ['Modulus Size', 'PKCS#11 Mechanism', 'Public Exponent', 'Storage', 'CKA_SENSITIVE', 'CKA_EXTRACTABLE'],
        [
            ['2048 bits', 'CKM_RSA_PKCS_KEY_PAIR_GEN', '65537 (0x010001)', 'CKA_TOKEN=TRUE', 'TRUE', 'FALSE'],
            ['3072 bits', 'CKM_RSA_PKCS_KEY_PAIR_GEN', '65537 (0x010001)', 'CKA_TOKEN=TRUE', 'TRUE', 'FALSE'],
            ['4096 bits', 'CKM_RSA_PKCS_KEY_PAIR_GEN', '65537 (0x010001)', 'CKA_TOKEN=TRUE', 'TRUE', 'FALSE'],
        ],
        col_widths=[2.5, 4.5, 4.0, 3.0, 3.0, 3.0]
    )
    doc.add_paragraph()

    add_heading(doc, '2.2 EC Key Generation', 2)
    doc.add_paragraph(
        'EC key pairs are generated with CKM_EC_KEY_PAIR_GEN. '
        'The curve is specified via CKA_EC_PARAMS (DER-encoded OID). '
        'EC keys are AT_SIGNATURE only — decryption (ECDH) is not implemented.'
    ).runs[0].font.size = Pt(10)

    add_table(doc,
        ['Curve', 'CNG Algorithm ID', 'Coordinate Size', 'CKA_EC_PARAMS (DER OID)', 'OID Hex', 'AT_ Spec'],
        [
            ['P-256 (secp256r1)', 'ECDSA_P256 / ECDH_P256', '32 bytes', 'prime256v1', '06 08 2A 86 48 CE 3D 03 01 07  (10 bytes)', 'AT_SIGNATURE / AT_KEYEXCHANGE'],
            ['P-384 (secp384r1)', 'ECDSA_P384 / ECDH_P384', '48 bytes', 'secp384r1',  '06 05 2B 81 04 00 22  (7 bytes)',           'AT_SIGNATURE / AT_KEYEXCHANGE'],
            ['P-521 (secp521r1)', 'ECDSA_P521 / ECDH_P521', '66 bytes', 'secp521r1',  '06 05 2B 81 04 00 23  (7 bytes)',           'AT_SIGNATURE / AT_KEYEXCHANGE'],
            ['Ed25519',           'EDDSA_ED25519',          '32 bytes (raw key)', 'Ed25519', '06 03 2B 65 70  (5 bytes)',          'AT_SIGNATURE'],
            ['Ed448',             'EDDSA_ED448',            '57 bytes (raw key)', 'Ed448',   '06 03 2B 65 71  (5 bytes)',          'AT_SIGNATURE'],
        ],
        col_widths=[3.0, 4.0, 3.0, 2.5, 5.5, 4.0]
    )

    doc.add_paragraph()
    add_note(doc,
        'ECDSA and ECDH keys share the same generation mechanism and curve OIDs. '
        'They are distinguished by CKA_DERIVE: an ECDH key sets CKA_DERIVE=TRUE '
        'and CKA_SIGN=FALSE, an ECDSA key the reverse. EdDSA keys use the '
        'Edwards-curve generation mechanism and are signature-only.'
    )
    doc.add_paragraph()

    # ── 3. Signing ────────────────────────────────────────────────────────
    add_heading(doc, '3. Signing Operations', 1)

    add_heading(doc, '3.1 RSA Signing', 2)
    add_table(doc,
        ['Padding Mode', 'CNG Flag', 'PKCS#11 Mechanism', 'Padding Info Struct (CNG)', 'Hash Algorithms', 'Output Size'],
        [
            ['PKCS#1 v1.5', 'NCRYPT_PAD_PKCS1_FLAG (0x2)', 'CKM_RSA_PKCS',
             'BCRYPT_PKCS1_PADDING_INFO { pszAlgId }',
             'SHA-1 (20 B)\nSHA-256 (32 B)\nSHA-384 (48 B)\nSHA-512 (64 B)',
             '256 B (RSA-2048)\n384 B (RSA-3072)\n512 B (RSA-4096)'],
            ['PSS', 'NCRYPT_PAD_PSS_FLAG (0x8)', 'CKM_RSA_PKCS_PSS',
             'BCRYPT_PSS_PADDING_INFO { pszAlgId, cbSalt }',
             'SHA-1 (20 B)\nSHA-256 (32 B)\nSHA-384 (48 B)\nSHA-512 (64 B)',
             '256 B (RSA-2048)\n384 B (RSA-3072)\n512 B (RSA-4096)'],
        ],
        col_widths=[3.0, 4.0, 4.0, 5.5, 3.5, 4.0]
    )
    doc.add_paragraph()

    add_heading(doc, 'RSA PSS — PKCS#11 Parameter Mapping', 3)
    add_table(doc,
        ['CNG Hash (pszAlgId)', 'CK_RSA_PKCS_PSS_PARAMS.hashAlg', 'CK_RSA_PKCS_PSS_PARAMS.mgf', 'Typical cbSalt'],
        [
            ['SHA1 / BCRYPT_SHA1_ALGORITHM',   'CKM_SHA_1',   'CKG_MGF1_SHA1',   '20 bytes'],
            ['SHA256 / BCRYPT_SHA256_ALGORITHM','CKM_SHA256',  'CKG_MGF1_SHA256', '32 bytes'],
            ['SHA384 / BCRYPT_SHA384_ALGORITHM','CKM_SHA384',  'CKG_MGF1_SHA384', '48 bytes'],
            ['SHA512 / BCRYPT_SHA512_ALGORITHM','CKM_SHA512',  'CKG_MGF1_SHA512', '64 bytes'],
        ],
        col_widths=[5.5, 5.0, 5.0, 3.0]
    )
    doc.add_paragraph()

    add_heading(doc, '3.2 ECDSA Signing', 2)
    add_table(doc,
        ['Curve', 'CNG Algorithm ID', 'Recommended Hash', 'CNG Flag', 'PKCS#11 Mechanism', 'PKCS#11 Output Format', 'KSP Output Format', 'Signature Size'],
        [
            ['P-256', 'ECDSA_P256', 'SHA-256 (32 B)', '0 (no padding)', 'CKM_ECDSA', 'DER ASN.1 (30 XX 02 XX r 02 XX s)', 'Raw r‖s (Windows)', '64 bytes (r=32, s=32)'],
            ['P-384', 'ECDSA_P384', 'SHA-384 (48 B)', '0 (no padding)', 'CKM_ECDSA', 'DER ASN.1 (30 XX 02 XX r 02 XX s)', 'Raw r‖s (Windows)', '96 bytes (r=48, s=48)'],
            ['P-521', 'ECDSA_P521', 'SHA-512 (64 B)', '0 (no padding)', 'CKM_ECDSA', 'DER ASN.1, long-form length', 'Raw r‖s (Windows)', '132 bytes (r=66, s=66)'],
        ],
        col_widths=[2.0, 3.0, 3.5, 2.5, 3.0, 5.0, 4.0, 3.5]
    )

    doc.add_paragraph()
    add_heading(doc, '3.3 EdDSA Signing', 2)
    doc.add_paragraph(
        'EdDSA is deterministic and takes no padding parameters. Unlike ECDSA, '
        'SoftHSM2 returns the signature already in raw form, so no DER decoding '
        'is performed. EdDSA hashes the message internally, so the value passed '
        'to NCryptSignHash is the message rather than a pre-computed digest.'
    ).runs[0].font.size = Pt(10)

    add_table(doc,
        ['Curve', 'CNG Algorithm ID', 'CNG Flag', 'PKCS#11 Mechanism', 'Output Format', 'Signature Size', 'Public Key Size'],
        [
            ['Ed25519', 'EDDSA_ED25519', '0 (no padding)', 'CKM_EDDSA', 'Raw (no conversion)', '64 bytes', '32 bytes'],
            ['Ed448',   'EDDSA_ED448',   '0 (no padding)', 'CKM_EDDSA', 'Raw (no conversion)', '114 bytes', '57 bytes'],
        ],
        col_widths=[2.5, 3.5, 3.0, 3.0, 4.0, 3.0, 3.0]
    )

    doc.add_paragraph()
    add_heading(doc, '3.4 HMAC (Symmetric MAC)', 2)
    add_table(doc,
        ['CNG Algorithm ID', 'PKCS#11 Mechanism', 'Key Type', 'Default Key Size', 'MAC Output'],
        [
            ['HMAC_SHA1',   'CKM_SHA_1_HMAC',  'CKK_GENERIC_SECRET', '160 bits', '20 bytes'],
            ['HMAC_SHA256', 'CKM_SHA256_HMAC', 'CKK_GENERIC_SECRET', '256 bits', '32 bytes'],
            ['HMAC_SHA384', 'CKM_SHA384_HMAC', 'CKK_GENERIC_SECRET', '384 bits', '48 bytes'],
            ['HMAC_SHA512', 'CKM_SHA512_HMAC', 'CKK_GENERIC_SECRET', '512 bits', '64 bytes'],
        ],
        col_widths=[4.0, 4.5, 4.5, 3.5, 3.5]
    )
    doc.add_paragraph()

    add_note(doc,
        'SoftHSM2 returns ECDSA signatures in DER format. The KSP converts them to '
        'Windows raw r‖s format via P11_DecodeDerEcdsaSignature() in p11_utils.c.'
    )

    # ── 4. Decryption ─────────────────────────────────────────────────────
    doc.add_paragraph()
    add_heading(doc, '4. Decryption Operations', 1)
    doc.add_paragraph(
        'RSA keys (AT_KEYEXCHANGE) support asymmetric decryption; AES keys '
        'support symmetric decryption. ECDSA and EdDSA curves are '
        'signature-only; ECDH curves perform key agreement rather than '
        'decryption.'
    ).runs[0].font.size = Pt(10)

    add_table(doc,
        ['Padding Mode', 'CNG Flag', 'PKCS#11 Mechanism', 'Padding Info Struct (CNG)', 'Hash (OAEP only)', 'Key Spec Required'],
        [
            ['PKCS#1 v1.5', 'NCRYPT_PAD_PKCS1_FLAG (0x2)', 'CKM_RSA_PKCS',
             'NULL', 'N/A', 'AT_KEYEXCHANGE'],
            ['OAEP', 'NCRYPT_PAD_OAEP_FLAG (0x4)', 'CKM_RSA_PKCS_OAEP',
             'BCRYPT_OAEP_PADDING_INFO { pszAlgId, pbLabel, cbLabel }',
             'SHA-1, SHA-256', 'AT_KEYEXCHANGE'],
        ],
        col_widths=[3.0, 4.5, 4.0, 5.5, 3.0, 3.5]
    )
    doc.add_paragraph()

    add_heading(doc, 'RSA OAEP — PKCS#11 Parameter Mapping', 3)
    add_table(doc,
        ['CNG Hash (pszAlgId)', 'CK_RSA_PKCS_OAEP_PARAMS.hashAlg', 'CK_RSA_PKCS_OAEP_PARAMS.mgf', 'source', 'pSourceData / ulSourceDataLen'],
        [
            ['SHA1',   'CKM_SHA_1',  'CKG_MGF1_SHA1',   'CKZ_DATA_SPECIFIED', 'pbLabel / cbLabel (optional)'],
            ['SHA224', 'CKM_SHA224', 'CKG_MGF1_SHA224', 'CKZ_DATA_SPECIFIED', 'pbLabel / cbLabel (optional)'],
            ['SHA256', 'CKM_SHA256', 'CKG_MGF1_SHA256', 'CKZ_DATA_SPECIFIED', 'pbLabel / cbLabel (optional)'],
            ['SHA384', 'CKM_SHA384', 'CKG_MGF1_SHA384', 'CKZ_DATA_SPECIFIED', 'pbLabel / cbLabel (optional)'],
            ['SHA512', 'CKM_SHA512', 'CKG_MGF1_SHA512', 'CKZ_DATA_SPECIFIED', 'pbLabel / cbLabel (optional)'],
        ],
        col_widths=[3.5, 5.0, 5.0, 4.0, 6.0]
    )
    doc.add_paragraph()

    add_heading(doc, '4.1 AES Symmetric Encryption and Decryption', 2)
    doc.add_paragraph(
        'AES keys follow the CNG symmetric contract: the chaining mode is set '
        'through NCRYPT_CHAINING_MODE_PROPERTY and the IV or nonce through '
        'NCRYPT_INITIALIZATION_VECTOR, both before the operation. The same '
        'mechanism serves NCryptEncrypt and NCryptDecrypt.'
    ).runs[0].font.size = Pt(10)

    add_table(doc,
        ['Chaining Mode', 'NCRYPT_CHAINING_MODE_PROPERTY', 'PKCS#11 Mechanism', 'IV / Nonce', 'Parameter Struct', 'Notes'],
        [
            ['ECB', 'ChainingModeECB', 'CKM_AES_ECB', 'None', '—', 'Input must be whole blocks'],
            ['CBC', 'ChainingModeCBC', 'CKM_AES_CBC', '16 bytes', 'Raw IV bytes', 'Unpadded'],
            ['CBC + padding', 'ChainingModeCBC', 'CKM_AES_CBC_PAD', '16 bytes', 'Raw IV bytes', 'Selected by NCRYPT_PAD_CIPHER_FLAG'],
            ['CTR', 'ChainingModeCTR', 'CKM_AES_CTR', '16 bytes', 'CK_AES_CTR_PARAMS', 'KSP extension; 32-bit counter'],
            ['GCM', 'ChainingModeGCM', 'CKM_AES_GCM', '12 bytes typical', 'CK_GCM_PARAMS', 'AAD via NCRYPT_AUTH_TAG_LENGTH; 128-bit tag'],
        ],
        col_widths=[3.0, 4.5, 3.5, 3.0, 4.0, 5.0]
    )
    doc.add_paragraph()

    add_note(doc,
        'CCM and CFB are rejected with NTE_NOT_SUPPORTED: no SoftHSM2 mechanism '
        'is wired to them. AES key sizes outside 128 / 192 / 256 bits are '
        'rejected with NTE_BAD_LEN.'
    )
    doc.add_paragraph()

    add_heading(doc, '4.2 ECDH Key Agreement', 2)
    doc.add_paragraph(
        'ECDH is exposed through the CNG secret-agreement functions. '
        'NCryptSecretAgreement derives a shared secret from a local private key '
        'and a peer public key, returning an NCRYPT_SECRET_HANDLE; '
        'NCryptDeriveKey then extracts the raw secret, and NCryptFreeObject '
        'releases it.'
    ).runs[0].font.size = Pt(10)

    add_table(doc,
        ['Curve', 'CNG Algorithm ID', 'PKCS#11 Mechanism', 'KDF', 'Shared Secret Size', 'Supported KDF'],
        [
            ['P-256', 'ECDH_P256', 'CKM_ECDH1_DERIVE', 'CKD_NULL', '32 bytes', 'BCRYPT_KDF_RAW_SECRET'],
            ['P-384', 'ECDH_P384', 'CKM_ECDH1_DERIVE', 'CKD_NULL', '48 bytes', 'BCRYPT_KDF_RAW_SECRET'],
            ['P-521', 'ECDH_P521', 'CKM_ECDH1_DERIVE', 'CKD_NULL', '66 bytes', 'BCRYPT_KDF_RAW_SECRET'],
        ],
        col_widths=[2.5, 3.5, 4.0, 3.0, 4.0, 5.0]
    )
    doc.add_paragraph()

    add_note(doc,
        'The KSP requests CKD_NULL so SoftHSM2 returns the raw Z value; any KDF '
        'is applied afterwards. Hash-based KDFs through NCryptDeriveKey return '
        'NTE_NOT_SUPPORTED — request the raw secret and run the KDF with BCrypt. '
        'Both keys must sit on the same curve, or the call returns NTE_BAD_ALGID.'
    )

    # ── 5. Key Export / Import ─────────────────────────────────────────────
    add_heading(doc, '5. Key Export and Import', 1)
    add_table(doc,
        ['Operation', 'Blob Type', 'Supported', 'Notes'],
        [
            ['RSA public key export',  'BCRYPT_RSAPUBLIC_BLOB',     '✓ Supported',     'BCRYPT_RSAKEY_BLOB header + exponent + modulus'],
            ['EC public key export',   'BCRYPT_ECCPUBLIC_BLOB',     '✓ Supported',     'BCRYPT_ECCKEY_BLOB header + X + Y coordinates'],
            ['EdDSA public key export','BCRYPT_ECCPUBLIC_BLOB',     '✓ Supported',     'Generic ECC magic + single raw point'],
            ['RSA public key import',  'BCRYPT_RSAPUBLIC_BLOB',     '✓ Supported',     'Creates a CKO_PUBLIC_KEY session object'],
            ['EC public key import',   'BCRYPT_ECCPUBLIC_BLOB',     '✓ Supported',     'Creates a CKO_PUBLIC_KEY session object; usable as an ECDH peer'],
            ['RSA private key export', 'BCRYPT_RSAFULLPRIVATE_BLOB','✗ NTE_NOT_SUPPORTED', 'Keys marked CKA_EXTRACTABLE=FALSE'],
            ['EC private key export',  'BCRYPT_ECCPRIVATE_BLOB',    '✗ NTE_NOT_SUPPORTED', 'Keys marked CKA_EXTRACTABLE=FALSE'],
            ['Private key import',     'Any',                        '✗ Not implemented',   'HSM design — private material never leaves SoftHSM2'],
        ],
        col_widths=[4.5, 5.5, 4.0, 9.5]
    )
    doc.add_paragraph()

    add_heading(doc, '5.1 RSA Public Key Blob Layout (BCRYPT_RSAPUBLIC_BLOB)', 2)
    add_code_block(doc,
        'typedef struct {\n'
        '    ULONG Magic;           // BCRYPT_RSAPUBLIC_MAGIC (0x31415352)\n'
        '    ULONG BitLength;       // modulus bit length (2048 / 3072 / 4096)\n'
        '    ULONG cbPublicExp;     // public exponent byte count (typically 3)\n'
        '    ULONG cbModulus;       // modulus byte count (256 / 384 / 512)\n'
        '    ULONG cbPrime1;        // 0 for public blob\n'
        '    ULONG cbPrime2;        // 0 for public blob\n'
        '} BCRYPT_RSAKEY_BLOB;\n'
        '// followed by: public exponent (cbPublicExp bytes) + modulus (cbModulus bytes)'
    )
    doc.add_paragraph()

    add_heading(doc, '5.2 EC Public Key Blob Layout (BCRYPT_ECCPUBLIC_BLOB)', 2)
    add_code_block(doc,
        'typedef struct {\n'
        '    ULONG dwMagic;   // BCRYPT_ECDSA_PUBLIC_P256_MAGIC (0x31534345)\n'
        '                     // or BCRYPT_ECDSA_PUBLIC_P384_MAGIC (0x33534345)\n'
        '    ULONG cbKey;     // coordinate size in bytes (32 for P-256, 48 for P-384)\n'
        '} BCRYPT_ECCKEY_BLOB;\n'
        '// followed by: X coordinate (cbKey bytes) + Y coordinate (cbKey bytes)'
    )
    doc.add_paragraph()

    # ── 6. Key Properties ─────────────────────────────────────────────────
    add_heading(doc, '6. Key Properties (NCrypt)', 1)

    add_heading(doc, '6.1 Key Object Properties', 2)
    add_table(doc,
        ['NCrypt Property Name', 'Windows Constant', 'Access', 'RSA Values', 'EC Values'],
        [
            ['Algorithm Name', 'NCRYPT_ALGORITHM_PROPERTY', 'R', '"RSA"', '"ECDSA_P256" or "ECDSA_P384"'],
            ['Length', 'NCRYPT_LENGTH_PROPERTY', 'R/W (pre-finalize)', '2048, 3072, or 4096', '256 (P-256) or 384 (P-384)'],
            ['Key Type', 'NCRYPT_KEY_TYPE_PROPERTY', 'R', 'AT_SIGNATURE (2) or AT_KEYEXCHANGE (1)', 'AT_SIGNATURE (2)'],
            ['Name', 'NCRYPT_NAME_PROPERTY', 'R', 'Key label (CKA_LABEL string)', 'Key label (CKA_LABEL string)'],
            ['Unique Name', 'NCRYPT_UNIQUE_NAME_PROPERTY', 'R', 'Same as key label', 'Same as key label'],
            ['Export Policy', 'NCRYPT_EXPORT_POLICY_PROPERTY', 'R', '0 (non-exportable)', '0 (non-exportable)'],
            ['Key Usage', 'NCRYPT_KEY_USAGE_PROPERTY', 'R',
             'AT_SIGNATURE → NCRYPT_ALLOW_SIGNING_FLAG (2)\nAT_KEYEXCHANGE → NCRYPT_ALLOW_DECRYPT_FLAG (1)',
             'NCRYPT_ALLOW_SIGNING_FLAG (2)'],
            ['Algorithm Group', 'NCRYPT_ALGORITHM_GROUP_PROPERTY', 'R', '"RSA"', '"ECDSA"'],
        ],
        col_widths=[4.0, 5.5, 1.5, 5.0, 5.5]
    )
    doc.add_paragraph()

    add_heading(doc, '6.2 Provider Object Properties', 2)
    add_table(doc,
        ['NCrypt Property Name', 'Windows Constant', 'Value'],
        [
            ['Name',            'NCRYPT_NAME_PROPERTY',      '"SoftHSM KSP"'],
            ['Version',         'NCRYPT_VERSION_PROPERTY',   '1'],
            ['Implementation Type', 'NCRYPT_IMPL_TYPE_PROPERTY', 'NCRYPT_IMPL_HARDWARE_FLAG set'],
        ],
        col_widths=[5.0, 6.0, 10.0]
    )
    doc.add_paragraph()

    # ── 7. Key Persistence & Security ─────────────────────────────────────
    add_heading(doc, '7. Key Persistence and Security Attributes', 1)
    doc.add_paragraph(
        'All keys — regardless of algorithm — are created with the following PKCS#11 '
        'attributes to emulate a hardware HSM:'
    ).runs[0].font.size = Pt(10)

    add_code_block(doc,
        'CKA_TOKEN       = TRUE   // Key is persistent on the SoftHSM2 token (SQLite)\n'
        'CKA_SENSITIVE   = TRUE   // Key material is sensitive\n'
        'CKA_EXTRACTABLE = FALSE  // Private key cannot be extracted\n'
        'CKA_LABEL       = <key name>  // NCrypt key name maps to PKCS#11 label\n'
        '\n'
        '// AT_SIGNATURE keys additionally:\n'
        'CKA_SIGN        = TRUE   // RSA PKCS1/PSS and ECDSA\n'
        '\n'
        '// AT_KEYEXCHANGE RSA keys additionally:\n'
        'CKA_DECRYPT     = TRUE   // RSA PKCS1 and OAEP decryption'
    )
    doc.add_paragraph()

    add_table(doc,
        ['PKCS#11 Attribute', 'Value', 'Applies to', 'Purpose'],
        [
            ['CKA_TOKEN',       'TRUE',  'All keys',      'Persistent storage in SoftHSM2 SQLite database'],
            ['CKA_SENSITIVE',   'TRUE',  'All keys',      'Marks key as sensitive (cannot be read in clear)'],
            ['CKA_EXTRACTABLE', 'FALSE', 'All keys',      'Prevents private key from being exported'],
            ['CKA_LABEL',       'Key name string', 'All keys', 'Maps NCrypt key name to PKCS#11 object label'],
            ['CKA_SIGN',        'TRUE',  'AT_SIGNATURE',  'Enables sign operations (RSA and ECDSA)'],
            ['CKA_DECRYPT',     'TRUE',  'AT_KEYEXCHANGE RSA only', 'Enables decrypt operations (RSA PKCS1/OAEP)'],
        ],
        col_widths=[4.0, 4.0, 5.0, 9.5]
    )
    doc.add_paragraph()

    # ── 8. Known Limitations ──────────────────────────────────────────────
    add_heading(doc, '8. Known Limitations', 1)
    add_table(doc,
        ['Feature', 'Status', 'Reason'],
        [
            ['Raw RSA (CKM_RSA_X_509)',           '✗ Not supported', 'SoftHSM2 does not implement CKM_RSA_X_509'],
            ['Private key import',                 '✗ Not supported', 'HSM design principle — private material never leaves the device'],
            ['Multiple HSM slots',                 '✗ Not supported', 'Only the first slot with a token present is used'],
            ['RSA sizes other than 2048/3072/4096','✗ Rejected (NTE_BAD_LEN)', 'Hardcoded validation in ksp_properties.c'],
            ['AES sizes other than 128/192/256',   '✗ Rejected (NTE_BAD_LEN)', 'Hardcoded validation in ksp_properties.c'],
            ['EC curves beyond P-256/384/521, Ed25519, Ed448', '✗ Not supported', 'Only these OIDs are defined in config.h'],
            ['AES-CCM and AES-CFB',                '✗ NTE_NOT_SUPPORTED', 'No SoftHSM2 mechanism wired to these modes'],
            ['Hash-based KDFs in NCryptDeriveKey', '✗ NTE_NOT_SUPPORTED', 'Request BCRYPT_KDF_RAW_SECRET and run the KDF with BCrypt'],
            ['DES / 3DES, DSA, PKCS#3 DH, GOST',   '✗ Out of scope', 'Deprecated, or outside the Microsoft HLK test plan'],
            ['Raw hash and sign-with-hash mechanisms', '✗ Unreachable by design', 'CNG always supplies NCryptSignHash a pre-computed digest'],
            ['SHA-3 family hash algorithms',        '✗ Not supported', 'SoftHSM2 PKCS#11 hash mapping not defined'],
            ['Re-initialization without process restart', '✗ Not supported', 'InitOnceExecuteOnce is a one-shot barrier'],
        ],
        col_widths=[6.5, 4.5, 12.5]
    )
    doc.add_paragraph()

    # ── 9. Quick-Reference Summary ────────────────────────────────────────
    add_heading(doc, '9. Quick-Reference Summary', 1)
    add_table(doc,
        ['Algorithm', 'Key Size(s)', 'Key Spec', 'Sign PKCS1', 'Sign PSS', 'Sign ECDSA', 'Decrypt PKCS1', 'Decrypt OAEP', 'Export Public'],
        [
            ['RSA-2048', '2048 bits', 'AT_SIGN or AT_KE', '✓', '✓', '—', '✓ (AT_KE)', '✓ (AT_KE)', '✓'],
            ['RSA-3072', '3072 bits', 'AT_SIGN or AT_KE', '✓', '✓', '—', '✓ (AT_KE)', '✓ (AT_KE)', '✓'],
            ['RSA-4096', '4096 bits', 'AT_SIGN or AT_KE', '✓', '✓', '—', '✓ (AT_KE)', '✓ (AT_KE)', '✓'],
            ['ECDSA P-256', '256 bits', 'AT_SIGNATURE',   '—', '—', '✓', '—', '—', '✓'],
            ['ECDSA P-384', '384 bits', 'AT_SIGNATURE',   '—', '—', '✓', '—', '—', '✓'],
            ['ECDSA P-521', '521 bits', 'AT_SIGNATURE',   '—', '—', '✓', '—', '—', '✓'],
            ['ECDH P-256',  '256 bits', 'AT_KEYEXCHANGE', '—', '—', '—', '—', '—', '✓'],
            ['ECDH P-384',  '384 bits', 'AT_KEYEXCHANGE', '—', '—', '—', '—', '—', '✓'],
            ['ECDH P-521',  '521 bits', 'AT_KEYEXCHANGE', '—', '—', '—', '—', '—', '✓'],
            ['Ed25519', '255 bits', 'AT_SIGNATURE', '—', '—', '✓ (EdDSA)', '—', '—', '✓'],
            ['Ed448',   '448 bits', 'AT_SIGNATURE', '—', '—', '✓ (EdDSA)', '—', '—', '✓'],
            ['AES-128', '128 bits', 'Symmetric', '—', '—', '—', '—', '✓ (4 modes)', '—'],
            ['AES-192', '192 bits', 'Symmetric', '—', '—', '—', '—', '✓ (4 modes)', '—'],
            ['AES-256', '256 bits', 'Symmetric', '—', '—', '—', '—', '✓ (4 modes)', '—'],
            ['HMAC-SHA256', '256 bits', 'Symmetric', '—', '—', '✓ (MAC)', '—', '—', '—'],
        ],
        col_widths=[3.5, 2.5, 3.5, 2.5, 2.5, 3.0, 3.5, 3.5, 3.5]
    )

    doc.add_paragraph()
    p2 = doc.add_paragraph()
    r2 = p2.add_run('ECDH key agreement is exercised through NCryptSecretAgreement '
                    'and NCryptDeriveKey rather than the sign/decrypt columns above.')
    r2.font.size = Pt(8)
    r2.font.italic = True
    r2.font.color.rgb = RGBColor(0x60, 0x60, 0x60)
    doc.add_paragraph()

    p = doc.add_paragraph()
    r = p.add_run('AT_SIGN = AT_SIGNATURE (2)  |  AT_KE = AT_KEYEXCHANGE (1)')
    r.font.size = Pt(8)
    r.font.italic = True
    r.font.color.rgb = RGBColor(0x60, 0x60, 0x60)

    out = 'softhsm_ksp/SoftHSM2_KSP_Algorithm_Reference.docx'
    doc.save(out)
    print(f'Saved: {out}')


if __name__ == '__main__':
    build()
