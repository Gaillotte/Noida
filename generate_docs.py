"""
Generate full project documentation + test specification in Word format.
Run: python generate_docs.py
"""

import datetime
from docx import Document
from docx.shared import Pt, Inches, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.style import WD_STYLE_TYPE
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import io

# ── colour palette ────────────────────────────────────────────────────────────
DARK_BLUE  = RGBColor(0x1A, 0x3A, 0x5C)
MID_BLUE   = RGBColor(0x2E, 0x6D, 0xA4)
LIGHT_BLUE = RGBColor(0xDE, 0xEB, 0xF7)
DARK_GREY  = RGBColor(0x40, 0x40, 0x40)
PASS_GREEN = RGBColor(0x1E, 0x80, 0x2E)
FAIL_RED   = RGBColor(0xC0, 0x0F, 0x0F)
CODE_BG    = RGBColor(0xF5, 0xF5, 0xF5)

TODAY = datetime.date.today().strftime("%d %B %Y")


# ── helpers ───────────────────────────────────────────────────────────────────

def set_cell_bg(cell, hex_color: str):
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd  = OxmlElement('w:shd')
    shd.set(qn('w:fill'), hex_color)
    shd.set(qn('w:val'),  'clear')
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
    run.bold   = bold
    run.italic = italic
    run.font.size = Pt(size)
    if colour:
        run.font.color.rgb = colour
    return p


def add_code(doc, text):
    p = doc.add_paragraph(style='No Spacing')
    p.paragraph_format.left_indent  = Inches(0.3)
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after  = Pt(2)
    run = p.add_run(text)
    run.font.name = 'Courier New'
    run.font.size = Pt(8.5)
    run.font.color.rgb = RGBColor(0x00, 0x33, 0x66)
    return p


def add_bullet(doc, text, level=0):
    p = doc.add_paragraph(style='List Bullet')
    p.paragraph_format.left_indent = Inches(0.3 + level * 0.25)
    p.add_run(text)
    return p


def section_break(doc):
    doc.add_paragraph()


def add_table_header_row(table, headers, bg="1A3A5C"):
    row = table.rows[0]
    for i, h in enumerate(headers):
        cell = row.cells[i]
        cell.text = h
        set_cell_bg(cell, bg)
        for para in cell.paragraphs:
            for run in para.runs:
                run.bold = True
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                run.font.size = Pt(9)


def add_table_row(table, values, alt=False):
    row = table.add_row()
    bg  = "EEF4FA" if alt else "FFFFFF"
    for i, v in enumerate(values):
        cell = row.cells[i]
        cell.text = str(v)
        set_cell_bg(cell, bg)
        for para in cell.paragraphs:
            for run in para.runs:
                run.font.size = Pt(8.5)
    return row


# ══════════════════════════════════════════════════════════════════════════════
# Document build
# ══════════════════════════════════════════════════════════════════════════════

def build():
    doc = Document()

    # ── page margins ──────────────────────────────────────────────────────────
    for sec in doc.sections:
        sec.top_margin    = Inches(1.0)
        sec.bottom_margin = Inches(1.0)
        sec.left_margin   = Inches(1.2)
        sec.right_margin  = Inches(1.2)

    # ── default body font ────────────────────────────────────────────────────
    doc.styles['Normal'].font.name = 'Calibri'
    doc.styles['Normal'].font.size = Pt(10)

    # ═══════════════════════════════════════════════════════════════════════
    # TITLE PAGE
    # ═══════════════════════════════════════════════════════════════════════
    doc.add_paragraph()
    doc.add_paragraph()

    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    tr = title.add_run("KMIP on PKCS#11")
    tr.bold = True
    tr.font.size = Pt(28)
    tr.font.color.rgb = DARK_BLUE

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sr = sub.add_run("Full Project Documentation & Test Specification")
    sr.font.size = Pt(16)
    sr.font.color.rgb = MID_BLUE

    doc.add_paragraph()

    info_lines = [
        ("Project",   "KMIP 2.1 Server on PKCS#11 / SoftHSM2"),
        ("Version",   "1.0.0"),
        ("Standard",  "OASIS KMIP 2.1 (OASIS kmip-spec-v2.1-os)"),
        ("Date",      TODAY),
        ("Language",  "Python 3.9+"),
        ("HSM",       "SoftHSM2 / any PKCS#11-compliant HSM"),
    ]
    info = doc.add_table(rows=len(info_lines), cols=2)
    info.style = 'Table Grid'
    for i, (k, v) in enumerate(info_lines):
        info.rows[i].cells[0].text = k
        info.rows[i].cells[1].text = v
        info.rows[i].cells[0].width = Inches(1.5)
        info.rows[i].cells[1].width = Inches(4.5)
        set_cell_bg(info.rows[i].cells[0], "1A3A5C")
        for para in info.rows[i].cells[0].paragraphs:
            for run in para.runs:
                run.bold = True
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                run.font.size = Pt(9)
        for para in info.rows[i].cells[1].paragraphs:
            for run in para.runs:
                run.font.size = Pt(9)

    doc.add_page_break()

    # ═══════════════════════════════════════════════════════════════════════
    # 1. EXECUTIVE SUMMARY
    # ═══════════════════════════════════════════════════════════════════════
    add_heading(doc, "1. Executive Summary", 1, DARK_BLUE)

    add_para(doc,
        "This document is the complete reference for the kmip_pkcs11 project — a full "
        "implementation of the OASIS Key Management Interoperability Protocol (KMIP) "
        "version 2.1 built on top of a PKCS#11 Hardware Security Module (HSM). "
        "Cryptographic material never leaves the HSM: the KMIP layer manages object "
        "lifecycle, metadata, access control, and protocol framing while delegating all "
        "key operations to PKCS#11."
    )
    section_break(doc)

    add_para(doc, "Key properties of this implementation:", bold=True)
    bullets = [
        "Standards-compliant: OASIS KMIP 2.1 wire format (TTLV binary encoding, batching, "
        "BatchErrorContinuationOption, MaximumResponseSize)",
        "HSM-backed: all key material stored in SoftHSM2 via PKCS#11 (Cryptoki); the shim "
        "is the only file that imports pkcs11, so a FIPS-validated token can be swapped "
        "in with no change above pkcs11_shim/",
        "Full lifecycle: Pre-Active → Active → Deactivated / Compromised → Destroyed, "
        "plus Archive/Recover, ReKey/ReKeyKeyPair/ReCertify, and split-key XOR sharing",
        "Access control (RBAC): every object records its creator; operations against an "
        "existing object require ownership, the admin role, or an explicit delegated "
        "grant — see Section 4.4b",
        "Capability-probed algorithms: the shim queries the token's real mechanism list "
        "at startup and rejects unsupported algorithm/mode combinations cleanly "
        "(OperationNotSupported) instead of leaking a raw PKCS#11 error",
        "Transport: TLS enforced by default (TLS 1.2 floor, hot certificate reload, "
        "optional mTLS-derived identity); plain TCP requires an explicit opt-out",
        "Persistent metadata: SQLite store (WAL mode, versioned migrations) for KMIP "
        "attributes, identities, roles, groups, grants, approvals and a hash-chained "
        "audit log; secret blobs enveloped under an HSM-resident master key",
        "Governance: cryptoperiod enforcement with scheduled deactivation and optional "
        "auto-rotation, and dual control (M-of-N approval) for destructive operations",
        "41 of 53 KMIP operations implemented; 811 automated tests; 100 % pass rate",
    ]
    for b in bullets:
        add_bullet(doc, b)

    # ═══════════════════════════════════════════════════════════════════════
    # 2. PROJECT STRUCTURE
    # ═══════════════════════════════════════════════════════════════════════
    doc.add_page_break()
    add_heading(doc, "2. Project Structure", 1, DARK_BLUE)

    tree = [
        "kmip_pkcs11/",
        "├── core/",
        "│   ├── enums.py                # KMIP enumerations (Tag, Operation, State …)",
        "│   ├── ttlv.py                 # TTLV encoder / decoder",
        "│   └── exceptions.py           # KMIP exception hierarchy",
        "├── lifecycle/",
        "│   ├── state_machine.py        # Key lifecycle state transitions",
        "│   ├── access_control.py       # Owner / admin / grants / groups / role allowlists",
        "│   ├── dual_control.py         # M-of-N approval for destructive operations",
        "│   └── governance.py           # Cryptoperiod scan, scheduled deactivation/rotation",
        "├── metadata/",
        "│   ├── store.py                # SQLite store (objects, attrs, identities, roles,",
        "│   │                           #   groups, grants, approvals, audit chain)",
        "│   ├── backup.py               # Online backup / restore with token pairing checks",
        "│   └── blob_cipher.py          # AES-GCM envelope encryption under an HSM master key",
        "├── pkcs11_shim/",
        "│   └── shim.py                 # PKCS#11 / SoftHSM2 wrapper, capability probe, session lock",
        "├── operations/                 # One file per KMIP operation (41 files) — dispatcher.py routes",
        "│   ├── dispatcher.py",
        "│   ├── create.py                create_keypair.py       register.py",
        "│   ├── import_op.py             export_op.py",
        "│   ├── get.py                   get_attributes.py       get_usage_allocation.py",
        "│   ├── locate.py",
        "│   ├── add_attribute.py         modify_attribute.py     delete_attribute.py",
        "│   ├── set_attribute.py         adjust_attribute.py",
        "│   ├── activate.py              revoke.py               destroy.py",
        "│   ├── archive.py               recover.py              check.py",
        "│   ├── encrypt.py               decrypt.py",
        "│   ├── sign.py                  signature_verify.py",
        "│   ├── mac.py                   mac_verify.py           hash_op.py",
        "│   ├── rekey.py                 rekey_keypair.py",
        "│   ├── certify.py               recertify.py",
        "│   ├── derive_key.py",
        "│   ├── create_split_key.py      join_split_key.py",
        "│   ├── validate.py              obtain_lease.py",
        "│   ├── rng_retrieve.py          rng_seed.py",
        "│   └── query.py                 discover_versions.py",
        "├── server/",
        "│   ├── server.py               # TCP server (thread-per-client, auth, TLS, request caps)",
        "│   └── workers.py              # Pre-fork multi-process worker pool",
        "├── config.py                   # YAML configuration loading and validation",
        "├── observability.py            # Metrics, health endpoints, JSON logging",
        "├── cli/",
        "│   ├── server_cli.py           # kmip-server entry point",
        "│   └── admin_cli.py            # kmip-admin: identities, roles, groups, grants,",
        "│                               #   permissions, approvals, cryptoperiods, audit,",
        "│                               #   backup, master-key rotation",
        "├── test_app/",
        "│   ├── client.py               # Synchronous KMIP 2.1 client",
        "│   └── demo.py                 # End-to-end demo application",
        "└── tests/",
        "    ├── conftest.py             # pytest fixtures (SoftHSM2, store, shim, server)",
        "    ├── test_ttlv.py            #  22 TTLV unit tests",
        "    ├── test_lifecycle.py       #  26 lifecycle state-machine tests",
        "    ├── test_metadata.py        #  18 metadata store unit tests",
        "    ├── test_operations.py      #   8 operation integration tests",
        "    ├── test_conformance.py     #  48 OASIS KMIP conformance tests",
        "    └── test_extended_coverage.py # 502 live tests: every operation, algorithm",
        "                                 #  coverage, error paths, access control,",
        "                                 #  session concurrency",
    ]
    for line in tree:
        add_code(doc, line)

    # ═══════════════════════════════════════════════════════════════════════
    # 3. ARCHITECTURE
    # ═══════════════════════════════════════════════════════════════════════
    doc.add_page_break()
    add_heading(doc, "3. Architecture", 1, DARK_BLUE)

    add_heading(doc, "3.1 Layered Architecture", 2, MID_BLUE)
    add_para(doc,
        "The system is designed as four horizontal layers. Each layer has a single "
        "responsibility and communicates only with the layer directly beneath it."
    )
    section_break(doc)

    layers = [
        ("Layer 4 – Transport", "server/server.py",
         "TCP socket listener. Reads raw bytes from the network, passes them to the "
         "protocol layer, and writes the response bytes back. Optionally wraps the "
         "connection in TLS."),
        ("Layer 3 – Protocol", "core/ttlv.py, operations/dispatcher.py",
         "Decodes the TTLV binary stream into a tree of TTLVItem objects, routes each "
         "RequestBatchItem to the correct handler, and serialises the ResponseMessage."),
        ("Layer 2 – Business Logic", "operations/*.py, lifecycle/state_machine.py, "
                                      "lifecycle/access_control.py",
         "Implements each of the 41 KMIP operations: validates inputs, enforces lifecycle "
         "rules (state machine) and access control (owner / admin role / delegated grant), "
         "updates metadata, and calls the HSM shim."),
        ("Layer 1 – HSM Integration", "pkcs11_shim/shim.py",
         "Wraps python-pkcs11 behind a single session serialized by a threading.RLock "
         "(see Section 3.3). All cryptographic operations (generate, encrypt, decrypt, "
         "sign, verify, MAC, hash, derive, destroy) execute inside the HSM, gated by a "
         "capability probe of the token's mechanism list. Metadata the HSM cannot hold "
         "(lifecycle dates, names, state, ownership) is delegated to Layer 0."),
        ("Layer 0 – Persistence", "metadata/store.py",
         "Thread-safe SQLite store (WAL mode, connection-per-thread). Holds the "
         "authoritative KMIP object state, all KMIP attributes, and the access-control "
         "tables (identity roles, delegated object grants)."),
    ]

    tbl = doc.add_table(rows=1, cols=3)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Layer", "Module(s)", "Responsibility"])
    for i, (lyr, mod, resp) in enumerate(layers):
        add_table_row(tbl, [lyr, mod, resp], alt=(i % 2 == 0))

    section_break(doc)
    add_heading(doc, "3.2 Request Processing Flow", 2, MID_BLUE)

    flow = [
        "1. Client opens a TCP (or TLS) connection to port 5696.",
        "2. Client sends a TTLV-encoded RequestMessage.",
        "3. Server reads exactly one TTLV top-level item using the 8-byte header length.",
        "4. Server decodes the RequestMessage into a TTLVItem tree.",
        "5. For each BatchItem in the request (of 41 registered Operation handlers):",
        "   a. OperationDispatcher reads the Operation tag.",
        "   b. Dispatches to the matching handler function.",
        "   c. Handler validates inputs, checks lifecycle state, checks access control",
        "      (owner / admin role / delegated grant — Section 4.4b), calls shim/store.",
        "   d. Handler returns response payload bytes.",
        "   e. Dispatcher wraps in a success or failure BatchItem.",
        "6. Server encodes the full ResponseMessage and sends it back.",
        "7. Connection remains open for further requests (persistent session).",
    ]
    for f in flow:
        add_code(doc, f)

    section_break(doc)
    add_heading(doc, "3.3 Threading Model", 2, MID_BLUE)
    add_para(doc,
        "The server is thread-per-connection: the accept loop runs in a daemon thread "
        "(start_background()), and every accepted client connection is handled in its "
        "own dedicated daemon thread for the lifetime of that connection."
    )
    add_bullet(doc, "MetadataStore: threading.local connection-per-thread (SQLite WAL mode) "
                    "— each request thread gets its own SQLite connection, so no locking "
                    "is needed at this layer.")
    add_bullet(doc, "PKCS11Shim: exactly ONE shared PKCS#11 session for the whole process, "
                    "used by every connection thread, serialized behind a single "
                    "threading.RLock. shim.py's @_synchronized decorator wraps every "
                    "session-touching method (generate, encrypt, decrypt, sign, verify, "
                    "MAC, hash, derive, destroy, initialize, finalize) so only one thread "
                    "is ever inside the PKCS#11 session at a time.")
    section_break(doc)

    add_para(doc,
        "This single locked session is a deliberate, permanent design decision — not a "
        "stopgap awaiting a connection/session pool. A session pool (one PKCS#11 session "
        "per thread, no shared lock) was built and tested, and reproducibly segfaulted "
        "or corrupted operations under concurrency. The root cause: python-pkcs11 0.9.5 "
        "calls C_Initialize(NULL), which leaves CKF_OS_LOCKING_OK unset, so the "
        "underlying PKCS#11 library's own internal thread safety is never enabled. "
        "Verified live against this SoftHSM2 build — N threads, each on its own session, "
        "calling generate_key/encrypt/decrypt concurrently, reproducibly either "
        "segfaulted the native extension or returned GeneralError/MechanismInvalid on "
        "most threads. Separate sessions do not make PKCS#11 access safe under this "
        "binding, so a session pool is not a viable fix here.",
        bold=False,
    )
    section_break(doc)
    add_para(doc, "A real fix for this would require one of:", bold=True)
    add_bullet(doc, "A PKCS#11 binding that passes CKF_OS_LOCKING_OK at C_Initialize, "
                    "enabling the library's own internal thread safety, or")
    add_bullet(doc, "A multi-process worker pool, where each process owns exactly one "
                    "PKCS#11 session used by only one thread.")
    add_para(doc,
        "Both are materially larger changes than a lock, and neither has been "
        "implemented; the lock is therefore treated as correctness over throughput, "
        "by design, for the lifetime of this codebase."
    )
    section_break(doc)
    add_bullet(doc, "No other shared mutable state exists at the Python layer between "
                    "request threads beyond the single PKCS#11 session described above.")

    # ═══════════════════════════════════════════════════════════════════════
    # 4. MODULE REFERENCE
    # ═══════════════════════════════════════════════════════════════════════
    doc.add_page_break()
    add_heading(doc, "4. Module Reference", 1, DARK_BLUE)

    # ── 4.1 core/enums.py ────────────────────────────────────────────────
    add_heading(doc, "4.1 core/enums.py — KMIP Enumerations", 2, MID_BLUE)
    add_para(doc,
        "Defines all KMIP enumeration classes as Python IntEnum. "
        "Tag values match the OASIS KMIP TTLV specification exactly."
    )
    enums = [
        ("Tag", "TTLV tag identifiers (0x42xxxx range). Covers all message structures, "
                "attributes, and crypto parameters defined in KMIP 2.1."),
        ("Type", "TTLV item types: Structure(0x01), TextString(0x02), ByteString(0x03), "
                 "Integer(0x04), LongInteger(0x05), BigInteger(0x06), "
                 "Enumeration(0x07), Boolean(0x08), DateTime(0x09)."),
        ("ObjectType", "Certificate, SymmetricKey, PublicKey, PrivateKey, SecretData, "
                       "OpaqueObject (9 types)."),
        ("Operation", "All 53 KMIP operation codes (Create through ReProvision)."),
        ("ResultStatus", "Success, OperationFailed, OperationPending, OperationUndone."),
        ("ResultReason", "18 error reason codes (ItemNotFound, MissingData, "
                         "CryptographicFailure, IllegalOperation, etc.)"),
        ("CryptographicAlgorithm", "40 algorithms including AES, RSA, EC, ECDSA, HMAC-SHA* "
                                   "variants, ChaCha20, SHA3-* family."),
        ("KeyFormatType", "23 key format types (Raw, PKCS#1, PKCS#8, X.509, "
                          "Transparent key formats, etc.)"),
        ("State", "6 lifecycle states: PreActive, Active, Deactivated, Compromised, "
                  "Destroyed, DestroyedCompromised."),
        ("RevocationReasonCode", "7 reason codes (Unspecified, KeyCompromise, CACompromise, "
                                  "AffiliationChanged, Superseded, CessationOfOperation, "
                                  "PrivilegeWithdrawn)."),
        ("CryptographicUsageMask", "20 bit-mask flags (Sign, Verify, Encrypt, Decrypt, "
                                    "WrapKey, UnwrapKey, Export, MACGenerate, DeriveKey, etc.)"),
        ("BlockCipherMode", "18 cipher modes (CBC, ECB, GCM, CTR, CCM, XTS, AEAD, etc.)"),
        ("QueryFunction", "12 query selectors for server capability discovery."),
    ]

    tbl = doc.add_table(rows=1, cols=2)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Enum Class", "Description"])
    for i, (cls, desc) in enumerate(enums):
        add_table_row(tbl, [cls, desc], alt=(i % 2 == 0))

    section_break(doc)

    # ── 4.2 core/ttlv.py ─────────────────────────────────────────────────
    add_heading(doc, "4.2 core/ttlv.py — TTLV Encoder/Decoder", 2, MID_BLUE)
    add_para(doc,
        "Implements the full KMIP TTLV wire format. Each item is encoded as an "
        "8-byte header (3-byte tag | 1-byte type | 4-byte length) followed by the "
        "value padded to an 8-byte boundary. All multi-byte integers are big-endian."
    )
    section_break(doc)
    add_para(doc, "Encoder functions:", bold=True)
    enc_fns = [
        ("encode_item(tag, type_, value_bytes)", "Low-level primitive — packs header and padded value."),
        ("encode_structure(tag, children)", "Encodes a Structure containing pre-encoded children bytes."),
        ("encode_text_string(tag, value)", "UTF-8 string."),
        ("encode_byte_string(tag, value)", "Opaque bytes."),
        ("encode_integer(tag, value)", "Signed 32-bit big-endian integer."),
        ("encode_long_integer(tag, value)", "Signed 64-bit big-endian integer."),
        ("encode_enumeration(tag, value)", "Unsigned 32-bit big-endian enum value."),
        ("encode_boolean(tag, value)", "64-bit boolean (KMIP spec §9.1.3.8)."),
        ("encode_datetime(tag, value)", "UTC datetime as 64-bit Unix timestamp."),
        ("encode_big_integer(tag, value)", "Arbitrary-precision integer."),
    ]
    tbl = doc.add_table(rows=1, cols=2)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Function", "Description"])
    for i, (fn, desc) in enumerate(enc_fns):
        add_table_row(tbl, [fn, desc], alt=(i % 2 == 0))

    section_break(doc)
    add_para(doc, "TTLVItem class:", bold=True)
    methods = [
        ("TTLVItem.tag", "24-bit KMIP tag (int)."),
        ("TTLVItem.type", "1-byte KMIP type (int)."),
        ("TTLVItem.value", "Decoded Python value (int, str, bytes, datetime, bool, or None for Structure)."),
        ("TTLVItem.children", "List[TTLVItem] for Structure items."),
        (".get(tag)", "Return first child with the given tag, or None."),
        (".get_all(tag)", "Return all children with the given tag."),
        (".get_value(tag, default)", "Return .value of first matching child, or default."),
    ]
    tbl = doc.add_table(rows=1, cols=2)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Attribute / Method", "Description"])
    for i, (m, d) in enumerate(methods):
        add_table_row(tbl, [m, d], alt=(i % 2 == 0))

    section_break(doc)

    # ── 4.3 core/exceptions.py ───────────────────────────────────────────
    add_heading(doc, "4.3 core/exceptions.py — Exception Hierarchy", 2, MID_BLUE)
    add_para(doc,
        "All exceptions inherit from KMIPError which carries a reason integer "
        "matching ResultReason. The dispatcher catches KMIPError subclasses and "
        "returns the correct KMIP OperationFailed response."
    )
    exc = [
        ("KMIPError",              "Base class. reason = GeneralFailure."),
        ("ItemNotFound",           "Object UID not found in the store."),
        ("AuthenticationFailed",   "Client credential rejected."),
        ("NotAuthorized",          "Client lacks permission for the operation."),
        ("InvalidMessage",         "TTLV parsing / framing error."),
        ("InvalidField",           "A required or invalid field was present."),
        ("OperationNotSupported",  "Operation code has no registered handler."),
        ("CryptographicFailure",   "PKCS#11 returned an error."),
        ("IllegalOperation",       "State machine rejects the requested transition."),
        ("NotExtractable",         "Key CKA_EXTRACTABLE is False."),
        ("MissingData",            "Required payload field absent."),
        ("GeneralFailure",         "Catch-all for unexpected errors."),
    ]
    tbl = doc.add_table(rows=1, cols=2)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Exception", "When Raised"])
    for i, (e, d) in enumerate(exc):
        add_table_row(tbl, [e, d], alt=(i % 2 == 0))

    section_break(doc)

    # ── 4.4 lifecycle/state_machine.py ───────────────────────────────────
    doc.add_page_break()
    add_heading(doc, "4.4 lifecycle/state_machine.py — Key Lifecycle", 2, MID_BLUE)
    add_para(doc,
        "Enforces KMIP Section 4 lifecycle transitions. The state machine is "
        "implemented as a pure-Python lookup table with no mutable state."
    )
    section_break(doc)

    add_para(doc, "State transition table:", bold=True)
    transitions = [
        ("PreActive",   "activate",          "Active"),
        ("PreActive",   "revoke_normal",      "Deactivated"),
        ("PreActive",   "revoke_compromise",  "Compromised"),
        ("PreActive",   "destroy",            "Destroyed"),
        ("Active",      "revoke_normal",      "Deactivated"),
        ("Active",      "revoke_compromise",  "Compromised"),
        ("Active",      "destroy",            "Destroyed"),
        ("Deactivated", "revoke_compromise",  "Compromised"),
        ("Deactivated", "destroy",            "Destroyed"),
        ("Compromised", "destroy",            "DestroyedCompromised"),
    ]
    tbl = doc.add_table(rows=1, cols=3)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["From State", "Operation", "To State"])
    for i, (fr, op, to) in enumerate(transitions):
        add_table_row(tbl, [fr, op, to], alt=(i % 2 == 0))

    section_break(doc)
    add_para(doc, "Usage enforcement (check_usage_allowed):", bold=True)
    usage = [
        ("PreActive",             "Any crypto op (encrypt, sign, decrypt, verify)", "IllegalOperation"),
        ("Active",                "All crypto ops",                                  "Permitted"),
        ("Deactivated",           "Encrypt, Sign",                                   "IllegalOperation"),
        ("Deactivated",           "Decrypt, Verify",                                 "Permitted (data recovery)"),
        ("Compromised",           "Get, GetAttributes, Export only",                 "All others: IllegalOperation"),
        ("Destroyed/DestrComp",   "Any operation",                                   "IllegalOperation"),
    ]
    tbl = doc.add_table(rows=1, cols=3)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["State", "Operation Type", "Result"])
    for i, row in enumerate(usage):
        add_table_row(tbl, row, alt=(i % 2 == 0))

    section_break(doc)

    # ── 4.4b lifecycle/access_control.py ─────────────────────────────────
    add_heading(doc, "4.4b lifecycle/access_control.py — Access Control", 2, MID_BLUE)
    add_para(doc,
        "Every managed object records the identity that created it. Operations against "
        "an existing object are authorized by a four-tier check, evaluated in this "
        "order for every operation:"
    )
    section_break(doc)
    ac_tiers = [
        ("1. Admin role", "store.assign_role(identity, \"admin\")",
         "Unconditional access to every object, regardless of owner."),
        ("2. Ownership", "identity == owner_identity",
         "The owner_identity recorded on the object at Create / Register / CreateKeyPair / "
         "Certify / JoinSplitKey time."),
        ("3. Delegated grant", "store.grant_access(uid, grantee, \"read\" | \"full\")",
         "\"read\" covers Get, GetAttributes, GetAttributeList, Check, Export, "
         "ObtainLease; every other operation (Encrypt, Destroy, ReKey, …) requires "
         "\"full\"."),
        ("4. Group grant", "store.grant_access(uid, \"group:<name>\", …) plus "
                           "store.add_to_group(identity, \"<name>\")",
         "A grantee named group:<name> reaches every member of that group, so access "
         "follows team membership instead of being re-granted per person. Leaving the "
         "group withdraws the access."),
    ]
    tbl = doc.add_table(rows=1, cols=3)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Tier", "Mechanism", "Detail"])
    for i, row in enumerate(ac_tiers):
        add_table_row(tbl, row, alt=(i % 2 == 0))

    section_break(doc)
    add_para(doc,
        "Objects with no recorded owner (owner_identity = None) remain reachable by any "
        "identity — this only applies to objects created outside the normal Create/"
        "Register path, so nothing pre-existing is orphaned by layering access control "
        "on top of the store. check_owner() in this module implements the check and "
        "raises NotAuthorized when none of the three tiers grant access; the store and "
        "uid parameters are optional so any pre-existing call site keeps owner-only "
        "semantics if it doesn't pass them, but every operations/*.py handler now passes "
        "both, so the admin/grant checks apply everywhere ownership is enforced."
    )
    section_break(doc)
    add_para(doc,
        "Locate results are filtered to the caller's own objects (or all objects, for an "
        "admin) — a non-admin identity cannot enumerate objects it doesn't own or hold a "
        "grant on."
    )
    section_break(doc)
    add_para(doc, "Per-role operation allowlists", bold=True)
    add_para(doc,
        "Separately, and before any of the four tiers above, check_operation_allowed() "
        "enforces a role's operation allowlist: if any role an identity holds names a "
        "set of permitted operations, the identity may perform only the union of those "
        "sets. This is deliberately opt-in — an identity whose roles define no allowlist "
        "is unrestricted at this layer, so introducing roles never silently locks anyone "
        "out of operations they could previously perform. It narrows what an identity "
        "may do; it never widens it. The admin role is exempt. Holding an unrestricted "
        "role alongside a restricted one does not dissolve the restriction, or roles "
        "would be additive in the wrong direction."
    )
    section_break(doc)
    add_para(doc, "There is NO KMIP wire operation for role, group or grant management",
             bold=True)
    add_para(doc,
        "The KMIP spec does not define an operation for it. Identity, role, group, grant "
        "and permission management is purely an admin surface — the kmip-admin CLI, or "
        "the MetadataStore called directly — never over the KMIP wire protocol:"
    )
    for line in [
        "store.assign_role(\"alice\", \"admin\")            # alice can touch anything",
        "store.grant_access(uid, \"bob\", \"read\")          # bob can Get this one object",
        "store.add_to_group(\"bob\", \"crypto-team\")       # membership",
        "store.grant_access(uid, \"group:crypto-team\", \"read\")",
        "store.allow_role_operation(\"auditor\", \"Get\")   # role allowlist",
        "store.revoke_access(uid, \"bob\")",
        "store.revoke_role(\"alice\", \"admin\")",
    ]:
        add_code(doc, line)
    section_break(doc)
    add_para(doc, "or, equivalently, through the operator CLI:")
    for line in [
        "kmip-admin -c config.yaml identity add alice",
        "kmip-admin -c config.yaml role grant alice admin",
        "kmip-admin -c config.yaml group add bob crypto-team",
        "kmip-admin -c config.yaml access grant <uid> group:crypto-team --permission read",
        "kmip-admin -c config.yaml permission allow auditor Get",
    ]:
        add_code(doc, line)

    section_break(doc)

    # ── 4.4c governance ──────────────────────────────────────────────────
    add_heading(doc, "4.4c lifecycle/governance.py and lifecycle/dual_control.py",
                2, MID_BLUE)
    add_para(doc,
        "Access control decides who may ask. Governance is the part that acts without "
        "being asked, and the part that stops one person acting alone. Both are off by "
        "default and enabled in the governance: section of the configuration file."
    )
    section_break(doc)
    add_para(doc, "Cryptoperiod enforcement", bold=True)
    add_para(doc,
        "KMIP defines no separate cryptoperiod attribute — the Deactivation Date is the "
        "end of the period — so a cryptoperiod here is that standard attribute plus "
        "something that acts on it. Without the scheduler, a key with a two-year "
        "cryptoperiod stays Active into year five unless somebody remembers. "
        "KeyLifecycleScheduler runs a background scan every scan_interval_seconds that "
        "deactivates keys whose Deactivation Date has passed, warns warn_days ahead as "
        "keys approach it, and — with auto_rotate — first creates a replacement "
        "symmetric key cross-linked to the old one via Link_ReplacementKey / "
        "Link_ReplacedKey, exactly the lineage a client-driven ReKey produces. Rotation "
        "runs before deactivation so a replacement exists before the old key stops being "
        "usable; if rotation fails the key is deactivated anyway, because an expired key "
        "left Active is the worse outcome. Every action is audited under the identity "
        "system:scheduler, so an automated deactivation is as attributable as a human "
        "one. In a multi-worker deployment only worker 0 runs the scheduler — otherwise "
        "workers would race to deactivate the same keys."
    )
    section_break(doc)
    add_para(doc, "Dual control (M-of-N approval)", bold=True)
    add_para(doc,
        "Destroy zeroizes key material; Export hands out key bytes. Under dual control "
        "those do not execute on request: the first attempt is refused and records an "
        "approval request, enough other identities approve it out of band through "
        "kmip-admin, and the requester retries. The check runs before the handler, so a "
        "blocked operation has no effect at all — the point is that the destructive step "
        "never happens without the second signature."
    )
    section_break(doc)
    for rule in [
        "The requester can never approve their own request — enforced in the store, so "
        "it holds however approvals are submitted.",
        "An approval authorises exactly one attempt, on one object, by one identity. It "
        "is consumed on use rather than becoming a standing permission, and consumed "
        "before the handler runs, so a handler that fails partway leaves no reusable "
        "approval behind.",
        "Approvals expire (approval_ttl_seconds).",
        "A retry reuses the open request rather than opening another, so a client in a "
        "retry loop cannot fill the table with requests nobody will approve.",
        "approvals_required must be at least 2 when dual control is on; the "
        "configuration is rejected otherwise.",
    ]:
        add_bullet(doc, rule)
    section_break(doc)
    add_para(doc,
        "KMIP has no wire operation for a pending, out-of-band-approved request, so the "
        "refusal reaches the client as OperationFailed / PermissionDenied carrying the "
        "request id, and approval happens through kmip-admin approval approve.",
        italic=True
    )

    section_break(doc)

    # ── 4.5 metadata/store.py ────────────────────────────────────────────
    add_heading(doc, "4.5 metadata/store.py — MetadataStore", 2, MID_BLUE)
    add_para(doc,
        "SQLite-backed store for all KMIP attributes that PKCS#11 cannot hold, plus the "
        "access-control tables (identities, roles, groups, delegated object grants, "
        "per-role operation allowlists), the dual-control approval tables, and the "
        "hash-chained audit log. Uses WAL journal mode, a connection-per-thread pattern "
        "for concurrent access, and PRAGMA user_version migrations."
    )
    section_break(doc)
    add_para(doc, "Database schema:", bold=True)
    for line in [
        "TABLE kmip_objects",
        "  uuid TEXT PK              — RFC-4122 UUID (KMIP UniqueIdentifier)",
        "  object_type INTEGER       — ObjectType enum",
        "  pkcs11_handle INTEGER     — reserved (CKA_ID stored as attribute)",
        "  state INTEGER             — State enum",
        "  cryptographic_algorithm INTEGER",
        "  cryptographic_length    INTEGER",
        "  usage_mask              INTEGER",
        "  initial_date            REAL  — Unix timestamp",
        "  activation_date         REAL",
        "  deactivation_date       REAL",
        "  destroy_date            REAL",
        "  compromise_date         REAL",
        "  revocation_reason       INTEGER",
        "  revocation_message      TEXT",
        "  sensitive               INTEGER (0|1)",
        "  extractable             INTEGER (0|1)",
        "  owner_identity          TEXT",
        "  raw_key_value           BLOB  — for Register operation",
        "  created_at              REAL",
        "",
        "TABLE kmip_attributes",
        "  id INTEGER PK AUTOINCREMENT",
        "  object_uuid TEXT FK → kmip_objects.uuid",
        "  attr_name   TEXT",
        "  attr_index  INTEGER   — multi-valued attribute index",
        "  attr_value  TEXT      — JSON-encoded value",
        "",
        "TABLE kmip_identity_roles          — new: role-based access control",
        "  identity TEXT              — PK (identity, role)",
        "  role     TEXT              — e.g. \"admin\"",
        "",
        "TABLE kmip_object_grants           — delegated per-object access",
        "  object_uuid TEXT FK → kmip_objects.uuid  — PK (object_uuid, grantee)",
        "  grantee     TEXT                  — an identity, or \"group:<name>\"",
        "  permission  TEXT DEFAULT 'full'   — \"read\" or \"full\"",
        "",
        "TABLE kmip_identity_groups         — group membership",
        "  identity   TEXT                   — PK (identity, group_name)",
        "  group_name TEXT",
        "",
        "TABLE kmip_role_permissions        — per-role operation allowlist",
        "  role           TEXT               — PK (role, operation_name)",
        "  operation_name TEXT               — e.g. \"Get\", \"Destroy\"",
        "",
        "TABLE kmip_approval_requests       — dual control",
        "  request_id     TEXT PK",
        "  operation_name TEXT",
        "  object_uid     TEXT",
        "  requester      TEXT",
        "  required       INTEGER            — how many other identities must approve",
        "  created_at     REAL",
        "  expires_at     REAL",
        "  consumed_at    REAL               — NULL until the approval is spent",
        "",
        "TABLE kmip_approvals",
        "  request_id  TEXT FK → kmip_approval_requests  — PK (request_id, approver)",
        "  approver    TEXT               — never equal to the request's requester",
        "  approved_at REAL",
    ]:
        add_code(doc, line)

    section_break(doc)
    add_para(doc, "Key methods:", bold=True)
    methods = [
        ("create_object(**kwargs) → str", "Creates a row in kmip_objects and optional Name attributes. Returns UUID."),
        ("get_object(uid) → dict|None", "Fetches all columns for a single object."),
        ("get_attributes(uid) → list[dict]", "Returns all kmip_attributes rows for an object."),
        ("get_attribute(uid, name) → list", "Returns JSON-decoded values for a named attribute."),
        ("activate(uid)", "Sets state=Active, activation_date=now."),
        ("set_revoke(uid, state, reason, message)", "Sets state, deactivation_date or compromise_date."),
        ("set_destroy(uid)", "Sets state=Destroyed, destroy_date=now, pkcs11_handle=NULL."),
        ("add_attribute(uid, name, value)", "Appends a JSON-encoded attribute; auto-increments attr_index."),
        ("delete_attribute(uid, name, index)", "Removes a specific attribute value."),
        ("locate(**filters) → list[str]", "Flexible object search with optional filters on type, state, name, algorithm, owner."),
        ("get_owner(uid) → str|None", "Lightweight ownership lookup for handlers that don't need the full object row."),
        ("assign_role(identity, role)", "Inserts into kmip_identity_roles (INSERT OR IGNORE). No wire operation — admin surface only."),
        ("revoke_role(identity, role)", "Deletes the matching kmip_identity_roles row."),
        ("get_roles(identity) → list[str]", "Returns all roles assigned to an identity (checked by lifecycle/access_control.is_admin())."),
        ("grant_access(uid, grantee, permission='full')", "Upserts a kmip_object_grants row (\"read\" or \"full\")."),
        ("revoke_access(uid, grantee)", "Deletes the matching kmip_object_grants row."),
        ("get_grant(uid, grantee) → str|None", "Returns the grantee's permission level for one object, or None."),
        ("add_to_group(identity, group) / remove_from_group(…)", "Group membership; a grant to \"group:<name>\" then reaches every member."),
        ("get_groups(identity) → list[str]", "The identity's groups, consulted by check_owner() when resolving grants."),
        ("list_group_members(group) → list[str]", "The reverse lookup, for the kmip-admin group members command."),
        ("allow_role_operation(role, op) / disallow_role_operation(…)", "Maintains a role's operation allowlist."),
        ("allowed_operations_for(identity) → set|None", "Union of allowlists across the identity's roles; None means no restriction, so adding a role never silently locks anyone out."),
        ("create_approval_request(…) → str", "Opens a dual-control request and returns its id."),
        ("approve_request(request_id, approver) → dict", "Records one approval. Refuses the requester, an expired request, and an already-consumed one."),
        ("find_satisfied_request(op, uid, requester) → dict|None", "The unconsumed, unexpired, fully approved request that lets a retry through."),
        ("find_pending_request(op, uid, requester) → dict|None", "An open request still short of approvals, so a retry points at it instead of opening another."),
        ("consume_approval_request(request_id)", "Marks a request used, so one round of approvals authorises exactly one operation."),
        ("list_grants(uid) → list[dict]", "Returns all {grantee, permission} grants for one object."),
    ]
    tbl = doc.add_table(rows=1, cols=2)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Method", "Description"])
    for i, (m, d) in enumerate(methods):
        add_table_row(tbl, [m, d], alt=(i % 2 == 0))

    section_break(doc)

    # ── 4.6 pkcs11_shim/shim.py ──────────────────────────────────────────
    doc.add_page_break()
    add_heading(doc, "4.6 pkcs11_shim/shim.py — PKCS11Shim", 2, MID_BLUE)
    add_para(doc,
        "Wraps python-pkcs11 to provide KMIP-oriented operations. "
        "All cryptographic material remains inside the HSM (SoftHSM2 or real hardware). "
        "Key handles are returned as CKA_ID byte strings (16 random bytes per key); "
        "these are stored as the _pkcs11_cka_id attribute in the metadata store. "
        "This is the only file in the project that imports pkcs11 — swapping in a "
        "different (e.g. FIPS-validated) token requires no change above this module."
    )
    section_break(doc)

    add_para(doc, "Capability probe:", bold=True)
    add_para(doc,
        "initialize() queries slot.get_mechanisms() once, immediately after opening the "
        "session, and caches the result as self._available_mechanisms. Every "
        "algorithm/mode-specific method (generate, encrypt, decrypt, MAC, hash) calls "
        "supports_mechanism(mechanism) or the internal _require_mechanism(mechanism, what) "
        "before dispatching to PKCS#11. If the token doesn't advertise the mechanism, "
        "_require_mechanism raises OperationNotSupported with a clear message instead of "
        "letting a native PKCS#11 error surface mid-operation. On this SoftHSM2 build, "
        "15 of 40 CryptographicAlgorithm values map to a mechanism that is actually "
        "present — see Section 6 for the full breakdown."
    )
    section_break(doc)

    add_para(doc, "Single locked session:", bold=True)
    add_para(doc,
        "self._lock is a threading.RLock; the module-level @_synchronized decorator wraps "
        "every session-touching method so only one thread executes inside the shared "
        "PKCS#11 session at a time. This is the permanent design, not a stopgap — see "
        "Section 3.3 Threading Model for the full rationale and the concurrency test that "
        "verified a lock-free session pool is unsafe with python-pkcs11 0.9.5."
    )
    section_break(doc)

    add_para(doc, "Constructor:", bold=True)
    add_code(doc, "PKCS11Shim(lib_path: str, token_label: str, user_pin: str)")
    add_para(doc, "  lib_path    — path to libsofthsm2.so (or vendor PKCS#11 .so/.dll)")
    add_para(doc, "  token_label — PKCS#11 token label (CKA_LABEL)")
    add_para(doc, "  user_pin    — CKU_USER PIN for token authentication")

    section_break(doc)
    add_para(doc, "Methods:", bold=True)
    shim_methods = [
        ("initialize()", "Opens a PKCS#11 session (idempotent; skips if already open)."),
        ("finalize()", "Closes the PKCS#11 session. Keeps _lib alive (cannot re-init in same process)."),
        ("generate_symmetric_key(algorithm, length_bits, …) → (handle_id, cka_id)",
         "Generates a symmetric key on the token. Returns Python object id and 16-byte CKA_ID. "
         "Applies effective_sensitive = sensitive AND NOT extractable workaround for SoftHSM2."),
        ("generate_key_pair(algorithm, key_length, …) → (pub_cka_id, priv_cka_id)",
         "Generates RSA or EC key pair. Returns two CKA_IDs."),
        ("import_symmetric_key(algorithm, length_bits, key_bytes, …) → cka_id",
         "Imports externally-supplied raw key material via C_CreateObject."),
        ("import_public_key / import_private_key(algorithm, der_bytes, …) → cka_id",
         "Imports an externally-supplied RSA public/private key (PKCS#1 or PKCS#8 DER) for Register."),
        ("wrap_key(wrapping_cka_id, target_cka_id) → bytes",
         "Wraps a SecretKey with another SecretKey (KEK) via CKM_AES_KEY_WRAP_PAD."),
        ("unwrap_key(wrapping_cka_id, wrapped_bytes, target_algorithm, …) → cka_id",
         "Unwraps key material directly into a new SecretKey object; plaintext never "
         "leaves the HSM/server boundary into Python memory."),
        ("get_key_value(cka_id) → bytes",
         "Exports CKA_VALUE of a SECRET_KEY object. Raises NotExtractable if CKA_EXTRACTABLE=False."),
        ("get_public_key_der(cka_id) → bytes",
         "Exports PUBLIC_KEY in SubjectPublicKeyInfo/PKCS#1 DER, EC point, or DH value form."),
        ("get_private_key_der(cka_id) → bytes",
         "Exports PRIVATE_KEY DER (only if extractable)."),
        ("destroy_object(cka_id, obj_class=None)",
         "Calls C_DestroyObject. Silently ignores ItemNotFound."),
        ("supports_mechanism(mechanism) → bool / _require_mechanism(mechanism, what)",
         "Capability-probe check against self._available_mechanisms; _require_mechanism "
         "raises OperationNotSupported if absent. See the capability-probe note above."),
        ("encrypt(cka_id, plaintext, mechanism_id, iv, aad) → (ct, tag_or_None)",
         "Encrypts with HSM-resident key. Supports CBC, ECB, GCM, CTR, CFB, OFB, CCM "
         "(AES) plus DES/3DES/Blowfish/Twofish variants, gated by supports_mechanism()."),
        ("decrypt(cka_id, ciphertext, mechanism_id, iv, aad, tag) → bytes",
         "Decrypts with HSM-resident key."),
        ("sign(cka_id, data, mechanism) → bytes",
         "Signs data with a PRIVATE_KEY."),
        ("verify(cka_id, data, signature, mechanism) → bool",
         "Verifies a signature against a PUBLIC_KEY."),
        ("mac(cka_id, data, mechanism) → bytes / mac_verify(cka_id, data, mac_value, mechanism) → bool",
         "HMAC generate/verify against a SecretKey, capability-gated per mechanism."),
        ("hash_data(data, hash_alg) → bytes",
         "Digests data via session.digest(), capability-gated per HashingAlgorithm."),
        ("derive_key(cka_id, base_algorithm, peer_value, target_algorithm, …) → cka_id",
         "Derives a symmetric key from a DH/ECDH private key and a peer's public value."),
        ("generate_random(length) → bytes / seed_random(seed)",
         "Retrieves/seeds HSM-generated random bytes via C_GenerateRandom / C_SeedRandom."),
        ("verify_pin(pin) → bool",
         "Constant-time-ish comparison used for KMIP UsernameAndPassword Credential auth."),
        ("get_mechanism_list() → list",
         "Returns the cached (or freshly queried) mechanisms supported by the token slot."),
        ("get_token_info() → str",
         "Returns a string representation of the token slot info."),
    ]
    tbl = doc.add_table(rows=1, cols=2)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Method", "Description"])
    for i, (m, d) in enumerate(shim_methods):
        add_table_row(tbl, [m, d], alt=(i % 2 == 0))

    section_break(doc)

    # ── 4.7 Operations ───────────────────────────────────────────────────
    add_heading(doc, "4.7 operations/ — KMIP Operation Handlers", 2, MID_BLUE)
    add_para(doc,
        "Each handler is a module-level handle(payload, identity, store, shim) → bytes function. "
        "The dispatcher calls them after extracting the RequestPayload TTLVItem. "
        "41 operations are implemented across four categories: object lifecycle (18), "
        "retrieval & discovery (8), attributes (5), and cryptographic operations (10). "
        "See Section 6 for the full categorized table; the notes below cover the "
        "handlers' key implementation details."
    )
    section_break(doc)
    ops = [
        ("create.py",           "Create",           "Parses TemplateAttribute; generates symmetric key on HSM; "
                                                     "creates metadata row (state=Active); "
                                                     "stores CKA_ID as _pkcs11_cka_id attribute."),
        ("create_keypair.py",   "CreateKeyPair",    "Generates RSA or EC key pair; creates two metadata rows "
                                                     "(public key and private key); returns two UniqueIdentifiers."),
        ("register.py",         "Register",         "Imports externally-supplied key material via "
                                                     "shim.import_symmetric_key(); stores raw bytes if "
                                                     "no PKCS#11 lib is available."),
        ("get.py",              "Get",              "Retrieves the key value bytes from the HSM "
                                                     "via shim.get_key_value(); returns a TTLV KeyBlock."),
        ("get_attributes.py",   "GetAttributes / GetAttributeList",
                                                     "Returns KMIP attribute structures for the requested "
                                                     "attribute names. Reads from both the kmip_objects table "
                                                     "and kmip_attributes table."),
        ("add_attribute.py",    "AddAttribute",     "Validates attribute name; stores value JSON-encoded "
                                                     "in kmip_attributes; returns UniqueIdentifier."),
        ("delete_attribute.py", "DeleteAttribute",  "Removes a specific attribute value by name + index."),
        ("locate.py",           "Locate",           "Translates KMIP Locate filters to MetadataStore.locate() "
                                                     "parameters; returns UniqueIdentifier list."),
        ("activate.py",         "Activate",         "Validates PreActive state; transitions to Active via "
                                                     "state machine; calls store.activate()."),
        ("revoke.py",           "Revoke",           "Reads RevocationReasonCode; determines revoke_normal "
                                                     "or revoke_compromise; calls store.set_revoke()."),
        ("destroy.py",          "Destroy",          "Validates state machine allows destroy; calls "
                                                     "shim.destroy_object() on the HSM; calls store.set_destroy()."),
        ("encrypt.py",          "Encrypt",          "Calls check_usage_allowed(Active, 'encrypt'); "
                                                     "delegates to shim.encrypt(); returns Data + IVCounterNonce."),
        ("decrypt.py",          "Decrypt",          "Calls check_usage_allowed for Active/Deactivated; "
                                                     "delegates to shim.decrypt(); returns Data."),
        ("query.py",            "Query",            "Returns supported operations, object types, and "
                                                     "vendor identification string."),
        ("discover_versions.py","DiscoverVersions", "Returns list of supported KMIP versions "
                                                     "(currently 1.0, 1.1, 1.2, 1.3, 1.4, 2.0, 2.1)."),
        ("import_op.py",        "Import",           "Imports key material (symmetric or RSA public/private) "
                                                     "via the shim's import_* methods; access-controlled like Register."),
        ("export_op.py",        "Export",           "Exports a key/object; requires \"read\"-level access "
                                                     "(owner, admin, or grant) and CKA_EXTRACTABLE=True."),
        ("get_usage_allocation.py", "GetUsageAllocation", "Reserves/decrements a usage-limit counter on an "
                                                     "object (KMIP usage-limits attribute)."),
        ("modify_attribute.py",  "ModifyAttribute",  "Replaces an existing attribute value in kmip_attributes."),
        ("set_attribute.py",     "SetAttribute",     "KMIP 2.x single-value attribute set; upserts via "
                                                     "store.set_or_add_attribute()."),
        ("adjust_attribute.py",  "AdjustAttribute",  "Increments/decrements a numeric attribute (e.g. usage "
                                                     "counters) in place."),
        ("archive.py",           "Archive",          "Marks an object archived (archived=1); state is unchanged "
                                                     "but the object is unusable for anything but metadata reads."),
        ("recover.py",           "Recover",          "Clears the archived flag, restoring normal usability."),
        ("check.py",             "Check",            "Validates requested attribute values against the "
                                                     "object's actual stored values without exporting key material."),
        ("sign.py",              "Sign",             "Enforces Active-state usage; delegates to shim.sign() "
                                                     "against a PRIVATE_KEY."),
        ("signature_verify.py",  "SignatureVerify",  "Delegates to shim.verify() against a PUBLIC_KEY; "
                                                     "returns a KMIP ValidationSuccess/Failure indicator."),
        ("mac.py",               "MAC",              "Delegates to shim.mac(); capability-gated on the HMAC "
                                                     "mechanism via _require_mechanism()."),
        ("mac_verify.py",        "MACVerify",        "Delegates to shim.mac_verify(); returns pass/fail."),
        ("hash_op.py",           "Hash",             "Delegates to shim.hash_data(); capability-gated per "
                                                     "HashingAlgorithm."),
        ("rekey.py",             "ReKey",            "Creates a new symmetric key that supersedes an existing "
                                                     "one; copies forward compatible attributes."),
        ("rekey_keypair.py",     "ReKeyKeyPair",     "Creates a new key pair that supersedes an existing one."),
        ("certify.py",           "Certify",          "Creates a Certificate object bound to a public key "
                                                     "(self-signed / CA-signed depending on inputs)."),
        ("recertify.py",         "ReCertify",        "Renews/replaces an existing Certificate object."),
        ("derive_key.py",        "DeriveKey",        "Delegates to shim.derive_key() for DH/ECDH key agreement; "
                                                     "returns the new symmetric key's UniqueIdentifier."),
        ("create_split_key.py",  "CreateSplitKey",   "Splits a key into N shares via XOR secret sharing; "
                                                     "creates one metadata row per share."),
        ("join_split_key.py",    "JoinSplitKey",     "XORs the shares back together and re-registers the "
                                                     "reconstructed key on the HSM."),
        ("validate.py",          "Validate",         "Validates a certificate chain against KMIP Validate "
                                                     "semantics."),
        ("obtain_lease.py",      "ObtainLease",      "Returns a lease/expiration time for an object; "
                                                     "\"read\"-level access."),
        ("rng_retrieve.py",      "RNGRetrieve",      "Delegates to shim.generate_random() — HSM-backed RNG."),
        ("rng_seed.py",          "RNGSeed",          "Delegates to shim.seed_random()."),
    ]
    tbl = doc.add_table(rows=1, cols=3)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Module", "KMIP Operation", "Implementation Notes"])
    for i, (mod, op, notes) in enumerate(ops):
        add_table_row(tbl, [mod, op, notes], alt=(i % 2 == 0))

    section_break(doc)

    # ── 4.8 server/server.py ─────────────────────────────────────────────
    doc.add_page_break()
    add_heading(doc, "4.8 server/server.py — KMIPServer", 2, MID_BLUE)
    add_para(doc,
        "A TCP server that listens on a configurable host:port. Each accepted "
        "connection is handled in a dedicated daemon thread. TLS wrapping is "
        "optional and supports mutual TLS."
    )
    section_break(doc)
    add_para(doc, "Constructor parameters:", bold=True)
    params = [
        ("store",               "MetadataStore", "Metadata store instance."),
        ("shim",                "PKCS11Shim",    "PKCS#11 shim instance."),
        ("host",                "str",           "Bind address (default: 127.0.0.1)."),
        ("port",                "int",           "TCP port (default: 5696, IANA KMIP)."),
        ("tls_cert",            "str|None",      "Path to server PEM certificate."),
        ("tls_key",             "str|None",      "Path to server private key."),
        ("tls_ca",              "str|None",      "CA cert for client verification."),
        ("require_client_cert", "bool",          "If True, require mTLS client certificate."),
    ]
    tbl = doc.add_table(rows=1, cols=3)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Parameter", "Type", "Description"])
    for i, row in enumerate(params):
        add_table_row(tbl, row, alt=(i % 2 == 0))

    section_break(doc)
    add_para(doc, "Key methods:", bold=True)
    srv_methods = [
        ("start()", "Calls shim.initialize(), binds socket, starts accept loop (blocking)."),
        ("start_background() → Thread", "Runs start() in a daemon thread. Returns the thread."),
        ("stop()", "Sets _running=False, closes socket, calls shim.finalize()."),
    ]
    tbl = doc.add_table(rows=1, cols=2)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Method", "Description"])
    for i, (m, d) in enumerate(srv_methods):
        add_table_row(tbl, [m, d], alt=(i % 2 == 0))

    section_break(doc)

    # ── 4.9 test_app/client.py ───────────────────────────────────────────
    add_heading(doc, "4.9 test_app/client.py — KMIPClient", 2, MID_BLUE)
    add_para(doc,
        "A synchronous KMIP 2.1 client over TCP. Supports all operations "
        "implemented by the server. Suitable for integration tests and as a "
        "reference for client development."
    )
    section_break(doc)
    client_methods = [
        ("connect() / close()", "Open / close TCP (or TLS) connection."),
        ("discover_versions() → list[tuple]", "Returns list of (major, minor) version tuples."),
        ("query(functions) → dict", "Returns dict with 'operations', 'object_types', 'vendor'."),
        ("create(algorithm, length, usage_mask, name, extractable) → str",
         "Creates a symmetric key; returns UID (UUID string)."),
        ("create_key_pair(algorithm, length, name) → (pub_uid, priv_uid)",
         "Creates RSA/EC key pair; returns two UIDs."),
        ("get(uid) → TTLVItem", "Retrieves the full key object response payload."),
        ("get_attributes(uid, names) → dict", "Returns {attr_name: value} dict."),
        ("locate(object_type, state, name, algorithm) → list[str]", "Returns list of matching UIDs."),
        ("activate(uid) → str", "Activates a Pre-Active key; returns UID."),
        ("revoke(uid, reason, message) → str", "Revokes a key; returns UID."),
        ("destroy(uid) → str", "Destroys a key; returns UID."),
        ("encrypt(uid, plaintext, iv, mode) → (ct, iv, tag)", "Encrypts; returns ciphertext + IV + auth tag."),
        ("decrypt(uid, ciphertext, iv, auth_tag, mode) → bytes", "Decrypts; returns plaintext."),
        ("add_attribute(uid, name, value) → str", "Adds a custom attribute; returns UID."),
    ]
    tbl = doc.add_table(rows=1, cols=2)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Method", "Description"])
    for i, (m, d) in enumerate(client_methods):
        add_table_row(tbl, [m, d], alt=(i % 2 == 0))

    # ═══════════════════════════════════════════════════════════════════════
    # 5. INSTALLATION & CONFIGURATION
    # ═══════════════════════════════════════════════════════════════════════
    doc.add_page_break()
    add_heading(doc, "5. Installation & Configuration", 1, DARK_BLUE)

    add_heading(doc, "5.1 Prerequisites", 2, MID_BLUE)
    prereqs = [
        ("Python", "3.9 or newer"),
        ("SoftHSM2", "2.6+ (Ubuntu: apt install softhsm2)"),
        ("python-pkcs11", "0.9.5 (pip install python-pkcs11)"),
        ("pytest", ">=7.0 (for running the test suite)"),
    ]
    tbl = doc.add_table(rows=1, cols=2)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Dependency", "Version / Notes"])
    for i, (d, v) in enumerate(prereqs):
        add_table_row(tbl, [d, v], alt=(i % 2 == 0))

    section_break(doc)
    add_heading(doc, "5.2 Installation", 2, MID_BLUE)
    for line in [
        "# Install system dependencies",
        "sudo apt install softhsm2",
        "",
        "# Install Python package in editable mode",
        "pip install -e .[dev]",
        "",
        "# Initialize a SoftHSM2 token for development",
        "softhsm2-util --init-token --slot 0 --label KMIPTest --pin 1234 --so-pin 5678",
    ]:
        add_code(doc, line)

    section_break(doc)
    add_heading(doc, "5.3 Environment Variables", 2, MID_BLUE)
    env_vars = [
        ("SOFTHSM2_LIB",  "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
         "Path to the PKCS#11 shared library."),
        ("SOFTHSM2_CONF", "/tmp/softhsm2_tests/softhsm2.conf",
         "SoftHSM2 configuration file path. Created automatically by the test fixtures."),
    ]
    tbl = doc.add_table(rows=1, cols=3)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Variable", "Default Value", "Purpose"])
    for i, row in enumerate(env_vars):
        add_table_row(tbl, row, alt=(i % 2 == 0))

    section_break(doc)
    add_heading(doc, "5.4 Running the Server", 2, MID_BLUE)
    for line in [
        "from kmip_pkcs11.metadata.store import MetadataStore",
        "from kmip_pkcs11.pkcs11_shim.shim import PKCS11Shim",
        "from kmip_pkcs11.server.server import KMIPServer",
        "",
        "store  = MetadataStore('/var/kmip/kmip.db')",
        "shim   = PKCS11Shim('/usr/lib/.../libsofthsm2.so', 'MyToken', 'userpin')",
        "server = KMIPServer(store, shim, host='0.0.0.0', port=5696)",
        "server.start()  # blocking; use start_background() for non-blocking",
    ]:
        add_code(doc, line)

    section_break(doc)
    add_heading(doc, "5.4b Assigning the First Admin", 2, MID_BLUE)
    add_para(doc,
        "There is no environment variable or server constructor argument for this — "
        "assign at least one admin identity directly against the store before "
        "starting the server, since there is no KMIP wire operation for role "
        "management (see Section 4.4b):"
    )
    for line in [
        "# Optional: grant one identity the admin role before anyone connects",
        "# (there's no wire operation for this — call the store directly)",
        "store.assign_role('ops-team', 'admin')",
    ]:
        add_code(doc, line)

    section_break(doc)
    add_heading(doc, "5.5 Running the Demo", 2, MID_BLUE)
    add_code(doc, "python -m kmip_pkcs11.test_app.demo")
    add_para(doc,
        "The demo walks through DiscoverVersions, Query, Create AES-256, "
        "GetAttributes, Locate, Encrypt/Decrypt, CreateKeyPair, Register, and a "
        "full Revoke → Destroy lifecycle."
    )

    # ═══════════════════════════════════════════════════════════════════════
    # 6. SUPPORTED OPERATIONS
    # ═══════════════════════════════════════════════════════════════════════
    doc.add_page_break()
    add_heading(doc, "6. Supported KMIP Operations", 1, DARK_BLUE)

    add_para(doc,
        "41 of 53 KMIP 2.1 operations are implemented, grouped below by category. "
        "The remaining 12 are a deliberate scope decision — see Section 9 Known "
        "Limitations for why each was excluded."
    )
    section_break(doc)

    op_categories = [
        ("Object lifecycle (18)",
         "Create, CreateKeyPair, Register, ReKey, ReKeyKeyPair, DeriveKey, Certify, "
         "ReCertify, CreateSplitKey, JoinSplitKey, Import, Export, Activate, Revoke, "
         "Destroy, Archive, Recover, Check"),
        ("Retrieval & discovery (8)",
         "Get, GetAttributes, GetAttributeList, Locate, Query, DiscoverVersions, "
         "ObtainLease, GetUsageAllocation"),
        ("Attributes (5)",
         "AddAttribute, ModifyAttribute, DeleteAttribute, SetAttribute, AdjustAttribute"),
        ("Cryptographic operations (10)",
         "Encrypt, Decrypt, Sign, SignatureVerify, MAC, MACVerify, Hash, RNGRetrieve, "
         "RNGSeed, Validate"),
    ]
    tbl = doc.add_table(rows=1, cols=2)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Category", "Operations"])
    for i, row in enumerate(op_categories):
        add_table_row(tbl, row, alt=(i % 2 == 0))

    section_break(doc)
    add_para(doc, "Deferred (12) — not implemented, by design:", bold=True)
    add_para(doc,
        "Cancel, Poll, Notify — asynchronous operation control; this server processes "
        "every request synchronously within its batch, so there is nothing to cancel "
        "or poll for."
    )
    add_para(doc,
        "Put, Log, Login, Logout, DelegatedLogin, SetEndpointRole — session/identity "
        "management operations that don't fit a synchronous, per-request-authenticated "
        "server; auth here is Credential-based per connection, not a login/logout "
        "session state machine."
    )
    add_para(doc,
        "PKCS11, Interop, ReProvision — vendor/profile-specific and provisioning "
        "operations outside the KMIP Baseline/Symmetric/Asymmetric Key server "
        "profiles this implementation targets."
    )

    # ═══════════════════════════════════════════════════════════════════════
    # 7. TEST SPECIFICATION
    # ═══════════════════════════════════════════════════════════════════════
    doc.add_page_break()
    add_heading(doc, "7. Test Specification", 1, DARK_BLUE)

    add_para(doc,
        "The test suite comprises 811 tests organised into seven modules, all passing "
        "(100 % pass rate). All tests are executed with pytest. The test suite requires "
        "a running SoftHSM2 token (initialised automatically by the conftest.py session "
        "fixture). The original five modules' test classes map to OASIS KMIP TC (Test "
        "Case) identifiers; the sixth module, test_extended_coverage.py, is a later, "
        "much larger addition covering everything built after the original five files "
        "— see Section 7.9."
    )
    section_break(doc)

    # ── 7.1 Suite summary ────────────────────────────────────────────────
    add_heading(doc, "7.1 Test Suite Summary", 2, MID_BLUE)
    summary = [
        ("test_ttlv.py",        "TTLV codec unit tests",                "22",  "Pure unit (no HSM)"),
        ("test_lifecycle.py",   "Lifecycle state machine unit tests",   "26",  "Pure unit (no HSM)"),
        ("test_metadata.py",    "MetadataStore unit tests",             "18",  "SQLite only (no HSM)"),
        ("test_operations.py",  "Operation integration tests",          "8",   "Requires SoftHSM2"),
        ("test_conformance.py", "KMIP conformance tests (end-to-end)",  "48",  "Requires SoftHSM2"),
        ("test_governance.py",  "Cryptoperiod enforcement, dual control, groups, "
                                "per-role operation allowlists",        "48",  "Requires SoftHSM2"),
        ("test_extended_coverage.py", "All 41 operations, algorithm/mode coverage, "
                                      "error paths, access control, session concurrency",
                                      "641", "Requires SoftHSM2"),
        ("TOTAL",               "",                                     "811", ""),
    ]
    tbl = doc.add_table(rows=1, cols=4)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Module", "Description", "Tests", "Requires"])
    for i, row in enumerate(summary):
        r = add_table_row(tbl, row, alt=(i % 2 == 0))
        if row[0] == "TOTAL":
            set_cell_bg(tbl.rows[-1].cells[0], "1E802E")
            set_cell_bg(tbl.rows[-1].cells[2], "1E802E")
            for cell in tbl.rows[-1].cells:
                for para in cell.paragraphs:
                    for run in para.runs:
                        run.bold = True
                        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

    section_break(doc)

    # ── 7.2 Running the tests ─────────────────────────────────────────────
    add_heading(doc, "7.2 Running the Test Suite", 2, MID_BLUE)
    for line in [
        "# Run all 811 tests",
        "pytest",
        "",
        "# Run a specific module",
        "pytest kmip_pkcs11/tests/test_conformance.py -v",
        "",
        "# Run with coverage",
        "pytest --cov=kmip_pkcs11 --cov-report=html",
        "",
        "# Run only tests that don't need SoftHSM2",
        "pytest kmip_pkcs11/tests/test_ttlv.py kmip_pkcs11/tests/test_lifecycle.py",
    ]:
        add_code(doc, line)

    section_break(doc)

    # ── 7.3 Test fixtures ─────────────────────────────────────────────────
    add_heading(doc, "7.3 Test Fixtures (conftest.py)", 2, MID_BLUE)
    fixtures = [
        ("softhsm_token", "session, autouse",
         "Initialises a SoftHSM2 token at /tmp/softhsm2_tests with label 'KMIPTestSuite'. "
         "Runs once per pytest session."),
        ("store", "function",
         "Creates a fresh MetadataStore backed by a tmp_path SQLite file. "
         "Each test gets an isolated database."),
        ("shim", "session",
         "Single PKCS11Shim shared across all tests. Opened once, kept alive "
         "until end of session (PKCS#11 cannot re-initialize in the same process)."),
        ("server_client", "function",
         "Spawns a KMIPServer on a unique port (itertools.count from 15700) "
         "with a fresh MetadataStore. Polls for readiness then returns (client, store). "
         "Teardown closes the client and stops the server without calling shim.finalize()."),
    ]
    tbl = doc.add_table(rows=1, cols=3)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Fixture", "Scope", "Description"])
    for i, row in enumerate(fixtures):
        add_table_row(tbl, row, alt=(i % 2 == 0))

    section_break(doc)

    # ── 7.4 TTLV Unit Tests ───────────────────────────────────────────────
    doc.add_page_break()
    add_heading(doc, "7.4 TTLV Unit Tests — test_ttlv.py", 2, MID_BLUE)
    add_para(doc, "Class: TestEncodeDecode  |  Class: TestTTLVErrorHandling", bold=True)
    add_para(doc,
        "Validates the encode/decode round-trip for every KMIP data type. "
        "No HSM required. Tests run in milliseconds."
    )
    section_break(doc)

    ttlv_tests = [
        ("TT-001", "test_integer_positive",          "Encode/decode positive 32-bit integer (42)."),
        ("TT-002", "test_integer_negative",          "Encode/decode negative integer (-1)."),
        ("TT-003", "test_integer_max",               "Encode/decode maximum signed 32-bit (2^31-1)."),
        ("TT-004", "test_long_integer",              "Encode/decode 64-bit long integer (2^40)."),
        ("TT-005", "test_enumeration",               "Encode/decode enumeration value (7)."),
        ("TT-006", "test_boolean_true",              "Encode/decode Boolean True."),
        ("TT-007", "test_boolean_false",             "Encode/decode Boolean False."),
        ("TT-008", "test_text_string_ascii",         "Encode/decode ASCII text string."),
        ("TT-009", "test_text_string_unicode",       "Encode/decode Unicode text (non-ASCII chars)."),
        ("TT-010", "test_text_string_empty",         "Encode/decode empty text string."),
        ("TT-011", "test_byte_string",               "Encode/decode 4-byte binary string."),
        ("TT-012", "test_byte_string_empty",         "Encode/decode empty byte string."),
        ("TT-013", "test_datetime",                  "Encode/decode UTC datetime as Unix timestamp."),
        ("TT-014", "test_structure_nested",          "Encode/decode nested Structure with one Integer child."),
        ("TT-015", "test_structure_multiple_children","Structure with 3 children of different types."),
        ("TT-016", "test_decode_all_multiple_items", "decode_all() processes concatenated items."),
        ("TT-017", "test_padding_alignment",         "2-char string pads to 8 bytes (total 16 bytes)."),
        ("TT-018", "test_structure_item_get",        ".get(tag) returns first matching child."),
        ("TT-019", "test_get_returns_none_for_missing_tag", ".get() returns None for absent tag."),
        ("TT-020", "test_get_value_default",         ".get_value() returns default for absent tag."),
        ("TT-021", "test_truncated_header_raises",   "decode() raises ValueError on 3-byte input."),
        ("TT-022", "test_truncated_value_raises",    "decode() raises ValueError when value bytes missing."),
    ]

    tbl = doc.add_table(rows=1, cols=3)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["ID", "Test Name", "Description"])
    for i, row in enumerate(ttlv_tests):
        add_table_row(tbl, row, alt=(i % 2 == 0))

    section_break(doc)

    # ── 7.5 Lifecycle Unit Tests ──────────────────────────────────────────
    add_heading(doc, "7.5 Lifecycle Unit Tests — test_lifecycle.py", 2, MID_BLUE)
    add_para(doc, "Classes: TestTransitions | TestRevocationOperation | TestUsageAllowed", bold=True)
    section_break(doc)

    lc_tests = [
        ("LC-001", "test_pre_active_to_active",           "PreActive + activate → Active"),
        ("LC-002", "test_active_to_deactivated",          "Active + revoke_normal → Deactivated"),
        ("LC-003", "test_pre_active_to_deactivated",      "PreActive + revoke_normal → Deactivated"),
        ("LC-004", "test_active_to_compromised",          "Active + revoke_compromise → Compromised"),
        ("LC-005", "test_pre_active_to_compromised",      "PreActive + revoke_compromise → Compromised"),
        ("LC-006", "test_deactivated_to_compromised",     "Deactivated + revoke_compromise → Compromised"),
        ("LC-007", "test_pre_active_to_destroyed",        "PreActive + destroy → Destroyed"),
        ("LC-008", "test_active_to_destroyed",            "Active + destroy → Destroyed"),
        ("LC-009", "test_deactivated_to_destroyed",       "Deactivated + destroy → Destroyed"),
        ("LC-010", "test_compromised_to_destroyed_compromised", "Compromised + destroy → DestroyedCompromised"),
        ("LC-011", "test_destroyed_cannot_activate",      "Destroyed + activate → IllegalOperation"),
        ("LC-012", "test_destroyed_cannot_destroy_again", "Destroyed + destroy → IllegalOperation"),
        ("LC-013", "test_active_cannot_activate_again",   "Active + activate → IllegalOperation"),
        ("LC-014", "test_deactivated_cannot_activate",    "Deactivated + activate → IllegalOperation"),
        ("LC-015", "test_superseded_is_normal",           "Superseded reason → revoke_normal"),
        ("LC-016", "test_key_compromise_is_compromise",   "KeyCompromise reason → revoke_compromise"),
        ("LC-017", "test_ca_compromise_is_compromise",    "CACompromise reason → revoke_compromise"),
        ("LC-018", "test_cessation_is_normal",            "CessationOfOperation → revoke_normal"),
        ("LC-019", "test_active_encrypt_ok",              "Active state permits encrypt"),
        ("LC-020", "test_active_decrypt_ok",              "Active state permits decrypt"),
        ("LC-021", "test_pre_active_encrypt_forbidden",   "PreActive forbids encrypt"),
        ("LC-022", "test_deactivated_encrypt_forbidden",  "Deactivated forbids encrypt"),
        ("LC-023", "test_deactivated_decrypt_ok",         "Deactivated permits decrypt"),
        ("LC-024", "test_destroyed_any_op_forbidden",     "Destroyed forbids all operations"),
        ("LC-025", "test_compromised_get_ok",             "Compromised permits get"),
        ("LC-026", "test_compromised_encrypt_forbidden",  "Compromised forbids encrypt"),
    ]

    tbl = doc.add_table(rows=1, cols=3)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["ID", "Test Name", "Assertion"])
    for i, row in enumerate(lc_tests):  # 26 total
        add_table_row(tbl, row, alt=(i % 2 == 0))

    section_break(doc)

    # ── 7.6 Metadata Store Unit Tests ────────────────────────────────────
    add_heading(doc, "7.6 Metadata Store Unit Tests — test_metadata.py", 2, MID_BLUE)
    add_para(doc, "Classes: TestCreateObject | TestStateTransitions | TestAttributes | TestLocate", bold=True)
    section_break(doc)

    meta_tests = [
        ("MS-001", "test_create_returns_uuid",        "create_object() returns a 36-char UUID string."),
        ("MS-002", "test_created_object_retrievable", "Created object's columns match inputs."),
        ("MS-003", "test_default_state_is_pre_active","Default state is PreActive."),
        ("MS-004", "test_create_with_names",          "Name attributes stored correctly as JSON."),
        ("MS-005", "test_nonexistent_object_returns_none", "get_object('does-not-exist') returns None."),
        ("MS-006", "test_activate",                   "activate() sets state=Active."),
        ("MS-007", "test_set_state",                  "set_state() updates arbitrary state value."),
        ("MS-008", "test_set_destroy",                "set_destroy() sets state=Destroyed, records timestamp."),
        ("MS-009", "test_revoke_normal",              "set_revoke(Deactivated) records deactivation_date."),
        ("MS-010", "test_revoke_compromise",          "set_revoke(Compromised) records compromise_date."),
        ("MS-011", "test_add_and_get_attribute",      "add_attribute / get_attribute round-trip."),
        ("MS-012", "test_add_multiple_values",        "Multi-valued attribute uses sequential attr_index."),
        ("MS-013", "test_delete_attribute",           "delete_attribute removes one value by name+index."),
        ("MS-014", "test_locate_by_type",             "locate(object_type) returns only matching types."),
        ("MS-015", "test_locate_by_state",            "locate(state) returns only matching state."),
        ("MS-016", "test_locate_by_name",             "locate(name) uses JSON-extract on Name attr."),
        ("MS-017", "test_locate_with_max_items",      "locate(max_items=2) returns at most 2 results."),
        ("MS-018", "test_locate_no_match",            "locate(name='nonexistent') returns []."),
    ]

    tbl = doc.add_table(rows=1, cols=3)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["ID", "Test Name", "Assertion"])
    for i, row in enumerate(meta_tests):
        add_table_row(tbl, row, alt=(i % 2 == 0))

    section_break(doc)

    # ── 7.7 Operation Integration Tests ──────────────────────────────────
    doc.add_page_break()
    add_heading(doc, "7.7 Operation Integration Tests — test_operations.py", 2, MID_BLUE)
    add_para(doc,
        "End-to-end tests that call operation handler functions directly "
        "(bypassing the server transport). Requires SoftHSM2."
    )
    section_break(doc)

    op_tests = [
        ("OI-001", "TestCreate::test_create_aes256",         "create.handle() generates AES-256 key; verifies UID + metadata."),
        ("OI-002", "TestCreate::test_create_aes128",         "create.handle() generates AES-128 key."),
        ("OI-003", "TestDestroy::test_destroy_existing",     "destroy.handle() transitions state to Destroyed."),
        ("OI-004", "TestDestroy::test_destroy_nonexistent_raises", "destroy.handle() raises ItemNotFound for unknown UID."),
        ("OI-005", "TestLocateOperation::test_locate_returns_created_key", "locate.handle() finds key by Name attribute."),
        ("OI-006", "TestEncryptDecrypt::test_aes_cbc_roundtrip", "encrypt + decrypt round-trip via handler functions."),
        ("OI-007", "TestActivateRevoke::test_activate_pre_active_key", "activate.handle() on PreActive key → Active."),
        ("OI-008", "TestActivateRevoke::test_revoke_active_key", "revoke.handle() on Active key → Deactivated."),
    ]

    tbl = doc.add_table(rows=1, cols=3)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["ID", "Test Name", "Assertion"])
    for i, row in enumerate(op_tests):
        add_table_row(tbl, row, alt=(i % 2 == 0))

    section_break(doc)

    # ── 7.8 Conformance Tests ─────────────────────────────────────────────
    add_heading(doc, "7.8 KMIP Conformance Tests — test_conformance.py", 2, MID_BLUE)
    add_para(doc,
        "End-to-end tests over TCP using KMIPClient. Each test case maps to an OASIS "
        "KMIP Test Cases v2.1 identifier. These tests verify protocol compliance at "
        "the network level."
    )
    section_break(doc)

    conformance = [
        # TC-DISC
        ("TC-DISC-001-a", "TestDiscoverVersions::test_discover_returns_list",
         "CS-AC-M", "DiscoverVersions returns a non-empty list."),
        ("TC-DISC-001-b", "test_discover_includes_v2_1",
         "CS-AC-M", "Response includes (2, 1) tuple."),
        ("TC-DISC-001-c", "test_discover_includes_v1_x",
         "CS-AC-M", "Response includes at least one v1.x version."),
        ("TC-DISC-001-d", "test_discover_versions_are_ordered_descending",
         "CS-AC-M", "Latest version is first in the list."),
        # TC-QUERY
        ("TC-QUERY-001-a", "TestQuery::test_query_returns_operations",
         "CS-AC-M", "Query(Operations) returns non-empty operations list."),
        ("TC-QUERY-001-b", "test_query_includes_create",
         "CS-AC-M", "Operations list contains Operation.Create."),
        ("TC-QUERY-001-c", "test_query_includes_destroy",
         "CS-AC-M", "Operations list contains Operation.Destroy."),
        ("TC-QUERY-001-d", "test_query_includes_locate",
         "CS-AC-M", "Operations list contains Operation.Locate."),
        ("TC-QUERY-001-e", "test_query_object_types",
         "CS-AC-M", "Query(Objects) includes ObjectType.SymmetricKey."),
        ("TC-QUERY-001-f", "test_query_server_info",
         "CS-AC-M", "Query(ServerInformation) returns non-empty vendor string."),
        # TC-CREATE
        ("TC-CREATE-001-a", "TestCreate::test_create_aes256_returns_uid",
         "CS-AC-M", "Create AES-256 returns a 36-char UUID."),
        ("TC-CREATE-001-b", "test_create_aes128_returns_uid",
         "CS-AC-M", "Create AES-128 returns a UID."),
        ("TC-CREATE-001-c", "test_create_with_name",
         "CS-AC-M", "Created key with name is locatable by name."),
        ("TC-CREATE-001-d", "test_create_uids_are_unique",
         "CS-AC-M", "Two Create calls return different UIDs."),
        ("TC-CREATE-001-e", "test_create_sets_state_active",
         "CS-AC-M", "Newly created key has State=Active."),
        # TC-CREATE-KP
        ("TC-CKP-001-a", "TestCreateKeyPair::test_create_rsa2048_returns_two_uids",
         "CS-AC-O", "RSA-2048 CreateKeyPair returns two distinct 36-char UIDs."),
        ("TC-CKP-001-b", "test_create_rsa_keys_are_active",
         "CS-AC-O", "Both RSA key objects have State=Active."),
        # TC-GET
        ("TC-GET-001-a", "TestGet::test_get_extractable_key_succeeds",
         "CS-AC-M", "Get returns a non-None response for an extractable key."),
        ("TC-GET-001-b", "test_get_nonexistent_uid_fails",
         "CS-AC-M", "Get with unknown UID raises KMIPClientError(ItemNotFound)."),
        # TC-GETATTR
        ("TC-GETATTR-001-a", "TestGetAttributes::test_get_object_type",
         "CS-AC-M", "GetAttributes('Object Type') returns ObjectType.SymmetricKey."),
        ("TC-GETATTR-001-b", "test_get_cryptographic_algorithm",
         "CS-AC-M", "GetAttributes('Cryptographic Algorithm') returns AES."),
        ("TC-GETATTR-001-c", "test_get_cryptographic_length",
         "CS-AC-M", "GetAttributes('Cryptographic Length') returns 192."),
        ("TC-GETATTR-001-d", "test_get_state_attribute",
         "CS-AC-M", "GetAttributes('State') returns Active."),
        ("TC-GETATTR-001-e", "test_get_all_attributes",
         "CS-AC-M", "GetAttributes() returns dict with all standard attributes."),
        # TC-LOCATE
        ("TC-LOCATE-001-a", "TestLocate::test_locate_all_returns_list",
         "CS-AC-M", "Locate() returns list containing the created UID."),
        ("TC-LOCATE-001-b", "test_locate_by_object_type",
         "CS-AC-M", "Locate(ObjectType=SymmetricKey) finds the key."),
        ("TC-LOCATE-001-c", "test_locate_by_name",
         "CS-AC-M", "Locate by name attribute returns matching UID."),
        ("TC-LOCATE-001-d", "test_locate_by_state",
         "CS-AC-M", "Locate(State=Active) finds the key."),
        ("TC-LOCATE-001-e", "test_locate_unknown_name_returns_empty",
         "CS-AC-M", "Locate with non-existent name returns []."),
        ("TC-LOCATE-001-f", "test_locate_by_algorithm",
         "CS-AC-M", "Locate(algorithm=AES) finds the key."),
        # TC-LIFECYCLE
        ("TC-LC-001-a", "TestLifecycle::test_revoke_transitions_to_deactivated",
         "CS-AC-M", "Revoke(Superseded) → State=Deactivated."),
        ("TC-LC-001-b", "test_revoke_compromise_transitions_to_compromised",
         "CS-AC-M", "Revoke(KeyCompromise) → State=Compromised."),
        ("TC-LC-001-c", "test_destroy_transitions_to_destroyed",
         "CS-AC-M", "Revoke + Destroy → State=Destroyed."),
        ("TC-LC-001-d", "test_destroy_active_key",
         "CS-AC-M", "Destroy without Revoke → State=Destroyed (Active→Destroyed allowed)."),
        ("TC-LC-001-e", "test_cannot_destroy_twice",
         "CS-AC-M", "Double Destroy raises KMIPClientError."),
        ("TC-LC-001-f", "test_cannot_revoke_destroyed_key",
         "CS-AC-M", "Revoke after Destroy raises KMIPClientError."),
        # TC-CRYPT
        ("TC-CRYPT-001-a", "TestEncryptDecrypt::test_encrypt_returns_ciphertext",
         "CS-AC-O", "Encrypt returns non-empty ciphertext != plaintext."),
        ("TC-CRYPT-001-b", "test_decrypt_recovers_plaintext",
         "CS-AC-O", "Decrypt recovers original plaintext."),
        ("TC-CRYPT-001-c", "test_different_plaintexts_give_different_ciphertexts",
         "CS-AC-O", "Different plaintexts produce different ciphertexts."),
        ("TC-CRYPT-001-d", "test_encrypt_deactivated_key_fails",
         "CS-AC-O", "Encrypt with Deactivated key raises KMIPClientError."),
        ("TC-CRYPT-001-e", "test_decrypt_deactivated_key_succeeds",
         "CS-AC-O", "Decrypt with Deactivated key succeeds (data recovery)."),
        # TC-ATTR
        ("TC-ATTR-001-a", "TestAttributes::test_add_custom_attribute",
         "CS-AC-M", "AddAttribute stores; GetAttributes retrieves custom attr."),
        ("TC-ATTR-001-b", "test_add_multiple_custom_attributes",
         "CS-AC-M", "Two custom attributes independently stored and retrieved."),
        # TC-ERR
        ("TC-ERR-001-a", "TestErrorHandling::test_get_nonexistent_returns_item_not_found",
         "CS-AC-M", "Get(unknown-UID) returns OperationFailed/ItemNotFound."),
        ("TC-ERR-001-b", "test_activate_nonexistent_returns_item_not_found",
         "CS-AC-M", "Activate(unknown-UID) returns OperationFailed."),
        ("TC-ERR-001-c", "test_destroy_nonexistent_returns_item_not_found",
         "CS-AC-M", "Destroy(unknown-UID) returns OperationFailed."),
        ("TC-ERR-001-d", "test_double_destroy_fails",
         "CS-AC-M", "Second Destroy on same UID returns OperationFailed."),
        ("TC-ERR-001-e", "test_revoke_nonexistent_fails",
         "CS-AC-M", "Revoke(unknown-UID) returns OperationFailed."),
    ]

    tbl = doc.add_table(rows=1, cols=4)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["TC-ID", "Test Name", "Class", "Assertion"])
    for i, row in enumerate(conformance):
        add_table_row(tbl, row, alt=(i % 2 == 0))

    section_break(doc)

    # ── 7.9 Extended Coverage Tests ──────────────────────────────────────
    doc.add_page_break()
    add_heading(doc, "7.9 Extended Coverage Tests — test_extended_coverage.py", 2, MID_BLUE)
    add_para(doc,
        "test_conformance.py covers the mandatory/optional KMIP TC surface described in "
        "Section 7.8 above — the operations and behaviors present when this project had "
        "15 operations and 122 tests. test_extended_coverage.py is a later, much larger "
        "addition (502 tests, over four times the size of the original five test modules "
        "combined) covering everything built since: the remaining 25 operations not "
        "exercised by test_conformance.py, algorithm and cipher-mode coverage across the "
        "capability-probed CryptographicAlgorithm set, error paths, and the access-control "
        "and session-concurrency work described in Sections 3.3 and 4.4b."
    )
    section_break(doc)
    ext_areas = [
        ("All 41 operations", "End-to-end coverage of every operation in Section 6's "
         "table, not just the 16 covered by the original conformance suite."),
        ("Algorithm / mode coverage", "Every CryptographicAlgorithm + BlockCipherMode "
         "combination the capability probe reports as available on this SoftHSM2 token, "
         "plus confirmation that unsupported combinations fail cleanly with "
         "OperationNotSupported."),
        ("Error paths", "Invalid input, missing fields, wrong object state, and "
         "cross-identity access attempts across every operation, not just the small "
         "TC-ERR-001 subset in test_conformance.py."),
        ("Access control", "Ownership enforcement, the admin-role bypass, and delegated "
         "\"read\" vs \"full\" grants — the three tiers described in Section 4.4b — "
         "exercised against real operations over TCP."),
        ("Session concurrency", "Concurrent client threads driving the server's single "
         "locked PKCS#11 session (Section 3.3) to confirm correctness under load, given "
         "that the earlier lock-free session-pool approach was proven unsafe."),
    ]
    tbl = doc.add_table(rows=1, cols=2)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Coverage Area", "Detail"])
    for i, row in enumerate(ext_areas):
        add_table_row(tbl, row, alt=(i % 2 == 0))

    # ═══════════════════════════════════════════════════════════════════════
    # 8. TEST RESULTS SUMMARY
    # ═══════════════════════════════════════════════════════════════════════
    doc.add_page_break()
    add_heading(doc, "8. Test Results Summary", 1, DARK_BLUE)

    add_para(doc,
        "All 811 tests pass on a Debian installation with a SoftHSM2 2.7.0 build "
        "against OpenSSL 3.0.13 and Python 3.11."
    )
    section_break(doc)

    result_table = [
        ("test_ttlv.py",             "22",  "22",  "0",  "100 %"),
        ("test_lifecycle.py",        "26",  "26",  "0",  "100 %"),
        ("test_metadata.py",         "18",  "18",  "0",  "100 %"),
        ("test_operations.py",       "8",   "8",   "0",  "100 %"),
        ("test_conformance.py",      "48",  "48",  "0",  "100 %"),
        ("test_governance.py",       "48",  "48",  "0",  "100 %"),
        ("test_extended_coverage.py","641", "641", "0",  "100 %"),
        ("TOTAL",                    "811", "811", "0",  "100 %"),
    ]

    tbl = doc.add_table(rows=1, cols=5)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Module", "Total", "Passed", "Failed", "Pass Rate"])
    for i, row in enumerate(result_table):
        r = add_table_row(tbl, row, alt=(i % 2 == 0))
        if row[0] == "TOTAL":
            for cell in tbl.rows[-1].cells:
                set_cell_bg(cell, "1E802E")
                for para in cell.paragraphs:
                    for run in para.runs:
                        run.bold = True
                        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

    section_break(doc)

    # ═══════════════════════════════════════════════════════════════════════
    # 9. KNOWN LIMITATIONS & FUTURE WORK
    # ═══════════════════════════════════════════════════════════════════════
    add_heading(doc, "9. Known Limitations & Future Work", 1, DARK_BLUE)

    add_heading(doc, "9.1 Current Limitations", 2, MID_BLUE)
    limits = [
        ("Single, locked PKCS#11 session", "server.py runs one thread per connection, "
         "but they share one PKCS11Shim session serialized by a threading.RLock. This is "
         "the deliberate, permanent design, not a stopgap — a session pool (separate "
         "session per thread) was built and tested, and reproducibly segfaults or "
         "corrupts operations under concurrency: python-pkcs11 0.9.5 calls "
         "C_Initialize(NULL), so the library's own internal thread safety is never "
         "enabled, and separate sessions don't work around that. A real fix needs a "
         "PKCS#11 binding that passes CKF_OS_LOCKING_OK, or a multi-process worker pool. "
         "See Section 3.3."),
        ("RBAC and governance have no wire protocol", "Identities, roles, groups, "
         "grants, per-role operation allowlists, cryptoperiods and dual-control "
         "approvals are all managed through kmip-admin (or the MetadataStore "
         "directly), never over KMIP — the specification defines no operations for any "
         "of it. A client under dual control learns only that its operation was "
         "refused and which request id to have approved; the approval happens out of "
         "band. See Section 4.4b."),
        ("Audit log is local and unsigned", "Entries are hash-chained and append-only, "
         "which makes tampering detectable, but the chain is not anchored anywhere "
         "external — an attacker who rewrites the whole log consistently leaves no "
         "trace. Ship entries to an external collector for stronger guarantees."),
        ("No ACME / automated certificate issuance", "TLS is enforced by default and "
         "reload_tls() picks up renewed material without dropping connections, but "
         "obtaining and renewing certificates is left to the operator."),
        ("No multi-tenancy", "Groups and role allowlists partition access, but not the "
         "namespace: object names, Locate queries and quotas are global, and there is "
         "no tenant boundary that would let two unrelated customers share one "
         "deployment. Isolation today means one deployment per tenant."),
        ("Not FIPS/CC validated", "SoftHSM2 isn't a validated HSM. The PKCS#11 boundary "
         "means a validated token can be swapped in with no code change above "
         "pkcs11_shim/, but that swap hasn't happened here."),
        ("SoftHSM2 SENSITIVE+EXTRACTABLE bug", "SENSITIVE=True AND EXTRACTABLE=True "
         "blocks CKA_VALUE read on this token; the shim downgrades sensitivity "
         "automatically (effective_sensitive = sensitive AND NOT extractable) when "
         "extractability is explicitly requested."),
        ("No batch atomicity", "Failure in one BatchItem does not roll back previous "
         "items in the same batch."),
        ("Algorithm coverage", "15 of 40 CryptographicAlgorithm values work against "
         "this token, capability-probed at startup; the rest are cleanly rejected with "
         "OperationNotSupported rather than a raw PKCS#11 error. See Section 4.6."),
        ("Worker scaling is ~1.5x, not linear", "server.workers genuinely exceeds one "
         "core, but the hash-chained audit log serialises every audited operation on a "
         "single database write lock. Higher scaling would need a fundamentally "
         "different audit design (per-shard chains, or an external append-only "
         "service)."),
        ("No PostgreSQL backend or HSM failover", "The store is heavily SQLite-specific "
         "(PRAGMA user_version, json_extract, RAISE(ABORT) triggers), so a second "
         "backend is a substantial rewrite; HSM failover needs a second token to "
         "verify against. Neither was built rather than shipped untested."),
        ("No HA", "Single SQLite file, single HSM token; no clustering or replication. "
         "Backup and restore are tooled (kmip-admin backup create/inspect/restore/"
         "verify, online backup API, token-pairing checks), but point-in-time rather "
         "than continuous."),
    ]
    tbl = doc.add_table(rows=1, cols=2)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Limitation", "Detail"])
    for i, (k, v) in enumerate(limits):
        add_table_row(tbl, [k, v], alt=(i % 2 == 0))

    section_break(doc)
    add_heading(doc, "9.2 Roadmap", 2, MID_BLUE)
    roadmap = [
        "A PKCS#11 binding that passes CKF_OS_LOCKING_OK at C_Initialize, or a "
        "multi-process worker pool — the two real fixes for the single-session lock "
        "(a same-process session pool is not viable; see Section 3.3)",
        "Multi-tenancy: a namespace boundary and per-tenant quotas, so unrelated "
        "customers can share one deployment",
        "ACME integration, so certificate renewal is automatic rather than an operator "
        "task on top of the existing hot reload",
        "An external anchor for the audit chain (shipping entries to an append-only "
        "collector), so a wholesale rewrite of the local log is still detectable",
        "FIPS/CC-validated HSM backend swap-in and validation",
        "KMIP Batch Item atomicity (rollback on error)",
        "Additional PKCS#11-backed mechanisms (SHA-3 HMAC/hash, Blowfish, Twofish) once "
        "a capable token/backend is available — no code change needed above the shim",
        "A second storage backend (PostgreSQL) and HSM failover, both of which need "
        "infrastructure this project has not been able to test against",
        "HA / clustering, beyond the point-in-time backup and restore tooling that "
        "exists today",
    ]
    for r in roadmap:
        add_bullet(doc, r)

    # ═══════════════════════════════════════════════════════════════════════
    # 10. REFERENCES
    # ═══════════════════════════════════════════════════════════════════════
    doc.add_page_break()
    add_heading(doc, "10. References", 1, DARK_BLUE)
    refs = [
        ("[KMIP21]",    "OASIS KMIP Specification Version 2.1. "
                        "https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html"),
        ("[KMIP-TC21]", "OASIS KMIP Test Cases Version 2.1. "
                        "https://docs.oasis-open.org/kmip/kmip-testcases/v2.1/"),
        ("[PKCS11]",    "PKCS #11 Cryptographic Token Interface Standard v3.0. "
                        "https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.0/"),
        ("[SOFTHSM2]",  "SoftHSM2 — Software implementation of a cryptographic store. "
                        "https://github.com/opendnssec/SoftHSMv2"),
        ("[python-pkcs11]", "python-pkcs11 — PKCS#11 bindings for Python. "
                            "https://python-pkcs11.readthedocs.io/"),
        ("[RFC4122]",   "A Universally Unique IDentifier (UUID) URN Namespace. "
                        "https://datatracker.ietf.org/doc/html/rfc4122"),
    ]
    tbl = doc.add_table(rows=1, cols=2)
    tbl.style = 'Table Grid'
    add_table_header_row(tbl, ["Reference", "Description / URL"])
    for i, (ref, desc) in enumerate(refs):
        add_table_row(tbl, [ref, desc], alt=(i % 2 == 0))

    # ── footer ────────────────────────────────────────────────────────────
    section_break(doc)
    section_break(doc)
    footer_p = doc.add_paragraph()
    footer_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fr = footer_p.add_run(
        f"KMIP on PKCS#11 — Project Documentation v1.0.0 — {TODAY}"
    )
    fr.font.size = Pt(8)
    fr.font.color.rgb = RGBColor(0x80, 0x80, 0x80)

    # ── save ──────────────────────────────────────────────────────────────
    out = "/home/user/Noida/KMIP_PKCS11_Project_Documentation.docx"
    doc.save(out)
    print(f"Saved: {out}")
    return out


if __name__ == "__main__":
    build()
