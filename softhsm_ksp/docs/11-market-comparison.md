# 11 — CNG KSP market comparison

A capability audit of shipping CNG Key Storage Providers, compared against
this project. Every claim is graded by how well it could be verified.

*Audit date: September 2026.*

---

## Headline

**Almost every shipping CNG KSP exposes exactly three algorithm families:
RSA, ECDSA and ECDH — all on NIST curves.** Not one of the providers
surveyed advertises AES, HMAC or EdDSA through the KSP interface, even when
the underlying HSM performs those operations happily over PKCS#11.

That makes this project's symmetric and Edwards-curve support genuinely
unusual — but unusual in a way that carries a cost, because the algorithm
identifiers those features require do not exist in CNG. See
[finding 2](#finding-2--our-eddsa-and-hmac-support-uses-identifiers-cng-does-not-define).

---

## Evidence grades

Vendor CNG algorithm tables are mostly behind support portals or on domains
that could not be reached when this audit was run. Rather than paper over
that, every column carries a grade.

| Grade | Meaning |
|-------|---------|
| **A — Verified** | Read directly from source code, or from an authoritative vendor API reference that enumerates the KSP's own algorithm list. |
| **B — Documented** | Stated in vendor or Microsoft documentation surfaced through search, but the primary page could not be fetched and read in full. |
| **C — Inferred** | Drawn from HSM datasheets describing the *device*, not the KSP. See [finding 1](#finding-1--an-hsms-capability-is-not-its-ksps-capability) for why that distinction matters. Do not rely on these cells. |

No cell in this document is a guess. Where nothing could be established, the
cell says "not established".

> Treat anything below grade A as a starting point for your own vendor
> conversation, not as a procurement input.

---

## Master comparison

Capability as exposed **through the CNG KSP interface** — what
`NCryptCreatePersistedKey` and `NCryptIsAlgSupported` will accept — not what
the backing device can compute.

| Capability | This project (A) | MS Software KSP (B) | MS Platform Crypto / TPM (B) | AWS CloudHSM (B) | Utimaco CryptoServer (B) | Luna · nShield · Securosys (C) |
|---|---|---|---|---|---|---|
| **RSA** | ✓ 2048 / 3072 / 4096 | ✓ 512–16384, 64-bit steps | ✓ typically 2048 | ✓ to 4096 | ✓ 512–16384, 8-bit steps | ✓ to 4096+ |
| **ECDSA** | ✓ P-256 / 384 / 521 | ✓ P-256 / 384 / 521 | ◐ P-256/384/521, Win10 21H2+ | ✓ P-256 / 384 / 521 | ✓ P-256 / 384 / 521 | ✓ NIST + Brainpool claimed |
| **ECDH** | ✓ P-256 / 384 / 521 | ✓ P-256 / 384 / 521 | ✗ | ✗ not in alg list | ✓ P-256 / 384 / 521 | Not established |
| **Finite-field DH** | ✗ out of scope | ✓ 512–4096 | ✗ | ✗ | Not established | Not established |
| **DSA** | ✗ deprecated | ✓ 512–1024 | ✗ | ✗ | Not established | Not established |
| **EdDSA** (Ed25519/Ed448) | ◐ **extension**, non-standard identifier | ✗ | ✗ | ✗ | ✗ | ✗ device may, KSP does not |
| **AES** | ✓ 128 / 192 / 256 | ✗ BCrypt, not KSP | ✗ | ✗ not in alg list | ✗ not in KSP list | ✗ device yes, KSP not shown |
| **HMAC** | ◐ **extension**, non-standard identifier | ✗ | ✗ | ✗ | ✗ | ✗ |
| **Post-quantum** (ML-DSA / ML-KEM / LMS) | ✗ | ✗ | ✗ | ✗ | Not established | ◐ Luna claims device support |
| **Key protection** | Software token (encrypted SQLite) | Software, DPAPI | Hardware TPM | FIPS 140-2 L3 HSM | FIPS / CC certified HSM | FIPS / CC certified HSM |
| **Private key export** | ✗ refused by design | ◐ policy-dependent | ✗ | ✗ | ✗ | ✗ |
| **HLK certifiable** | ✗ software + unsigned | ✓ ships in Windows | ✓ ships in Windows | ✓ signed product | ✓ signed product | ✓ signed products |
| **Licence** | Open source | Bundled with Windows | Bundled with Windows | Commercial | Commercial | Commercial |

Legend: ✓ exposed · ◐ conditional or non-standard · ✗ not exposed through the KSP.

---

## Key sizes by algorithm

Where a provider accepts a range, the increment matters as much as the
bounds — a KSP advertising 512–16384 in 64-bit steps will reject 2056.

| Provider | RSA | ECDSA / ECDH curves | AES | Other |
|---|---|---|---|---|
| **This project** | 2048, 3072, 4096 — exactly these three | P-256, P-384, P-521 (both ECDSA and ECDH) | 128, 192, 256 | Ed25519 (255), Ed448 (448); HMAC ≥128, whole bytes |
| MS Software KSP | 512 – 16384, 64-bit increments | P-256, P-384, P-521 | — | DH 512–4096, DSA 512–1024 |
| MS Platform Crypto | Bounded by the TPM, 2048 in practice | P-256, P-384, P-521 (Win10 21H2+) | — | — |
| AWS CloudHSM | up to 4096 | P-256, P-384, P-521 | — (device yes, KSP no) | — |
| Utimaco CryptoServer | 512 – 16384, 8-bit increments | P-256, P-384, P-521 | — | — |

Thales, Entrust and Securosys are omitted from this table on purpose: their
CNG-specific size tables could not be reached, and quoting device datasheet
ranges here would misrepresent the KSP.

---

## Operation modes

### Signing and padding

| Mode | This project | Others surveyed | Notes |
|---|---|---|---|
| RSA PKCS#1 v1.5 | ✓ SHA-1/256/384/512 | ✓ universal | The baseline every KSP implements |
| RSA PSS | ✓ SHA-1/256/384/512 | ✓ expected | Salt length from `BCRYPT_PSS_PADDING_INFO` |
| ECDSA | ✓ raw r‖s output | ✓ universal | DER→r‖s conversion is the KSP's job |
| EdDSA | ◐ extension | ✗ none | CNG defines no EdDSA algorithm ID |
| HMAC | ◐ extension | ✗ none | CNG does HMAC through BCrypt flags |

### Decryption and key agreement

| Mode | This project | Others surveyed | Notes |
|---|---|---|---|
| RSA PKCS#1 decrypt | ✓ | ✓ expected | — |
| RSA OAEP decrypt | ✓ SHA-1/224/256/384/512 + label | ◐ hash range unconfirmed | Five hashes is broader than typical |
| ECDH agreement | ✓ P-256/384/521, raw Z | ◐ Microsoft and Utimaco yes | `BCRYPT_KDF_RAW_SECRET` only |
| Hash-based KDF | ✗ `NTE_NOT_SUPPORTED` | Not established | Caller runs the KDF via BCrypt |

### Symmetric cipher modes — this project only

| Chaining mode | Identifier | Standard? | PKCS#11 mechanism | IV / nonce |
|---|---|---|---|---|
| ECB | `ChainingModeECB` | CNG standard | `CKM_AES_ECB` | none |
| CBC | `ChainingModeCBC` | CNG standard | `CKM_AES_CBC` | 16 bytes |
| CBC padded | `ChainingModeCBC` + pad flag | CNG standard | `CKM_AES_CBC_PAD` | 16 bytes |
| GCM | `ChainingModeGCM` | CNG standard | `CKM_AES_GCM` | 12 bytes, 128-bit tag |
| CTR | `ChainingModeCTR` | **Our extension** | `CKM_AES_CTR` | 16-byte counter block |
| CCM, CFB | — | — | ✗ `NTE_NOT_SUPPORTED` | — |

Four of the five modes use standard CNG chaining-mode strings, so an
application already written against `BCRYPT_CHAIN_MODE_*` would work
unchanged — if it could get an AES key handle from a KSP in the first place.

---

## Findings

### Finding 1 — An HSM's capability is not its KSP's capability

AWS CloudHSM is the clean proof. The device performs AES, DES3, HMAC and
ECDH; its own documentation says so. But the KSP's `NCryptIsAlgSupported`
answers for exactly four identifiers: `RSA`, `ECDSA_P256`, `ECDSA_P384`,
`ECDSA_P521`. Everything else the hardware can do is unreachable through CNG.

This is the trap in reading HSM datasheets as KSP comparisons. Thales Luna
advertises ML-DSA and ML-KEM; Entrust nShield advertises Ed25519 and
Camellia. Neither claim tells you what their CNG provider exposes, and that
is the only thing that matters to a Windows application. Every grade-C cell
in the table above exists because of this distinction.

### Finding 2 — Our EdDSA and HMAC support uses identifiers CNG does not define

Windows CNG has **no algorithm identifier for EdDSA**. It gained
`BCRYPT_ECC_CURVE_25519` in Windows 10, but for X25519 key agreement — not
Ed25519 signing. This is why .NET still cannot do Ed25519 through the OS.

This provider accepts `EDDSA_ED25519`, `EDDSA_ED448` and `HMAC_SHA256` as
algorithm names. Those strings are ours. No stock Windows application,
certificate enrolment flow or HLK test will ever ask for them, because
nothing in CNG names them. Two consequences follow:

- These features are reachable only from an application written specifically
  against this KSP.
- They cannot be verified end-to-end with BCrypt the way the ECDSA paths
  are — which is why the EdDSA tests assert signature *size* and blob layout
  rather than round-tripping a verification.

The implementation is sound and the tests are honest about what they check.
But the feature list should say "PKCS#11 mechanism reachable through a
private interface", not "CNG algorithm support".

The AES surface is different and better: `AES` and three of four chaining
modes are real CNG identifiers.

| Identifier | Standard CNG? |
|---|---|
| `RSA` | ✓ `BCRYPT_RSA_ALGORITHM` |
| `ECDSA_P256` / `_P384` / `_P521` | ✓ `BCRYPT_ECDSA_P*_ALGORITHM` |
| `ECDH_P256` / `_P384` / `_P521` | ✓ `BCRYPT_ECDH_P*_ALGORITHM` |
| `AES` | ✓ `BCRYPT_AES_ALGORITHM` |
| `ChainingModeECB` / `CBC` / `GCM` | ✓ `BCRYPT_CHAIN_MODE_*` |
| `ChainingModeCTR` | ✗ our extension |
| `EDDSA_ED25519` / `EDDSA_ED448` | ✗ our extension |
| `HMAC_SHA1` / `_SHA256` / `_SHA384` / `_SHA512` | ✗ our extension |

### Finding 3 — On the algorithms that matter, we are at parity

Strip out the extensions and compare only standard CNG surface. For RSA,
ECDSA and ECDH — the three families every surveyed provider ships — this
project covers the same curves as Microsoft's own Software KSP, and a wider
curve set than the TPM provider offers.

Two places where the surface is genuinely broader than the field:

- **OAEP hash coverage.** Five hashes plus label support. No surveyed
  provider documents a range this wide, though absence of documentation is
  not evidence of absence.
- **AES through a KSP at all**, using standard `ChainingMode*` strings.

The RSA range now runs from 2048 to 16384 bits in 64-bit steps, matching
Microsoft's granularity at the top end. The remaining difference is at the
bottom: Microsoft and Utimaco accept 512-bit RSA, and this provider rejects
anything below `KSP_RSA_MIN_BITS` (2048 by default) with `NTE_BAD_LEN`. That
floor is a deliberate choice, not an omission — a build that must talk to a
legacy CA can lower the constant, but no deployment gets weak keys by
default.

### Finding 4 — The real differentiator is not algorithms

Every commercial entry in this table is a signed, certified product backed
by tamper-resistant hardware. This project is an unsigned DLL over a
software token that keeps keys in an encrypted SQLite file. No amount of
algorithm coverage closes that gap, and the provider reports
`NCRYPT_IMPL_HARDWARE_FLAG` as a testing convenience rather than a truthful
hardware claim — see [10 — Running the Microsoft HLK tests](./10-hlk-execution.md).

Read the comparison accordingly: it is a fair map of the *interface*
surface, and says nothing about assurance. Where this project competes is
development, CI and integration testing — exercising a CNG KSP integration
without provisioning an HSM.

### Finding 5 — Small gaps closed, and one found

The gap analysis in `SoftHSM2_KSP_Feature_Matrix.pdf` originally listed ten
small (S-effort) gaps. Five are now closed in code and tests: the RSA size
range, the 64-bit step, a settable RSA public exponent, PSS with SHA-224,
and HMAC-SHA224.

Two are deliberately left partial. RSA below 2048 became a build-time option
rather than a default, for the reason above. secp256k1 generates and signs,
but only through this provider's own `ECDSA_SECP256K1` identifier; the
standard CNG route is the generic ECDSA algorithm with
`BCRYPT_ECC_CURVE_NAME` set to `BCRYPT_ECC_CURVE_SECP256K1`, which needs
curve-name property handling.

One, `OPS-03` (an Authenticode-signed binary), cannot be closed by a code
change — it needs a purchased certificate and a legal entity.

The remaining two, `LIFE-06` (`EnumAlgorithms`) and `LIFE-07`
(`IsAlgSupported`), were **mis-graded as small**. The original note claimed
`ncrypt.dll` answers both from the registry. That is wrong: both are real
slots in `NCRYPT_KEY_STORAGE_FUNCTION_TABLE`, and closing them means
correcting the function table itself. Investigating that turned up a more
serious problem, recorded as `TABLE-01`: the table in `ksp_main.c` is
ordered to a hand-written struct in `tests/mock/windows_compat.h` rather
than to the Windows SDK's `ncrypt_provider.h`, which the Linux unit tests
cannot detect because they compile against that same hand-written struct.
`TABLE-01` blocks both, and is graded M.

---

## What could not be verified

Recorded so the gaps are visible rather than silently absent.

| Subject | Why it is missing |
|---------|-------------------|
| Thales Luna KSP | `thalesdocs.com` unreachable from the audit environment. Device-level PQC and NIST algorithm claims found; no CNG-specific algorithm or key-size table obtained. |
| Entrust nShield CNG | `nshielddocs.entrust.com` unreachable. Device supports Ed25519 and X25519 per datasheet; whether the CNG provider exposes them is unconfirmed. |
| Securosys Primus CNG | Algorithm table lives in a support-portal PDF. Only RSA-4096 and AES-256 for SQL Always Encrypted were confirmed. |
| Microsoft primary sources | `learn.microsoft.com` unreachable. Microsoft KSP figures come from search summaries of that documentation rather than the pages themselves. |
| Smart card KSP, YubiHSM, Azure Managed HSM | Not surveyed. Each would need the same treatment before appearing in a decision-grade table. |
| Mode-level detail elsewhere | No surveyed vendor documented OAEP hash coverage or PSS salt handling at the CNG level. Comparison on those rows is one-sided. |

---

## Method

This project's column was read from its own source — `config.h`,
`ksp_key.c`, `ksp_crypto.c`, `ksp_properties.c` — and is grade A throughout.
Every other column came from web search summaries; direct page fetches were
blocked by the audit environment's egress policy, so no primary vendor page
was read in full. Nothing in the vendor columns was inferred from the shape
of a competitor's offering.

To refresh this audit, re-check each source below and re-grade any cell whose
evidence has improved.

### Sources

1. [Microsoft — CNG Key Storage Providers](https://learn.microsoft.com/en-us/windows/desktop/SecCertEnroll/cng-key-storage-providers)
2. [AWS CloudHSM — NCryptIsAlgSupported with KSP](https://docs.aws.amazon.com/cloudhsm/latest/userguide/ksp-library-apis-is-alg-supported.html)
3. [Utimaco — CryptoServer SDK data sheet](https://support.hsm.utimaco.com/documents/20182/82257/CryptoServer+SDK+-+EN)
4. [Microsoft — CNG named elliptic curves](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-named-elliptic-curves)
5. [Gradenegger — EC keys with the Platform Crypto Provider](https://www.gradenegger.eu/en/certificate-requests-with-elliptic-curve-based-keys-will-fail-when-using-the-microsoft-platform-crypto-provider/)
6. Cited from search summaries, pages not reachable:
   [Thales — Luna KSP for CNG](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/microsoft/ksp_cng.htm) ·
   [Entrust — nShield cryptographic algorithms](https://nshielddocs.entrust.com/security-world-docs/v13.3/solo-ug-win/crypto-algorithms.html) ·
   [Securosys — Primus CNG/KSP](https://docs.securosys.com/mscng/overview/)

---

## See also

- [00 — Documentation index](./00-index.md)
- [04 — Cryptographic operations](./04-crypto-operations.md) — the mechanism mapping behind this project's column
- [10 — Running the Microsoft HLK tests](./10-hlk-execution.md) — why this KSP is not certifiable
