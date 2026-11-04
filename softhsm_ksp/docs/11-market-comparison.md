# 11 — CNG KSP market comparison

A capability audit of shipping CNG Key Storage Providers, compared against
this project. Every claim is graded by how well it could be verified.

*First audited September 2026. **Refreshed after roadmap phases 0–4** — this
project's column had drifted badly out of date, and the market moved under
it. See [what changed since the first audit](#what-changed-since-the-first-audit).*

---

## Headline

The first audit found that **almost every shipping CNG KSP exposes exactly
three algorithm families: RSA, ECDSA and ECDH, all on NIST curves.** That is
still true of the commercial HSM providers.

**It is no longer true of Microsoft.** ML-DSA reached general availability on
Windows Server 2025 and Windows 11 24H2/25H2 in late 2025, and AD CS gained
certificate enrolment against it in May 2026 — running, for the phase-1
deployment path, on the **Microsoft Software KSP**. Post-quantum signing is
now a shipping KSP feature, not a datasheet claim (grade B).

That inverts the most interesting row in this comparison. This project
implements ML-DSA and cannot deliver it, because its default backend does
not. Microsoft's software KSP delivers it today.

---

## Evidence grades

Vendor CNG algorithm tables are mostly behind support portals or on domains
this environment's egress policy blocks. Rather than paper over that, every
column carries a grade.

| Grade | Meaning |
|-------|---------|
| **A — Verified** | Read directly from source code, or from an authoritative reference that enumerates the KSP's own algorithm list. |
| **B — Documented** | Stated in vendor or Microsoft documentation surfaced through search, but the primary page could not be fetched and read in full. |
| **C — Inferred** | Drawn from HSM datasheets describing the *device*, not the KSP. See [finding 1](#finding-1--an-hsms-capability-is-not-its-ksps-capability) for why that distinction matters. Do not rely on these cells. |

No cell in this document is a guess. Where nothing could be established, the
cell says "not established".

**The egress policy is the binding constraint on grade.** On this refresh,
`learn.microsoft.com`, `techcommunity.microsoft.com`, vendor domains and
even third-party analyst posts were all refused by the proxy. Search result
summaries were reachable; the pages behind them were not. Every non-A cell
below therefore rests on a summary of a page nobody here has read.

> Treat anything below grade A as a starting point for your own vendor
> conversation, not as a procurement input.

---

## Master comparison

Capability as exposed **through the CNG KSP interface** — what
`NCryptCreatePersistedKey` and `NCryptIsAlgSupported` will accept — not what
the backing device can compute.

| Capability | This project (A) | MS Software KSP (B) | MS Platform Crypto / TPM (B) | AWS CloudHSM (B) | Utimaco CryptoServer (B) | Luna · nShield · Securosys (C) |
|---|---|---|---|---|---|---|
| **RSA** | ✓ 2048–16384, 64-bit steps | ✓ 512–16384, 64-bit steps | ✓ typically 2048 | ✓ to 4096 | ✓ 512–16384, 8-bit steps | ✓ to 4096+ |
| **ECDSA — NIST** | ✓ P-256 / 384 / 521 | ✓ P-256 / 384 / 521 | ◐ P-256/384/521, Win10 21H2+ | ✓ P-256 / 384 / 521 | ✓ P-256 / 384 / 521 | ✓ NIST + Brainpool claimed |
| **ECDSA — Brainpool, secp256k1** | ✓ via `BCRYPT_ECC_CURVE_NAME` | ✗ | ✗ | ✗ | Not established | ◐ device claims, KSP not established |
| **ECDH — NIST** | ✓ P-256 / 384 / 521 | ✓ P-256 / 384 / 521 | ✗ | ✗ not in alg list | ✓ P-256 / 384 / 521 | Not established |
| **X25519 agreement** | ✓ `BCRYPT_ECC_CURVE_25519` | Not established | ✗ | ✗ | Not established | ◐ device claims |
| **Key derivation (KDF)** | ✓ RAW_SECRET, HASH, HKDF, HMAC, TLS 1.2 PRF | Not established | — | — | Not established | Not established |
| **Finite-field DH** | ✗ out of scope | ✓ 512–4096 | ✗ | ✗ | Not established | Not established |
| **DSA** | ✗ deprecated | ✓ 512–1024 | ✗ | ✗ | Not established | Not established |
| **EdDSA** (Ed25519/Ed448) | ◐ **extension**, non-standard identifier | ✗ | ✗ | ✗ | ✗ | ✗ device may, KSP does not |
| **AES** | ✓ 128 / 192 / 256 | ✗ BCrypt, not KSP | ✗ | ✗ not in alg list | ✗ not in KSP list | ✗ device yes, KSP not shown |
| **HMAC** | ◐ **extension**, non-standard identifier | ✗ | ✗ | ✗ | ✗ | ✗ |
| **ML-DSA** (FIPS 204) | ◐ implemented, **backend cannot deliver** | ✓ **GA; AD CS enrolment, May 2026** | ✗ | Not established | Not established | ◐ device firmware yes (Luna 7.9+, nShield 5/XC); KSP exposure not established |
| **ML-KEM** (FIPS 203) | ✗ no function-table slot | ✓ CNG GA (BCrypt-side) | ✗ | ✗ | Not established | ◐ device firmware claims |
| **LMS / XMSS** | ✗ | Not established | ✗ | ✗ | Not established | ◐ device claims |
| **Backend portability** | ✓ any PKCS#11 v2.40+ module | ✗ n/a | ✗ n/a | ✗ own HSM only | ✗ own HSM only | ✗ own HSM only |
| **Runtime capability discovery** | ✓ `C_GetMechanismList` at startup | n/a — fixed algorithm set | n/a | n/a | n/a | n/a |
| **Key protection** | Software token (encrypted SQLite) | Software, DPAPI | Hardware TPM | FIPS 140-2 L3 HSM | FIPS / CC certified HSM | FIPS / CC certified HSM |
| **Private key export** | ✗ refused by design | ◐ policy-dependent | ✗ | ✗ | ✗ | ✗ |
| **Authenticode signed** | ✗ tooling ready, no certificate | ✓ ships in Windows | ✓ ships in Windows | ✓ signed product | ✓ signed product | ✓ signed products |
| **HLK certifiable** | ✗ software + unsigned | ✓ ships in Windows | ✓ ships in Windows | ✓ signed product | ✓ signed product | ✓ signed products |
| **Licence** | Open source | Bundled with Windows | Bundled with Windows | Commercial | Commercial | Commercial |

Legend: ✓ exposed · ◐ conditional or non-standard · ✗ not exposed through the KSP.

---

## Key sizes by algorithm

Where a provider accepts a range, the increment matters as much as the
bounds — a KSP advertising 512–16384 in 64-bit steps will reject 2056.

| Provider | RSA | ECDSA / ECDH curves | AES | Other |
|---|---|---|---|---|
| **This project** | 2048–16384, 64-bit increments (floor is a build-time constant) | P-256, P-384, P-521, secp256k1, brainpoolP256r1/384r1/512r1 (ECDSA); P-256/384/521 + X25519 (ECDH) | 128, 192, 256 | Ed25519 (255), Ed448 (448); HMAC ≥128, whole bytes; ML-DSA-44/65/87 (backend permitting) |
| MS Software KSP | 512 – 16384, 64-bit increments | P-256, P-384, P-521 | — | DH 512–4096, DSA 512–1024, ML-DSA-44/65/87 |
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
| RSA PSS | ✓ SHA-1/224/256/384/512 | ✓ expected | Salt length from `BCRYPT_PSS_PADDING_INFO` |
| ECDSA | ✓ raw r‖s output | ✓ universal | DER→r‖s conversion is the KSP's job |
| ML-DSA | ◐ raw signature, backend permitting | ✓ MS Software KSP | No padding; signature size fixed per parameter set |
| EdDSA | ◐ extension | ✗ none | CNG defines no EdDSA algorithm ID |
| HMAC | ◐ extension | ✗ none | CNG does HMAC through BCrypt flags |

### Decryption and key agreement

| Mode | This project | Others surveyed | Notes |
|---|---|---|---|
| RSA PKCS#1 decrypt | ✓ | ✓ expected | — |
| RSA OAEP decrypt | ✓ SHA-1/224/256/384/512 + label | ◐ hash range unconfirmed | Five hashes is broader than typical |
| ECDH agreement | ✓ P-256/384/521 + X25519, raw Z | ◐ Microsoft and Utimaco yes | — |
| Hash-based KDF | ✓ `BCRYPT_KDF_HASH` | Not established | Hash(prepend ‖ Z ‖ append) |
| HKDF (RFC 5869) | ✓ salt and info | Not established | — |
| HMAC KDF | ✓ incl. `KDF_USE_SECRET_AS_HMAC_KEY_FLAG` | Not established | — |
| TLS PRF | ◐ **TLS 1.2 only** | Not established | 1.0/1.1 refused deliberately — MD5/SHA-1 split PRF, deprecated by RFC 8996 |
| ML-KEM encapsulation | ✗ no function-table slot | ✓ BCrypt-side GA | See [finding 6](#finding-6--ml-kem-is-blocked-by-the-cng-interface-not-the-backend) |

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

This is the trap in reading HSM datasheets as KSP comparisons, and the 2026
post-quantum announcements make it worse, not better. Thales Luna ships
ML-DSA in firmware 7.9+; Entrust nShield ships it on XC, 5 and nSaaS. Both
are device claims. **Neither tells you whether their CNG provider exposes
the algorithm**, and that is the only thing a Windows application can use.
One of the reachable summaries puts it plainly: hardware-backed ML-DSA
"depends entirely on your HSM vendor's CNG provider exposing the algorithm".

Every grade-C cell in the table above exists because of this distinction —
including, now, the post-quantum rows.

### Finding 2 — Several of our extensions became standard-reachable; two did not

The first audit's central criticism was that `EDDSA_*`, `HMAC_*` and
`ECDSA_SECP256K1` are identifiers **this project invented**, so no stock
Windows application could ever ask for them.

Phase 2 fixed the curve half of that. The standard CNG route to any curve is
the generic `BCRYPT_ECDSA_ALGORITHM` or `BCRYPT_ECDH_ALGORITHM` plus
`BCRYPT_ECC_CURVE_NAME` before finalising, and the provider now implements
that property. secp256k1, all three Brainpool curves and X25519 are reachable
by a portable application that names nothing provider-specific.

EdDSA and HMAC are **not** fixed and cannot be, because CNG defines no
identifier for either. They remain private-interface features.

| Identifier | Standard CNG? |
|---|---|
| `RSA` | ✓ `BCRYPT_RSA_ALGORITHM` |
| `ECDSA_P256` / `_P384` / `_P521` | ✓ `BCRYPT_ECDSA_P*_ALGORITHM` |
| `ECDH_P256` / `_P384` / `_P521` | ✓ `BCRYPT_ECDH_P*_ALGORITHM` |
| generic `ECDSA` / `ECDH` + `ECCCurveName` | ✓ reaches secp256k1, Brainpool, X25519 |
| `AES` | ✓ `BCRYPT_AES_ALGORITHM` |
| `ChainingModeECB` / `CBC` / `GCM` | ✓ `BCRYPT_CHAIN_MODE_*` |
| `ChainingModeCTR` | ✗ our extension |
| `ECDSA_SECP256K1`, `ECDSA_BRAINPOOL*`, `ECDH_X25519` | ◐ our names, but the curves are reachable the standard way |
| `EDDSA_ED25519` / `EDDSA_ED448` | ✗ our extension — CNG has no EdDSA identifier |
| `HMAC_SHA1` / `_SHA224` / `_SHA256` / `_SHA384` / `_SHA512` | ✗ our extension |
| `ML-DSA-44` / `-65` / `-87` | ◐ our names; **CNG's own spelling could not be confirmed** — see finding 5 |

### Finding 3 — On the classical algorithms that matter, we are at or above parity

Strip out the extensions and compare only standard CNG surface. For RSA,
ECDSA and ECDH — the three families every surveyed provider ships — this
project now covers **more** than Microsoft's own Software KSP: the same NIST
curves, plus Brainpool, secp256k1 and X25519 through the standard curve-name
route, plus four KDFs on top of raw secret agreement.

Two caveats keep that honest. Microsoft also ships finite-field DH and DSA,
which this project refuses as out of scope and deprecated respectively — so
"more" means broader on the modern families, not a superset. And Microsoft
now ships ML-DSA, which this project cannot deliver; see finding 5.

Two places where the surface is genuinely broader than the field:

- **OAEP hash coverage.** Five hashes plus label support. No surveyed
  provider documents a range this wide, though absence of documentation is
  not evidence of absence.
- **AES through a KSP at all**, using standard `ChainingMode*` strings.

The RSA range runs from 2048 to 16384 bits in 64-bit steps, matching
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
algorithm coverage closes that gap.

The provider is at least honest about it: it reports
`NCRYPT_IMPL_SOFTWARE_FLAG`, which is what SoftHSM2 is. *The first audit
said the opposite — that the provider claimed hardware backing as a testing
convenience. That was wrong in an instructive way: the constant named
`NCRYPT_IMPL_HARDWARE_FLAG` in the test mock held `0x2`, which is the real
value of the SOFTWARE flag. The emitted byte never changed; only the name
became truthful.* See [13 — Roadmap](./13-roadmap.md), Phase 0.

Read the comparison accordingly: it is a fair map of the *interface*
surface, and says nothing about assurance. Where this project competes is
development, CI and integration testing — exercising a CNG KSP integration
without provisioning an HSM.

### Finding 5 — Post-quantum: the market moved, and we are on the wrong side of it

This is the significant change since the first audit, and the largest open
gap.

**Microsoft's own software KSP now signs with ML-DSA.** ML-KEM and ML-DSA
reached GA on Windows Server 2025 and Windows 11 24H2/25H2 in late 2025;
AD CS added ML-DSA certificate enrolment in May 2026 (KB5087539), and the
documented phase-1 path runs on the Microsoft Software KSP. A Windows PKI
can issue post-quantum certificates today, with no HSM (grade B).

**This project implements ML-DSA and cannot deliver it.** Roadmap phase 4
wired the mechanism through — resolution, `CKA_PARAMETER_SET` key
generation for all three parameter sets, signing — and gated it on a runtime
capability probe. SoftHSM2 2.7.0 defines `CKM_ML_DSA` in its bundled header
and implements it nowhere in `src/`, so the token never advertises it and
the provider never offers it. On a PKCS#11 v3.2 token that does implement it
— SoftHSMv3 and Kryoptic both claim the mechanisms — the same binary reaches
it with no rebuild.

Two things remain genuinely unresolved, and both are evidence problems
rather than engineering ones:

1. **CNG's own ML-DSA identifier could not be confirmed.** Microsoft Learn,
   Microsoft's community blog and every third-party analysis of it are
   blocked by this environment's egress policy. The names are absent from
   mingw-w64 (11 and master), from Wine's `bcrypt.h` and from the Rust
   winapi crate — all three checked, none carries a post-quantum name at
   all. Search summaries consistently show AD CS offering **ML-DSA-44,
   ML-DSA-65 and ML-DSA-87**, which happens to match the names this project
   chose; that is encouraging but it is a summary of a page nobody here has
   read, and it does not settle whether CNG treats those as three algorithm
   identifiers or as one algorithm with a parameter-set property. The
   project declares no `BCRYPT_*` PQC constant on that evidence.
2. **ML-DSA public key export is refused.** The CNG post-quantum key blob
   layout and magic live in a Windows SDK `bcrypt.h` not available here. A
   guessed blob would pass this project's own tests and fail on Windows —
   the `BCRYPT_SHA224_ALGORITHM` failure repeated exactly.

So the honest position: the KSP-side work is done and tested; the gap that
remains is a backend that implements the mechanism, and a Windows SDK header
to confirm the identifiers against. Neither is a code change here.

### Finding 6 — ML-KEM is blocked by the CNG interface, not the backend

Worth separating from ML-DSA, because the blocker is different in kind.

Encapsulation and decapsulation have **no slot** in the
`NCRYPT_KEY_STORAGE_FUNCTION_TABLE` this project builds against. A KSP can
hold an ML-KEM key and has no entry point through which any caller could use
it. That is not something a better backend fixes: the provider's capability
probe recognises `CKM_ML_KEM` on a token that implements it, and the
provider still advertises nothing, because advertising a key-encapsulation
algorithm no caller can reach would be worse than silence.

Whether a newer `ncrypt_provider.h` adds such slots cannot be determined
here — that header is not present in this workspace, which is the same
blocker as `BUILD-01`.

### Finding 7 — One capability no commercial provider has

Every commercial KSP in this table is bound to one vendor's hardware. The
algorithm list is fixed at build time because the device behind it is fixed.

This project is not. `KSP_PKCS11_LIB` points at any PKCS#11 v2.40+ module,
and since phase 4 the provider **asks the token what it implements** through
`C_GetMechanismList` at startup, advertising the intersection of that and
what it can map. A token that can generate EC keys but not derive from them
gets ECDSA advertised and ECDH withheld.

Before that probe existed, this was a latent defect rather than a feature:
the provider advertised a fixed list describing SoftHSM2 and would claim
AES, ECDH and P-521 on a token that had none of them, with the lie surfacing
only at key generation.

It is now the one row in the comparison where this project offers something
the commercial field structurally cannot — and it is also the mechanism by
which the post-quantum gap in finding 5 closes, since a v3.2 token becomes a
configuration change rather than a port.

---

## What could not be verified

Recorded so the gaps are visible rather than silently absent.

| Subject | Why it is missing |
|---------|-------------------|
| Microsoft primary sources | `learn.microsoft.com` and `techcommunity.microsoft.com` are both blocked by this environment's egress proxy. Every Microsoft figure here, including the entire post-quantum finding, comes from search summaries rather than the pages themselves. |
| CNG's ML-DSA algorithm identifier | Blocked at every source tried — Microsoft's own pages, third-party analyses, and vendor application notes. Absent from mingw-w64, Wine and the Rust winapi crate. |
| Whether vendor CNG providers expose ML-DSA | Thales (Luna firmware 7.9+) and Entrust (nShield XC / 5 / nSaaS) both ship ML-DSA **in the device**. No source reachable here states what their CNG KSP advertises. |
| Thales Luna KSP | `thalesdocs.com` unreachable. Device-level PQC and NIST algorithm claims found; no CNG-specific algorithm or key-size table obtained. |
| Entrust nShield CNG | `nshielddocs.entrust.com` unreachable. Device supports Ed25519, X25519 and now ML-DSA per datasheet; CNG exposure unconfirmed. |
| Securosys Primus CNG | Algorithm table lives in a support-portal PDF. Only RSA-4096 and AES-256 for SQL Always Encrypted were confirmed. |
| Smart card KSP, YubiHSM, Azure Managed HSM | Not surveyed. The Microsoft Smart Card KSP is now interesting — one reachable summary mentions creating an ML-DSA CA against it — and would need the same treatment before appearing here. |
| Mode-level detail elsewhere | No surveyed vendor documented OAEP hash coverage, PSS salt handling or KDF support at the CNG level. Those comparison rows are one-sided. |

---

## What changed since the first audit

The first audit was run before roadmap phases 0–4. Both columns moved.

**This project's column was stale in nine places**, all now corrected:

| Row | Was | Is |
|---|---|---|
| RSA sizes | 2048 / 3072 / 4096 only | 2048–16384, 64-bit steps |
| ECDSA curves | NIST only | plus secp256k1 and three Brainpool curves |
| ECDH curves | NIST only | plus X25519 |
| Curve selection | provider-specific names only | standard `BCRYPT_ECC_CURVE_NAME` route |
| KDF | `NTE_NOT_SUPPORTED` | HASH, HKDF, HMAC, TLS 1.2 PRF |
| PSS hashes | SHA-1/256/384/512 | plus SHA-224 |
| Post-quantum | not covered | implemented, gated on the backend |
| Impl type | *stated* as a false hardware claim | reports `NCRYPT_IMPL_SOFTWARE_FLAG`; the original criticism was itself wrong |
| Backend | implicitly SoftHSM2 | any PKCS#11 module, with runtime capability discovery |

**The market moved once, decisively**: post-quantum signing went from a
Thales datasheet claim to a shipping Microsoft KSP feature with AD CS
enrolment behind it.

**Finding 5 of the first audit is retired.** It tracked ten small feature-matrix
gaps and the `TABLE-01` function-table defect it uncovered. All of that was
resolved in phases 0–2 and is recorded in [13 — Roadmap](./13-roadmap.md);
repeating it here would be duplicate bookkeeping.

---

## Method

This project's column was read from its own source — `config.h`,
`ksp_key.c`, `ksp_crypto.c`, `ksp_properties.c`, `ksp_provider.c`,
`p11_caps.c` — and is grade A throughout.

Every other column came from web search summaries. On this refresh, **every
direct page fetch attempted was refused by the egress proxy** — Microsoft,
vendor and third-party alike — so no primary source was read in full.
Nothing in the vendor columns was inferred from the shape of a competitor's
offering.

To refresh this audit, re-check each source below from an environment
without the egress restriction, and re-grade any cell whose evidence
improves. The two worth the most are the CNG ML-DSA identifier and whether
any vendor CNG provider exposes it.

### Sources

1. [Microsoft — CNG Key Storage Providers](https://learn.microsoft.com/en-us/windows/desktop/SecCertEnroll/cng-key-storage-providers)
2. [AWS CloudHSM — NCryptIsAlgSupported with KSP](https://docs.aws.amazon.com/cloudhsm/latest/userguide/ksp-library-apis-is-alg-supported.html)
3. [Utimaco — CryptoServer SDK data sheet](https://support.hsm.utimaco.com/documents/20182/82257/CryptoServer+SDK+-+EN)
4. [Microsoft — CNG named elliptic curves](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-named-elliptic-curves)
5. [Gradenegger — EC keys with the Platform Crypto Provider](https://www.gradenegger.eu/en/certificate-requests-with-elliptic-curve-based-keys-will-fail-when-using-the-microsoft-platform-crypto-provider/)
6. Post-quantum, all cited from search summaries — pages not reachable:
   [Microsoft — PQC APIs generally available](https://techcommunity.microsoft.com/blog/microsoft-security-blog/post-quantum-cryptography-apis-now-generally-available-on-microsoft-platforms/4469093) ·
   [Microsoft — Configure a CA to use ML-DSA](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-ml-dsa-certification-authority) ·
   [Microsoft — PQC in AD CS overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/post-quantum-cryptography-overview) ·
   [Thales — Luna post-quantum algorithms](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/extensions/pqc/post_quantum_algorithms.htm) ·
   [Entrust — NIST-approved PQC in future-ready HSMs](https://www.entrust.com/blog/2025/05/provide-nist-approved-post-quantum-algorithms-in-future-ready-hsms)
7. Vendor CNG pages, still unreachable:
   [Thales — Luna KSP for CNG](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/microsoft/ksp_cng.htm) ·
   [Entrust — nShield cryptographic algorithms](https://nshielddocs.entrust.com/security-world-docs/v13.3/solo-ug-win/crypto-algorithms.html) ·
   [Securosys — Primus CNG/KSP](https://docs.securosys.com/mscng/overview/)

---

## See also

- [00 — Documentation index](./00-index.md)
- [04 — Cryptographic operations](./04-crypto-operations.md) — the mechanism mapping behind this project's column
- [12 — PKCS#11 backend requirements](./12-pkcs11-requirements.md) — what a replacement token must implement, including the v3.2 post-quantum tier
- [13 — Roadmap](./13-roadmap.md) — the phased plan, and what each phase settled
- [10 — Running the Microsoft HLK tests](./10-hlk-execution.md) — why this KSP is not certifiable
- [`feature-matrix.csv`](./feature-matrix.csv) — the row-by-row gap analysis behind this comparison
