# 13 — Roadmap to market parity

What it would take for this project to stand alongside the commercial CNG
Key Storage Providers surveyed in
[11 — CNG KSP market comparison](./11-market-comparison.md), and in what
order the work has to happen.

*Written: September 2026. **Phase 0 is done** — see §3 for what that changed
and what it could not settle. Complements the gap analysis
in [`feature-matrix.csv`](./feature-matrix.csv) and
[`SoftHSM2_KSP_Feature_Matrix.pdf`](../SoftHSM2_KSP_Feature_Matrix.pdf).*

---

## Headline

**The DLL had never been compiled for Windows.**

Everything else in this document is downstream of that. Phase 0 has since
fixed all six root causes: nine of the ten source files now cross-compile
clean, and CI enforces it. The tenth, `ksp_main.c`, needs a header that
only Windows has — the CI `windows` job is what will confirm it. The feature matrix
records 49 of 99 capabilities as covered, and 780 unit assertions pass at
89.8 % line coverage — but all of it is measured on Linux, against a
hand-written stand-in for the Windows headers. On the platform the product
actually targets, nothing has been demonstrated to work at all.

That is the real distance between this project and a shipping provider. It
is not a matter of missing algorithms; by algorithm count this project
already exceeds every provider in the audit.

---

## 1. Evidence

### 1.1 The build

A cross-compile with `mingw-w64` fails on **7 of the 10 source files**:

```bash
sudo apt-get install -y gcc-mingw-w64-x86-64
cd softhsm_ksp
for f in src/pkcs11/*.c src/ksp/*.c src/common/*.c; do
  x86_64-w64-mingw32-gcc -c -municode -DUNICODE -D_UNICODE \
      -DWIN32_LEAN_AND_MEAN \
      -Isrc/pkcs11 -Isrc/ksp -Isrc/common "$f" -o /dev/null \
    || echo "FAILED: $f"
done
```

| Result | Files |
|--------|-------|
| Compiles | `ksp_provider.c`, `logging.c`, `memory.c` |
| Fails | `p11_context.c`, `p11_session.c`, `p11_utils.c`, `ksp_main.c`, `ksp_key.c`, `ksp_crypto.c`, `ksp_properties.c` |

There is also **no CI configuration anywhere in the repository**, so nothing
has ever been enforcing this.

`mingw-w64` is a good proxy but not an authority: it lags the Windows SDK
(it lacks `BCRYPT_ECC_CURVE_NAME` and the Brainpool/secp256k1 curve
constants, which real Windows 10+ has). Every defect below was confirmed
against the real headers or is a header that genuinely does not exist.

### 1.2 The defects behind it

| # | Defect | Consequence | Why no test catches it |
|---|--------|-------------|------------------------|
| 1 | `NCRYPT_KEY_STORAGE_FUNCTION_TABLE` is not declared by `<ncrypt.h>`. It lives in the WDK's `ncrypt_provider.h` | `ksp_main.c` and `ksp_main.h` cannot compile | The mock declares its own struct |
| 2 | `BCRYPT_SHA224_ALGORITHM` **does not exist in CNG** — Windows has no SHA-224 algorithm identifier | `p11_utils.c` and `ksp_crypto.c` cannot compile | The mock invents it |
| 3 | `NTE_KEY_DOES_NOT_EXIST` is not a Windows constant either, and the mock gives it `0x80090026` — the real value of `NTE_INVALID_HANDLE` | `ksp_crypto.c` cannot compile (3 call sites) | The mock aliases the two to one number, so the assertions cannot tell them apart |
| 4 | `NCRYPT_IMPL_HARDWARE_FLAG` is `0x1`. We use `0x2`, which is `NCRYPT_IMPL_SOFTWARE_FLAG` | `GetProviderProperty` reports the opposite of what the code intends | Mock has the wrong value; the test asserts the same wrong value |
| 5 | `NTE_BAD_KEYSET_PARAM` is `0x8009001F`. We use `0x8009001E` | Wrong error code returned to callers | As above |
| 6 | `SECURITY_STATUS` and `AT_SIGNATURE` / `AT_KEYEXCHANGE` are used without including `<ncrypt.h>` / `<wincrypt.h>`; `WIN32_LEAN_AND_MEAN` excludes the latter | Several headers cannot compile standalone | The mock defines them unconditionally |

Defect 4 is quietly the most interesting: the provider means to claim
hardware backing and in fact reports *software*. That happens to be the more
honest answer — see [10 — Running the HLK tests](./10-hlk-execution.md) —
but it is an accident, not a decision.

### 1.3 How far the mock has drifted — and how far it has not

Of the 110 `NCRYPT_*` / `BCRYPT_*` / `NTE_*` macros
`tests/mock/windows_compat.h` defines, **108 match the real Windows headers
exactly**. Two carry wrong values (defects 4 and 5) and two name constants
that do not exist (defects 2 and 3).

This is the encouraging half of the finding. The mock is not systemically
fictional; it is a faithful copy with a handful of transcription errors and
three inventions. Phase 0 is therefore a correction, not a rewrite.

The structural problem is narrower and sharper: **the mock is maintained by
hand, in the same commits as the code that consumes it.** Nothing forces it
to agree with Windows, so any future divergence will again pass 780 tests.

---

## 2. What "market parity" can and cannot mean

Every commercial provider in the audit is a certified product over
tamper-resistant hardware — FIPS 140-3, Common Criteria, a vendor with
liability. A software token keeping keys in an encrypted SQLite file cannot
reach that at any level of effort. Treating that as the target is a category
error, and no amount of work in this repository changes it.

Two targets *are* reachable, and both are worth having:

1. **Full CNG interface parity.** No surveyed provider exceeds RSA + ECDSA +
   ECDH. The interface surface — not the algorithm list — is where this
   project is genuinely behind, and it is a finite amount of work.
2. **The best CNG KSP for development, CI and integration testing.** Here
   the commercial products are *unusable*, because they require an HSM.
   Nobody occupies this position today.

The roadmap below is ordered for those two targets.

---

## 3. Phases

### Phase 0 — Make it real ✅ done

**Blocked every other phase. Completed September 2026.**

| Done | Detail |
|------|--------|
| Defects 1–6 fixed | See the table below for each |
| Function table by name | Designated initialisers; the SDK header assigns the slots |
| `IsAlgSupported`, `EnumAlgorithms` | Implemented — closes `LIFE-06` and `LIFE-07` |
| `VerifySignature` | Stub returning `NTE_NOT_SUPPORTED`; the slot is no longer absent |
| SHA-224 | Kept, as the provider extension `KSP_SHA224_ALGORITHM` |
| Mock drift guard | `tests/check_mock_drift.py`, run in CI |
| CI | `.github/workflows/ksp-ci.yml` — three jobs |

| Defect | Fix |
|--------|-----|
| 1 `NCRYPT_KEY_STORAGE_FUNCTION_TABLE` | `ksp_main.h` includes `<ncrypt_provider.h>`; table uses designated initialisers |
| 2 `BCRYPT_SHA224_ALGORITHM` | Replaced by `KSP_SHA224_ALGORITHM` in `config.h`, documented as non-CNG |
| 3 `NTE_KEY_DOES_NOT_EXIST` | Replaced by `NTE_INVALID_HANDLE` — the same value the mock was aliasing |
| 4 `NCRYPT_IMPL_HARDWARE_FLAG` | Corrected to `0x1`; the provider now reports `NCRYPT_IMPL_SOFTWARE_FLAG`, which is both truthful and the same value it always emitted |
| 5 `NTE_BAD_KEYSET_PARAM` | Corrected to `0x8009001F` |
| 6 Missing includes | New `src/common/ksp_windows.h` holds the include policy; every header uses it |

Unit tests went 780 → **903 assertions** across 14 → **15 suites**, coverage
89.8 % → **90.2 %** lines at 100 % functions. The new suite,
`test_function_table.c`, covers `ksp_main.c` — which nothing had ever
compiled, on any platform.

**What the first CI run settled.** Two things, both previously unknown:

- **`ncrypt_provider.h` is not in the Windows SDK.** A recursive search of
  the Windows Kits on a clean `windows-latest` runner found nothing. It
  ships with the **WDK**, so building a CNG provider requires the WDK — a
  genuine prerequisite this project had never documented. Now recorded in
  `README.md` and `CLAUDE.md`, and installed by the CI `windows` job.
- **`windows-latest` has moved past Visual Studio 2022.** The pinned
  generator failed with "could not find any instance of Visual Studio". The
  `-G` flag is gone from CI and from both build guides; CMake picks whatever
  is installed.

The Linux job — unit suite, mock-drift check and the nine-file
cross-compile — passed on that same first run, as did the PowerShell job.

**Still unsettled.** That the complete DLL builds under MSVC and loads under
`NCryptOpenStorageProvider`. `BUILD-01` and `TABLE-01` stay **Partial**
until a `windows` job goes green.

What the phase originally called for:

- Fix defects 1–6 from §1.2.
- Build `ksp_main.c` against the real `ncrypt_provider.h` and let the
  compiler assign the function-table slots by name. This is `TABLE-01`, and
  it is the one that matters: the current table omits `IsAlgSupported`,
  `EnumAlgorithms` and `VerifySignature` and adds `GetOperationProperty` and
  `FreeObject`, which are not KSP entry points, so the slots are displaced
  from the thirteenth onward. On Windows this does not fail cleanly — it
  calls the wrong function pointers.
- Decide SHA-224's fate. CNG has no identifier for it, so the current PSS,
  OAEP and HMAC SHA-224 support is unreachable from any standard caller.
  Either drop it or relabel it as a documented non-CNG extension.
- **Generate `windows_compat.h` from the SDK headers** instead of hand-
  maintaining it, so defects 2–5 cannot recur.
- **Add CI**: `windows-latest` + MSVC for the authoritative build, plus the
  `mingw-w64` cross-compile on Linux as a fast pre-check, plus the existing
  unit suite. No CI exists today.

Correcting the function table closes `LIFE-06` and `LIFE-07` as a side
effect — both are slots in it, not registry lookups as the matrix
originally claimed.

**Exit criterion:** `softhsm_ksp.dll` builds clean at `/W3 /WX`, loads under
`NCryptOpenStorageProvider`, and CI enforces both. The first two remain
unproven until the CI `windows` job has run; the third is in place.

### Phase 1 — Interface parity

The table-stakes items every commercial provider has and this one does not.
`LIFE-06` and `LIFE-07` were on this list and closed in Phase 0.

| ID | Item | Note |
|----|------|------|
| `LIFE-08` | Machine vs user key scope | All providers |
| `OPS-04` | Multiple slots / tokens | All commercial providers; today only the first token-present slot is used |
| `OPS-09` | PIN caching / re-login | All commercial providers |
| `FMT-08` | `BCRYPT_KEY_DATA_BLOB` | Microsoft Software KSP |
| `IFACE-04` | `SetProviderProperty` | Currently stubbed `NTE_NOT_SUPPORTED` |

### Phase 2 — Standard-CNG reach

Converting invented identifiers into ones real callers can reach, highest
value first.

- **`EDDSA-03` — X25519 key agreement.** The single highest-value gap in the
  matrix. Unlike Ed25519 *signing*, X25519 **is** a standard CNG curve, so
  this is reachable by ordinary applications.
- **`ECDSA-05` — secp256k1 the standard way.** It works today only through
  this project's own `ECDSA_SECP256K1` identifier. The standard route is the
  generic ECDSA algorithm with `BCRYPT_ECC_CURVE_NAME` set to
  `BCRYPT_ECC_CURVE_SECP256K1`.
- **`ECDSA-04` — Brainpool curves**, same mechanism.
- **`ECDH-04` / `ECDH-05` — the ECDH KDFs** (`BCRYPT_KDF_HASH`,
  `BCRYPT_KDF_HMAC`, `TLS_PRF`, `HKDF`). The Microsoft Software KSP supports
  these; today all hash KDFs return `NTE_NOT_SUPPORTED`.

This phase should also settle the standing question about how
`EDDSA_ED25519`, `EDDSA_ED448` and `HMAC_SHA*` are described. They are
private extensions no standard CNG caller can reach, and `README.md` and
`SoftHSM2_KSP_Algorithm_Reference.docx` still present them as plain
algorithm support. Convert what is convertible; relabel the rest.

### Phase 3 — Assurance

- **`OPS-03` — Authenticode signing.** Not a code change: it needs a
  purchased code-signing certificate and a legal entity. Microsoft does not
  sign cryptographic providers — see
  [10 — Running the HLK tests](./10-hlk-execution.md).
- **Actually execute the HLK suite.** The ~150-test PowerShell suite is
  written and its C# validated, but it has never been run against a real
  build, for the reason in §1.

### Phase 4 — Post-quantum, and the backend question

PQC is the genuine "top line" in 2026: Windows CNG now ships ML-DSA and
ML-KEM, and Thales Luna claims them at the device level (`PQC-01`,
`PQC-02`, `PQC-03`).

**This is blocked by the backend, not by the KSP.** SoftHSM2 2.7.0 carries
`CKM_ML_KEM_KEY_PAIR_GEN`, `CKM_ML_KEM`, `CKM_ML_DSA_KEY_PAIR_GEN` and
`CKM_ML_DSA` **as constants in `pkcs11.h` with no implementation anywhere in
`src/`**. No amount of KSP work reaches them.

Two options, and this is a strategic decision rather than a coding task:

| Option | Cost | Consequence |
|--------|------|-------------|
| Patch SoftHSM2 to implement the PQC mechanisms | Large; a cryptographic implementation in a fork | Keeps one backend, but the fork must be maintained |
| Support a second PKCS#11 v3.1 backend alongside SoftHSM2 | Moderate; the KSP already isolates the backend behind `p11_*` | Needs `OPS-04` (multi-token) from Phase 1 first |

The second is better aligned with the existing architecture, and
[12 — PKCS#11 backend requirements](./12-pkcs11-requirements.md) already
documents the contract a replacement token must satisfy.

---

## 4. Sequencing

```
Phase 0  Make it real ─────────────────┐  blocks everything
                                       │
         ┌─────────────────────────────┼─────────────────┐
         ▼                             ▼                 ▼
Phase 1  Interface parity     Phase 2  Standard-CNG   Phase 3  Assurance
         │                             reach             (OPS-03 needs a
         │                                                legal entity)
         └──────────► Phase 4  PQC (needs OPS-04, and a backend decision)
```

Phases 1 and 2 are independent of each other and can run in parallel.
Phase 3's Authenticode item is procurement, not engineering, and can start
at any time. Phase 4 depends on Phase 1's multi-token work.

---

## 5. What cannot be verified from this repository

Recorded so the limits of the analysis are visible.

| Subject | Why |
|---------|-----|
| That the corrected build is MSVC-clean at `/W3 /WX` | No Windows machine and no MSVC here; `mingw-w64` is a proxy that lags the SDK |
| That the DLL loads and serves `NCryptOpenStorageProvider` | Needs Windows |
| The exact slot order of `NCRYPT_KEY_STORAGE_FUNCTION_TABLE` | `ncrypt_provider.h` ships with the WDK and is not present here; the defect is proven by the struct's absence from `<ncrypt.h>`, not by a diff against it |
| Whether `NTE_KEY_DOES_NOT_EXIST` exists in some SDK version | Absent from `mingw-w64` entirely; treated as non-existent |
| Any HLK result | Requires a signed build on certified hardware |

Both of the first two are answered the moment CI exists, which is why it is
in Phase 0 rather than treated as tooling polish.
