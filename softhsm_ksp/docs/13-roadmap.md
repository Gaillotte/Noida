# 13 — Roadmap to market parity

What it would take for this project to stand alongside the commercial CNG
Key Storage Providers surveyed in
[11 — CNG KSP market comparison](./11-market-comparison.md), and in what
order the work has to happen.

*Written: September 2026. **Phases 0, 1 and 2 are done**; Phase 3 is tooled
as far as it can be here — see §3 for what each changed and what it could
not settle. Complements the gap analysis
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

*This section records the state that prompted the roadmap, before Phase 0.
For what it looks like now, see Phase 0 in §3.*

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

There was also **no CI configuration anywhere in the repository**, so
nothing had ever been enforcing this. Phase 0 added
`.github/workflows/ksp-ci.yml`; all three jobs are green.

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

- **MSVC compiles nine of the ten source files clean, at `/W3 /WX`.** No
  errors and no warnings, and `test_p11_layer.exe` linked. That is the first
  time any of this code has been built by the compiler it targets.
- **`ncrypt_provider.h` is not in the Windows SDK, and the WDK does not
  supply it.** A recursive search of the Windows Kits on a clean
  `windows-latest` runner found nothing, before or after a WDK install that
  Chocolatey reported as successful. Where the header *does* come from is
  still unestablished — two guesses (the WDK, then a CPDK directory beside
  the SDK) were both wrong, so the build now takes `-DCPDK_INCLUDE_DIR` to
  be pointed at it, and a whole-disk search in CI is recording the answer
  rather than a third guess. The prerequisite is now in `README.md` and
  `CLAUDE.md`; it had never been written down at all.
- **The runner has Visual Studio 18 (2026), MSVC 19.51.** Which is why the
  pinned "Visual Studio 17 2022" generator failed.
- **`windows-latest` has moved past Visual Studio 2022.** The pinned
  generator failed with "could not find any instance of Visual Studio". The
  `-G` flag is gone from CI and from both build guides; CMake picks whatever
  is installed.

The Linux job — unit suite, mock-drift check and the nine-file
cross-compile — passed on that same first run, as did the PowerShell job.

**Settled by the fifth run: the header is not obtainable in hosted CI.**
A `dir /s /b` across both drives of a `windows-latest` runner returned
exactly one `ncrypt_provider.h` — this repository's own test mock — and that
was *after* `choco install windowsdriverkit11` reported success. No
`bcrypt_provider.h` either. The WDK step has been removed from CI: it cost
three minutes a run and never supplied the header.

CI therefore builds what MSVC can build. When the header is absent CMake
skips the `softhsm_ksp` target instead of emitting a DLL without its entry
point, and the job posts a warning so a green run is never mistaken for a
built DLL.

**Still unsettled, and now bounded.** That the complete DLL builds and loads
under `NCryptOpenStorageProvider`. This needs a machine that has
`ncrypt_provider.h` — a self-hosted runner, or a one-off developer build.
`BUILD-01` and `TABLE-01` stay **Partial**.

The alternative, vendoring a hand-written declaration of the table, is
deliberately **not** taken. It would reintroduce exactly the failure this
phase existed to remove: a layout nobody can verify, failing silently by
calling the wrong function pointer.

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

### Phase 1 — Interface parity ✅ done

The table-stakes items every commercial provider has. `LIFE-06` and
`LIFE-07` were on this list and closed in Phase 0.

| Item | Result |
|------|--------|
| `OPS-04` — multiple slots / tokens | **Covered** — `SOFTHSM2_TOKEN_LABEL` or `SOFTHSM2_SLOT`; an unmatched selection is an error, never a fallback |
| `OPS-09` — session recovery | **Covered** — `C_GetSessionInfo` validates a pooled session before reuse |
| `IFACE-04` — `SetProviderProperty` | Partial — `NCRYPT_PIN_PROPERTY` works; token selection is read-only by design |
| `FMT-08` — `BCRYPT_KEY_DATA_BLOB` | Partial — import works; export refused because every key is `CKA_EXTRACTABLE=FALSE` |
| `LIFE-08` — machine vs user scope | Partial — `CKA_LABEL` prefixes give namespacing, **not isolation** |

Each Partial is a deliberate stopping point, not unfinished work, and the
matrix records the reason on the row rather than implying a remedy exists.

`p11_session.c` had no tests at all before this phase — it was in no suite,
so none of its code appeared in the coverage report, despite holding the
token credential and every session the provider uses. It is now covered by
`test_p11_session.c`.

### Phase 2 — Standard-CNG reach ✅ done

| Item | Result |
|------|--------|
| `ECDH-04` — `BCRYPT_KDF_HASH` | **Covered** |
| `ECDH-05` — HKDF, HMAC, TLS PRF | **Covered** |
| `EDDSA-03` — X25519 key agreement | **Covered** |
| `ECDSA-04` — Brainpool P256r1/P384r1/P512r1 | **Covered** |
| `ECDSA-05` — secp256k1 | **Covered** |

**Key derivation is complete.** Every CNG KDF: the raw secret,
`BCRYPT_KDF_HASH`, `BCRYPT_KDF_HKDF`, `BCRYPT_KDF_HMAC` (including
`KDF_USE_SECRET_AS_HMAC_KEY_FLAG`) and `BCRYPT_KDF_TLS_PRF` for TLS 1.2.
TLS 1.0 and 1.1 are refused deliberately: their PRF is the MD5/SHA-1 split
construction and both versions are deprecated by RFC 8996.

**Every curve is reachable the standard CNG way.** A key created with the
generic `BCRYPT_ECDSA_ALGORITHM` or `BCRYPT_ECDH_ALGORITHM` takes its curve
from `BCRYPT_ECC_CURVE_NAME` before finalising — the route a portable
application uses, naming nothing provider-specific:

```c
NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_ECDSA_ALGORITHM, ...);
NCryptSetProperty(hKey, BCRYPT_ECC_CURVE_NAME,
                  (PBYTE)BCRYPT_ECC_CURVE_BRAINPOOLP384R1, ..., 0);
NCryptFinalizeKey(hKey, 0);
```

Resolving the name rewrites the key's algorithm to this provider's specific
identifier, after which generation, OID lookup, coordinate size and
signature length all work unchanged. A curve that cannot do what the chosen
generic algorithm asks is refused rather than reinterpreted: X25519 cannot
sign, and no ECDH form of secp256k1 or Brainpool is wired here.

#### A blocker I declared too early

This route was reported as blocked because none of `BCRYPT_ECDSA_ALGORITHM`,
`BCRYPT_ECDH_ALGORITHM`, `BCRYPT_ECC_CURVE_NAME` or the `BCRYPT_ECC_CURVE_*`
values appears in mingw-w64, in 11 or master. That was true, and the
conclusion drawn from it — that the values could not be established here —
was wrong. **One header set is not the same as every available source.**

Two independent sources have them and agree exactly: Wine's
`include/bcrypt.h` and the Rust `winapi` crate's `shared/bcrypt.rs`. The
crate had already been downloaded, for an unrelated search, before the
blocker was declared.

The values are defined in `config.h` behind `#ifndef`, so a real SDK wins
wherever it has them, and curve names are compared case-insensitively —
which matters, because CNG spells one of them `secP256k1` and a guess would
have used a lowercase `p`.

The caution that produced the wrong call was itself sound: this project has
shipped invented constants before, and `BCRYPT_SHA224_ALGORITHM` really did
break the Windows build. The error was stopping at "I cannot verify this"
without exhausting what was to hand.

### Phase 3 — Assurance ⚠️ tooled, not achievable here

Neither item can be **completed** in this repository, and saying so plainly
matters more than showing progress. What could be built has been.

**`OPS-03` — Authenticode signing. Tooling complete and proven; certificate
missing.**

`tools/sign_ksp.ps1` signs, timestamps and verifies in one checked step,
taking a certificate from the Windows store, a PFX (password from the
environment, never a parameter) or Azure Trusted Signing. The CI `windows`
job signs automatically the moment a `KSP_SIGN_PFX_BASE64` secret exists,
and reports the signature state on every run either way, so "unsigned" is
visible rather than assumed. `*.pfx` is in `.gitignore`: a certificate
committed by accident is a certificate that must be revoked.

The tooling is **exercised, not merely written**. A CI step generates a
throwaway self-signed certificate, trusts it on the runner, and runs
`sign_ksp.ps1` against `test_p11_layer.exe` — sign, timestamp, verify, and
the verification parsing that decides whether a timestamp was applied. That
proves the pipeline; it does not produce a distributable signature, and the
artefact stays unsigned. A script that only parses is how this project got
`BCRYPT_SHA224_ALGORITHM`.

What remains is **not engineering**. An OV or EV code-signing certificate
must be bought by a verified legal entity — a registered company whose
registration, address and telephone a CA can check independently. Nothing
in this repository can supply that, so the row stays **Not covered**. The
binary is unsigned, and calling the gap closed because the tooling exists
would be the same error as calling it closed because a plan exists.

**Running the HLK suite. Blocked, and behind two other things.**

The ~150-test PowerShell suite is written and its embedded C# is validated
on every CI run, but it has never executed against a real build. It cannot
be, in order:

1. `BUILD-01` — the DLL does not build in CI, for want of
   `ncrypt_provider.h`. Unlike the `BCRYPT_ECC_CURVE_*` names, which Wine
   and the Rust `winapi` crate both carry, this header is reachable from no
   source available here: Wine, ReactOS and `winapi` all implement the
   *consumer* side of CNG and have no need of the provider function table.
   Checked, not assumed.
2. `OPS-03` — a provider must be signed to be loaded and exercised
   meaningfully.
3. A Windows machine with the HLK controller installed.

Each is a prerequisite for the next, so this is the last thing in the
project to become possible, not something to attempt earlier.

**What Phase 3 cannot change at all.** `OPS-01` (hardware key protection)
and `OPS-02` (FIPS validation) are graded N/A because they are properties
of the *backend*, not this KSP. A software token storing keys in an
encrypted SQLite file cannot be made tamper-resistant by any amount of work
here. The PKCS#11 abstraction already allows pointing the provider at a
real HSM, and that — not code in this repository — is what would close
them.

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
