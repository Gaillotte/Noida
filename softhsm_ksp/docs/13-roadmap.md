# 13 — Roadmap to market parity

What it would take for this project to stand alongside the commercial CNG
Key Storage Providers surveyed in
[11 — CNG KSP market comparison](./11-market-comparison.md), and in what
order the work has to happen.

*Written: September 2026. **Phases 0, 1, 2, 4, 5 and 7 step 1 are done**;
Phase 3 is tooled as far as it can be here — see §3 for what each changed and what it
could not settle. Complements the gap analysis
in [`feature-matrix.csv`](./feature-matrix.csv) and
[`SoftHSM2_KSP_Feature_Matrix.pdf`](../SoftHSM2_KSP_Feature_Matrix.pdf).*

---

## Headline

**The DLL had never been compiled for Windows.**

Everything else in this document is downstream of that. Phase 0 has since
fixed all six root causes: nine of the ten source files now cross-compile
clean, and CI enforces it. The tenth, `ksp_main.c`, needs a header that
only Windows has — the CI `windows` job is what will confirm it. The feature
matrix now records 65 of 101 capabilities as covered, and 1434 unit
assertions pass at 88.5 % line coverage — but all of it is measured on
Linux, against a hand-written stand-in for the Windows headers. On the
platform the product actually targets, nothing has been demonstrated to
work at all.

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

### Phase 4 — Post-quantum, and the backend question — **done, with one
half deliberately left closed**

PQC is the genuine "top line" in 2026: Windows CNG now ships ML-DSA and
ML-KEM, and Thales Luna claims them at the device level (`PQC-01`,
`PQC-02`, `PQC-03`).

The earlier framing of this phase was a strategic choice between forking
SoftHSM2 and adopting a second backend. **That framing was wrong, and
recognising why is most of the phase.** The KSP has always loaded whatever
PKCS#11 module a path points at — but it then advertised a fixed list of
algorithms compiled into the DLL, describing SoftHSM2 2.7.0 and nothing
else. So "support a second backend" was never a porting job. It was a
correctness bug: point the provider at a different module and it would
still claim AES, ECDH and P-521 whether or not the token had them, and the
claim would only come apart at key generation, long after the application
had committed to the algorithm on the provider's word.

#### What changed

**The provider now asks the token.** `src/pkcs11/p11_caps.c` calls
`C_GetMechanismList` and `C_GetInfo` once at initialisation.
`NCryptEnumAlgorithms` and `NCryptIsAlgSupported` answer from the
intersection of what the KSP can map and what the token implements.
Generation and use are checked separately, so a token with
`CKM_EC_KEY_PAIR_GEN` but no `CKM_ECDH1_DERIVE` advertises ECDSA and not
ECDH.

A token that refuses `C_GetMechanismList` loses nothing: with no probe,
`P11_HasMechanism` answers permissively and the provider behaves exactly as
it did before. A token reporting an implausible mechanism count abandons
the probe rather than truncating it — half a capability view would make the
provider refuse algorithms the token really has, which is worse than no
view at all.

**`KSP_PKCS11_LIB`** replaces `SOFTHSM2_LIB` as the name for the module
path. `SOFTHSM2_LIB` still works. Nothing in the provider is
SoftHSM2-specific; the old name made a general mechanism look like a debug
hook for one backend.

**ML-DSA is wired through**, gated on the probe: mechanism resolution,
`CKA_PARAMETER_SET` key generation for all three parameter sets, and
signing. Signing needed no new code — ML-DSA signatures are raw, like
EdDSA's, so the existing non-ECDSA path carries them unchanged.

On SoftHSM2 2.7.0 none of it is reachable, and that is asserted rather than
assumed: the mechanisms appear in its header and in none of its `src/`, so
the token never lists them and the provider never offers them. On a
PKCS#11 v3.2 token that does implement them, the same binary reaches them
with no rebuild. `tests/unit/test_mldsa.c` drives both directions — a gate
that never opens and a gate that never closes both pass a one-sided test.

#### ML-KEM: recognised, deliberately not offered

ML-KEM is **not** blocked by the backend. It is blocked by the CNG
interface this project builds against.

Encapsulation and decapsulation have no slot in the
`NCRYPT_KEY_STORAGE_FUNCTION_TABLE` this provider implements. A KSP can
hold an ML-KEM key and has no entry point through which anyone could use
it. Whether a newer `ncrypt_provider.h` adds such slots cannot be
determined here — that header is not available in this workspace, which is
the same blocker as `BUILD-01`.

So the provider recognises `CKM_ML_KEM` during the probe and offers no
ML-KEM algorithm. Advertising a key-encapsulation algorithm a caller
cannot then use would be worse than silence.

#### What this leaves

| Item | State |
|------|-------|
| ML-DSA through a v3.2 token | Implemented and gated; untested against a real PQC token, because none is available here |
| ML-DSA public key export | **Refused on purpose.** The CNG post-quantum key blob layout and magic are in a Windows SDK `bcrypt.h` this workspace has no copy of, and no other source carries them — Wine, ReactOS and the Rust winapi crate have no PQC names at all. A guessed blob would pass our own tests and fail on Windows, which is precisely the `BCRYPT_SHA224_ALGORITHM` failure again |
| CNG's own PQC identifiers | Not declared. Microsoft Learn is blocked by this workspace's network policy, so the spellings rest on search-result summaries — grade B, below the bar the `BCRYPT_ECC_CURVE_*` constants had to clear. The parameter sets are named as KSP extensions instead, as EdDSA and HMAC already are |
| ML-KEM | Unreachable through the key-storage contract; same missing header as `BUILD-01` |
| Forking SoftHSM2 | No longer needed for PQC. A v3.2 token — SoftHSMv3 and Kryoptic both claim the mechanisms — is now a configuration change |

[12 — PKCS#11 backend requirements](./12-pkcs11-requirements.md) documents
the contract a replacement token must satisfy.

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
         └──────────► Phase 4  PQC + capability probe
```

Phases 1 and 2 are independent of each other and can run in parallel.
Phase 3's Authenticode item is procurement, not engineering, and can start
at any time. Phase 4 turned out not to need a backend decision at all: the
capability probe makes a different PKCS#11 module a configuration change,
so the fork that looked unavoidable is not.

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

---

## 6. Phases 5–7 — what is left, and what is actually reachable

*Added after the phase-4 refresh of
[11 — CNG KSP market comparison](./11-market-comparison.md), from the 30
actionable gaps in [`feature-matrix.csv`](./feature-matrix.csv).*

Thirty gaps is a misleading headline. Sorted by what actually stands in the
way rather than by effort, they fall into five groups, and only two of those
are work this repository can do.

| Group | Count | Blocker |
|-------|-------|---------|
| A — closable here, now | 5 | Nothing. Code and tests on Linux |
| B — closable here, dark until the token supports it | 3 | Nothing, since phase 4 |
| C — needs a second real backend standing up | 1 | Build time, plus OpenSSL 3.5+ |
| D — blocked on something not obtainable here | 6 | A Windows SDK header, a machine, or a certificate |
| E — should stay open on purpose | 15 | A decision, already taken |

### Phase 5 — The five that are simply work ✅ done

Every one of these was re-checked against the real headers before being
listed, because the feature matrix had two of them mis-graded.

| Gap | Why it is worth doing | Note |
|-----|----------------------|------|
| **PROP-14** `NCRYPT_CERTIFICATE_PROPERTY` | Certificate enrolment expects a KSP to hold the issued certificate beside the key. Without it this provider cannot fully participate in the flow it exists to serve | Both halves standard: `L"SmartCardKeyCertificate"` confirmed in mingw-w64, and SoftHSM2 has `CKO_CERTIFICATE` |
| **AES-10** AES-CMAC | **Re-graded L → S.** The matrix claimed this would need a private identifier like HMAC. It does not: `BCRYPT_AES_CMAC_ALGORITHM` is `L"AES-CMAC"`, confirmed in mingw-w64 | Routes through `KSP_SignHash` exactly as HMAC already does; SoftHSM2 has `CKM_AES_CMAC` |
| **AES-09** AES key wrap | **Re-graded L → M.** `KSP_ExportKey` already takes `hExportKey`, CNG defines `BCRYPT_AES_WRAP_KEY_BLOB` (`L"Rfc3565KeyWrapBlob"`), SoftHSM2 has `CKM_AES_KEY_WRAP` and `_PAD` | The only legitimate route for key material to leave a token where every key is `CKA_EXTRACTABLE=FALSE`. Partly answers FMT-06 and FMT-07 without breaking the HSM posture |
| **OPS-08** Re-initialisation without restart | `InitOnceExecuteOnce` is one-shot per process *even on failure*, so one bad module path poisons the provider until the host restarts | Needs a resettable guard and care around in-flight sessions |
| **PROP-13** Per-key PIN | Provider-wide PIN works; per-key needs a per-handle credential cache and re-login per operation | Smallest value of the five; listed for completeness |

All five are done. Three extend the standard CNG surface rather than this
provider's private one, which is the criticism finding 2 of the market
comparison has levelled since the first audit.

**What the phase actually turned up.** `PROP-13` looked like the weakest
item on the list and was the most interesting: a "per-key PIN" is a
smart-card idea and PKCS#11 has no second user within a slot to hang it on.
What it does have is `CKA_ALWAYS_AUTHENTICATE` and
`C_Login(CKU_CONTEXT_SPECIFIC)`, which SoftHSM2 implements — verified in the
submodule rather than assumed from the constants appearing in a header. That
is a real per-key mechanism, so the credential is replayed on every
operation rather than cached as a one-time unlock.

`AES-09` split in two. Unwrap works on any token and is the migration path;
wrap works only for a key the TOKEN considers extractable, which this
provider never creates. The matrix records it Partial for that reason — a
consequence of the non-extractable posture, not an omission.

`OPS-08` came with a bonus: `p11_context.c` had no unit tests at all and
could not have had any, because the `LoadLibrary` stand-in in
`windows_compat.h` was an inline stub that always failed. Making it
controllable gave the module that loads the backend, initialises Cryptoki
and selects the slot its first coverage — 75 % of it, from nothing.

Two defects were found in the test build rather than the product, and both
were of the kind this project keeps paying for. The Makefile listed only
`.c` files as prerequisites, so editing a header rebuilt nothing: a mock
buffer was enlarged, the suite re-run, and it failed identically against a
binary that had not been recompiled. And a key-wrap assertion checked only
that two handles differed, so swapping them passed; strengthening it
revealed it examined only the second of two `C_WrapKey` calls, leaving the
size query unchecked.

Unit tests 1289 → **1434 assertions** across 17 → **21 suites**. Line
coverage reads 89.0 % → **88.5 %**, which is a fall on paper and a rise in
fact: `p11_context.c` entered the measurement for the first time carrying
106 previously uncounted lines.

### Phase 6 — The three that phase 4 quietly unblocked

`RSA-12` (raw RSA, `CKM_RSA_X_509`), `AES-07` (CCM) and `AES-08` (CFB) are
all recorded as backend blockers: SoftHSM2 2.7.0 implements none of them.

**That stopped being a reason not to implement them.** The capability probe
means a mechanism can be wired, gated on the token advertising it, and left
dark on SoftHSM2 — which is exactly how ML-DSA is handled today. The work is
the same shape as phase 4's and the tests are the same shape as
`test_mldsa.c`: assert the gate closed on a SoftHSM2-like token and open on
a capable one.

Whether this is worth doing depends on whether anyone will point this
provider at a token that has those mechanisms. It is cheap, and it is honest
— but three more dark code paths with no backend to exercise them is a real
cost, and the answer may reasonably be "not yet".

### Phase 7 — Stand up a second backend, and finally verify phase 4

This is the highest-value item on the list, and it is a verification task
rather than a feature.

Two claims currently rest on a mock and nothing else:

- **OPS-13 / OPS-14** — that any PKCS#11 v2.40+ module can back this
  provider, and that the probe correctly narrows what it advertises.
- **PQC-01** — that ML-DSA works on a v3.2 token. The gating is proven; the
  mechanism plumbing has never met a real implementation.

**Kryoptic** answers both. It is a PKCS#11 soft token in Rust with `mldsa`,
`mlkem` and `slhdsa` feature flags, and a Rust toolchain is already present
in this environment. Two things were checked and one of them bites:

| Check | Result |
|-------|--------|
| Rust toolchain available | ✓ `cargo` and `rustc` present |
| Kryoptic has ML-DSA | ✓ `mldsa = ["hash", "ossl/ossl350"]` |
| OpenSSL new enough | ✗ **the catch.** The PQC features need OpenSSL 3.5+; this image has 3.0.13 and Ubuntu Noble ships nothing newer |

So the phase splits cleanly, and the cheaper half is worth doing on its own:

1. **Build Kryoptic with default features** and add a CI job that runs the
   PKCS#11 layer against it. That alone turns "any module works" from an
   assertion into a tested claim, and it will find whatever this provider
   has quietly assumed about SoftHSM2's behaviour.
2. **Build OpenSSL 3.5+ from source**, rebuild Kryoptic with `pqc`, and run
   the ML-DSA path end to end. This is the only route visible from here to
   moving `PQC-01` from Partial to Covered.

Step 1 is the one to do first: it is bounded, it validates the architectural
claim phase 4 was built on, and it does not depend on step 2.

#### Step 1 ✅ done — and it earned its keep immediately

`tests/linux/` builds Kryoptic, initialises a token in it, and runs the real
`p11_*` and `ksp_*` sources against it. The only substitution is the loader:
`LoadLibraryW` becomes `dlopen`. Everything else is the same source the
Windows DLL compiles.

**It found two defects on the first run, both of which had survived 1434
assertions against the mock.** That is the entire argument for this phase,
made better than any reasoning could have.

**One: a size query poisoned the session pool.** `NCryptSignHash` and its
siblings are called twice — once with a NULL buffer to learn the length,
then again to do the work. The provider answered the first call by starting
a token operation, reading the length, and returning *without finishing it*.
The session went back into the pool with that operation still active, and
the next caller to draw it — any key, any thread — got
`CKR_OPERATION_ACTIVE` from its own `C_SignInit`. PKCS#11 v2.40 §5.2 is
explicit that this is the correct token behaviour, and it offers no way to
cancel an operation, so the only portable fix is not to start one: every
size is now computed from the key and the mechanism. SoftHSM2 permits
re-initialising over an active operation, which is why nine sessions of work
never saw it.

**Two: ECDSA signing had never worked against a conformant token.** The
provider DER-decoded every ECDSA signature, on the documented premise that
SoftHSM2 returns DER. It does not, and neither does anything else: PKCS#11
v2.40 §2.3.1 mandates raw `r‖s`, and SoftHSM2's own `OSSLECDSA.cpp` writes
`BN_bn2bin(r)` then `BN_bn2bin(s)` into a `2*len` buffer. The decoder was
parsing a raw signature as a structure and rejecting it. The mock hid this
perfectly, because the mock returned whatever DER the test had just built.
The conformant shape now passes through and the decoder is kept as a
fallback for a token returning the OpenSSL EVP form.

Neither bug is exotic. Both sit on the main path of the two most-used
operations in the provider. Both were invisible to a test suite that only
ever asked a mock whether the provider agreed with itself.

#### Step 1b ✅ done — widen it, because the first pass only touched a third

42 assertions found two defects. The obvious next move was to cover the rest
of the surface rather than add features on top of it: ECDH and the KDFs, AES
encryption, the certificate property. **80 assertions now, and a third
defect.**

**Three: a deleted key left its certificate on the token.** `KSP_DeleteKey`
destroyed the private, public and secret objects and not the
`CKO_CERTIFICATE` stored beside them. That is not only a storage leak — the
certificate is found by the key's scoped label, so the next key created with
the same name inherits a certificate belonging to a key that no longer
exists, and a caller reading `NCRYPT_CERTIFICATE_PROPERTY` gets one whose
public key does not match the key it now holds. The live suite demonstrated
it by failing on its *second* run, reading back what its first run had left.

And a prediction came due. Phase 5 set `CKA_SUBJECT` aside with this note:

> A token that enforces the specification's marking would refuse, and there
> is no such token here to test a workaround against — writing one blind is
> how this project accumulated code that only ever worked against its own
> assumptions.

Kryoptic is that token: `CKR_TEMPLATE_INCONSISTENT`. So the subject is now
parsed out of the certificate by `P11_ExtractCertSubject`, a bounds-checked
DER walk verified against a real `openssl req -x509` certificate whose
subject offset and length come from `openssl asn1parse` rather than from the
parser agreeing with itself. Every truncation of that certificate is walked
under AddressSanitizer, because this project has already shipped one
out-of-bounds read in DER handling. A certificate it cannot parse falls back
to an empty Name, so a token that does not require the attribute still
stores the object.

What passed first time is worth recording too: ECDH agreement, the raw-secret
/ hash / HKDF derivations, and AES-CBC round-trip encryption all worked
against an unfamiliar token without changes.

#### Step 1c ✅ done — finish the sweep, and find two more

80 assertions had found three defects. The untouched surface was the phase-5
work — key wrap, CMAC, the per-key PIN — plus HMAC, which had been
advertised since session 4. **108 assertions now, and two more defects,
both in that untouched surface.**

**Four: a symmetric key could never sign.** `KSP_SignHash` passed
`pKey->hPrivKey` to `C_SignInit` unconditionally, and rejected outright any
key whose `hPrivKey` was invalid. An HMAC or CMAC key has no private key —
it lives in `hSecretKey` — so **HMAC signing had never worked at all**,
despite being advertised since the mechanism work in session 4, and AES-CMAC
was born broken in phase 5.

This one was not hidden by the mock. It was never covered: the unit suites
checked that HMAC resolved to the right mechanism and never once called
`KSP_SignHash` with an HMAC key. The mock would have passed either way,
because it discarded the object handle argument. A real token cannot.

**Five: AES keys were created without the right to wrap.** PKCS#11 gates
`C_WrapKey` on `CKA_WRAP`, and this provider set neither `CKA_WRAP` nor
`CKA_UNWRAP` on the AES keys it creates. Kryoptic answers
`CKR_KEY_FUNCTION_NOT_PERMITTED`; SoftHSM2 does not enforce usage flags at
all. So AES-09 — shipped in phase 5 with 40 mock assertions behind it — was
non-functional on any token that checks.

CNG has no separate notion of a key-encryption key: whatever the caller
passes as `hExportKey` is used as one, so AES keys now carry both rights.
The capability is narrower than it sounds — a wrapping key can only extract
a key the token marks `CKA_EXTRACTABLE`, and this provider never creates
one. MAC keys get no wrapping rights.

What passed first time: RSA and ECDSA signing, public key export, ECDH and
the KDFs, AES-CBC round trip, the certificate property, the per-key PIN's
tolerance path.

**Five defects, from one suite, in code that 1434 mock assertions called
healthy.** Three of the five are in phase-5 features that were days old.
The lesson is not that the unit suites are bad — they catch regressions well
— but that a mock can only confirm the provider agrees with its author.

#### Step 1d ✅ done — the sweep ends, and the harness gets teeth

The remainder: RSA PKCS#1 and OAEP decryption, RSA-PSS signing, the three
AES chaining modes CBC had not covered, the standard curve-name route, and
machine/user scoping. **156 assertions, and no new defects.**

That is a result, not an anticlimax. Five defects came out of the first 108
assertions and none out of the next 48, which is the first evidence that the
sweep has reached the bottom rather than merely paused. The remaining
surface is now covered, and saying so is more useful than sweeping again out
of habit.

**The harness itself changed, and that may outlast the assertions.** The
suite now runs *twice against the same token*, without re-initialising
between. A whole class of defect is invisible to a single pass — anything
the provider leaves behind — and the orphaned-certificate bug was found
exactly that way. Re-injecting it confirms the mechanism: pass 1 green, pass
2 red. "The token is as clean as we found it" is now an enforced property.

The suite runs in CI as the `second-backend` job.

### Group D — real, and not reachable from this repository

Listing these as backlog items would be dishonest; they need something this
environment cannot supply.

| Gap | What it actually needs |
|-----|------------------------|
| **BUILD-01**, **TABLE-01** | `ncrypt_provider.h` and a Windows machine. **This is the highest-leverage item in the whole analysis** — until the DLL builds and loads, every other claim here is measured on Linux against a hand-written mock. `TABLE-01` is graded S because the *fix* is small; getting into a position to apply it is not |
| **PQC-01** (export half) | The CNG post-quantum key blob layout, from a Windows SDK `bcrypt.h`. Refusing to guess it is the current position and should stay so |
| **PQC-02** ML-KEM | Function-table slots for encapsulation that this project's header does not have. No backend fixes it |
| **OPS-03** Authenticode | A purchased OV/EV certificate and a legal entity. The tooling is written and CI-exercised; nothing else can be done here |
| **OPS-05** Key attestation | No PKCS#11 standard mechanism exists. Unreachable through a portable PKCS#11 layer, whatever the device does |

The single most useful thing anyone with access could do is establish where
`ncrypt_provider.h` actually comes from. Two guesses at its location have
already been wrong, a WDK install that reported success did not supply it,
and a whole-disk search of a `windows-latest` runner found only this
repository's own mock.

### Group E — the fifteen that should stay open

Recorded so nobody reopens a settled question. Three kinds:

**Already answered correctly by refusing.** `IFACE-06`
(`GetOperationProperty`) reports async operation state; PKCS#11 is
synchronous, so there is nothing to report and `NTE_NOT_SUPPORTED` is the
right answer, not a gap. `IFACE-05` (`NotifyChangeKey`) is a no-op for the
same class of reason.

**Deliberate positions.** `RSA-02` (RSA below 2048), `ECDH-06` (finite-field
DH), `DSA-01`, `3DES-01`, `FMT-07` and `FMT-09` (private key import and
PKCS#8 — both contradict a non-extractable-key posture). `LIFE-08` is as
closed as it can get: the machine/user scope is namespacing, and real
isolation needs an ACL model PKCS#11 does not have within a slot.

**Would be worse than the gap.** These deserve naming, because each is a
place where implementing the feature would make the provider *less*
truthful:

- **PROP-11** `NCRYPT_SECURITY_DESCR_PROPERTY` — a per-key ACL over a
  side-channel store the token does not enforce. Anyone who can log into the
  token still reads every key. That is the `m/` `u/` namespacing trap again,
  except this time the property's name promises access control outright.
- **PROP-16** `NCRYPT_USE_COUNT_PROPERTY` — SoftHSM2 has no atomic counter
  primitive, so the count would be racy. A usage counter that undercounts
  under load is worse than no counter, because it will be believed.
- **PQC-03** LMS / XMSS — stateful hash-based signatures need one-time-key
  state persisted without fail. A lost state update forges signatures. No
  surveyed v3.2 token implements them, and this provider has no state model
  that would make it safe. This one should probably never be built here.
- **IFACE-07** / **PROP-12** / **PROP-15** — the `PromptUser` cluster needs
  a UI thread and a window handle. This is a server-side software token; the
  feature has no user to prompt, and none of it is testable here.
- **FMT-10** `OPAQUETRANSPORT` — there is no standard to follow, so
  implementing it means inventing a wrapping format and calling it
  interoperable. If key transport is wanted, `AES-09` above is the standard
  answer.

### Suggested order

```
Phase 7 step 1  Kryoptic in CI ──────► validates phase 4's central claim
      │                                 (do this first — it is verification,
      │                                  not features, and everything else
      │                                  rests on it)
      ▼
Phase 5  The five that are work ─────► PROP-14 and AES-09 first: both extend
      │                                 the standard CNG surface
      ▼
Phase 7 step 2  OpenSSL 3.5 + PQC ───► the only route to closing PQC-01
      │
      ▼
Phase 6  The three dark mechanisms ──► cheap, but only if a token will use them

Group D  runs in parallel and is not engineering: a header, a machine, a
         certificate. BUILD-01 outranks everything above it in value and
         cannot be started from here.
```
