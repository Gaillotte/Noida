# SoftHSM2 KSP — CNG Key Storage Provider via PKCS#11

Prototype of a complete **CNG (Cryptography Next Generation) Key Storage Provider (KSP)** that delegates all cryptographic operations to **SoftHSM2** via the PKCS#11 interface.

## Prerequisites

| Component | Minimum version |
|-----------|-----------------|
| Windows   | 10 / 11 x64     |
| Visual Studio | 2022 (MSVC) |
| CMake     | 3.20+           |
| SoftHSM2  | **2.7.0** (OpenSSL backend — built from submodule or installed separately) |
| OpenSSL   | 1.1.x or 3.x (via vcpkg when building from source) |
| Windows SDK | 10.0.19041+  |

## Getting SoftHSM2 2.7.0

Two options — choose one:

### Option A — Build from source (recommended, included as submodule)

```powershell
# After cloning the repo:
git submodule update --init --recursive

# In a Visual Studio x64 Native Tools prompt:
.\softhsm_ksp\tools\build_softhsm_windows.ps1

# The DLL ends up in softhsm2-install\ and the KSP CMake step below
# picks it up automatically via -DSOFTHSM2_DIR.
```

### Option B — Pre-built installer

1. Download the 2.7.0 installer from https://github.com/opendnssec/SoftHSMv2/releases
2. Install to `C:\Program Files\SoftHSM2\` (default)
3. Initialise a token:
   ```powershell
   softhsm2-util --init-token --slot 0 --label "MyToken" --so-pin 0000 --pin 1234
   ```

## Build

```powershell
# In a Visual Studio x64 Native Tools prompt
cd softhsm_ksp
mkdir build && cd build

# Option A (submodule build — DLL path baked in at compile time):
cmake .. -G "Visual Studio 17 2022" -A x64 `
         -DSOFTHSM2_DIR=..\..\softhsm2-install

# Option B (pre-built installer in default location):
cmake .. -G "Visual Studio 17 2022" -A x64

cmake --build . --config Release
```

The DLL `Release\softhsm_ksp.dll` is built in `softhsm_ksp\build\Release\`.

## Configuration

| Environment variable | Default value | Description |
|----------------------|---------------|-------------|
| `SOFTHSM2_LIB` | `C:\Program Files\SoftHSM2\lib\softhsm2-x64.dll` | Path to the SoftHSM2 DLL |
| `SOFTHSM2_PIN` | `1234` | Token user PIN |
| `KSP_DEBUG` | `0` | Enable logging (`1` = enabled) |

Logging is visible in real time with **DebugView** (Sysinternals).

## Registering the KSP

### Via PowerShell (Administrator)

```powershell
.\tools\register_ksp.ps1 -DllPath "C:\path\to\softhsm_ksp.dll"
```

The script does two things, and both matter. `BCryptRegisterProvider`
records the DLL so `NCryptOpenStorageProvider` can load it by name;
`BCryptAddContextFunctionProvider` publishes the algorithm list so that
callers which discover providers *by algorithm* can find it. To undo both:

```powershell
.\tools\register_ksp.ps1 -Unregister
```

CNG reads the provider list at process start, so restart any application
that was already running.

### Via the .reg file

Edit `tools\register_ksp.reg` to replace `<ABSOLUTE_PATH>`, then double-click.

This route writes only the `Image` and `Type` values, which covers loading
the provider by name but **not** algorithm publication — use it only as a
fallback when the PowerShell script cannot run.

### Verification

```powershell
certutil -csplist | Select-String "SoftHSM"
```

### Uninstallation

```powershell
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\SoftHSM KSP" -Recurse -Force
```

## Tests

Four complementary layers. See [docs/09-tests.md](docs/09-tests.md) for the full test reference.

### Layer 1 — Unit tests (Linux/GCC, no SoftHSM2 needed)

```bash
cd tests/unit && make run
```

14 test suites · 780 assertions · **89.8 % line coverage, 100 % function coverage** (gcov).
Full HTML report: `tests/unit/coverage_html/index.html`.

```bash
make run           # build and run all 14 suites
make coverage      # plus an HTML coverage report
make syntax-check  # parse the Windows-only integration test
```

### Layer 2 — KSP integration tests (Windows, 40 tests)

```powershell
.\build\Release\test_ksp_integration.exe
```

Tests 1–14: original integration suite (OpenProvider → DeleteKey).  
Tests 15–21: **HLK-conformant scenarios** — RSA PSS + BCrypt verify, RSA PKCS1 BCrypt verify,
ECDSA P-256/P-384 BCrypt verify, RSA 3072 deferred generation, RSA OAEP decrypt, error conditions.  
Tests 22–40: **SoftHSM2 2.7.0 mechanism coverage** — ECDSA P-521, OAEP SHA-384/512 and labels,
EC public key import, ECDH agreement on all three curves, Ed25519/Ed448, AES ECB/CBC/CTR/GCM,
HMAC-SHA256, symmetric key reopen.

### Layer 3 — PowerShell functional tests (registered KSP)

```powershell
# Basic functional tests (9 scenarios, 17 checks)
.\tools\test_ksp.ps1

# Microsoft CNG HLK-conformant test suite (~150 tests, 14 sections)
.\tools\test_cng_hlk.ps1
```

`test_cng_hlk.ps1` mirrors Microsoft's **TPM 2.0 Platform Crypto Provider KSP Test**
(HLK ID: `7c938be0-ff4a-44f9-916c-b578f027f0ca`). Covers RSA 2048/3072 PKCS1+PSS with
BCrypt end-to-end verification, OAEP encrypt/decrypt, ECDSA P-256/P-384/P-521 with BCrypt
verify, ECDH two-party key agreement, EdDSA, AES across four chaining modes, all NCrypt
property queries, error conditions, and full key lifecycle.

The suite embeds a C# P/Invoke block. Validate it on any platform — no Windows needed:

```bash
pwsh -File tools/validate_hlk_script.ps1
```

### Layer 4 — Official Microsoft HLK

See [docs/10-hlk-execution.md](docs/10-hlk-execution.md) for the HLK Studio procedure,
prerequisites, and what stands between this KSP and a real certification submission.

## Architecture

```
softhsm_ksp/
├── src/pkcs11/      PKCS#11 layer (context, sessions, utilities)
├── src/ksp/         CNG KSP implementation (provider, keys, crypto)
├── src/common/      Logging, memory, configuration
├── tools/           Registration and test scripts
└── tests/           Unit and integration tests
```

### Typical call flow (signing)

```
Windows Application
    ↓ NCryptSignHash()
KSP_SignHash()          [ksp_crypto.c]
    ↓ P11_AcquireSession()
    ↓ C_SignInit() → C_Sign()
SoftHSM2 (softhsm2-x64.dll)
    ↓ DER result (ECDSA) → conversion r||s
    ↓ RSA result → passed through as-is
Windows Application
```

## Supported algorithms

| Algorithm | Generation | Signing | Decryption | Key agreement | Public export |
|-----------|:----------:|---------|------------|:-------------:|:-------------:|
| RSA 2048–16384 (step 64) | ✓ | PKCS1, PSS (SHA-1/224/256/384/512) | PKCS1, OAEP (SHA-1/224/256/384/512) | — | ✓ |
| ECDSA P-256/P-384/P-521 | ✓ | ✓ (r‖s) | — | — | ✓ |
| ECDSA secp256k1 | ✓ | ✓ (r‖s) | — | — | ✓ |
| ECDH P-256/P-384/P-521 | ✓ | — | — | ✓ | ✓ |
| EdDSA Ed25519 / Ed448 | ✓ | ✓ (raw) | — | — | ✓ |
| AES 128/192/256 | ✓ | — | ECB, CBC, CTR, GCM | — | — |
| HMAC SHA-1/224/256/384/512 | ✓ | ✓ (MAC) | — | — | — |

`EDDSA_ED25519`, `EDDSA_ED448`, `HMAC_SHA*` and `ECDSA_SECP256K1` are this
provider's own identifiers, not standard CNG ones, so only an application
written against this KSP will reach them. CNG has no EdDSA algorithm
identifier at all; it does know secp256k1, but as a curve selected through
`BCRYPT_ECC_CURVE_NAME` (`BCRYPT_ECC_CURVE_SECP256K1`) on the generic ECDSA
algorithm rather than as an algorithm name — supporting that route as well
is tracked as ECDSA-05 in the feature matrix. Everything else in the table
uses the standard CNG identifiers.

Asymmetric private keys are **never exportable** (to simulate the behaviour of a
hardware HSM). See [SoftHSM2_KSP_Algorithm_Reference.docx](SoftHSM2_KSP_Algorithm_Reference.docx)
for the full mechanism, mode and key-size reference.

## Security

- Private keys are marked `CKA_SENSITIVE=TRUE`, `CKA_EXTRACTABLE=FALSE`
- The PIN is read from the `SOFTHSM2_PIN` environment variable (never hardcode in production)
- Sensitive memory is zeroed with `SecureZeroMemory()` after use

## Known limitations

- SoftHSM2 does not support `CKM_RSA_X_509` (raw RSA) — not implemented
- Private key import not supported (HSM by design)
- Only one token/slot used (the first one with a token present)
- DES/3DES, DSA, PKCS#3 Diffie-Hellman and GOST are deliberately out of scope
  (deprecated, or outside the HLK test plan)
- Raw hash and sign-with-integrated-hash PKCS#11 mechanisms are unreachable by
  design: CNG always hands `NCryptSignHash` a pre-computed hash
