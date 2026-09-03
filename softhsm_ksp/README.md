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

### Via the .reg file

Edit `tools\register_ksp.reg` to replace `<ABSOLUTE_PATH>`, then double-click.

### Verification

```powershell
certutil -csplist | Select-String "SoftHSM"
```

### Uninstallation

```powershell
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\SoftHSM KSP" -Recurse -Force
```

## Tests

Three complementary layers. See [docs/09-tests.md](docs/09-tests.md) for the full test reference.

### Layer 1 — Unit tests (Linux/GCC, no SoftHSM2 needed)

```bash
cd tests/unit && make
./test_p11rv_mapping && ./test_logging && ./test_mechanism_resolve \
  && ./test_export_blobs && ./test_ksp_provider && ./test_ksp_key_ops \
  && ./test_ksp_crypto && ./test_ksp_key_props && ./test_memory && ./test_ecdsa_decode
```

10 test suites · 281 assertions · **91 % line coverage, 100 % function coverage** (gcov).
Full HTML report: `tests/unit/coverage_html/index.html`.

### Layer 2 — KSP integration tests (Windows, 21 tests)

```powershell
.\build\Release\test_ksp_integration.exe
```

Tests 1–14: original integration suite (OpenProvider → DeleteKey).  
Tests 15–21: **HLK-conformant scenarios** — RSA PSS + BCrypt verify, RSA PKCS1 BCrypt verify,
ECDSA P-256/P-384 BCrypt verify, RSA 3072 deferred generation, RSA OAEP decrypt, error conditions.

### Layer 3 — PowerShell functional tests (registered KSP)

```powershell
# Basic functional tests (9 scenarios)
.\tools\test_ksp.ps1

# Microsoft CNG HLK-conformant test suite (61 tests, 9 sections)
.\tools\test_cng_hlk.ps1
```

`test_cng_hlk.ps1` mirrors Microsoft's **TPM 2.0 Platform Crypto Provider KSP Test**
(HLK ID: `7c938be0-ff4a-44f9-916c-b578f027f0ca`). Covers RSA 2048/3072 PKCS1+PSS with
BCrypt end-to-end verification, OAEP encrypt/decrypt, ECDSA P-256/P-384 with BCrypt verify,
all NCrypt property queries, error conditions, and full key lifecycle.

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

| Algorithm | Generation | Signing | Decryption | Public export |
|-----------|-----------|---------|------------|---------------|
| RSA 2048/3072/4096 | ✓ | PKCS1, PSS | PKCS1, OAEP | ✓ |
| ECDSA P-256 | ✓ | ✓ | — | ✓ |
| ECDSA P-384 | ✓ | ✓ | — | ✓ |

Private keys are **never exportable** (to simulate the behaviour of a hardware HSM).

## Security

- Private keys are marked `CKA_SENSITIVE=TRUE`, `CKA_EXTRACTABLE=FALSE`
- The PIN is read from the `SOFTHSM2_PIN` environment variable (never hardcode in production)
- Sensitive memory is zeroed with `SecureZeroMemory()` after use

## Known limitations

- SoftHSM2 does not support `CKM_RSA_X_509` (raw RSA) — not implemented
- Private key import not supported (HSM by design)
- Only one token/slot used (the first one with a token present)
