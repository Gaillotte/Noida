# SoftHSM2 KSP — CNG Key Storage Provider via PKCS#11

Prototype of a complete **CNG (Cryptography Next Generation) Key Storage Provider (KSP)** that delegates all cryptographic operations to **SoftHSM2** via the PKCS#11 interface.

## Prerequisites

| Component | Minimum version |
|-----------|-----------------|
| Windows   | 10 / 11 x64     |
| Visual Studio | 2022 (MSVC) |
| CMake     | 3.20+           |
| SoftHSM2  | 2.6+            |
| Windows SDK | 10.0.19041+  |

### Installing SoftHSM2

1. Download the installer from https://github.com/opendnssec/SoftHSMv2
2. Install in `C:\Program Files\SoftHSM2\` (default path)
3. Initialise a token:
   ```
   softhsm2-util --init-token --slot 0 --label "MyToken" \
                 --so-pin 0000 --pin 1234
   ```

## Build

```powershell
# In a Visual Studio terminal (x64 Native Tools)
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

The DLL `Release\softhsm_ksp.dll` is built in `build\Release\`.

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

### PKCS#11 layer unit tests

```powershell
.\build\Release\test_p11_layer.exe
```

Covers: initialisation, sessions, lookup, RSA generation, PKCS1/PSS signing, destruction.

### KSP integration tests

```powershell
.\build\Release\test_ksp_integration.exe
```

Covers: OpenProvider, CreatePersistedKey, FinalizeKey, GetKeyProperty, SignHash RSA/ECDSA, ExportKey, EnumKeys, DeleteKey.

### Full functional tests (PowerShell)

```powershell
.\tools\test_ksp.ps1
```

Requires the KSP registered in the registry. Runs 9 complete scenarios via the NCrypt API.

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
