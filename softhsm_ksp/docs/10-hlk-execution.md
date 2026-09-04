# 10 — Running the Microsoft HLK tests

How to exercise the SoftHSM2 KSP against Microsoft's Hardware Lab Kit, and
what the in-repo PowerShell suite substitutes for when HLK infrastructure
is not available.

---

## Two ways to run HLK-conformant tests

| | Layer 3b — in-repo suite | Layer 4 — official HLK |
|---|---|---|
| Runner | `tools/test_cng_hlk.ps1` | HLK Studio + HLK Controller |
| Infrastructure | One Windows machine | Controller + separate test client |
| Setup time | Minutes | Hours |
| Produces a submission package | No | Yes |
| Test cases | ~150 across 14 sections | The full Microsoft catalogue |

The in-repo suite mirrors Microsoft's **TPM 2.0 Platform Crypto Provider
KSP Test** (HLK test ID `7c938be0-ff4a-44f9-916c-b578f027f0ca`) case for
case. Use it during development; use the official HLK only when you need a
signed submission package.

---

## Layer 3b — the in-repo HLK suite

### Prerequisites

1. **SoftHSM2 2.7.0 built and installed** — see `README.md`, or build the
   in-tree submodule:
   ```powershell
   .\tools\build_softhsm_windows.ps1
   ```

2. **A token initialised**:
   ```powershell
   $env:SOFTHSM2_CONF = "<repo>\softhsm2-install\etc\softhsm2.conf"
   softhsm2-util --init-token --slot 0 --label "MyToken" `
                 --so-pin 0000 --pin 1234
   ```

3. **The KSP built and registered** (Administrator):
   ```powershell
   cd softhsm_ksp
   cmake -B build -G "Visual Studio 17 2022" -A x64 `
         -DSOFTHSM2_DIR=..\softhsm2-install
   cmake --build build --config Release
   .\tools\register_ksp.ps1 -DllPath "$PWD\build\Release\softhsm_ksp.dll"
   ```

4. **Verify the provider is visible**:
   ```powershell
   certutil -csplist | Select-String "SoftHSM"
   ```

### Running

```powershell
# Administrator PowerShell
$env:SOFTHSM2_PIN = "1234"
.\tools\test_cng_hlk.ps1
```

Exit code is `0` when every test passes, `1` otherwise — suitable for CI.

### What the sections cover

| Section | Coverage |
|---------|----------|
| S1  | Provider enumeration, `NCryptOpenStorageProvider`, provider properties |
| S2  | RSA-2048 `AT_SIGNATURE`: PKCS#1 + PSS signing, BCrypt verification, property queries, private-export rejection |
| S3  | RSA-2048 `AT_KEYEXCHANGE`: OAEP encrypt/decrypt round-trip |
| S4  | RSA-3072 deferred creation (`SetProperty` → `FinalizeKey`), sign, verify |
| S5  | ECDSA P-256 lifecycle, BCrypt verification, property queries |
| S6  | ECDSA P-384, SHA-384 signing, 96-byte signature |
| S7  | `NCryptEnumKeys` + `NCryptOpenKey` round-trip |
| S8  | Error conditions: invalid handles, missing keys, forbidden exports |
| S9  | Cleanup — deletes every key the run created |
| S10 | ECDSA P-521: SHA-512 signing, 132-byte signature, blob layout |
| S11 | ECDH over P-256 / P-384 / P-521 — **both parties must derive the same secret** |
| S12 | EdDSA Ed25519 (64-byte sig) and Ed448 (114-byte sig) |
| S13 | AES-256 ECB / CBC / CTR / GCM encrypt-decrypt round-trips |
| S14 | Error conditions for the extended algorithm set |

Every key created is named `HLK_*_<random>`, so parallel runs do not
collide, and S9 removes them all.

### Validating the suite without Windows

The suite embeds a C# P/Invoke block compiled at run time by `Add-Type`.
Two bug classes in it can be caught on any platform:

```bash
pwsh -File tools/validate_hlk_script.ps1
```

This parses the script and compiles the embedded C#, catching parse errors
and P/Invoke signature mistakes (typically a length argument typed `int`
where the declaration says `uint`) before you reach a Windows machine.
It loads no Windows DLL, so it runs on Linux and macOS.

---

## Layer 4 — the official Microsoft HLK

### What you need

| Component | Notes |
|-----------|-------|
| HLK Controller | Windows Server with the HLK Controller + Studio installed |
| Test client | A separate Windows machine, joined to the controller |
| HLK version | Must match the client's Windows build |
| Test signing | `bcdedit /set testsigning on` on the client |

The controller and client must be **different machines** — HLK will not
run both roles on one host.

### Procedure

1. **Install the HLK Controller** on the server. Download the kit matching
   your target Windows build from Microsoft's Hardware Lab Kit page.

2. **Provision the test client**: run the HLK client installer from the
   controller's share, usually
   `\\<controller>\HLKInstall\Client\setup.cmd`.

3. **Prepare the client**:
   ```powershell
   # Administrator, on the client
   bcdedit /set testsigning on
   # reboot

   # Install and initialise SoftHSM2
   $env:SOFTHSM2_CONF = "C:\SoftHSM2\etc\softhsm2.conf"
   softhsm2-util --init-token --slot 0 --label "HLKToken" `
                 --so-pin 0000 --pin 1234

   # Register the KSP machine-wide
   .\tools\register_ksp.ps1 -DllPath "C:\ksp\softhsm_ksp.dll"

   # Make the PIN available to the service account HLK runs tests under
   [Environment]::SetEnvironmentVariable(
       "SOFTHSM2_PIN", "1234", "Machine")
   [Environment]::SetEnvironmentVariable(
       "SOFTHSM2_CONF", "C:\SoftHSM2\etc\softhsm2.conf", "Machine")
   ```

   Setting the variables at **Machine** scope matters: HLK runs tests in a
   different session from your interactive one, and a User-scope variable
   will not be visible to it.

4. **Create a project in HLK Studio**:
   - *Project* → *Create Project*, name it (e.g. `SoftHSM-KSP`)
   - *Selection* tab → select the test client
   - Choose the **Software Device** product type
   - Add the KSP as the device under test

5. **Select the tests**: in the *Tests* tab, filter for
   `7c938be0-ff4a-44f9-916c-b578f027f0ca` — the *TPM 2.0 Platform Crypto
   Provider KSP Test*. Select it and any other CNG KSP tests your
   submission requires.

6. **Run**, then review results in the *Results* tab. Failures include a
   log; the KSP's own trace is visible in DebugView when `KSP_DEBUG=1`.

7. **Package**: *Package* tab → *Create Package* produces the `.hlkx`
   submission file.

### Interpreting failures

| Symptom | Likely cause |
|---------|--------------|
| Provider not found | KSP not registered, or registered for the wrong architecture |
| `NTE_BAD_KEYSET` on every test | Token not initialised, or the PIN is wrong for HLK's session |
| Key generation times out | SoftHSM2 RSA-4096 generation is slow; raise the test timeout |
| Signature verification fails | ECDSA DER → r‖s conversion; check `P11_DecodeDerEcdsaSignature` |
| Sporadic failures under load | Session pool exhaustion — the pool holds 16 sessions (`P11_SESSION_POOL_SIZE`) |

Enable KSP tracing on the client while diagnosing:

```powershell
[Environment]::SetEnvironmentVariable("KSP_DEBUG", "1", "Machine")
# then watch with DebugView (Sysinternals), running elevated
```

---

## What HLK will not accept

This KSP is a **development and test provider**, not a certifiable one.
Two things stand between it and a real submission:

- **SoftHSM2 is a software token.** It stores keys in an encrypted SQLite
  database on disk, so it cannot satisfy the hardware key-protection
  requirements a Platform Crypto Provider submission is judged against.
  The KSP reports `NCRYPT_IMPL_HARDWARE_FLAG` so that CNG treats it like a
  hardware provider during testing — that is a testing convenience, not a
  truthful hardware claim.

- **The DLL is unsigned.** A submission needs a production code-signing
  certificate; test-signing only works on a machine with testsigning
  enabled.

Run the HLK suite to validate *behaviour*. Certification would require
backing the same KSP with real hardware.

---

## See also

- [09 — Test suite](./09-tests.md) — the three-layer test pyramid
- [04 — Cryptographic operations](./04-operations-crypto.md) — mechanism mapping
- [06 — Error mapping](./06-mapping-erreurs.md) — `CK_RV` → `SECURITY_STATUS`
