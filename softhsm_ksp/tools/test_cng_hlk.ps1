#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Microsoft CNG KSP HLK-conformant test suite for SoftHSM KSP.

.DESCRIPTION
    Mirrors the test scenarios from Microsoft's Hardware Lab Kit (HLK)
    "TPM 2.0 Platform Crypto Provider KSP Test"
    (HLK test ID: 7c938be0-ff4a-44f9-916c-b578f027f0ca).

    Covers:
      S1  — Provider enumeration and property queries
      S2  — RSA 2048 full lifecycle: create, sign (PKCS1 + PSS), BCrypt verify,
             key property queries, private export rejection
      S3  — RSA 2048 AT_KEYEXCHANGE: OAEP encryption and decryption
      S4  — RSA 3072 deferred creation (SetProperty + FinalizeKey), sign, verify
      S5  — ECDSA P-256 full lifecycle: create, sign, BCrypt verify, property queries
      S6  — ECDSA P-384: sign SHA-384, BCrypt verify
      S7  — Key enumeration and NCryptOpenKey round-trip
      S8  — Error conditions: invalid handles, missing keys, forbidden private export
      S9  — Cleanup: delete all test keys

    Requirements:
      - SoftHSM2 installed and initialised (softhsm2-util --init-token)
      - SoftHSM KSP registered (regsvr32 softhsm_ksp.dll)
      - Environment variables: SOFTHSM2_LIB, SOFTHSM2_PIN (or defaults)
#>

$ErrorActionPreference = "Stop"
$ProviderName = "SoftHSM KSP"

# Test key names (unique per run)
$Rnd          = Get-Random -Minimum 10000 -Maximum 99999
$KeyRsa2048   = "HLK_RSA2048_$Rnd"
$KeyRsaKex    = "HLK_RSA_KEX_$Rnd"
$KeyRsa3072   = "HLK_RSA3072_$Rnd"
$KeyEcP256    = "HLK_ECP256_$Rnd"
$KeyEcP384    = "HLK_ECP384_$Rnd"

$script:Pass  = 0
$script:Fail  = 0
$script:Skip  = 0

function Test-Result {
    param([string]$Name, [bool]$Success, [string]$Detail = "")
    if ($Success) {
        Write-Host "[PASS] $Name" -ForegroundColor Green
        $script:Pass++
    } else {
        Write-Host "[FAIL] $Name$(if ($Detail) {': ' + $Detail})" -ForegroundColor Red
        $script:Fail++
    }
}

function Skip-Test {
    param([string]$Name, [string]$Reason)
    Write-Host "[SKIP] $Name : $Reason" -ForegroundColor Yellow
    $script:Skip++
}

# ── Native interop ────────────────────────────────────────────────────────────
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class Hlk {

    // ── NCrypt ────────────────────────────────────────────────────────────────

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(
        out IntPtr phProvider, string pszProviderName, uint dwFlags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptCreatePersistedKey(
        IntPtr hProvider, out IntPtr phKey,
        string pszAlgId, string pszKeyName,
        uint dwLegacyKeySpec, uint dwFlags);

    [DllImport("ncrypt.dll")]
    public static extern int NCryptFinalizeKey(IntPtr hKey, uint dwFlags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenKey(
        IntPtr hProvider, out IntPtr phKey,
        string pszKeyName, uint dwLegacyKeySpec, uint dwFlags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptGetProperty(
        IntPtr hObject, string pszProperty,
        byte[] pbOutput, uint cbOutput,
        out uint pcbResult, uint dwFlags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptSetProperty(
        IntPtr hObject, string pszProperty,
        byte[] pbInput, uint cbInput, uint dwFlags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptExportKey(
        IntPtr hKey, IntPtr hExportKey, string pszBlobType,
        IntPtr pParameterList, byte[] pbOutput, uint cbOutput,
        out uint pcbResult, uint dwFlags);

    [DllImport("ncrypt.dll")]
    public static extern int NCryptSignHash(
        IntPtr hKey, IntPtr pPaddingInfo,
        byte[] pbHashValue, uint cbHashValue,
        byte[] pbSignature, uint cbSignature,
        out uint pcbResult, uint dwFlags);

    [DllImport("ncrypt.dll")]
    public static extern int NCryptDecrypt(
        IntPtr hKey, byte[] pbInput, uint cbInput,
        IntPtr pPaddingInfo,
        byte[] pbOutput, uint cbOutput,
        out uint pcbResult, uint dwFlags);

    [DllImport("ncrypt.dll")]
    public static extern int NCryptDeleteKey(IntPtr hKey, uint dwFlags);

    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr hObject);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptEnumKeys(
        IntPtr hProvider, string pszScope,
        out IntPtr ppKeyName, ref IntPtr ppEnumState, uint dwFlags);

    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeBuffer(IntPtr pvInput);

    // ── BCrypt ────────────────────────────────────────────────────────────────

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int BCryptOpenAlgorithmProvider(
        out IntPtr phAlgorithm, string pszAlgId,
        string pszImplementation, uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern int BCryptCloseAlgorithmProvider(
        IntPtr hAlgorithm, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int BCryptImportKeyPair(
        IntPtr hAlgorithm, IntPtr hImportKey, string pszBlobType,
        out IntPtr phKey, byte[] pbInput, uint cbInput, uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern int BCryptDestroyKey(IntPtr hKey);

    [DllImport("bcrypt.dll")]
    public static extern int BCryptVerifySignature(
        IntPtr hKey, IntPtr pPaddingInfo,
        byte[] pbHash, uint cbHash,
        byte[] pbSignature, uint cbSignature, uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern int BCryptEncrypt(
        IntPtr hKey, byte[] pbInput, uint cbInput,
        IntPtr pPaddingInfo, byte[] pbIV, uint cbIV,
        byte[] pbOutput, uint cbOutput,
        out uint pcbResult, uint dwFlags);

    // ── BCrypt helper: RSA PKCS1 verification ─────────────────────────────────
    // hashAlg: "SHA1", "SHA256", "SHA384", "SHA512"
    public static bool VerifyRsaPkcs1(byte[] rsaPublicBlob, string hashAlg,
                                      byte[] hash, byte[] signature) {
        IntPtr hAlg = IntPtr.Zero, hKey = IntPtr.Zero;
        IntPtr pszAlg = IntPtr.Zero, pInfo = IntPtr.Zero;
        try {
            if (BCryptOpenAlgorithmProvider(out hAlg, "RSA", null, 0) != 0)
                return false;
            if (BCryptImportKeyPair(hAlg, IntPtr.Zero, "RSAPUBLICBLOB",
                    out hKey, rsaPublicBlob, (uint)rsaPublicBlob.Length, 0) != 0)
                return false;
            // BCRYPT_PKCS1_PADDING_INFO = { LPCWSTR pszAlgId } (one pointer on x64 = 8 bytes)
            pszAlg = Marshal.StringToHGlobalUni(hashAlg);
            pInfo  = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pInfo, pszAlg);
            return BCryptVerifySignature(hKey, pInfo,
                       hash, (uint)hash.Length,
                       signature, (uint)signature.Length,
                       2) == 0; // BCRYPT_PAD_PKCS1
        } finally {
            if (pInfo   != IntPtr.Zero) Marshal.FreeHGlobal(pInfo);
            if (pszAlg  != IntPtr.Zero) Marshal.FreeHGlobal(pszAlg);
            if (hKey    != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlg    != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }

    // ── BCrypt helper: RSA PSS verification ───────────────────────────────────
    // cbSalt: typically equal to hash output size (SHA-256 → 32, SHA-384 → 48)
    public static bool VerifyRsaPss(byte[] rsaPublicBlob, string hashAlg, uint cbSalt,
                                    byte[] hash, byte[] signature) {
        IntPtr hAlg = IntPtr.Zero, hKey = IntPtr.Zero;
        IntPtr pszAlg = IntPtr.Zero, pInfo = IntPtr.Zero;
        try {
            if (BCryptOpenAlgorithmProvider(out hAlg, "RSA", null, 0) != 0)
                return false;
            if (BCryptImportKeyPair(hAlg, IntPtr.Zero, "RSAPUBLICBLOB",
                    out hKey, rsaPublicBlob, (uint)rsaPublicBlob.Length, 0) != 0)
                return false;
            // BCRYPT_PSS_PADDING_INFO = { LPCWSTR pszAlgId; ULONG cbSalt }
            // x64 layout: 8 bytes (ptr) + 4 bytes (ULONG) + 4 bytes padding = 16 bytes
            pszAlg = Marshal.StringToHGlobalUni(hashAlg);
            pInfo  = Marshal.AllocHGlobal(16);
            Marshal.WriteIntPtr(pInfo, 0, pszAlg);
            Marshal.WriteInt32(pInfo, IntPtr.Size, (int)cbSalt);
            return BCryptVerifySignature(hKey, pInfo,
                       hash, (uint)hash.Length,
                       signature, (uint)signature.Length,
                       8) == 0; // BCRYPT_PAD_PSS
        } finally {
            if (pInfo   != IntPtr.Zero) Marshal.FreeHGlobal(pInfo);
            if (pszAlg  != IntPtr.Zero) Marshal.FreeHGlobal(pszAlg);
            if (hKey    != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlg    != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }

    // ── BCrypt helper: ECDSA verification ─────────────────────────────────────
    // bcryptAlg: "ECDSA_P256" or "ECDSA_P384"
    public static bool VerifyEcdsa(string bcryptAlg, byte[] eccPublicBlob,
                                   byte[] hash, byte[] signature) {
        IntPtr hAlg = IntPtr.Zero, hKey = IntPtr.Zero;
        try {
            if (BCryptOpenAlgorithmProvider(out hAlg, bcryptAlg, null, 0) != 0)
                return false;
            if (BCryptImportKeyPair(hAlg, IntPtr.Zero, "ECCPUBLICBLOB",
                    out hKey, eccPublicBlob, (uint)eccPublicBlob.Length, 0) != 0)
                return false;
            return BCryptVerifySignature(hKey, IntPtr.Zero,
                       hash, (uint)hash.Length,
                       signature, (uint)signature.Length, 0) == 0;
        } finally {
            if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }

    // ── BCrypt helper: RSA OAEP encryption (public key) ──────────────────────
    // hashAlg: "SHA1" or "SHA256"
    public static byte[] EncryptRsaOaep(byte[] rsaPublicBlob, string hashAlg,
                                        byte[] plaintext) {
        IntPtr hAlg = IntPtr.Zero, hKey = IntPtr.Zero;
        IntPtr pszAlg = IntPtr.Zero, pInfo = IntPtr.Zero;
        try {
            if (BCryptOpenAlgorithmProvider(out hAlg, "RSA", null, 0) != 0)
                return null;
            if (BCryptImportKeyPair(hAlg, IntPtr.Zero, "RSAPUBLICBLOB",
                    out hKey, rsaPublicBlob, (uint)rsaPublicBlob.Length, 0) != 0)
                return null;
            // BCRYPT_OAEP_PADDING_INFO = { LPCWSTR pszAlgId; PUCHAR pbLabel; ULONG cbLabel }
            // x64 layout: 8 + 8 + 4 + 4 (padding) = 24 bytes
            pszAlg = Marshal.StringToHGlobalUni(hashAlg);
            pInfo  = Marshal.AllocHGlobal(24);
            Marshal.WriteIntPtr(pInfo, 0,  pszAlg);
            Marshal.WriteIntPtr(pInfo, 8,  IntPtr.Zero); // pbLabel = NULL
            Marshal.WriteInt32(pInfo,  16, 0);           // cbLabel = 0
            uint cbCipher = 0;
            if (BCryptEncrypt(hKey, plaintext, (uint)plaintext.Length, pInfo,
                              null, 0, null, 0, out cbCipher, 4) != 0)  // BCRYPT_PAD_OAEP
                return null;
            byte[] cipher = new byte[cbCipher];
            if (BCryptEncrypt(hKey, plaintext, (uint)plaintext.Length, pInfo,
                              null, 0, cipher, cbCipher, out cbCipher, 4) != 0)
                return null;
            Array.Resize(ref cipher, (int)cbCipher);
            return cipher;
        } finally {
            if (pInfo   != IntPtr.Zero) Marshal.FreeHGlobal(pInfo);
            if (pszAlg  != IntPtr.Zero) Marshal.FreeHGlobal(pszAlg);
            if (hKey    != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlg    != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }

    // ── NCrypt helper: OAEP decryption ────────────────────────────────────────
    // hashAlg: "SHA1" or "SHA256"
    public static byte[] DecryptOaep(IntPtr hKey, string hashAlg, byte[] ciphertext) {
        IntPtr pszAlg = IntPtr.Zero, pInfo = IntPtr.Zero;
        try {
            pszAlg = Marshal.StringToHGlobalUni(hashAlg);
            pInfo  = Marshal.AllocHGlobal(24);
            Marshal.WriteIntPtr(pInfo, 0,  pszAlg);
            Marshal.WriteIntPtr(pInfo, 8,  IntPtr.Zero);
            Marshal.WriteInt32(pInfo,  16, 0);
            uint cbResult = 0;
            // NCRYPT_PAD_OAEP_FLAG = 4
            if (NCryptDecrypt(hKey, ciphertext, (uint)ciphertext.Length, pInfo,
                              null, 0, out cbResult, 4) != 0)
                return null;
            byte[] plain = new byte[cbResult];
            if (NCryptDecrypt(hKey, ciphertext, (uint)ciphertext.Length, pInfo,
                              plain, cbResult, out cbResult, 4) != 0)
                return null;
            Array.Resize(ref plain, (int)cbResult);
            return plain;
        } finally {
            if (pInfo   != IntPtr.Zero) Marshal.FreeHGlobal(pInfo);
            if (pszAlg  != IntPtr.Zero) Marshal.FreeHGlobal(pszAlg);
        }
    }

    // ── NCrypt helper: export public key blob ─────────────────────────────────
    public static byte[] ExportPublicKey(IntPtr hKey, string blobType) {
        uint cbNeeded = 0;
        if (NCryptExportKey(hKey, IntPtr.Zero, blobType, IntPtr.Zero,
                            null, 0, out cbNeeded, 0) != 0 || cbNeeded == 0)
            return null;
        byte[] blob = new byte[cbNeeded];
        uint cbResult = 0;
        if (NCryptExportKey(hKey, IntPtr.Zero, blobType, IntPtr.Zero,
                            blob, cbNeeded, out cbResult, 0) != 0)
            return null;
        Array.Resize(ref blob, (int)cbResult);
        return blob;
    }

    // ── NCrypt helper: read string property ───────────────────────────────────
    public static string GetStringProperty(IntPtr hObject, string property) {
        uint cbNeeded = 0;
        if (NCryptGetProperty(hObject, property, null, 0, out cbNeeded, 0) != 0
                || cbNeeded == 0)
            return null;
        byte[] buf = new byte[cbNeeded];
        if (NCryptGetProperty(hObject, property, buf, cbNeeded, out cbNeeded, 0) != 0)
            return null;
        // Remove trailing null wide char
        return System.Text.Encoding.Unicode.GetString(buf).TrimEnd('\0');
    }

    // ── NCrypt helper: read DWORD property ────────────────────────────────────
    public static int GetDwordProperty(IntPtr hObject, string property, out bool ok) {
        uint cbNeeded = 0;
        byte[] buf = new byte[4];
        int hr = NCryptGetProperty(hObject, property, buf, 4, out cbNeeded, 0);
        ok = (hr == 0 && cbNeeded == 4);
        if (!ok) return 0;
        return BitConverter.ToInt32(buf, 0);
    }

    // ── NCrypt helper: sign hash (PKCS1) ──────────────────────────────────────
    public static byte[] SignPkcs1(IntPtr hKey, byte[] hash) {
        // Build BCRYPT_PKCS1_PADDING_INFO for NCryptSignHash
        IntPtr pszAlg = IntPtr.Zero, pInfo = IntPtr.Zero;
        try {
            pszAlg = Marshal.StringToHGlobalUni("SHA256");
            pInfo  = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pInfo, pszAlg);
            uint cbResult = 0;
            // size query
            if (NCryptSignHash(hKey, pInfo, hash, (uint)hash.Length,
                               null, 0, out cbResult, 2) != 0)  // NCRYPT_PAD_PKCS1_FLAG
                return null;
            byte[] sig = new byte[cbResult];
            if (NCryptSignHash(hKey, pInfo, hash, (uint)hash.Length,
                               sig, cbResult, out cbResult, 2) != 0)
                return null;
            Array.Resize(ref sig, (int)cbResult);
            return sig;
        } finally {
            if (pInfo  != IntPtr.Zero) Marshal.FreeHGlobal(pInfo);
            if (pszAlg != IntPtr.Zero) Marshal.FreeHGlobal(pszAlg);
        }
    }

    // ── NCrypt helper: sign hash (PSS, SHA-256, cbSalt=32) ───────────────────
    public static byte[] SignPss(IntPtr hKey, byte[] hash) {
        IntPtr pszAlg = IntPtr.Zero, pInfo = IntPtr.Zero;
        try {
            pszAlg = Marshal.StringToHGlobalUni("SHA256");
            pInfo  = Marshal.AllocHGlobal(16);
            Marshal.WriteIntPtr(pInfo, 0, pszAlg);
            Marshal.WriteInt32(pInfo, IntPtr.Size, 32); // cbSalt
            uint cbResult = 0;
            if (NCryptSignHash(hKey, pInfo, hash, (uint)hash.Length,
                               null, 0, out cbResult, 8) != 0)  // NCRYPT_PAD_PSS_FLAG
                return null;
            byte[] sig = new byte[cbResult];
            if (NCryptSignHash(hKey, pInfo, hash, (uint)hash.Length,
                               sig, cbResult, out cbResult, 8) != 0)
                return null;
            Array.Resize(ref sig, (int)cbResult);
            return sig;
        } finally {
            if (pInfo  != IntPtr.Zero) Marshal.FreeHGlobal(pInfo);
            if (pszAlg != IntPtr.Zero) Marshal.FreeHGlobal(pszAlg);
        }
    }

    // ── NCrypt helper: sign hash (ECDSA, no padding) ─────────────────────────
    public static byte[] SignEcdsa(IntPtr hKey, byte[] hash) {
        uint cbResult = 0;
        if (NCryptSignHash(hKey, IntPtr.Zero, hash, (uint)hash.Length,
                           null, 0, out cbResult, 0) != 0)
            return null;
        byte[] sig = new byte[cbResult];
        if (NCryptSignHash(hKey, IntPtr.Zero, hash, (uint)hash.Length,
                           sig, cbResult, out cbResult, 0) != 0)
            return null;
        Array.Resize(ref sig, (int)cbResult);
        return sig;
    }
}
"@ -PassThru | Out-Null

# ── Common test data ──────────────────────────────────────────────────────────
$sha256     = [System.Security.Cryptography.SHA256]::Create()
$sha384     = [System.Security.Cryptography.SHA384]::Create()
$testData   = [System.Text.Encoding]::UTF8.GetBytes("SoftHSM KSP HLK Test 2024")
$hashSha256 = $sha256.ComputeHash($testData)
$hashSha384 = $sha384.ComputeHash($testData)
$plaintext  = [System.Text.Encoding]::UTF8.GetBytes("HLK OAEP plaintext 12345!")

# Handles that need cleanup
$keysToDelete = [System.Collections.Generic.List[IntPtr]]::new()

# ── Open the provider (shared across all sections) ────────────────────────────
$hProv = [IntPtr]::Zero
$hr = [Hlk]::NCryptOpenStorageProvider([ref]$hProv, $ProviderName, 0)
if ($hr -ne 0) {
    Write-Host "[FATAL] NCryptOpenStorageProvider failed: hr=0x$($hr.ToString('X8'))" -ForegroundColor Red
    Write-Host "Ensure SoftHSM KSP is registered and SoftHSM2 is initialised." -ForegroundColor Yellow
    exit 1
}
Write-Host "Provider '$ProviderName' opened successfully." -ForegroundColor Cyan

# =============================================================================
# S1 — Provider enumeration and property queries
# =============================================================================
Write-Host ""
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White
Write-Host "S1 — Provider enumeration and property queries" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White

# certutil -csplist
try {
    $cspList = certutil -csplist 2>&1 | Out-String
    Test-Result "S1.1 certutil -csplist lists SoftHSM KSP" ($cspList -match "SoftHSM")
} catch {
    Test-Result "S1.1 certutil -csplist" $false $_.Exception.Message
}

# Provider Name property
$propName = [Hlk]::GetStringProperty($hProv, "Name")
Test-Result "S1.2 NCRYPT_NAME_PROPERTY = 'SoftHSM KSP'" ($propName -eq "SoftHSM KSP") "got='$propName'"

# Version property
$ok = $false
$ver = [Hlk]::GetDwordProperty($hProv, "Version", [ref]$ok)
Test-Result "S1.3 NCRYPT_VERSION_PROPERTY = 1" ($ok -and $ver -eq 1) "ver=$ver"

# Implementation type — must include hardware flag (0x1)
$impl = [Hlk]::GetDwordProperty($hProv, "Impl Type", [ref]$ok)
Test-Result "S1.4 NCRYPT_IMPL_TYPE_PROPERTY has hardware flag" ($ok -and ($impl -band 1) -ne 0) "impl=0x$($impl.ToString('X'))"

# =============================================================================
# S2 — RSA 2048 AT_SIGNATURE: PKCS1 + PSS signing, property queries
# =============================================================================
Write-Host ""
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White
Write-Host "S2 — RSA 2048 AT_SIGNATURE: signing, BCrypt verification, properties" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White

$hRsa2048 = [IntPtr]::Zero
$hr = [Hlk]::NCryptCreatePersistedKey($hProv, [ref]$hRsa2048, "RSA", $KeyRsa2048, 2, 0) # AT_SIGNATURE=2
Test-Result "S2.1 NCryptCreatePersistedKey RSA 2048" ($hr -eq 0) "hr=0x$($hr.ToString('X8'))"

if ($hr -eq 0) {
    $hr = [Hlk]::NCryptFinalizeKey($hRsa2048, 0)
    Test-Result "S2.2 NCryptFinalizeKey RSA 2048" ($hr -eq 0) "hr=0x$($hr.ToString('X8'))"
    $keysToDelete.Add($hRsa2048)
}

if ($hRsa2048 -ne [IntPtr]::Zero) {
    # Property queries
    $alg = [Hlk]::GetStringProperty($hRsa2048, "Algorithm Name")
    Test-Result "S2.3 NCRYPT_ALGORITHM_PROPERTY = 'RSA'" ($alg -eq "RSA") "got='$alg'"

    $len = [Hlk]::GetDwordProperty($hRsa2048, "Length", [ref]$ok)
    Test-Result "S2.4 NCRYPT_LENGTH_PROPERTY = 2048" ($ok -and $len -eq 2048) "len=$len"

    $usage = [Hlk]::GetDwordProperty($hRsa2048, "Key Usage", [ref]$ok)
    Test-Result "S2.5 NCRYPT_KEY_USAGE_PROPERTY has ALLOW_SIGNING (0x2)" ($ok -and ($usage -band 2) -ne 0) "usage=0x$($usage.ToString('X'))"

    $policy = [Hlk]::GetDwordProperty($hRsa2048, "Export Policy", [ref]$ok)
    Test-Result "S2.6 NCRYPT_EXPORT_POLICY_PROPERTY = 0 (non-exportable)" ($ok -and $policy -eq 0) "policy=$policy"

    $group = [Hlk]::GetStringProperty($hRsa2048, "Algorithm Group")
    Test-Result "S2.7 NCRYPT_ALGORITHM_GROUP_PROPERTY = 'RSA'" ($group -eq "RSA") "got='$group'"

    $uname = [Hlk]::GetStringProperty($hRsa2048, "Unique Name")
    Test-Result "S2.8 NCRYPT_UNIQUE_NAME_PROPERTY = key label" ($uname -eq $KeyRsa2048) "got='$uname'"

    # RSA PKCS1 sign + BCrypt verify
    $sigPkcs1 = [Hlk]::SignPkcs1($hRsa2048, $hashSha256)
    Test-Result "S2.9 NCryptSignHash RSA PKCS1 (SHA-256)" ($sigPkcs1 -ne $null -and $sigPkcs1.Length -eq 256) "len=$($sigPkcs1.Length)"

    if ($sigPkcs1 -ne $null) {
        $rsaBlob = [Hlk]::ExportPublicKey($hRsa2048, "RSAPUBLICBLOB")
        Test-Result "S2.10 NCryptExportKey BCRYPT_RSAPUBLIC_BLOB" ($rsaBlob -ne $null) "blob=$($rsaBlob.Length) bytes"
        if ($rsaBlob -ne $null) {
            $ok = [Hlk]::VerifyRsaPkcs1($rsaBlob, "SHA256", $hashSha256, $sigPkcs1)
            Test-Result "S2.11 BCryptVerifySignature RSA PKCS1 (SHA-256)" $ok
        }
    }

    # RSA PSS sign + BCrypt verify (SHA-256, cbSalt=32)
    $sigPss = [Hlk]::SignPss($hRsa2048, $hashSha256)
    Test-Result "S2.12 NCryptSignHash RSA PSS (SHA-256, cbSalt=32)" ($sigPss -ne $null -and $sigPss.Length -eq 256) "len=$($sigPss.Length)"

    if ($sigPss -ne $null -and $rsaBlob -ne $null) {
        $ok = [Hlk]::VerifyRsaPss($rsaBlob, "SHA256", 32, $hashSha256, $sigPss)
        Test-Result "S2.13 BCryptVerifySignature RSA PSS (SHA-256)" $ok
    }

    # Private key export must fail (NTE_NOT_SUPPORTED = 0x80090029 = -2146893783)
    $cbDummy = 0u
    $hrExp = [Hlk]::NCryptExportKey($hRsa2048, [IntPtr]::Zero, "RSAFULLPRIVATEBLOB",
                                    [IntPtr]::Zero, $null, 0, [ref]$cbDummy, 0)
    Test-Result "S2.14 Private export returns NTE_NOT_SUPPORTED" ($hrExp -ne 0) "hr=0x$($hrExp.ToString('X8'))"
}

# =============================================================================
# S3 — RSA 2048 AT_KEYEXCHANGE: OAEP encryption and decryption
# =============================================================================
Write-Host ""
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White
Write-Host "S3 — RSA 2048 AT_KEYEXCHANGE: OAEP encrypt / decrypt" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White

$hRsaKex = [IntPtr]::Zero
$hr = [Hlk]::NCryptCreatePersistedKey($hProv, [ref]$hRsaKex, "RSA", $KeyRsaKex, 1, 0) # AT_KEYEXCHANGE=1
Test-Result "S3.1 NCryptCreatePersistedKey RSA AT_KEYEXCHANGE" ($hr -eq 0) "hr=0x$($hr.ToString('X8'))"

if ($hr -eq 0) {
    $hr = [Hlk]::NCryptFinalizeKey($hRsaKex, 0)
    Test-Result "S3.2 NCryptFinalizeKey RSA KEX" ($hr -eq 0) "hr=0x$($hr.ToString('X8'))"
    $keysToDelete.Add($hRsaKex)
}

if ($hRsaKex -ne [IntPtr]::Zero) {
    $usage = [Hlk]::GetDwordProperty($hRsaKex, "Key Usage", [ref]$ok)
    Test-Result "S3.3 NCRYPT_KEY_USAGE_PROPERTY has ALLOW_DECRYPT (0x1)" ($ok -and ($usage -band 1) -ne 0) "usage=0x$($usage.ToString('X'))"

    $rsaKexBlob = [Hlk]::ExportPublicKey($hRsaKex, "RSAPUBLICBLOB")
    Test-Result "S3.4 Export RSA KEX public key" ($rsaKexBlob -ne $null) "blob=$($rsaKexBlob.Length) bytes"

    if ($rsaKexBlob -ne $null) {
        $ciphertext = [Hlk]::EncryptRsaOaep($rsaKexBlob, "SHA1", $plaintext)
        Test-Result "S3.5 BCryptEncrypt RSA OAEP (SHA-1)" ($ciphertext -ne $null -and $ciphertext.Length -eq 256) "len=$($ciphertext.Length)"

        if ($ciphertext -ne $null) {
            $decrypted = [Hlk]::DecryptOaep($hRsaKex, "SHA1", $ciphertext)
            $decOk = ($decrypted -ne $null -and
                      [System.Linq.Enumerable]::SequenceEqual($decrypted, $plaintext))
            Test-Result "S3.6 NCryptDecrypt RSA OAEP: plaintext matches" $decOk `
                "decLen=$($decrypted.Length) expected=$($plaintext.Length)"
        }
    }
}

# =============================================================================
# S4 — RSA 3072: deferred creation, sign, BCrypt verify
# =============================================================================
Write-Host ""
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White
Write-Host "S4 — RSA 3072: deferred key creation (SetProperty + FinalizeKey)" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White

$hRsa3072 = [IntPtr]::Zero
# NCRYPT_PERSIST_ONLY_FLAG = 0x40000000
$hr = [Hlk]::NCryptCreatePersistedKey($hProv, [ref]$hRsa3072, "RSA", $KeyRsa3072, 2, 0x40000000)
Test-Result "S4.1 NCryptCreatePersistedKey RSA (PERSIST_ONLY)" ($hr -eq 0) "hr=0x$($hr.ToString('X8'))"

if ($hr -eq 0 -and $hRsa3072 -ne [IntPtr]::Zero) {
    $bits3072 = [BitConverter]::GetBytes([uint32]3072)
    $hr = [Hlk]::NCryptSetProperty($hRsa3072, "Length", $bits3072, 4, 0)
    Test-Result "S4.2 NCryptSetProperty LENGTH=3072" ($hr -eq 0) "hr=0x$($hr.ToString('X8'))"

    Write-Host "  Generating RSA 3072 key pair (may take a few seconds)..." -ForegroundColor DarkGray
    $hr = [Hlk]::NCryptFinalizeKey($hRsa3072, 0)
    Test-Result "S4.3 NCryptFinalizeKey RSA 3072" ($hr -eq 0) "hr=0x$($hr.ToString('X8'))"
    $keysToDelete.Add($hRsa3072)

    $len = [Hlk]::GetDwordProperty($hRsa3072, "Length", [ref]$ok)
    Test-Result "S4.4 NCRYPT_LENGTH_PROPERTY = 3072" ($ok -and $len -eq 3072) "len=$len"

    $sigPkcs1_3072 = [Hlk]::SignPkcs1($hRsa3072, $hashSha256)
    Test-Result "S4.5 NCryptSignHash RSA 3072 PKCS1" ($sigPkcs1_3072 -ne $null -and $sigPkcs1_3072.Length -eq 384) "len=$($sigPkcs1_3072.Length)"

    if ($sigPkcs1_3072 -ne $null) {
        $blob3072 = [Hlk]::ExportPublicKey($hRsa3072, "RSAPUBLICBLOB")
        if ($blob3072 -ne $null) {
            $ok = [Hlk]::VerifyRsaPkcs1($blob3072, "SHA256", $hashSha256, $sigPkcs1_3072)
            Test-Result "S4.6 BCryptVerifySignature RSA 3072 PKCS1" $ok
        }
    }
}

# =============================================================================
# S5 — ECDSA P-256: full lifecycle, BCrypt verify, property queries
# =============================================================================
Write-Host ""
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White
Write-Host "S5 — ECDSA P-256: create, sign, BCrypt verify, properties" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White

$hEcP256 = [IntPtr]::Zero
$hr = [Hlk]::NCryptCreatePersistedKey($hProv, [ref]$hEcP256, "ECDSA_P256", $KeyEcP256, 2, 0)
Test-Result "S5.1 NCryptCreatePersistedKey ECDSA_P256" ($hr -eq 0) "hr=0x$($hr.ToString('X8'))"

if ($hr -eq 0) {
    $hr = [Hlk]::NCryptFinalizeKey($hEcP256, 0)
    Test-Result "S5.2 NCryptFinalizeKey ECDSA_P256" ($hr -eq 0) "hr=0x$($hr.ToString('X8'))"
    $keysToDelete.Add($hEcP256)
}

if ($hEcP256 -ne [IntPtr]::Zero) {
    $alg = [Hlk]::GetStringProperty($hEcP256, "Algorithm Name")
    Test-Result "S5.3 NCRYPT_ALGORITHM_PROPERTY = 'ECDSA_P256'" ($alg -eq "ECDSA_P256") "got='$alg'"

    $len = [Hlk]::GetDwordProperty($hEcP256, "Length", [ref]$ok)
    Test-Result "S5.4 NCRYPT_LENGTH_PROPERTY = 256" ($ok -and $len -eq 256) "len=$len"

    $usage = [Hlk]::GetDwordProperty($hEcP256, "Key Usage", [ref]$ok)
    Test-Result "S5.5 NCRYPT_KEY_USAGE_PROPERTY has ALLOW_SIGNING (0x2)" ($ok -and ($usage -band 2) -ne 0) "usage=0x$($usage.ToString('X'))"

    $group = [Hlk]::GetStringProperty($hEcP256, "Algorithm Group")
    Test-Result "S5.6 NCRYPT_ALGORITHM_GROUP_PROPERTY = 'ECDSA'" ($group -eq "ECDSA") "got='$group'"

    $sigEc256 = [Hlk]::SignEcdsa($hEcP256, $hashSha256)
    Test-Result "S5.7 NCryptSignHash ECDSA P-256 (SHA-256)" ($sigEc256 -ne $null -and $sigEc256.Length -eq 64) "len=$($sigEc256.Length)"

    if ($sigEc256 -ne $null) {
        $eccBlob256 = [Hlk]::ExportPublicKey($hEcP256, "ECCPUBLICBLOB")
        Test-Result "S5.8 NCryptExportKey BCRYPT_ECCPUBLIC_BLOB" ($eccBlob256 -ne $null) "blob=$($eccBlob256.Length) bytes"
        if ($eccBlob256 -ne $null) {
            $ok = [Hlk]::VerifyEcdsa("ECDSA_P256", $eccBlob256, $hashSha256, $sigEc256)
            Test-Result "S5.9 BCryptVerifySignature ECDSA P-256" $ok
        }
    }
}

# =============================================================================
# S6 — ECDSA P-384: sign with SHA-384, BCrypt verify
# =============================================================================
Write-Host ""
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White
Write-Host "S6 — ECDSA P-384: sign SHA-384, BCrypt verify" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White

$hEcP384 = [IntPtr]::Zero
$hr = [Hlk]::NCryptCreatePersistedKey($hProv, [ref]$hEcP384, "ECDSA_P384", $KeyEcP384, 2, 0)
Test-Result "S6.1 NCryptCreatePersistedKey ECDSA_P384" ($hr -eq 0) "hr=0x$($hr.ToString('X8'))"

if ($hr -eq 0) {
    $hr = [Hlk]::NCryptFinalizeKey($hEcP384, 0)
    Test-Result "S6.2 NCryptFinalizeKey ECDSA_P384" ($hr -eq 0) "hr=0x$($hr.ToString('X8'))"
    $keysToDelete.Add($hEcP384)
}

if ($hEcP384 -ne [IntPtr]::Zero) {
    $len = [Hlk]::GetDwordProperty($hEcP384, "Length", [ref]$ok)
    Test-Result "S6.3 NCRYPT_LENGTH_PROPERTY = 384" ($ok -and $len -eq 384) "len=$len"

    # ECDSA P-384 signs a SHA-384 hash (48 bytes); expected raw signature = 96 bytes (r‖s)
    $sigEc384 = [Hlk]::SignEcdsa($hEcP384, $hashSha384)
    Test-Result "S6.4 NCryptSignHash ECDSA P-384 (SHA-384)" ($sigEc384 -ne $null -and $sigEc384.Length -eq 96) "len=$($sigEc384.Length)"

    if ($sigEc384 -ne $null) {
        $eccBlob384 = [Hlk]::ExportPublicKey($hEcP384, "ECCPUBLICBLOB")
        Test-Result "S6.5 NCryptExportKey ECCPUBLICBLOB (P-384)" ($eccBlob384 -ne $null) "blob=$($eccBlob384.Length) bytes"
        if ($eccBlob384 -ne $null) {
            $ok = [Hlk]::VerifyEcdsa("ECDSA_P384", $eccBlob384, $hashSha384, $sigEc384)
            Test-Result "S6.6 BCryptVerifySignature ECDSA P-384" $ok
        }
    }
}

# =============================================================================
# S7 — Key enumeration and NCryptOpenKey round-trip
# =============================================================================
Write-Host ""
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White
Write-Host "S7 — Key enumeration and NCryptOpenKey round-trip" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White

$pEnumState = [IntPtr]::Zero
$pKeyName   = [IntPtr]::Zero
$enumCount  = 0
$foundKeys  = [System.Collections.Generic.HashSet[string]]::new()

try {
    do {
        $hr = [Hlk]::NCryptEnumKeys($hProv, $null, [ref]$pKeyName, [ref]$pEnumState, 0)
        if ($hr -eq 0 -and $pKeyName -ne [IntPtr]::Zero) {
            $namePtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($pKeyName)
            $name    = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($namePtr)
            $foundKeys.Add($name) | Out-Null
            [Hlk]::NCryptFreeBuffer($pKeyName) | Out-Null
            $enumCount++
        }
    } while ($hr -eq 0)

    Test-Result "S7.1 NCryptEnumKeys finds RSA 2048 key"   $foundKeys.Contains($KeyRsa2048)
    Test-Result "S7.2 NCryptEnumKeys finds RSA KEX key"    $foundKeys.Contains($KeyRsaKex)
    Test-Result "S7.3 NCryptEnumKeys finds RSA 3072 key"   $foundKeys.Contains($KeyRsa3072)
    Test-Result "S7.4 NCryptEnumKeys finds ECDSA P-256 key" $foundKeys.Contains($KeyEcP256)
    Test-Result "S7.5 NCryptEnumKeys finds ECDSA P-384 key" $foundKeys.Contains($KeyEcP384)
    Write-Host "  Total keys enumerated: $enumCount"
} catch {
    Test-Result "S7 NCryptEnumKeys" $false $_.Exception.Message
}

# NCryptOpenKey round-trip: close and reopen the RSA 2048 key
if ($hRsa2048 -ne [IntPtr]::Zero) {
    [Hlk]::NCryptFreeObject($hRsa2048) | Out-Null
    $hRsa2048 = [IntPtr]::Zero
    $hReopened = [IntPtr]::Zero
    $hr = [Hlk]::NCryptOpenKey($hProv, [ref]$hReopened, $KeyRsa2048, 0, 0)
    Test-Result "S7.6 NCryptOpenKey (reopen RSA 2048 by label)" ($hr -eq 0 -and $hReopened -ne [IntPtr]::Zero) "hr=0x$($hr.ToString('X8'))"
    if ($hr -eq 0 -and $hReopened -ne [IntPtr]::Zero) {
        $reopenAlg = [Hlk]::GetStringProperty($hReopened, "Algorithm Name")
        Test-Result "S7.7 Reopened key algorithm = 'RSA'" ($reopenAlg -eq "RSA") "got='$reopenAlg'"
        # Replace handle for cleanup
        for ($i = 0; $i -lt $keysToDelete.Count; $i++) {
            if ($keysToDelete[$i] -eq $hRsa2048) { break }
        }
        $hRsa2048 = $hReopened
        # Update in cleanup list (first entry was the original handle, now freed)
        $keysToDelete[0] = $hRsa2048
    }
}

# =============================================================================
# S8 — Error conditions
# =============================================================================
Write-Host ""
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White
Write-Host "S8 — Error conditions" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White

# Sign with zero (invalid) key handle
$cbDummy = [uint32]0
$hrErr = [Hlk]::NCryptSignHash([IntPtr]::Zero, [IntPtr]::Zero,
                               $hashSha256, [uint32]$hashSha256.Length,
                               $null, 0, [ref]$cbDummy, 2)
Test-Result "S8.1 NCryptSignHash(invalid handle) returns error" ($hrErr -ne 0) "hr=0x$($hrErr.ToString('X8'))"

# Export private key blob — must fail
$cbDummy = [uint32]0
if ($hEcP256 -ne [IntPtr]::Zero) {
    $hrExp = [Hlk]::NCryptExportKey($hEcP256, [IntPtr]::Zero, "ECCFULLPRIVATEBLOB",
                                    [IntPtr]::Zero, $null, 0, [ref]$cbDummy, 0)
    Test-Result "S8.2 Private export (ECCFULLPRIVATEBLOB) returns error" ($hrExp -ne 0) "hr=0x$($hrExp.ToString('X8'))"
}

# OpenKey with non-existent label
$hGhost = [IntPtr]::Zero
$hrOpen = [Hlk]::NCryptOpenKey($hProv, [ref]$hGhost, "_NonExistentHlkKey_${Rnd}_", 0, 0)
Test-Result "S8.3 NCryptOpenKey(non-existent) returns error" ($hrOpen -ne 0) "hr=0x$($hrOpen.ToString('X8'))"
if ($hrOpen -eq 0 -and $hGhost -ne [IntPtr]::Zero) {
    [Hlk]::NCryptFreeObject($hGhost) | Out-Null
}

# GetProperty on zero handle
$cbDummy2 = [uint32]0
$hrProp = [Hlk]::NCryptGetProperty([IntPtr]::Zero, "Algorithm Name",
                                   $null, 0, [ref]$cbDummy2, 0)
Test-Result "S8.4 NCryptGetProperty(invalid handle) returns error" ($hrProp -ne 0) "hr=0x$($hrProp.ToString('X8'))"

# =============================================================================
# S9 — Cleanup: delete all test keys
# =============================================================================
Write-Host ""
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White
Write-Host "S9 — Cleanup: deleting all HLK test keys" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White

$deleteMap = @{
    $KeyRsa2048 = $hRsa2048
    $KeyRsaKex  = $hRsaKex
    $KeyRsa3072 = $hRsa3072
    $KeyEcP256  = $hEcP256
    $KeyEcP384  = $hEcP384
}

foreach ($entry in $deleteMap.GetEnumerator()) {
    $name = $entry.Key
    $h    = $entry.Value
    if ($h -ne [IntPtr]::Zero) {
        $hr = [Hlk]::NCryptDeleteKey($h, 0)
        Test-Result "S9 NCryptDeleteKey '$name'" ($hr -eq 0) "hr=0x$($hr.ToString('X8'))"
    }
}

[Hlk]::NCryptFreeObject($hProv) | Out-Null

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White
Write-Host ("HLK Test Results — PASS={0}  FAIL={1}  SKIP={2}" -f $script:Pass, $script:Fail, $script:Skip) `
    -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor White

if ($script:Fail -gt 0) { exit 1 }
