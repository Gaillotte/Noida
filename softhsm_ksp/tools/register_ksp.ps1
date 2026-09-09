#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Registers the SoftHSM KSP with Windows CNG.

.DESCRIPTION
    Registration has two distinct parts, and both are required for the
    provider to be fully usable:

      1. The provider binary. BCryptRegisterProvider records the DLL under
         HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers and
         makes NCryptOpenStorageProvider able to load it by name.

      2. The algorithm list. BCryptAddContextFunctionProvider publishes which
         algorithms the provider implements, so that enumeration APIs
         (NCryptEnumAlgorithms, certificate-request UIs, certutil) can see
         them. Writing the "Image" and "Type" registry values by hand covers
         only part 1: the provider loads, but reports no algorithms, and
         anything that discovers providers by algorithm will skip it.

    This script performs both, using the documented CNG APIs rather than raw
    registry writes, so that the on-disk layout stays whatever the running
    version of Windows expects.

.PARAMETER DllPath
    Absolute path to softhsm_ksp.dll. Defaults to the current directory.

.PARAMETER Unregister
    Remove the provider and its algorithm registrations instead of adding
    them.

.EXAMPLE
    .\register_ksp.ps1 -DllPath "C:\KSP\softhsm_ksp.dll"

.EXAMPLE
    .\register_ksp.ps1 -Unregister

.NOTES
    Run from an elevated prompt. CNG reads the provider list at process
    start, so applications already running must be restarted before they
    see a newly registered provider.
#>

param(
    [string]$DllPath = (Join-Path (Get-Location) "softhsm_ksp.dll"),
    [switch]$Unregister
)

$ErrorActionPreference = "Stop"

$ProviderName = "SoftHSM KSP"

# Algorithms this KSP implements, grouped by the CNG interface they belong
# to. Only identifiers CNG actually defines are listed here: the KSP also
# supports EdDSA and HMAC, but CNG has no algorithm identifier for those, so
# they cannot be published to the enumeration APIs and are reachable only
# from an application coded against this provider directly.
$SignatureAlgorithms = @("RSA", "ECDSA_P256", "ECDSA_P384", "ECDSA_P521")
$SecretAgreementAlgorithms = @("ECDH_P256", "ECDH_P384", "ECDH_P521")
$CipherAlgorithms = @("AES")

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CngRegistration
{
    // CRYPT_PROVIDER_REG / CRYPT_IMAGE_REG as declared in bcrypt.h.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CRYPT_INTERFACE_REG
    {
        public uint   dwInterface;
        public uint   dwFlags;
        public uint   cFunctions;
        public IntPtr rgpszFunctions;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CRYPT_IMAGE_REG
    {
        public IntPtr pszImage;
        public uint   cInterfaces;
        public IntPtr rgpInterfaces;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CRYPT_PROVIDER_REG
    {
        public uint   cAliases;
        public IntPtr rgpszAliases;
        public IntPtr pUM;
        public IntPtr pKM;
    }

    public const uint NCRYPT_KEY_STORAGE_INTERFACE = 0x00010001;

    public const uint CRYPT_LOCAL      = 0x00000001;
    public const uint CRYPT_ANY        = 0x00000004;
    public const uint CRYPT_PRIORITY_TOP = 0x00000000;

    public const uint BCRYPT_CIPHER_INTERFACE           = 0x00000001;
    public const uint BCRYPT_SIGNATURE_INTERFACE        = 0x00000005;
    public const uint BCRYPT_SECRET_AGREEMENT_INTERFACE = 0x00000004;

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern uint BCryptRegisterProvider(
        string pszProvider, uint dwFlags, ref CRYPT_PROVIDER_REG pReg);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern uint BCryptUnregisterProvider(string pszProvider);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern uint BCryptAddContextFunctionProvider(
        uint dwTable, string pszContext, uint dwInterface,
        string pszFunction, string pszProvider, uint dwPosition);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern uint BCryptRemoveContextFunctionProvider(
        uint dwTable, string pszContext, uint dwInterface,
        string pszFunction, string pszProvider);

    // Registers the provider binary and declares that it implements the
    // key-storage interface.
    public static uint RegisterProvider(string provider, string imagePath)
    {
        IntPtr pImage     = IntPtr.Zero;
        IntPtr pIfaceArr  = IntPtr.Zero;
        IntPtr pIface     = IntPtr.Zero;
        IntPtr pImageReg  = IntPtr.Zero;

        try
        {
            CRYPT_INTERFACE_REG iface = new CRYPT_INTERFACE_REG();
            iface.dwInterface    = NCRYPT_KEY_STORAGE_INTERFACE;
            iface.dwFlags        = CRYPT_LOCAL;
            iface.cFunctions     = 0;
            iface.rgpszFunctions = IntPtr.Zero;

            pIface = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CRYPT_INTERFACE_REG)));
            Marshal.StructureToPtr(iface, pIface, false);

            pIfaceArr = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pIfaceArr, 0, pIface);

            pImage = Marshal.StringToHGlobalUni(imagePath);

            CRYPT_IMAGE_REG imageReg = new CRYPT_IMAGE_REG();
            imageReg.pszImage      = pImage;
            imageReg.cInterfaces   = 1;
            imageReg.rgpInterfaces = pIfaceArr;

            pImageReg = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CRYPT_IMAGE_REG)));
            Marshal.StructureToPtr(imageReg, pImageReg, false);

            CRYPT_PROVIDER_REG reg = new CRYPT_PROVIDER_REG();
            reg.cAliases     = 0;
            reg.rgpszAliases = IntPtr.Zero;
            reg.pUM          = pImageReg;   // user mode
            reg.pKM          = IntPtr.Zero; // no kernel-mode image

            return BCryptRegisterProvider(provider, 0, ref reg);
        }
        finally
        {
            if (pImageReg != IntPtr.Zero) Marshal.FreeHGlobal(pImageReg);
            if (pImage    != IntPtr.Zero) Marshal.FreeHGlobal(pImage);
            if (pIfaceArr != IntPtr.Zero) Marshal.FreeHGlobal(pIfaceArr);
            if (pIface    != IntPtr.Zero) Marshal.FreeHGlobal(pIface);
        }
    }
}
"@

function Test-NtStatus {
    param([uint32]$Status, [string]$What)
    # BCrypt returns NTSTATUS; 0 is STATUS_SUCCESS.
    if ($Status -ne 0) {
        throw ("{0} failed with NTSTATUS 0x{1:X8}" -f $What, $Status)
    }
}

if ($Unregister) {
    Write-Host "Unregistering $ProviderName ..."

    # Remove the algorithm registrations first, then the provider itself, so
    # no context entry is left pointing at a provider that no longer exists.
    $groups = @(
        @{ Interface = [CngRegistration]::BCRYPT_SIGNATURE_INTERFACE
           Algorithms = $SignatureAlgorithms }
        @{ Interface = [CngRegistration]::BCRYPT_SECRET_AGREEMENT_INTERFACE
           Algorithms = $SecretAgreementAlgorithms }
        @{ Interface = [CngRegistration]::BCRYPT_CIPHER_INTERFACE
           Algorithms = $CipherAlgorithms }
    )

    foreach ($g in $groups) {
        foreach ($alg in $g.Algorithms) {
            $rc = [CngRegistration]::BCryptRemoveContextFunctionProvider(
                [CngRegistration]::CRYPT_LOCAL, "Default",
                [uint32]$g.Interface, $alg, $ProviderName)
            # A missing entry is not an error when unregistering.
            if ($rc -ne 0) {
                Write-Host ("  (skipped {0}: 0x{1:X8})" -f $alg, $rc)
            }
        }
    }

    $rc = [CngRegistration]::BCryptUnregisterProvider($ProviderName)
    Test-NtStatus $rc "BCryptUnregisterProvider"

    Write-Host "Unregistered."
    return
}

if (-not (Test-Path $DllPath)) {
    Write-Error "DLL not found: $DllPath"
    exit 1
}

$DllPath = (Resolve-Path $DllPath).Path

Write-Host "Registering $ProviderName ..."
Write-Host "  DLL : $DllPath"

# Step 1 — the provider binary.
$rc = [CngRegistration]::RegisterProvider($ProviderName, $DllPath)
Test-NtStatus $rc "BCryptRegisterProvider"
Write-Host "  Provider registered."

# Step 2 — the algorithms, so the provider is discoverable by algorithm and
# not merely loadable by name.
$groups = @(
    @{ Name = "signature"
       Interface = [CngRegistration]::BCRYPT_SIGNATURE_INTERFACE
       Algorithms = $SignatureAlgorithms }
    @{ Name = "secret agreement"
       Interface = [CngRegistration]::BCRYPT_SECRET_AGREEMENT_INTERFACE
       Algorithms = $SecretAgreementAlgorithms }
    @{ Name = "cipher"
       Interface = [CngRegistration]::BCRYPT_CIPHER_INTERFACE
       Algorithms = $CipherAlgorithms }
)

foreach ($g in $groups) {
    foreach ($alg in $g.Algorithms) {
        $rc = [CngRegistration]::BCryptAddContextFunctionProvider(
            [CngRegistration]::CRYPT_LOCAL, "Default",
            [uint32]$g.Interface, $alg, $ProviderName,
            [CngRegistration]::CRYPT_PRIORITY_TOP)
        Test-NtStatus $rc ("BCryptAddContextFunctionProvider($alg)")
        Write-Host ("  + {0} ({1})" -f $alg, $g.Name)
    }
}

Write-Host ""
Write-Host "Registration complete."
Write-Host ""
Write-Host "To verify:"
Write-Host "  certutil -csplist | Select-String 'SoftHSM'"
Write-Host ""
Write-Host "To unregister:"
Write-Host "  .\register_ksp.ps1 -Unregister"
