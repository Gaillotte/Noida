<#
.SYNOPSIS
    Provision the token PIN for the SoftHSM KSP as a DPAPI-protected blob.

.DESCRIPTION
    ADCS readiness plan, option C-b. A headless certsrv never calls
    NCryptSetProperty(NCRYPT_PIN_PROPERTY), so without this the only
    credential route for a service is a machine-wide environment variable
    that every process on the host can read. For a CA that inverts the
    model the HSM was bought for: the key cannot be extracted, but anyone
    on the box can ask the token to sign, and signing is the asset.

    The PIN is encrypted with CryptProtectData at CRYPTPROTECT_LOCAL_MACHINE
    scope and written as a REG_BINARY value under HKLM.

    THE ACL IS THE PROTECTION, NOT THE ENCRYPTION. Machine-scope DPAPI can
    be unprotected by anything running on this host. What stops that is
    being unable to READ the registry value, so -ServiceAccount is not
    optional in a real deployment: without it this script leaves the blob
    readable by every local account and the result is no better than the
    environment variable it replaces. The script says so if you omit it.

.PARAMETER Scope
    Machine or User. Matches the provider's per-scope tokens: the machine
    scope is the one a CA uses.

.PARAMETER ServiceAccount
    The account that runs certsrv, e.g. 'NT Service\\CertSvc'. The registry
    value is ACL'd to it plus Administrators, and inheritance is removed.

.PARAMETER Remove
    Delete the provisioned blob for the chosen scope.

.EXAMPLE
    .\set_ksp_pin.ps1 -Scope Machine -ServiceAccount 'NT Service\CertSvc'

.NOTES
    NOT YET RUN ON WINDOWS. This script and the provider code that reads
    the blob are both unproven until ADCS plan Phase B provides a machine.
    It parses and its logic is reviewable; that is not the same claim.
#>
[CmdletBinding()]
param(
    [ValidateSet('Machine', 'User')]
    [string] $Scope = 'Machine',

    [string] $ServiceAccount,

    [switch] $Remove
)

$ErrorActionPreference = 'Stop'

# Must match src/common/config.h — KSP_PIN_BLOB_KEY and the value names.
$RegPath    = 'HKLM:\SOFTWARE\SoftHSM KSP'
$ValueName  = if ($Scope -eq 'Machine') { 'MachinePinBlob' } else { 'UserPinBlob' }

# P11_MAX_PIN_LEN in config.h. The provider REFUSES an over-long PIN rather
# than truncating it, so refusing here too means the failure is reported
# while an administrator is standing in front of it, not at service start.
$MaxPinLen  = 127

Add-Type -AssemblyName System.Security

if ($Remove) {
    if (Test-Path $RegPath) {
        Remove-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
        Write-Host "Removed $ValueName from $RegPath"
    } else {
        Write-Host "Nothing to remove: $RegPath does not exist"
    }
    return
}

if (-not $ServiceAccount) {
    Write-Warning @"
No -ServiceAccount given, so the registry value will inherit the default
ACL and any local account can read it. Machine-scope DPAPI can then be
unprotected by anything on this host, which leaves you no better off than
the environment variable this replaces. Provision with -ServiceAccount for
anything that is not a scratch lab.
"@
}

# Read the PIN without echoing it and without it appearing in the command
# line, where it would reach the process list and the PowerShell history.
$secure = Read-Host -AsSecureString "Token PIN for the $Scope scope"
$bstr   = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $pin = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

if ([string]::IsNullOrEmpty($pin)) {
    throw "Empty PIN. The provider refuses an empty credential, so this would not work."
}

# The provider stores and compares bytes, so bound the BYTE count, not the
# character count: a non-ASCII PIN is longer in UTF-8 than it looks.
$bytes = [Text.Encoding]::UTF8.GetBytes($pin)
if ($bytes.Length -gt $MaxPinLen) {
    throw ("PIN is $($bytes.Length) bytes; the provider's limit is $MaxPinLen " +
           "and it REFUSES rather than truncating. Shorten it.")
}

$blob = [Security.Cryptography.ProtectedData]::Protect(
            $bytes, $null,
            [Security.Cryptography.DataProtectionScope]::LocalMachine)

# Clear the plaintext copies we control. The .NET string cannot be wiped —
# that is a limitation of doing this in PowerShell, and it is why the blob,
# not this script's process, is the thing that has to be right.
[Array]::Clear($bytes, 0, $bytes.Length)
$pin = $null

if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
New-ItemProperty -Path $RegPath -Name $ValueName -Value $blob `
                 -PropertyType Binary -Force | Out-Null

Write-Host "Wrote $($blob.Length)-byte blob to $RegPath\$ValueName"

if ($ServiceAccount) {
    # Break inheritance, then grant only the service account and the local
    # Administrators group. Done on the KEY: Windows has no per-VALUE ACL.
    $acl = Get-Acl $RegPath
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRule($rule) | Out-Null }

    foreach ($id in @($ServiceAccount, 'BUILTIN\Administrators')) {
        $acl.AddAccessRule(
            (New-Object Security.AccessControl.RegistryAccessRule(
                $id, 'ReadKey', 'ContainerInherit,ObjectInherit',
                'None', 'Allow')))
    }
    # Administrators also need to be able to re-provision.
    $acl.AddAccessRule(
        (New-Object Security.AccessControl.RegistryAccessRule(
            'BUILTIN\Administrators', 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow')))

    Set-Acl -Path $RegPath -AclObject $acl
    Write-Host "ACL set: read for $ServiceAccount and Administrators only"
}

Write-Host ""
Write-Host "The provider prefers this blob over SOFTHSM2_PIN. Remove that"
Write-Host "variable if it is still set, or you will not be able to tell"
Write-Host "which credential a successful login actually used."
