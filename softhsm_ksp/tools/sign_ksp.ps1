#Requires -Version 5.1
<#
.SYNOPSIS
    Authenticode-sign softhsm_ksp.dll, timestamp it, and verify the result.

.DESCRIPTION
    Microsoft does not sign cryptographic providers — that programme was
    retired at Windows 8, and the mailboxes for it are dead. A CNG provider
    is signed by its author with a commercial code-signing certificate, like
    any other DLL. See docs/10-hlk-execution.md.

    This script does not obtain a certificate; nothing can automate that.
    What it does is make the signing itself a single, checked step, so that
    the day a certificate arrives there is no procedure left to work out.

    Three certificate sources, in the order you are likely to use them:

      -Thumbprint       a certificate already in the Windows store, which is
                        how an EV certificate on a hardware token appears
      -PfxPath          a PFX file; the password comes from the
                        KSP_SIGN_PFX_PASSWORD environment variable, never a
                        parameter
      -AzureTrustedSigning  Azure Trusted Signing, which is how most CI
                        signs today since EV certificates are bound to
                        hardware tokens that a build agent cannot hold

.PARAMETER DllPath
    File to sign. Defaults to the Release build output.

.PARAMETER Thumbprint
    SHA-1 thumbprint of a certificate in the current user or machine store.

.PARAMETER PfxPath
    Path to a PFX. The password is read from KSP_SIGN_PFX_PASSWORD.

.PARAMETER AzureTrustedSigning
    Sign through Azure Trusted Signing using an azure-trusted-signing
    metadata file given by -AzureMetadata.

.PARAMETER AzureMetadata
    Path to the Azure Trusted Signing JSON metadata file.

.PARAMETER TimestampUrl
    RFC 3161 timestamp authority. Defaults to DigiCert's.

.PARAMETER VerifyOnly
    Do not sign; only report whether the file already carries a valid,
    timestamped signature.

.EXAMPLE
    # A certificate already in the store (EV token, or an imported OV cert)
    .\sign_ksp.ps1 -Thumbprint A1B2C3...

.EXAMPLE
    # A PFX, with the password kept out of the command line
    $env:KSP_SIGN_PFX_PASSWORD = Read-Host -AsSecureString | ConvertFrom-SecureString -AsPlainText
    .\sign_ksp.ps1 -PfxPath .\codesign.pfx

.EXAMPLE
    # Check what a build already carries
    .\sign_ksp.ps1 -VerifyOnly

.NOTES
    A signature without a timestamp stops validating the day the
    certificate expires, taking every copy of the DLL already deployed with
    it. This script therefore always timestamps and treats a missing
    timestamp as a failure, not a warning.
#>

[CmdletBinding(DefaultParameterSetName = 'Store')]
param(
    [string]$DllPath = (Join-Path $PSScriptRoot '..\build\Release\softhsm_ksp.dll'),

    [Parameter(ParameterSetName = 'Store')]
    [string]$Thumbprint,

    [Parameter(ParameterSetName = 'Pfx', Mandatory = $true)]
    [string]$PfxPath,

    [Parameter(ParameterSetName = 'Azure', Mandatory = $true)]
    [switch]$AzureTrustedSigning,

    [Parameter(ParameterSetName = 'Azure', Mandatory = $true)]
    [string]$AzureMetadata,

    [string]$TimestampUrl = 'http://timestamp.digicert.com',

    [switch]$VerifyOnly
)

$ErrorActionPreference = 'Stop'

# ── Locate signtool ──────────────────────────────────────────────────────
# signtool is not on PATH by default; it lives in the Windows SDK, and the
# newest version wins because older ones predate some timestamp algorithms.
function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $roots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin"
    ) | Where-Object { Test-Path $_ }

    $found = foreach ($r in $roots) {
        Get-ChildItem -Path $r -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' }
    }

    if (-not $found) {
        throw "signtool.exe not found. It ships with the Windows SDK; " +
              "install the SDK or add signtool to PATH."
    }

    ($found | Sort-Object FullName -Descending | Select-Object -First 1).FullName
}

function Test-Signature {
    param([string]$Tool, [string]$Path)

    # /pa uses the Authenticode policy rather than the driver one; a KSP is
    # a user-mode DLL, not a driver.
    $output = & $Tool verify /pa /v $Path 2>&1
    $ok = ($LASTEXITCODE -eq 0)

    # An expired certificate with no timestamp verifies today and fails
    # tomorrow, so the timestamp is checked explicitly rather than trusted
    # to be there.
    $timestamped = ($output | Select-String -Quiet -Pattern 'Timestamp|The signature is timestamped')

    [pscustomobject]@{
        Valid       = $ok
        Timestamped = [bool]$timestamped
        Output      = ($output -join [Environment]::NewLine)
    }
}

# ── Main ─────────────────────────────────────────────────────────────────
if (-not (Test-Path $DllPath)) {
    throw "Not found: $DllPath`nBuild first, or pass -DllPath."
}
$DllPath = (Resolve-Path $DllPath).Path

$signtool = Find-SignTool
Write-Host "signtool : $signtool"
Write-Host "file     : $DllPath"

if ($VerifyOnly) {
    $r = Test-Signature -Tool $signtool -Path $DllPath
    Write-Host ''
    Write-Host $r.Output
    if (-not $r.Valid) {
        Write-Host ''
        Write-Host 'UNSIGNED or INVALID.'
        exit 1
    }
    if (-not $r.Timestamped) {
        Write-Host ''
        Write-Host 'SIGNED BUT NOT TIMESTAMPED — the signature will stop'
        Write-Host 'validating when the certificate expires.'
        exit 1
    }
    Write-Host ''
    Write-Host 'Signed and timestamped.'
    exit 0
}

# Build the signtool arguments for whichever certificate source was chosen.
$signArgs = @('sign', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256', '/v')

switch ($PSCmdlet.ParameterSetName) {
    'Store' {
        if ($Thumbprint) {
            $signArgs += @('/sha1', $Thumbprint)
        } else {
            # /a picks the best available signing certificate in the store.
            # Fine for a machine with exactly one; ambiguous otherwise,
            # which is why -Thumbprint exists.
            $signArgs += '/a'
        }
    }
    'Pfx' {
        if (-not (Test-Path $PfxPath)) { throw "PFX not found: $PfxPath" }
        $pw = $env:KSP_SIGN_PFX_PASSWORD
        if ([string]::IsNullOrEmpty($pw)) {
            throw "Set KSP_SIGN_PFX_PASSWORD before signing with a PFX. " +
                  "It is read from the environment rather than taken as a " +
                  "parameter so it does not land in shell history or a " +
                  "process listing."
        }
        $signArgs += @('/f', (Resolve-Path $PfxPath).Path, '/p', $pw)
    }
    'Azure' {
        if (-not (Test-Path $AzureMetadata)) {
            throw "Azure metadata not found: $AzureMetadata"
        }
        # Azure Trusted Signing plugs into signtool as a dlib. Most CI uses
        # this now: EV certificates live on hardware tokens a build agent
        # cannot hold.
        $dlib = "${env:ProgramFiles}\Microsoft SDKs\Azure\Azure.CodeSigning.Dlib\bin\x64\Azure.CodeSigning.Dlib.dll"
        if (-not (Test-Path $dlib)) {
            throw "Azure.CodeSigning.Dlib not found at $dlib. Install the " +
                  "Trusted Signing client tools."
        }
        $signArgs += @('/dlib', $dlib, '/dmdf', (Resolve-Path $AzureMetadata).Path)
    }
}

$signArgs += $DllPath

Write-Host ''
Write-Host 'Signing...'
& $signtool @signArgs
if ($LASTEXITCODE -ne 0) {
    throw "signtool sign failed with exit code $LASTEXITCODE"
}

# Signing that reports success but leaves an unusable signature is the
# failure worth catching, so the result is always read back.
Write-Host ''
Write-Host 'Verifying...'
$r = Test-Signature -Tool $signtool -Path $DllPath
Write-Host $r.Output

if (-not $r.Valid) {
    throw 'Signed, but verification failed.'
}
if (-not $r.Timestamped) {
    throw 'Signed, but no timestamp was applied. Refusing to call this done.'
}

Write-Host ''
Write-Host 'Signed and timestamped.'
