<#
.SYNOPSIS
    Validate tools/test_cng_hlk.ps1 without a Windows machine.

.DESCRIPTION
    The HLK suite only *runs* on Windows against a registered KSP, but two
    classes of bug in it can be caught anywhere PowerShell runs:

      1. PowerShell parse errors.
      2. C# compile errors in the embedded P/Invoke block — most commonly a
         length argument typed as int where the declaration says uint.

    This script parses the suite and compiles its embedded C# block, then
    exercises the pure byte-comparison helpers. It touches no Windows DLL,
    so it runs on Linux, macOS or Windows with PowerShell 7+.

.EXAMPLE
    pwsh -File tools/validate_hlk_script.ps1
#>

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$target    = Join-Path $scriptDir 'test_cng_hlk.ps1'

if (-not (Test-Path $target)) {
    Write-Host "Target not found: $target" -ForegroundColor Red
    exit 2
}

$failures = 0

# ── 1. Parse the suite ────────────────────────────────────────────────────
Write-Host '── Parsing test_cng_hlk.ps1 ──' -ForegroundColor Cyan
$errors = $null
$tokens = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    $target, [ref]$tokens, [ref]$errors) | Out-Null

if ($errors.Count -gt 0) {
    Write-Host "  $($errors.Count) parse error(s):" -ForegroundColor Red
    $errors | Select-Object -First 10 | ForEach-Object {
        Write-Host ("    line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message)
    }
    $failures++
} else {
    Write-Host "  OK — parsed cleanly ($($tokens.Count) tokens)" -ForegroundColor Green
}

# ── 2. Compile the embedded C# block ──────────────────────────────────────
Write-Host ''
Write-Host '── Compiling the embedded C# P/Invoke block ──' -ForegroundColor Cyan

$lines = Get-Content $target
$start = -1
$end   = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($start -lt 0 -and $lines[$i].TrimEnd().EndsWith('@"')) {
        $start = $i + 1
        continue
    }
    if ($start -ge 0 -and $lines[$i].TrimStart().StartsWith('"@')) {
        $end = $i - 1
        break
    }
}

if ($start -lt 0 -or $end -lt 0) {
    Write-Host '  Could not locate the embedded C# block' -ForegroundColor Red
    exit 2
}

$cs = ($lines[$start..$end] -join "`n")
Write-Host "  Block spans lines $($start + 1)..$($end + 1)"

try {
    Add-Type -TypeDefinition $cs -ErrorAction Stop
    Write-Host '  OK — C# compiles cleanly' -ForegroundColor Green
} catch {
    Write-Host '  C# COMPILE FAILED:' -ForegroundColor Red
    Write-Host "    $($_.Exception.Message)"
    exit 1
}

# ── 3. Check the helpers the suite depends on are present ─────────────────
Write-Host ''
Write-Host '── Checking helper surface ──' -ForegroundColor Cyan

$flags   = [System.Reflection.BindingFlags]::Public -bor `
           [System.Reflection.BindingFlags]::Static
$methods = [Hlk].GetMethods($flags)

$expected = @(
    'NCryptOpenStorageProvider', 'NCryptCreatePersistedKey',
    'NCryptFinalizeKey', 'NCryptOpenKey', 'NCryptGetProperty',
    'NCryptSetProperty', 'NCryptExportKey', 'NCryptSignHash',
    'NCryptDecrypt', 'NCryptDeleteKey', 'NCryptEnumKeys',
    'NCryptImportKey', 'NCryptEncrypt', 'NCryptSecretAgreement',
    'NCryptDeriveKey',
    'SetStringProperty', 'SetBinaryProperty', 'SetDwordProperty',
    'Encrypt', 'DecryptSym', 'AgreeAndDeriveRaw', 'ImportPublic',
    'BytesEqual', 'BytesDiffer'
)

foreach ($name in $expected) {
    if ($methods | Where-Object { $_.Name -eq $name }) {
        Write-Host ("  {0,-26} present" -f $name)
    } else {
        Write-Host ("  {0,-26} MISSING" -f $name) -ForegroundColor Red
        $failures++
    }
}

# ── 4. Exercise the pure helpers ──────────────────────────────────────────
Write-Host ''
Write-Host '── Exercising pure helpers ──' -ForegroundColor Cyan

$a = [byte[]](1, 2, 3, 4)
$b = [byte[]](1, 2, 3, 4)
$c = [byte[]](1, 2, 3, 9)

$checks = @(
    @{ Name = 'BytesEqual: identical arrays';        Ok = [Hlk]::BytesEqual($a, $b) }
    @{ Name = 'BytesEqual: differing arrays';        Ok = -not [Hlk]::BytesEqual($a, $c) }
    @{ Name = 'BytesEqual: null is not equal';       Ok = -not [Hlk]::BytesEqual($null, $b) }
    @{ Name = 'BytesEqual: length mismatch';         Ok = -not [Hlk]::BytesEqual($a, [byte[]](1, 2)) }
    @{ Name = 'BytesDiffer: full-length difference'; Ok = [Hlk]::BytesDiffer($a, $c, 4) }
    @{ Name = 'BytesDiffer: identical arrays';       Ok = -not [Hlk]::BytesDiffer($a, $b, 4) }
    @{ Name = 'BytesDiffer: prefix matches';         Ok = -not [Hlk]::BytesDiffer($a, $c, 3) }
)

foreach ($ck in $checks) {
    if ($ck.Ok) {
        Write-Host ("  [PASS] {0}" -f $ck.Name) -ForegroundColor Green
    } else {
        Write-Host ("  [FAIL] {0}" -f $ck.Name) -ForegroundColor Red
        $failures++
    }
}

# ── Summary ───────────────────────────────────────────────────────────────
Write-Host ''
if ($failures -eq 0) {
    Write-Host 'VALIDATION PASSED' -ForegroundColor Green
    exit 0
} else {
    Write-Host "VALIDATION FAILED — $failures problem(s)" -ForegroundColor Red
    exit 1
}
