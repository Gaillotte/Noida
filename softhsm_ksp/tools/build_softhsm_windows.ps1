#Requires -Version 5.1
<#
.SYNOPSIS
    Build SoftHSM2 2.7.0 from source on Windows (OpenSSL backend, x64).

.DESCRIPTION
    Uses vcpkg to install OpenSSL, then compiles the softhsm2 submodule
    with CMake + MSVC for x64 Release. Installs the result under
    <repo_root>\softhsm2-install\.

.PARAMETER VcpkgDir
    Path to an existing vcpkg installation.
    If omitted, vcpkg is cloned into <repo_root>\vcpkg\.

.PARAMETER Jobs
    Number of parallel build jobs (default: logical CPU count).

.EXAMPLE
    # Run from a Visual Studio x64 Native Tools prompt:
    .\tools\build_softhsm_windows.ps1

    # Use an existing vcpkg:
    .\tools\build_softhsm_windows.ps1 -VcpkgDir C:\vcpkg
#>
param(
    [string]$VcpkgDir = "",
    [int]$Jobs = [Environment]::ProcessorCount
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Resolve paths ─────────────────────────────────────────────────────────────
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$KspDir     = Split-Path -Parent $ScriptDir          # softhsm_ksp/
$RepoRoot   = Split-Path -Parent $KspDir             # noida/
$Src        = Join-Path $RepoRoot "softhsm2"
$InstallDir = Join-Path $RepoRoot "softhsm2-install"
$BuildDir   = Join-Path $RepoRoot "softhsm2-build-win"

Write-Host "=== SoftHSM2 2.7.0 — Windows x64 build (OpenSSL backend) ===" -ForegroundColor Cyan
Write-Host "Source  : $Src"
Write-Host "Install : $InstallDir"
Write-Host "Jobs    : $Jobs"

# ── Verify submodule ─────────────────────────────────────────────────────────
if (-not (Test-Path (Join-Path $Src "CMakeLists.txt"))) {
    Write-Error "softhsm2 submodule not found at $Src. Run: git submodule update --init --recursive"
}

# ── Locate or install vcpkg ───────────────────────────────────────────────────
if ($VcpkgDir -eq "") {
    $VcpkgDir = Join-Path $RepoRoot "vcpkg"
}
$Vcpkg = Join-Path $VcpkgDir "vcpkg.exe"

if (-not (Test-Path $Vcpkg)) {
    Write-Host "`n>>> Cloning vcpkg into $VcpkgDir ..." -ForegroundColor Yellow
    git clone https://github.com/Microsoft/vcpkg.git $VcpkgDir
    & (Join-Path $VcpkgDir "bootstrap-vcpkg.bat") -disableMetrics
}

Write-Host "`n>>> Installing OpenSSL x64 via vcpkg ..." -ForegroundColor Yellow
& $Vcpkg install "openssl:x64-windows" --no-print-usage

# ── CMake configure ───────────────────────────────────────────────────────────
$Toolchain = Join-Path $VcpkgDir "scripts\buildsystems\vcpkg.cmake"
Write-Host "`n>>> Configuring SoftHSM2 with CMake ..." -ForegroundColor Yellow

New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$cmakeArgs = @(
    "-S", $Src,
    "-B", $BuildDir,
    "-G", "Visual Studio 17 2022",
    "-A", "x64",
    "-DCMAKE_TOOLCHAIN_FILE=$Toolchain",
    "-DCMAKE_INSTALL_PREFIX=$InstallDir",
    "-DVCPKG_TARGET_TRIPLET=x64-windows",
    "-DWITH_CRYPTO_BACKEND=openssl",
    "-DENABLE_ECC=ON",
    "-DENABLE_EDDSA=ON",
    "-DENABLE_GOST=OFF",
    "-DBUILD_TESTS=OFF",
    "-DWITH_OBJECTSTORE_BACKEND_DB=OFF",
    "-DENABLE_P11_KIT=OFF"
)
& cmake @cmakeArgs
if ($LASTEXITCODE -ne 0) { Write-Error "CMake configure failed" }

# ── Build ─────────────────────────────────────────────────────────────────────
Write-Host "`n>>> Building (Release, $Jobs jobs) ..." -ForegroundColor Yellow
& cmake --build $BuildDir --config Release --parallel $Jobs
if ($LASTEXITCODE -ne 0) { Write-Error "CMake build failed" }

# ── Install ───────────────────────────────────────────────────────────────────
Write-Host "`n>>> Installing to $InstallDir ..." -ForegroundColor Yellow
& cmake --install $BuildDir --config Release
if ($LASTEXITCODE -ne 0) { Write-Error "CMake install failed" }

# ── Locate the built DLL ──────────────────────────────────────────────────────
$Dll = Get-ChildItem -Path $InstallDir -Recurse -Filter "softhsm2.dll" |
       Select-Object -First 1

if ($Dll) {
    Write-Host ""
    Write-Host "=== Build complete ===" -ForegroundColor Green
    Write-Host ""
    Write-Host "DLL location : $($Dll.FullName)"
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. Initialise a token:"
    Write-Host "       `$env:SOFTHSM2_CONF = '$InstallDir\etc\softhsm2.conf'"
    Write-Host "       softhsm2-util --init-token --slot 0 --label MyToken --so-pin 0000 --pin 1234"
    Write-Host "  2. Set SOFTHSM2_LIB for the KSP:"
    Write-Host "       `$env:SOFTHSM2_LIB = '$($Dll.FullName)'"
    Write-Host "  3. Build the KSP DLL:"
    Write-Host "       cd softhsm_ksp"
    Write-Host "       cmake -B build -G 'Visual Studio 17 2022' -A x64 -DSOFTHSM2_DIR=$InstallDir"
    Write-Host "       cmake --build build --config Release"
} else {
    Write-Warning "Build succeeded but softhsm2.dll not found under $InstallDir — check the install layout."
}
