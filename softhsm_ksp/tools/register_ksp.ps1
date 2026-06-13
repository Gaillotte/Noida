#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enregistre le KSP SoftHSM dans le registre Windows.

.PARAMETER DllPath
    Chemin absolu vers softhsm_ksp.dll.
    Par défaut : répertoire courant.

.EXAMPLE
    .\register_ksp.ps1 -DllPath "C:\KSP\softhsm_ksp.dll"
#>

param(
    [string]$DllPath = (Join-Path (Get-Location) "softhsm_ksp.dll")
)

$ErrorActionPreference = "Stop"

# Vérifie que la DLL existe
if (-not (Test-Path $DllPath)) {
    Write-Error "DLL introuvable : $DllPath"
    exit 1
}

$DllPath = (Resolve-Path $DllPath).Path

# Chemin de registre du KSP
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\SoftHSM KSP"

Write-Host "Enregistrement du KSP SoftHSM..."
Write-Host "  DLL    : $DllPath"
Write-Host "  Clé    : $regPath"

# Crée la clé si nécessaire
New-Item -Path $regPath -Force | Out-Null

# Définit les valeurs
Set-ItemProperty -Path $regPath -Name "Image" -Value $DllPath -Type String
Set-ItemProperty -Path $regPath -Name "Type"  -Value 1        -Type DWord

Write-Host "Enregistrement terminé avec succès."
Write-Host ""
Write-Host "Pour vérifier :"
Write-Host "  certutil -csplist | Select-String 'SoftHSM'"
Write-Host ""
Write-Host "Pour désinstaller :"
Write-Host "  Remove-Item -Path '$regPath' -Recurse -Force"
