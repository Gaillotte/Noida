# SoftHSM2 KSP — CNG Key Storage Provider via PKCS#11

Prototype d'un **KSP (Key Storage Provider) Microsoft CNG** complet qui délègue toutes les opérations cryptographiques à **SoftHSM2** via l'interface PKCS#11.

## Prérequis

| Composant | Version minimale |
|-----------|-----------------|
| Windows   | 10 / 11 x64     |
| Visual Studio | 2022 (MSVC) |
| CMake     | 3.20+           |
| SoftHSM2  | 2.6+            |
| Windows SDK | 10.0.19041+  |

### Installation de SoftHSM2

1. Télécharger l'installeur depuis https://github.com/opendnssec/SoftHSMv2
2. Installer dans `C:\Program Files\SoftHSM2\` (chemin par défaut)
3. Initialiser un token :
   ```
   softhsm2-util --init-token --slot 0 --label "MyToken" \
                 --so-pin 0000 --pin 1234
   ```

## Build

```powershell
# Dans un terminal Visual Studio (x64 Native Tools)
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

La DLL `Release\softhsm_ksp.dll` est créée dans `build\Release\`.

## Configuration

| Variable d'environnement | Valeur par défaut | Description |
|--------------------------|-------------------|-------------|
| `SOFTHSM2_LIB` | `C:\Program Files\SoftHSM2\lib\softhsm2-x64.dll` | Chemin vers la DLL SoftHSM2 |
| `SOFTHSM2_PIN` | `1234` | PIN utilisateur du token |
| `KSP_DEBUG` | `0` | Active le logging (`1` = actif) |

Le logging est visible avec **DebugView** (Sysinternals) en temps réel.

## Enregistrement du KSP

### Via PowerShell (Administrateur)

```powershell
.\tools\register_ksp.ps1 -DllPath "C:\chemin\vers\softhsm_ksp.dll"
```

### Via le fichier .reg

Éditer `tools\register_ksp.reg` pour remplacer `<CHEMIN_ABSOLU>`, puis double-cliquer.

### Vérification

```powershell
certutil -csplist | Select-String "SoftHSM"
```

### Désinstallation

```powershell
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\SoftHSM KSP" -Recurse -Force
```

## Tests

### Tests unitaires couche PKCS#11

```powershell
.\build\Release\test_p11_layer.exe
```

Couvre : initialisation, sessions, recherche, génération RSA, signature PKCS1/PSS, destruction.

### Tests d'intégration KSP

```powershell
.\build\Release\test_ksp_integration.exe
```

Couvre : OpenProvider, CreatePersistedKey, FinalizeKey, GetKeyProperty, SignHash RSA/ECDSA, ExportKey, EnumKeys, DeleteKey.

### Tests fonctionnels complets (PowerShell)

```powershell
.\tools\test_ksp.ps1
```

Requiert le KSP enregistré dans le registre. Exécute 9 scénarios complets via l'API NCrypt.

## Architecture

```
softhsm_ksp/
├── src/pkcs11/      Couche PKCS#11 (contexte, sessions, utilitaires)
├── src/ksp/         Implémentation CNG KSP (provider, clés, crypto)
├── src/common/      Logging, mémoire, configuration
├── tools/           Scripts d'enregistrement et de test
└── tests/           Tests unitaires et d'intégration
```

### Flux d'appel typique (signature)

```
Application Windows
    ↓ NCryptSignHash()
KSP_SignHash()          [ksp_crypto.c]
    ↓ P11_AcquireSession()
    ↓ C_SignInit() → C_Sign()
SoftHSM2 (softhsm2-x64.dll)
    ↓ résultat DER (ECDSA) → conversion r||s
    ↓ résultat RSA → transmis tel quel
Application Windows
```

## Algorithmes supportés

| Algorithme | Génération | Signature | Déchiffrement | Export pub |
|------------|-----------|-----------|---------------|------------|
| RSA 2048/3072/4096 | ✓ | PKCS1, PSS | PKCS1, OAEP | ✓ |
| ECDSA P-256 | ✓ | ✓ | — | ✓ |
| ECDSA P-384 | ✓ | ✓ | — | ✓ |

Les clés privées ne sont **jamais exportables** (simuler le comportement d'un HSM matériel).

## Sécurité

- Les clés privées sont marquées `CKA_SENSITIVE=TRUE`, `CKA_EXTRACTABLE=FALSE`
- Le PIN est lu depuis la variable d'environnement `SOFTHSM2_PIN` (ne jamais coder en dur en production)
- Zéro mémoire sensible effacée avec `SecureZeroMemory()` après usage

## Limitations connues

- SoftHSM2 ne supporte pas `CKM_RSA_X_509` (raw RSA) — non implémenté
- Import de clés privées non supporté (HSM par design)
- Un seul token/slot utilisé (le premier avec token présent)
