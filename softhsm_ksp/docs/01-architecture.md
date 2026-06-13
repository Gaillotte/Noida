# Architecture — SoftHSM2 KSP

## Vue d'ensemble

Le KSP SoftHSM2 s'insère dans la pile cryptographique Windows comme une couche
d'adaptation entre l'API **CNG (Cryptography Next Generation)** et la bibliothèque
**SoftHSM2** exposée via l'interface standard **PKCS#11 v2.40**.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        APPLICATION WINDOWS                          │
│          (certutil, PowerShell, .NET, IE/Edge, WinHTTP…)           │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ NCryptSignHash() / NCryptOpenKey()…
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     NCRYPT.DLL  (CNG runtime)                       │
│   Résout le KSP via le registre, charge la DLL, dispatche les       │
│   appels via la NCRYPT_KEY_STORAGE_FUNCTION_TABLE                   │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ Table de fonctions → KSP_*()
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    SOFTHSM_KSP.DLL  (ce projet)                     │
│                                                                     │
│  ┌─────────────────────┐   ┌──────────────────────────────────────┐ │
│  │    Couche KSP        │   │         Couche PKCS#11               │ │
│  │  ksp_main.c          │   │  p11_context.c  (singleton)          │ │
│  │  ksp_provider.c      │──▶│  p11_session.c  (pool sessions)      │ │
│  │  ksp_key.c           │   │  p11_utils.c    (mécanismes, attrs)  │ │
│  │  ksp_crypto.c        │   └──────────────────┬───────────────────┘ │
│  │  ksp_properties.c    │                      │ C_XXX()             │
│  └─────────────────────┘                      │                     │
│  ┌─────────────────────┐                      │                     │
│  │    Common            │                      │                     │
│  │  config.h            │                      │                     │
│  │  logging.c           │                      │                     │
│  │  memory.c            │                      │                     │
│  └─────────────────────┘                      │                     │
└──────────────────────────────────────────────┬─┘                    │
                                               │ LoadLibrary +        │
                                               │ CK_FUNCTION_LIST     │
                                               ▼                      │
┌─────────────────────────────────────────────────────────────────────┐
│                 SOFTHSM2-X64.DLL  (SoftHSM2)                       │
│    Implémente PKCS#11 v2.40 ; stocke les clés dans une base        │
│    SQLite chiffrée sur le disque                                    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Composants internes

### Couche KSP

| Fichier | Responsabilité |
|---------|---------------|
| `ksp_main.c` | `DllMain`, `GetKeyStorageInterface`, table `NCRYPT_KEY_STORAGE_FUNCTION_TABLE` |
| `ksp_provider.c` | `OpenProvider`, `FreeProvider`, propriétés fournisseur, stubs |
| `ksp_key.c` | `CreatePersistedKey`, `OpenKey`, `FinalizeKey`, `DeleteKey`, `EnumKeys` |
| `ksp_crypto.c` | `SignHash`, `Decrypt`, `ExportKey`, `ImportKey` |
| `ksp_properties.c` | `GetKeyProperty`, `SetKeyProperty` |

### Couche PKCS#11

| Fichier | Responsabilité |
|---------|---------------|
| `pkcs11.h` | Header standard OASIS v2.40 (types, constantes, `CK_FUNCTION_LIST`) |
| `p11_context.c` | Singleton — chargement de la DLL, `C_Initialize`, sélection du slot |
| `p11_session.c` | Pool de sessions avec sémaphore Windows |
| `p11_utils.c` | Résolution des mécanismes, conversion d'erreurs, export des clés |

### Commun

| Fichier | Responsabilité |
|---------|---------------|
| `config.h` | Constantes : chemins, PIN, OIDs DER, noms d'algorithmes |
| `logging.c` | `OutputDebugString` conditionnel (`KSP_DEBUG=1`) |
| `memory.c` | `KSP_Alloc`/`KSP_Free` sur `GetProcessHeap()` |

---

## Structures de données internes

### KSP_PROVIDER

```c
typedef struct _KSP_PROVIDER {
    DWORD  dwMagic;      // KSP_PROVIDER_MAGIC = 0x4B535050 ('KSPP')
    WCHAR  szName[256];  // "SoftHSM KSP"
} KSP_PROVIDER;
```

Le handle `NCRYPT_PROV_HANDLE` est un cast direct de `KSP_PROVIDER *`.
Le champ `dwMagic` permet de valider les handles entrants (defense in depth).

### KSP_KEY

```c
typedef struct _KSP_KEY {
    DWORD            dwMagic;         // KSP_KEY_MAGIC = 0x4B53504B ('KSPK')
    WCHAR            szKeyName[256];  // = CKA_LABEL dans SoftHSM2
    WCHAR            szAlgId[64];     // "RSA", "ECDSA_P256", "ECDSA_P384"
    DWORD            dwKeyBitLen;     // 2048, 3072, 4096 (RSA) / 256, 384 (EC)
    DWORD            dwKeySpec;       // AT_SIGNATURE | AT_KEYEXCHANGE
    CK_OBJECT_HANDLE hPrivKey;        // Handle PKCS#11 clé privée
    CK_OBJECT_HANDLE hPubKey;         // Handle PKCS#11 clé publique
    CK_SLOT_ID       slotId;          // Slot SoftHSM2 sélectionné
    BOOL             bFinalized;      // FinalizeKey() appelé ?
    BOOL             bPersistOnly;    // Génération différée ?
} KSP_KEY;
```

### P11_CONTEXT (singleton)

```c
typedef struct _P11_CONTEXT {
    HMODULE              hModule;       // Handle softhsm2-x64.dll
    CK_FUNCTION_LIST_PTR pFunctionList; // Table des fonctions PKCS#11
    CK_SLOT_ID           slotId;        // Premier slot avec token présent
    BOOL                 bInitialized;  // TRUE après C_Initialize réussi
} P11_CONTEXT;
```

### P11_SESSION_ENTRY (pool)

```c
typedef struct _P11_SESSION_ENTRY {
    CK_SESSION_HANDLE hSession;   // Handle PKCS#11 (ou CK_INVALID_HANDLE)
    BOOL              bInUse;     // Slot occupé ?
    BOOL              bLoggedIn;  // C_Login() effectué ?
    CRITICAL_SECTION  cs;         // Verrou per-session
} P11_SESSION_ENTRY;
```

---

## Cycle de vie des objets Windows

### Enregistrement dans le registre

```
HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\
  └── SoftHSM KSP\
        Image = "C:\...\softhsm_ksp.dll"
        Type  = 0x00000001
```

### Chargement par ncrypt.dll

```
ncrypt.dll
  ├── RegOpenKey("SoftHSM KSP")
  ├── RegQueryValueEx("Image") → chemin DLL
  ├── LoadLibrary(chemin)
  └── GetProcAddress("GetKeyStorageInterface")
         └── → NCRYPT_KEY_STORAGE_FUNCTION_TABLE *
```

---

## Modèle de threading

```
Thread 1                   Thread 2                  Thread 3
────────                   ────────                  ────────
P11_Initialize()           P11_Initialize()
  InitOnceExecuteOnce ─────▶ (attend)                P11_Initialize()
  LoadLibrary()                                        (attend)
  C_Initialize()
  C_GetSlotList()
  ◀── retour OK ─────────── retour OK ────────────── retour OK

P11_AcquireSession()       P11_AcquireSession()
  WaitForSingleObject(      WaitForSingleObject(
    Semaphore, 5000) ───────▶ sémaphore)
  [slot 0 libre]            [attend si pool plein]
  ◀── hSession[0] ──────

                           [slot 1 libre]
                           ◀── hSession[1] ──────

KSP_SignHash()             KSP_SignHash()
  C_Sign()                   C_Sign()
  (concurrent OK grâce       (session distincte)
   à CKF_OS_LOCKING_OK)

P11_ReleaseSession(s0)     P11_ReleaseSession(s1)
  ReleaseSemaphore           ReleaseSemaphore
```

---

## Gestion mémoire

Tous les buffers retournés à l'appelant CNG sont alloués sur `GetProcessHeap()` :

```
KSP_Alloc(n)    → HeapAlloc(GetProcessHeap(), 0, n)
KSP_AllocZero(n)→ HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n)
KSP_Free(p)     → HeapFree(GetProcessHeap(), 0, p)
```

`KSP_FreeBuffer(pvInput)` est la fonction exposée au runtime CNG pour libérer
tous les buffers qu'il reçoit du KSP (noms de clés, blobs de clés, etc.).
