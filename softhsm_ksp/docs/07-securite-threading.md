# Sécurité et threading

## Modèle de concurrence

### Garanties de thread-safety

| Composant | Mécanisme | Portée |
|-----------|-----------|--------|
| Initialisation singleton | `InitOnceExecuteOnce` | Processus entier |
| Pool de sessions | `CreateSemaphore` (compteur) | Accès au pool |
| Recherche slot libre | `CRITICAL_SECTION csPool` | Liste des slots |
| Opération par session | `CRITICAL_SECTION cs[i]` | Session individuelle |
| SoftHSM2 (interne) | `CKF_OS_LOCKING_OK` | Bibliothèque PKCS#11 |

### Invariant clé

> Deux threads peuvent effectuer des opérations cryptographiques **simultanément**
> car chacun utilise une session distincte du pool (handle `CK_SESSION_HANDLE` différent).
> `CKF_OS_LOCKING_OK` garantit que SoftHSM2 lui-même est thread-safe en interne.

---

## Diagramme — Accès concurrent au pool de sessions

```mermaid
sequenceDiagram
    participant T1 as Thread 1
    participant T2 as Thread 2
    participant T3 as Thread 3 (attente)
    participant Sem as Sémaphore (16)
    participant Pool as Pool[0..15]

    note over Sem: État initial : count=16

    T1->>Sem: WaitForSingleObject → count=15
    T2->>Sem: WaitForSingleObject → count=14

    T1->>Pool: EnterCS(csPool), slot[0].bInUse=TRUE, LeaveCS
    T2->>Pool: EnterCS(csPool), slot[1].bInUse=TRUE, LeaveCS

    T1->>Pool: C_Sign() sur session[0]
    T2->>Pool: C_Sign() sur session[1]
    note over T1,T2: Concurrence OK — sessions distinctes

    note over T3: Pool plein (toutes 16 sessions occupées)
    T3->>Sem: WaitForSingleObject(5000ms) → BLOQUÉ

    T1->>Pool: slot[0].bInUse=FALSE
    T1->>Sem: ReleaseSemaphore → count=1

    note over T3: Débloqué
    T3->>Sem: WaitForSingleObject → count=0
    T3->>Pool: slot[0].bInUse=TRUE
```

---

## Gestion sécurisée du PIN

```mermaid
flowchart TD
    A["GetEnvironmentVariableA(SOFTHSM2_PIN_ENV,\nszPin, sizeof szPin)"]
    A --> B{Variable définie ?}
    B -- Non --> C["szPin = SOFTHSM2_PIN_DEFAULT\n= '1234'"]
    B -- Oui --> D["szPin = valeur lue"]
    C --> E["C_Login(hSession, CKU_USER,\nszPin, strlen(szPin))"]
    D --> E
    E --> F["SecureZeroMemory(szPin, sizeof szPin)"]
    note right of F: Efface immédiatement le PIN\nde la pile/heap pour éviter\nqu'il reste accessible en mémoire
    F --> G["Résultat CK_RV"]
```

> **Recommandation production** : ne jamais stocker le PIN dans une variable d'environnement
> en production. Utiliser un coffre-fort de secrets (Windows DPAPI, Azure Key Vault, etc.)

---

## Validation des handles

Chaque fonction KSP valide les handles entrants avant tout traitement :

```mermaid
flowchart LR
    H["NCRYPT_PROV_HANDLE hProv"]
    A["(KSP_PROVIDER *)hProv"]
    B{"pProv != NULL\net\npProv->dwMagic ==\nKSP_PROVIDER_MAGIC ?"}
    OK["Traitement normal"]
    ERR["NTE_INVALID_HANDLE\nou NTE_INVALID_PARAMETER"]

    H --> A --> B
    B -- Oui --> OK
    B -- Non --> ERR
```

```mermaid
flowchart LR
    H["NCRYPT_KEY_HANDLE hKey"]
    A["(KSP_KEY *)hKey"]
    B{"pKey != NULL\net\npKey->dwMagic ==\nKSP_KEY_MAGIC ?"}
    OK["Traitement normal"]
    ERR["NTE_INVALID_HANDLE"]

    H --> A --> B
    B -- Oui --> OK
    B -- Non --> ERR
```

Les magic numbers servent de canaries : si un appelant passe un pointeur arbitraire
ou un handle d'un autre fournisseur, la vérification du magic échoue avant
tout déréférencement potentiellement dangereux.

---

## Cycle de vie complet d'un objet KSP_KEY

```mermaid
stateDiagram-v2
    [*] --> Alloue : KSP_CreatePersistedKey()

    Alloue --> Generee : !PERSIST_ONLY\n(C_GenerateKeyPair immédiat)
    Alloue --> Partielle : PERSIST_ONLY_FLAG\n(génération différée)

    Partielle --> Modifiable : SetKeyProperty(LENGTH)
    Modifiable --> Partielle : (peut modifier plusieurs fois)
    Partielle --> Generee : KSP_FinalizeKey()\n→ C_GenerateKeyPair

    Generee --> EnUse : KSP_SignHash / KSP_Decrypt / KSP_ExportKey
    EnUse --> Generee : (après chaque opération)

    Generee --> [*] : KSP_DeleteKey()\n→ C_DestroyObject × 2\n→ HeapFree

    Generee --> [*] : KSP_FreeKey()\n→ HeapFree (objet PKCS#11 reste en token)
```

---

## Contre-mesures de sécurité

### Clés non exportables

Toutes les clés privées sont créées avec :
```c
{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }  // FALSE
{ CKA_SENSITIVE,   &bTrue,  sizeof(bTrue)  }  // TRUE
```

Tentative d'export de clé privée → `NTE_NOT_SUPPORTED` immédiat (sans appel PKCS#11).

### Pas de lien statique softhsm2.dll

La DLL est chargée via `LoadLibrary` uniquement, ce qui évite :
- La dépendance au moment du build
- Les problèmes d'ABI entre versions
- Le chargement inutile en l'absence de SoftHSM2

### Zeroing de la mémoire sensible

- PIN : `SecureZeroMemory()` après `C_Login()`
- Les buffers de hash et de signature ne sont **pas** zéroïsés car ils ne sont pas secrets

---

## Logging et débogage

```mermaid
sequenceDiagram
    participant App as Application
    participant KSP as KSP (toute fonction)
    participant Log as logging.c
    participant DBG as DebugView (Sysinternals)

    note over App: KSP_DEBUG=1 dans l'environnement

    App->>KSP: Appel quelconque
    KSP->>Log: LOG_ENTER("KSP_SignHash")
    Log->>Log: g_bDebugEnabled == TRUE
    Log->>DBG: OutputDebugStringA("[SOFTHSM_KSP] KSP_SignHash: entree\n")

    KSP->>KSP: Traitement...

    KSP->>Log: LOG_INFO("hPrivKey=0x%lX", hPrivKey)
    Log->>DBG: OutputDebugStringA("[SOFTHSM_KSP] hPrivKey=0x6\n")

    KSP->>Log: LOG_LEAVE("KSP_SignHash", ERROR_SUCCESS)
    Log->>DBG: OutputDebugStringA("[SOFTHSM_KSP] KSP_SignHash: sortie status=0x00000000\n")
```

### Format des messages de log

```
[SOFTHSM_KSP] <NomFonction>: entree
[SOFTHSM_KSP] <NomFonction>: <clé>=<valeur>
[SOFTHSM_KSP] <NomFonction>: sortie status=0x00000000
[SOFTHSM_KSP] <NomFonction>: ERREUR status=0x80090009
```
