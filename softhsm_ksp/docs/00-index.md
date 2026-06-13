# Documentation — SoftHSM2 KSP

Prototype d'un **Key Storage Provider (KSP) Microsoft CNG** qui délègue toutes
les opérations cryptographiques à **SoftHSM2** via l'interface **PKCS#11 v2.40**.

---

## Table des matières

| Document | Contenu |
|----------|---------|
| [01 — Architecture](./01-architecture.md) | Vue d'ensemble, couches, structures de données, modèle de threading, gestion mémoire |
| [02 — Initialisation](./02-initialisation.md) | Chargement de softhsm2.dll, singleton `InitOnceExecuteOnce`, pool de sessions, cycle de vie |
| [03 — Gestion des clés](./03-gestion-cles.md) | CreatePersistedKey (RSA / ECDSA), OpenKey, EnumKeys, DeleteKey, OIDs DER |
| [04 — Opérations cryptographiques](./04-operations-crypto.md) | SignHash (PKCS1 / PSS / ECDSA), Decrypt (PKCS1 / OAEP), ExportKey, ImportKey, formats de blobs |
| [05 — Propriétés](./05-proprietes.md) | GetKeyProperty, SetKeyProperty, GetProviderProperty, tableau de correspondance |
| [06 — Mapping d'erreurs](./06-mapping-erreurs.md) | CK_RV → SECURITY_STATUS, codes par fonction, diagramme de flux d'erreur |
| [07 — Sécurité et threading](./07-securite-threading.md) | Concurrence, validation des handles, gestion du PIN, logging |
| [08 — Flux complets](./08-flux-complets.md) | Scénarios TLS, signature de code, énumération, rotation de clé, erreur token absent |

---

## Diagramme d'ensemble rapide

```
Application Windows
       │
       │ NCrypt*() API
       ▼
  ncrypt.dll ──── registre : HKLM\...\SoftHSM KSP\Image
       │                     GetKeyStorageInterface()
       │ NCRYPT_KEY_STORAGE_FUNCTION_TABLE
       ▼
softhsm_ksp.dll
  ├── ksp_*()          Implémente les 22 fonctions de la table CNG
  ├── p11_context.c    Singleton PKCS#11 (LoadLibrary + C_Initialize)
  ├── p11_session.c    Pool 16 sessions (sémaphore Windows)
  └── p11_utils.c      Mécanismes, conversions format, export clés
       │
       │ C_XXX() via CK_FUNCTION_LIST
       │ LoadLibrary (pas de lien statique)
       ▼
softhsm2-x64.dll       PKCS#11 v2.40 — stockage SQLite chiffré
```

---

## Algorithmes supportés

| Algorithme | Génération | Signature | Déchiffrement | Export pub |
|------------|:---------:|:---------:|:-------------:|:----------:|
| RSA 2048 | ✓ | PKCS1 v1.5, PSS | PKCS1, OAEP | ✓ |
| RSA 3072 | ✓ | PKCS1 v1.5, PSS | PKCS1, OAEP | ✓ |
| RSA 4096 | ✓ | PKCS1 v1.5, PSS | PKCS1, OAEP | ✓ |
| ECDSA P-256 | ✓ | ✓ (r‖s) | — | ✓ |
| ECDSA P-384 | ✓ | ✓ (r‖s) | — | ✓ |

---

## Mapping CNG → PKCS#11 résumé

| Fonction CNG | Mécanisme PKCS#11 | Notes |
|-------------|-------------------|-------|
| `SignHash` RSA PKCS1 | `CKM_RSA_PKCS` | Hash passé tel quel |
| `SignHash` RSA PSS | `CKM_RSA_PKCS_PSS` | `CK_RSA_PKCS_PSS_PARAMS` mappés depuis `BCRYPT_PSS_PADDING_INFO` |
| `SignHash` ECDSA | `CKM_ECDSA` | Résultat DER converti en r‖s |
| `Decrypt` PKCS1 | `CKM_RSA_PKCS` | — |
| `Decrypt` OAEP | `CKM_RSA_PKCS_OAEP` | `CK_RSA_PKCS_OAEP_PARAMS` mappés depuis `BCRYPT_OAEP_PADDING_INFO` |
| `CreateKey` RSA | `CKM_RSA_PKCS_KEY_PAIR_GEN` | `SENSITIVE=TRUE`, `EXTRACTABLE=FALSE` |
| `CreateKey` EC | `CKM_EC_KEY_PAIR_GEN` | OID DER P-256 ou P-384 dans `CKA_EC_PARAMS` |

---

## Conventions du code

- **Commentaires** : en français sur les fonctions publiques
- **Warnings** : zéro à `/W3` MSVC
- **Mémoire** : `HeapAlloc`/`HeapFree` sur `GetProcessHeap()` uniquement
- **Nommage** : `KSP_` (couche KSP), `P11_` (couche PKCS#11)
- **Handles** : cast direct `(KSP_PROVIDER *)hProvider`, validés par `dwMagic`
- **Thread-safety** : toutes les fonctions sont réentrantes
