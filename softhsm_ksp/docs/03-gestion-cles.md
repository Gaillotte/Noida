# Gestion des clés — Mapping CNG → PKCS#11

## Correspondance des concepts

| Concept CNG | Équivalent PKCS#11 | Champ KSP_KEY |
|-------------|-------------------|---------------|
| `NCRYPT_KEY_HANDLE` | `CK_OBJECT_HANDLE` (paire) | `hPrivKey` + `hPubKey` |
| Nom de clé (`pszKeyName`) | `CKA_LABEL` | `szKeyName` |
| Algorithme (`pszAlgId`) | `CKM_*_KEY_PAIR_GEN` | `szAlgId` |
| `AT_SIGNATURE` | `CKA_SIGN = TRUE` | `dwKeySpec` |
| `AT_KEYEXCHANGE` | `CKA_DECRYPT = TRUE` | `dwKeySpec` |
| Clé persistante | `CKA_TOKEN = TRUE` | implicite |
| Non exportable | `CKA_EXTRACTABLE = FALSE` | implicite |

---

## CreatePersistedKey — RSA

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_key.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    App->>NCrypt: NCryptCreatePersistedKey(hProv, &hKey, "RSA", "MaCle", AT_SIGNATURE, 0)
    NCrypt->>KSP: KSP_CreatePersistedKey(hProv, &hKey, L"RSA", L"MaCle", AT_SIGNATURE, 0)

    KSP->>KSP: AllocZero(KSP_KEY)<br/>szAlgId="RSA"<br/>szKeyName="MaCle"<br/>dwKeyBitLen=2048 (défaut)<br/>dwKeySpec=AT_SIGNATURE<br/>bFinalized=FALSE

    note over KSP: dwFlags ne contient pas NCRYPT_PERSIST_ONLY_FLAG<br/>→ génération immédiate

    KSP->>Session: P11_AcquireSession(&hSession)
    Session-->>KSP: hSession

    KSP->>HSM: C_GenerateKeyPair(hSession, CKM_RSA_PKCS_KEY_PAIR_GEN,<br/>  pubTemplate, privTemplate,<br/>  &hPubKey, &hPrivKey)

    note over HSM: Template clé publique :<br/>CKA_CLASS=CKO_PUBLIC_KEY<br/>CKA_TOKEN=TRUE<br/>CKA_LABEL="MaCle"<br/>CKA_MODULUS_BITS=2048<br/>CKA_PUBLIC_EXPONENT=65537<br/>CKA_VERIFY=TRUE<br/><br/>Template clé privée :<br/>CKA_CLASS=CKO_PRIVATE_KEY<br/>CKA_TOKEN=TRUE<br/>CKA_LABEL="MaCle"<br/>CKA_SENSITIVE=TRUE<br/>CKA_EXTRACTABLE=FALSE<br/>CKA_SIGN=TRUE

    HSM-->>KSP: CKR_OK, hPubKey=0x05, hPrivKey=0x06

    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: pKey->hPrivKey=0x06<br/>pKey->hPubKey=0x05<br/>pKey->bFinalized=TRUE

    KSP-->>NCrypt: hKey = (NCRYPT_KEY_HANDLE)pKey, ERROR_SUCCESS
    NCrypt-->>App: hKey, ERROR_SUCCESS
```

---

## CreatePersistedKey — ECDSA P-256 (mode différé)

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_key.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    App->>NCrypt: NCryptCreatePersistedKey(hProv, &hKey,<br/>"ECDSA_P256", "CleEC",<br/>AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG)
    NCrypt->>KSP: KSP_CreatePersistedKey(..., NCRYPT_PERSIST_ONLY_FLAG)

    KSP->>KSP: AllocZero(KSP_KEY)<br/>bFinalized=FALSE<br/>bPersistOnly=TRUE<br/>(PAS de génération)

    KSP-->>NCrypt: hKey, ERROR_SUCCESS

    note over App: Optionnel : modifier les propriétés avant finalisation
    App->>NCrypt: NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, &dwBits, ...)
    NCrypt->>KSP: KSP_SetKeyProperty(..., L"Length", &2048, ...)
    KSP->>KSP: pKey->dwKeyBitLen = 2048

    App->>NCrypt: NCryptFinalizeKey(hKey, 0)
    NCrypt->>KSP: KSP_FinalizeKey(hProv, hKey, 0)

    note over KSP: bFinalized == FALSE → génération maintenant

    KSP->>Session: P11_AcquireSession(&hSession)
    Session-->>KSP: hSession

    KSP->>HSM: C_GenerateKeyPair(hSession, CKM_EC_KEY_PAIR_GEN,<br/>  pubTemplate, privTemplate,<br/>  &hPubKey, &hPrivKey)

    note over HSM: CKA_EC_PARAMS = OID DER P-256<br/>06 08 2a 86 48 ce 3d 03 01 07

    HSM-->>KSP: CKR_OK

    KSP->>Session: P11_ReleaseSession(hSession)
    KSP->>KSP: bFinalized = TRUE

    KSP-->>NCrypt: ERROR_SUCCESS
    NCrypt-->>App: ERROR_SUCCESS
```

---

## OpenKey — Réouverture d'une clé existante

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_key.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    App->>NCrypt: NCryptOpenKey(hProv, &hKey, "MaCle", 0, 0)
    NCrypt->>KSP: KSP_OpenKey(hProv, &hKey, L"MaCle", 0, 0)

    KSP->>Session: P11_AcquireSession(&hSession)
    Session-->>KSP: hSession

    KSP->>HSM: C_FindObjectsInit(hSession,<br/>  {CKA_CLASS=CKO_PRIVATE_KEY, CKA_LABEL="MaCle"})
    HSM-->>KSP: CKR_OK

    KSP->>HSM: C_FindObjects(hSession, &hObj, 1, &ulCount)
    HSM-->>KSP: hPrivKey=0x06, ulCount=1

    KSP->>HSM: C_FindObjectsFinal(hSession)

    KSP->>HSM: C_FindObjectsInit(hSession,<br/>  {CKA_CLASS=CKO_PUBLIC_KEY, CKA_LABEL="MaCle"})
    KSP->>HSM: C_FindObjects(...) → hPubKey=0x05
    KSP->>HSM: C_FindObjectsFinal(hSession)

    KSP->>HSM: C_GetAttributeValue(hSession, hPrivKey,<br/>  {CKA_KEY_TYPE})
    HSM-->>KSP: CKK_RSA

    alt Clé RSA
        KSP->>HSM: C_GetAttributeValue(..., CKA_MODULUS_BITS)
        HSM-->>KSP: 2048
        KSP->>KSP: szAlgId="RSA", dwKeyBitLen=2048
    else Clé EC
        KSP->>HSM: C_GetAttributeValue(..., CKA_EC_PARAMS)
        HSM-->>KSP: OID bytes
        alt OID == P-256 (10 octets)
            KSP->>KSP: szAlgId="ECDSA_P256", dwKeyBitLen=256
        else OID == P-384 (7 octets)
            KSP->>KSP: szAlgId="ECDSA_P384", dwKeyBitLen=384
        end
    end

    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: AllocZero(KSP_KEY)<br/>hPrivKey=0x06, hPubKey=0x05<br/>bFinalized=TRUE

    KSP-->>NCrypt: hKey, ERROR_SUCCESS
    NCrypt-->>App: hKey, ERROR_SUCCESS
```

---

## EnumKeys — Énumération paginée

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_key.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    note over App: Première itération (ppEnumState == NULL)

    App->>NCrypt: NCryptEnumKeys(hProv, NULL, &pKeyName, &pEnumState, 0)
    NCrypt->>KSP: KSP_EnumKeys(hProv, NULL, &pKeyName, &pEnumState, 0)

    KSP->>Session: P11_AcquireSession(&hSession)
    Session-->>KSP: hSession

    KSP->>HSM: C_FindObjectsInit(hSession,<br/>  {CKA_CLASS=CKO_PRIVATE_KEY, CKA_TOKEN=TRUE})
    KSP->>HSM: C_FindObjects(hSession, aBuf, 256, &ulFound)
    note over HSM: Retourne tous les handles de clés privées<br/>stockées dans le token
    HSM-->>KSP: handles[0..N-1], ulFound=N
    KSP->>HSM: C_FindObjectsFinal(hSession)
    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: Alloue KSP_ENUM_STATE<br/>phObjects=handles[0..N-1]<br/>dwCount=N, dwIndex=0
    KSP->>KSP: *ppEnumState = pState

    KSP->>Session: P11_AcquireSession(&hSession)
    KSP->>HSM: C_GetAttributeValue(handles[0], CKA_LABEL)
    HSM-->>KSP: "MaCle" (UTF-8)
    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: Alloue NCryptKeyName + szName<br/>pName->pszName = "MaCle"<br/>dwIndex = 1

    KSP-->>NCrypt: *ppKeyName=pName, ERROR_SUCCESS
    NCrypt-->>App: pKeyName, ERROR_SUCCESS

    note over App: Itérations suivantes (ppEnumState != NULL)

    loop Pour chaque clé restante
        App->>NCrypt: NCryptEnumKeys(..., &pEnumState)
        NCrypt->>KSP: KSP_EnumKeys(..., &pEnumState)
        KSP->>KSP: pState->dwIndex++
        KSP->>HSM: C_GetAttributeValue(handles[i], CKA_LABEL)
        KSP-->>NCrypt: pKeyName, ERROR_SUCCESS
    end

    note over App: Fin de l'énumération

    App->>NCrypt: NCryptEnumKeys(..., &pEnumState)
    NCrypt->>KSP: KSP_EnumKeys(...)
    KSP->>KSP: dwIndex >= dwCount<br/>→ libère KSP_ENUM_STATE<br/>→ *ppEnumState = NULL
    KSP-->>NCrypt: NTE_NO_MORE_ITEMS
    NCrypt-->>App: NTE_NO_MORE_ITEMS
```

---

## DeleteKey

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_key.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    App->>NCrypt: NCryptDeleteKey(hKey, 0)
    NCrypt->>KSP: KSP_DeleteKey(hProv, hKey, 0)

    KSP->>Session: P11_AcquireSession(&hSession)
    Session-->>KSP: hSession

    KSP->>HSM: C_DestroyObject(hSession, hPrivKey)
    note over HSM: Supprime la clé privée du stockage persistant
    HSM-->>KSP: CKR_OK

    KSP->>HSM: C_DestroyObject(hSession, hPubKey)
    HSM-->>KSP: CKR_OK

    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: pKey->dwMagic = 0
    KSP->>KSP: HeapFree(pKey)

    KSP-->>NCrypt: ERROR_SUCCESS
    NCrypt-->>App: ERROR_SUCCESS
```

---

## OIDs DER des courbes elliptiques

Les courbes sont identifiées par leur OID encodé en DER passé dans `CKA_EC_PARAMS` :

| Courbe | OID | Encodage DER |
|--------|-----|-------------|
| P-256 (secp256r1) | 1.2.840.10045.3.1.7 | `06 08 2A 86 48 CE 3D 03 01 07` (10 octets) |
| P-384 (secp384r1) | 1.3.132.0.34 | `06 05 2B 81 04 00 22` (7 octets) |

À la lecture (`OpenKey`), la longueur du blob OID suffit à distinguer les courbes :
- 10 octets → P-256
- 7 octets → P-384
