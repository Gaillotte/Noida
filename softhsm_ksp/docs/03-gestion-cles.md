# Key management — CNG → PKCS#11 mapping

## Concept mapping

| CNG concept | PKCS#11 equivalent | KSP_KEY field |
|-------------|-------------------|---------------|
| `NCRYPT_KEY_HANDLE` | `CK_OBJECT_HANDLE` (pair) | `hPrivKey` + `hPubKey` |
| Key name (`pszKeyName`) | `CKA_LABEL` | `szKeyName` |
| Algorithm (`pszAlgId`) | `CKM_*_KEY_PAIR_GEN` | `szAlgId` |
| `AT_SIGNATURE` | `CKA_SIGN = TRUE` | `dwKeySpec` |
| `AT_KEYEXCHANGE` | `CKA_DECRYPT = TRUE` | `dwKeySpec` |
| Persistent key | `CKA_TOKEN = TRUE` | implicit |
| Non-exportable | `CKA_EXTRACTABLE = FALSE` | implicit |

---

## CreatePersistedKey — RSA

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_key.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    App->>NCrypt: NCryptCreatePersistedKey(hProv, &hKey, "RSA", "MyKey", AT_SIGNATURE, 0)
    NCrypt->>KSP: KSP_CreatePersistedKey(hProv, &hKey, L"RSA", L"MyKey", AT_SIGNATURE, 0)

    KSP->>KSP: AllocZero(KSP_KEY)<br/>szAlgId="RSA"<br/>szKeyName="MyKey"<br/>dwKeyBitLen=2048 (default)<br/>dwKeySpec=AT_SIGNATURE<br/>bFinalized=FALSE

    note over KSP: dwFlags does not contain NCRYPT_PERSIST_ONLY_FLAG<br/>→ immediate generation

    KSP->>Session: P11_AcquireSession(&hSession)
    Session-->>KSP: hSession

    KSP->>HSM: C_GenerateKeyPair(hSession, CKM_RSA_PKCS_KEY_PAIR_GEN,<br/>  pubTemplate, privTemplate,<br/>  &hPubKey, &hPrivKey)

    note over HSM: Public key template:<br/>CKA_CLASS=CKO_PUBLIC_KEY<br/>CKA_TOKEN=TRUE<br/>CKA_LABEL="MyKey"<br/>CKA_MODULUS_BITS=2048<br/>CKA_PUBLIC_EXPONENT=65537<br/>CKA_VERIFY=TRUE<br/><br/>Private key template:<br/>CKA_CLASS=CKO_PRIVATE_KEY<br/>CKA_TOKEN=TRUE<br/>CKA_LABEL="MyKey"<br/>CKA_SENSITIVE=TRUE<br/>CKA_EXTRACTABLE=FALSE<br/>CKA_SIGN=TRUE

    HSM-->>KSP: CKR_OK, hPubKey=0x05, hPrivKey=0x06

    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: pKey->hPrivKey=0x06<br/>pKey->hPubKey=0x05<br/>pKey->bFinalized=TRUE

    KSP-->>NCrypt: hKey = (NCRYPT_KEY_HANDLE)pKey, ERROR_SUCCESS
    NCrypt-->>App: hKey, ERROR_SUCCESS
```

---

## CreatePersistedKey — ECDSA P-256 (deferred mode)

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_key.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    App->>NCrypt: NCryptCreatePersistedKey(hProv, &hKey,<br/>"ECDSA_P256", "EcKey",<br/>AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG)
    NCrypt->>KSP: KSP_CreatePersistedKey(..., NCRYPT_PERSIST_ONLY_FLAG)

    KSP->>KSP: AllocZero(KSP_KEY)<br/>bFinalized=FALSE<br/>bPersistOnly=TRUE<br/>(NO generation)

    KSP-->>NCrypt: hKey, ERROR_SUCCESS

    note over App: Optional: modify properties before finalisation
    App->>NCrypt: NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, &dwBits, ...)
    NCrypt->>KSP: KSP_SetKeyProperty(..., L"Length", &2048, ...)
    KSP->>KSP: pKey->dwKeyBitLen = 2048

    App->>NCrypt: NCryptFinalizeKey(hKey, 0)
    NCrypt->>KSP: KSP_FinalizeKey(hProv, hKey, 0)

    note over KSP: bFinalized == FALSE → generate now

    KSP->>Session: P11_AcquireSession(&hSession)
    Session-->>KSP: hSession

    KSP->>HSM: C_GenerateKeyPair(hSession, CKM_EC_KEY_PAIR_GEN,<br/>  pubTemplate, privTemplate,<br/>  &hPubKey, &hPrivKey)

    note over HSM: CKA_EC_PARAMS = P-256 DER OID<br/>06 08 2a 86 48 ce 3d 03 01 07

    HSM-->>KSP: CKR_OK

    KSP->>Session: P11_ReleaseSession(hSession)
    KSP->>KSP: bFinalized = TRUE

    KSP-->>NCrypt: ERROR_SUCCESS
    NCrypt-->>App: ERROR_SUCCESS
```

---

## OpenKey — Reopening an existing key

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_key.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    App->>NCrypt: NCryptOpenKey(hProv, &hKey, "MyKey", 0, 0)
    NCrypt->>KSP: KSP_OpenKey(hProv, &hKey, L"MyKey", 0, 0)

    KSP->>Session: P11_AcquireSession(&hSession)
    Session-->>KSP: hSession

    KSP->>HSM: C_FindObjectsInit(hSession,<br/>  {CKA_CLASS=CKO_PRIVATE_KEY, CKA_LABEL="MyKey"})
    HSM-->>KSP: CKR_OK

    KSP->>HSM: C_FindObjects(hSession, &hObj, 1, &ulCount)
    HSM-->>KSP: hPrivKey=0x06, ulCount=1

    KSP->>HSM: C_FindObjectsFinal(hSession)

    KSP->>HSM: C_FindObjectsInit(hSession,<br/>  {CKA_CLASS=CKO_PUBLIC_KEY, CKA_LABEL="MyKey"})
    KSP->>HSM: C_FindObjects(...) → hPubKey=0x05
    KSP->>HSM: C_FindObjectsFinal(hSession)

    KSP->>HSM: C_GetAttributeValue(hSession, hPrivKey,<br/>  {CKA_KEY_TYPE})
    HSM-->>KSP: CKK_RSA

    alt RSA key
        KSP->>HSM: C_GetAttributeValue(..., CKA_MODULUS_BITS)
        HSM-->>KSP: 2048
        KSP->>KSP: szAlgId="RSA", dwKeyBitLen=2048
    else EC key
        KSP->>HSM: C_GetAttributeValue(..., CKA_EC_PARAMS)
        HSM-->>KSP: OID bytes
        alt OID == P-256 (10 bytes)
            KSP->>KSP: szAlgId="ECDSA_P256", dwKeyBitLen=256
        else OID == P-384 (7 bytes)
            KSP->>KSP: szAlgId="ECDSA_P384", dwKeyBitLen=384
        end
    end

    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: AllocZero(KSP_KEY)<br/>hPrivKey=0x06, hPubKey=0x05<br/>bFinalized=TRUE

    KSP-->>NCrypt: hKey, ERROR_SUCCESS
    NCrypt-->>App: hKey, ERROR_SUCCESS
```

---

## EnumKeys — Paginated enumeration

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_key.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    note over App: First iteration (ppEnumState == NULL)

    App->>NCrypt: NCryptEnumKeys(hProv, NULL, &pKeyName, &pEnumState, 0)
    NCrypt->>KSP: KSP_EnumKeys(hProv, NULL, &pKeyName, &pEnumState, 0)

    KSP->>Session: P11_AcquireSession(&hSession)
    Session-->>KSP: hSession

    KSP->>HSM: C_FindObjectsInit(hSession,<br/>  {CKA_CLASS=CKO_PRIVATE_KEY, CKA_TOKEN=TRUE})
    KSP->>HSM: C_FindObjects(hSession, aBuf, 256, &ulFound)
    note over HSM: Returns all private key handles<br/>stored in the token
    HSM-->>KSP: handles[0..N-1], ulFound=N
    KSP->>HSM: C_FindObjectsFinal(hSession)
    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: Allocate KSP_ENUM_STATE<br/>phObjects=handles[0..N-1]<br/>dwCount=N, dwIndex=0
    KSP->>KSP: *ppEnumState = pState

    KSP->>Session: P11_AcquireSession(&hSession)
    KSP->>HSM: C_GetAttributeValue(handles[0], CKA_LABEL)
    HSM-->>KSP: "MyKey" (UTF-8)
    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: Allocate NCryptKeyName + szName<br/>pName->pszName = "MyKey"<br/>dwIndex = 1

    KSP-->>NCrypt: *ppKeyName=pName, ERROR_SUCCESS
    NCrypt-->>App: pKeyName, ERROR_SUCCESS

    note over App: Subsequent iterations (ppEnumState != NULL)

    loop For each remaining key
        App->>NCrypt: NCryptEnumKeys(..., &pEnumState)
        NCrypt->>KSP: KSP_EnumKeys(..., &pEnumState)
        KSP->>KSP: pState->dwIndex++
        KSP->>HSM: C_GetAttributeValue(handles[i], CKA_LABEL)
        KSP-->>NCrypt: pKeyName, ERROR_SUCCESS
    end

    note over App: End of enumeration

    App->>NCrypt: NCryptEnumKeys(..., &pEnumState)
    NCrypt->>KSP: KSP_EnumKeys(...)
    KSP->>KSP: dwIndex >= dwCount<br/>→ free KSP_ENUM_STATE<br/>→ *ppEnumState = NULL
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
    note over HSM: Removes the private key from persistent storage
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

## DER OIDs for elliptic curves

Curves are identified by their DER-encoded OID passed in `CKA_EC_PARAMS`:

| Curve | OID | DER encoding |
|-------|-----|-------------|
| P-256 (secp256r1) | 1.2.840.10045.3.1.7 | `06 08 2A 86 48 CE 3D 03 01 07` (10 bytes) |
| P-384 (secp384r1) | 1.3.132.0.34 | `06 05 2B 81 04 00 22` (7 bytes) |

When reading (`OpenKey`), the OID blob length is sufficient to distinguish curves:
- 10 bytes → P-256
- 7 bytes → P-384
