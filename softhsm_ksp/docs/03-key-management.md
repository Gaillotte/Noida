# Key management — CNG → PKCS#11 mapping

## Concept mapping

| CNG concept | PKCS#11 equivalent | KSP_KEY field |
|-------------|-------------------|---------------|
| `NCRYPT_KEY_HANDLE` (asymmetric) | `CK_OBJECT_HANDLE` (pair) | `hPrivKey` + `hPubKey` |
| `NCRYPT_KEY_HANDLE` (symmetric) | `CK_OBJECT_HANDLE` (secret) | `hSecretKey` |
| `NCRYPT_SECRET_HANDLE` | `CKO_SECRET_KEY` from `C_DeriveKey` | `KSP_SECRET.hSecretObj` |
| Key name (`pszKeyName`) | `CKA_LABEL` | `szKeyName` |
| Algorithm (`pszAlgId`) | `CKM_*_KEY_GEN` / `CKM_*_KEY_PAIR_GEN` | `szAlgId` |
| `AT_SIGNATURE` | `CKA_SIGN = TRUE` | `dwKeySpec` |
| `AT_KEYEXCHANGE` (RSA) | `CKA_DECRYPT = TRUE` | `dwKeySpec` |
| `AT_KEYEXCHANGE` (ECDH) | `CKA_DERIVE = TRUE` | `dwKeySpec` |
| Persistent key | `CKA_TOKEN = TRUE` | implicit |
| Non-exportable | `CKA_EXTRACTABLE = FALSE` | implicit |

---

## Supported algorithm families

`KSP_CreatePersistedKey` validates `pszAlgId` against five families. The
classifiers in `ksp_key.c` (`KSP_IsEcdsaAlg`, `KSP_IsEcdhAlg`,
`KSP_IsEddsaAlg`, `KSP_IsSymmetricAlg`) route each name to its generator.

| Family | CNG algorithm IDs | Generator | PKCS#11 mechanism |
|--------|-------------------|-----------|-------------------|
| RSA | `RSA` | `KSP_GenerateRsaKeyPair` | `CKM_RSA_PKCS_KEY_PAIR_GEN` |
| ECDSA | `ECDSA_P256`, `ECDSA_P384`, `ECDSA_P521` | `KSP_GenerateEcKeyPair` | `CKM_EC_KEY_PAIR_GEN` |
| ECDH | `ECDH_P256`, `ECDH_P384`, `ECDH_P521` | `KSP_GenerateEcKeyPair` | `CKM_EC_KEY_PAIR_GEN` |
| EdDSA | `EDDSA_ED25519`, `EDDSA_ED448` | `KSP_GenerateEddsaKeyPair` | `CKM_EC_EDWARDS_KEY_PAIR_GEN` |
| Symmetric | `AES`, `HMAC_SHA1/256/384/512` | `KSP_GenerateSymmetricKey` | `CKM_AES_KEY_GEN`, `CKM_GENERIC_SECRET_KEY_GEN` |

ECDSA and ECDH share both the generator and the curve OIDs. They differ only
in the attributes set on the pair:

| | ECDSA | ECDH |
|---|---|---|
| `CKA_SIGN` / `CKA_VERIFY` | `TRUE` | `FALSE` |
| `CKA_DERIVE` | `FALSE` | `TRUE` |
| `dwKeySpec` | `AT_SIGNATURE` | `AT_KEYEXCHANGE` (forced) |

An ECDH key is always created as `AT_KEYEXCHANGE` even when the caller asks
for `AT_SIGNATURE`, because a derive-only key cannot sign.

### Default key sizes

| Algorithm | Default | Settable before `FinalizeKey` |
|-----------|---------|-------------------------------|
| `RSA` | 2048 | 2048 / 3072 / 4096 |
| `ECDSA_*` / `ECDH_*` | fixed by curve | curve value only |
| `EDDSA_ED25519` | 255 | fixed |
| `EDDSA_ED448` | 448 | fixed |
| `AES` | 256 | 128 / 192 / 256 |
| `HMAC_SHA1` | 160 | any whole-byte size ≥ 128 |
| `HMAC_SHA256` | 256 | any whole-byte size ≥ 128 |
| `HMAC_SHA384` | 384 | any whole-byte size ≥ 128 |
| `HMAC_SHA512` | 512 | any whole-byte size ≥ 128 |

Sizes outside these sets return `NTE_BAD_LEN`.

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
| P-521 (secp521r1) | 1.3.132.0.35 | `06 05 2B 81 04 00 23` (7 bytes) |
| Ed25519 | 1.3.101.112 | `06 03 2B 65 70` (5 bytes) |
| Ed448 | 1.3.101.113 | `06 03 2B 65 71` (5 bytes) |

`P11_GetCurveOid()` in `p11_utils.c` maps an algorithm name to its OID; both
the ECDSA and ECDH name for a curve return the same bytes.

### Identifying a curve when reopening a key

`KSP_OpenKey` reads `CKA_EC_PARAMS` and compares the **bytes**, not the
length. Length alone is not sufficient: P-384 and P-521 are both 7 bytes,
and Ed25519 and Ed448 are both 5. The final byte is what separates each
pair (`0x22` vs `0x23`, `0x70` vs `0x71`).

`CKA_DERIVE` is then read to decide between the ECDSA and ECDH name for the
identified curve:

```
CKA_EC_PARAMS bytes  ──▶ curve      ──┐
                                      ├──▶ szAlgId
CKA_DERIVE           ──▶ ECDH or ECDSA┘
```

A key whose `CKA_EC_PARAMS` matches an Edwards OID is always EdDSA — those
curves are signature-only, so `CKA_DERIVE` is not consulted.

---

## Symmetric keys

Symmetric keys have no key pair. `KSP_GenerateSymmetricKey` calls
`C_GenerateKey` and stores the single resulting handle in `hSecretKey`,
leaving `hPrivKey` and `hPubKey` at `CK_INVALID_HANDLE`.

| Attribute | AES | HMAC |
|-----------|-----|------|
| `CKA_CLASS` | `CKO_SECRET_KEY` | `CKO_SECRET_KEY` |
| `CKA_KEY_TYPE` | `CKK_AES` | `CKK_GENERIC_SECRET` |
| `CKA_VALUE_LEN` | 16 / 24 / 32 | hash size in bytes |
| `CKA_ENCRYPT` / `CKA_DECRYPT` | `TRUE` | `FALSE` |
| `CKA_SIGN` / `CKA_VERIFY` | `FALSE` | `TRUE` |
| `CKA_TOKEN` | `TRUE` | `TRUE` |
| `CKA_SENSITIVE` | `TRUE` | `TRUE` |
| `CKA_EXTRACTABLE` | `FALSE` | `FALSE` |

### Reopening a symmetric key

`KSP_OpenKey` first searches for a `CKO_PRIVATE_KEY` with the requested
label. When none is found it retries as `CKO_SECRET_KEY` before giving up
with `NTE_BAD_KEYSET`, so an AES or HMAC key reopens by name like any other:

```
P11_FindObjectByLabel(CKO_PRIVATE_KEY, name)
  ├── found     ──▶ asymmetric path (read CKA_KEY_TYPE, CKA_EC_PARAMS)
  └── not found ──▶ P11_FindObjectByLabel(CKO_SECRET_KEY, name)
                      ├── found     ──▶ symmetric path (read CKA_VALUE_LEN)
                      └── not found ──▶ NTE_BAD_KEYSET
```

`CKA_KEY_TYPE` then selects the reported algorithm: `CKK_AES` reports `AES`,
anything else reports `HMAC_SHA256`. The key length comes from
`CKA_VALUE_LEN × 8`.

> Because PKCS#11 stores no HMAC hash choice on a generic secret, a reopened
> HMAC key always reports `HMAC_SHA256`. Reopen an HMAC key by name only when
> SHA-256 is the intended hash; otherwise keep the original handle.

---

## Key deletion and release

`KSP_DeleteKey` destroys whichever object handles are set — private, public
and secret — then frees the wrapper.

`KSP_FreeKey` normally frees only the wrapper and leaves token objects in
place. The exception is an **imported public key**: `KSP_ImportKey` creates
a session object and sets `bSessionObject = TRUE`, so `KSP_FreeKey` destroys
it rather than leaking it into the session.
