# End-to-end flows — Complete scenarios

## Scenario 1: Generating and using an RSA key for TLS signing

This scenario illustrates the complete flow from an application (e.g. IIS/Schannel server)
to SoftHSM2.

```mermaid
sequenceDiagram
    participant IIS as IIS Server / Schannel
    participant NCrypt as ncrypt.dll
    participant KSP as softhsm_ksp.dll
    participant HSM as softhsm2-x64.dll

    rect rgb(230, 245, 255)
        note over IIS,HSM: Phase 1 — Certificate generation (once)

        IIS->>NCrypt: NCryptOpenStorageProvider("SoftHSM KSP")
        NCrypt->>KSP: KSP_OpenProvider() → P11_Initialize()
        KSP->>HSM: LoadLibrary + C_Initialize + C_GetSlotList

        IIS->>NCrypt: NCryptCreatePersistedKey(..., "RSA", "WebServerKey", AT_KEYEXCHANGE)
        NCrypt->>KSP: KSP_CreatePersistedKey()
        KSP->>HSM: C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN,<br/>bits=2048, DECRYPT=TRUE)

        IIS->>NCrypt: NCryptExportKey(..., BCRYPT_RSAPUBLIC_BLOB)
        NCrypt->>KSP: KSP_ExportKey()
        KSP->>HSM: C_GetAttributeValue(CKA_MODULUS + CKA_PUBLIC_EXPONENT)
        KSP-->>IIS: BCRYPT_RSAKEY_BLOB (public key)

        note over IIS: Creates CSR with the public key,<br/>submits to CA, receives X.509 certificate
    end

    rect rgb(255, 245, 230)
        note over IIS,HSM: Phase 2 — TLS handshake (on every client connection)

        IIS->>NCrypt: NCryptOpenKey(..., "WebServerKey")
        NCrypt->>KSP: KSP_OpenKey()
        KSP->>HSM: C_FindObjectsInit/C_FindObjects (label="WebServerKey")

        note over IIS: Receives RSA-encrypted ClientKeyExchange

        IIS->>NCrypt: NCryptDecrypt(hKey, pbEncryptedPMS, 256,<br/>&oaepInfo, pbPMS, &cbPMS, OAEP)
        NCrypt->>KSP: KSP_Decrypt()
        KSP->>HSM: C_DecryptInit(CKM_RSA_PKCS_OAEP)<br/>C_Decrypt(pbEncryptedPMS, pbPMS)
        KSP-->>IIS: Decrypted Pre-Master Secret

        note over IIS: Derives TLS session keys
    end
```

---

## Scenario 2: Code signing with ECDSA P-256

```mermaid
sequenceDiagram
    participant Tool as Signing tool
    participant NCrypt as ncrypt.dll
    participant KSP as softhsm_ksp.dll
    participant BCrypt as bcrypt.dll
    participant HSM as softhsm2-x64.dll

    Tool->>NCrypt: NCryptOpenStorageProvider("SoftHSM KSP")
    Tool->>NCrypt: NCryptCreatePersistedKey(..., "ECDSA_P256",<br/>"CodeSignKey", AT_SIGNATURE)
    NCrypt->>KSP: KSP_CreatePersistedKey()
    KSP->>HSM: C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN,<br/>EC_PARAMS=P-256 OID)

    note over Tool: Computes SHA-256 of the binary to sign

    Tool->>BCrypt: BCryptCreateHash(SHA256) + BCryptFinishHash
    BCrypt-->>Tool: pbHash[32]

    Tool->>NCrypt: NCryptSignHash(hKey, NULL,<br/>pbHash, 32, NULL, 0, &cbSig, 0)
    NCrypt->>KSP: KSP_SignHash(..., NULL) → cbSig=64
    KSP->>HSM: C_SignInit(CKM_ECDSA) + C_Sign(..., NULL, &cbDer)
    KSP-->>Tool: cbSig=64

    Tool->>NCrypt: NCryptSignHash(hKey, NULL,<br/>pbHash, 32, pbSig, 64, &cbSig, 0)
    NCrypt->>KSP: KSP_SignHash(..., pbSig)
    KSP->>HSM: C_SignInit(CKM_ECDSA) + C_Sign(pbHash, 32, pbRawDer, &cbDer)
    HSM-->>KSP: [30 44 02 20 <r> 02 20 <s>] (DER, ~70 bytes)
    KSP->>KSP: P11_DecodeDerEcdsaSignature()<br/>→ pbSig[0..31]=r, pbSig[32..63]=s
    KSP-->>Tool: Windows signature (64 bytes r‖s)

    note over Tool: Verification on the validator side (BCrypt)

    Tool->>BCrypt: BCryptVerifySignature(hBCryptPubKey,<br/>pbHash, pbSig, 64, 0)
    BCrypt-->>Tool: STATUS_SUCCESS (valid signature)
```

---

## Scenario 3: Key enumeration and audit

```mermaid
sequenceDiagram
    participant Audit as PowerShell script
    participant NCrypt as ncrypt.dll
    participant KSP as softhsm_ksp.dll
    participant HSM as softhsm2-x64.dll

    Audit->>NCrypt: NCryptOpenStorageProvider("SoftHSM KSP")

    note over Audit,HSM: First iteration (initialises state)

    Audit->>NCrypt: NCryptEnumKeys(hProv, NULL,<br/>&pKeyName, &pState, 0)
    NCrypt->>KSP: KSP_EnumKeys(..., ppEnumState=NULL)
    KSP->>HSM: C_FindObjectsInit({CKA_CLASS=CKO_PRIVATE_KEY, CKA_TOKEN=TRUE})
    KSP->>HSM: C_FindObjects(256 max) → N handles
    KSP->>HSM: C_FindObjectsFinal()
    KSP->>KSP: Allocate KSP_ENUM_STATE{handles[0..N-1], idx=0}
    KSP->>HSM: C_GetAttributeValue(handles[0], CKA_LABEL) → "WebServerKey"
    KSP-->>Audit: pKeyName.pszName="WebServerKey"

    loop For each subsequent key (idx=1..N-1)
        Audit->>NCrypt: NCryptEnumKeys(..., &pState)
        NCrypt->>KSP: KSP_EnumKeys(ppEnumState=pState)
        KSP->>HSM: C_GetAttributeValue(handles[idx], CKA_LABEL)
        KSP-->>Audit: pKeyName.pszName=<label>
        Audit->>Audit: NCryptGetProperty(hKeyTmp, NCRYPT_ALGORITHM_PROPERTY)<br/>→ "RSA" or "ECDSA_P256"
        Audit->>Audit: NCryptGetProperty(hKeyTmp, NCRYPT_LENGTH_PROPERTY)<br/>→ 2048, 256, etc.
        Audit->>Audit: Log: label + algo + bits
    end

    Audit->>NCrypt: NCryptEnumKeys(..., &pState)
    NCrypt->>KSP: KSP_EnumKeys() → idx >= count
    KSP->>KSP: Free KSP_ENUM_STATE, *ppState=NULL
    KSP-->>Audit: NTE_NO_MORE_ITEMS
```

---

## Scenario 4: Key rotation

```mermaid
sequenceDiagram
    participant Ops as Operator
    participant NCrypt as ncrypt.dll
    participant KSP as softhsm_ksp.dll
    participant HSM as softhsm2-x64.dll

    note over Ops,HSM: Step 1: Generate the new key under a temporary name

    Ops->>NCrypt: NCryptCreatePersistedKey(..., "RSA", "WebKey_v2", AT_KEYEXCHANGE)
    NCrypt->>KSP: KSP_CreatePersistedKey()
    KSP->>HSM: C_GenerateKeyPair("WebKey_v2", 4096 bits)

    note over Ops: Exports the v2 public key, has a new<br/>certificate signed by the CA

    note over Ops,HSM: Step 2: Switch (old key kept during the transition period)

    Ops->>NCrypt: NCryptOpenKey(..., "WebKey_v1")
    note over Ops: Use WebKey_v2 for new connections,<br/>WebKey_v1 for in-flight sessions

    note over Ops,HSM: Step 3: Delete the old key

    Ops->>NCrypt: NCryptDeleteKey(hKeyV1)
    NCrypt->>KSP: KSP_DeleteKey()
    KSP->>HSM: C_DestroyObject(hPrivV1)
    KSP->>HSM: C_DestroyObject(hPubV1)
    note over HSM: Key v1 permanently deleted from the token
```

---

## Scenario 5: Error recovery — Missing token

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as softhsm_ksp.dll
    participant P11 as p11_context.c

    note over P11: SOFTHSM2_LIB points to a missing DLL

    App->>NCrypt: NCryptOpenStorageProvider("SoftHSM KSP")
    NCrypt->>KSP: KSP_OpenProvider()
    KSP->>P11: P11_Initialize()
    P11->>P11: LoadLibrary("C:\...\softhsm2-x64.dll")
    note over P11: GetLastError() = ERROR_MOD_NOT_FOUND
    P11->>P11: hModule = NULL
    P11->>P11: g_initStatus = NTE_PROVIDER_DLL_FAIL
    P11-->>KSP: NTE_PROVIDER_DLL_FAIL

    KSP-->>NCrypt: NTE_PROVIDER_DLL_FAIL
    NCrypt-->>App: NTE_PROVIDER_DLL_FAIL (0x80090011)

    note over App: SOFTHSM2_LIB corrected (restart needed,<br/>InitOnceExecuteOnce is one-shot)
```

> **Limitation**: `InitOnceExecuteOnce` executes the callback exactly once
> per process, even on failure. If the SoftHSM2 DLL is absent on the first
> call, the process must be restarted after correcting the path.

---

## Scenario 6: ECDH key agreement between two parties

The strongest end-to-end test in the suite: two independently generated key
pairs must arrive at the same shared secret. This is the ECDHE handshake at
the heart of TLS 1.3.

```mermaid
sequenceDiagram
    participant A as Party A
    participant KSP as softhsm_ksp.dll
    participant HSM as SoftHSM2
    participant B as Party B

    note over A,B: 1 — Each party generates an ECDH key pair

    A->>KSP: NCryptCreatePersistedKey("ECDH_P256", "KeyA", AT_KEYEXCHANGE)
    KSP->>HSM: C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN,<br/>CKA_EC_PARAMS=P-256 OID,<br/>CKA_DERIVE=TRUE, CKA_SIGN=FALSE)
    HSM-->>KSP: hPrivA, hPubA

    B->>KSP: NCryptCreatePersistedKey("ECDH_P256", "KeyB", AT_KEYEXCHANGE)
    KSP->>HSM: C_GenerateKeyPair(...)
    HSM-->>KSP: hPrivB, hPubB

    note over A,B: 2 — Public keys are exchanged over the wire

    A->>KSP: NCryptExportKey(hKeyA, ECCPUBLICBLOB)
    KSP->>HSM: C_GetAttributeValue(hPubA, CKA_EC_POINT)
    KSP-->>A: BCRYPT_ECCKEY_BLOB { magic, cbKey=32 } ‖ X ‖ Y

    B->>KSP: NCryptExportKey(hKeyB, ECCPUBLICBLOB)
    KSP-->>B: BCRYPT_ECCKEY_BLOB ‖ X ‖ Y

    note over A,B: A sends its blob to B, B sends its blob to A

    note over A,B: 3 — Each imports the peer's public key

    A->>KSP: NCryptImportKey(ECCPUBLICBLOB, blobB) → hPubB'
    KSP->>KSP: P11_BuildEcPointDer(X, Y, 32)
    KSP->>HSM: C_CreateObject(CKO_PUBLIC_KEY,<br/>CKA_EC_POINT=DER, CKA_DERIVE=TRUE)
    HSM-->>KSP: hPubB' (session object)

    B->>KSP: NCryptImportKey(ECCPUBLICBLOB, blobA) → hPubA'

    note over A,B: 4 — Each derives the shared secret

    A->>KSP: NCryptSecretAgreement(hKeyA, hPubB', &hSecretA)
    KSP->>KSP: Curves match (both 32-byte coords)
    KSP->>HSM: C_DeriveKey(CKM_ECDH1_DERIVE,<br/>{CKD_NULL, pPublicData=04‖Xb‖Yb}, hPrivA)
    note over HSM: Z = d_A · Q_B
    HSM-->>KSP: hDerivedA

    B->>KSP: NCryptSecretAgreement(hKeyB, hPubA', &hSecretB)
    KSP->>HSM: C_DeriveKey(..., hPrivB)
    note over HSM: Z = d_B · Q_A
    HSM-->>KSP: hDerivedB

    A->>KSP: NCryptDeriveKey(hSecretA, "TRUNCATE") → secretA (32 bytes)
    B->>KSP: NCryptDeriveKey(hSecretB, "TRUNCATE") → secretB (32 bytes)

    note over A,B: secretA == secretB — both sides computed the same Z

    A->>KSP: NCryptFreeObject(hSecretA)
    KSP->>HSM: C_DestroyObject(hDerivedA)
    B->>KSP: NCryptFreeObject(hSecretB)
    KSP->>HSM: C_DestroyObject(hDerivedB)
```

The mathematics behind the assertion: `d_A · Q_B = d_A · (d_B · G) =
d_B · (d_A · G) = d_B · Q_A`. Integration test 27 and HLK section S11 both
assert the two derived buffers are byte-identical, which fails if the DER
point unwrapping or the curve check is wrong.

> Attempting agreement across different curves (P-256 private with a P-384
> peer) returns `NTE_BAD_ALGID` before any PKCS#11 call.

---

## Scenario 7: AES data encryption

```mermaid
sequenceDiagram
    participant App as Application
    participant KSP as softhsm_ksp.dll
    participant HSM as SoftHSM2

    note over App: 1 — Create an AES-256 key (deferred, so Length can be set)

    App->>KSP: NCryptCreatePersistedKey("AES", "DataKey",<br/>0, NCRYPT_PERSIST_ONLY_FLAG)
    App->>KSP: NCryptSetProperty(hKey, "Length", 256)
    App->>KSP: NCryptFinalizeKey(hKey)
    KSP->>HSM: C_GenerateKey(CKM_AES_KEY_GEN,<br/>CKA_VALUE_LEN=32, CKA_ENCRYPT=TRUE,<br/>CKA_SENSITIVE=TRUE, CKA_EXTRACTABLE=FALSE)
    HSM-->>KSP: hSecretKey

    note over App: 2 — Select the mode and nonce as key properties

    App->>KSP: NCryptSetProperty(hKey, "Chaining Mode", "ChainingModeGCM")
    App->>KSP: NCryptSetProperty(hKey, "IV", nonce, 12)
    note over KSP: Stored in pKey->szChainingMode and pKey->pbIV

    note over App: 3 — Encrypt

    App->>KSP: NCryptEncrypt(hKey, plaintext, 32, NULL,<br/>NULL, 0, &cbNeeded, 0)
    KSP->>KSP: KspBuildAesMechanism() → CKM_AES_GCM<br/>+ CK_GCM_PARAMS {pIv, 12, 96 bits, tag=128}
    KSP->>HSM: C_EncryptInit + C_Encrypt(NULL) → size
    KSP-->>App: cbNeeded

    App->>KSP: NCryptEncrypt(hKey, plaintext, 32, NULL,<br/>ciphertext, cbNeeded, &cbResult, 0)
    KSP->>HSM: C_EncryptInit + C_Encrypt
    HSM-->>KSP: ciphertext ‖ 16-byte GCM tag
    KSP-->>App: ERROR_SUCCESS

    note over App: 4 — Decrypt: the IV must be set again

    App->>KSP: NCryptSetProperty(hKey, "IV", nonce, 12)
    App->>KSP: NCryptDecrypt(hKey, ciphertext, ...)
    KSP->>HSM: C_DecryptInit + C_Decrypt
    HSM-->>KSP: plaintext (tag verified)
    KSP-->>App: ERROR_SUCCESS
```

> **The IV is consumed by the operation.** Re-set
> `NCRYPT_INITIALIZATION_VECTOR` before the matching decrypt, exactly as
> BCrypt requires. Forgetting this is the most common AES integration bug.

---

## Module dependency overview

```mermaid
graph TB
    subgraph KSP["KSP layer"]
        ksp_main["ksp_main.c\nGetKeyStorageInterface\nDllMain"]
        ksp_prov["ksp_provider.c\nOpenProvider\nFreeProvider"]
        ksp_key["ksp_key.c\nCreateKey / OpenKey\nDeleteKey / EnumKeys"]
        ksp_crypto["ksp_crypto.c\nSignHash / Decrypt\nExportKey / ImportKey"]
        ksp_props["ksp_properties.c\nGetKeyProperty\nSetKeyProperty"]
    end

    subgraph P11["PKCS#11 layer"]
        p11_ctx["p11_context.c\nSingleton\nLoadLibrary"]
        p11_sess["p11_session.c\nSession pool\nAcquire / Release"]
        p11_utils["p11_utils.c\nMechanisms\nConversions"]
    end

    subgraph Common["Common"]
        config["config.h\nConstants"]
        logging["logging.c\nOutputDebugString"]
        memory["memory.c\nHeapAlloc / HeapFree"]
    end

    subgraph Windows["Windows SDK"]
        ncrypt["ncrypt.lib"]
        bcrypt["bcrypt.lib"]
    end

    HSM["softhsm2-x64.dll\n(dynamic)"]

    ksp_main --> ksp_prov
    ksp_main --> ksp_key
    ksp_main --> ksp_crypto
    ksp_main --> ksp_props
    ksp_prov --> p11_ctx
    ksp_prov --> p11_sess
    ksp_key --> p11_ctx
    ksp_key --> p11_sess
    ksp_key --> p11_utils
    ksp_crypto --> p11_sess
    ksp_crypto --> p11_utils
    ksp_props --> ksp_key

    p11_ctx --> HSM
    p11_sess --> p11_ctx
    p11_utils --> p11_ctx
    p11_utils --> memory

    ksp_key --> memory
    ksp_crypto --> memory
    ksp_prov --> memory
    ksp_key --> logging
    ksp_crypto --> logging
    ksp_prov --> logging
    p11_ctx --> logging
    p11_sess --> logging

    ksp_main --> ncrypt
    ksp_main --> bcrypt
```
