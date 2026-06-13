# Flux de bout en bout — Scénarios complets

## Scénario 1 : Génération et utilisation d'une clé RSA pour signature TLS

Ce scénario illustre le flux complet depuis une application (ex: serveur IIS/Schannel)
jusqu'à SoftHSM2.

```mermaid
sequenceDiagram
    participant IIS as Serveur IIS / Schannel
    participant NCrypt as ncrypt.dll
    participant KSP as softhsm_ksp.dll
    participant HSM as softhsm2-x64.dll

    rect rgb(230, 245, 255)
        note over IIS,HSM: Phase 1 — Génération du certificat (une seule fois)

        IIS->>NCrypt: NCryptOpenStorageProvider("SoftHSM KSP")
        NCrypt->>KSP: KSP_OpenProvider() → P11_Initialize()
        KSP->>HSM: LoadLibrary + C_Initialize + C_GetSlotList

        IIS->>NCrypt: NCryptCreatePersistedKey(..., "RSA", "WebServerKey", AT_KEYEXCHANGE)
        NCrypt->>KSP: KSP_CreatePersistedKey()
        KSP->>HSM: C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN,\nbits=2048, DECRYPT=TRUE)

        IIS->>NCrypt: NCryptExportKey(..., BCRYPT_RSAPUBLIC_BLOB)
        NCrypt->>KSP: KSP_ExportKey()
        KSP->>HSM: C_GetAttributeValue(CKA_MODULUS + CKA_PUBLIC_EXPONENT)
        KSP-->>IIS: BCRYPT_RSAKEY_BLOB (clé publique)

        note over IIS: Crée CSR avec la clé publique,<br/>soumet à la CA, reçoit certificat X.509
    end

    rect rgb(255, 245, 230)
        note over IIS,HSM: Phase 2 — Handshake TLS (à chaque connexion client)

        IIS->>NCrypt: NCryptOpenKey(..., "WebServerKey")
        NCrypt->>KSP: KSP_OpenKey()
        KSP->>HSM: C_FindObjectsInit/C_FindObjects (label="WebServerKey")

        note over IIS: Reçoit ClientKeyExchange chiffré RSA

        IIS->>NCrypt: NCryptDecrypt(hKey, pbEncryptedPMS, 256,\n&oaepInfo, pbPMS, &cbPMS, OAEP)
        NCrypt->>KSP: KSP_Decrypt()
        KSP->>HSM: C_DecryptInit(CKM_RSA_PKCS_OAEP)\nC_Decrypt(pbEncryptedPMS, pbPMS)
        KSP-->>IIS: Pre-Master Secret déchiffré

        note over IIS: Dérive les clés de session TLS
    end
```

---

## Scénario 2 : Signature de code avec ECDSA P-256

```mermaid
sequenceDiagram
    participant Tool as Outil de signature
    participant NCrypt as ncrypt.dll
    participant KSP as softhsm_ksp.dll
    participant BCrypt as bcrypt.dll
    participant HSM as softhsm2-x64.dll

    Tool->>NCrypt: NCryptOpenStorageProvider("SoftHSM KSP")
    Tool->>NCrypt: NCryptCreatePersistedKey(..., "ECDSA_P256",\n"CodeSignKey", AT_SIGNATURE)
    NCrypt->>KSP: KSP_CreatePersistedKey()
    KSP->>HSM: C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN,\nEC_PARAMS=P-256 OID)

    note over Tool: Calcule SHA-256 du binaire à signer

    Tool->>BCrypt: BCryptCreateHash(SHA256) + BCryptFinishHash
    BCrypt-->>Tool: pbHash[32]

    Tool->>NCrypt: NCryptSignHash(hKey, NULL,\npbHash, 32, NULL, 0, &cbSig, 0)
    NCrypt->>KSP: KSP_SignHash(..., NULL) → cbSig=64
    KSP->>HSM: C_SignInit(CKM_ECDSA) + C_Sign(..., NULL, &cbDer)
    KSP-->>Tool: cbSig=64

    Tool->>NCrypt: NCryptSignHash(hKey, NULL,\npbHash, 32, pbSig, 64, &cbSig, 0)
    NCrypt->>KSP: KSP_SignHash(..., pbSig)
    KSP->>HSM: C_SignInit(CKM_ECDSA) + C_Sign(pbHash, 32, pbRawDer, &cbDer)
    HSM-->>KSP: [30 44 02 20 <r> 02 20 <s>] (DER, ~70 octets)
    KSP->>KSP: P11_DecodeDerEcdsaSignature()<br/>→ pbSig[0..31]=r, pbSig[32..63]=s
    KSP-->>Tool: Signature Windows (64 octets r‖s)

    note over Tool: Vérification côté validateur (BCrypt)

    Tool->>BCrypt: BCryptVerifySignature(hBCryptPubKey,\npbHash, pbSig, 64, 0)
    BCrypt-->>Tool: STATUS_SUCCESS (signature valide)
```

---

## Scénario 3 : Énumération et audit des clés

```mermaid
sequenceDiagram
    participant Audit as Script PowerShell
    participant NCrypt as ncrypt.dll
    participant KSP as softhsm_ksp.dll
    participant HSM as softhsm2-x64.dll

    Audit->>NCrypt: NCryptOpenStorageProvider("SoftHSM KSP")

    note over Audit,HSM: Première itération (initialise l'état)

    Audit->>NCrypt: NCryptEnumKeys(hProv, NULL,\n&pKeyName, &pState, 0)
    NCrypt->>KSP: KSP_EnumKeys(..., ppEnumState=NULL)
    KSP->>HSM: C_FindObjectsInit({CKA_CLASS=CKO_PRIVATE_KEY, CKA_TOKEN=TRUE})
    KSP->>HSM: C_FindObjects(256 max) → N handles
    KSP->>HSM: C_FindObjectsFinal()
    KSP->>KSP: Alloue KSP_ENUM_STATE{handles[0..N-1], idx=0}
    KSP->>HSM: C_GetAttributeValue(handles[0], CKA_LABEL) → "WebServerKey"
    KSP-->>Audit: pKeyName.pszName="WebServerKey"

    loop Pour chaque clé suivante (idx=1..N-1)
        Audit->>NCrypt: NCryptEnumKeys(..., &pState)
        NCrypt->>KSP: KSP_EnumKeys(ppEnumState=pState)
        KSP->>HSM: C_GetAttributeValue(handles[idx], CKA_LABEL)
        KSP-->>Audit: pKeyName.pszName=<label>
        Audit->>Audit: NCryptGetProperty(hKeyTmp, NCRYPT_ALGORITHM_PROPERTY)\n→ "RSA" ou "ECDSA_P256"
        Audit->>Audit: NCryptGetProperty(hKeyTmp, NCRYPT_LENGTH_PROPERTY)\n→ 2048, 256, etc.
        Audit->>Audit: Journalise : label + algo + bits
    end

    Audit->>NCrypt: NCryptEnumKeys(..., &pState)
    NCrypt->>KSP: KSP_EnumKeys() → idx >= count
    KSP->>KSP: Libère KSP_ENUM_STATE, *ppState=NULL
    KSP-->>Audit: NTE_NO_MORE_ITEMS
```

---

## Scénario 4 : Rotation de clé

```mermaid
sequenceDiagram
    participant Ops as Opérateur
    participant NCrypt as ncrypt.dll
    participant KSP as softhsm_ksp.dll
    participant HSM as softhsm2-x64.dll

    note over Ops,HSM: Étape 1 : Générer la nouvelle clé sous un nom temporaire

    Ops->>NCrypt: NCryptCreatePersistedKey(..., "RSA", "WebKey_v2", AT_KEYEXCHANGE)
    NCrypt->>KSP: KSP_CreatePersistedKey()
    KSP->>HSM: C_GenerateKeyPair("WebKey_v2", 4096 bits)

    note over Ops: Exporte la clé publique v2, fait signer<br/>un nouveau certificat par la CA

    note over Ops,HSM: Étape 2 : Bascule (ancienne clé gardée pendant la période de transition)

    Ops->>NCrypt: NCryptOpenKey(..., "WebKey_v1")
    note over Ops: Utilise WebKey_v2 pour les nouvelles connexions,<br/>WebKey_v1 pour les sessions en cours

    note over Ops,HSM: Étape 3 : Suppression de l'ancienne clé

    Ops->>NCrypt: NCryptDeleteKey(hKeyV1)
    NCrypt->>KSP: KSP_DeleteKey()
    KSP->>HSM: C_DestroyObject(hPrivV1)
    KSP->>HSM: C_DestroyObject(hPubV1)
    note over HSM: Clé v1 définitivement supprimée du token
```

---

## Scénario 5 : Récupération d'erreur — Token absent

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as softhsm_ksp.dll
    participant P11 as p11_context.c

    note over P11: SOFTHSM2_LIB pointe vers une DLL absente

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

    note over App: SOFTHSM2_LIB corrigé (redémarrage nécessaire,<br/>InitOnceExecuteOnce est one-shot)
```

> **Limitation** : `InitOnceExecuteOnce` exécute le callback exactement une fois
> par processus, même en cas d'échec. Si la DLL SoftHSM2 est absente au premier
> appel, le processus devra être redémarré après correction du chemin.

---

## Vue d'ensemble des dépendances entre modules

```mermaid
graph TB
    subgraph KSP["Couche KSP"]
        ksp_main["ksp_main.c\nGetKeyStorageInterface\nDllMain"]
        ksp_prov["ksp_provider.c\nOpenProvider\nFreeProvider"]
        ksp_key["ksp_key.c\nCreateKey / OpenKey\nDeleteKey / EnumKeys"]
        ksp_crypto["ksp_crypto.c\nSignHash / Decrypt\nExportKey / ImportKey"]
        ksp_props["ksp_properties.c\nGetKeyProperty\nSetKeyProperty"]
    end

    subgraph P11["Couche PKCS#11"]
        p11_ctx["p11_context.c\nSingleton\nLoadLibrary"]
        p11_sess["p11_session.c\nPool de sessions\nAcquire / Release"]
        p11_utils["p11_utils.c\nMécanismes\nConversions"]
    end

    subgraph Common["Commun"]
        config["config.h\nConstantes"]
        logging["logging.c\nOutputDebugString"]
        memory["memory.c\nHeapAlloc / HeapFree"]
    end

    subgraph Windows["Windows SDK"]
        ncrypt["ncrypt.lib"]
        bcrypt["bcrypt.lib"]
    end

    HSM["softhsm2-x64.dll\n(dynamique)"]

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
