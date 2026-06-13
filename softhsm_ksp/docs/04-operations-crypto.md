# Opérations cryptographiques — Mapping CNG → PKCS#11

## Vue d'ensemble du mapping des mécanismes

| Appel CNG | Flag / Info | Mécanisme PKCS#11 | Paramètres |
|-----------|------------|-------------------|------------|
| `SignHash("RSA")` | `NCRYPT_PAD_PKCS1_FLAG` | `CKM_RSA_PKCS` | aucun |
| `SignHash("RSA")` | `NCRYPT_PAD_PSS_FLAG` + `BCRYPT_PSS_PADDING_INFO` | `CKM_RSA_PKCS_PSS` | `CK_RSA_PKCS_PSS_PARAMS` |
| `SignHash("ECDSA_P256")` | — | `CKM_ECDSA` | aucun |
| `SignHash("ECDSA_P384")` | — | `CKM_ECDSA` | aucun |
| `Decrypt("RSA")` | `NCRYPT_PAD_PKCS1_FLAG` | `CKM_RSA_PKCS` | aucun |
| `Decrypt("RSA")` | `NCRYPT_PAD_OAEP_FLAG` + `BCRYPT_OAEP_PADDING_INFO` | `CKM_RSA_PKCS_OAEP` | `CK_RSA_PKCS_OAEP_PARAMS` |

---

## SignHash — RSA PKCS#1 v1.5

### Pattern double-appel CNG

CNG impose un protocole en deux étapes : le premier appel avec `pbSignature=NULL`
retourne la taille requise, le second effectue la signature réelle.

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_crypto.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    note over App: Étape 1 : obtenir la taille

    App->>NCrypt: NCryptSignHash(hKey, NULL, pbHash, 32,<br/>NULL, 0, &cbResult, NCRYPT_PAD_PKCS1_FLAG)
    NCrypt->>KSP: KSP_SignHash(..., NULL, cbHash=32,<br/>pbSignature=NULL, cbSignature=0, &cbResult)

    KSP->>KSP: P11_ResolveMechanism("RSA", PKCS1_FLAG)<br/>→ mech = {CKM_RSA_PKCS, NULL, 0}

    KSP->>Session: P11_AcquireSession(&hSession)
    Session-->>KSP: hSession

    KSP->>HSM: C_SignInit(hSession, CKM_RSA_PKCS, hPrivKey)
    HSM-->>KSP: CKR_OK

    KSP->>HSM: C_Sign(hSession, pbHash, 32,<br/>pSignature=NULL, &cbRawSig)
    note over HSM: SoftHSM2 retourne la taille sans signer
    HSM-->>KSP: CKR_OK, cbRawSig=256

    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: pbSignature == NULL → retourne juste la taille<br/>*pcbResult = 256
    KSP-->>NCrypt: ERROR_SUCCESS, cbResult=256
    NCrypt-->>App: ERROR_SUCCESS, cbResult=256

    note over App: Étape 2 : signature effective

    App->>NCrypt: NCryptSignHash(hKey, NULL, pbHash, 32,<br/>pbSig, 256, &cbResult, NCRYPT_PAD_PKCS1_FLAG)
    NCrypt->>KSP: KSP_SignHash(..., pbSignature=pbSig, cbSignature=256)

    KSP->>Session: P11_AcquireSession(&hSession)

    KSP->>HSM: C_SignInit(hSession, CKM_RSA_PKCS, hPrivKey)
    HSM-->>KSP: CKR_OK

    KSP->>HSM: C_Sign(hSession, pbHash, 32, pbRawSig, &cbRawSig)
    note over HSM: Signature RSA PKCS#1 v1.5<br/>Résultat = RSASP1(privKey, EM)<br/>EM = 0x00 0x01 0xFF...FF 0x00 DigestInfo || hash
    HSM-->>KSP: CKR_OK, signature 256 octets

    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: memcpy(pbSignature, pbRawSig, 256)<br/>*pcbResult = 256

    KSP-->>NCrypt: ERROR_SUCCESS, cbResult=256
    NCrypt-->>App: ERROR_SUCCESS
```

---

## SignHash — RSA PSS

### Mapping BCRYPT_PSS_PADDING_INFO → CK_RSA_PKCS_PSS_PARAMS

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_crypto.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    App->>NCrypt: NCryptSignHash(hKey, &pssInfo, pbHash, 32,<br/>pbSig, 256, &cbResult, NCRYPT_PAD_PSS_FLAG)

    note over NCrypt: pssInfo = {<br/>  pszAlgId = BCRYPT_SHA256_ALGORITHM,<br/>  cbSalt   = 32<br/>}

    NCrypt->>KSP: KSP_SignHash(..., pPaddingInfo=&pssInfo,<br/>dwFlags=NCRYPT_PAD_PSS_FLAG)

    KSP->>KSP: P11_ResolveMechanism("RSA", PSS_FLAG)<br/>→ mech = {CKM_RSA_PKCS_PSS, &pssParams, sizeof}

    KSP->>KSP: FillPssParams(pssInfo, &pssParams)<br/>pssParams.hashAlg = CKM_SHA256<br/>pssParams.mgf     = CKG_MGF1_SHA256<br/>pssParams.sLen    = 32

    KSP->>Session: P11_AcquireSession(&hSession)

    KSP->>HSM: C_SignInit(hSession,<br/>  {CKM_RSA_PKCS_PSS, &pssParams, 12},<br/>  hPrivKey)
    note over HSM: SoftHSM2 configure l'opération PSS<br/>avec SHA-256 + MGF1-SHA256 + sel=32 octets
    HSM-->>KSP: CKR_OK

    KSP->>HSM: C_Sign(hSession, pbHash, 32, pbRawSig, &cbSig)
    note over HSM: Signature RSA-PSS :<br/>1. MGF1(H(M)) → masque<br/>2. Encodage PSS (RFC 8017)<br/>3. RSASP1(privKey, encoded)
    HSM-->>KSP: CKR_OK, 256 octets

    KSP->>Session: P11_ReleaseSession(hSession)
    KSP-->>NCrypt: ERROR_SUCCESS

    note over KSP: Mapping des algorithmes de hash PSS :<br/>BCRYPT_SHA1_ALGORITHM   → CKM_SHA_1  + CKG_MGF1_SHA1<br/>BCRYPT_SHA256_ALGORITHM → CKM_SHA256 + CKG_MGF1_SHA256<br/>BCRYPT_SHA384_ALGORITHM → CKM_SHA384 + CKG_MGF1_SHA384<br/>BCRYPT_SHA512_ALGORITHM → CKM_SHA512 + CKG_MGF1_SHA512
```

---

## SignHash — ECDSA (avec conversion de format)

### Problème : format DER vs format Windows

SoftHSM2 retourne la signature ECDSA en **ASN.1 DER** (SEQUENCE { INTEGER r, INTEGER s }),
mais Windows CNG attend le format **r‖s** (concaténation brute, taille fixe selon la courbe).

```
Format DER (SoftHSM2) :       Format Windows CNG (attendu) :
30 44                         ← SEQUENCE                r (32 octets, big-endian, zéro-paddé)
  02 20                       ← INTEGER r               s (32 octets, big-endian, zéro-paddé)
    <32 octets de r>          ─────────────────────────────────────────────────
  02 20                       ← INTEGER s               Total : 64 octets (P-256)
    <32 octets de s>                                            96 octets (P-384)
```

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_crypto.c
    participant Utils as p11_utils.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    App->>NCrypt: NCryptSignHash(hKey, NULL, pbHash, 32,<br/>NULL, 0, &cbResult, 0)
    NCrypt->>KSP: KSP_SignHash("ECDSA_P256", pbHash, 32, NULL)

    KSP->>KSP: P11_ResolveMechanism("ECDSA_P256", 0)<br/>→ CKM_ECDSA (sans paramètres)

    KSP->>Session: P11_AcquireSession(&hSession)

    KSP->>HSM: C_SignInit(hSession, CKM_ECDSA, hPrivKey)
    HSM-->>KSP: CKR_OK

    KSP->>HSM: C_Sign(hSession, pbHash, 32, NULL, &cbRawSig)
    note over HSM: Taille DER ≈ 70–72 octets pour P-256
    HSM-->>KSP: CKR_OK, cbRawSig=70

    KSP->>KSP: pbSignature == NULL<br/>→ taille = P11_EcCoordSize("ECDSA_P256") × 2<br/>→ *pcbResult = 64

    KSP->>Session: P11_ReleaseSession(hSession)
    KSP-->>NCrypt: ERROR_SUCCESS, cbResult=64

    note over App: Étape 2 : signature réelle + conversion

    App->>NCrypt: NCryptSignHash(..., pbSig, 64, &cbResult, 0)
    NCrypt->>KSP: KSP_SignHash(..., pbSig, 64)

    KSP->>Session: P11_AcquireSession(&hSession)
    KSP->>HSM: C_SignInit + C_Sign(pbHash, 32, pbRawSig, &cbDer)
    HSM-->>KSP: DER [30 44 02 20 <r> 02 20 <s>] (70 octets)
    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>Utils: P11_DecodeDerEcdsaSignature("ECDSA_P256",<br/>pbDer, 70, pbSig, &cbOut)

    note over Utils: Décodage DER :<br/>1. Skip SEQUENCE tag + length<br/>2. INTEGER r : extrait, retire 0x00 de signe, zero-pad à 32<br/>3. INTEGER s : idem<br/>4. Copie r → pbSig[0..31]<br/>   Copie s → pbSig[32..63]

    Utils-->>KSP: pbSig = r‖s (64 octets), ERROR_SUCCESS

    KSP-->>NCrypt: ERROR_SUCCESS, cbResult=64
    NCrypt-->>App: ERROR_SUCCESS
```

### Algorithme de décodage DER → r‖s

```
Entrée : SEQUENCE { INTEGER r, INTEGER s }  (format DER)
Sortie : r‖s  (taille fixe cbCoord×2)

1. Vérifie tag=0x30 (SEQUENCE)
2. Skip la longueur de la séquence
3. Lit INTEGER r :
   a. Vérifie tag=0x02
   b. Lit longueur cbInt, pointe pbInt
   c. Si pbInt[0] == 0x00 → skip (byte de signe DER), cbInt--
   d. Si cbInt > cbCoord → erreur (dépassement)
   e. Copie dans pbOut[cbCoord - cbInt .. cbCoord - 1]
      (aligné à droite, zero-paddé à gauche)
4. Répète pour INTEGER s → pbOut[cbCoord .. 2*cbCoord - 1]
```

---

## Decrypt — RSA OAEP

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_crypto.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    App->>NCrypt: NCryptDecrypt(hKey, pbCipher, 256,<br/>&oaepInfo, pbPlain, cbPlain, &cbResult,<br/>NCRYPT_PAD_OAEP_FLAG)

    note over NCrypt: oaepInfo = {<br/>  pszAlgId = BCRYPT_SHA256_ALGORITHM,<br/>  pbLabel = NULL, cbLabel = 0<br/>}

    NCrypt->>KSP: KSP_Decrypt(..., pPaddingInfo=&oaepInfo,<br/>dwFlags=NCRYPT_PAD_OAEP_FLAG)

    KSP->>KSP: Construit CK_RSA_PKCS_OAEP_PARAMS :<br/>hashAlg = CKM_SHA256<br/>mgf     = CKG_MGF1_SHA256<br/>source  = CKZ_DATA_SPECIFIED<br/>pSourceData = NULL<br/>ulSourceDataLen = 0

    KSP->>KSP: mech = {CKM_RSA_PKCS_OAEP,<br/>  &oaepParams, sizeof oaepParams}

    KSP->>Session: P11_AcquireSession(&hSession)

    KSP->>HSM: C_DecryptInit(hSession,<br/>  {CKM_RSA_PKCS_OAEP, &params},<br/>  hPrivKey)
    HSM-->>KSP: CKR_OK

    KSP->>HSM: C_Decrypt(hSession,<br/>  pbCipher, 256,<br/>  pbPlain, &cbDecrypted)
    note over HSM: OAEP avec SHA-256 :<br/>1. RSAEP(pubKey, C) → EM<br/>2. OAEP-Decode(EM, hash, label)<br/>3. Retourne M (message clair)
    HSM-->>KSP: CKR_OK, cbDecrypted = len(M)

    KSP->>Session: P11_ReleaseSession(hSession)
    KSP-->>NCrypt: ERROR_SUCCESS, cbResult=len(M)
    NCrypt-->>App: ERROR_SUCCESS
```

---

## ExportKey — Clé publique RSA → BCRYPT_RSAKEY_BLOB

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_crypto.c
    participant Utils as p11_utils.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    App->>NCrypt: NCryptExportKey(hKey, 0,<br/>BCRYPT_RSAPUBLIC_BLOB, NULL,<br/>pbOut, cbOut, &cbResult, 0)
    NCrypt->>KSP: KSP_ExportKey(..., L"RSAPUBLICBLOB", ...)

    KSP->>Session: P11_AcquireSession(&hSession)

    KSP->>Utils: P11_ExportRsaPublicKey(hSession, hPubKey,<br/>&pbBlob, &cbBlob)

    Utils->>HSM: C_GetAttributeValue(hSession, hPubKey,<br/>  {CKA_MODULUS, NULL, 0})
    HSM-->>Utils: cbModulus = 256 (pour 2048 bits)

    Utils->>Utils: Alloue pbModulus[256]
    Utils->>HSM: C_GetAttributeValue(..., CKA_MODULUS, pbModulus)
    HSM-->>Utils: 256 octets (big-endian)

    Utils->>HSM: C_GetAttributeValue(..., CKA_PUBLIC_EXPONENT, NULL)
    HSM-->>Utils: cbExponent = 3 (65537 = 01 00 01)

    Utils->>Utils: Alloue pbExponent[3]
    Utils->>HSM: C_GetAttributeValue(..., CKA_PUBLIC_EXPONENT, pbExponent)
    HSM-->>Utils: [01 00 01]

    Utils->>Utils: cbBlob = sizeof(BCRYPT_RSAKEY_BLOB) + 3 + 256<br/>Alloue pbBlob[cbBlob]

    note over Utils: Construit BCRYPT_RSAKEY_BLOB :<br/>Magic       = BCRYPT_RSAPUBLIC_MAGIC<br/>BitLength   = 2048<br/>cbPublicExp = 3<br/>cbModulus   = 256<br/>cbPrime1    = 0<br/>cbPrime2    = 0<br/>+ [01 00 01] (exposant)<br/>+ [N…N] 256 octets (modulus)

    Utils-->>KSP: pbBlob, cbBlob, ERROR_SUCCESS
    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: memcpy(pbOut, pbBlob, cbBlob)<br/>*cbResult = cbBlob

    KSP-->>NCrypt: ERROR_SUCCESS
    NCrypt-->>App: ERROR_SUCCESS
```

### Structure BCRYPT_RSAKEY_BLOB en mémoire

```
Offset  Taille  Contenu
──────  ──────  ──────────────────────────────────────────
0       4       Magic = 0x31415352 ('RSA1' = RSAPUBLIC)
4       4       BitLength = 2048
8       4       cbPublicExp = 3
12      4       cbModulus = 256
16      4       cbPrime1 = 0
20      4       cbPrime2 = 0
24      3       Exposant public [01 00 01]
27      256     Modulus N (big-endian)
```

---

## ExportKey — Clé publique EC → BCRYPT_ECCKEY_BLOB

```mermaid
sequenceDiagram
    participant KSP as ksp_crypto.c
    participant Utils as p11_utils.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    KSP->>Utils: P11_ExportEcPublicKey(hSession, hPubKey,<br/>&pbBlob, &cbBlob)

    Utils->>HSM: C_GetAttributeValue(..., CKA_EC_POINT, NULL)
    HSM-->>Utils: cbEcPoint = 67 (P-256 : 2 + 1 + 32 + 32)

    Utils->>HSM: C_GetAttributeValue(..., CKA_EC_POINT, pbEcPoint)
    note over HSM: Format retourné par SoftHSM2 :<br/>DER OCTET STRING wrapping :<br/>04 41 → TAG(OCTET STRING) LEN=65<br/>  04   → point non compressé<br/>  Qx   → 32 octets<br/>  Qy   → 32 octets

    HSM-->>Utils: [04 41 04 <Qx 32 octets> <Qy 32 octets>]

    Utils->>Utils: Détecte le wrapper DER OCTET STRING<br/>(pbPoint[0]==0x04 && pbPoint[2]==0x04)<br/>→ skip 2 premiers octets<br/>→ pointe sur [04 Qx Qy]

    Utils->>Utils: cbCoord = (67 - 2 - 1) / 2 = 32<br/>cbBlob = sizeof(BCRYPT_ECCKEY_BLOB) + 64

    note over Utils: Construit BCRYPT_ECCKEY_BLOB :<br/>dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC<br/>cbKey   = 32<br/>+ Qx (32 octets)<br/>+ Qy (32 octets)

    Utils-->>KSP: pbBlob, cbBlob=72, ERROR_SUCCESS
```

### Structure BCRYPT_ECCKEY_BLOB en mémoire

```
Offset  Taille  Contenu (P-256)
──────  ──────  ──────────────────────────────────────────
0       4       dwMagic = 0x31534345 (ECDSA P-256 public)
4       4       cbKey = 32
8       32      Qx (coordonnée X du point public)
40      32      Qy (coordonnée Y du point public)
```

---

## ImportKey — Clé publique RSA

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_crypto.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    App->>NCrypt: NCryptImportKey(hProv, 0,<br/>BCRYPT_RSAPUBLIC_BLOB, NULL,<br/>&hKey, pbData, cbData, 0)
    NCrypt->>KSP: KSP_ImportKey(..., L"RSAPUBLICBLOB",<br/>pbData, cbData)

    KSP->>KSP: Parse BCRYPT_RSAKEY_BLOB :<br/>pbExp = pbData + sizeof(header)<br/>pbMod = pbExp + cbPublicExp

    KSP->>Session: P11_AcquireSession(&hSession)

    KSP->>HSM: C_CreateObject(hSession, template, N, &hPubObj)

    note over HSM: Template :<br/>CKA_CLASS=CKO_PUBLIC_KEY<br/>CKA_KEY_TYPE=CKK_RSA<br/>CKA_TOKEN=FALSE  (session uniquement)<br/>CKA_MODULUS=pbMod<br/>CKA_PUBLIC_EXPONENT=pbExp<br/>CKA_MODULUS_BITS=BitLength<br/>CKA_VERIFY=TRUE

    HSM-->>KSP: CKR_OK, hPubObj

    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: AllocZero(KSP_KEY)<br/>hPubKey=hPubObj<br/>hPrivKey=INVALID (pas de clé privée)<br/>szAlgId="RSA"

    KSP-->>NCrypt: hKey, ERROR_SUCCESS
```

> **Note :** L'import de clés privées retourne `NTE_NOT_SUPPORTED`.
> Les clés privées ne quittent jamais SoftHSM2 (`CKA_EXTRACTABLE=FALSE`).
