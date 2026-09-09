# Cryptographic operations — CNG → PKCS#11 mapping

## Mechanism mapping overview

| CNG call | Flag / Info | PKCS#11 mechanism | Parameters |
|----------|------------|-------------------|------------|
| `SignHash("RSA")` | `NCRYPT_PAD_PKCS1_FLAG` | `CKM_RSA_PKCS` | none |
| `SignHash("RSA")` | `NCRYPT_PAD_PSS_FLAG` + `BCRYPT_PSS_PADDING_INFO` | `CKM_RSA_PKCS_PSS` | `CK_RSA_PKCS_PSS_PARAMS` |
| `SignHash("ECDSA_P256/384/521")` | — | `CKM_ECDSA` | none |
| `SignHash("EDDSA_ED25519/ED448")` | — | `CKM_EDDSA` | none |
| `SignHash("HMAC_SHA1/224/256/384/512")` | — | `CKM_SHA*_HMAC` | none |
| `Decrypt("RSA")` | `NCRYPT_PAD_PKCS1_FLAG` | `CKM_RSA_PKCS` | none |
| `Decrypt("RSA")` | `NCRYPT_PAD_OAEP_FLAG` + `BCRYPT_OAEP_PADDING_INFO` | `CKM_RSA_PKCS_OAEP` | `CK_RSA_PKCS_OAEP_PARAMS` |
| `Encrypt("AES")` / `Decrypt("AES")` | chaining mode key property | `CKM_AES_ECB/CBC/CBC_PAD/CTR/GCM` | IV, `CK_GCM_PARAMS` or `CK_AES_CTR_PARAMS` |
| `SecretAgreement("ECDH_P256/384/521")` | — | `CKM_ECDH1_DERIVE` | `CK_ECDH1_DERIVE_PARAMS` |

Signing dispatch lives in `P11_ResolveMechanism()`; the AES mechanism is
built by `KspBuildAesMechanism()`, which reads the chaining mode and IV from
the key rather than from call flags.

---

## SignHash — RSA PKCS#1 v1.5

### CNG double-call pattern

CNG requires a two-step protocol: the first call with `pbSignature=NULL`
returns the required size, the second performs the actual signing.

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_crypto.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    note over App: Step 1: get the size

    App->>NCrypt: NCryptSignHash(hKey, NULL, pbHash, 32,<br/>NULL, 0, &cbResult, NCRYPT_PAD_PKCS1_FLAG)
    NCrypt->>KSP: KSP_SignHash(..., NULL, cbHash=32,<br/>pbSignature=NULL, cbSignature=0, &cbResult)

    KSP->>KSP: P11_ResolveMechanism("RSA", PKCS1_FLAG)<br/>→ mech = {CKM_RSA_PKCS, NULL, 0}

    KSP->>Session: P11_AcquireSession(&hSession)
    Session-->>KSP: hSession

    KSP->>HSM: C_SignInit(hSession, CKM_RSA_PKCS, hPrivKey)
    HSM-->>KSP: CKR_OK

    KSP->>HSM: C_Sign(hSession, pbHash, 32,<br/>pSignature=NULL, &cbRawSig)
    note over HSM: SoftHSM2 returns the size without signing
    HSM-->>KSP: CKR_OK, cbRawSig=256

    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: pbSignature == NULL → return size only<br/>*pcbResult = 256
    KSP-->>NCrypt: ERROR_SUCCESS, cbResult=256
    NCrypt-->>App: ERROR_SUCCESS, cbResult=256

    note over App: Step 2: actual signing

    App->>NCrypt: NCryptSignHash(hKey, NULL, pbHash, 32,<br/>pbSig, 256, &cbResult, NCRYPT_PAD_PKCS1_FLAG)
    NCrypt->>KSP: KSP_SignHash(..., pbSignature=pbSig, cbSignature=256)

    KSP->>Session: P11_AcquireSession(&hSession)

    KSP->>HSM: C_SignInit(hSession, CKM_RSA_PKCS, hPrivKey)
    HSM-->>KSP: CKR_OK

    KSP->>HSM: C_Sign(hSession, pbHash, 32, pbRawSig, &cbRawSig)
    note over HSM: RSA PKCS#1 v1.5 signature<br/>Result = RSASP1(privKey, EM)<br/>EM = 0x00 0x01 0xFF...FF 0x00 DigestInfo || hash
    HSM-->>KSP: CKR_OK, signature 256 bytes

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
    note over HSM: SoftHSM2 configures the PSS operation<br/>with SHA-256 + MGF1-SHA256 + salt=32 bytes
    HSM-->>KSP: CKR_OK

    KSP->>HSM: C_Sign(hSession, pbHash, 32, pbRawSig, &cbSig)
    note over HSM: RSA-PSS signature:<br/>1. MGF1(H(M)) → mask<br/>2. PSS encoding (RFC 8017)<br/>3. RSASP1(privKey, encoded)
    HSM-->>KSP: CKR_OK, 256 bytes

    KSP->>Session: P11_ReleaseSession(hSession)
    KSP-->>NCrypt: ERROR_SUCCESS

    note over KSP: PSS hash algorithm mapping:<br/>BCRYPT_SHA1_ALGORITHM   → CKM_SHA_1  + CKG_MGF1_SHA1<br/>BCRYPT_SHA224_ALGORITHM → CKM_SHA224 + CKG_MGF1_SHA224<br/>BCRYPT_SHA256_ALGORITHM → CKM_SHA256 + CKG_MGF1_SHA256<br/>BCRYPT_SHA384_ALGORITHM → CKM_SHA384 + CKG_MGF1_SHA384<br/>BCRYPT_SHA512_ALGORITHM → CKM_SHA512 + CKG_MGF1_SHA512
```

---

## SignHash — ECDSA (with format conversion)

### Problem: DER format vs Windows format

SoftHSM2 returns the ECDSA signature in **ASN.1 DER** format (SEQUENCE { INTEGER r, INTEGER s }),
but Windows CNG expects the **r‖s** format (raw concatenation, fixed size per curve).

```
DER format (SoftHSM2):              Expected Windows CNG format:
30 44                         ← SEQUENCE                r (32 bytes, big-endian, zero-padded)
  02 20                       ← INTEGER r               s (32 bytes, big-endian, zero-padded)
    <32 bytes of r>           ─────────────────────────────────────────────────
  02 20                       ← INTEGER s               Total: 64 bytes (P-256)
    <32 bytes of s>                                             96 bytes (P-384)
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

    KSP->>KSP: P11_ResolveMechanism("ECDSA_P256", 0)<br/>→ CKM_ECDSA (no parameters)

    KSP->>Session: P11_AcquireSession(&hSession)

    KSP->>HSM: C_SignInit(hSession, CKM_ECDSA, hPrivKey)
    HSM-->>KSP: CKR_OK

    KSP->>HSM: C_Sign(hSession, pbHash, 32, NULL, &cbRawSig)
    note over HSM: DER size ≈ 70–72 bytes for P-256
    HSM-->>KSP: CKR_OK, cbRawSig=70

    KSP->>KSP: pbSignature == NULL<br/>→ size = P11_EcCoordSize("ECDSA_P256") × 2<br/>→ *pcbResult = 64

    KSP->>Session: P11_ReleaseSession(hSession)
    KSP-->>NCrypt: ERROR_SUCCESS, cbResult=64

    note over App: Step 2: actual signature + conversion

    App->>NCrypt: NCryptSignHash(..., pbSig, 64, &cbResult, 0)
    NCrypt->>KSP: KSP_SignHash(..., pbSig, 64)

    KSP->>Session: P11_AcquireSession(&hSession)
    KSP->>HSM: C_SignInit + C_Sign(pbHash, 32, pbRawSig, &cbDer)
    HSM-->>KSP: DER [30 44 02 20 <r> 02 20 <s>] (70 bytes)
    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>Utils: P11_DecodeDerEcdsaSignature("ECDSA_P256",<br/>pbDer, 70, pbSig, &cbOut)

    note over Utils: DER decoding:<br/>1. Skip SEQUENCE tag + length<br/>2. INTEGER r: extract, strip 0x00 sign byte, zero-pad to 32<br/>3. INTEGER s: same<br/>4. Copy r → pbSig[0..31]<br/>   Copy s → pbSig[32..63]

    Utils-->>KSP: pbSig = r‖s (64 bytes), ERROR_SUCCESS

    KSP-->>NCrypt: ERROR_SUCCESS, cbResult=64
    NCrypt-->>App: ERROR_SUCCESS
```

### DER → r‖s decoding algorithm

```
Input:  SEQUENCE { INTEGER r, INTEGER s }  (DER format)
Output: r‖s  (fixed size cbCoord×2)

1. Check tag=0x30 (SEQUENCE)
2. Skip the sequence length
3. Read INTEGER r:
   a. Check tag=0x02
   b. Read length cbInt, point pbInt
   c. If pbInt[0] == 0x00 → skip (DER sign byte), cbInt--
   d. If cbInt > cbCoord → error (overflow)
   e. Copy into pbOut[cbCoord - cbInt .. cbCoord - 1]
      (right-aligned, zero-padded on the left)
4. Repeat for INTEGER s → pbOut[cbCoord .. 2*cbCoord - 1]
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

    KSP->>KSP: Build CK_RSA_PKCS_OAEP_PARAMS:<br/>hashAlg = CKM_SHA256<br/>mgf     = CKG_MGF1_SHA256<br/>source  = CKZ_DATA_SPECIFIED<br/>pSourceData = NULL<br/>ulSourceDataLen = 0

    KSP->>KSP: mech = {CKM_RSA_PKCS_OAEP,<br/>  &oaepParams, sizeof oaepParams}

    KSP->>Session: P11_AcquireSession(&hSession)

    KSP->>HSM: C_DecryptInit(hSession,<br/>  {CKM_RSA_PKCS_OAEP, &params},<br/>  hPrivKey)
    HSM-->>KSP: CKR_OK

    KSP->>HSM: C_Decrypt(hSession,<br/>  pbCipher, 256,<br/>  pbPlain, &cbDecrypted)
    note over HSM: OAEP with SHA-256:<br/>1. RSAEP(pubKey, C) → EM<br/>2. OAEP-Decode(EM, hash, label)<br/>3. Return M (plaintext)
    HSM-->>KSP: CKR_OK, cbDecrypted = len(M)

    KSP->>Session: P11_ReleaseSession(hSession)
    KSP-->>NCrypt: ERROR_SUCCESS, cbResult=len(M)
    NCrypt-->>App: ERROR_SUCCESS
```

### OAEP hash and label mapping

`P11_BuildOaepParams()` fills `CK_RSA_PKCS_OAEP_PARAMS` from the caller's
`BCRYPT_OAEP_PADDING_INFO`. All five SHA-2 family hashes are supported:

| `pszAlgId` | `hashAlg` | `mgf` |
|-----------|-----------|-------|
| `BCRYPT_SHA1_ALGORITHM` | `CKM_SHA_1` | `CKG_MGF1_SHA1` |
| `BCRYPT_SHA224_ALGORITHM` | `CKM_SHA224` | `CKG_MGF1_SHA224` |
| `BCRYPT_SHA256_ALGORITHM` | `CKM_SHA256` | `CKG_MGF1_SHA256` |
| `BCRYPT_SHA384_ALGORITHM` | `CKM_SHA384` | `CKG_MGF1_SHA384` |
| `BCRYPT_SHA512_ALGORITHM` | `CKM_SHA512` | `CKG_MGF1_SHA512` |

Any other name returns `NTE_NOT_SUPPORTED`. A `NULL` padding info, or a
`NULL` `pszAlgId`, defaults to SHA-1 — the CNG legacy behaviour.

When `pbLabel` is non-NULL and `cbLabel` is non-zero, the label is passed
through as `pSourceData` / `ulSourceDataLen`. A zero-length label is treated
as absent. Decryption with a different label than encryption fails, which is
the point of the label.

---

## SignHash — EdDSA (Ed25519 / Ed448)

EdDSA differs from every other signing path in three ways:

1. **No padding parameters.** `CKM_EDDSA` takes no mechanism parameter, and
   padding flags in `dwFlags` are ignored.
2. **No DER conversion.** SoftHSM2 returns the signature already in raw
   form, so `P11_DecodeDerEcdsaSignature()` is not called.
3. **The input is the message, not a digest.** EdDSA hashes internally, so
   what CNG calls the "hash" is passed through unchanged.

| Curve | Signature size | Public key size |
|-------|---------------:|----------------:|
| Ed25519 | 64 bytes | 32 bytes |
| Ed448 | 114 bytes | 57 bytes |

Export uses `BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC` and a single raw point
after the `BCRYPT_ECCKEY_BLOB` header — there is no X/Y split.

---

## Encrypt / Decrypt — AES

AES follows the CNG symmetric contract: the chaining mode and IV are **key
properties set before the operation**, not call arguments.

```
NCryptSetProperty(hKey, NCRYPT_CHAINING_MODE_PROPERTY, "ChainingModeGCM")
NCryptSetProperty(hKey, NCRYPT_INITIALIZATION_VECTOR, nonce, 12)
NCryptEncrypt(hKey, plaintext, ...)
```

| Chaining mode | PKCS#11 mechanism | IV | Mechanism parameter |
|---------------|-------------------|-----|---------------------|
| `ChainingModeECB` | `CKM_AES_ECB` | none | none |
| `ChainingModeCBC` | `CKM_AES_CBC` | 16 bytes | raw IV bytes |
| `ChainingModeCBC` + `NCRYPT_PAD_CIPHER_FLAG` | `CKM_AES_CBC_PAD` | 16 bytes | raw IV bytes |
| `ChainingModeCTR` | `CKM_AES_CTR` | 16 bytes | `CK_AES_CTR_PARAMS`, 32-bit counter |
| `ChainingModeGCM` | `CKM_AES_GCM` | 12 bytes typical | `CK_GCM_PARAMS`, 128-bit tag |

`ChainingModeCTR` is a KSP extension: CNG defines no standard string for
counter mode. `ChainingModeCCM` and `ChainingModeCFB` return
`NTE_NOT_SUPPORTED` — no SoftHSM2 mechanism is wired to them.

GCM additional authenticated data is supplied through
`NCRYPT_AUTH_TAG_LENGTH` and stored on the key until the operation runs.

> **The IV is consumed by the operation.** Set it again before decrypting
> the ciphertext you just produced, exactly as with BCrypt.

`KSP_Encrypt` rejects asymmetric keys with `NTE_NOT_SUPPORTED`: RSA
encryption is a public-key operation that BCrypt performs on the exported
public key, not something a storage provider does.

---

## SecretAgreement / DeriveKey — ECDH

ECDH is a two-call sequence. `NCryptSecretAgreement` produces an opaque
`NCRYPT_SECRET_HANDLE`; `NCryptDeriveKey` turns it into key material.

```mermaid
sequenceDiagram
    participant App as Application
    participant KSP as ksp_crypto.c
    participant HSM as SoftHSM2

    note over App: Party A holds hPrivA, and hPubB<br/>imported from party B's blob

    App->>KSP: NCryptSecretAgreement(hPrivA, hPubB, &hSecret, 0)

    KSP->>KSP: Check both curves match<br/>(P11_EcCoordSize equal), else NTE_BAD_ALGID
    KSP->>HSM: C_GetAttributeValue(hPubB, CKA_EC_POINT)
    HSM-->>KSP: DER OCTET STRING { 04 || X || Y }
    KSP->>KSP: Strip the DER wrapper —<br/>CKM_ECDH1_DERIVE wants the raw point

    KSP->>HSM: C_DeriveKey(CKM_ECDH1_DERIVE,<br/>  {kdf=CKD_NULL, pPublicData=raw point},<br/>  hPrivA, template, &hDerived)
    note over HSM: Computes Z = d_A · Q_B<br/>CKD_NULL → raw Z, no KDF
    HSM-->>KSP: CKR_OK, hDerived

    KSP->>KSP: Wrap in KSP_SECRET<br/>{magic, hDerived, len}
    KSP-->>App: NCRYPT_SECRET_HANDLE

    App->>KSP: NCryptDeriveKey(hSecret, "TRUNCATE", ...)
    KSP->>HSM: C_GetAttributeValue(hDerived, CKA_VALUE)
    HSM-->>KSP: raw Z bytes
    KSP-->>App: shared secret

    App->>KSP: NCryptFreeObject(hSecret)
    KSP->>HSM: C_DestroyObject(hDerived)
```

| Curve | Shared secret size |
|-------|-------------------:|
| P-256 | 32 bytes |
| P-384 | 48 bytes |
| P-521 | 66 bytes |

Two constraints are enforced before any PKCS#11 call:

- **Both keys must be on the same curve**, or the call returns
  `NTE_BAD_ALGID`. `P11_EcCoordSize()` on each algorithm name is the check.
- **The private key must have a real private object** and the public key a
  real public object, or the call returns `NTE_BAD_KEY`. This is why
  Phase 3's import fix matters: an imported peer key with
  `CK_INVALID_HANDLE` could not be used as an ECDH peer.

### Supported KDFs

`KSP_DeriveKey` implements `BCRYPT_KDF_RAW_SECRET` (`"TRUNCATE"`) only,
returning the raw Z value. A `NULL` KDF name is treated as the raw secret.
Hash-based KDFs return `NTE_NOT_SUPPORTED` — request the raw secret and run
the KDF with BCrypt.

The derived secret object is created with `CKA_EXTRACTABLE=TRUE` and
`CKA_TOKEN=FALSE`: it is a short-lived session object that exists only so
its `CKA_VALUE` can be read back, and `KSP_FreeSecret` destroys it.

---

## ExportKey — RSA public key → BCRYPT_RSAKEY_BLOB

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
    HSM-->>Utils: cbModulus = 256 (for 2048 bits)

    Utils->>Utils: Allocate pbModulus[256]
    Utils->>HSM: C_GetAttributeValue(..., CKA_MODULUS, pbModulus)
    HSM-->>Utils: 256 bytes (big-endian)

    Utils->>HSM: C_GetAttributeValue(..., CKA_PUBLIC_EXPONENT, NULL)
    HSM-->>Utils: cbExponent = 3 (65537 = 01 00 01)

    Utils->>Utils: Allocate pbExponent[3]
    Utils->>HSM: C_GetAttributeValue(..., CKA_PUBLIC_EXPONENT, pbExponent)
    HSM-->>Utils: [01 00 01]

    Utils->>Utils: cbBlob = sizeof(BCRYPT_RSAKEY_BLOB) + 3 + 256<br/>Allocate pbBlob[cbBlob]

    note over Utils: Build BCRYPT_RSAKEY_BLOB:<br/>Magic       = BCRYPT_RSAPUBLIC_MAGIC<br/>BitLength   = 2048<br/>cbPublicExp = 3<br/>cbModulus   = 256<br/>cbPrime1    = 0<br/>cbPrime2    = 0<br/>+ [01 00 01] (exponent)<br/>+ [N…N] 256 bytes (modulus)

    Utils-->>KSP: pbBlob, cbBlob, ERROR_SUCCESS
    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: memcpy(pbOut, pbBlob, cbBlob)<br/>*cbResult = cbBlob

    KSP-->>NCrypt: ERROR_SUCCESS
    NCrypt-->>App: ERROR_SUCCESS
```

### BCRYPT_RSAKEY_BLOB memory layout

```
Offset  Size    Content
──────  ──────  ──────────────────────────────────────────
0       4       Magic = 0x31415352 ('RSA1' = RSAPUBLIC)
4       4       BitLength = 2048
8       4       cbPublicExp = 3
12      4       cbModulus = 256
16      4       cbPrime1 = 0
20      4       cbPrime2 = 0
24      3       Public exponent [01 00 01]
27      256     Modulus N (big-endian)
```

---

## ExportKey — EC public key → BCRYPT_ECCKEY_BLOB

```mermaid
sequenceDiagram
    participant KSP as ksp_crypto.c
    participant Utils as p11_utils.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    KSP->>Utils: P11_ExportEcPublicKey(hSession, hPubKey,<br/>&pbBlob, &cbBlob)

    Utils->>HSM: C_GetAttributeValue(..., CKA_EC_POINT, NULL)
    HSM-->>Utils: cbEcPoint = 67 (P-256: 2 + 1 + 32 + 32)

    Utils->>HSM: C_GetAttributeValue(..., CKA_EC_POINT, pbEcPoint)
    note over HSM: Format returned by SoftHSM2:<br/>DER OCTET STRING wrapping:<br/>04 41 → TAG(OCTET STRING) LEN=65<br/>  04   → uncompressed point<br/>  Qx   → 32 bytes<br/>  Qy   → 32 bytes

    HSM-->>Utils: [04 41 04 <Qx 32 bytes> <Qy 32 bytes>]

    Utils->>Utils: Detect DER OCTET STRING wrapper<br/>(pbPoint[0]==0x04 && pbPoint[2]==0x04)<br/>→ skip first 2 bytes<br/>→ point to [04 Qx Qy]

    Utils->>Utils: cbCoord = (67 - 2 - 1) / 2 = 32<br/>cbBlob = sizeof(BCRYPT_ECCKEY_BLOB) + 64

    note over Utils: Build BCRYPT_ECCKEY_BLOB:<br/>dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC<br/>cbKey   = 32<br/>+ Qx (32 bytes)<br/>+ Qy (32 bytes)

    Utils-->>KSP: pbBlob, cbBlob=72, ERROR_SUCCESS
```

### BCRYPT_ECCKEY_BLOB memory layout

```
Offset  Size    Content (P-256)
──────  ──────  ──────────────────────────────────────────
0       4       dwMagic = 0x31534345 (ECDSA P-256 public)
4       4       cbKey = 32
8       32      Qx (X coordinate of the public point)
40      32      Qy (Y coordinate of the public point)
```

---

## ImportKey — RSA public key

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_crypto.c
    participant Session as p11_session.c
    participant HSM as SoftHSM2

    App->>NCrypt: NCryptImportKey(hProv, 0,<br/>BCRYPT_RSAPUBLIC_BLOB, NULL,<br/>&hKey, pbData, cbData, 0)
    NCrypt->>KSP: KSP_ImportKey(..., L"RSAPUBLICBLOB",<br/>pbData, cbData)

    KSP->>KSP: Parse BCRYPT_RSAKEY_BLOB:<br/>pbExp = pbData + sizeof(header)<br/>pbMod = pbExp + cbPublicExp

    KSP->>Session: P11_AcquireSession(&hSession)

    KSP->>HSM: C_CreateObject(hSession, template, N, &hPubObj)

    note over HSM: Template:<br/>CKA_CLASS=CKO_PUBLIC_KEY<br/>CKA_KEY_TYPE=CKK_RSA<br/>CKA_TOKEN=FALSE  (session only)<br/>CKA_MODULUS=pbMod<br/>CKA_PUBLIC_EXPONENT=pbExp<br/>CKA_MODULUS_BITS=BitLength<br/>CKA_VERIFY=TRUE

    HSM-->>KSP: CKR_OK, hPubObj

    KSP->>Session: P11_ReleaseSession(hSession)

    KSP->>KSP: AllocZero(KSP_KEY)<br/>hPubKey=hPubObj<br/>hPrivKey=INVALID (no private key)<br/>szAlgId="RSA"

    KSP-->>NCrypt: hKey, ERROR_SUCCESS
```

> **Note:** Private key import returns `NTE_NOT_SUPPORTED`.
> Private keys never leave SoftHSM2 (`CKA_EXTRACTABLE=FALSE`).

---

## ImportKey — EC public key

EC import follows the same shape as RSA but must rebuild `CKA_EC_POINT`
from the blob's X and Y coordinates.

```
BCRYPT_ECCKEY_BLOB { dwMagic, cbKey } || X (cbKey) || Y (cbKey)
           │
           ▼  P11_BuildEcPointDer()
DER OCTET STRING { 0x04 || X || Y }
           │
           ▼  C_CreateObject
CKO_PUBLIC_KEY { CKA_KEY_TYPE=CKK_EC, CKA_EC_PARAMS=<curve OID>,
                 CKA_EC_POINT=<DER>, CKA_VERIFY=TRUE, CKA_DERIVE=TRUE }
```

The curve is identified from `cbKey`: 32 → P-256, 48 → P-384, 66 → P-521.
Any other size returns `NTE_BAD_ALGID`.

`P11_BuildEcPointDer()` selects the DER length form by size. A P-256 point
is 65 bytes and uses the short form (`04 41 04 …`); a P-521 point is 133
bytes and needs the long form (`04 81 85 04 …`). Getting this wrong is the
classic P-521 bug — the same asymmetry appears when *reading*
`CKA_EC_POINT` back in `P11_ExportEcPublicKey`.

Validation before any PKCS#11 call:

| Condition | Result |
|-----------|--------|
| `cbData < sizeof(BCRYPT_ECCKEY_BLOB)` | `NTE_INVALID_PARAMETER` |
| `cbData < header + 2 × cbKey` | `NTE_INVALID_PARAMETER` |
| `cbKey` not 32 / 48 / 66 | `NTE_BAD_ALGID` |

The resulting key is marked `bSessionObject = TRUE`, so `KSP_FreeKey`
destroys the session object instead of leaking it. `CKA_DERIVE=TRUE` is set
so the imported key can serve as an ECDH peer.
