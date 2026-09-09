# 12 — PKCS#11 backend requirements

Everything a PKCS#11 token must provide for this CNG KSP to be fully
functional: functions, mechanisms, attributes, mechanism parameters and
session semantics.

Use this to evaluate whether a given HSM or software token can back the
provider, and to know exactly which capability is lost when one is missing.

> **Derived from source.** Every entry below was extracted from
> `src/pkcs11/` and `src/ksp/` rather than written from memory. Nothing is
> listed that the KSP does not actually call.

---

## 1. Summary

| Category | Count | Notes |
|----------|------:|-------|
| Cryptoki functions called | 22 | of ~68 in PKCS#11 v2.40 |
| Mechanisms used as `CK_MECHANISM.mechanism` | 21 | see §3 |
| Mechanisms used only as a hash **parameter** | 5 | never passed to `C_DigestInit` — see §3.6 |
| Object attributes set or read | 18 | see §4 |
| Mechanism parameter structures | 5 | see §5 |

**Minimum viable token** — RSA and ECDSA only, which is what every
commercial CNG KSP on the market exposes — needs 6 mechanisms and 17 of
those 22 functions. Everything beyond that is additive; see §7 for the tiers.

---

## 2. Cryptoki functions

All calls go through the `CK_FUNCTION_LIST` obtained from
`C_GetFunctionList`. The KSP resolves that symbol by `GetProcAddress` after
`LoadLibrary` — it never links the token statically.

| Function | Called from | Purpose | Required for |
|----------|-------------|---------|--------------|
| `C_GetFunctionList` | `p11_context.c` | Resolve the dispatch table | **Always** |
| `C_Initialize` | `p11_context.c` | One-shot init with `CKF_OS_LOCKING_OK` | **Always** |
| `C_Finalize` | `p11_context.c` | Process detach | **Always** |
| `C_GetSlotList` | `p11_context.c` | Slot discovery, `tokenPresent = CK_TRUE` | **Always** |
| `C_OpenSession` | `p11_session.c` | Pool of 16 R/W serial sessions | **Always** |
| `C_CloseSession` | `p11_session.c` | Pool teardown | **Always** |
| `C_Login` | `p11_session.c` | `CKU_USER` with the PIN | **Always** |
| `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal` | `p11_utils.c`, `ksp_key.c` | `OpenKey` by label, `EnumKeys` | **Always** |
| `C_GetAttributeValue` | `p11_utils.c` | Key type, sizes, public key material | **Always** |
| `C_DestroyObject` | `ksp_key.c`, `ksp_crypto.c` | `DeleteKey`, session-object cleanup | **Always** |
| `C_GenerateKeyPair` | `ksp_key.c` | RSA, EC, EdDSA key creation | Asymmetric keys |
| `C_SignInit` / `C_Sign` | `ksp_crypto.c` | `NCryptSignHash` | Signing |
| `C_DecryptInit` / `C_Decrypt` | `ksp_crypto.c` | `NCryptDecrypt` | RSA decrypt, AES decrypt |
| `C_CreateObject` | `ksp_crypto.c` | Public key import as a session object | `NCryptImportKey` |
| `C_GenerateKey` | `ksp_key.c` | AES and HMAC secret keys | Symmetric keys |
| `C_EncryptInit` / `C_Encrypt` | `ksp_crypto.c` | `NCryptEncrypt` | AES encrypt |
| `C_DeriveKey` | `ksp_crypto.c` | `NCryptSecretAgreement` | ECDH |

### Functions deliberately **not** used

| Function | Why not |
|----------|---------|
| `C_Digest*` | CNG always supplies a pre-computed hash to `NCryptSignHash`. The KSP never digests. |
| `C_Verify*` | Verification is a public-key operation; CNG applications use BCrypt on the exported public key. |
| `C_SignUpdate` / `C_EncryptUpdate` | The KSP is single-part only. Multi-part is not reachable through the CNG KSP contract. |
| `C_WrapKey` / `C_UnwrapKey` | No key wrapping is exposed. |
| `C_SeedRandom` / `C_GenerateRandom` | Randomness comes from the token internally during key generation. |
| `C_SetAttributeValue` | Attributes are fixed at creation; nothing is mutated on the token. |
| `C_InitToken` / `C_InitPIN` / `C_SetPIN` | Token provisioning is out of scope — use the vendor's tooling. |

---

## 3. Mechanisms

### 3.1 Key generation

| Mechanism | CNG algorithm ID | Object produced | Notes |
|-----------|------------------|-----------------|-------|
| `CKM_RSA_PKCS_KEY_PAIR_GEN` | `RSA` | `CKO_PUBLIC_KEY` + `CKO_PRIVATE_KEY` | Public exponent fixed at 65537 |
| `CKM_EC_KEY_PAIR_GEN` | `ECDSA_P256/384/521`, `ECDSA_SECP256K1`, `ECDH_P256/384/521` | `CKO_PUBLIC_KEY` + `CKO_PRIVATE_KEY` | Curve chosen by `CKA_EC_PARAMS` |
| `CKM_EC_EDWARDS_KEY_PAIR_GEN` | `EDDSA_ED25519`, `EDDSA_ED448` | `CKO_PUBLIC_KEY` + `CKO_PRIVATE_KEY` | PKCS#11 v3.0 mechanism |
| `CKM_AES_KEY_GEN` | `AES` | `CKO_SECRET_KEY` | Size from `CKA_VALUE_LEN` |
| `CKM_GENERIC_SECRET_KEY_GEN` | `HMAC_SHA1/256/384/512` | `CKO_SECRET_KEY` | Size from `CKA_VALUE_LEN` |

### 3.2 Signing — `C_SignInit` + `C_Sign`

| Mechanism | CNG entry | Parameter | Input | Output |
|-----------|-----------|-----------|-------|--------|
| `CKM_RSA_PKCS` | `NCryptSignHash` + `NCRYPT_PAD_PKCS1_FLAG` | none | DigestInfo | modulus-sized |
| `CKM_RSA_PKCS_PSS` | `NCryptSignHash` + `NCRYPT_PAD_PSS_FLAG` | `CK_RSA_PKCS_PSS_PARAMS` | raw hash | modulus-sized |
| `CKM_ECDSA` | `NCryptSignHash`, no padding | none | raw hash | **DER**, converted to r‖s by the KSP |
| `CKM_EDDSA` | `NCryptSignHash`, no padding | none | message | raw, no conversion |
| `CKM_SHA_1_HMAC` | `NCryptSignHash` on an HMAC key | none | message | 20 bytes |
| `CKM_SHA224_HMAC` | " | none | message | 28 bytes |
| `CKM_SHA256_HMAC` | " | none | message | 32 bytes |
| `CKM_SHA384_HMAC` | " | none | message | 48 bytes |
| `CKM_SHA512_HMAC` | " | none | message | 64 bytes |

> **The token must return ECDSA signatures in DER.** `P11_DecodeDerEcdsaSignature`
> parses `SEQUENCE { INTEGER r, INTEGER s }` and left-pads each to the
> coordinate size. A token returning raw r‖s would fail this decode.

### 3.3 Decryption — `C_DecryptInit` + `C_Decrypt`

| Mechanism | CNG entry | Parameter |
|-----------|-----------|-----------|
| `CKM_RSA_PKCS` | `NCryptDecrypt` + `NCRYPT_PAD_PKCS1_FLAG` | none |
| `CKM_RSA_PKCS_OAEP` | `NCryptDecrypt` + `NCRYPT_PAD_OAEP_FLAG` | `CK_RSA_PKCS_OAEP_PARAMS` |
| `CKM_AES_ECB` / `CBC` / `CBC_PAD` / `CTR` / `GCM` | `NCryptDecrypt` on an AES key | see §3.4 |

### 3.4 Symmetric encryption — `C_EncryptInit` + `C_Encrypt`

Selected by `NCRYPT_CHAINING_MODE_PROPERTY` on the key, not by call flags.

| Mechanism | Chaining mode string | Parameter | IV / nonce |
|-----------|----------------------|-----------|------------|
| `CKM_AES_ECB` | `ChainingModeECB` | none | none |
| `CKM_AES_CBC` | `ChainingModeCBC` | raw IV bytes | 16 bytes |
| `CKM_AES_CBC_PAD` | `ChainingModeCBC` + `NCRYPT_PAD_CIPHER_FLAG` | raw IV bytes | 16 bytes |
| `CKM_AES_CTR` | `ChainingModeCTR` *(KSP extension)* | `CK_AES_CTR_PARAMS` | 16-byte counter block |
| `CKM_AES_GCM` | `ChainingModeGCM` | `CK_GCM_PARAMS` | 12 bytes typical, 128-bit tag |

### 3.5 Key derivation — `C_DeriveKey`

| Mechanism | CNG entry | Parameter | Produces |
|-----------|-----------|-----------|----------|
| `CKM_ECDH1_DERIVE` | `NCryptSecretAgreement` | `CK_ECDH1_DERIVE_PARAMS`, `kdf = CKD_NULL` | `CKO_SECRET_KEY`, `CKK_GENERIC_SECRET` |

The KSP requests `CKD_NULL` so the token returns the raw Z value; any KDF is
applied afterwards by the caller. The derived object must be readable —
see §4.3.

### 3.6 Hash mechanisms — parameter values only

These five are **never passed to `C_DigestInit`**. They appear only as the
`hashAlg` field inside PSS and OAEP parameter structures, so the token must
recognise them as valid parameter values for those mechanisms.

| Mechanism | MGF companion | Used by |
|-----------|---------------|---------|
| `CKM_SHA_1` | `CKG_MGF1_SHA1` | PSS, OAEP |
| `CKM_SHA224` | `CKG_MGF1_SHA224` | PSS, OAEP |
| `CKM_SHA256` | `CKG_MGF1_SHA256` | PSS, OAEP |
| `CKM_SHA384` | `CKG_MGF1_SHA384` | PSS, OAEP |
| `CKM_SHA512` | `CKG_MGF1_SHA512` | PSS, OAEP |

---

## 4. Object attributes

### 4.1 Set at creation — asymmetric key pairs

| Attribute | Public | Private | Value | Purpose |
|-----------|:------:|:-------:|-------|---------|
| `CKA_CLASS` | ✓ | ✓ | `CKO_PUBLIC_KEY` / `CKO_PRIVATE_KEY` | Object class |
| `CKA_KEY_TYPE` | ✓ | ✓ | `CKK_RSA`, `CKK_EC`, `CKK_EC_EDWARDS` | Set explicitly for EdDSA and imports |
| `CKA_TOKEN` | ✓ | ✓ | `CK_TRUE` | Persistent — survives session close |
| `CKA_LABEL` | ✓ | ✓ | UTF-8 key name | The CNG key name; how `OpenKey` finds it |
| `CKA_SENSITIVE` | — | ✓ | `CK_TRUE` | Key material not readable |
| `CKA_EXTRACTABLE` | — | ✓ | `CK_FALSE` | Cannot be exported |
| `CKA_SIGN` | — | ✓ | `CK_TRUE` for signature keys | Enables `C_Sign` |
| `CKA_VERIFY` | ✓ | — | `CK_TRUE` for signature keys | Public counterpart |
| `CKA_DECRYPT` | — | ✓ | `CK_TRUE` for RSA `AT_KEYEXCHANGE` | Enables `C_Decrypt` |
| `CKA_ENCRYPT` | ✓ | — | `CK_TRUE` for RSA `AT_KEYEXCHANGE` | Public counterpart |
| `CKA_DERIVE` | ✓ | ✓ | `CK_TRUE` for ECDH, `CK_FALSE` for ECDSA | **The ECDSA/ECDH discriminator** |
| `CKA_MODULUS_BITS` | ✓ | — | 2048 / 3072 / 4096 | RSA size |
| `CKA_PUBLIC_EXPONENT` | ✓ | — | `01 00 01` | Defaults to 65537; big-endian, minimal length, from `KSP_EncodePublicExponent` |
| `CKA_EC_PARAMS` | ✓ | ✓ | DER curve OID | Curve selection — see §6 |

### 4.2 Set at creation — symmetric keys

| Attribute | Value | AES | HMAC |
|-----------|-------|:---:|:----:|
| `CKA_CLASS` | `CKO_SECRET_KEY` | ✓ | ✓ |
| `CKA_KEY_TYPE` | `CKK_AES` / `CKK_GENERIC_SECRET` | ✓ | ✓ |
| `CKA_TOKEN` | `CK_TRUE` | ✓ | ✓ |
| `CKA_LABEL` | UTF-8 key name | ✓ | ✓ |
| `CKA_VALUE_LEN` | 16 / 24 / 32 (AES), hash size (HMAC) | ✓ | ✓ |
| `CKA_SENSITIVE` | `CK_TRUE` | ✓ | ✓ |
| `CKA_EXTRACTABLE` | `CK_FALSE` | ✓ | ✓ |
| `CKA_ENCRYPT` / `CKA_DECRYPT` | `CK_TRUE` for AES, `CK_FALSE` for HMAC | ✓ | ✗ |
| `CKA_SIGN` / `CKA_VERIFY` | `CK_FALSE` for AES, `CK_TRUE` for HMAC | ✗ | ✓ |

### 4.3 Set on the ECDH derived secret

This is the one object created **without** sensitivity protection, because
`NCryptDeriveKey` must hand raw key material back to the caller.

| Attribute | Value | Why |
|-----------|-------|-----|
| `CKA_CLASS` | `CKO_SECRET_KEY` | — |
| `CKA_KEY_TYPE` | `CKK_GENERIC_SECRET` | Raw Z value |
| `CKA_TOKEN` | `CK_FALSE` | Session object — never written to the token |
| `CKA_SENSITIVE` | `CK_FALSE` | So `CKA_VALUE` can be read back |
| `CKA_EXTRACTABLE` | `CK_TRUE` | Same reason |
| `CKA_VALUE_LEN` | coordinate size (32 / 48 / 66) | Expected secret length |

> A token that refuses to create a non-sensitive extractable secret from
> `C_DeriveKey` cannot support `NCryptDeriveKey` through this KSP.

### 4.4 Read back via `C_GetAttributeValue`

| Attribute | Read from | Used for |
|-----------|-----------|----------|
| `CKA_KEY_TYPE` | private or secret key | Identify the family on `OpenKey` |
| `CKA_MODULUS_BITS` | RSA private key | Report `NCRYPT_LENGTH_PROPERTY` |
| `CKA_MODULUS` | RSA public key | Build `BCRYPT_RSAPUBLIC_BLOB` |
| `CKA_PUBLIC_EXPONENT` | RSA public key | Build `BCRYPT_RSAPUBLIC_BLOB` |
| `CKA_EC_PARAMS` | EC private key | Identify the curve — **compared by bytes** |
| `CKA_EC_POINT` | EC public key | Build `BCRYPT_ECCPUBLIC_BLOB`, ECDH peer point |
| `CKA_DERIVE` | EC private key | Distinguish ECDH from ECDSA |
| `CKA_VALUE_LEN` | secret key | Report key length on reopen |
| `CKA_VALUE` | derived ECDH secret | Return raw Z to the caller |
| `CKA_LABEL` | any key | `EnumKeys` |

> **`CKA_EC_POINT` must be DER-encoded** as an `OCTET STRING` wrapping
> `04 || X || Y`. The KSP unwraps both the short form (P-256, P-384) and the
> long form `81 LEN` (P-521, 133 bytes). A token returning a bare point
> without the wrapper will produce a malformed blob.

---

## 5. Mechanism parameter structures

| Structure | Mechanism | Fields the KSP sets |
|-----------|-----------|---------------------|
| `CK_RSA_PKCS_PSS_PARAMS` | `CKM_RSA_PKCS_PSS` | `hashAlg`, `mgf`, `sLen` from `BCRYPT_PSS_PADDING_INFO` |
| `CK_RSA_PKCS_OAEP_PARAMS` | `CKM_RSA_PKCS_OAEP` | `hashAlg`, `mgf`, `source = CKZ_DATA_SPECIFIED`, `pSourceData` / `ulSourceDataLen` for the label |
| `CK_ECDH1_DERIVE_PARAMS` | `CKM_ECDH1_DERIVE` | `kdf = CKD_NULL`, `pPublicData` / `ulPublicDataLen` — the **raw** peer point, DER wrapper stripped |
| `CK_GCM_PARAMS` | `CKM_AES_GCM` | `pIv`, `ulIvLen`, `ulIvBits`, `pAAD`, `ulAADLen`, `ulTagBits = 128` |
| `CK_AES_CTR_PARAMS` | `CKM_AES_CTR` | `ulCounterBits = 32`, `cb[16]` counter block |

`CKM_AES_CBC` and `CKM_AES_CBC_PAD` take the raw 16-byte IV directly as
`pParameter`, with no wrapping structure.

---

## 6. Curve OIDs in `CKA_EC_PARAMS`

| Curve | OID | DER bytes | Length |
|-------|-----|-----------|-------:|
| P-256 (secp256r1) | 1.2.840.10045.3.1.7 | `06 08 2A 86 48 CE 3D 03 01 07` | 10 |
| P-384 (secp384r1) | 1.3.132.0.34 | `06 05 2B 81 04 00 22` | 7 |
| P-521 (secp521r1) | 1.3.132.0.35 | `06 05 2B 81 04 00 23` | 7 |
| secp256k1 | 1.3.132.0.10 | `06 05 2B 81 04 00 0A` | 7 |
| Ed25519 | 1.3.101.112 | `06 03 2B 65 70` | 5 |
| Ed448 | 1.3.101.113 | `06 03 2B 65 71` | 5 |

> Length alone cannot identify a curve: P-384, P-521 and secp256k1 are all
> 7 bytes, Ed25519 and Ed448 both 5. The KSP compares the full byte sequence.

---

## 7. Capability tiers

What each tier costs in backend support, and what is lost without it.

### Tier 1 — Parity with commercial CNG KSPs

Everything the market ships. Sufficient for certificate enrolment, TLS
server keys, code signing and AD CS.

| Requirement | Items |
|-------------|-------|
| Functions | 17 — the 12 always-required (§2), plus `C_GenerateKeyPair`, `C_SignInit`, `C_Sign`, `C_DecryptInit`, `C_Decrypt` |
| Mechanisms | `CKM_RSA_PKCS_KEY_PAIR_GEN`, `CKM_EC_KEY_PAIR_GEN`, `CKM_RSA_PKCS`, `CKM_RSA_PKCS_PSS`, `CKM_RSA_PKCS_OAEP`, `CKM_ECDSA` |
| Parameters | `CK_RSA_PKCS_PSS_PARAMS`, `CK_RSA_PKCS_OAEP_PARAMS` |
| Curves | P-256, P-384, P-521 |

### Tier 2 — Public key import

Adds `NCryptImportKey` for public keys, needed to use an imported key as an
ECDH peer or for verification against the token.

| Requirement | Items |
|-------------|-------|
| Functions | `C_CreateObject` |
| Attributes | Ability to create a session-scoped `CKO_PUBLIC_KEY` with caller-supplied `CKA_EC_POINT` / `CKA_MODULUS` |

### Tier 3 — ECDH key agreement

Adds `NCryptSecretAgreement` and `NCryptDeriveKey`. Required for TLS 1.3
ECDHE and IKEv2.

| Requirement | Items |
|-------------|-------|
| Functions | `C_DeriveKey` |
| Mechanisms | `CKM_ECDH1_DERIVE` with `CKD_NULL` |
| Parameters | `CK_ECDH1_DERIVE_PARAMS` |
| Attributes | Non-sensitive, extractable derived secret (§4.3) |

### Tier 4 — Symmetric

Adds `NCryptEncrypt` and symmetric `NCryptDecrypt`. Reachable only from an
application coded against this KSP's `AES` key handles.

| Requirement | Items |
|-------------|-------|
| Functions | `C_GenerateKey`, `C_EncryptInit`, `C_Encrypt` |
| Mechanisms | `CKM_AES_KEY_GEN`, `CKM_AES_ECB`, `CKM_AES_CBC`, `CKM_AES_CBC_PAD`, `CKM_AES_CTR`, `CKM_AES_GCM` |
| Parameters | `CK_GCM_PARAMS`, `CK_AES_CTR_PARAMS` |

### Tier 5 — EdDSA and HMAC

| Requirement | Items |
|-------------|-------|
| Mechanisms | `CKM_EC_EDWARDS_KEY_PAIR_GEN`, `CKM_EDDSA`, `CKM_GENERIC_SECRET_KEY_GEN`, `CKM_SHA_1_HMAC`, `CKM_SHA224_HMAC`, `CKM_SHA256_HMAC`, `CKM_SHA384_HMAC`, `CKM_SHA512_HMAC` |
| Key types | `CKK_EC_EDWARDS`, `CKK_GENERIC_SECRET` |

> **Tiers 4 and 5 use CNG algorithm identifiers this project defined itself.**
> `EDDSA_ED25519`, `EDDSA_ED448`, `HMAC_SHA*` and `ChainingModeCTR` are not
> CNG standards, so no stock Windows application will request them. See
> [11 — CNG KSP market comparison](./11-market-comparison.md), finding 2.

---

## 8. Session and token semantics

| Requirement | Value | Consequence if unmet |
|-------------|-------|----------------------|
| `C_Initialize` flags | `CKF_OS_LOCKING_OK` | The KSP is multi-threaded; a token without OS locking is unsafe |
| `CKR_CRYPTOKI_ALREADY_INITIALIZED` | Tolerated | Another library in-process may have initialised first |
| Slot selection | First slot from `C_GetSlotList(CK_TRUE, …)` | Multi-slot tokens: only the first with a token present is used |
| Session flags | `CKF_SERIAL_SESSION \| CKF_RW_SESSION` | R/W is required — keys are created and destroyed |
| Concurrent sessions | Up to **16** | A token with a lower session limit will block under load |
| Login | `C_Login(CKU_USER, pin)` per session | SO login is never used |
| `CKR_USER_ALREADY_LOGGED_IN` | Tolerated | Login state is often per-token, not per-session |
| PIN source | `SOFTHSM2_PIN` environment variable | Zeroed with `SecureZeroMemory` after login |

---

## 9. Backend evaluation checklist

Work down this list against a candidate token's `C_GetMechanismList` output
and its documentation.

- [ ] `C_GetFunctionList` exported from a loadable library
- [ ] `C_Initialize` accepts `CKF_OS_LOCKING_OK`
- [ ] At least one slot reports a token present
- [ ] 16 concurrent R/W sessions supported
- [ ] `C_Login` with `CKU_USER`
- [ ] `CKM_RSA_PKCS_KEY_PAIR_GEN` — RSA, any multiple of 64 from 2048 to 16384
- [ ] `CKM_RSA_PKCS` for both sign and decrypt
- [ ] `CKM_RSA_PKCS_PSS` with `CK_RSA_PKCS_PSS_PARAMS`, SHA-1/224/256/384/512
- [ ] `CKM_RSA_PKCS_OAEP` with SHA-1/224/256/384/512 and a label
- [ ] `CKM_EC_KEY_PAIR_GEN` — P-256, P-384, P-521, secp256k1
- [ ] `CKM_ECDSA` returning **DER-encoded** signatures
- [ ] `CKA_EC_POINT` returned as a DER `OCTET STRING`, long form for P-521
- [ ] `CKA_TOKEN=TRUE` + `CKA_SENSITIVE=TRUE` + `CKA_EXTRACTABLE=FALSE` accepted together
- [ ] `CKA_LABEL` searchable via `C_FindObjects`
- [ ] `C_CreateObject` for session-scoped public keys *(tier 2)*
- [ ] `CKM_ECDH1_DERIVE` with `CKD_NULL` *(tier 3)*
- [ ] Derived secret creatable as non-sensitive and extractable *(tier 3)*
- [ ] `CKM_AES_KEY_GEN` + ECB / CBC / CBC_PAD / CTR / GCM *(tier 4)*
- [ ] `CKM_EC_EDWARDS_KEY_PAIR_GEN` + `CKM_EDDSA` *(tier 5)*
- [ ] `CKM_GENERIC_SECRET_KEY_GEN` + `CKM_SHA*_HMAC` *(tier 5)*

---

## 10. Known backend constraints

Behaviours that are the token's responsibility and will break the KSP if
they differ.

| Expectation | Where it matters | Symptom if violated |
|-------------|------------------|---------------------|
| ECDSA signatures are DER | `P11_DecodeDerEcdsaSignature` | `NTE_INVALID_PARAMETER` on every ECDSA sign |
| `CKA_EC_POINT` is DER-wrapped | `P11_ExportEcPublicKey`, ECDH | `NTE_BAD_KEY` on export, or a wrong shared secret |
| P-521 point uses long-form DER length | Same | Truncated or malformed 133-byte points |
| `C_Sign` supports the two-call size pattern | `KSP_SignHash` | Buffer sizing fails |
| `C_Decrypt` returns `CKR_BUFFER_TOO_SMALL` on a short buffer | `KSP_Decrypt` | Size query returns the wrong length |
| Derived ECDH secret exposes `CKA_VALUE` | `KSP_DeriveKey` | `NTE_BAD_KEY` on derive |
| RSA public exponent 65537 accepted | `KSP_GenerateRsaKeyPair` | Key generation fails |

---

## See also

- [04 — Cryptographic operations](./04-crypto-operations.md) — how each mechanism is invoked
- [03 — Key management](./03-key-management.md) — the attribute templates in context
- [06 — Error mapping](./06-error-mapping.md) — `CK_RV` → `SECURITY_STATUS`
- [11 — CNG KSP market comparison](./11-market-comparison.md) — which of these tiers other providers ship
