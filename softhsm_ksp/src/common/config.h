/* config.h — SoftHSM2 KSP configuration constants
 * Default paths, PIN, and global constants.
 * Minimum SoftHSM2 version required: 2.7.0 (OpenSSL backend, PKCS#11 v2.40)
 */
#ifndef CONFIG_H
#define CONFIG_H

/* Default path to the SoftHSM2 library.
 * SOFTHSM2_LIB_DEFAULT_OVERRIDE is injected by CMake when SOFTHSM2_DIR is set
 * (i.e. when SoftHSM2 is compiled from the in-tree submodule). */
#ifdef SOFTHSM2_LIB_DEFAULT_OVERRIDE
# define SOFTHSM2_LIB_DEFAULT  L ## SOFTHSM2_LIB_DEFAULT_OVERRIDE
#else
# define SOFTHSM2_LIB_DEFAULT  L"C:\\Program Files\\SoftHSM2\\lib\\softhsm2-x64.dll"
#endif

/* Environment variable to override the library path */
#define SOFTHSM2_LIB_ENV       "SOFTHSM2_LIB"

/* Default user PIN */
#define SOFTHSM2_PIN_DEFAULT   "1234"

/* Environment variable to override the PIN */
#define SOFTHSM2_PIN_ENV       "SOFTHSM2_PIN"

/* Environment variable to enable debug logging */
#define KSP_DEBUG_ENV          "KSP_DEBUG"

/* CNG provider name */
#define KSP_PROVIDER_NAME      L"SoftHSM KSP"

/* KSP version */
#define KSP_VERSION            1

/* Magic numbers to validate structures */
#define KSP_PROVIDER_MAGIC     0x4B535050UL  /* 'KSPP' */
#define KSP_KEY_MAGIC          0x4B53504BUL  /* 'KSPK' */

/* Maximum session pool size */
#define P11_SESSION_POOL_SIZE  16

/* Default RSA key size (bits) */
#define RSA_DEFAULT_KEY_BITS   2048

/* Accepted RSA modulus range.
 *
 * The floor is deliberately 2048: Microsoft's Software KSP and Utimaco both
 * accept 512-bit RSA, but issuing such a key from this provider would be a
 * security regression. Define KSP_RSA_MIN_BITS at build time to lower it for
 * legacy interoperability — the default is never weakened silently.
 *
 *     cmake .. -DCMAKE_C_FLAGS="/DKSP_RSA_MIN_BITS=1024"
 */
#ifndef KSP_RSA_MIN_BITS
# define KSP_RSA_MIN_BITS      2048
#endif
#define KSP_RSA_MAX_BITS       16384
#define KSP_RSA_BITS_STEP      64      /* modulus must be a multiple of this */

/* Default RSA public exponent (65537). Overridable per key through
 * KSP_PUBLIC_EXPONENT_PROPERTY — see below. */
#define RSA_DEFAULT_PUBEXP     65537UL

/* Maximum key label length */
#define MAX_KEY_LABEL_LEN      256

/* Maximum algorithm identifier length */
#define MAX_ALG_ID_LEN         64

/* DER-encoded OIDs for EC curves */
/* P-256 (secp256r1): OID 1.2.840.10045.3.1.7 */
#define EC_OID_P256 \
    "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
#define EC_OID_P256_LEN  10

/* P-384 (secp384r1): OID 1.3.132.0.34 */
#define EC_OID_P384 \
    "\x06\x05\x2b\x81\x04\x00\x22"
#define EC_OID_P384_LEN  7

/* secp256k1: OID 1.3.132.0.10 — note the final byte is the only thing
 * separating it from P-384 (0x22) and P-521 (0x23); all three are 7 bytes. */
#define EC_OID_SECP256K1 \
    "\x06\x05\x2b\x81\x04\x00\x0a"
#define EC_OID_SECP256K1_LEN  7

/* P-521 (secp521r1): OID 1.3.132.0.35 */
#define EC_OID_P521 \
    "\x06\x05\x2b\x81\x04\x00\x23"
#define EC_OID_P521_LEN  7

/* Ed25519: OID 1.3.101.112 */
#define EC_OID_ED25519 \
    "\x06\x03\x2b\x65\x70"
#define EC_OID_ED25519_LEN  5

/* Ed448: OID 1.3.101.113 */
#define EC_OID_ED448 \
    "\x06\x03\x2b\x65\x71"
#define EC_OID_ED448_LEN  5

/* EC coordinate size in bytes */
#define EC_P256_COORD_SIZE  32
#define EC_P384_COORD_SIZE  48
#define EC_P521_COORD_SIZE  66   /* ceil(521 / 8) */
#define EC_SECP256K1_COORD_SIZE 32

/* EdDSA public key / signature sizes in bytes */
#define ED25519_PUBKEY_SIZE   32
#define ED25519_SIG_SIZE      64
#define ED448_PUBKEY_SIZE     57
#define ED448_SIG_SIZE       114

/* AES key sizes in bytes */
#define AES_128_KEY_BYTES  16
#define AES_192_KEY_BYTES  24
#define AES_256_KEY_BYTES  32
#define AES_BLOCK_SIZE     16
#define AES_GCM_TAG_BITS  128

/* CNG algorithm names — asymmetric */
#define ALG_RSA        L"RSA"
#define ALG_ECDSA_P256 L"ECDSA_P256"
#define ALG_ECDSA_P384 L"ECDSA_P384"
#define ALG_ECDSA_P521 L"ECDSA_P521"
/* secp256k1. CNG names the algorithm "ECDSA" and selects the curve through
 * BCRYPT_ECC_CURVE_NAME; this per-curve identifier is a KSP extension, in
 * keeping with how the NIST curves are already named here. */
#define ALG_ECDSA_SECP256K1 L"ECDSA_SECP256K1"
#define ALG_ECDH_P256  L"ECDH_P256"
#define ALG_ECDH_P384  L"ECDH_P384"
#define ALG_ECDH_P521  L"ECDH_P521"
#define ALG_EDDSA_ED25519 L"EDDSA_ED25519"
#define ALG_EDDSA_ED448   L"EDDSA_ED448"

/* CNG algorithm names — symmetric / MAC */
#define ALG_AES          L"AES"
#define ALG_HMAC_SHA1    L"HMAC_SHA1"
#define ALG_HMAC_SHA224  L"HMAC_SHA224"
#define ALG_HMAC_SHA256  L"HMAC_SHA256"
#define ALG_HMAC_SHA384  L"HMAC_SHA384"
#define ALG_HMAC_SHA512  L"HMAC_SHA512"

/* CNG algorithm group names */
#define ALG_GROUP_RSA    L"RSA"
#define ALG_GROUP_ECDSA  L"ECDSA"
#define ALG_GROUP_ECDH   L"ECDH"
#define ALG_GROUP_EDDSA  L"EDDSA"
#define ALG_GROUP_AES    L"AES"
#define ALG_GROUP_HMAC   L"HMAC"

/* Key class — distinguishes asymmetric pairs from symmetric secrets */
#define KSP_KEY_CLASS_ASYMMETRIC  0
#define KSP_KEY_CLASS_SYMMETRIC   1

/* Maximum GCM additional-authenticated-data length retained on a key */
#define MAX_AUTH_DATA_LEN  256

/* Chaining mode for AES-CTR. CNG defines no standard string for counter
 * mode, so the KSP accepts this name in NCRYPT_CHAINING_MODE_PROPERTY. */
#define KSP_CHAIN_MODE_CTR  L"ChainingModeCTR"

/* RSA public exponent, settable before FinalizeKey. CNG defines no standard
 * property for this, so the name is a KSP extension. */
#define KSP_PUBLIC_EXPONENT_PROPERTY  L"RSA Public Exponent"

/* Magic number validating a (KSP_SECRET *) agreed-secret handle */
#define KSP_SECRET_MAGIC       0x4B535053UL  /* 'KSPS' */

#endif /* CONFIG_H */
