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

/* EC coordinate size in bytes */
#define EC_P256_COORD_SIZE  32
#define EC_P384_COORD_SIZE  48

/* CNG algorithm names */
#define ALG_RSA        L"RSA"
#define ALG_ECDSA_P256 L"ECDSA_P256"
#define ALG_ECDSA_P384 L"ECDSA_P384"

#endif /* CONFIG_H */
