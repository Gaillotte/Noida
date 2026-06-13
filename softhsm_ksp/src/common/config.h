/* config.h — Constantes de configuration du KSP SoftHSM2
 * Chemins par défaut, PIN et constantes globales.
 */
#ifndef CONFIG_H
#define CONFIG_H

/* Chemin par défaut de la bibliothèque SoftHSM2 */
#define SOFTHSM2_LIB_DEFAULT   L"C:\\Program Files\\SoftHSM2\\lib\\softhsm2-x64.dll"

/* Variable d'environnement pour surcharger le chemin */
#define SOFTHSM2_LIB_ENV       "SOFTHSM2_LIB"

/* PIN utilisateur par défaut */
#define SOFTHSM2_PIN_DEFAULT   "1234"

/* Variable d'environnement pour surcharger le PIN */
#define SOFTHSM2_PIN_ENV       "SOFTHSM2_PIN"

/* Variable d'environnement pour activer le logging debug */
#define KSP_DEBUG_ENV          "KSP_DEBUG"

/* Nom du fournisseur CNG */
#define KSP_PROVIDER_NAME      L"SoftHSM KSP"

/* Version du KSP */
#define KSP_VERSION            1

/* Magic numbers pour valider les structures */
#define KSP_PROVIDER_MAGIC     0x4B535050UL  /* 'KSPP' */
#define KSP_KEY_MAGIC          0x4B53504BUL  /* 'KSPK' */

/* Taille maximale du pool de sessions */
#define P11_SESSION_POOL_SIZE  16

/* Taille de clé RSA par défaut (bits) */
#define RSA_DEFAULT_KEY_BITS   2048

/* Longueur maximale du label de clé */
#define MAX_KEY_LABEL_LEN      256

/* Longueur maximale de l'identifiant d'algorithme */
#define MAX_ALG_ID_LEN         64

/* OID DER encodés pour les courbes EC */
/* P-256 (secp256r1) : OID 1.2.840.10045.3.1.7 */
#define EC_OID_P256 \
    "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
#define EC_OID_P256_LEN  10

/* P-384 (secp384r1) : OID 1.3.132.0.34 */
#define EC_OID_P384 \
    "\x06\x05\x2b\x81\x04\x00\x22"
#define EC_OID_P384_LEN  7

/* Taille des coordonnées EC en octets */
#define EC_P256_COORD_SIZE  32
#define EC_P384_COORD_SIZE  48

/* Noms d'algorithmes CNG */
#define ALG_RSA        L"RSA"
#define ALG_ECDSA_P256 L"ECDSA_P256"
#define ALG_ECDSA_P384 L"ECDSA_P384"

#endif /* CONFIG_H */
