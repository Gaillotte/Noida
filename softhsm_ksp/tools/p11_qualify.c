/* p11_qualify.c — qualify a PKCS#11 token for this KSP, by running it.
 *
 * WHY THIS EXISTS
 *
 * docs/12-pkcs11-requirements.md §9 is a checklist, and its instruction was
 * "work down this list against a candidate token's C_GetMechanismList
 * output and its documentation". That is how one of its lines stayed wrong
 * for four sessions: it said CKM_ECDSA must return DER-encoded signatures,
 * when PKCS#11 v2.40 §2.3.1 mandates raw r||s and a conformant token
 * returns raw. A vendor answering "yes, DER" would have been the one that
 * could not work. Reading a checklist does not check anything.
 *
 * It matters more than tidiness because of how this KSP is developed and
 * where it is deployed: development happens against SoftHSM2, production is
 * meant to be a certified hardware HSM. Those are not the same token, and
 * the difference is not a list of features. SoftHSM2 is PERMISSIVE in
 * specific places, and every one of those places has already cost this
 * project a defect that passed its whole test suite:
 *
 *   - it answers CKA_MODULUS_BITS on the private key, where the standard
 *     puts it on the public one, so a misdirected read returned a value
 *     instead of failing;
 *   - it tolerates C_SignInit over an operation that was never finished, so
 *     a size query that poisoned the session pool looked harmless;
 *   - it enforces neither CKA_WRAP nor CKA_UNWRAP, so key wrap was
 *     non-functional on any strict token while passing here;
 *   - it accepts CKA_SUBJECT on a certificate that a strict token refuses.
 *
 * None of those is visible in C_GetMechanismList. A capability list cannot
 * express them, because they are not capabilities — they are the token
 * choosing whether to enforce something. So this program has two sections:
 *
 *   CONFORMANCE  what the KSP REQUIRES. A failure here means the token
 *                cannot host this provider, and the exit code says so.
 *
 *   DIVERGENCE   where tokens legitimately differ in strictness. Neither
 *                answer is a failure. What matters is knowing which side
 *                your DEVELOPMENT token is on, because a permissive one
 *                lets code pass that production will reject.
 *
 * ADVERTISEMENT IS NOT CAPABILITY, and the probe is mechanism-granular
 * where the limits are not. SoftHSM2 reports CKM_RSA_PKCS_OAEP as present
 * and then rejects every hash but SHA-1, because the restriction lives
 * inside the mechanism PARAMETERS. So the OAEP and PSS checks here run one
 * operation per hash rather than asking whether the mechanism exists.
 *
 * Standalone on purpose: it links nothing from this repository but
 * pkcs11.h, so it can be built and run against a vendor's library on a
 * machine that has no copy of the KSP.
 *
 *   gcc -O2 -o p11_qualify tools/p11_qualify.c -Isrc/pkcs11 -ldl
 *   ./p11_qualify <module.so> [--label L | --slot N] [--pin PIN]
 *
 * The PIN may also come from P11_QUALIFY_PIN, which keeps it off the
 * process list. Every object it creates is destroyed before it exits.
 */
/* The OASIS header expects its consumer to supply these before including
 * it, and src/pkcs11/pkcs11.h only defines them for _WIN32. Elsewhere in
 * this repository they come from tests/mock/windows_compat.h, which this
 * tool deliberately does not include: it has to build on a machine that
 * has a vendor's PKCS#11 library and no copy of the KSP. */
#ifndef CK_PTR
#  define CK_PTR *
#endif
#ifndef CK_DECLARE_FUNCTION
#  define CK_DECLARE_FUNCTION(returnType, name) returnType name
#endif
#ifndef CK_DECLARE_FUNCTION_POINTER
#  define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#endif
#ifndef CK_CALLBACK_FUNCTION
#  define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#endif
#ifndef NULL_PTR
#  define NULL_PTR NULL
#endif

#include "pkcs11.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LBL "p11qualify"

/* ───────────────────────────── reporting ───────────────────────────── */

static int g_conf_pass, g_conf_fail, g_conf_skip;
static int g_permissive, g_strict;

static void ok(const char *what, const char *detail)
{
    printf("  \033[32mPASS\033[0m  %-46s %s\n", what, detail ? detail : "");
    g_conf_pass++;
}

static void fail(const char *what, const char *detail)
{
    printf("  \033[31mFAIL\033[0m  %-46s %s\n", what, detail ? detail : "");
    g_conf_fail++;
}

/* A skip is not a pass. A token that cannot be asked a question has not
 * answered it, and a checklist that quietly counted "could not test" as
 * satisfied would be the same lie this program exists to stop. */
static void skip(const char *what, const char *why)
{
    printf("  \033[33mSKIP\033[0m  %-46s %s\n", what, why ? why : "");
    g_conf_skip++;
}

/* Divergences are reported, never failed. "Permissive" means this token
 * allows something a strict one refuses — which is a warning about what
 * your tests can no longer catch, not a defect in the token. */
static void permissive(const char *what, const char *detail)
{
    printf("  \033[33mPERMISSIVE\033[0m  %-40s %s\n", what, detail);
    g_permissive++;
}

static void strict(const char *what, const char *detail)
{
    printf("  \033[32mSTRICT\033[0m      %-40s %s\n", what, detail);
    g_strict++;
}

static const char *rvname(CK_RV rv)
{
    static char buf[32];
    switch (rv) {
    case CKR_OK:                        return "CKR_OK";
    case CKR_MECHANISM_INVALID:         return "CKR_MECHANISM_INVALID";
    case CKR_MECHANISM_PARAM_INVALID:   return "CKR_MECHANISM_PARAM_INVALID";
    case CKR_ATTRIBUTE_TYPE_INVALID:    return "CKR_ATTRIBUTE_TYPE_INVALID";
    case CKR_ATTRIBUTE_VALUE_INVALID:   return "CKR_ATTRIBUTE_VALUE_INVALID";
    case CKR_ATTRIBUTE_SENSITIVE:       return "CKR_ATTRIBUTE_SENSITIVE";
    case CKR_TEMPLATE_INCONSISTENT:     return "CKR_TEMPLATE_INCONSISTENT";
    case CKR_TEMPLATE_INCOMPLETE:       return "CKR_TEMPLATE_INCOMPLETE";
    case CKR_OPERATION_ACTIVE:          return "CKR_OPERATION_ACTIVE";
    case CKR_BUFFER_TOO_SMALL:          return "CKR_BUFFER_TOO_SMALL";
    case CKR_KEY_FUNCTION_NOT_PERMITTED:
                                        return "CKR_KEY_FUNCTION_NOT_PERMITTED";
    case CKR_KEY_UNEXTRACTABLE:         return "CKR_KEY_UNEXTRACTABLE";
    case CKR_KEY_HANDLE_INVALID:        return "CKR_KEY_HANDLE_INVALID";
    case CKR_WRAPPING_KEY_HANDLE_INVALID:
                                   return "CKR_WRAPPING_KEY_HANDLE_INVALID";
    case CKR_FUNCTION_NOT_SUPPORTED:    return "CKR_FUNCTION_NOT_SUPPORTED";
    case CKR_DOMAIN_PARAMS_INVALID:     return "CKR_DOMAIN_PARAMS_INVALID";
    case CKR_PIN_INCORRECT:             return "CKR_PIN_INCORRECT";
    case CKR_USER_ALREADY_LOGGED_IN:    return "CKR_USER_ALREADY_LOGGED_IN";
    case CKR_CRYPTOKI_ALREADY_INITIALIZED:
                                    return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
    default:
        snprintf(buf, sizeof(buf), "CK_RV 0x%lX", (unsigned long)rv);
        return buf;
    }
}

/* ───────────────────────────── state ───────────────────────────── */

static void                 *g_dl;
static CK_FUNCTION_LIST_PTR  g_fn;
static CK_SLOT_ID            g_slot;
static CK_SESSION_HANDLE     g_sess = CK_INVALID_HANDLE;

/* Curves, by the DER OID that goes in CKA_EC_PARAMS. Byte arrays rather
 * than names because that is what the attribute carries, and §6 of the
 * requirements document is explicit that the KSP compares them by bytes. */
typedef struct {
    const char   *name;
    const CK_BYTE oid[16];
    CK_ULONG      oidlen;
    CK_ULONG      coord;        /* one coordinate, in bytes */
    int           tier1;        /* required, versus a KSP extension */
} CURVE;

/* Tier 1 is P-256, P-384 and P-521 — §7 of the requirements document, and
 * what every commercial CNG KSP ships. secp256k1 and the Brainpool curves
 * are reachable only through a CNG algorithm identifier this project
 * defined itself, so a token without them is not disqualified; it just
 * offers less. The first version of this check failed the whole run
 * because Kryoptic lacks secp256k1, which would have told somebody
 * evaluating an HSM that a perfectly good token was unfit. */
static const CURVE CURVES[] = {
    { "P-256",     { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 }, 10, 32, 1 },
    { "P-384",     { 0x06,0x05,0x2B,0x81,0x04,0x00,0x22 },                 7, 48, 1 },
    { "P-521",     { 0x06,0x05,0x2B,0x81,0x04,0x00,0x23 },                 7, 66, 1 },
    { "secp256k1", { 0x06,0x05,0x2B,0x81,0x04,0x00,0x0A },                 7, 32, 0 },
};
#define NCURVES ((int)(sizeof(CURVES) / sizeof(CURVES[0])))

typedef struct {
    const char *name;
    CK_ULONG    hashAlg;
    CK_ULONG    mgf;
    CK_ULONG    len;            /* digest length, bytes */
} HASH;

static const HASH HASHES[] = {
    { "SHA-1",   CKM_SHA_1,  CKG_MGF1_SHA1,   20 },
    { "SHA-224", CKM_SHA224, CKG_MGF1_SHA224, 28 },
    { "SHA-256", CKM_SHA256, CKG_MGF1_SHA256, 32 },
    { "SHA-384", CKM_SHA384, CKG_MGF1_SHA384, 48 },
    { "SHA-512", CKM_SHA512, CKG_MGF1_SHA512, 64 },
};
#define NHASHES ((int)(sizeof(HASHES) / sizeof(HASHES[0])))

/* Objects created along the way, destroyed on the way out. A qualification
 * run that leaves keys on somebody's HSM is not acceptable, and the token
 * may well be one that cannot simply be reinitialised. */
#define MAX_TRACKED 64
static CK_OBJECT_HANDLE g_tracked[MAX_TRACKED];
static int              g_ntracked;

static void track(CK_OBJECT_HANDLE h)
{
    if (h != CK_INVALID_HANDLE && g_ntracked < MAX_TRACKED)
        g_tracked[g_ntracked++] = h;
}

static void destroy_tracked(void)
{
    int i, failed = 0;
    for (i = g_ntracked - 1; i >= 0; i--)
        if (g_fn->C_DestroyObject(g_sess, g_tracked[i]) != CKR_OK)
            failed++;
    g_ntracked = 0;
    if (failed)
        printf("\n  note: %d object(s) could not be destroyed — search the "
               "token for CKA_LABEL beginning \"%s\"\n", failed, LBL);
}

/* ───────────────────────── conformance checks ───────────────────────── */

static int load_module(const char *path)
{
    CK_RV (*getlist)(CK_FUNCTION_LIST_PTR_PTR);

    g_dl = dlopen(path, RTLD_NOW);
    if (!g_dl) {
        fail("module loads", dlerror());
        return 0;
    }
    getlist = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
              dlsym(g_dl, "C_GetFunctionList");
    if (!getlist) {
        fail("C_GetFunctionList exported", "symbol not found");
        return 0;
    }
    if (getlist(&g_fn) != CKR_OK || !g_fn) {
        fail("C_GetFunctionList answers", "returned no function list");
        return 0;
    }
    ok("C_GetFunctionList exported and answers", path);
    return 1;
}

static int initialise(void)
{
    CK_C_INITIALIZE_ARGS args;
    CK_INFO              info;
    CK_RV                rv;
    char                 buf[128];

    memset(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = g_fn->C_Initialize(&args);
    if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        ok("C_Initialize accepts CKF_OS_LOCKING_OK", "already initialised");
    } else if (rv != CKR_OK) {
        /* Not a nicety. The KSP is multi-threaded and PKCS#11 v2.40 §5.4
         * requires this flag before an application may rely on the
         * module's own locking. A token without it is unsafe here, not
         * merely slower. */
        fail("C_Initialize accepts CKF_OS_LOCKING_OK", rvname(rv));
        return 0;
    } else {
        ok("C_Initialize accepts CKF_OS_LOCKING_OK", NULL);
    }

    if (g_fn->C_GetInfo(&info) == CKR_OK) {
        snprintf(buf, sizeof(buf), "Cryptoki %u.%u, %.32s",
                 info.cryptokiVersion.major, info.cryptokiVersion.minor,
                 info.manufacturerID);
        ok("C_GetInfo answers", buf);
    } else {
        skip("C_GetInfo answers", "refused");
    }
    return 1;
}

static int pick_slot(const char *label, long want_slot)
{
    CK_SLOT_ID  slots[64];
    CK_ULONG    count = 64, i;
    CK_TOKEN_INFO ti;
    char        buf[128];

    if (g_fn->C_GetSlotList(CK_TRUE, slots, &count) != CKR_OK || count == 0) {
        fail("a slot reports a token present", "C_GetSlotList found none");
        return 0;
    }
    for (i = 0; i < count; i++) {
        if (g_fn->C_GetTokenInfo(slots[i], &ti) != CKR_OK)
            continue;
        if (want_slot >= 0 && (CK_SLOT_ID)want_slot != slots[i])
            continue;
        if (label) {
            char lab[33];
            size_t n;
            memcpy(lab, ti.label, 32);
            lab[32] = '\0';
            for (n = 32; n > 0 && lab[n - 1] == ' '; n--)
                lab[n - 1] = '\0';
            if (strcmp(lab, label) != 0)
                continue;
        }
        g_slot = slots[i];
        snprintf(buf, sizeof(buf), "slot %lu, label \"%.32s\"",
                 (unsigned long)g_slot, ti.label);
        ok("a slot reports a token present", buf);

        /* How this token expects to be authenticated. Reported, never
         * failed — all three are legitimate, and which one you get decides
         * Phase C of the AD CS plan. This is the question worth putting to
         * an HSM vendor, and answering it by measurement beats answering
         * it from a datasheet.
         *
         * The provider implements all three as of session 19; before that
         * it demanded a PIN of everything, so a token in either of the
         * first two rows was refused outright. */
        if ((ti.flags & CKF_LOGIN_REQUIRED) == 0)
            printf("  %-6s  %-46s %s\n", "auth", "token authentication model",
                   "no CKF_LOGIN_REQUIRED — no C_Login needed (plan option "
                   "C-d)");
        else if (ti.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
            printf("  %-6s  %-46s %s\n", "auth", "token authentication model",
                   "PROTECTED AUTHENTICATION PATH — no PIN travels through "
                   "Windows (plan option C-c, the one to prefer)");
        else
            printf("  %-6s  %-46s %s\n", "auth", "token authentication model",
                   "a PIN is required — Windows must hold a credential "
                   "(plan option C-a or C-b)");
        return 1;
    }
    fail("a slot reports a token present",
         label ? "no slot carries that label" : "no slot matched");
    return 0;
}

static int open_and_login(const char *pin)
{
    CK_RV rv = g_fn->C_OpenSession(g_slot,
                                   CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                   NULL, NULL, &g_sess);
    if (rv != CKR_OK) {
        fail("R/W session opens", rvname(rv));
        return 0;
    }
    ok("R/W session opens", "CKF_SERIAL_SESSION | CKF_RW_SESSION");

    if (!pin) {
        skip("C_Login as CKU_USER", "no PIN given");
        return 0;
    }
    rv = g_fn->C_Login(g_sess, CKU_USER, (CK_UTF8CHAR_PTR)pin,
                       (CK_ULONG)strlen(pin));
    if (rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN) {
        ok("C_Login as CKU_USER", rv == CKR_OK ? NULL : "already logged in");
        return 1;
    }
    fail("C_Login as CKU_USER", rvname(rv));
    return 0;
}

static void check_session_count(void)
{
    /* The KSP's pool is 16. A token with a lower ceiling does not fail
     * outright — it blocks under load, which is the kind of problem that
     * shows up in production and not in a test. */
    CK_SESSION_HANDLE s[15];
    int               n = 0, i;
    char              buf[64];

    /* 15, not 16: the session this program is already holding counts
     * toward the pool's 16. Opening 16 more reported "17 of 16", which is
     * a true statement of the wrong quantity. */
    for (i = 0; i < 15; i++) {
        if (g_fn->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                NULL, NULL, &s[n]) != CKR_OK)
            break;
        n++;
    }
    snprintf(buf, sizeof(buf), "%d of 16 concurrent", n + 1);
    if (n >= 15)
        ok("16 concurrent R/W sessions", buf);
    else
        fail("16 concurrent R/W sessions", buf);
    for (i = 0; i < n; i++)
        g_fn->C_CloseSession(s[i]);
}

/* Generate the RSA pair every later RSA check uses. */
static int gen_rsa(CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv)
{
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_ULONG     bits = 2048;
    CK_BYTE      e[] = { 0x01, 0x00, 0x01 };
    CK_BBOOL     yes = CK_TRUE, no = CK_FALSE;
    char         lab[64];
    CK_RV        rv;

    snprintf(lab, sizeof(lab), "%s-rsa", LBL);

    CK_ATTRIBUTE pubt[] = {
        { CKA_TOKEN,           &yes,  sizeof(yes) },
        { CKA_LABEL,           lab,   (CK_ULONG)strlen(lab) },
        { CKA_MODULUS_BITS,    &bits, sizeof(bits) },
        { CKA_PUBLIC_EXPONENT, e,     sizeof(e) },
        { CKA_VERIFY,          &yes,  sizeof(yes) },
        { CKA_ENCRYPT,         &yes,  sizeof(yes) },
    };
    /* The three together are the point. A token that accepts each alone
     * and refuses the combination cannot hold a key for this provider. */
    CK_ATTRIBUTE privt[] = {
        { CKA_TOKEN,       &yes, sizeof(yes) },
        { CKA_LABEL,       lab,  (CK_ULONG)strlen(lab) },
        { CKA_PRIVATE,     &yes, sizeof(yes) },
        { CKA_SENSITIVE,   &yes, sizeof(yes) },
        { CKA_EXTRACTABLE, &no,  sizeof(no) },
        { CKA_SIGN,        &yes, sizeof(yes) },
        { CKA_DECRYPT,     &yes, sizeof(yes) },
    };

    rv = g_fn->C_GenerateKeyPair(g_sess, &mech,
                                 pubt, sizeof(pubt) / sizeof(pubt[0]),
                                 privt, sizeof(privt) / sizeof(privt[0]),
                                 pub, priv);
    if (rv != CKR_OK) {
        fail("RSA-2048 keygen, e=65537, sensitive+non-extractable",
             rvname(rv));
        return 0;
    }
    track(*pub);
    track(*priv);
    ok("RSA-2048 keygen, e=65537, sensitive+non-extractable", NULL);
    return 1;
}

static void check_rsa_public_attrs(CK_OBJECT_HANDLE pub)
{
    CK_ULONG     bits = 0;
    CK_ATTRIBUTE a = { CKA_MODULUS_BITS, &bits, sizeof(bits) };
    CK_ATTRIBUTE m[2];
    CK_RV        rv;
    char         buf[64];

    rv = g_fn->C_GetAttributeValue(g_sess, pub, &a, 1);
    if (rv == CKR_OK && bits == 2048) {
        ok("CKA_MODULUS_BITS on the PUBLIC key", "2048");
    } else {
        /* This is the attribute whose misdirected read gave every reopened
         * key dwKeyBitLen = 0, and CNG's length-first calling convention
         * turned that into a failure on every signature. */
        snprintf(buf, sizeof(buf), "%s, value %lu", rvname(rv),
                 (unsigned long)bits);
        fail("CKA_MODULUS_BITS on the PUBLIC key", buf);
    }

    m[0].type = CKA_MODULUS;          m[0].pValue = NULL; m[0].ulValueLen = 0;
    m[1].type = CKA_PUBLIC_EXPONENT;  m[1].pValue = NULL; m[1].ulValueLen = 0;
    rv = g_fn->C_GetAttributeValue(g_sess, pub, m, 2);
    if (rv == CKR_OK && m[0].ulValueLen == 256 && m[1].ulValueLen >= 3) {
        ok("CKA_MODULUS + CKA_PUBLIC_EXPONENT readable", "256-byte modulus");
    } else {
        snprintf(buf, sizeof(buf), "%s, modulus %lu bytes", rvname(rv),
                 (unsigned long)m[0].ulValueLen);
        fail("CKA_MODULUS + CKA_PUBLIC_EXPONENT readable", buf);
    }
}

static void check_rsa_pkcs_sign(CK_OBJECT_HANDLE priv)
{
    /* DigestInfo for SHA-256, as NCryptSignHash hands it over with
     * NCRYPT_PAD_PKCS1_FLAG: the provider never hashes anything itself. */
    CK_BYTE      di[51] = {
        0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,
        0x02,0x01,0x05,0x00,0x04,0x20
    };
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
    CK_BYTE      sig[512];
    CK_ULONG     cb = 0;
    CK_RV        rv;
    char         buf[80];

    rv = g_fn->C_SignInit(g_sess, &mech, priv);
    if (rv != CKR_OK) {
        fail("CKM_RSA_PKCS sign", rvname(rv));
        return;
    }
    /* The two-call pattern, which is not optional: CNG calls every
     * operation twice, NULL buffer first for the length. */
    rv = g_fn->C_Sign(g_sess, di, sizeof(di), NULL, &cb);
    if (rv != CKR_OK || cb != 256) {
        snprintf(buf, sizeof(buf), "%s, length %lu", rvname(rv),
                 (unsigned long)cb);
        fail("CKM_RSA_PKCS two-call size query", buf);
        return;
    }
    rv = g_fn->C_Sign(g_sess, di, sizeof(di), sig, &cb);
    if (rv == CKR_OK && cb == 256)
        ok("CKM_RSA_PKCS sign, two-call size pattern", "256 bytes");
    else
        fail("CKM_RSA_PKCS sign, two-call size pattern", rvname(rv));
}

static void check_pss(CK_OBJECT_HANDLE priv)
{
    char line[160] = "";
    int  i, got = 0;

    for (i = 0; i < NHASHES; i++) {
        CK_RSA_PKCS_PSS_PARAMS p;
        CK_MECHANISM mech;
        CK_BYTE      hash[64], sig[512];
        CK_ULONG     cb = sizeof(sig);
        CK_RV        rv;

        p.hashAlg = HASHES[i].hashAlg;
        p.mgf     = HASHES[i].mgf;
        p.sLen    = HASHES[i].len;
        mech.mechanism      = CKM_RSA_PKCS_PSS;
        mech.pParameter     = &p;
        mech.ulParameterLen = sizeof(p);
        memset(hash, 0xA5, sizeof(hash));

        rv = g_fn->C_SignInit(g_sess, &mech, priv);
        if (rv == CKR_OK)
            rv = g_fn->C_Sign(g_sess, hash, HASHES[i].len, sig, &cb);
        if (rv == CKR_OK) {
            got++;
            strncat(line, HASHES[i].name, sizeof(line) - strlen(line) - 2);
            strncat(line, " ", sizeof(line) - strlen(line) - 2);
        }
    }
    if (got == NHASHES)
        ok("CKM_RSA_PKCS_PSS, all five hashes", line);
    else if (got > 0)
        fail("CKM_RSA_PKCS_PSS, all five hashes", line[0] ? line : "none");
    else
        fail("CKM_RSA_PKCS_PSS, all five hashes", "no hash accepted");
}

static void check_oaep(CK_OBJECT_HANDLE pub, CK_OBJECT_HANDLE priv)
{
    /* One full round trip per hash, because the limit that bit this
     * project is inside the mechanism PARAMETERS and invisible to
     * C_GetMechanismList: SoftHSM2 advertises CKM_RSA_PKCS_OAEP and then
     * rejects any hashAlg but CKM_SHA_1. */
    char line[160] = "";
    int  i, got = 0;

    for (i = 0; i < NHASHES; i++) {
        CK_RSA_PKCS_OAEP_PARAMS p;
        CK_MECHANISM mech;
        CK_BYTE      msg[32], ct[512], pt[512];
        CK_ULONG     cbct = sizeof(ct), cbpt = sizeof(pt);
        CK_RV        rv;

        memset(&p, 0, sizeof(p));
        p.hashAlg = HASHES[i].hashAlg;
        p.mgf     = HASHES[i].mgf;
        /* CKZ_DATA_SPECIFIED with a NULL label, which is exactly what
         * P11_BuildOaepParams sends — the probe has to ask the question
         * the KSP asks, not a nearby one.
         *
         * The first version set source = 0 on the reasoning that there is
         * no label to specify. Kryoptic accepted that and SoftHSM2
         * answered CKR_ARGUMENTS_BAD, so the probe reported that SoftHSM2
         * supports OAEP with no hash at all — a false failure against a
         * token that works, which for a tool meant to qualify somebody's
         * HSM is the worst way to be wrong. */
        p.source  = CKZ_DATA_SPECIFIED;
        mech.mechanism      = CKM_RSA_PKCS_OAEP;
        mech.pParameter     = &p;
        mech.ulParameterLen = sizeof(p);
        memset(msg, 0x5A, sizeof(msg));

        rv = g_fn->C_EncryptInit(g_sess, &mech, pub);
        if (rv == CKR_OK)
            rv = g_fn->C_Encrypt(g_sess, msg, sizeof(msg), ct, &cbct);
        if (rv != CKR_OK)
            continue;
        rv = g_fn->C_DecryptInit(g_sess, &mech, priv);
        if (rv == CKR_OK)
            rv = g_fn->C_Decrypt(g_sess, ct, cbct, pt, &cbpt);
        if (rv == CKR_OK && cbpt == sizeof(msg) &&
            memcmp(pt, msg, sizeof(msg)) == 0) {
            got++;
            strncat(line, HASHES[i].name, sizeof(line) - strlen(line) - 2);
            strncat(line, " ", sizeof(line) - strlen(line) - 2);
        }
    }
    if (got == NHASHES)
        ok("CKM_RSA_PKCS_OAEP round trip, all five hashes", line);
    else if (got > 0)
        /* Not a conformance failure of the token so much as a limit the
         * KSP cannot discover by probing — recorded as a failure because a
         * caller asking for OAEP-SHA256 will be refused at run time. */
        fail("CKM_RSA_PKCS_OAEP round trip, all five hashes",
             line[0] ? line : "none");
    else
        fail("CKM_RSA_PKCS_OAEP round trip, all five hashes",
             "no hash completed a round trip");
}

static void check_decrypt_short_buffer(CK_OBJECT_HANDLE pub,
                                       CK_OBJECT_HANDLE priv)
{
    /* KSP_Decrypt's size query depends on this answer being
     * CKR_BUFFER_TOO_SMALL rather than a truncated success. */
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
    CK_BYTE      msg[16], ct[512], pt[4];
    CK_ULONG     cbct = sizeof(ct), cbpt = sizeof(pt);
    CK_RV        rv;

    memset(msg, 0x33, sizeof(msg));
    if (g_fn->C_EncryptInit(g_sess, &mech, pub) != CKR_OK ||
        g_fn->C_Encrypt(g_sess, msg, sizeof(msg), ct, &cbct) != CKR_OK) {
        skip("short buffer gives CKR_BUFFER_TOO_SMALL",
             "could not encrypt a sample");
        return;
    }
    if (g_fn->C_DecryptInit(g_sess, &mech, priv) != CKR_OK) {
        skip("short buffer gives CKR_BUFFER_TOO_SMALL", "C_DecryptInit failed");
        return;
    }
    rv = g_fn->C_Decrypt(g_sess, ct, cbct, pt, &cbpt);
    if (rv == CKR_BUFFER_TOO_SMALL)
        ok("short buffer gives CKR_BUFFER_TOO_SMALL", NULL);
    else
        fail("short buffer gives CKR_BUFFER_TOO_SMALL", rvname(rv));
    /* The operation is still active; PKCS#11 lets it be retried with a
     * bigger buffer, which also releases it. */
    cbpt = sizeof(ct);
    g_fn->C_Decrypt(g_sess, ct, cbct, ct, &cbpt);
}

static int gen_ec(const CURVE *c, CK_OBJECT_HANDLE *pub,
                  CK_OBJECT_HANDLE *priv)
{
    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_BBOOL     yes = CK_TRUE, no = CK_FALSE;
    char         lab[64];
    CK_RV        rv;

    snprintf(lab, sizeof(lab), "%s-%s", LBL, c->name);

    CK_ATTRIBUTE pubt[] = {
        { CKA_TOKEN,     &yes, sizeof(yes) },
        { CKA_LABEL,     lab,  (CK_ULONG)strlen(lab) },
        { CKA_EC_PARAMS, (void *)c->oid, c->oidlen },
        { CKA_VERIFY,    &yes, sizeof(yes) },
    };
    CK_ATTRIBUTE privt[] = {
        { CKA_TOKEN,       &yes, sizeof(yes) },
        { CKA_LABEL,       lab,  (CK_ULONG)strlen(lab) },
        { CKA_PRIVATE,     &yes, sizeof(yes) },
        { CKA_SENSITIVE,   &yes, sizeof(yes) },
        { CKA_EXTRACTABLE, &no,  sizeof(no) },
        { CKA_SIGN,        &yes, sizeof(yes) },
        { CKA_DERIVE,      &no,  sizeof(no) },
    };

    rv = g_fn->C_GenerateKeyPair(g_sess, &mech,
                                 pubt, sizeof(pubt) / sizeof(pubt[0]),
                                 privt, sizeof(privt) / sizeof(privt[0]),
                                 pub, priv);
    if (rv != CKR_OK)
        return 0;
    track(*pub);
    track(*priv);
    return 1;
}

/* The check this program was written for. */
static void check_ecdsa_form(void)
{
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_MECHANISM     mech = { CKM_ECDSA, NULL, 0 };
    CK_BYTE          hash[32], sig[256];
    CK_ULONG         cb = sizeof(sig);
    CK_RV            rv;
    char             buf[128];

    if (!gen_ec(&CURVES[0], &pub, &priv)) {
        skip("ECDSA signatures are raw r||s, not DER", "no P-256 key");
        return;
    }
    memset(hash, 0x11, sizeof(hash));
    rv = g_fn->C_SignInit(g_sess, &mech, priv);
    if (rv == CKR_OK)
        rv = g_fn->C_Sign(g_sess, hash, sizeof(hash), sig, &cb);
    if (rv != CKR_OK) {
        fail("ECDSA signatures are raw r||s, not DER", rvname(rv));
        return;
    }

    if (cb == 2 * CURVES[0].coord) {
        ok("ECDSA signatures are raw r||s, not DER", "64 bytes, conformant");
    } else if (cb > 0 && sig[0] == 0x30) {
        /* PKCS#11 v2.40 §2.3.1 mandates raw. The KSP keeps a DER decoder
         * as a fallback and selects it by length, so such a token works —
         * but it is the non-conformant one, and the requirements document
         * said the opposite for four sessions. */
        snprintf(buf, sizeof(buf),
                 "%lu bytes beginning 0x30 — DER; non-conformant but the "
                 "KSP's fallback handles it", (unsigned long)cb);
        fail("ECDSA signatures are raw r||s, not DER", buf);
    } else {
        snprintf(buf, sizeof(buf), "%lu bytes, neither raw nor DER",
                 (unsigned long)cb);
        fail("ECDSA signatures are raw r||s, not DER", buf);
    }
}

static void check_curves_and_point(void)
{
    char missing[160] = "", extra[160] = "";
    int  i, need = 0, got = 0, wrapped = 0, tested = 0;

    for (i = 0; i < NCURVES; i++) {
        CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
        CK_ATTRIBUTE     a;
        CK_BYTE          pt[256];

        if (CURVES[i].tier1)
            need++;
        if (!gen_ec(&CURVES[i], &pub, &priv)) {
            char *dst = CURVES[i].tier1 ? missing : extra;
            size_t cap = sizeof(missing) - strlen(dst) - 2;
            if (CURVES[i].tier1) {
                strncat(dst, CURVES[i].name, cap);
                strncat(dst, " ", sizeof(missing) - strlen(dst) - 2);
            }
            continue;
        }
        if (CURVES[i].tier1)
            got++;
        else {
            strncat(extra, CURVES[i].name, sizeof(extra) - strlen(extra) - 2);
            strncat(extra, " ", sizeof(extra) - strlen(extra) - 2);
        }

        a.type = CKA_EC_POINT; a.pValue = pt; a.ulValueLen = sizeof(pt);
        if (g_fn->C_GetAttributeValue(g_sess, pub, &a, 1) != CKR_OK)
            continue;
        tested++;
        /* DER OCTET STRING wrapping 04||X||Y. The tag and the uncompressed
         * point marker are both 0x04, so the length is what distinguishes a
         * wrapped point from a bare one: P-256 wrapped is 67 bytes, bare is
         * 65. P-521 needs the long form, 04 81 85. */
        if (a.ulValueLen == 2 * CURVES[i].coord + 1 + 2 &&
            pt[0] == 0x04 && pt[1] == (CK_BYTE)(2 * CURVES[i].coord + 1))
            wrapped++;
        else if (a.ulValueLen == 2 * CURVES[i].coord + 1 + 3 &&
                 pt[0] == 0x04 && pt[1] == 0x81 &&
                 pt[2] == (CK_BYTE)(2 * CURVES[i].coord + 1))
            wrapped++;
    }

    if (got == need)
        ok("CKM_EC_KEY_PAIR_GEN on P-256, P-384, P-521", NULL);
    else
        fail("CKM_EC_KEY_PAIR_GEN on P-256, P-384, P-521",
             missing[0] ? missing : "none generated");

    /* Reported, never failed: an absent extension curve costs the token
     * nothing it is being evaluated for. */
    printf("  %-6s  %-46s %s\n", "note", "extension curves available",
           extra[0] ? extra : "none — secp256k1 absent, which is allowed");

    if (tested == 0)
        skip("CKA_EC_POINT is a DER OCTET STRING", "no point readable");
    else if (wrapped == tested)
        ok("CKA_EC_POINT is a DER OCTET STRING",
           "including the long form where needed");
    else
        fail("CKA_EC_POINT is a DER OCTET STRING", "bare point returned");
}

static void check_find_by_label(void)
{
    char             lab[64];
    CK_ATTRIBUTE     t[1];
    CK_OBJECT_HANDLE h[4];
    CK_ULONG         n = 0;
    CK_RV            rv;

    snprintf(lab, sizeof(lab), "%s-rsa", LBL);
    t[0].type = CKA_LABEL; t[0].pValue = lab;
    t[0].ulValueLen = (CK_ULONG)strlen(lab);

    rv = g_fn->C_FindObjectsInit(g_sess, t, 1);
    if (rv != CKR_OK) {
        fail("CKA_LABEL searchable via C_FindObjects", rvname(rv));
        return;
    }
    rv = g_fn->C_FindObjects(g_sess, h, 4, &n);
    g_fn->C_FindObjectsFinal(g_sess);
    if (rv == CKR_OK && n >= 2)
        ok("CKA_LABEL searchable via C_FindObjects", "public and private");
    else
        fail("CKA_LABEL searchable via C_FindObjects",
             rv == CKR_OK ? "label matched too few objects" : rvname(rv));
}

/* ───────────────────────── divergence probes ───────────────────────── */

static void diverge_modulus_bits_private(CK_OBJECT_HANDLE priv)
{
    CK_ULONG     bits = 0;
    CK_ATTRIBUTE a = { CKA_MODULUS_BITS, &bits, sizeof(bits) };
    CK_RV        rv = g_fn->C_GetAttributeValue(g_sess, priv, &a, 1);

    if (rv == CKR_OK && bits == 2048)
        permissive("CKA_MODULUS_BITS on the private key",
                   "answered 2048 — a misdirected read SUCCEEDS here");
    else
        strict("CKA_MODULUS_BITS on the private key", rvname(rv));
}

static void diverge_operation_active(CK_OBJECT_HANDLE priv)
{
    /* Deliberately leave an operation unfinished, then start another. A
     * strict token answers CKR_OPERATION_ACTIVE; PKCS#11 v2.40 §5.2 gives
     * no way to cancel one. SoftHSM2 tolerates it, which is why a size
     * query that returned without finishing its C_Sign poisoned the
     * session pool for nine sessions without being noticed.
     *
     * On its own session, because a token that refuses leaves this one
     * holding an operation nothing can clear. */
    CK_SESSION_HANDLE s = CK_INVALID_HANDLE;
    CK_MECHANISM      mech = { CKM_RSA_PKCS, NULL, 0 };
    CK_ULONG          cb = 0;
    CK_BYTE           di[51] = { 0x30, 0x31 };
    CK_RV             rv;

    if (g_fn->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL, NULL, &s) != CKR_OK) {
        printf("  SKIP        %-40s %s\n", "re-init over a live operation",
               "could not open a scratch session");
        return;
    }
    if (g_fn->C_SignInit(s, &mech, priv) != CKR_OK) {
        g_fn->C_CloseSession(s);
        printf("  SKIP        %-40s %s\n", "re-init over a live operation",
               "C_SignInit failed on the scratch session");
        return;
    }
    /* Size query only — the operation stays live, exactly as the defect
     * left it. */
    g_fn->C_Sign(s, di, sizeof(di), NULL, &cb);
    rv = g_fn->C_SignInit(s, &mech, priv);
    if (rv == CKR_OK)
        permissive("re-init over a live operation",
                   "tolerated — a leaked operation is INVISIBLE here");
    else
        strict("re-init over a live operation", rvname(rv));
    g_fn->C_CloseSession(s);
}

static void diverge_wrap_enforcement(void)
{
    /* An AES key created WITHOUT CKA_WRAP. PKCS#11 gates C_WrapKey on it;
     * a token that does not enforce it let AES key wrap pass here while
     * being non-functional on any strict token. */
    CK_MECHANISM gen = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_ULONG     len = 32;
    CK_BBOOL     yes = CK_TRUE, no = CK_FALSE;
    CK_OBJECT_HANDLE kek = CK_INVALID_HANDLE, target = CK_INVALID_HANDLE;
    CK_BYTE      iv[16], out[128];
    CK_ULONG     cbout = sizeof(out);
    CK_MECHANISM wrapmech;
    char         lab[64], lab2[64];
    CK_RV        rv;

    snprintf(lab,  sizeof(lab),  "%s-kek", LBL);
    snprintf(lab2, sizeof(lab2), "%s-tgt", LBL);
    memset(iv, 0xA6, sizeof(iv));

    CK_ATTRIBUTE kekt[] = {
        { CKA_TOKEN,       &yes, sizeof(yes) },
        { CKA_LABEL,       lab,  (CK_ULONG)strlen(lab) },
        { CKA_VALUE_LEN,   &len, sizeof(len) },
        { CKA_SENSITIVE,   &yes, sizeof(yes) },
        { CKA_EXTRACTABLE, &no,  sizeof(no) },
        /* CKA_WRAP deliberately absent — that is the whole probe. */
    };
    CK_ATTRIBUTE tgtt[] = {
        { CKA_TOKEN,       &yes, sizeof(yes) },
        { CKA_LABEL,       lab2, (CK_ULONG)strlen(lab2) },
        { CKA_VALUE_LEN,   &len, sizeof(len) },
        { CKA_SENSITIVE,   &yes, sizeof(yes) },
        { CKA_EXTRACTABLE, &yes, sizeof(yes) },
    };

    if (g_fn->C_GenerateKey(g_sess, &gen, kekt,
                            sizeof(kekt) / sizeof(kekt[0]), &kek) != CKR_OK ||
        g_fn->C_GenerateKey(g_sess, &gen, tgtt,
                            sizeof(tgtt) / sizeof(tgtt[0]),
                            &target) != CKR_OK) {
        printf("  SKIP        %-40s %s\n", "CKA_WRAP enforced on C_WrapKey",
               "no AES key generation");
        if (kek != CK_INVALID_HANDLE)
            track(kek);
        return;
    }
    track(kek);
    track(target);

    wrapmech.mechanism      = CKM_AES_KEY_WRAP;
    wrapmech.pParameter     = NULL;
    wrapmech.ulParameterLen = 0;
    rv = g_fn->C_WrapKey(g_sess, &wrapmech, kek, target, out, &cbout);
    /* Three refusals mean the same thing. A token may reject the key as
     * not permitted for the function, or reject the HANDLE as not a
     * wrapping key at all — Kryoptic answers the latter. Treating only the
     * first as strict reported a strict token as untestable, which is the
     * wrong answer given confidently. */
    if (rv == CKR_OK)
        permissive("CKA_WRAP enforced on C_WrapKey",
                   "wrapped without CKA_WRAP — not enforced");
    else if (rv == CKR_KEY_FUNCTION_NOT_PERMITTED ||
             rv == CKR_WRAPPING_KEY_HANDLE_INVALID ||
             rv == CKR_KEY_HANDLE_INVALID)
        strict("CKA_WRAP enforced on C_WrapKey", rvname(rv));
    else
        printf("  SKIP        %-40s %s\n", "CKA_WRAP enforced on C_WrapKey",
               rvname(rv));
}

static void diverge_cert_subject(void)
{
    /* A CKO_CERTIFICATE without CKA_SUBJECT. Kryoptic answers
     * CKR_TEMPLATE_INCONSISTENT, which is why the KSP parses the subject
     * out of the DER rather than leaving it unset — a phase-5 prediction
     * that came due the first time a strict token saw it. */
    CK_OBJECT_CLASS cls  = CKO_CERTIFICATE;
    /* CK_ULONG rather than CK_CERTIFICATE_TYPE: this repository's pkcs11.h
     * is a partial copy of the OASIS header carrying what the KSP uses, and
     * ksp_key.c declares this attribute the same way. */
    CK_ULONG        ct  = CKC_X_509;
    CK_BBOOL        yes = CK_TRUE;
    /* Not a real certificate: the point is which attributes the token
     * demands in the template, which it decides before parsing the value. */
    CK_BYTE         der[8] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    char            lab[64];
    CK_RV           rv;

    snprintf(lab, sizeof(lab), "%s-cert", LBL);
    CK_ATTRIBUTE t[] = {
        { CKA_CLASS,            &cls, sizeof(cls) },
        { CKA_CERTIFICATE_TYPE, &ct,  sizeof(ct) },
        { CKA_TOKEN,            &yes, sizeof(yes) },
        { CKA_LABEL,            lab,  (CK_ULONG)strlen(lab) },
        { CKA_VALUE,            der,  sizeof(der) },
        /* CKA_SUBJECT deliberately absent. */
    };

    rv = g_fn->C_CreateObject(g_sess, t, sizeof(t) / sizeof(t[0]), &h);
    if (rv == CKR_OK) {
        track(h);
        permissive("CKA_SUBJECT required on a certificate",
                   "certificate created without it");
    } else if (rv == CKR_TEMPLATE_INCOMPLETE ||
               rv == CKR_TEMPLATE_INCONSISTENT) {
        strict("CKA_SUBJECT required on a certificate", rvname(rv));
    } else {
        printf("  SKIP        %-40s %s\n",
               "CKA_SUBJECT required on a certificate", rvname(rv));
    }
}

/* ───────────────────────────── main ───────────────────────────── */

static void usage(const char *argv0)
{
    fprintf(stderr,
      "usage: %s <module.so> [--label LABEL | --slot N] [--pin PIN]\n"
      "\n"
      "Qualifies a PKCS#11 token for the SoftHSM2 CNG KSP by running\n"
      "operations against it, not by reading its mechanism list.\n"
      "The PIN may be given in P11_QUALIFY_PIN instead of on the command\n"
      "line. Every object created is destroyed before exit.\n", argv0);
}

int main(int argc, char **argv)
{
    const char *module = NULL, *label = NULL, *pin = getenv("P11_QUALIFY_PIN");
    long        slot = -1;
    int         i, logged_in;
    CK_OBJECT_HANDLE rsapub = CK_INVALID_HANDLE, rsapriv = CK_INVALID_HANDLE;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--label") == 0 && i + 1 < argc)
            label = argv[++i];
        else if (strcmp(argv[i], "--slot") == 0 && i + 1 < argc)
            slot = strtol(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--pin") == 0 && i + 1 < argc)
            pin = argv[++i];
        else if (argv[i][0] != '-' && !module)
            module = argv[i];
        else {
            usage(argv[0]);
            return 2;
        }
    }
    if (!module) {
        usage(argv[0]);
        return 2;
    }

    printf("\nPKCS#11 qualification for the SoftHSM2 CNG KSP\n");
    printf("module: %s\n", module);

    printf("\n── CONFORMANCE — what the KSP requires ──────────────────\n");
    if (!load_module(module) || !initialise())
        return 1;
    if (!pick_slot(label, slot))
        goto done;
    logged_in = open_and_login(pin);
    if (!logged_in) {
        printf("\n  Without a login nothing below can run. Pass --pin or "
               "set P11_QUALIFY_PIN.\n");
        goto done;
    }
    check_session_count();

    if (gen_rsa(&rsapub, &rsapriv)) {
        check_rsa_public_attrs(rsapub);
        check_rsa_pkcs_sign(rsapriv);
        check_pss(rsapriv);
        check_oaep(rsapub, rsapriv);
        check_decrypt_short_buffer(rsapub, rsapriv);
    }
    check_ecdsa_form();
    check_curves_and_point();
    check_find_by_label();

    printf("\n── DIVERGENCE — where a permissive token hides a defect ──\n");
    printf("  Neither answer is wrong. A PERMISSIVE development token lets\n"
           "  code pass that a strict production token will reject, and\n"
           "  every line below has already cost this project a defect.\n\n");
    if (rsapriv != CK_INVALID_HANDLE) {
        diverge_modulus_bits_private(rsapriv);
        diverge_operation_active(rsapriv);
    }
    diverge_wrap_enforcement();
    diverge_cert_subject();

done:
    if (g_sess != CK_INVALID_HANDLE) {
        destroy_tracked();
        g_fn->C_CloseSession(g_sess);
    }
    if (g_fn)
        g_fn->C_Finalize(NULL);
    if (g_dl)
        dlclose(g_dl);

    printf("\n── RESULT ───────────────────────────────────────────────\n");
    printf("  conformance : %d passed, %d failed, %d not testable\n",
           g_conf_pass, g_conf_fail, g_conf_skip);
    printf("  divergence  : %d strict, %d permissive\n",
           g_strict, g_permissive);
    if (g_conf_fail == 0 && g_conf_skip == 0)
        printf("\n  This token meets the KSP's Tier 1 requirements.\n");
    else if (g_conf_fail == 0)
        printf("\n  No failures, but %d check(s) could not be run — an\n"
               "  untested requirement is not a satisfied one.\n",
               g_conf_skip);
    else
        printf("\n  %d requirement(s) unmet. See "
               "docs/12-pkcs11-requirements.md.\n", g_conf_fail);
    if (g_permissive)
        printf("  %d permissive behaviour(s): defects in those areas will\n"
               "  not show up against this token.\n", g_permissive);
    printf("\n");

    return g_conf_fail ? 1 : 0;
}
