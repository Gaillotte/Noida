/* test_rsa_lengths.c — NCRYPT_LENGTHS_PROPERTY under a moved RSA floor.
 *
 * The provider reports a default RSA size through NCRYPT_LENGTHS_PROPERTY,
 * and clamps it into [KSP_RSA_MIN_BITS, KSP_RSA_MAX_BITS]. In the DEFAULT
 * build that clamp does nothing: the floor and the default are both 2048,
 * so deleting it changes no assertion anywhere. It only does work when a
 * build moves the floor, and both directions matter.
 *
 * LOWERED (-DKSP_RSA_MIN_BITS=1024) is the security-relevant one. A legacy
 * build lowers the floor so an old key can still be opened. It must NOT
 * thereby make 1024 the size a CA setup wizard preselects — the escape
 * hatch is for reading old keys, not for minting weak new ones. That is the
 * whole reason KSP_RSA_DEFAULT_BITS is a separate constant from
 * KSP_RSA_MIN_BITS rather than the same one reused.
 *
 * RAISED (-DKSP_RSA_MIN_BITS=4096) is the correctness one. A policy that
 * demands 4096 must not have the wizard preselect 2048 and then be refused
 * at FinalizeKey, which is a confusing failure at exactly the wrong moment.
 *
 * A small dedicated binary rather than recompiling test_ksp_key_props:
 * that suite hardcodes 2048, 2112 and 3072 as valid RSA sizes, which a
 * raised floor correctly rejects, so reusing it would mean six assertions
 * special-cased for a configuration they were never about.
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/common/config.h"
#include "test_framework.h"
#include <string.h>
#include <wchar.h>

/* The same stand-ins test_ksp_key_props.c uses: this suite links
 * ksp_properties.c and ksp_provider.c without the context, session or
 * logging layers. */
typedef struct { void *hModule; CK_FUNCTION_LIST_PTR pFunctionList;
                 CK_SLOT_ID slotId; BOOL bInitialized; } P11_CONTEXT;
static P11_CONTEXT g_testCtx;
P11_CONTEXT *P11_GetContext(void) { return &g_testCtx; }
SECURITY_STATUS P11_Initialize(void)             { return ERROR_SUCCESS; }
SECURITY_STATUS P11_SessionPool_Initialize(void) { return ERROR_SUCCESS; }
void Log_Debug(const char *f, ...) { (void)f; }
void Log_Error(const char *f, ...) { (void)f; }
void Log_Initialize(void) {}

void *KSP_AllocZero(SIZE_T n);
void  KSP_Free(void *p);

#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_provider.h"
#include "../../src/ksp/ksp_properties.h" 

int main(void)
{
    NCRYPT_PROV_HANDLE       hProv = 0;
    NCRYPT_KEY_HANDLE        hKey;
    KSP_KEY                 *pKey;
    NCRYPT_SUPPORTED_LENGTHS lens;
    DWORD                    cb = 0;

    P11Mock_Reset();
    ASSERT_OK("OpenProvider", KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0));

    pKey = (KSP_KEY *)KSP_AllocZero(sizeof(KSP_KEY));
    pKey->dwMagic     = KSP_KEY_MAGIC;
    pKey->dwKeyBitLen = 2048;
    pKey->dwKeySpec   = AT_SIGNATURE;
    wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, ALG_RSA);
    hKey = (NCRYPT_KEY_HANDLE)(ULONG_PTR)pKey;

    /* The floor is a macro, so stringify it for the suite title: the three
     * binaries are otherwise indistinguishable in the run output. */
#define STR_(x) #x
#define STR(x)  STR_(x)
    TEST_SUITE("RSA lengths, floor = " STR(KSP_RSA_MIN_BITS) " bits");

    memset(&lens, 0xAA, sizeof(lens));
    ASSERT_OK("Read NCRYPT_LENGTHS_PROPERTY",
        KSP_GetKeyProperty(hProv, hKey, NCRYPT_LENGTHS_PROPERTY,
                           (PBYTE)&lens, sizeof(lens), &cb, 0));

    ASSERT_EQ("minimum is this build's floor",
              lens.dwMinLength, (DWORD)KSP_RSA_MIN_BITS);
    ASSERT_EQ("maximum is unchanged by the floor",
              lens.dwMaxLength, (DWORD)KSP_RSA_MAX_BITS);

    /* The security invariant, stated with a LITERAL and outside every #if.
     *
     * The first version of this test put the real assertion inside
     * "#if KSP_RSA_MIN_BITS < KSP_RSA_DEFAULT_BITS". Injecting the defect
     * it guards — defining the default as the floor — made the two equal,
     * which compiled the assertion OUT. The suite went from 8 assertions to
     * 7 and reported no failure: the test did not fail, it ceased to exist.
     * A conditional assertion can be deleted by the very change it is meant
     * to catch, which is the vacuous-test failure this project keeps
     * finding.
     *
     * 2048 is written out rather than referenced as KSP_RSA_DEFAULT_BITS,
     * because the point is that no build configuration may preselect
     * anything weaker, and a macro could be redefined to make this pass. */
    ASSERT("no build preselects an RSA size below 2048 bits",
           lens.dwDefaultLength >= 2048);

    ASSERT("the reported default is never below the floor",
           lens.dwDefaultLength >= lens.dwMinLength);
    ASSERT("and never above the ceiling",
           lens.dwDefaultLength <= lens.dwMaxLength);

#if KSP_RSA_MIN_BITS < KSP_RSA_DEFAULT_BITS
    /* Lowered floor: the legacy escape hatch must not drag the default
     * down with it. This is the assertion that stops a legacy build from
     * quietly offering 1024-bit CA keys. */
    ASSERT_EQ("a lowered floor does NOT lower the default",
              lens.dwDefaultLength, (DWORD)KSP_RSA_DEFAULT_BITS);
    ASSERT("and the default is strictly above the lowered floor",
           lens.dwDefaultLength > lens.dwMinLength);
#elif KSP_RSA_MIN_BITS > KSP_RSA_DEFAULT_BITS
    /* Raised floor: the default comes up to meet it. */
    ASSERT_EQ("a raised floor raises the default to match",
              lens.dwDefaultLength, (DWORD)KSP_RSA_MIN_BITS);
#else
    ASSERT_EQ("default build: the default is the compiled default",
              lens.dwDefaultLength, (DWORD)KSP_RSA_DEFAULT_BITS);
#endif

    KSP_Free(pKey);
    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
