/* p11_init_token.c — initialise a token on a real PKCS#11 module.
 *
 * Stands up the token the real-backend harness then runs against:
 * C_InitToken with an SO PIN, then C_InitPIN for the user PIN. Written in
 * C rather than run through pkcs11-tool so CI needs no extra package, and
 * so the setup uses the same Cryptoki calls as everything else here.
 *
 *   p11_init_token <module.so> <label> <so-pin> <user-pin>
 *
 * Deliberately separate from the harness: this runs C_Initialize itself,
 * and the harness must be able to start from a process that has never
 * touched the module, which is the state a real application is in.
 */
/* windows_compat.h supplies the CK_PTR / CK_DECLARE_FUNCTION_POINTER
 * macros that pkcs11.h only defines for _WIN32. Including it here keeps
 * this tool using the same Cryptoki declarations as everything else. */
#include "../mock/windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef CK_RV (*GetFnList)(CK_FUNCTION_LIST **);

static int fail(const char *what, CK_RV rv)
{
    fprintf(stderr, "p11_init_token: %s failed: 0x%08lX\n",
            what, (unsigned long)rv);
    return 1;
}

int main(int argc, char **argv)
{
    void             *h;
    GetFnList         getList;
    CK_FUNCTION_LIST *fn = NULL;
    CK_RV             rv;
    CK_SLOT_ID        slots[16];
    CK_ULONG          nSlots = 16;
    CK_SESSION_HANDLE hSession = 0;
    CK_UTF8CHAR       label[32];

    if (argc != 5) {
        fprintf(stderr,
                "usage: %s <module.so> <label> <so-pin> <user-pin>\n", argv[0]);
        return 2;
    }

    h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }

    getList = (GetFnList)dlsym(h, "C_GetFunctionList");
    if (!getList) { fprintf(stderr, "no C_GetFunctionList\n"); return 1; }

    rv = getList(&fn);
    if (rv != CKR_OK || !fn) return fail("C_GetFunctionList", rv);

    rv = fn->C_Initialize(NULL);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
        return fail("C_Initialize", rv);

    /* tokenPresent = FALSE: an uninitialised slot has no token yet, which
     * is exactly the state this program exists to change. */
    rv = fn->C_GetSlotList(CK_FALSE, slots, &nSlots);
    if (rv != CKR_OK) return fail("C_GetSlotList", rv);
    if (nSlots == 0) { fprintf(stderr, "no slots\n"); return 1; }

    /* CK_TOKEN_INFO.label is 32 bytes padded with spaces, not NUL. */
    memset(label, ' ', sizeof(label));
    {
        size_t n = strlen(argv[2]);
        if (n > sizeof(label)) n = sizeof(label);
        memcpy(label, argv[2], n);
    }

    rv = fn->C_InitToken(slots[0], (CK_UTF8CHAR_PTR)argv[3],
                         (CK_ULONG)strlen(argv[3]), label);
    if (rv != CKR_OK) return fail("C_InitToken", rv);

    rv = fn->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                           NULL, NULL, &hSession);
    if (rv != CKR_OK) return fail("C_OpenSession", rv);

    rv = fn->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR)argv[3],
                     (CK_ULONG)strlen(argv[3]));
    if (rv != CKR_OK) return fail("C_Login(SO)", rv);

    rv = fn->C_InitPIN(hSession, (CK_UTF8CHAR_PTR)argv[4],
                       (CK_ULONG)strlen(argv[4]));
    if (rv != CKR_OK) return fail("C_InitPIN", rv);

    fn->C_Logout(hSession);
    fn->C_CloseSession(hSession);
    fn->C_Finalize(NULL);

    printf("token '%s' initialised in slot %lu\n",
           argv[2], (unsigned long)slots[0]);
    return 0;
}
