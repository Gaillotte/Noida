/* p11_real_loader.c — load a real PKCS#11 module on Linux.
 *
 * The unit suites link tests/mock/p11_mock.c, whose LoadLibraryW hands back
 * a fake handle and a function list built in C. That is right for unit
 * tests and useless for the question this directory exists to answer:
 * whether the provider works against a PKCS#11 module nobody here wrote.
 *
 * This file provides the same three entry points over dlopen, so the
 * provider's own p11_context.c — unmodified, the same code the DLL uses —
 * reaches a live token. Nothing else about the build changes: the KSP and
 * PKCS#11 layers compile exactly as they do for the unit suites.
 *
 * The provider calls LoadLibraryW with a wide string, because that is what
 * it does on Windows. It is narrowed here rather than in the provider.
 */
#include "../mock/windows_compat.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static void *g_handle = NULL;

HMODULE LoadLibraryW(const wchar_t *path)
{
    char  szPath[1024];
    size_t i = 0;

    if (!path)
        return NULL;

    /* The paths involved are filesystem paths from an environment
     * variable, so a byte-per-character narrowing is enough; anything
     * outside 7-bit ASCII is refused rather than silently mangled. */
    for (i = 0; i + 1 < sizeof(szPath) && path[i]; i++) {
        if (path[i] > 0x7F) {
            fprintf(stderr, "[loader] non-ASCII module path refused\n");
            return NULL;
        }
        szPath[i] = (char)path[i];
    }
    szPath[i] = '\0';

    g_handle = dlopen(szPath, RTLD_NOW | RTLD_LOCAL);
    if (!g_handle) {
        fprintf(stderr, "[loader] dlopen(%s): %s\n", szPath, dlerror());
        return NULL;
    }
    return (HMODULE)g_handle;
}

void *GetProcAddress(HMODULE m, const char *n)
{
    if (!m || !n)
        return NULL;
    return dlsym((void *)m, n);
}

int FreeLibrary(HMODULE m)
{
    if (m && (void *)m == g_handle) {
        dlclose(g_handle);
        g_handle = NULL;
    }
    return 1;
}
