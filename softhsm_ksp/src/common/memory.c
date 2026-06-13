/* memory.c — Implémentation des helpers mémoire */
#include "memory.h"
#include <string.h>

/* Alloue un buffer sur le heap du processus */
void *KSP_Alloc(SIZE_T cbSize)
{
    return HeapAlloc(GetProcessHeap(), 0, cbSize);
}

/* Alloue et initialise à zéro */
void *KSP_AllocZero(SIZE_T cbSize)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize);
}

/* Libère un buffer alloué par KSP_Alloc */
void KSP_Free(void *pv)
{
    if (pv)
        HeapFree(GetProcessHeap(), 0, pv);
}

/* Duplique une chaîne wide sur le heap du processus */
LPWSTR KSP_WStrDup(LPCWSTR pwsz)
{
    SIZE_T cbLen;
    LPWSTR pwszCopy;

    if (!pwsz)
        return NULL;

    cbLen    = (wcslen(pwsz) + 1) * sizeof(WCHAR);
    pwszCopy = (LPWSTR)KSP_Alloc(cbLen);
    if (pwszCopy)
        memcpy(pwszCopy, pwsz, cbLen);

    return pwszCopy;
}
