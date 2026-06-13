/* memory.c — Memory helper implementation */
#include "memory.h"
#include <string.h>

/* Allocate a buffer on the process heap */
void *KSP_Alloc(SIZE_T cbSize)
{
    return HeapAlloc(GetProcessHeap(), 0, cbSize);
}

/* Allocate and zero-initialise */
void *KSP_AllocZero(SIZE_T cbSize)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize);
}

/* Free a buffer allocated by KSP_Alloc */
void KSP_Free(void *pv)
{
    if (pv)
        HeapFree(GetProcessHeap(), 0, pv);
}

/* Duplicate a wide string on the process heap */
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
