/* memory.h — CNG FreeBuffer-compatible allocator
 * All buffers returned to the CNG runtime must be allocated
 * on GetProcessHeap() and freed via HeapFree.
 */
#ifndef MEMORY_H
#define MEMORY_H

#include <windows.h>

/* Allocate a buffer on the process heap (compatible with CNG FreeBuffer) */
void *KSP_Alloc(SIZE_T cbSize);

/* Allocate and zero-initialise */
void *KSP_AllocZero(SIZE_T cbSize);

/* Free a buffer allocated by KSP_Alloc */
void KSP_Free(void *pv);

/* Duplicate a wide string on the process heap */
LPWSTR KSP_WStrDup(LPCWSTR pwsz);

#endif /* MEMORY_H */
