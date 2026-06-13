/* memory.h — Allocateur compatible avec FreeBuffer CNG
 * Tous les buffers retournés au runtime CNG doivent être alloués
 * sur GetProcessHeap() et libérés via HeapFree.
 */
#ifndef MEMORY_H
#define MEMORY_H

#include <windows.h>

/* Alloue un buffer sur le heap du processus (compatible CNG FreeBuffer) */
void *KSP_Alloc(SIZE_T cbSize);

/* Alloue et initialise à zéro */
void *KSP_AllocZero(SIZE_T cbSize);

/* Libère un buffer alloué par KSP_Alloc */
void KSP_Free(void *pv);

/* Duplique une chaîne wide sur le heap du processus */
LPWSTR KSP_WStrDup(LPCWSTR pwsz);

#endif /* MEMORY_H */
