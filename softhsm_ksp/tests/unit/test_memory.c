/* test_memory.c — Couverture complète des fonctions mémoire KSP
 * KSP_Alloc, KSP_AllocZero, KSP_Free, KSP_WStrDup
 */
#include "../mock/windows_compat.h"
#include "test_framework.h"
#include <string.h>
#include <wchar.h>

/* Inclut directement les fonctions testées */
void *KSP_Alloc(SIZE_T cbSize);
void *KSP_AllocZero(SIZE_T cbSize);
void  KSP_Free(void *pv);
LPWSTR KSP_WStrDup(LPCWSTR pwsz);

int main(void)
{
    /* ── Suite 1 : KSP_Alloc ─────────────────────────────────────────────── */
    TEST_SUITE("KSP_Alloc");

    void *p1 = KSP_Alloc(128);
    ASSERT_NOTNULL("Alloc 128 octets → non NULL", p1);
    KSP_Free(p1);

    void *p2 = KSP_Alloc(1);
    ASSERT_NOTNULL("Alloc 1 octet → non NULL", p2);
    KSP_Free(p2);

    void *p3 = KSP_Alloc(1024 * 1024);
    ASSERT_NOTNULL("Alloc 1 Mo → non NULL", p3);
    KSP_Free(p3);

    /* Vérifie que deux allocations donnent des pointeurs distincts */
    void *pa = KSP_Alloc(64);
    void *pb = KSP_Alloc(64);
    ASSERT("Deux allocations → pointeurs distincts", pa != pb);
    KSP_Free(pa);
    KSP_Free(pb);

    /* ── Suite 2 : KSP_AllocZero ────────────────────────────────────────── */
    TEST_SUITE("KSP_AllocZero");

    void *pz = KSP_AllocZero(256);
    ASSERT_NOTNULL("AllocZero 256 → non NULL", pz);

    /* Vérifie que les octets sont à zéro */
    int allZero = 1;
    BYTE *pb2 = (BYTE *)pz;
    for (int i = 0; i < 256; i++) if (pb2[i] != 0) { allZero = 0; break; }
    ASSERT("AllocZero → tous octets à 0", allZero);
    KSP_Free(pz);

    /* AllocZero de 1 octet */
    BYTE *pz1 = (BYTE *)KSP_AllocZero(1);
    ASSERT_NOTNULL("AllocZero 1 octet", pz1);
    ASSERT_EQ("AllocZero 1 octet = 0", *pz1, 0);
    KSP_Free(pz1);

    /* ── Suite 3 : KSP_Free ──────────────────────────────────────────────── */
    TEST_SUITE("KSP_Free");

    KSP_Free(NULL);  /* Ne doit pas planter */
    ASSERT("KSP_Free(NULL) ne plante pas", 1);

    void *pf = KSP_Alloc(32);
    ASSERT_NOTNULL("Alloc avant Free", pf);
    KSP_Free(pf);
    ASSERT("KSP_Free après alloc valide ne plante pas", 1);

    /* ── Suite 4 : KSP_WStrDup ───────────────────────────────────────────── */
    TEST_SUITE("KSP_WStrDup");

    LPWSTR dup1 = KSP_WStrDup(L"SoftHSM KSP");
    ASSERT_NOTNULL("WStrDup non NULL", dup1);
    ASSERT("WStrDup contenu correct", wcscmp(dup1, L"SoftHSM KSP") == 0);
    ASSERT("WStrDup → copie indépendante",
           dup1 != (void*)L"SoftHSM KSP"); /* Pas alias */
    KSP_Free(dup1);

    LPWSTR dup2 = KSP_WStrDup(L"");
    ASSERT_NOTNULL("WStrDup chaîne vide → non NULL", dup2);
    ASSERT("WStrDup vide → L\"\"", wcscmp(dup2, L"") == 0);
    KSP_Free(dup2);

    LPWSTR dup3 = KSP_WStrDup(NULL);
    ASSERT_NULL("WStrDup(NULL) → NULL", dup3);

    /* Chaîne longue */
    WCHAR longStr[512];
    for (int i = 0; i < 511; i++) longStr[i] = L'X';
    longStr[511] = L'\0';
    LPWSTR dupLong = KSP_WStrDup(longStr);
    ASSERT_NOTNULL("WStrDup longue → non NULL", dupLong);
    ASSERT_EQ("WStrDup longue → longueur correcte",
        wcslen(dupLong), 511U);
    KSP_Free(dupLong);

    /* Unicité : deux dups de la même chaîne → adresses différentes */
    LPWSTR d1 = KSP_WStrDup(L"Test");
    LPWSTR d2 = KSP_WStrDup(L"Test");
    ASSERT("Deux WStrDup → pointeurs distincts", d1 != d2);
    ASSERT("Deux WStrDup → contenu identique", wcscmp(d1, d2) == 0);
    KSP_Free(d1);
    KSP_Free(d2);

    TEST_REPORT();
    TEST_EXIT();
}
