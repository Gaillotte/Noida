/* test_memory.c — Full coverage of KSP memory functions
 * KSP_Alloc, KSP_AllocZero, KSP_Free, KSP_WStrDup
 */
#include "../mock/windows_compat.h"
#include "test_framework.h"
#include <string.h>
#include <wchar.h>

/* Directly includes the tested functions */
void *KSP_Alloc(SIZE_T cbSize);
void *KSP_AllocZero(SIZE_T cbSize);
void  KSP_Free(void *pv);
LPWSTR KSP_WStrDup(LPCWSTR pwsz);

int main(void)
{
    /* ── Suite 1 : KSP_Alloc ─────────────────────────────────────────────── */
    TEST_SUITE("KSP_Alloc");

    void *p1 = KSP_Alloc(128);
    ASSERT_NOTNULL("Alloc 128 bytes → non-NULL", p1);
    KSP_Free(p1);

    void *p2 = KSP_Alloc(1);
    ASSERT_NOTNULL("Alloc 1 byte → non-NULL", p2);
    KSP_Free(p2);

    void *p3 = KSP_Alloc(1024 * 1024);
    ASSERT_NOTNULL("Alloc 1 MB → non-NULL", p3);
    KSP_Free(p3);

    /* Verify that two allocations return distinct pointers */
    void *pa = KSP_Alloc(64);
    void *pb = KSP_Alloc(64);
    ASSERT("Two allocations → distinct pointers", pa != pb);
    KSP_Free(pa);
    KSP_Free(pb);

    /* ── Suite 2 : KSP_AllocZero ────────────────────────────────────────── */
    TEST_SUITE("KSP_AllocZero");

    void *pz = KSP_AllocZero(256);
    ASSERT_NOTNULL("AllocZero 256 → non-NULL", pz);

    /* Verify that all bytes are zero */
    int allZero = 1;
    BYTE *pb2 = (BYTE *)pz;
    for (int i = 0; i < 256; i++) if (pb2[i] != 0) { allZero = 0; break; }
    ASSERT("AllocZero → all bytes are 0", allZero);
    KSP_Free(pz);

    /* AllocZero of 1 byte */
    BYTE *pz1 = (BYTE *)KSP_AllocZero(1);
    ASSERT_NOTNULL("AllocZero 1 byte", pz1);
    ASSERT_EQ("AllocZero 1 byte = 0", *pz1, 0);
    KSP_Free(pz1);

    /* ── Suite 3 : KSP_Free ──────────────────────────────────────────────── */
    TEST_SUITE("KSP_Free");

    KSP_Free(NULL);  /* Must not crash */
    ASSERT("KSP_Free(NULL) does not crash", 1);

    void *pf = KSP_Alloc(32);
    ASSERT_NOTNULL("Alloc before Free", pf);
    KSP_Free(pf);
    ASSERT("KSP_Free after valid alloc does not crash", 1);

    /* ── Suite 4 : KSP_WStrDup ───────────────────────────────────────────── */
    TEST_SUITE("KSP_WStrDup");

    LPWSTR dup1 = KSP_WStrDup(L"SoftHSM KSP");
    ASSERT_NOTNULL("WStrDup non-NULL", dup1);
    ASSERT("WStrDup correct content", wcscmp(dup1, L"SoftHSM KSP") == 0);
    ASSERT("WStrDup → independent copy",
           dup1 != (void*)L"SoftHSM KSP"); /* not an alias */
    KSP_Free(dup1);

    LPWSTR dup2 = KSP_WStrDup(L"");
    ASSERT_NOTNULL("WStrDup empty string → non-NULL", dup2);
    ASSERT("WStrDup empty → L\"\"", wcscmp(dup2, L"") == 0);
    KSP_Free(dup2);

    LPWSTR dup3 = KSP_WStrDup(NULL);
    ASSERT_NULL("WStrDup(NULL) → NULL", dup3);

    /* Long string */
    WCHAR longStr[512];
    for (int i = 0; i < 511; i++) longStr[i] = L'X';
    longStr[511] = L'\0';
    LPWSTR dupLong = KSP_WStrDup(longStr);
    ASSERT_NOTNULL("WStrDup long string → non-NULL", dupLong);
    ASSERT_EQ("WStrDup long string → correct length",
        wcslen(dupLong), 511U);
    KSP_Free(dupLong);

    /* Uniqueness: two dups of the same string → different addresses */
    LPWSTR d1 = KSP_WStrDup(L"Test");
    LPWSTR d2 = KSP_WStrDup(L"Test");
    ASSERT("Two WStrDup → distinct pointers", d1 != d2);
    ASSERT("Two WStrDup → identical content", wcscmp(d1, d2) == 0);
    KSP_Free(d1);
    KSP_Free(d2);

    TEST_REPORT();
    TEST_EXIT();
}
