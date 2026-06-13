/* test_framework.h — Minimal test framework shared by all unit tests */
#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Global counters */
static int _tf_pass = 0;
static int _tf_fail = 0;
static const char *_tf_current_suite = "?";

/* Start a test suite */
#define TEST_SUITE(name) \
    do { _tf_current_suite = (name); \
         printf("\n╔══ %s ══\n", name); } while(0)

/* Base assertion */
#define ASSERT(desc, expr) \
    do { \
        if (expr) { \
            printf("  [PASS] %s\n", desc); \
            _tf_pass++; \
        } else { \
            printf("  [FAIL] %s  (%s:%d)\n", desc, __FILE__, __LINE__); \
            _tf_fail++; \
        } \
    } while(0)

#define ASSERT_EQ(desc, a, b)      ASSERT(desc, (a) == (b))
#define ASSERT_NEQ(desc, a, b)     ASSERT(desc, (a) != (b))
#define ASSERT_NULL(desc, p)       ASSERT(desc, (p) == NULL)
#define ASSERT_NOTNULL(desc, p)    ASSERT(desc, (p) != NULL)
#define ASSERT_OK(desc, ss)        ASSERT(desc, (ss) == 0)
#define ASSERT_ERR(desc, ss)       ASSERT(desc, (ss) != 0)
#define ASSERT_STR(desc, a, b)     ASSERT(desc, strcmp(a, b) == 0)
#define ASSERT_WSTR(desc, a, b)    ASSERT(desc, wcscmp(a, b) == 0)
#define ASSERT_MEM(desc, a, b, n)  ASSERT(desc, memcmp(a, b, n) == 0)

/* Final summary */
#define TEST_REPORT() \
    do { \
        printf("\n══════════════════════════════════════════\n"); \
        printf("  TOTAL : %d tests  PASS: %d  FAIL: %d\n", \
               _tf_pass + _tf_fail, _tf_pass, _tf_fail); \
        printf("══════════════════════════════════════════\n"); \
    } while(0)

#define TEST_EXIT() return (_tf_fail == 0) ? 0 : 1

#endif /* TEST_FRAMEWORK_H */
