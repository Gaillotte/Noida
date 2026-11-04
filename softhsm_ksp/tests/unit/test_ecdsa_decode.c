/* test_ecdsa_decode.c — Full coverage of P11_DecodeDerEcdsaSignature()
 * Tests all paths: normal P-256/P-384 cases, DER padding, errors.
 */
#include "../mock/windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/common/config.h"
#include "test_framework.h"
#include <string.h>

SECURITY_STATUS P11_DecodeDerEcdsaSignature(
    LPCWSTR pszAlgId, BYTE *pbDer, DWORD cbDer,
    BYTE *pbOut, DWORD *pcbOut);

DWORD P11_EcCoordSize(LPCWSTR pszAlgId);

/* ── Helpers pour construire des signatures DER ──────────────────────────── */

/* Build SEQUENCE { INTEGER r, INTEGER s } with zero-padding if needed */
static DWORD build_der(
    const BYTE *r, DWORD cbR, int r_pad,  /* r_pad=1 prepends 0x00 */
    const BYTE *s, DWORD cbS, int s_pad,
    BYTE *out, DWORD cbOut)
{
    DWORD cbRtotal = cbR + (r_pad ? 1 : 0);
    DWORD cbStotal = cbS + (s_pad ? 1 : 0);
    DWORD cbInner  = 2 + cbRtotal + 2 + cbStotal;
    DWORD cbTotal  = 2 + cbInner;

    if (cbTotal > cbOut) return 0;

    BYTE *p = out;
    *p++ = 0x30;          /* SEQUENCE */
    *p++ = (BYTE)cbInner;
    *p++ = 0x02;          /* INTEGER r */
    *p++ = (BYTE)cbRtotal;
    if (r_pad) *p++ = 0x00;
    memcpy(p, r, cbR); p += cbR;
    *p++ = 0x02;          /* INTEGER s */
    *p++ = (BYTE)cbStotal;
    if (s_pad) *p++ = 0x00;
    memcpy(p, s, cbS);

    return cbTotal;
}

int main(void)
{
    /* P-256 test values (32 bytes) */
    BYTE r32[32], s32[32];
    BYTE r31[31], s31[31]; /* shorter r/s (significant leading zero) */
    BYTE derBuf[128];
    BYTE outBuf[96];
    DWORD cbDer, cbOut;
    SECURITY_STATUS ss;
    int i;

    for (i = 0; i < 32; i++) { r32[i] = (BYTE)(0xAA + i); s32[i] = (BYTE)(0x55 - i); }
    for (i = 0; i < 31; i++) { r31[i] = (BYTE)(0x11 + i); s31[i] = (BYTE)(0xFF - i); }

    /* ── Suite 1 : P11_EcCoordSize ─────────────────────────────────────── */
    TEST_SUITE("P11_EcCoordSize");

    ASSERT_EQ("P-256 → 32",  P11_EcCoordSize(L"ECDSA_P256"), 32U);
    ASSERT_EQ("P-384 → 48",  P11_EcCoordSize(L"ECDSA_P384"), 48U);
    ASSERT_EQ("P-521 → 66",  P11_EcCoordSize(L"ECDSA_P521"), 66U);
    ASSERT_EQ("ECDH P-256 → 32", P11_EcCoordSize(L"ECDH_P256"), 32U);
    ASSERT_EQ("ECDH P-384 → 48", P11_EcCoordSize(L"ECDH_P384"), 48U);
    ASSERT_EQ("ECDH P-521 → 66", P11_EcCoordSize(L"ECDH_P521"), 66U);
    ASSERT_EQ("RSA → 0",     P11_EcCoordSize(L"RSA"),        0U);
    ASSERT_EQ("Empty → 0",   P11_EcCoordSize(L""),           0U);
    ASSERT_EQ("NULL → 0",    P11_EcCoordSize(NULL),          0U);
    ASSERT_EQ("EdDSA → 0 (not a NIST curve)",
              P11_EcCoordSize(L"EDDSA_ED25519"),            0U);

    /* ── Suite 2 : Cas nominaux P-256 ───────────────────────────────────── */
    TEST_SUITE("P11_DecodeDerEcdsaSignature — P-256 nominal cases");

    /* r=32 bytes no padding, s=32 bytes no padding */
    cbDer = build_der(r32, 32, 0, s32, 32, 0, derBuf, sizeof derBuf);
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_OK("r=32 s=32 no padding → OK", ss);
    ASSERT_EQ("cbOut = 64", cbOut, 64U);
    ASSERT_MEM("r correct in pbOut[0..31]", outBuf, r32, 32);
    ASSERT_MEM("s correct in pbOut[32..63]", outBuf + 32, s32, 32);

    /* r=32 with leading 0x00 (DER sign byte) */
    cbDer = build_der(r32, 32, 1, s32, 32, 0, derBuf, sizeof derBuf);
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_OK("r with DER 0x00 → OK", ss);
    ASSERT_MEM("r without the 0x00 in pbOut", outBuf, r32, 32);

    /* s=32 with leading 0x00 */
    cbDer = build_der(r32, 32, 0, s32, 32, 1, derBuf, sizeof derBuf);
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_OK("s with 0x00 DER → OK", ss);

    /* r=31 bytes (value < 2^248), must be left-zero-padded */
    cbDer = build_der(r31, 31, 0, s32, 32, 0, derBuf, sizeof derBuf);
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_OK("r=31 bytes zero-padded → OK", ss);
    ASSERT_EQ("pbOut[0] = 0x00 (padding)", outBuf[0], 0x00);
    ASSERT_MEM("r[1..31] correct", outBuf + 1, r31, 31);

    /* s=31 bytes */
    cbDer = build_der(r32, 32, 0, s31, 31, 0, derBuf, sizeof derBuf);
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_OK("s=31 bytes zero-padded → OK", ss);
    ASSERT_EQ("pbOut[32] = 0x00 (padding)", outBuf[32], 0x00);

    /* r and s both 31 bytes */
    cbDer = build_der(r31, 31, 0, s31, 31, 0, derBuf, sizeof derBuf);
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_OK("r=31 s=31 → OK", ss);

    /* ── Suite 3 : Mode taille seule (pbOut == NULL) ────────────────────── */
    TEST_SUITE("P11_DecodeDerEcdsaSignature — size-only mode");

    cbDer = build_der(r32, 32, 0, s32, 32, 0, derBuf, sizeof derBuf);
    cbOut = 0;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, NULL, &cbOut);
    ASSERT_OK("pbOut=NULL → ERROR_SUCCESS", ss);
    ASSERT_EQ("cbOut = 64 (P-256)", cbOut, 64U);

    cbOut = 0;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P384", derBuf, cbDer, NULL, &cbOut);
    ASSERT_OK("pbOut=NULL P-384 → ERROR_SUCCESS", ss);
    ASSERT_EQ("cbOut = 96 (P-384)", cbOut, 96U);

    /* ── Suite 4 : P-384 cas nominaux ──────────────────────────────────── */
    TEST_SUITE("P11_DecodeDerEcdsaSignature — P-384 cases");

    BYTE r48[48], s48[48];
    BYTE outBuf96[96];
    for (i = 0; i < 48; i++) { r48[i] = (BYTE)(0xAA + i); s48[i] = (BYTE)(0x55 + i); }

    cbDer = build_der(r48, 48, 1, s48, 48, 1, derBuf, sizeof derBuf);
    cbOut = 96;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P384", derBuf, cbDer, outBuf96, &cbOut);
    ASSERT_OK("P-384 r=48 s=48 → OK", ss);
    ASSERT_EQ("cbOut = 96", cbOut, 96U);
    ASSERT_MEM("r P-384 correct", outBuf96, r48, 48);
    ASSERT_MEM("s P-384 correct", outBuf96 + 48, s48, 48);

    /* ── Suite 5 : Cas d'erreur ─────────────────────────────────────────── */
    TEST_SUITE("P11_DecodeDerEcdsaSignature — error cases");

    /* Unknown algorithm. P-521 used to stand in here, but it is supported
     * now and only failed because cbOut was too small — a pass for the wrong
     * reason. Use a curve the KSP genuinely does not know. */
    cbDer = build_der(r32, 32, 0, s32, 32, 0, derBuf, sizeof derBuf);
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P192", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_EQ("Unknown curve → NTE_BAD_ALGID",
        ss, (SECURITY_STATUS)NTE_BAD_ALGID);

    /* P-521 is supported: it needs 132 bytes, so a 64-byte buffer is a
     * size error rather than an algorithm error. */
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P521", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_EQ("P-521 into a 64-byte buffer → NTE_BUFFER_TOO_SMALL",
        ss, (SECURITY_STATUS)NTE_BUFFER_TOO_SMALL);

    /* Invalid SEQUENCE tag */
    derBuf[0] = 0x31; /* Wrong tag */
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, 6, outBuf, &cbOut);
    ASSERT_ERR("Invalid SEQUENCE tag → error", ss);
    derBuf[0] = 0x30; /* Restore */

    /* Output buffer too small */
    cbDer = build_der(r32, 32, 0, s32, 32, 0, derBuf, sizeof derBuf);
    cbOut = 32; /* Too small (needs 64) */
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_EQ("Output buffer too small → NTE_BUFFER_TOO_SMALL",
        ss, (SECURITY_STATUS)NTE_BUFFER_TOO_SMALL);

    /* r too large (> cbCoord): build DER with 33 significant bytes for r */
    {
        BYTE bigR[33];
        memset(bigR, 0xCC, 33);
        bigR[0] = 0x01; /* Pas de byte de signe */
        DWORD cbBigDer = build_der(bigR, 33, 0, s32, 32, 0, derBuf, sizeof derBuf);
        cbOut = 64;
        ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbBigDer, outBuf, &cbOut);
        ASSERT_ERR("r too large → error", ss);
    }

    /* Invalid INTEGER r tag */
    {
        cbDer = build_der(r32, 32, 0, s32, 32, 0, derBuf, sizeof derBuf);
        /* Find the first 0x02 (INTEGER r tag) and corrupt it */
        DWORD seqLenBytes = (derBuf[1] & 0x80) ? (derBuf[1] & 0x7F) + 1 : 1;
        derBuf[2 + seqLenBytes] = 0x03; /* Wrong tag */
        cbOut = 64;
        ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
        ASSERT_ERR("Invalid INTEGER r tag → error", ss);
    }

    /* ── Suite 6 : Idempotence / robustesse ─────────────────────────────── */
    TEST_SUITE("P11_DecodeDerEcdsaSignature — idempotence");

    /* Same call twice → same result */
    BYTE outBuf2[64];
    cbDer = build_der(r32, 32, 0, s32, 32, 0, derBuf, sizeof derBuf);

    memset(outBuf, 0, 64); cbOut = 64;
    P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    memset(outBuf2, 0, 64); cbOut = 64;
    P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf2, &cbOut);
    ASSERT_MEM("Two identical calls produce the same result", outBuf, outBuf2, 64);


    /* ── secp256k1 (gap ECDSA-05) ───────────────────────────────────────── */
    TEST_SUITE("P11_EcCoordSize — secp256k1");

    ASSERT_EQ("secp256k1 -> 32", P11_EcCoordSize(L"ECDSA_SECP256K1"), 32U);
    ASSERT_EQ("secp256k1 signature is 64 bytes (2 x 32)",
              P11_EcCoordSize(L"ECDSA_SECP256K1") * 2, 64U);

    /* secp256k1, P-384 and P-521 OIDs are all 7 bytes: only the final byte
     * separates them, so a length-based lookup would confuse the three. */
    ASSERT_EQ("secp256k1 OID length equals P-384's",
              (unsigned)EC_OID_SECP256K1_LEN, (unsigned)EC_OID_P384_LEN);
    ASSERT("secp256k1 OID differs from P-384 in its bytes",
           memcmp(EC_OID_SECP256K1, EC_OID_P384, EC_OID_P384_LEN) != 0);
    ASSERT("secp256k1 OID differs from P-521 in its bytes",
           memcmp(EC_OID_SECP256K1, EC_OID_P521, EC_OID_P521_LEN) != 0);
    ASSERT_EQ("secp256k1 OID final byte is 0x0A",
              (unsigned char)EC_OID_SECP256K1[EC_OID_SECP256K1_LEN - 1],
              (unsigned char)0x0A);

    /* Truncated DER: the length bytes must be validated against the buffer
     * that is actually present, or the decoder reads past its end. */
    {
        BYTE trunc[8];
        trunc[0] = 0x30; trunc[1] = 0x44;   /* SEQUENCE, claims 68 bytes */
        trunc[2] = 0x02; trunc[3] = 0x20;   /* INTEGER r, claims 32 bytes */
        trunc[4] = 0x11; trunc[5] = 0x22; trunc[6] = 0x33; trunc[7] = 0x44;
        cbOut = sizeof outBuf;
        ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", trunc, sizeof trunc,
                                         outBuf, &cbOut);
        ASSERT_EQ("Truncated INTEGER r → NTE_INVALID_PARAMETER",
            ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);
    }
    {
        /* r complete, s truncated */
        BYTE trunc[40];
        memset(trunc, 0, sizeof trunc);
        trunc[0] = 0x30; trunc[1] = 0x26;
        trunc[2] = 0x02; trunc[3] = 0x20;   /* r: 32 bytes, all present */
        trunc[36] = 0x02; trunc[37] = 0x20; /* s: claims 32, only 2 follow */
        cbOut = sizeof outBuf;
        ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", trunc, sizeof trunc,
                                         outBuf, &cbOut);
        ASSERT_EQ("Truncated INTEGER s → NTE_INVALID_PARAMETER",
            ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);
    }
    {
        /* Long-form SEQUENCE length claiming more bytes than exist */
        BYTE trunc[5];
        trunc[0] = 0x30; trunc[1] = 0x84;   /* long form, 4 length bytes */
        trunc[2] = 0x00; trunc[3] = 0x00; trunc[4] = 0x00;
        cbOut = sizeof outBuf;
        ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", trunc, sizeof trunc,
                                         outBuf, &cbOut);
        ASSERT_EQ("Truncated long-form length → NTE_INVALID_PARAMETER",
            ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);
    }

    TEST_REPORT();
    TEST_EXIT();
}
