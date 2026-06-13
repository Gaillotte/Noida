/* test_ecdsa_decode.c — Couverture complète de P11_DecodeDerEcdsaSignature()
 * Teste tous les chemins : cas normaux P-256/P-384, padding DER, erreurs.
 */
#include "../mock/windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"
#include "test_framework.h"
#include <string.h>

SECURITY_STATUS P11_DecodeDerEcdsaSignature(
    LPCWSTR pszAlgId, BYTE *pbDer, DWORD cbDer,
    BYTE *pbOut, DWORD *pcbOut);

DWORD P11_EcCoordSize(LPCWSTR pszAlgId);

/* ── Helpers pour construire des signatures DER ──────────────────────────── */

/* Construit SEQUENCE { INTEGER r, INTEGER s } avec zéro-padding si besoin */
static DWORD build_der(
    const BYTE *r, DWORD cbR, int r_pad,  /* r_pad=1 ajoute 0x00 en tête */
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
    /* Valeurs de test P-256 (32 octets) */
    BYTE r32[32], s32[32];
    BYTE r31[31], s31[31]; /* r/s plus courts (leading zero significatif) */
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
    ASSERT_EQ("Inconnu → 0", P11_EcCoordSize(L"ECDSA_P521"), 0U);
    ASSERT_EQ("RSA → 0",     P11_EcCoordSize(L"RSA"),        0U);
    ASSERT_EQ("Vide → 0",    P11_EcCoordSize(L""),           0U);

    /* ── Suite 2 : Cas nominaux P-256 ───────────────────────────────────── */
    TEST_SUITE("P11_DecodeDerEcdsaSignature — P-256 cas nominaux");

    /* r=32 octets sans padding, s=32 octets sans padding */
    cbDer = build_der(r32, 32, 0, s32, 32, 0, derBuf, sizeof derBuf);
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_OK("r=32 s=32 sans padding → OK", ss);
    ASSERT_EQ("cbOut = 64", cbOut, 64U);
    ASSERT_MEM("r correct dans pbOut[0..31]", outBuf, r32, 32);
    ASSERT_MEM("s correct dans pbOut[32..63]", outBuf + 32, s32, 32);

    /* r=32 avec 0x00 en tête (byte de signe DER) */
    cbDer = build_der(r32, 32, 1, s32, 32, 0, derBuf, sizeof derBuf);
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_OK("r avec 0x00 DER → OK", ss);
    ASSERT_MEM("r sans le 0x00 dans pbOut", outBuf, r32, 32);

    /* s=32 avec 0x00 en tête */
    cbDer = build_der(r32, 32, 0, s32, 32, 1, derBuf, sizeof derBuf);
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_OK("s avec 0x00 DER → OK", ss);

    /* r=31 octets (valeur < 2^248), doit être zero-paddé à gauche */
    cbDer = build_der(r31, 31, 0, s32, 32, 0, derBuf, sizeof derBuf);
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_OK("r=31 octets zero-paddé → OK", ss);
    ASSERT_EQ("pbOut[0] = 0x00 (padding)", outBuf[0], 0x00);
    ASSERT_MEM("r[1..31] correct", outBuf + 1, r31, 31);

    /* s=31 octets */
    cbDer = build_der(r32, 32, 0, s31, 31, 0, derBuf, sizeof derBuf);
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_OK("s=31 octets zero-paddé → OK", ss);
    ASSERT_EQ("pbOut[32] = 0x00 (padding)", outBuf[32], 0x00);

    /* r et s tous deux 31 octets */
    cbDer = build_der(r31, 31, 0, s31, 31, 0, derBuf, sizeof derBuf);
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_OK("r=31 s=31 → OK", ss);

    /* ── Suite 3 : Mode taille seule (pbOut == NULL) ────────────────────── */
    TEST_SUITE("P11_DecodeDerEcdsaSignature — mode taille seule");

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
    TEST_SUITE("P11_DecodeDerEcdsaSignature — P-384");

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
    TEST_SUITE("P11_DecodeDerEcdsaSignature — cas d'erreur");

    /* Algorithme inconnu */
    cbDer = build_der(r32, 32, 0, s32, 32, 0, derBuf, sizeof derBuf);
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P521", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_ERR("Algorithme inconnu → erreur", ss);

    /* Tag SEQUENCE invalide */
    derBuf[0] = 0x31; /* Mauvais tag */
    cbOut = 64;
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, 6, outBuf, &cbOut);
    ASSERT_ERR("Tag SEQUENCE invalide → erreur", ss);
    derBuf[0] = 0x30; /* Restaure */

    /* Buffer trop petit pour la sortie */
    cbDer = build_der(r32, 32, 0, s32, 32, 0, derBuf, sizeof derBuf);
    cbOut = 32; /* Trop petit (besoin de 64) */
    ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    ASSERT_EQ("Buffer sortie trop petit → NTE_BUFFER_TOO_SMALL",
        ss, (SECURITY_STATUS)NTE_BUFFER_TOO_SMALL);

    /* r trop grand (> cbCoord) : construit un DER avec r de 33 octets significatifs */
    {
        BYTE bigR[33];
        memset(bigR, 0xCC, 33);
        bigR[0] = 0x01; /* Pas de byte de signe */
        DWORD cbBigDer = build_der(bigR, 33, 0, s32, 32, 0, derBuf, sizeof derBuf);
        cbOut = 64;
        ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbBigDer, outBuf, &cbOut);
        ASSERT_ERR("r trop grand → erreur", ss);
    }

    /* Tag INTEGER r invalide */
    {
        cbDer = build_der(r32, 32, 0, s32, 32, 0, derBuf, sizeof derBuf);
        /* Cherche le premier 0x02 (tag INTEGER r) et le corrompt */
        DWORD seqLenBytes = (derBuf[1] & 0x80) ? (derBuf[1] & 0x7F) + 1 : 1;
        derBuf[2 + seqLenBytes] = 0x03; /* Mauvais tag */
        cbOut = 64;
        ss = P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
        ASSERT_ERR("Tag INTEGER r invalide → erreur", ss);
    }

    /* ── Suite 6 : Idempotence / robustesse ─────────────────────────────── */
    TEST_SUITE("P11_DecodeDerEcdsaSignature — idempotence");

    /* Même appel deux fois → même résultat */
    BYTE outBuf2[64];
    cbDer = build_der(r32, 32, 0, s32, 32, 0, derBuf, sizeof derBuf);

    memset(outBuf, 0, 64); cbOut = 64;
    P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf, &cbOut);
    memset(outBuf2, 0, 64); cbOut = 64;
    P11_DecodeDerEcdsaSignature(L"ECDSA_P256", derBuf, cbDer, outBuf2, &cbOut);
    ASSERT_MEM("Deux appels identiques donnent le même résultat", outBuf, outBuf2, 64);

    TEST_REPORT();
    TEST_EXIT();
}
