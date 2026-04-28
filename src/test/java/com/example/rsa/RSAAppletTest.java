package com.example.rsa;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import org.junit.Before;
import org.junit.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * APDU-level tests for RSAApplet using JCardSim.
 *
 * Each test builds real CommandAPDU objects and verifies the ResponseAPDU
 * status word (SW) and/or data payload, exactly as a host application would.
 *
 * APDU summary:
 *   SELECT      00 A4 04 00 07 A0 00 00 00 01 01 02
 *   GEN_KEY     80 01 00 00                       → 90 00
 *   SIGN        80 02 00 00 Lc <data [1..200]> Le → <128-byte sig> 90 00
 *   GET_PUB_KEY 80 03 00 00 Le                    → <pubkey TLV> 90 00
 *   VERIFY step 1 (load data)
 *               80 04 00 00 Lc <data [1..200]>    → 90 00
 *   VERIFY step 2 (check signature)
 *               80 04 01 00 80 <sig [128]>        → 90 00 (valid) | 63 00 (invalid)
 */
public class RSAAppletTest {

    // ── Applet AID: A0 00 00 00 01 01 02 ────────────────────────────────────
    private static final byte[] AID_BYTES = {
        (byte) 0xA0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02
    };

    // ── APDU constants ───────────────────────────────────────────────────────
    private static final int  CLA              = 0x80;
    private static final int  INS_GEN_KEY      = 0x01;
    private static final int  INS_SIGN         = 0x02;
    private static final int  INS_GET_PUB_KEY  = 0x03;
    private static final int  INS_VERIFY       = 0x04;

    // ── Expected status words ────────────────────────────────────────────────
    private static final int SW_SUCCESS              = 0x9000;
    private static final int SW_VERIFICATION_FAILED = 0x6300;
    private static final int SW_DATA_NOT_LOADED      = 0x6984;
    private static final int SW_KEY_NOT_INIT         = 0x6985;
    private static final int SW_WRONG_LENGTH         = 0x6700;
    private static final int SW_INCORRECT_P1P2       = 0x6A86;
    private static final int SW_CLA_NOT_SUPPORTED    = 0x6E00;
    private static final int SW_INS_NOT_SUPPORTED    = 0x6D00;

    private JavaxSmartCardInterface simulator;

    // ── Test fixture ─────────────────────────────────────────────────────────
    @Before
    public void setUp() {
        AID appletAID = new AID(AID_BYTES, (short) 0, (byte) AID_BYTES.length);
        simulator = new JavaxSmartCardInterface();
        simulator.installApplet(appletAID, RSAApplet.class);
        simulator.selectApplet(appletAID);
    }

    // ════════════════════════════════════════════════════════════════════════
    // INS 0x01 – Generate key pair
    // ════════════════════════════════════════════════════════════════════════

    /**
     * APDU: 80 01 00 00
     * Expected: 90 00
     */
    @Test
    public void testGenerateKey_nominal() {
        ResponseAPDU resp = simulator.transmitCommand(
                new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));
        assertEquals("Generate key must succeed", SW_SUCCESS, resp.getSW());
        assertEquals("No data expected in response", 0, resp.getData().length);
    }

    /**
     * Call generate twice.
     * Expected: both succeed, and the exported public key differs (key was replaced).
     *
     * APDUs:
     *   80 01 00 00  → 90 00
     *   80 03 00 00  → <pubkey1> 90 00
     *   80 01 00 00  → 90 00
     *   80 03 00 00  → <pubkey2> 90 00
     */
    @Test
    public void testGenerateKey_replacesExistingKey() throws Exception {
        // First key
        assertSW(SW_SUCCESS, simulator.transmitCommand(
                new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00)));
        PublicKey pub1 = fetchPublicKey();

        // Replace with second key
        assertSW(SW_SUCCESS, simulator.transmitCommand(
                new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00)));
        PublicKey pub2 = fetchPublicKey();

        assertFalse("Second generation must produce a different key", pub1.equals(pub2));
    }

    // ════════════════════════════════════════════════════════════════════════
    // INS 0x03 – Export public key
    // ════════════════════════════════════════════════════════════════════════

    /**
     * APDU: 80 03 00 00  (no key generated yet)
     * Expected: 69 85
     */
    @Test
    public void testGetPublicKey_withoutKey_fails() {
        assertSW(SW_KEY_NOT_INIT, simulator.transmitCommand(
                new CommandAPDU(CLA, INS_GET_PUB_KEY, 0x00, 0x00, 256)));
    }

    /**
     * After key generation, export must return a parseable RSA-1024 public key.
     * Response: [2B modLen=128][128B modulus][2B expLen=3][3B exponent=65537]
     *
     * APDUs:
     *   80 01 00 00        → 90 00
     *   80 03 00 00 00     → <135 bytes> 90 00
     */
    @Test
    public void testGetPublicKey_format_rsa1024() {
        simulator.transmitCommand(new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));

        ResponseAPDU resp = simulator.transmitCommand(
                new CommandAPDU(CLA, INS_GET_PUB_KEY, 0x00, 0x00, 256));
        assertSW(SW_SUCCESS, resp);

        byte[] data   = resp.getData();
        int    modLen = parseShort(data, 0);
        // JCardSim may prefix the modulus with a leading 0x00 (BigInteger two's-complement
        // encoding); a real card returns exactly 128 bytes. Both forms are valid here.
        assertTrue("RSA-1024 modulus must be 128 or 129 bytes", modLen == 128 || modLen == 129);

        int expOffset = 2 + modLen;
        int expLen    = parseShort(data, expOffset);
        assertTrue("Exponent length must be positive", expLen > 0);

        // Reconstruct the key – throws if the bytes are malformed
        byte[] modBytes = Arrays.copyOfRange(data, 2, 2 + modLen);
        byte[] expBytes = Arrays.copyOfRange(data, expOffset + 2, expOffset + 2 + expLen);
        BigInteger modulus  = new BigInteger(1, modBytes);
        BigInteger exponent = new BigInteger(1, expBytes);

        assertEquals("Standard public exponent (65537) expected",
                BigInteger.valueOf(65537L), exponent);
        assertEquals("RSA-1024 modulus must be 1024 bits",
                1024, modulus.bitLength());
    }

    // ════════════════════════════════════════════════════════════════════════
    // INS 0x02 – Sign
    // ════════════════════════════════════════════════════════════════════════

    /**
     * APDU: 80 02 00 00 03 01 02 03  (no key generated yet)
     * Expected: 69 85
     */
    @Test
    public void testSign_withoutKey_fails() {
        ResponseAPDU resp = simulator.transmitCommand(
                new CommandAPDU(CLA, INS_SIGN, 0x00, 0x00,
                        new byte[]{0x01, 0x02, 0x03}, 128));
        assertSW(SW_KEY_NOT_INIT, resp);
    }

    /**
     * Sign a single byte (minimum valid length).
     * APDU: 80 02 00 00 01 42 80
     * Expected: 128-byte signature + 90 00
     */
    @Test
    public void testSign_oneByte_returnsValidSignature() throws Exception {
        simulator.transmitCommand(new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));
        assertSignatureValid(new byte[]{0x42});
    }

    /**
     * Sign 100 bytes.
     */
    @Test
    public void testSign_100Bytes_returnsValidSignature() throws Exception {
        simulator.transmitCommand(new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));
        byte[] data = buildSequentialBytes(100);
        assertSignatureValid(data);
    }

    /**
     * Sign exactly 200 bytes (maximum valid length).
     * APDU: 80 02 00 00 C8 <200 bytes> 80
     */
    @Test
    public void testSign_200Bytes_returnsValidSignature() throws Exception {
        simulator.transmitCommand(new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));
        byte[] data = buildSequentialBytes(200);
        assertSignatureValid(data);
    }

    /**
     * Sign 201 bytes – one byte over the maximum.
     * APDU: 80 02 00 00 C9 <201 bytes>
     * Expected: 67 00
     */
    @Test
    public void testSign_201Bytes_fails() {
        simulator.transmitCommand(new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));
        ResponseAPDU resp = simulator.transmitCommand(
                new CommandAPDU(CLA, INS_SIGN, 0x00, 0x00,
                        buildSequentialBytes(201), 128));
        assertSW(SW_WRONG_LENGTH, resp);
    }

    /**
     * After key replacement, the old signature must not verify with the new key
     * and the new signature must verify with the new key.
     *
     * APDUs:
     *   80 01 00 00          → 90 00   (key 1)
     *   80 02 00 00 04 ...   → <sig1>  (signed with key 1)
     *   80 03 00 00 00       → <pub1>
     *   80 01 00 00          → 90 00   (key 2 – replaces key 1)
     *   80 02 00 00 04 ...   → <sig2>  (signed with key 2)
     *   80 03 00 00 00       → <pub2>
     */
    @Test
    public void testSign_afterKeyReplacement() throws Exception {
        byte[] data = "test data".getBytes("UTF-8");

        // Key 1
        simulator.transmitCommand(new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));
        byte[]    sig1 = signRaw(data);
        PublicKey pub1 = fetchPublicKey();

        // Key 2 (replacement)
        simulator.transmitCommand(new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));
        byte[]    sig2 = signRaw(data);
        PublicKey pub2 = fetchPublicKey();

        assertTrue ("sig2 must verify with pub2", verifySignature(pub2, data, sig2));
        assertFalse("sig1 must NOT verify with pub2", verifySignature(pub2, data, sig1));
        assertFalse("sig2 must NOT verify with pub1", verifySignature(pub1, data, sig2));
    }

    // ════════════════════════════════════════════════════════════════════════
    // INS 0x04 – Verify signature  (two-step: P1=0x00 load, P1=0x01 check)
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Nominal path: load data, then verify with the correct signature → 9000.
     *
     * APDUs:
     *   80 01 00 00                   → 90 00   (generate key)
     *   80 02 00 00 10 <16B data> 80  → <sig>   (sign)
     *   80 04 00 00 10 <16B data>     → 90 00   (load)
     *   80 04 01 00 80 <sig 128B>     → 90 00   (verify → valid)
     */
    @Test
    public void testVerify_validSignature_succeeds() {
        simulator.transmitCommand(new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));
        byte[] data      = "Hello, JavaCard!".getBytes();
        byte[] signature = signRaw(data);
        assertSW(SW_SUCCESS,  verifyLoad(data));
        assertSW(SW_SUCCESS,  verifyCheck(signature));
    }

    /**
     * Load data-A, verify with sig-of-data-B → 6300.
     *
     * APDUs:
     *   80 04 00 00 0A <data-B>  → 90 00
     *   80 04 01 00 80 <sig-A>   → 63 00
     */
    @Test
    public void testVerify_tamperedData_fails() {
        simulator.transmitCommand(new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));
        byte[] original  = buildSequentialBytes(10);
        byte[] tampered  = buildSequentialBytes(10);
        tampered[0] ^= 0xFF;
        byte[] signature = signRaw(original);

        assertSW(SW_SUCCESS,             verifyLoad(tampered));   // load wrong data
        assertSW(SW_VERIFICATION_FAILED, verifyCheck(signature)); // sig doesn't match
    }

    /**
     * Load data, then verify with a corrupted signature (one bit flipped) → 6300.
     *
     * APDUs:
     *   80 04 00 00 0A <data>        → 90 00
     *   80 04 01 00 80 <bad sig>     → 63 00
     */
    @Test
    public void testVerify_tamperedSignature_fails() {
        simulator.transmitCommand(new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));
        byte[] data      = buildSequentialBytes(10);
        byte[] signature = signRaw(data).clone();
        signature[0] ^= 0x01;

        assertSW(SW_SUCCESS,             verifyLoad(data));
        assertSW(SW_VERIFICATION_FAILED, verifyCheck(signature));
    }

    /**
     * Step 2 (check) without step 1 (load) → 6984.
     *
     * APDU: 80 04 01 00 80 <128 bytes>
     * Expected: 69 84
     */
    @Test
    public void testVerify_checkWithoutLoad_fails() {
        simulator.transmitCommand(new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));
        assertSW(SW_DATA_NOT_LOADED, verifyCheck(new byte[128]));
    }

    /**
     * Step 2 without any key generation → 6985.
     *
     * APDUs:
     *   80 04 00 00 05 <5 bytes>  → 90 00
     *   80 04 01 00 80 <128B>     → 69 85
     */
    @Test
    public void testVerify_checkWithoutKey_fails() {
        assertSW(SW_SUCCESS,      verifyLoad(new byte[5]));
        assertSW(SW_KEY_NOT_INIT, verifyCheck(new byte[128]));
    }

    /**
     * Step 1 with empty data (Lc=0) → 6700.
     *
     * APDU: 80 04 00 00  (no data)
     * Expected: 67 00
     */
    @Test
    public void testVerify_loadEmptyData_fails() {
        simulator.transmitCommand(new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));
        assertSW(SW_WRONG_LENGTH,
                simulator.transmitCommand(new CommandAPDU(CLA, INS_VERIFY, 0x00, 0x00)));
    }

    /**
     * Step 2 with wrong signature length (not exactly 128 bytes) → 6700.
     *
     * APDU: 80 04 01 00 10 <16 bytes>  (only 16 bytes instead of 128)
     * Expected: 67 00
     */
    @Test
    public void testVerify_wrongSignatureLength_fails() {
        simulator.transmitCommand(new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));
        assertSW(SW_SUCCESS, verifyLoad(buildSequentialBytes(5)));
        assertSW(SW_WRONG_LENGTH,
                simulator.transmitCommand(
                        new CommandAPDU(CLA, INS_VERIFY, 0x01, 0x00, new byte[16])));
    }

    /**
     * Unknown P1 value → 6A86.
     *
     * APDU: 80 04 FF 00
     * Expected: 6A 86
     */
    @Test
    public void testVerify_unknownP1_fails() {
        assertSW(SW_INCORRECT_P1P2,
                simulator.transmitCommand(new CommandAPDU(CLA, INS_VERIFY, 0xFF, 0x00)));
    }

    /**
     * End-to-end with maximum data (200 bytes, standard APDU) → 9000.
     * Body of each step fits in a standard APDU (≤ 255 bytes).
     *
     * APDUs:
     *   80 04 00 00 C8 <200B>  → 90 00
     *   80 04 01 00 80 <128B>  → 90 00
     */
    @Test
    public void testVerify_200ByteData_succeeds() {
        simulator.transmitCommand(new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));
        byte[] data      = buildSequentialBytes(200);
        byte[] signature = signRaw(data);
        assertSW(SW_SUCCESS, verifyLoad(data));
        assertSW(SW_SUCCESS, verifyCheck(signature));
    }

    /**
     * After a failed verification (wrong sig), the loaded data is cleared;
     * a second check without re-loading must return 6984, not 6300.
     *
     * This ensures the applet does not retain sensitive data after a failed attempt.
     */
    @Test
    public void testVerify_dataCleared_afterFailedVerify() {
        simulator.transmitCommand(new CommandAPDU(CLA, INS_GEN_KEY, 0x00, 0x00));
        byte[] data      = buildSequentialBytes(10);
        byte[] badSig    = new byte[128]; // all zeros → invalid

        assertSW(SW_SUCCESS,             verifyLoad(data));
        assertSW(SW_VERIFICATION_FAILED, verifyCheck(badSig)); // data cleared here
        assertSW(SW_DATA_NOT_LOADED,     verifyCheck(badSig)); // no data anymore
    }

    // ════════════════════════════════════════════════════════════════════════
    // Error / edge-case tests
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Wrong CLA byte (0x00 instead of 0x80).
     * APDU: 00 01 00 00
     * Expected: 6E 00
     */
    @Test
    public void testWrongCLA_rejected() {
        assertSW(SW_CLA_NOT_SUPPORTED,
                simulator.transmitCommand(new CommandAPDU(0x00, INS_GEN_KEY, 0x00, 0x00)));
    }

    /**
     * Unknown INS byte (0xFF).
     * APDU: 80 FF 00 00
     * Expected: 6D 00
     */
    @Test
    public void testUnknownINS_rejected() {
        assertSW(SW_INS_NOT_SUPPORTED,
                simulator.transmitCommand(new CommandAPDU(CLA, 0xFF, 0x00, 0x00)));
    }

    // ════════════════════════════════════════════════════════════════════════
    // Private helpers
    // ════════════════════════════════════════════════════════════════════════

    /** INS 0x04 P1=0x00 – load data into the card's transient verify buffer. */
    private ResponseAPDU verifyLoad(byte[] data) {
        return simulator.transmitCommand(
                new CommandAPDU(CLA, INS_VERIFY, 0x00, 0x00, data));
    }

    /** INS 0x04 P1=0x01 – submit a 128-byte signature for verification. */
    private ResponseAPDU verifyCheck(byte[] signature) {
        return simulator.transmitCommand(
                new CommandAPDU(CLA, INS_VERIFY, 0x01, 0x00, signature));
    }

    /** Parse a big-endian unsigned short from buf[offset..offset+1]. */
    private static int parseShort(byte[] buf, int offset) {
        return ((buf[offset] & 0xFF) << 8) | (buf[offset + 1] & 0xFF);
    }

    /** Build a byte array [0x00, 0x01, ..., (len-1)] for repeatable test data. */
    private static byte[] buildSequentialBytes(int len) {
        byte[] data = new byte[len];
        for (int i = 0; i < len; i++) {
            data[i] = (byte) i;
        }
        return data;
    }

    /** Assert the status word and print a helpful message on failure. */
    private static void assertSW(int expected, ResponseAPDU resp) {
        assertEquals(
                String.format("Expected SW 0x%04X but got 0x%04X", expected, resp.getSW()),
                expected, resp.getSW());
    }

    /**
     * GET_PUB_KEY and reconstruct a Java PublicKey.
     * Verifies SW 9000; throws RuntimeException on any parsing error.
     */
    private PublicKey fetchPublicKey() {
        ResponseAPDU resp = simulator.transmitCommand(
                new CommandAPDU(CLA, INS_GET_PUB_KEY, 0x00, 0x00, 256));
        assertSW(SW_SUCCESS, resp);

        byte[] data      = resp.getData();
        int    modLen    = parseShort(data, 0);
        byte[] modBytes  = Arrays.copyOfRange(data, 2, 2 + modLen);
        int    expOffset = 2 + modLen;
        int    expLen    = parseShort(data, expOffset);
        byte[] expBytes  = Arrays.copyOfRange(data, expOffset + 2, expOffset + 2 + expLen);

        try {
            RSAPublicKeySpec spec = new RSAPublicKeySpec(
                    new BigInteger(1, modBytes),
                    new BigInteger(1, expBytes));
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to reconstruct public key from card response", e);
        }
    }

    /**
     * Send SIGN command and return the raw signature bytes.
     * Fails the test if SW != 9000.
     */
    private byte[] signRaw(byte[] data) {
        ResponseAPDU resp = simulator.transmitCommand(
                new CommandAPDU(CLA, INS_SIGN, 0x00, 0x00, data, 0, data.length, 128));
        assertSW(SW_SUCCESS, resp);
        return resp.getData();
    }

    /**
     * Verify an RSA-SHA1-PKCS1 signature using the Java security layer.
     * Corresponds to Signature.ALG_RSA_SHA_PKCS1 on the card.
     */
    private boolean verifySignature(PublicKey publicKey, byte[] data, byte[] signature)
            throws Exception {
        java.security.Signature verifier =
                java.security.Signature.getInstance("SHA1withRSA");
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }

    /**
     * Convenience: sign data and verify the resulting signature cryptographically.
     * Also checks that the signature length equals the modulus size (128 bytes).
     */
    private void assertSignatureValid(byte[] data) throws Exception {
        PublicKey pub       = fetchPublicKey();
        byte[]    signature = signRaw(data);

        assertEquals("RSA-1024 signature must be 128 bytes", 128, signature.length);
        assertTrue("Signature must verify against the card's public key",
                verifySignature(pub, data, signature));
    }
}
