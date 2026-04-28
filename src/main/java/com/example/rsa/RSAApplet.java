package com.example.rsa;

import javacard.framework.*;
import javacard.security.*;

/**
 * Java Card RSA 1024-bit applet.
 *
 * APDU interface (CLA = 0x80):
 *
 *   INS 0x01 – Generate (or replace) RSA-1024 key pair
 *              Command : 80 01 00 00
 *              Response: SW 9000
 *
 *   INS 0x02 – Sign [1..200] bytes  (SHA-1 / PKCS#1 v1.5)
 *              Command : 80 02 00 00 Lc <data [1..200]> Le
 *              Response: <128-byte signature> SW 9000
 *
 *   INS 0x03 – Export public key
 *              Command : 80 03 00 00 Le
 *              Response: [2B modLen][modulus][2B expLen][exponent]  SW 9000
 *
 *   INS 0x04 – Verify signature  (two-step, both standard APDUs)
 *
 *     Step 1 – Load data  (P1 = 0x00)
 *              Command : 80 04 00 00 Lc <data [1..200]>
 *              Response: SW 9000
 *
 *     Step 2 – Verify     (P1 = 0x01)
 *              Command : 80 04 01 00 80 <signature [128]>
 *              Response: SW 9000 (valid) | SW 6300 (invalid)
 *              Clears the loaded data after evaluation regardless of result.
 *
 * Custom status words:
 *   0x6300 – Signature verification failed
 *   0x6984 – No data loaded for verification (step 1 not completed)
 *   0x6985 – Key not yet generated
 */
public class RSAApplet extends Applet {

    // ── Custom CLA & instruction bytes ──────────────────────────────────────
    private static final byte CLA_APPLET      = (byte) 0x80;
    private static final byte INS_GEN_KEY     = (byte) 0x01;
    private static final byte INS_SIGN        = (byte) 0x02;
    private static final byte INS_GET_PUB_KEY = (byte) 0x03;
    private static final byte INS_VERIFY      = (byte) 0x04;

    // P1 values for INS_VERIFY
    private static final byte VERIFY_P1_LOAD  = (byte) 0x00;
    private static final byte VERIFY_P1_CHECK = (byte) 0x01;

    // ── Custom status words ──────────────────────────────────────────────────
    private static final short SW_VERIFICATION_FAILED = (short) 0x6300;
    private static final short SW_DATA_NOT_LOADED     = (short) 0x6984;
    private static final short SW_KEY_NOT_INITIALIZED = (short) 0x6985;

    // ── Applet constants ─────────────────────────────────────────────────────
    private static final short MAX_DATA_LEN = (short) 200;
    private static final short SIG_SIZE     = (short) 128; // RSA-1024 → 128 bytes

    // ── Persistent state (EEPROM) ────────────────────────────────────────────
    private final KeyPair   rsaKeyPair;
    private final Signature rsaSignature;
    private boolean         keyInitialized;

    // ── Transient buffers (cleared on card deselect) ─────────────────────────
    // sigBuffer  : holds sign output / verify sig copy (avoids same-array overlap)
    // verifyBuf  : holds data loaded in VERIFY step 1
    // verifyLen  : length of loaded data (0 = nothing loaded)
    private final byte[]  sigBuffer;
    private final byte[]  verifyBuf;
    private final short[] verifyLen; // single-element array (cheapest transient short)

    // ── AID: A0 00 00 00 01 01 02 ────────────────────────────────────────────
    protected RSAApplet() {
        rsaKeyPair   = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        rsaSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        sigBuffer    = JCSystem.makeTransientByteArray(SIG_SIZE,     JCSystem.CLEAR_ON_DESELECT);
        verifyBuf    = JCSystem.makeTransientByteArray(MAX_DATA_LEN, JCSystem.CLEAR_ON_DESELECT);
        verifyLen    = JCSystem.makeTransientShortArray((short) 1,   JCSystem.CLEAR_ON_DESELECT);
        keyInitialized = false;
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAApplet();
    }

    // ── APDU dispatcher ──────────────────────────────────────────────────────
    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buf = apdu.getBuffer();

        if (buf[ISO7816.OFFSET_CLA] != CLA_APPLET) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_GEN_KEY:
                generateKeyPair(apdu);
                break;
            case INS_SIGN:
                signData(apdu);
                break;
            case INS_GET_PUB_KEY:
                getPublicKey(apdu);
                break;
            case INS_VERIFY:
                dispatchVerify(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // ── INS 0x01 – Generate key pair ─────────────────────────────────────────
    private void generateKeyPair(APDU apdu) {
        if (keyInitialized) {
            rsaKeyPair.getPublic().clearKey();
            rsaKeyPair.getPrivate().clearKey();
        }
        rsaKeyPair.genKeyPair();
        keyInitialized = true;
    }

    // ── INS 0x02 – Sign data ─────────────────────────────────────────────────
    private void signData(APDU apdu) {
        if (!keyInitialized) {
            ISOException.throwIt(SW_KEY_NOT_INITIALIZED);
        }

        byte[] buf    = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        if (dataLen < (short) 1 || dataLen > MAX_DATA_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        rsaSignature.init(rsaKeyPair.getPrivate(), Signature.MODE_SIGN);

        // Sign into sigBuffer to avoid overlap with the input at OFFSET_CDATA
        short sigLen = rsaSignature.sign(
                buf, ISO7816.OFFSET_CDATA, dataLen,
                sigBuffer, (short) 0);

        Util.arrayCopyNonAtomic(sigBuffer, (short) 0, buf, (short) 0, sigLen);
        apdu.setOutgoingAndSend((short) 0, sigLen);
    }

    // ── INS 0x03 – Export public key ─────────────────────────────────────────
    private void getPublicKey(APDU apdu) {
        if (!keyInitialized) {
            ISOException.throwIt(SW_KEY_NOT_INITIALIZED);
        }

        RSAPublicKey pubKey = (RSAPublicKey) rsaKeyPair.getPublic();
        byte[]       buf    = apdu.getBuffer();
        short        offset = (short) 0;

        short modLen = pubKey.getModulus(buf, (short) (offset + 2));
        Util.setShort(buf, offset, modLen);
        offset += (short) (2 + modLen);

        short expLen = pubKey.getExponent(buf, (short) (offset + 2));
        Util.setShort(buf, offset, expLen);
        offset += (short) (2 + expLen);

        apdu.setOutgoingAndSend((short) 0, offset);
    }

    // ── INS 0x04 – Verify signature (dispatcher) ─────────────────────────────
    private void dispatchVerify(APDU apdu) {
        byte p1 = apdu.getBuffer()[ISO7816.OFFSET_P1];
        switch (p1) {
            case VERIFY_P1_LOAD:
                verifyLoad(apdu);
                break;
            case VERIFY_P1_CHECK:
                verifyCheck(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    // ── INS 0x04 / P1=0x00 – Load data for verification ─────────────────────
    //
    // Stores incoming bytes in the transient verifyBuf so that the next
    // VERIFY_P1_CHECK call can reference them.  Any previously loaded data
    // is silently overwritten.
    private void verifyLoad(APDU apdu) {
        byte[] buf    = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        if (dataLen < (short) 1 || dataLen > MAX_DATA_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, verifyBuf, (short) 0, dataLen);
        verifyLen[0] = dataLen;
    }

    // ── INS 0x04 / P1=0x01 – Verify signature against loaded data ────────────
    //
    // Takes a 128-byte RSA-1024 signature and verifies it against the data
    // previously stored by VERIFY_P1_LOAD.  The loaded data is cleared after
    // the check (success or failure) to prevent replay.
    //
    // Returns SW 9000 when valid, SW 6300 when invalid.
    private void verifyCheck(APDU apdu) {
        if (!keyInitialized) {
            ISOException.throwIt(SW_KEY_NOT_INITIALIZED);
        }
        if (verifyLen[0] == (short) 0) {
            ISOException.throwIt(SW_DATA_NOT_LOADED);
        }

        byte[] buf    = apdu.getBuffer();
        short sigLen  = apdu.setIncomingAndReceive();

        if (sigLen != SIG_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Copy signature to sigBuffer so verifyBuf and the sig are in separate arrays
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, sigBuffer, (short) 0, SIG_SIZE);

        short dataLen = verifyLen[0];
        verifyLen[0]  = (short) 0;   // clear loaded data length before the crypto call

        rsaSignature.init(rsaKeyPair.getPublic(), Signature.MODE_VERIFY);
        boolean valid = rsaSignature.verify(
                verifyBuf,  (short) 0, dataLen,
                sigBuffer,  (short) 0, SIG_SIZE);

        if (!valid) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
        // Valid → SW 9000 returned automatically
    }
}
