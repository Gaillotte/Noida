package com.example.rsa;

import javacard.framework.*;
import javacard.security.*;

/**
 * Java Card RSA 1024-bit applet.
 *
 * APDU interface:
 *   CLA = 0x80
 *   INS 0x01 – Generate (or replace) RSA-1024 key pair   – no data
 *   INS 0x02 – Sign [1..200] bytes                       – returns 128-byte signature
 *   INS 0x03 – Export public key                         – returns TLV-like structure
 *
 * Public-key response format:
 *   [2 bytes big-endian modulus length][modulus][2 bytes big-endian exponent length][exponent]
 *
 * Status words (in addition to standard ISO 7816 ones):
 *   0x6985 – Key not yet generated
 */
public class RSAApplet extends Applet {

    // ── Custom CLA & instruction bytes ──────────────────────────────────────
    private static final byte CLA_APPLET        = (byte) 0x80;
    private static final byte INS_GEN_KEY       = (byte) 0x01;
    private static final byte INS_SIGN          = (byte) 0x02;
    private static final byte INS_GET_PUB_KEY   = (byte) 0x03;

    // ── Custom status word ──────────────────────────────────────────────────
    private static final short SW_KEY_NOT_INITIALIZED = (short) 0x6985;

    // ── Applet constants ────────────────────────────────────────────────────
    private static final short MAX_DATA_LEN = (short) 200;
    private static final short SIG_SIZE     = (short) 128; // 1024-bit RSA → 128 bytes

    // ── Persistent state (EEPROM) ───────────────────────────────────────────
    private final KeyPair   rsaKeyPair;
    private final Signature rsaSignature;
    private boolean         keyInitialized;

    // ── Transient buffer to avoid input/output overlap in the APDU buffer ──
    private final byte[] sigBuffer;

    // ── AID: A0 00 00 00 01 01 02 ───────────────────────────────────────────
    protected RSAApplet() {
        rsaKeyPair   = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        rsaSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        sigBuffer    = JCSystem.makeTransientByteArray(SIG_SIZE, JCSystem.CLEAR_ON_DESELECT);
        keyInitialized = false;
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAApplet();
    }

    // ── APDU dispatcher ─────────────────────────────────────────────────────
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
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // ── INS 0x01 – Generate key pair ────────────────────────────────────────
    private void generateKeyPair(APDU apdu) {
        // Explicit clear before regeneration (good security hygiene)
        if (keyInitialized) {
            rsaKeyPair.getPublic().clearKey();
            rsaKeyPair.getPrivate().clearKey();
        }
        rsaKeyPair.genKeyPair();
        keyInitialized = true;
        // SW 9000 is returned automatically (no data)
    }

    // ── INS 0x02 – Sign data ────────────────────────────────────────────────
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

        // Sign into transient buffer to avoid overlap with APDU input at OFFSET_CDATA
        short sigLen = rsaSignature.sign(
                buf, ISO7816.OFFSET_CDATA, dataLen,
                sigBuffer, (short) 0);

        Util.arrayCopyNonAtomic(sigBuffer, (short) 0, buf, (short) 0, sigLen);
        apdu.setOutgoingAndSend((short) 0, sigLen);
    }

    // ── INS 0x03 – Export public key ────────────────────────────────────────
    private void getPublicKey(APDU apdu) {
        if (!keyInitialized) {
            ISOException.throwIt(SW_KEY_NOT_INITIALIZED);
        }

        RSAPublicKey pubKey = (RSAPublicKey) rsaKeyPair.getPublic();
        byte[]       buf    = apdu.getBuffer();
        short        offset = (short) 0;

        // Modulus
        short modLen = pubKey.getModulus(buf, (short) (offset + 2));
        Util.setShort(buf, offset, modLen);
        offset += (short) (2 + modLen);

        // Public exponent
        short expLen = pubKey.getExponent(buf, (short) (offset + 2));
        Util.setShort(buf, offset, expLen);
        offset += (short) (2 + expLen);

        apdu.setOutgoingAndSend((short) 0, offset);
    }
}
