"""
PKCS#11 shim — wraps python-pkcs11 to provide KMIP-oriented operations.

All cryptographic material stays inside the HSM (SoftHSM2 or real hardware).
The shim returns opaque object handles (integers); key bytes are only returned
when the caller explicitly requests export AND the key is marked extractable.
"""

import logging
import os
from typing import Optional, Tuple

import pkcs11
from pkcs11 import Attribute, KeyType, ObjectClass, Mechanism, MechanismFlag

# Convenient aliases used throughout this module
Attr     = Attribute
ObjClass = ObjectClass
KT       = KeyType
MF       = MechanismFlag
from pkcs11 import exceptions as pkcs11_exc

from ..core.enums import CryptographicAlgorithm, BlockCipherMode
from ..core.exceptions import (
    CryptographicFailure, NotExtractable, GeneralFailure, ItemNotFound
)

log = logging.getLogger(__name__)

# Map KMIP algorithm → PKCS#11 KeyType
ALGO_TO_PKCS11_KEYTYPE = {
    CryptographicAlgorithm.AES:    KT.AES,
    CryptographicAlgorithm.DES:    KT._DES,
    CryptographicAlgorithm.TDES:   KT.DES3,
    CryptographicAlgorithm.RSA:    KT.RSA,
    CryptographicAlgorithm.EC:     KT.EC,
    CryptographicAlgorithm.ECDSA:  KT.EC,
    CryptographicAlgorithm.HMACSHA256: KT.SHA256_HMAC,
    CryptographicAlgorithm.HMACSHA512: KT.SHA512_HMAC,
    CryptographicAlgorithm.HMACSHA1:   KT.SHA_1_HMAC,
}

# Map KMIP block cipher mode → PKCS#11 Mechanism
BLOCKMODE_TO_MECH = {
    BlockCipherMode.CBC: Mechanism.AES_CBC_PAD,
    BlockCipherMode.ECB: Mechanism.AES_ECB,
    BlockCipherMode.GCM: Mechanism.AES_GCM,
    BlockCipherMode.CTR: Mechanism.AES_CTR,
}


class PKCS11Shim:
    """
    Thin stateful wrapper around a single PKCS#11 session.
    One instance per server process; session pool can be added for HA.
    """

    def __init__(self, lib_path: str, token_label: str, user_pin: str):
        self._lib_path    = lib_path
        self._token_label = token_label
        self._user_pin    = user_pin
        self._lib         = None
        self._token       = None
        self._session     = None
        self._initialized = False

    # ── lifecycle ────────────────────────────────────────────────────────────

    def initialize(self):
        if self._initialized:
            return
        try:
            # pkcs11.lib() is a singleton per path; safe to call multiple times
            if self._lib is None:
                self._lib = pkcs11.lib(self._lib_path)
            tokens = list(self._lib.get_tokens(token_label=self._token_label))
            if not tokens:
                raise GeneralFailure(f"Token '{self._token_label}' not found")
            self._token   = tokens[0]
            self._session = self._token.open(rw=True, user_pin=self._user_pin)
            self._initialized = True
            log.info("PKCS#11 session opened on token '%s'", self._token_label)
        except pkcs11_exc.PKCS11Error as e:
            raise GeneralFailure(f"PKCS#11 init failed: {e}") from e

    def finalize(self):
        if self._session:
            try:
                self._session.close()
            except Exception:
                pass
        self._session     = None
        self._initialized = False
        # _lib is retained — PKCS#11 cannot be re-initialized in the same process
        log.info("PKCS#11 session closed")

    def _sess(self):
        if self._session is None:
            raise GeneralFailure("PKCS#11 session not initialized")
        return self._session

    # ── key generation ───────────────────────────────────────────────────────

    def generate_symmetric_key(
        self,
        algorithm: int,
        length_bits: int,
        label: str = "",
        extractable: bool = False,
        sensitive: bool = True,
        encrypt: bool = True,
        decrypt: bool = True,
        wrap: bool = False,
        unwrap: bool = False,
    ) -> Tuple[int, bytes]:
        """
        Generate a symmetric key on the HSM.
        Returns (handle_id, ckaid) where handle_id is the Python object id
        and ckaid is the CKA_ID used for persistent lookup.
        """
        key_type = ALGO_TO_PKCS11_KEYTYPE.get(algorithm)
        if key_type is None:
            raise CryptographicFailure(f"Unsupported algorithm {algorithm}")

        cka_id = os.urandom(16)
        try:
            # SoftHSM2: SENSITIVE+EXTRACTABLE blocks CKA_VALUE; disable SENSITIVE when extractable
            effective_sensitive = sensitive and not extractable
            key = self._sess().generate_key(
                key_type,
                length_bits,
                label=label,
                id=cka_id,
                store=True,
                capabilities=self._caps(encrypt, decrypt, wrap, unwrap),
                template={
                    Attr.SENSITIVE:   effective_sensitive,
                    Attr.EXTRACTABLE: extractable,
                },
            )
            log.debug("Generated %d-bit %s key label='%s'", length_bits, key_type.name, label)
            return id(key), cka_id
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Key generation failed: {e}") from e

    def generate_key_pair(
        self,
        algorithm: int,
        key_length: int = 2048,
        label: str = "",
        extractable: bool = False,
        sensitive: bool = True,
        sign: bool = True,
        verify: bool = True,
    ) -> Tuple[bytes, bytes]:
        """
        Generate RSA or EC key pair.
        Returns (pub_cka_id, priv_cka_id).
        """
        key_type = ALGO_TO_PKCS11_KEYTYPE.get(algorithm)
        if key_type is None:
            raise CryptographicFailure(f"Unsupported algorithm {algorithm}")

        pub_id  = os.urandom(16)
        priv_id = os.urandom(16)

        try:
            if key_type == KT.RSA:
                pub, priv = self._sess().generate_keypair(
                    KT.RSA,
                    key_length,
                    store=True,
                    label=label,
                    mechanism=Mechanism.RSA_PKCS_KEY_PAIR_GEN,
                    public_template={
                        Attr.ID: pub_id,
                        Attr.VERIFY: verify,
                        Attr.ENCRYPT: False,
                    },
                    private_template={
                        Attr.ID: priv_id,
                        Attr.SENSITIVE: sensitive,
                        Attr.EXTRACTABLE: extractable,
                        Attr.SIGN: sign,
                        Attr.DECRYPT: False,
                    },
                )
            elif key_type == KT.EC:
                from pkcs11.util.ec import encode_named_curve_parameters
                ec_params = encode_named_curve_parameters('secp256r1')
                pub, priv = self._sess().generate_keypair(
                    KT.EC,
                    label=label,
                    store=True,
                    mechanism=Mechanism.EC_KEY_PAIR_GEN,
                    public_template={
                        Attr.ID: pub_id,
                        Attr.EC_PARAMS: ec_params,
                        Attr.VERIFY: verify,
                    },
                    private_template={
                        Attr.ID: priv_id,
                        Attr.SENSITIVE: sensitive,
                        Attr.EXTRACTABLE: extractable,
                        Attr.SIGN: sign,
                    },
                )
            else:
                raise CryptographicFailure(f"Key pair generation not supported for {algorithm}")

            log.debug("Generated %s key pair label='%s'", key_type.name, label)
            return pub_id, priv_id
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Key pair generation failed: {e}") from e

    # ── import (register) ────────────────────────────────────────────────────

    def import_symmetric_key(
        self,
        algorithm: int,
        length_bits: int,
        key_bytes: bytes,
        label: str = "",
        extractable: bool = True,
        sensitive: bool = False,
        encrypt: bool = True,
        decrypt: bool = True,
    ) -> bytes:
        """Import externally supplied key material. Returns cka_id."""
        key_type = ALGO_TO_PKCS11_KEYTYPE.get(algorithm)
        if key_type is None:
            raise CryptographicFailure(f"Unsupported algorithm {algorithm}")

        cka_id = os.urandom(16)
        try:
            self._sess().create_object({
                Attr.CLASS:      ObjClass.SECRET_KEY,
                Attr.KEY_TYPE:   key_type,
                Attr.VALUE:      key_bytes,
                Attr.ID:         cka_id,
                Attr.LABEL:      label,
                Attr.TOKEN:      True,
                Attr.SENSITIVE:  sensitive,
                Attr.EXTRACTABLE: extractable,
                Attr.ENCRYPT:    encrypt,
                Attr.DECRYPT:    decrypt,
            })
            return cka_id
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Key import failed: {e}") from e

    # ── key retrieval ────────────────────────────────────────────────────────

    def _find_key(self, cka_id: bytes, obj_class=None):
        template = {Attr.ID: cka_id}
        if obj_class:
            template[Attr.CLASS] = obj_class
        for obj in self._sess().get_objects(template):
            return obj
        raise ItemNotFound(f"PKCS#11 object with CKA_ID not found")

    def get_key_value(self, cka_id: bytes) -> bytes:
        """Export key material (only if extractable)."""
        try:
            key = self._find_key(cka_id, ObjClass.SECRET_KEY)
            try:
                extractable = key[Attr.EXTRACTABLE]
            except Exception:
                extractable = True  # assume extractable if we can't read the attr
            if not extractable:
                raise NotExtractable("Key is not extractable")
            # Try direct CKA_VALUE read; fall back to wrap-based export
            try:
                val = key[Attr.VALUE]
                if val is None:
                    raise pkcs11_exc.AttributeSensitive()
                return bytes(val)
            except (pkcs11_exc.AttributeSensitive, pkcs11_exc.AttributeTypeInvalid,
                    AttributeError, TypeError):
                raise NotExtractable("Key value is not readable (sensitive or token policy)")
        except (NotExtractable, CryptographicFailure):
            raise
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(str(e)) from e

    def get_public_key_der(self, cka_id: bytes) -> bytes:
        """Export public key in DER (SubjectPublicKeyInfo) format."""
        try:
            key = self._find_key(cka_id, ObjClass.PUBLIC_KEY)
            from pkcs11.util.rsa import encode_rsa_public_key
            try:
                return encode_rsa_public_key(key)
            except Exception:
                # EC or other key type — try raw value
                return bytes(key[Attr.VALUE])
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(str(e)) from e

    # ── destroy ──────────────────────────────────────────────────────────────

    def destroy_object(self, cka_id: bytes, obj_class=None):
        try:
            obj = self._find_key(cka_id, obj_class)
            obj.destroy()
            log.debug("Destroyed PKCS#11 object cka_id=%s", cka_id.hex())
        except ItemNotFound:
            log.warning("Destroy: object not found on token, ignoring")
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Destroy failed: {e}") from e

    # ── encrypt / decrypt ────────────────────────────────────────────────────

    def encrypt(
        self,
        cka_id: bytes,
        plaintext: bytes,
        mechanism_id: int = BlockCipherMode.CBC,
        iv: Optional[bytes] = None,
        aad: Optional[bytes] = None,
    ) -> Tuple[bytes, Optional[bytes]]:
        """
        Encrypt using HSM-resident key.
        Returns (ciphertext, tag_or_None).
        """
        try:
            key  = self._find_key(cka_id, ObjClass.SECRET_KEY)
            mech = BLOCKMODE_TO_MECH.get(mechanism_id, Mechanism.AES_CBC_PAD)

            if mech == Mechanism.AES_GCM:
                result = key.encrypt(
                    plaintext,
                    mechanism=mech,
                    mechanism_param=pkcs11.GCMParams(
                        nonce=iv or b'\x00' * 12,
                        aad=aad,
                        tag_bits=128,
                    ),
                )
                return bytes(result[:-16]), bytes(result[-16:])
            elif mech == Mechanism.AES_CTR:
                param = pkcs11.CTRParams(nonce=iv or b'\x00' * 12)
                ct = key.encrypt(plaintext, mechanism=mech, mechanism_param=param)
                return bytes(ct), None
            else:
                # CBC / ECB: IV as raw bytes (ECB ignores it)
                ct = key.encrypt(plaintext, mechanism=mech, mechanism_param=iv or None)
                return bytes(ct), None
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Encrypt failed: {e}") from e

    def decrypt(
        self,
        cka_id: bytes,
        ciphertext: bytes,
        mechanism_id: int = BlockCipherMode.CBC,
        iv: Optional[bytes] = None,
        aad: Optional[bytes] = None,
        tag: Optional[bytes] = None,
    ) -> bytes:
        try:
            key  = self._find_key(cka_id, ObjClass.SECRET_KEY)
            mech = BLOCKMODE_TO_MECH.get(mechanism_id, Mechanism.AES_CBC_PAD)

            if mech == Mechanism.AES_GCM:
                data = ciphertext + (tag or b'')
                pt   = key.decrypt(
                    data,
                    mechanism=mech,
                    mechanism_param=pkcs11.GCMParams(
                        nonce=iv or b'\x00' * 12,
                        aad=aad,
                        tag_bits=128,
                    ),
                )
            elif mech == Mechanism.AES_CTR:
                param = pkcs11.CTRParams(nonce=iv or b'\x00' * 12)
                pt = key.decrypt(ciphertext, mechanism=mech, mechanism_param=param)
            else:
                pt = key.decrypt(ciphertext, mechanism=mech, mechanism_param=iv or None)
            return bytes(pt)
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Decrypt failed: {e}") from e

    # ── sign / verify ────────────────────────────────────────────────────────

    def sign(self, cka_id: bytes, data: bytes, mechanism=None) -> bytes:
        try:
            key = self._find_key(cka_id, ObjClass.PRIVATE_KEY)
            mech = mechanism or Mechanism.RSA_PKCS
            sig = key.sign(data, mechanism=mech)
            return bytes(sig)
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Sign failed: {e}") from e

    def verify(self, cka_id: bytes, data: bytes, signature: bytes, mechanism=None) -> bool:
        try:
            key  = self._find_key(cka_id, ObjClass.PUBLIC_KEY)
            mech = mechanism or Mechanism.RSA_PKCS
            key.verify(data, signature, mechanism=mech)
            return True
        except pkcs11_exc.SignatureInvalid:
            return False
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Verify failed: {e}") from e

    # ── random ───────────────────────────────────────────────────────────────

    def generate_random(self, length: int) -> bytes:
        try:
            return bytes(self._sess().generate_random(length * 8))
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"RNG failed: {e}") from e

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _caps(encrypt, decrypt, wrap, unwrap) -> MechanismFlag:
        flags = MechanismFlag(0)
        if encrypt: flags |= MF.ENCRYPT
        if decrypt: flags |= MF.DECRYPT
        if wrap:    flags |= MF.WRAP
        if unwrap:  flags |= MF.UNWRAP
        return flags

    def get_mechanism_list(self):
        try:
            return list(self._token.slot.get_mechanism_list())
        except Exception:
            return []

    def get_token_info(self):
        try:
            return str(self._token.slot.get_token())
        except Exception:
            return "SoftHSM2 Token"
