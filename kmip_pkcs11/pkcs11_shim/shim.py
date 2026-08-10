"""
PKCS#11 shim — wraps python-pkcs11 to provide KMIP-oriented operations.

All cryptographic material stays inside the HSM (SoftHSM2 or real hardware).
The shim returns opaque object handles (integers); key bytes are only returned
when the caller explicitly requests export AND the key is marked extractable.
"""

import functools
import logging
import os
import threading
from typing import Optional, Tuple

import pkcs11
from pkcs11 import Attribute, KeyType, ObjectClass, Mechanism, MechanismFlag

# Convenient aliases used throughout this module
Attr     = Attribute
ObjClass = ObjectClass
KT       = KeyType
MF       = MechanismFlag
from pkcs11 import exceptions as pkcs11_exc

from ..core.enums import CryptographicAlgorithm, BlockCipherMode, KeyFormatType
from ..core.exceptions import (
    CryptographicFailure, NotExtractable, GeneralFailure, ItemNotFound,
    OperationNotSupported
)

log = logging.getLogger(__name__)

# RFC 3526 Group 14 (2048-bit MODP) — a fixed, well-known DH group.
# DH key AGREEMENT requires both parties to share identical (P, G); generating
# fresh random domain parameters per CreateKeyPair call (as DSA does, where no
# secret needs to be shared) would silently put every party in a different
# group and make derived "shared" secrets never match.
_DH_GROUP14_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374"
    "FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE"
    "386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598D"
    "A48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F36208552BB9ED52"
    "9077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E77"
    "2C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF69558171839954"
    "97CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_DH_GROUP14_GENERATOR = 2


def _dh_group14_bytes():
    p_len = (_DH_GROUP14_PRIME.bit_length() + 7) // 8
    return (
        _DH_GROUP14_PRIME.to_bytes(p_len, 'big'),
        _DH_GROUP14_GENERATOR.to_bytes(1, 'big'),
    )


# Map KMIP algorithm → PKCS#11 KeyType
ALGO_TO_PKCS11_KEYTYPE = {
    CryptographicAlgorithm.AES:    KT.AES,
    CryptographicAlgorithm.DES:    KT._DES,
    CryptographicAlgorithm.TDES:   KT.DES3,
    CryptographicAlgorithm.RSA:    KT.RSA,
    CryptographicAlgorithm.EC:     KT.EC,
    CryptographicAlgorithm.ECDSA:  KT.EC,
    CryptographicAlgorithm.ECDH:   KT.EC,
    CryptographicAlgorithm.DSA:    KT.DSA,
    CryptographicAlgorithm.DH:     KT.DH,
    CryptographicAlgorithm.HMACMD5:    KT._MD5_HMAC,
    CryptographicAlgorithm.HMACSHA1:   KT.SHA_1_HMAC,
    CryptographicAlgorithm.HMACSHA224: KT.SHA224_HMAC,
    CryptographicAlgorithm.HMACSHA256: KT.SHA256_HMAC,
    CryptographicAlgorithm.HMACSHA384: KT.SHA384_HMAC,
    CryptographicAlgorithm.HMACSHA512: KT.SHA512_HMAC,
    # SHA-3 HMAC + Blowfish/Twofish: real PKCS#11 mechanisms (present in the
    # python-pkcs11 binding), gated at call time via supports_mechanism() —
    # this SoftHSM2 build does not implement them, but a capable token
    # (Botan-backed SoftHSM2, a newer OpenSSL-3-linked build, or real
    # hardware) needs no code change here to light these up.
    CryptographicAlgorithm.HMACSHA3224: KT.SHA3_224_HMAC,
    CryptographicAlgorithm.HMACSHA3256: KT.SHA3_256_HMAC,
    CryptographicAlgorithm.HMACSHA3384: KT.SHA3_384_HMAC,
    CryptographicAlgorithm.HMACSHA3512: KT.SHA3_512_HMAC,
    CryptographicAlgorithm.Blowfish:    KT.BLOWFISH,
    CryptographicAlgorithm.Twofish:     KT.TWOFISH,
}

# HMAC key types require CKM_GENERIC_SECRET_KEY_GEN + SIGN/VERIFY capabilities
# (not the encrypt/decrypt/wrap/unwrap capabilities used for AES/DES keys).
_MAC_KEY_TYPES = {
    KT._MD5_HMAC, KT.SHA_1_HMAC, KT.SHA224_HMAC,
    KT.SHA256_HMAC, KT.SHA384_HMAC, KT.SHA512_HMAC,
    KT.SHA3_224_HMAC, KT.SHA3_256_HMAC, KT.SHA3_384_HMAC, KT.SHA3_512_HMAC,
}

# Non-MAC symmetric key types → their PKCS#11 key-generation Mechanism.
# Used only to capability-gate generation up front (see supports_mechanism);
# MAC key types always use GENERIC_SECRET_KEY_GEN, handled separately above.
_SYMMETRIC_KEYGEN_MECH = {
    KT.AES:      Mechanism.AES_KEY_GEN,
    KT._DES:     Mechanism._DES_KEY_GEN,
    KT.DES3:     Mechanism.DES3_KEY_GEN,
    KT.BLOWFISH: Mechanism.BLOWFISH_KEY_GEN,
    KT.TWOFISH:  Mechanism.TWOFISH_KEY_GEN,
}

# KMIP HashingAlgorithm → PKCS#11 digest Mechanism (session.digest)
HASH_ALG_TO_MECH = {
    3: Mechanism._MD5,     # HashingAlgorithm.MD5
    4: Mechanism.SHA_1,    # HashingAlgorithm.SHA_1
    5: Mechanism.SHA224,   # HashingAlgorithm.SHA_224
    6: Mechanism.SHA256,   # HashingAlgorithm.SHA_256
    7: Mechanism.SHA384,   # HashingAlgorithm.SHA_384
    8: Mechanism.SHA512,   # HashingAlgorithm.SHA_512
    0xe: Mechanism.SHA3_224,   # HashingAlgorithm.SHA3_224 — gated, see above
    0xf: Mechanism.SHA3_256,   # HashingAlgorithm.SHA3_256
    0x10: Mechanism.SHA3_384,  # HashingAlgorithm.SHA3_384
    0x11: Mechanism.SHA3_512,  # HashingAlgorithm.SHA3_512
}

# Map KMIP block cipher mode → PKCS#11 Mechanism, per key family.
# CFB128/OFB/CCM are real PKCS#11 mechanisms that this specific SoftHSM2
# build does not implement (confirmed via slot.get_mechanisms() — see
# supports_mechanism()); encrypt()/decrypt() capability-gate on it and
# raise a clean OperationNotSupported instead of a raw PKCS#11 error.
# Single-DES ECB/CBC use raw CKM values (0x121/0x122) because python-pkcs11
# omits the DES_ECB / DES_CBC named constants (they are cryptographically broken).
BLOCKMODE_TO_MECH = {          # AES (default)
    BlockCipherMode.CBC: Mechanism.AES_CBC_PAD,
    BlockCipherMode.ECB: Mechanism.AES_ECB,
    BlockCipherMode.GCM: Mechanism.AES_GCM,
    BlockCipherMode.CTR: Mechanism.AES_CTR,
    BlockCipherMode.CFB: Mechanism.AES_CFB128,
    BlockCipherMode.OFB: Mechanism.AES_OFB,
    BlockCipherMode.CCM: Mechanism.AES_CCM,
}
DES3_BLOCKMODE_TO_MECH = {     # Triple-DES; SoftHSM2 supports ECB + CBC_PAD
    BlockCipherMode.CBC: Mechanism.DES3_CBC_PAD,
    BlockCipherMode.ECB: Mechanism.DES3_ECB,
}
DES_BLOCKMODE_TO_MECH = {      # Single-DES (legacy only; CBC has no padding variant)
    BlockCipherMode.CBC: Mechanism(0x0122),   # CKM_DES_CBC
    BlockCipherMode.ECB: Mechanism(0x0121),   # CKM_DES_ECB
}
BLOWFISH_BLOCKMODE_TO_MECH = { # Blowfish only defines a padded-CBC mechanism
    BlockCipherMode.CBC: Mechanism.BLOWFISH_CBC_PAD,
}
TWOFISH_BLOCKMODE_TO_MECH = {  # Twofish only defines a padded-CBC mechanism
    BlockCipherMode.CBC: Mechanism.TWOFISH_CBC_PAD,
}

# IV block size by key family: DES/3DES use 64-bit blocks → 8-byte IV
_DES_KEY_TYPES = {KT._DES, KT.DES3}


def _synchronized(method):
    """Serialize calls to a PKCS11Shim method behind self._lock.

    server.py runs one thread per connection, but every thread shares this
    one PKCS#11 session (see the class docstring) and python-pkcs11 session
    objects aren't safe for concurrent use from multiple threads.

    A session-pool (one PKCS#11 session per thread, no lock) was evaluated
    and rejected: python-pkcs11 0.9.5 calls C_Initialize(NULL) — see its
    _pkcs11.pyx — which leaves CKF_OS_LOCKING_OK unset, so the underlying
    library never enables its own internal thread safety. Verified live
    against this SoftHSM2 build: N threads each on their *own* session,
    calling generate_key/encrypt/decrypt concurrently, reproducibly either
    segfaults the native extension or returns GeneralError/MechanismInvalid
    on most threads — separate sessions do not make this safe. A real fix
    needs either a PKCS#11 binding that passes CKF_OS_LOCKING_OK at
    C_Initialize, or a multi-process worker pool (each process owns one
    session, used by only one thread) — both larger changes than a lock.
    This lock is therefore the permanent design, not a stopgap: correctness
    over throughput, deliberately.
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


class PKCS11Shim:
    """
    Thin stateful wrapper around a single PKCS#11 session, shared across all
    connection-handling threads and serialized via self._lock (see
    _synchronized). A session pool can be added later for real concurrency.
    """

    def __init__(self, lib_path: str, token_label: str, user_pin: str):
        self._lib_path    = lib_path
        self._token_label = token_label
        self._user_pin    = user_pin
        self._lib         = None
        self._token       = None
        self._session     = None
        self._initialized = False
        self._available_mechanisms = frozenset()
        self._lock = threading.RLock()

    # ── lifecycle ────────────────────────────────────────────────────────────

    @_synchronized
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
            # Capability probe: cache once so every algorithm/mode dispatch
            # can check availability up front rather than discovering it via
            # a native PKCS#11 error mid-operation.
            self._available_mechanisms = frozenset(
                int(m) for m in self._token.slot.get_mechanisms()
            )
            self._initialized = True
            log.info(
                "PKCS#11 session opened on token '%s' (%d mechanisms available)",
                self._token_label, len(self._available_mechanisms),
            )
        except pkcs11_exc.PKCS11Error as e:
            raise GeneralFailure(f"PKCS#11 init failed: {e}") from e

    def supports_mechanism(self, mechanism) -> bool:
        """True if this token's slot advertises the given Mechanism (or raw
        CKM_* int) via C_GetMechanismList. Used to reject an unsupported
        algorithm/mode cleanly (OperationNotSupported) instead of letting a
        native PKCS#11 error surface mid-operation."""
        return int(mechanism) in self._available_mechanisms

    def _require_mechanism(self, mechanism, what: str):
        if not self.supports_mechanism(mechanism):
            name = getattr(mechanism, "name", None) or f"0x{int(mechanism):04x}"
            raise OperationNotSupported(
                f"{what}: mechanism {name} is not available on this PKCS#11 token"
            )

    @_synchronized
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

    def verify_pin(self, pin: str) -> bool:
        """Constant-time-ish comparison against the configured token PIN, used
        as the shared secret for KMIP UsernameAndPassword Credential auth."""
        import hmac
        return hmac.compare_digest(pin or "", self._user_pin or "")

    def _sess(self):
        if self._session is None:
            raise GeneralFailure("PKCS#11 session not initialized")
        return self._session

    # ── key generation ───────────────────────────────────────────────────────

    @_synchronized
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
            if key_type in _MAC_KEY_TYPES:
                # HMAC key types are generic secrets: fixed keygen mechanism + SIGN/VERIFY caps
                self._require_mechanism(Mechanism.GENERIC_SECRET_KEY_GEN, "Create")
                key = self._sess().generate_key(
                    key_type,
                    length_bits,
                    label=label,
                    id=cka_id,
                    store=True,
                    mechanism=Mechanism.GENERIC_SECRET_KEY_GEN,
                    capabilities=MF.SIGN | MF.VERIFY,
                    template={
                        Attr.SENSITIVE:   effective_sensitive,
                        Attr.EXTRACTABLE: extractable,
                    },
                )
            else:
                keygen_mech = _SYMMETRIC_KEYGEN_MECH.get(key_type)
                if keygen_mech is not None:
                    self._require_mechanism(keygen_mech, "Create")
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

    @_synchronized
    def generate_key_pair(
        self,
        algorithm: int,
        key_length: int = 2048,
        curve: str = 'secp256r1',
        label: str = "",
        extractable: bool = False,
        sensitive: bool = True,
        sign: bool = True,
        verify: bool = True,
        derive: bool = False,
    ) -> Tuple[bytes, bytes]:
        """
        Generate RSA, EC, DSA, DH, or ECDH key pair.
        Returns (pub_cka_id, priv_cka_id).
        """
        key_type = ALGO_TO_PKCS11_KEYTYPE.get(algorithm)
        if key_type is None:
            raise CryptographicFailure(f"Unsupported algorithm {algorithm}")

        pub_id  = os.urandom(16)
        priv_id = os.urandom(16)
        is_derive_algo = algorithm in (CryptographicAlgorithm.ECDH, CryptographicAlgorithm.DH)

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
                ec_params = encode_named_curve_parameters(curve)
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
                        Attr.DERIVE: derive or is_derive_algo,
                    },
                )
            elif key_type == KT.DSA:
                # DSA needs domain parameters (P, Q, G) generated before the key pair.
                domain_params = self._sess().generate_domain_parameters(
                    KT.DSA, key_length, store=False
                )
                pub, priv = domain_params.generate_keypair(
                    store=True,
                    label=label,
                    public_template={
                        Attr.ID: pub_id,
                        Attr.VERIFY: verify,
                    },
                    private_template={
                        Attr.ID: priv_id,
                        Attr.SENSITIVE: sensitive,
                        Attr.EXTRACTABLE: extractable,
                        Attr.SIGN: sign,
                    },
                )
            elif key_type == KT.DH:
                # Use a fixed, well-known group (RFC 3526 Group 14) rather than
                # generating fresh random domain parameters per call — DH key
                # AGREEMENT only works if every party derives from the same
                # (P, G); a freshly-generated group per CreateKeyPair call
                # would put each party in an incompatible group.
                prime_bytes, base_bytes = _dh_group14_bytes()
                domain_params = self._sess().create_domain_parameters(
                    KT.DH, {Attr.PRIME: prime_bytes, Attr.BASE: base_bytes}, local=True
                )
                pub, priv = domain_params.generate_keypair(
                    store=True,
                    label=label,
                    public_template={
                        Attr.ID: pub_id,
                    },
                    private_template={
                        Attr.ID: priv_id,
                        Attr.SENSITIVE: sensitive,
                        Attr.EXTRACTABLE: extractable,
                        Attr.DERIVE: True,
                    },
                )
            else:
                raise CryptographicFailure(f"Key pair generation not supported for {algorithm}")

            log.debug("Generated %s key pair label='%s'", key_type.name, label)
            return pub_id, priv_id
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Key pair generation failed: {e}") from e

    # ── import (register) ────────────────────────────────────────────────────

    @_synchronized
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

    # ── key wrapping (SymmetricKey only — see wrap_key/unwrap_key docstrings) ──

    @_synchronized
    def wrap_key(self, wrapping_cka_id: bytes, target_cka_id: bytes) -> bytes:
        """Wrap a SecretKey using another SecretKey (the KEK) via CKM_AES_KEY_WRAP_PAD.
        Both keys must already exist as PKCS#11 objects on the token; the target
        must have CKA_EXTRACTABLE=True (PKCS#11 requires this for C_WrapKey,
        independent of KMIP's own Extractable attribute)."""
        try:
            kek    = self._find_key(wrapping_cka_id, ObjClass.SECRET_KEY)
            target = self._find_key(target_cka_id, ObjClass.SECRET_KEY)
            return bytes(kek.wrap_key(target, mechanism=Mechanism.AES_KEY_WRAP_PAD))
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Key wrap failed: {e}") from e

    @_synchronized
    def unwrap_key(
        self,
        wrapping_cka_id: bytes,
        wrapped_bytes: bytes,
        target_algorithm: int,
        label: str = "",
        extractable: bool = True,
        sensitive: bool = False,
        encrypt: bool = True,
        decrypt: bool = True,
    ) -> bytes:
        """Unwrap key material directly into a new SecretKey object via
        CKM_AES_KEY_WRAP_PAD — the plaintext never leaves the HSM/server
        boundary into Python memory. Returns the new object's cka_id."""
        target_key_type = ALGO_TO_PKCS11_KEYTYPE.get(target_algorithm)
        if target_key_type is None:
            raise CryptographicFailure(f"Unsupported target algorithm {target_algorithm}")

        try:
            kek = self._find_key(wrapping_cka_id, ObjClass.SECRET_KEY)
            new_id = os.urandom(16)
            # SoftHSM2: SENSITIVE+EXTRACTABLE blocks CKA_VALUE; disable SENSITIVE when extractable
            effective_sensitive = sensitive and not extractable
            kek.unwrap_key(
                ObjClass.SECRET_KEY,
                target_key_type,
                wrapped_bytes,
                id=new_id,
                label=label,
                store=True,
                mechanism=Mechanism.AES_KEY_WRAP_PAD,
                capabilities=self._caps(encrypt, decrypt, False, False),
                template={
                    Attr.SENSITIVE:   effective_sensitive,
                    Attr.EXTRACTABLE: extractable,
                },
            )
            return new_id
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Key unwrap failed: {e}") from e

    @_synchronized
    def import_public_key(
        self,
        algorithm: int,
        der_bytes: bytes,
        key_format_type: int,
        label: str = "",
        verify: bool = True,
    ) -> bytes:
        """Import an externally supplied RSA public key (PKCS#1 DER). Returns cka_id."""
        if algorithm != CryptographicAlgorithm.RSA:
            raise CryptographicFailure(f"Register PublicKey only supports RSA, got algorithm {algorithm}")

        from pkcs11.util.rsa import decode_rsa_public_key
        try:
            template = decode_rsa_public_key(der_bytes, capabilities=MF.VERIFY if verify else MF(0))
        except Exception as exc:
            raise CryptographicFailure(f"Could not parse RSA public key DER: {exc}") from exc

        cka_id = os.urandom(16)
        template.update({
            Attr.ID:    cka_id,
            Attr.LABEL: label,
            Attr.TOKEN: True,
            Attr.VERIFY: verify,
        })
        try:
            self._sess().create_object(template)
            return cka_id
        except pkcs11_exc.PKCS11Error as exc:
            raise CryptographicFailure(f"Public key import failed: {exc}") from exc

    @_synchronized
    def import_private_key(
        self,
        algorithm: int,
        der_bytes: bytes,
        key_format_type: int,
        label: str = "",
        extractable: bool = True,
        sensitive: bool = False,
        sign: bool = True,
    ) -> bytes:
        """Import an externally supplied RSA private key (PKCS#1 or PKCS#8 DER). Returns cka_id."""
        if algorithm != CryptographicAlgorithm.RSA:
            raise CryptographicFailure(f"Register PrivateKey only supports RSA, got algorithm {algorithm}")

        from pkcs11.util.rsa import decode_rsa_private_key
        try:
            if key_format_type == KeyFormatType.PKCS8:
                from asn1crypto.keys import PrivateKeyInfo as _PKInfo
                der_bytes = _PKInfo.load(der_bytes)['private_key'].parsed.dump()
            template = decode_rsa_private_key(der_bytes, capabilities=MF.SIGN if sign else MF(0))
        except Exception as exc:
            raise CryptographicFailure(f"Could not parse RSA private key DER: {exc}") from exc

        cka_id = os.urandom(16)
        template.update({
            Attr.ID:         cka_id,
            Attr.LABEL:      label,
            Attr.TOKEN:      True,
            Attr.SENSITIVE:  sensitive,
            Attr.EXTRACTABLE: extractable,
            Attr.SIGN:       sign,
        })
        try:
            self._sess().create_object(template)
            return cka_id
        except pkcs11_exc.PKCS11Error as exc:
            raise CryptographicFailure(f"Private key import failed: {exc}") from exc

    # ── key retrieval ────────────────────────────────────────────────────────

    def _find_key(self, cka_id: bytes, obj_class=None):
        template = {Attr.ID: cka_id}
        if obj_class:
            template[Attr.CLASS] = obj_class
        for obj in self._sess().get_objects(template):
            return obj
        raise ItemNotFound(f"PKCS#11 object with CKA_ID not found")

    @_synchronized
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

    @_synchronized
    def get_public_key_der(self, cka_id: bytes) -> bytes:
        """Export public key material.
        RSA: PKCS#1 DER (via python-pkcs11 component encoding).
        EC (ECDSA/ECDH): raw CKA_EC_POINT.
        DH: raw CKA_VALUE (the public value y = g^x mod p).
        """
        try:
            key = self._find_key(cka_id, ObjClass.PUBLIC_KEY)
            from pkcs11.util.rsa import encode_rsa_public_key
            try:
                return encode_rsa_public_key(key)
            except Exception:
                pass
            try:
                return bytes(key[Attr.EC_POINT])
            except (pkcs11_exc.AttributeTypeInvalid, AttributeError, TypeError):
                pass
            return bytes(key[Attr.VALUE])
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(str(e)) from e

    @_synchronized
    def get_private_key_der(self, cka_id: bytes) -> bytes:
        """Export private key material (only if extractable).
        RSA: returns PKCS#1 DER via python-pkcs11 component encoding.
        EC: returns raw CKA_VALUE (private key scalar bytes).
        """
        try:
            key = self._find_key(cka_id, ObjClass.PRIVATE_KEY)
            try:
                extractable = key[Attr.EXTRACTABLE]
            except Exception:
                extractable = False
            if not extractable:
                raise NotExtractable("Private key is not extractable")
            # RSA: build PKCS#1 DER from individual CKA components via asn1crypto
            try:
                from asn1crypto.keys import RSAPrivateKey as _RSAKey
                n  = int.from_bytes(bytes(key[Attr.MODULUS]),          'big')
                e  = int.from_bytes(bytes(key[Attr.PUBLIC_EXPONENT]),  'big')
                d  = int.from_bytes(bytes(key[Attr.PRIVATE_EXPONENT]), 'big')
                p  = int.from_bytes(bytes(key[Attr.PRIME_1]),          'big')
                q  = int.from_bytes(bytes(key[Attr.PRIME_2]),          'big')
                dp = int.from_bytes(bytes(key[Attr.EXPONENT_1]),       'big')
                dq = int.from_bytes(bytes(key[Attr.EXPONENT_2]),       'big')
                qi = int.from_bytes(bytes(key[Attr.COEFFICIENT]),      'big')
                return _RSAKey({
                    'version':          'two-prime',
                    'modulus':          n,
                    'public_exponent':  e,
                    'private_exponent': d,
                    'prime1':           p,
                    'prime2':           q,
                    'exponent1':        dp,
                    'exponent2':        dq,
                    'coefficient':      qi,
                }).dump()
            except Exception:
                pass
            # EC / other: CKA_VALUE holds raw private key scalar
            try:
                val = key[Attr.VALUE]
                if val is not None:
                    return bytes(val)
            except (pkcs11_exc.AttributeSensitive, pkcs11_exc.AttributeTypeInvalid,
                    AttributeError, TypeError):
                pass
            raise NotExtractable("Private key material is not readable from token")
        except (NotExtractable, CryptographicFailure):
            raise
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(str(e)) from e

    # ── destroy ──────────────────────────────────────────────────────────────

    @_synchronized
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

    @_synchronized
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
            key      = self._find_key(cka_id, ObjClass.SECRET_KEY)
            key_type = self._key_type(key)
            mech     = self._resolve_mech(mechanism_id, key_type)
            self._require_mechanism(mech, "Encrypt")

            if mech in (Mechanism.AES_GCM, Mechanism.AES_CCM):
                # Both GCM and CCM are AEAD modes returning (ciphertext, tag).
                # CCM uses the same GCMParams layout here; real hardware may need
                # a dedicated CK_CCM_PARAMS struct if the HSM enforces strict typing.
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
                # CBC, ECB, CFB128, OFB, DES/3DES CBC/ECB: IV as raw bytes
                ct = key.encrypt(plaintext, mechanism=mech, mechanism_param=iv or None)
                return bytes(ct), None
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Encrypt failed: {e}") from e

    @_synchronized
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
            key      = self._find_key(cka_id, ObjClass.SECRET_KEY)
            key_type = self._key_type(key)
            mech     = self._resolve_mech(mechanism_id, key_type)
            self._require_mechanism(mech, "Decrypt")

            if mech in (Mechanism.AES_GCM, Mechanism.AES_CCM):
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
                # CBC, ECB, CFB128, OFB, DES/3DES CBC/ECB: IV as raw bytes
                pt = key.decrypt(ciphertext, mechanism=mech, mechanism_param=iv or None)
            return bytes(pt)
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Decrypt failed: {e}") from e

    # ── sign / verify ────────────────────────────────────────────────────────

    @_synchronized
    def sign(self, cka_id: bytes, data: bytes, mechanism=None) -> bytes:
        try:
            key = self._find_key(cka_id, ObjClass.PRIVATE_KEY)
            mech = mechanism or Mechanism.RSA_PKCS
            sig = key.sign(data, mechanism=mech)
            return bytes(sig)
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Sign failed: {e}") from e

    @_synchronized
    def verify(self, cka_id: bytes, data: bytes, signature: bytes, mechanism=None) -> bool:
        try:
            key    = self._find_key(cka_id, ObjClass.PUBLIC_KEY)
            mech   = mechanism or Mechanism.RSA_PKCS
            result = key.verify(data, signature, mechanism=mech)
            # python-pkcs11 raises SignatureInvalid for some mechanisms but
            # returns a bool directly for others (e.g. DSA) — honor whichever.
            return True if result is None else bool(result)
        except pkcs11_exc.SignatureInvalid:
            return False
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Verify failed: {e}") from e

    # ── MAC / hash ───────────────────────────────────────────────────────────

    @_synchronized
    def mac(self, cka_id: bytes, data: bytes, mechanism=None) -> bytes:
        try:
            key  = self._find_key(cka_id, ObjClass.SECRET_KEY)
            mech = mechanism or Mechanism.SHA256_HMAC
            self._require_mechanism(mech, "MAC")
            return bytes(key.sign(data, mechanism=mech))
        except (NotExtractable, CryptographicFailure, OperationNotSupported):
            raise
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"MAC failed: {e}") from e

    @_synchronized
    def mac_verify(self, cka_id: bytes, data: bytes, mac_value: bytes, mechanism=None) -> bool:
        try:
            key    = self._find_key(cka_id, ObjClass.SECRET_KEY)
            mech   = mechanism or Mechanism.SHA256_HMAC
            self._require_mechanism(mech, "MACVerify")
            result = key.verify(data, mac_value, mechanism=mech)
            # python-pkcs11 raises SignatureInvalid for asymmetric mechanisms but
            # returns a bool directly for HMAC/MAC mechanisms — honor whichever.
            return True if result is None else bool(result)
        except pkcs11_exc.SignatureInvalid:
            return False
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"MACVerify failed: {e}") from e

    @_synchronized
    def hash_data(self, data: bytes, hash_alg: int) -> bytes:
        mech = HASH_ALG_TO_MECH.get(hash_alg)
        if mech is None:
            raise CryptographicFailure(f"Unsupported HashingAlgorithm {hash_alg}")
        self._require_mechanism(mech, "Hash")
        try:
            return bytes(self._sess().digest(data, mechanism=mech))
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"Hash failed: {e}") from e

    # ── key agreement / derive ──────────────────────────────────────────────

    @_synchronized
    def derive_key(
        self,
        cka_id: bytes,
        base_algorithm: int,
        peer_value: bytes,
        target_algorithm: int,
        target_length_bits: int,
        label: str = "",
        extractable: bool = False,
        sensitive: bool = True,
        encrypt: bool = True,
        decrypt: bool = True,
    ) -> bytes:
        """Derive a symmetric key from a DH/ECDH private key and a peer's public
        value. Returns the cka_id of the newly derived (and stored) key."""
        target_key_type = ALGO_TO_PKCS11_KEYTYPE.get(target_algorithm)
        if target_key_type is None:
            raise CryptographicFailure(f"Unsupported target algorithm {target_algorithm}")

        if base_algorithm == CryptographicAlgorithm.DH:
            mechanism, mechanism_param = Mechanism.DH_PKCS_DERIVE, peer_value
        elif base_algorithm == CryptographicAlgorithm.ECDH:
            from pkcs11.mechanisms import KDF
            mechanism, mechanism_param = Mechanism.ECDH1_DERIVE, (KDF.NULL, None, peer_value)
        else:
            raise CryptographicFailure(
                f"DeriveKey via key agreement not supported for base algorithm {base_algorithm}"
            )

        try:
            key = self._find_key(cka_id, ObjClass.PRIVATE_KEY)
            new_id = os.urandom(16)
            # SoftHSM2: SENSITIVE+EXTRACTABLE blocks CKA_VALUE; disable SENSITIVE when extractable
            effective_sensitive = sensitive and not extractable
            key.derive_key(
                target_key_type,
                target_length_bits,
                id=new_id,
                label=label,
                store=True,
                mechanism=mechanism,
                mechanism_param=mechanism_param,
                capabilities=self._caps(encrypt, decrypt, False, False),
                template={
                    Attr.SENSITIVE:   effective_sensitive,
                    Attr.EXTRACTABLE: extractable,
                },
            )
            return new_id
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"DeriveKey failed: {e}") from e

    # ── random ───────────────────────────────────────────────────────────────

    @_synchronized
    def generate_random(self, length: int) -> bytes:
        try:
            return bytes(self._sess().generate_random(length * 8))
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"RNG failed: {e}") from e

    @_synchronized
    def seed_random(self, seed: bytes) -> None:
        try:
            self._sess().seed_random(seed)
        except pkcs11_exc.PKCS11Error as e:
            raise CryptographicFailure(f"RNG seed failed: {e}") from e

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _key_type(key) -> KT:
        """Read CKA_KEY_TYPE from a PKCS#11 key object; default to AES."""
        try:
            return key[Attr.KEY_TYPE]
        except Exception:
            return KT.AES

    @staticmethod
    def _resolve_mech(mode_id: int, key_type: KT) -> Mechanism:
        """Return the PKCS#11 Mechanism for a KMIP BlockCipherMode + key type."""
        if key_type == KT.DES3:
            return DES3_BLOCKMODE_TO_MECH.get(mode_id, Mechanism.DES3_CBC_PAD)
        if key_type == KT._DES:
            return DES_BLOCKMODE_TO_MECH.get(mode_id, Mechanism(0x0122))  # CKM_DES_CBC
        if key_type == KT.BLOWFISH:
            return BLOWFISH_BLOCKMODE_TO_MECH.get(mode_id, Mechanism.BLOWFISH_CBC_PAD)
        if key_type == KT.TWOFISH:
            return TWOFISH_BLOCKMODE_TO_MECH.get(mode_id, Mechanism.TWOFISH_CBC_PAD)
        return BLOCKMODE_TO_MECH.get(mode_id, Mechanism.AES_CBC_PAD)

    @staticmethod
    def _caps(encrypt, decrypt, wrap, unwrap) -> MechanismFlag:
        flags = MechanismFlag(0)
        if encrypt: flags |= MF.ENCRYPT
        if decrypt: flags |= MF.DECRYPT
        if wrap:    flags |= MF.WRAP
        if unwrap:  flags |= MF.UNWRAP
        return flags

    @_synchronized
    def get_mechanism_list(self):
        if self._initialized:
            return list(self._available_mechanisms)
        try:
            return list(self._token.slot.get_mechanisms())
        except Exception:
            return []

    @_synchronized
    def get_token_info(self):
        try:
            return str(self._token.slot.get_token())
        except Exception:
            return "SoftHSM2 Token"
