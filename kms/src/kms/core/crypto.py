"""
Software cryptographic operations for KMS.

All functions are synchronous (CPU-bound work; no I/O).  They are intended
to be called from async code via ``asyncio.get_event_loop().run_in_executor``
when latency matters, or called directly for small payloads.

Nothing in this module talks to the HSM — see ``kms.core.hsm`` for that.
"""

from __future__ import annotations

import hmac as _stdlib_hmac
import os
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import hmac as _hmac
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate

# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

_CURVE_MAP: dict[str, type[ec.EllipticCurve]] = {
    "P-192": ec.SECP192R1,
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
    "secp256k1": ec.SECP256K1,
}

_HASH_MAP: dict[str, type[hashes.HashAlgorithm]] = {
    "SHA1": hashes.SHA1,
    "SHA224": hashes.SHA224,
    "SHA256": hashes.SHA256,
    "SHA384": hashes.SHA384,
    "SHA512": hashes.SHA512,
}

_GCM_TAG_BYTES = 16


def _get_hash(name: str) -> hashes.HashAlgorithm:
    """Instantiate a hash algorithm by name.  Raises ``ValueError`` if unknown."""
    cls = _HASH_MAP.get(name.upper())
    if cls is None:
        raise ValueError(
            f"Unknown hash algorithm '{name}'. Supported: {list(_HASH_MAP)}"
        )
    return cls()


# ---------------------------------------------------------------------------
# Symmetric key generation
# ---------------------------------------------------------------------------


def generate_aes_key(length_bits: int) -> bytes:
    """Generate an AES key of *length_bits* (128, 192 or 256).

    Returns raw key bytes.
    """
    if length_bits not in (128, 192, 256):
        raise ValueError(f"Invalid AES key length: {length_bits}. Must be 128, 192, or 256.")
    return os.urandom(length_bits // 8)


# ---------------------------------------------------------------------------
# Asymmetric key generation
# ---------------------------------------------------------------------------


def generate_rsa_key_pair(length_bits: int) -> tuple[bytes, bytes]:
    """Generate an RSA key pair of *length_bits* (e.g. 2048 or 4096).

    Returns
    -------
    (private_key_pkcs8_der, public_key_der)
    """
    if length_bits < 2048:
        raise ValueError(f"RSA key length {length_bits} is too short (minimum 2048).")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=length_bits,
        backend=default_backend(),
    )
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_der, public_der


def generate_ec_key_pair(curve_name: str) -> tuple[bytes, bytes]:
    """Generate an EC key pair on the named curve.

    *curve_name* must be one of: ``"P-192"``, ``"P-256"``, ``"P-384"``,
    ``"P-521"``, ``"secp256k1"``.

    Returns
    -------
    (private_key_pkcs8_der, public_key_der)
    """
    curve_cls = _CURVE_MAP.get(curve_name)
    if curve_cls is None:
        raise ValueError(
            f"Unknown EC curve '{curve_name}'. Supported: {list(_CURVE_MAP)}"
        )
    private_key = ec.generate_private_key(curve_cls(), backend=default_backend())
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_der, public_der


def generate_ed25519_key_pair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 key pair.

    Returns
    -------
    (private_key_pkcs8_der, public_key_der)
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_der, public_der


def generate_ed448_key_pair() -> tuple[bytes, bytes]:
    """Generate an Ed448 key pair.

    Returns
    -------
    (private_key_pkcs8_der, public_key_der)
    """
    private_key = ed448.Ed448PrivateKey.generate()
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_der, public_der


# ---------------------------------------------------------------------------
# AES-GCM encrypt / decrypt
# ---------------------------------------------------------------------------


def aes_gcm_encrypt(
    key: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> tuple[bytes, bytes, bytes]:
    """Encrypt *plaintext* with AES-GCM.

    Returns
    -------
    (ciphertext, iv, tag)

    IV is 12 random bytes.  The tag is 16 bytes.  ciphertext does **not**
    include the IV or tag.
    """
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext || tag  (tag = last 16 bytes)
    combined = aesgcm.encrypt(iv, plaintext, aad)
    ciphertext = combined[:-_GCM_TAG_BYTES]
    tag = combined[-_GCM_TAG_BYTES:]
    return ciphertext, iv, tag


def aes_gcm_decrypt(
    key: bytes,
    ciphertext: bytes,
    iv: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> bytes:
    """Decrypt AES-GCM.

    Raises ``cryptography.exceptions.InvalidTag`` (a subclass of
    ``ValueError``) if authentication fails.
    """
    aesgcm = AESGCM(key)
    combined = ciphertext + tag
    return aesgcm.decrypt(iv, combined, aad)


# ---------------------------------------------------------------------------
# RSA encrypt / decrypt / sign / verify
# ---------------------------------------------------------------------------


def _load_rsa_private_key(der: bytes):
    return serialization.load_der_private_key(der, password=None, backend=default_backend())


def _load_rsa_public_key(der: bytes):
    return serialization.load_der_public_key(der, backend=default_backend())


def rsa_encrypt(public_key_der: bytes, plaintext: bytes) -> bytes:
    """RSA-OAEP-SHA256 encryption."""
    public_key = _load_rsa_public_key(public_key_der)
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key_der: bytes, ciphertext: bytes) -> bytes:
    """RSA-OAEP-SHA256 decryption."""
    private_key = _load_rsa_private_key(private_key_der)
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_sign(
    private_key_der: bytes,
    data: bytes,
    hash_algo: str = "SHA256",
) -> bytes:
    """RSA-PSS signature.

    Returns DER-encoded signature bytes.
    """
    private_key = _load_rsa_private_key(private_key_der)
    hash_obj = _get_hash(hash_algo)
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hash_obj),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hash_obj,
    )


def rsa_verify(
    public_key_der: bytes,
    data: bytes,
    signature: bytes,
    hash_algo: str = "SHA256",
) -> bool:
    """RSA-PSS verification.

    Returns ``True`` if the signature is valid, ``False`` otherwise.
    """
    public_key = _load_rsa_public_key(public_key_der)
    hash_obj = _get_hash(hash_algo)
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hash_obj),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hash_obj,
        )
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# EC sign / verify
# ---------------------------------------------------------------------------


def _load_ec_private_key(der: bytes):
    return serialization.load_der_private_key(der, password=None, backend=default_backend())


def _load_ec_public_key(der: bytes):
    return serialization.load_der_public_key(der, backend=default_backend())


def ec_sign(
    private_key_der: bytes,
    data: bytes,
    hash_algo: str = "SHA256",
) -> bytes:
    """ECDSA signature, DER-encoded.

    Works for both EC and Ed25519 / Ed448 private keys (EdDSA uses prehash=False
    and ignores the ``hash_algo`` parameter).
    """
    private_key = serialization.load_der_private_key(
        private_key_der, password=None, backend=default_backend()
    )

    if isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        # EdDSA does not accept a separate hash algorithm
        return private_key.sign(data)

    hash_obj = _get_hash(hash_algo)
    return private_key.sign(data, ec.ECDSA(hash_obj))


def ec_verify(
    public_key_der: bytes,
    data: bytes,
    signature: bytes,
    hash_algo: str = "SHA256",
) -> bool:
    """ECDSA verification.  Returns ``True`` if valid."""
    public_key = serialization.load_der_public_key(
        public_key_der, backend=default_backend()
    )

    try:
        if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signature, data)
            return True

        hash_obj = _get_hash(hash_algo)
        public_key.verify(signature, data, ec.ECDSA(hash_obj))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def derive_key_hkdf(
    input_key: bytes,
    length: int,
    salt: bytes = b"",
    info: bytes = b"",
) -> bytes:
    """HKDF-SHA256 key derivation.

    Parameters
    ----------
    input_key:
        The input keying material (IKM).
    length:
        Desired output length in bytes.
    salt:
        Optional salt (empty bytes → HKDF uses the zero-filled salt).
    info:
        Optional context / application-specific information.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt if salt else None,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(input_key)


def derive_key_pbkdf2(
    password: bytes,
    salt: bytes,
    iterations: int,
    length: int,
) -> bytes:
    """PBKDF2-SHA256 key derivation.

    Parameters
    ----------
    password:
        Password / passphrase bytes.
    salt:
        Cryptographic salt (should be at least 16 bytes).
    iterations:
        Iteration count (NIST recommends ≥ 600 000 for SHA-256 in 2023).
    length:
        Derived key length in bytes.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(password)


# ---------------------------------------------------------------------------
# HMAC
# ---------------------------------------------------------------------------


def hmac_generate(
    key: bytes,
    data: bytes,
    hash_algo: str = "SHA256",
) -> bytes:
    """Compute an HMAC over *data* using *key*."""
    h = _hmac.HMAC(key, _get_hash(hash_algo), backend=default_backend())
    h.update(data)
    return h.finalize()


def hmac_verify(
    key: bytes,
    data: bytes,
    mac: bytes,
    hash_algo: str = "SHA256",
) -> bool:
    """Constant-time HMAC verification.

    Returns ``True`` if *mac* matches the HMAC of *data* under *key*.
    """
    expected = hmac_generate(key, data, hash_algo)
    return _stdlib_hmac.compare_digest(expected, mac)


# ---------------------------------------------------------------------------
# Certificate parsing
# ---------------------------------------------------------------------------


def parse_certificate_info(cert_der: bytes) -> dict[str, Any]:
    """Parse a DER-encoded X.509 certificate.

    Returns a dict containing:
    ``subject``, ``issuer``, ``serial_number``, ``not_valid_before``,
    ``not_valid_after``, ``san`` (Subject Alternative Names list).
    """
    from cryptography import x509 as _x509

    cert = load_der_x509_certificate(cert_der, backend=default_backend())

    def _rdn_to_str(name: _x509.Name) -> str:
        return ", ".join(
            f"{attr.oid.dotted_string if attr.oid._name == 'Unknown OID' else attr.oid._name}={attr.value}"
            for attr in name
        )

    # Subject Alternative Names
    san: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
        for general_name in san_ext.value:
            if isinstance(general_name, _x509.DNSName):
                san.append(f"DNS:{general_name.value}")
            elif isinstance(general_name, _x509.IPAddress):
                san.append(f"IP:{general_name.value}")
            elif isinstance(general_name, _x509.RFC822Name):
                san.append(f"email:{general_name.value}")
            elif isinstance(general_name, _x509.UniformResourceIdentifier):
                san.append(f"URI:{general_name.value}")
            else:
                san.append(str(general_name))
    except _x509.ExtensionNotFound:
        pass

    return {
        "subject": _rdn_to_str(cert.subject),
        "issuer": _rdn_to_str(cert.issuer),
        "serial_number": str(cert.serial_number),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "san": san,
    }


# ---------------------------------------------------------------------------
# Random bytes
# ---------------------------------------------------------------------------


def generate_random(length: int) -> bytes:
    """Generate *length* cryptographically random bytes using ``os.urandom``."""
    if length <= 0:
        raise ValueError(f"Length must be positive, got {length}")
    return os.urandom(length)
