"""Envelope encryption for metadata-store BLOBs.

Most managed objects keep their secret bytes on the HSM and the metadata store
holds only a `_pkcs11_cka_id` reference. A few object types cannot work that
way — SecretData, OpaqueObject and SplitKey shares are raw byte payloads with
no PKCS#11 object behind them — so their material lands in
`kmip_objects.raw_key_value`. Until now it landed there in the clear, which
meant a copy of the database file exposed those secrets outright.

This module encrypts those blobs under an AES-256 master key that is generated
on, and never leaves, the HSM. A stolen database yields ciphertext only; the
key to read it lives behind the PKCS#11 boundary.

Envelope layout (all fixed-width except the trailing ciphertext):

    b'\\x01'      1 byte    format version
    key_id       8 bytes   identifies which master key encrypted this blob
    nonce       12 bytes   per-blob random GCM nonce
    tag         16 bytes   GCM authentication tag
    ciphertext  N bytes

Carrying `key_id` is what makes rotation safe: re-encrypting a large store is
not atomic, so during a rotation the table legitimately holds blobs under both
the old and new key, and each row still says which one it needs. The old key is
destroyed only as a separate, explicit step once re-encryption has completed.
"""

import logging
import os
import struct

from ..core.enums import BlockCipherMode, CryptographicAlgorithm, CryptographicUsageMask
from ..core.exceptions import CryptographicFailure

log = logging.getLogger(__name__)

# Master keys are discovered on the token by this label prefix, and carry a
# monotonically increasing generation suffix: kmip-master-1, kmip-master-2, …
MASTER_KEY_LABEL_PREFIX = "kmip-master-"

_VERSION = 1
_KEYID_LEN = 8
_NONCE_LEN = 12
_TAG_LEN = 16
_HEADER = struct.Struct(">B8s12s16s")   # version, key_id, nonce, tag
_HEADER_LEN = _HEADER.size


def _key_id(cka_id: bytes) -> bytes:
    """Stable short identifier for a master key, derived from its CKA_ID."""
    return cka_id[:_KEYID_LEN].ljust(_KEYID_LEN, b"\x00")


def _generation(label: str) -> int:
    try:
        return int(label[len(MASTER_KEY_LABEL_PREFIX):])
    except (ValueError, IndexError):
        return 0


class BlobCipher:
    """Encrypts/decrypts metadata BLOBs under an HSM-resident master key.

    Discovers existing master keys on the token at construction, generating a
    first one if none exist. Every known master key stays usable for decryption
    so that a partially-rotated store remains fully readable; only the newest
    is used to encrypt.
    """

    def __init__(self, shim, auto_provision: bool = True):
        self._shim = shim
        self._keys = {}          # key_id -> cka_id, every key we can decrypt with
        self._active_cka_id = None
        self._active_generation = 0
        self._load_keys(auto_provision=auto_provision)

    # ── master key lifecycle ────────────────────────────────────────────────

    def _load_keys(self, auto_provision: bool):
        # Master-key labels are a dense sequence (kmip-master-1, -2, …), so
        # probing successive generations by exact label is far cheaper than
        # enumerating every secret key on the token and filtering — tokens in
        # real use hold thousands of keys. Stop at the first gap.
        generation = 1
        while True:
            cka_id = self._shim.find_secret_key_by_label(
                f"{MASTER_KEY_LABEL_PREFIX}{generation}")
            if cka_id is None:
                break
            self._keys[_key_id(cka_id)] = cka_id
            self._active_generation = generation
            self._active_cka_id = cka_id
            generation += 1

        if self._active_cka_id is None:
            if not auto_provision:
                raise CryptographicFailure("No master key present on the token")
            self._active_cka_id = self._generate_master_key(1)
            self._active_generation = 1
            self._keys[_key_id(self._active_cka_id)] = self._active_cka_id
            log.info("Provisioned master key %s1", MASTER_KEY_LABEL_PREFIX)

    def _generate_master_key(self, generation: int) -> bytes:
        """Create a new AES-256 master key on the token. Deliberately
        non-extractable and sensitive: it is only ever used *through* the HSM,
        so there is no reason for its bytes to be readable."""
        _, cka_id = self._shim.generate_symmetric_key(
            algorithm=CryptographicAlgorithm.AES,
            length_bits=256,
            label=f"{MASTER_KEY_LABEL_PREFIX}{generation}",
            extractable=False,
            sensitive=True,
            encrypt=True,
            decrypt=True,
        )
        return cka_id

    @property
    def active_key_id(self) -> bytes:
        return _key_id(self._active_cka_id)

    def known_key_ids(self):
        return set(self._keys)

    # ── envelope ────────────────────────────────────────────────────────────

    def encrypt(self, plaintext: bytes) -> bytes:
        """Wrap plaintext in an envelope under the active master key."""
        if plaintext is None:
            return None
        nonce = os.urandom(_NONCE_LEN)
        ciphertext, tag = self._shim.encrypt(
            self._active_cka_id, bytes(plaintext),
            mechanism_id=BlockCipherMode.GCM, iv=nonce,
        )
        if tag is None or len(tag) != _TAG_LEN:
            raise CryptographicFailure("Master key encryption returned no authentication tag")
        return _HEADER.pack(_VERSION, self.active_key_id, nonce, tag) + ciphertext

    def decrypt(self, blob: bytes) -> bytes:
        """Unwrap an envelope. Raises CryptographicFailure if the envelope is
        malformed, was written under a master key this token no longer holds,
        or fails its GCM authentication check — never silently returns the raw
        bytes, which would turn a tampered row into apparent plaintext."""
        if blob is None:
            return None
        blob = bytes(blob)
        if len(blob) < _HEADER_LEN:
            raise CryptographicFailure("Encrypted blob is shorter than its envelope header")

        version, key_id, nonce, tag = _HEADER.unpack_from(blob, 0)
        if version != _VERSION:
            raise CryptographicFailure(f"Unsupported blob envelope version {version}")

        cka_id = self._keys.get(key_id)
        if cka_id is None:
            raise CryptographicFailure(
                f"Blob was encrypted under master key {key_id.hex()}, which is not on this token"
            )

        return self._shim.decrypt(
            cka_id, blob[_HEADER_LEN:],
            mechanism_id=BlockCipherMode.GCM, iv=nonce, tag=tag,
        )

    # ── rotation ────────────────────────────────────────────────────────────

    def begin_rotation(self) -> bytes:
        """Generate the next master key and make it active. Previous keys stay
        loaded, so rows not yet re-encrypted remain readable. Returns the
        key_id of the key that was active before this call."""
        previous = self.active_key_id
        generation = self._active_generation + 1
        cka_id = self._generate_master_key(generation)
        self._keys[_key_id(cka_id)] = cka_id
        self._active_cka_id = cka_id
        self._active_generation = generation
        log.info("Rotated to master key %s%d", MASTER_KEY_LABEL_PREFIX, generation)
        return previous

    def retire_key(self, key_id: bytes) -> None:
        """Destroy a superseded master key. Only safe once nothing references
        it — MetadataStore.rotate_master_key() checks that before calling."""
        cka_id = self._keys.pop(key_id, None)
        if cka_id is None:
            return
        if cka_id == self._active_cka_id:
            raise CryptographicFailure("Refusing to retire the active master key")
        from pkcs11.constants import ObjectClass
        self._shim.destroy_object(cka_id, ObjectClass.SECRET_KEY)
        log.info("Retired master key %s", key_id.hex())
