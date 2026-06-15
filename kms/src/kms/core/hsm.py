"""
HSM connector for KMS using python-pkcs11 / SoftHSM2.

This module is the single point of contact for:
- The KEK (Key Encryption Key) that lives permanently in the HSM token.
- Wrapping / unwrapping other key material using the KEK.
- Optional generation of keys directly in the HSM.

All public methods are async; blocking PKCS#11 calls are dispatched to a
thread-pool executor so they don't block the asyncio event loop.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import (
    MultipleObjectsReturned,
    NoSuchKey,
    PKCS11Error,
    TokenNotPresent,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from kms.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GCM_TAG_BITS = 128
_GCM_TAG_BYTES = _GCM_TAG_BITS // 8
_AES_KEY_BYTES = 32  # 256-bit KEK


def _find_kek_sync(session: pkcs11.Session) -> pkcs11.Object:
    """Find the KEK inside an already-open PKCS#11 session (synchronous)."""
    keys = list(
        session.get_objects(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.LABEL: settings.kek_label,
                Attribute.ID: settings.kek_id,
            }
        )
    )
    if not keys:
        raise NoSuchKey(f"KEK '{settings.kek_label}' not found in token")
    if len(keys) > 1:
        raise MultipleObjectsReturned(
            f"Multiple objects match KEK label '{settings.kek_label}'"
        )
    return keys[0]


# ---------------------------------------------------------------------------
# HsmConnector
# ---------------------------------------------------------------------------


class HsmConnector:
    """Thread-safe async wrapper around python-pkcs11 for SoftHSM2.

    Initialization flow
    -------------------
    1. Call ``await connector.initialize()`` once at startup.
    2. Optionally call ``await connector.ensure_kek()`` to guarantee the KEK
       exists in the token.

    All public methods are safe to call from any coroutine; blocking work is
    dispatched via ``asyncio.get_event_loop().run_in_executor``.
    """

    def __init__(self) -> None:
        self._lib: pkcs11.lib | None = None
        self._token: pkcs11.Token | None = None
        self._lock: asyncio.Lock = asyncio.Lock()
        self._initialized: bool = False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run(self, fn, *args, **kwargs):
        """Run a synchronous callable in a thread-pool executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: fn(*args, **kwargs))

    def _open_session_sync(self, rw: bool = False) -> pkcs11.Session:
        """Open a user session against the token (synchronous)."""
        if self._token is None:
            raise RuntimeError("HSM not initialized — call initialize() first")
        return self._token.open(user_pin=settings.pkcs11_pin, rw=rw)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Load the PKCS#11 library and locate the token.

        Must be called once before any other method.  Idempotent.
        """
        async with self._lock:
            if self._initialized:
                return

            def _init_sync():
                lib = pkcs11.lib(settings.pkcs11_lib)
                token = lib.get_token(token_label=settings.pkcs11_token_label)
                return lib, token

            self._lib, self._token = await self._run(_init_sync)
            self._initialized = True
            logger.info(
                "HSM initialized: lib=%s token=%s",
                settings.pkcs11_lib,
                settings.pkcs11_token_label,
            )

    async def ensure_kek(self) -> None:
        """Ensure a KEK exists in the HSM token.  If not, generate one.

        Called once at startup.  Safe to call multiple times.
        """
        async with self._lock:
            def _ensure_sync():
                with self._open_session_sync(rw=True) as session:
                    try:
                        _find_kek_sync(session)
                        logger.info("KEK '%s' already exists in token.", settings.kek_label)
                        return False  # already existed
                    except NoSuchKey:
                        pass

                    # Generate the KEK
                    session.generate_key(
                        KeyType.AES,
                        256,
                        id=settings.kek_id,
                        label=settings.kek_label,
                        store=True,
                        template={
                            Attribute.SENSITIVE: True,
                            Attribute.EXTRACTABLE: False,
                            Attribute.ENCRYPT: True,
                            Attribute.DECRYPT: True,
                            Attribute.WRAP: True,
                            Attribute.UNWRAP: True,
                            Attribute.TOKEN: True,
                            Attribute.PRIVATE: True,
                        },
                    )
                    logger.info("KEK '%s' generated and stored in token.", settings.kek_label)
                    return True  # newly created

            await self._run(_ensure_sync)

    # ------------------------------------------------------------------
    # Wrap / unwrap key material
    # ------------------------------------------------------------------

    async def wrap_key(self, key_material: bytes) -> tuple[bytes, bytes, bytes]:
        """Encrypt *key_material* with AES-256-GCM using the KEK from the HSM.

        Strategy
        --------
        1. Try native PKCS#11 AES-GCM via ``Mechanism.AES_GCM``.
        2. If that is not supported (e.g. older SoftHSM2 builds), fall back to
           the ``cryptography`` library's ``AESGCM`` with the KEK value
           exported from the HSM (requires ``CKA_SENSITIVE=False`` on the KEK,
           see ``ensure_kek`` for the hard path; here we gracefully fall back).

        Returns
        -------
        (ciphertext, iv, tag)  — all as separate ``bytes`` objects.
        """
        async with self._lock:
            iv = os.urandom(12)

            def _wrap_sync():
                with self._open_session_sync(rw=False) as session:
                    kek = _find_kek_sync(session)

                    # ---- Path 1: native PKCS#11 AES-GCM -------------------
                    try:
                        # python-pkcs11 AES-GCM mechanism_param = (iv, aad, tag_bits)
                        raw = kek.encrypt(
                            key_material,
                            mechanism=Mechanism.AES_GCM,
                            mechanism_param=(iv, b"", _GCM_TAG_BITS),
                        )
                        # python-pkcs11 appends the tag to the ciphertext
                        ciphertext = raw[:-_GCM_TAG_BYTES]
                        tag = raw[-_GCM_TAG_BYTES:]
                        return ciphertext, iv, tag
                    except (PKCS11Error, AttributeError, NotImplementedError) as exc:
                        logger.debug(
                            "Native AES-GCM not available (%s); using software fallback.", exc
                        )

                    # ---- Path 2: software AES-GCM with extracted KEK value -
                    try:
                        kek_bytes = kek[Attribute.VALUE]
                    except Exception as exc:
                        raise RuntimeError(
                            "KEK is not extractable and native AES-GCM is unavailable. "
                            "Cannot wrap key material."
                        ) from exc

                    aesgcm = AESGCM(kek_bytes)
                    # AESGCM.encrypt returns ciphertext + tag (tag is last 16 bytes)
                    combined = aesgcm.encrypt(iv, key_material, b"")
                    ciphertext = combined[:-_GCM_TAG_BYTES]
                    tag = combined[-_GCM_TAG_BYTES:]
                    return ciphertext, iv, tag

            return await self._run(_wrap_sync)

    async def unwrap_key(self, ciphertext: bytes, iv: bytes, tag: bytes) -> bytes:
        """Decrypt *ciphertext* using the KEK.  Returns plaintext key material."""
        async with self._lock:
            def _unwrap_sync():
                with self._open_session_sync(rw=False) as session:
                    kek = _find_kek_sync(session)

                    # ---- Path 1: native PKCS#11 AES-GCM -------------------
                    try:
                        combined = ciphertext + tag
                        plaintext = kek.decrypt(
                            combined,
                            mechanism=Mechanism.AES_GCM,
                            mechanism_param=(iv, b"", _GCM_TAG_BITS),
                        )
                        return plaintext
                    except (PKCS11Error, AttributeError, NotImplementedError) as exc:
                        logger.debug(
                            "Native AES-GCM decrypt not available (%s); using software fallback.",
                            exc,
                        )

                    # ---- Path 2: software fallback -------------------------
                    try:
                        kek_bytes = kek[Attribute.VALUE]
                    except Exception as exc:
                        raise RuntimeError(
                            "KEK is not extractable and native AES-GCM is unavailable. "
                            "Cannot unwrap key material."
                        ) from exc

                    aesgcm = AESGCM(kek_bytes)
                    combined = ciphertext + tag
                    return aesgcm.decrypt(iv, combined, b"")

            return await self._run(_unwrap_sync)

    # ------------------------------------------------------------------
    # HSM-resident key generation and operations
    # ------------------------------------------------------------------

    async def generate_aes_key_in_hsm(
        self,
        length: int,
        label: str,
        key_id: bytes,
        usage_mask: int,
    ) -> bytes:
        """Generate an AES key directly inside the HSM.

        Parameters
        ----------
        length:
            Key length in *bits* (128, 192 or 256).
        label:
            PKCS#11 ``CKA_LABEL`` for the new key.
        key_id:
            ``CKA_ID`` bytes to use (and return).
        usage_mask:
            KMIP cryptographic usage mask (used to derive PKCS#11 capabilities).

        Returns
        -------
        The ``CKA_ID`` (``key_id``) that was used.
        """
        async with self._lock:
            def _gen_sync():
                # Derive basic PKCS#11 attributes from the KMIP usage mask.
                # KMIP usage mask bit definitions (KMIP 2.0 §9.1.3.2.19):
                #   0x0001 = Sign,  0x0002 = Verify,  0x0004 = Encrypt,
                #   0x0008 = Decrypt, 0x0010 = Wrap Key, 0x0020 = Unwrap Key
                can_encrypt = bool(usage_mask & 0x0004)
                can_decrypt = bool(usage_mask & 0x0008)
                can_wrap = bool(usage_mask & 0x0010)
                can_unwrap = bool(usage_mask & 0x0020)

                template = {
                    Attribute.SENSITIVE: True,
                    Attribute.EXTRACTABLE: False,
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: True,
                    Attribute.ENCRYPT: can_encrypt,
                    Attribute.DECRYPT: can_decrypt,
                    Attribute.WRAP: can_wrap,
                    Attribute.UNWRAP: can_unwrap,
                }

                with self._open_session_sync(rw=True) as session:
                    session.generate_key(
                        KeyType.AES,
                        length,
                        id=key_id,
                        label=label,
                        store=True,
                        template=template,
                    )
                return key_id

            return await self._run(_gen_sync)

    async def get_hsm_aes_key(self, key_id: bytes) -> Any:
        """Get a reference to an HSM key object by ``CKA_ID``.

        Returns the raw python-pkcs11 key object.  The caller must keep the
        session alive for as long as the object is used; this method returns
        the key in a detached manner suited only for attribute inspection.
        """
        async with self._lock:
            def _get_sync():
                with self._open_session_sync(rw=False) as session:
                    keys = list(
                        session.get_objects(
                            {
                                Attribute.CLASS: ObjectClass.SECRET_KEY,
                                Attribute.ID: key_id,
                            }
                        )
                    )
                    if not keys:
                        raise NoSuchKey(f"No key with id={key_id!r} in token")
                    if len(keys) > 1:
                        raise MultipleObjectsReturned(
                            f"Multiple keys with id={key_id!r}"
                        )
                    return keys[0]

            return await self._run(_get_sync)

    async def hsm_encrypt(
        self,
        key_id: bytes,
        plaintext: bytes,
        iv: bytes | None = None,
    ) -> tuple[bytes, bytes, bytes]:
        """Encrypt *plaintext* using an HSM-resident AES key (AES-256-GCM).

        Returns (ciphertext, iv, tag).
        """
        async with self._lock:
            if iv is None:
                iv = os.urandom(12)

            def _enc_sync():
                with self._open_session_sync(rw=False) as session:
                    keys = list(
                        session.get_objects(
                            {
                                Attribute.CLASS: ObjectClass.SECRET_KEY,
                                Attribute.ID: key_id,
                            }
                        )
                    )
                    if not keys:
                        raise NoSuchKey(f"No key with id={key_id!r}")
                    key = keys[0]

                    try:
                        raw = key.encrypt(
                            plaintext,
                            mechanism=Mechanism.AES_GCM,
                            mechanism_param=(iv, b"", _GCM_TAG_BITS),
                        )
                        ciphertext = raw[:-_GCM_TAG_BYTES]
                        tag = raw[-_GCM_TAG_BYTES:]
                        return ciphertext, iv, tag
                    except (PKCS11Error, AttributeError, NotImplementedError):
                        # Software fallback using extracted key value
                        key_bytes = key[Attribute.VALUE]
                        aesgcm = AESGCM(key_bytes)
                        combined = aesgcm.encrypt(iv, plaintext, b"")
                        return combined[:-_GCM_TAG_BYTES], iv, combined[-_GCM_TAG_BYTES:]

            return await self._run(_enc_sync)

    async def hsm_decrypt(
        self,
        key_id: bytes,
        ciphertext: bytes,
        iv: bytes,
        tag: bytes,
    ) -> bytes:
        """Decrypt *ciphertext* using an HSM-resident AES key."""
        async with self._lock:
            def _dec_sync():
                with self._open_session_sync(rw=False) as session:
                    keys = list(
                        session.get_objects(
                            {
                                Attribute.CLASS: ObjectClass.SECRET_KEY,
                                Attribute.ID: key_id,
                            }
                        )
                    )
                    if not keys:
                        raise NoSuchKey(f"No key with id={key_id!r}")
                    key = keys[0]

                    try:
                        combined = ciphertext + tag
                        return key.decrypt(
                            combined,
                            mechanism=Mechanism.AES_GCM,
                            mechanism_param=(iv, b"", _GCM_TAG_BITS),
                        )
                    except (PKCS11Error, AttributeError, NotImplementedError):
                        key_bytes = key[Attribute.VALUE]
                        aesgcm = AESGCM(key_bytes)
                        return aesgcm.decrypt(iv, ciphertext + tag, b"")

            return await self._run(_dec_sync)

    # ------------------------------------------------------------------
    # Status / health
    # ------------------------------------------------------------------

    async def status(self) -> dict:
        """Return a dict with HSM status info.

        Keys: ``token_label``, ``slot_id``, ``mechanism_count``, ``kek_present``.
        """
        async with self._lock:
            def _status_sync():
                if self._token is None:
                    return {
                        "token_label": None,
                        "slot_id": None,
                        "mechanism_count": 0,
                        "kek_present": False,
                        "error": "Not initialized",
                    }
                try:
                    slot = self._token.slot
                    mechanisms = list(slot.get_mechanisms())
                    slot_id = slot.slot_id
                except Exception as exc:
                    slot_id = None
                    mechanisms = []
                    logger.warning("Could not query slot info: %s", exc)

                kek_present = False
                try:
                    with self._open_session_sync(rw=False) as session:
                        _find_kek_sync(session)
                        kek_present = True
                except (NoSuchKey, TokenNotPresent, PKCS11Error):
                    pass

                return {
                    "token_label": settings.pkcs11_token_label,
                    "slot_id": slot_id,
                    "mechanism_count": len(mechanisms),
                    "kek_present": kek_present,
                }

            return await self._run(_status_sync)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_hsm_instance: HsmConnector | None = None
_hsm_init_lock: asyncio.Lock | None = None


def _get_init_lock() -> asyncio.Lock:
    global _hsm_init_lock
    if _hsm_init_lock is None:
        _hsm_init_lock = asyncio.Lock()
    return _hsm_init_lock


async def get_hsm() -> HsmConnector:
    """Return the initialized global :class:`HsmConnector` singleton."""
    global _hsm_instance
    if _hsm_instance is not None and _hsm_instance._initialized:
        return _hsm_instance

    lock = _get_init_lock()
    async with lock:
        if _hsm_instance is None:
            _hsm_instance = HsmConnector()
        if not _hsm_instance._initialized:
            await _hsm_instance.initialize()

    return _hsm_instance


# Convenience reference — populated after first call to get_hsm()
hsm: HsmConnector = None  # type: ignore[assignment]
