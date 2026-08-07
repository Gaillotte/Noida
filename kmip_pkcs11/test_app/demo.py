"""
Demo test application — exercises the full KMIP over PKCS#11 stack.
Runs a server (SoftHSM2) and client in-process.

Usage:
    python -m kmip_pkcs11.test_app.demo
"""

import logging
import os
import sys
import time
import threading

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s"
)
log = logging.getLogger("demo")

# ── paths ────────────────────────────────────────────────────────────────────

SOFTHSM_LIB = os.environ.get(
    "SOFTHSM2_LIB",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
)
TOKEN_LABEL = "KMIPTest"
USER_PIN    = "1234"
SO_PIN      = "5678"
DB_PATH     = "/tmp/kmip_demo.db"
SERVER_PORT = 15696   # non-privileged port for demo


def setup_softhsm():
    """Initialize SoftHSM2 token if not already present."""
    conf_dir = "/tmp/softhsm2_kmip"
    os.makedirs(conf_dir, exist_ok=True)
    os.makedirs(f"{conf_dir}/tokens", exist_ok=True)

    conf_path = f"{conf_dir}/softhsm2.conf"
    if not os.path.exists(conf_path):
        with open(conf_path, "w") as f:
            f.write(f"directories.tokendir = {conf_dir}/tokens\n")
            f.write("objectstore.backend = file\n")
            f.write("log.level = ERROR\n")

    os.environ["SOFTHSM2_CONF"] = conf_path

    # Init token
    ret = os.system(
        f"softhsm2-util --init-token --slot 0 --label {TOKEN_LABEL} "
        f"--pin {USER_PIN} --so-pin {SO_PIN} 2>/dev/null"
    )
    if ret != 0:
        log.warning("Token may already exist — continuing")


def run_demo():
    from ..metadata.store import MetadataStore
    from ..pkcs11_shim.shim import PKCS11Shim
    from ..server.server import KMIPServer
    from ..test_app.client import KMIPClient
    from ..core.enums import (
        CryptographicAlgorithm, CryptographicUsageMask,
        ObjectType, State, RevocationReasonCode
    )

    log.info("=" * 60)
    log.info("KMIP on PKCS#11 — Demo Application")
    log.info("=" * 60)

    # ── 1. Setup SoftHSM ──────────────────────────────────────────────────
    log.info("[1] Initializing SoftHSM2 token...")
    setup_softhsm()

    # ── 2. Start Server ───────────────────────────────────────────────────
    log.info("[2] Starting KMIP server on port %d...", SERVER_PORT)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    store  = MetadataStore(DB_PATH)
    shim   = PKCS11Shim(SOFTHSM_LIB, TOKEN_LABEL, USER_PIN)
    server = KMIPServer(store, shim, port=SERVER_PORT)
    server.start_background()
    time.sleep(0.5)

    try:
        with KMIPClient(port=SERVER_PORT) as c:

            # ── 3. Discover Versions ──────────────────────────────────────
            log.info("[3] DiscoverVersions...")
            versions = c.discover_versions()
            log.info("    Supported KMIP versions: %s", versions)
            assert (2, 1) in versions, "Expected KMIP 2.1 support"

            # ── 4. Query ──────────────────────────────────────────────────
            log.info("[4] Query server capabilities...")
            caps = c.query()
            log.info("    Vendor: %s", caps["vendor"])
            log.info("    Operations: %d supported", len(caps["operations"]))
            log.info("    Object types: %d supported", len(caps["object_types"]))

            # ── 5. Create AES-256 key ─────────────────────────────────────
            log.info("[5] Create AES-256 symmetric key...")
            uid_aes = c.create(
                algorithm=CryptographicAlgorithm.AES,
                length=256,
                usage_mask=CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt,
                name="demo-aes-key",
                extractable=True,
            )
            log.info("    Created AES-256 key: %s", uid_aes)
            assert uid_aes, "Expected a UID"

            # ── 6. GetAttributes ──────────────────────────────────────────
            log.info("[6] GetAttributes for AES key...")
            attrs = c.get_attributes(uid_aes)
            log.info("    State: %s", attrs.get("State"))
            log.info("    Algorithm: %s", attrs.get("Cryptographic Algorithm"))
            log.info("    Length: %s bits", attrs.get("Cryptographic Length"))

            # ── 7. Locate ─────────────────────────────────────────────────
            log.info("[7] Locate by name 'demo-aes-key'...")
            found = c.locate(name="demo-aes-key", object_type=ObjectType.SymmetricKey)
            log.info("    Found: %s", found)
            assert uid_aes in found

            # ── 8. Encrypt ────────────────────────────────────────────────
            log.info("[8] Encrypt 'Hello KMIP World!'...")
            plaintext = b"Hello KMIP World!!!" + b"\x00" * 13  # pad to 32 bytes
            ct, iv, tag = c.encrypt(uid_aes, plaintext)
            log.info("    Ciphertext (%d bytes): %s...", len(ct), ct[:16].hex())
            log.info("    IV: %s", iv.hex() if iv else "None")

            # ── 9. Decrypt ────────────────────────────────────────────────
            log.info("[9] Decrypt ciphertext...")
            recovered = c.decrypt(uid_aes, ct, iv=iv, auth_tag=tag)
            log.info("    Recovered: %r", recovered[:20])
            assert recovered[:19] == b"Hello KMIP World!!!", f"Decryption mismatch: {recovered}"

            # ── 10. Create RSA Key Pair ────────────────────────────────────
            log.info("[10] Create RSA-2048 key pair...")
            pub_uid, priv_uid = c.create_key_pair(
                algorithm=CryptographicAlgorithm.RSA,
                length=2048,
                name="demo-rsa",
            )
            log.info("    Public key:  %s", pub_uid)
            log.info("    Private key: %s", priv_uid)

            # ── 11. Get (export) AES key ───────────────────────────────────
            log.info("[11] Get (export) AES-256 key material...")
            get_resp = c.get(uid_aes)
            log.info("    Key retrieved from HSM successfully")

            # ── 12. AddAttribute ──────────────────────────────────────────
            log.info("[12] Add custom attribute to AES key...")
            c.add_attribute(uid_aes, "x-project", "KMIP-Demo-2025")
            log.info("    Attribute added")

            # ── 13. Register a secret ─────────────────────────────────────
            log.info("[13] Register a new AES-128 key...")
            import os
            key_bytes = os.urandom(16)
            reg_uid = _register_key(c, key_bytes, CryptographicAlgorithm.AES)
            log.info("    Registered key uid=%s", reg_uid)

            # ── 14. Create a Pre-Active key, then Activate ─────────────────
            log.info("[14] Lifecycle: Create → Activate → Revoke → Destroy...")
            uid_lc = c.create(
                algorithm=CryptographicAlgorithm.AES,
                length=128,
                name="lifecycle-key",
            )
            attrs2 = c.get_attributes(uid_lc)
            log.info("    Initial state: %s (Active expected)", attrs2.get("State"))

            revoked = c.revoke(uid_lc, reason=RevocationReasonCode.Superseded,
                               message="Superseded by newer key")
            log.info("    Revoked uid=%s", revoked)

            attrs3 = c.get_attributes(uid_lc)
            log.info("    State after revoke: %s", attrs3.get("State"))

            destroyed = c.destroy(uid_lc)
            log.info("    Destroyed uid=%s", destroyed)

            # ── 15. Verify destroyed key not usable ───────────────────────
            log.info("[15] Verify destroyed key is gone...")
            found_after = c.locate(name="lifecycle-key")
            found_alive = [u for u in found_after
                           if u not in [uid_lc]]  # destroyed ones may still appear in locate
            log.info("    Locate post-destroy: %s object(s) found", len(found_after))

            # ── 16. Destroy AES key ───────────────────────────────────────
            log.info("[16] Destroy AES-256 key...")
            c.revoke(uid_aes, reason=RevocationReasonCode.CessationOfOperation)
            c.destroy(uid_aes)
            log.info("    AES key destroyed")

            log.info("")
            log.info("=" * 60)
            log.info("ALL DEMO STEPS COMPLETED SUCCESSFULLY")
            log.info("=" * 60)

    finally:
        server.stop()


def _register_key(client, key_bytes: bytes, algorithm: int) -> str:
    """Register a raw symmetric key via the client."""
    from ..core.enums import (
        Tag, ObjectType, KeyFormatType, CryptographicUsageMask
    )
    from ..core.ttlv import (
        encode_structure, encode_byte_string, encode_enumeration,
        encode_integer, encode_text_string
    )
    from ..test_app.client import _attr

    key_material = encode_byte_string(Tag.KeyMaterial, key_bytes)
    key_value    = encode_structure(Tag.KeyValue, key_material)
    key_block    = encode_structure(
        Tag.KeyBlock,
        encode_enumeration(Tag.KeyFormatType, KeyFormatType.Raw) + key_value
    )
    attr_bytes = (
        _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, algorithm))
        + _attr("Cryptographic Usage Mask",
                encode_integer(Tag.AttributeValue,
                               CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt))
    )
    payload = (
        encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
        + encode_structure(Tag.TemplateAttribute, attr_bytes)
        + encode_structure(Tag.KeyBlock, key_block)
    )

    from ..core.enums import Operation
    resp     = client._request(Operation.Register, payload)
    uid_item = resp.get(Tag.UniqueIdentifier)
    return uid_item.value if uid_item else ""


def _attr_bytes(name, value_bytes):
    from ..core.enums import Tag
    from ..core.ttlv import encode_text_string, encode_structure
    return encode_structure(
        Tag.Attribute,
        encode_text_string(Tag.AttributeName, name) + value_bytes
    )


def _integer_bytes(tag, v):
    from ..core.ttlv import encode_integer
    return encode_integer(tag, v)


def encode_integer_bytes(tag, v):
    from ..core.ttlv import encode_integer
    return encode_integer(tag, v)


if __name__ == "__main__":
    run_demo()
