"""
Shared pytest fixtures: SoftHSM2 token, MetadataStore, PKCS11Shim, and a
live KMIPServer+KMIPClient pair.
"""

import itertools
import os
import socket
import time
import pytest

SOFTHSM_LIB = os.environ.get(
    "SOFTHSM2_LIB",
    "/usr/local/lib/softhsm/libsofthsm2.so"   # OpenSSL build — supports ECDSA_SHA*
)
TOKEN_LABEL = "KMIPTestSuite"
USER_PIN    = "9999"
SO_PIN      = "8888"
_port_counter = itertools.count(15700)


def _init_softhsm():
    conf_dir = "/tmp/softhsm2_tests"
    os.makedirs(f"{conf_dir}/tokens", exist_ok=True)
    conf_path = f"{conf_dir}/softhsm2.conf"
    with open(conf_path, "w") as f:
        f.write(f"directories.tokendir = {conf_dir}/tokens\n")
        f.write("objectstore.backend = file\n")
        f.write("log.level = ERROR\n")
    os.environ["SOFTHSM2_CONF"] = conf_path
    os.system(
        f"softhsm2-util --init-token --slot 0 --label {TOKEN_LABEL} "
        f"--pin {USER_PIN} --so-pin {SO_PIN} 2>/dev/null"
    )


@pytest.fixture(scope="session", autouse=True)
def softhsm_token():
    _init_softhsm()
    yield


@pytest.fixture
def store(tmp_path):
    from kmip_pkcs11.metadata.store import MetadataStore
    return MetadataStore(str(tmp_path / "test.db"))


@pytest.fixture(scope="session")
def shim():
    from kmip_pkcs11.pkcs11_shim.shim import PKCS11Shim
    s = PKCS11Shim(SOFTHSM_LIB, TOKEN_LABEL, USER_PIN)
    s.initialize()
    yield s
    s.finalize()


@pytest.fixture
def server_client(tmp_path, shim):
    """Spin up a KMIP server on a fresh port and return a connected client."""
    from kmip_pkcs11.metadata.store import MetadataStore
    from kmip_pkcs11.server.server import KMIPServer
    from kmip_pkcs11.test_app.client import KMIPClient

    port   = next(_port_counter)
    store  = MetadataStore(str(tmp_path / "srv.db"))
    srv    = KMIPServer(store, shim, port=port)
    srv.start_background()

    # Wait for server to be ready
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)

    client = KMIPClient(port=port)
    client.connect()

    yield client, store

    client.close()
    # Stop server but keep the session-scoped shim alive
    srv._running = False
    if srv._sock:
        try:
            srv._sock.close()
        except Exception:
            pass
