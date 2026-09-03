"""
Shared pytest fixtures: SoftHSM2 token, MetadataStore, PKCS11Shim, and a
live KMIPServer+KMIPClient pair.
"""

import itertools
import os
import shutil
import socket
import time
import pytest

# A source build of SoftHSM2 2.7.0, not the distribution package. The version
# is the reason, not the crypto backend: the packaged 2.6.1 already links
# OpenSSL, and enumerating both mechanism lists on one machine gives 70
# mechanisms without CKM_ECDSA_SHA256 for 2.6.1 and 79 with it for 2.7.0. Every
# EC signing test fails against the older build.
SOFTHSM_LIB = os.environ.get(
    "SOFTHSM2_LIB",
    "/usr/local/lib/softhsm/libsofthsm2.so"
)
TOKEN_LABEL = "KMIPTestSuite"
USER_PIN    = "9999"
SO_PIN      = "8888"
_port_counter = itertools.count(15700)


def _init_softhsm():
    """Start every session from an empty token.

    Each full run leaves several thousand keys behind, and nothing removes
    them — after enough runs the token held ~28k objects and startup's
    token-wide search for the master key took longer than the fixtures were
    willing to wait for the listener, so the suite began failing for reasons
    that had nothing to do with the code under test. Wiping is safe: this
    token exists only for the tests."""
    conf_dir = "/tmp/softhsm2_tests"
    shutil.rmtree(f"{conf_dir}/tokens", ignore_errors=True)
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


def _await_listener(srv, port, timeout=30.0):
    """Wait until the server is actually accepting connections.

    Startup opens the HSM session and provisions the master key before it
    binds, so a fixed short delay races it — and the failure looks like
    ConnectionRefusedError in an unrelated test."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if srv.is_serving():
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                return
            except OSError:
                pass
        time.sleep(0.05)
    raise RuntimeError(f"KMIP server did not start listening on port {port}")


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
    srv    = KMIPServer(store, shim, port=port, allow_plaintext=True)
    srv.start_background()

    _await_listener(srv, port)

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


@pytest.fixture
def kmip_server(tmp_path, shim):
    """Spin up a KMIP server on a fresh port without attaching a client, so
    tests can connect multiple KMIPClients (e.g. with different Credentials)
    against the same running server."""
    from kmip_pkcs11.metadata.store import MetadataStore
    from kmip_pkcs11.server.server import KMIPServer

    port  = next(_port_counter)
    store = MetadataStore(str(tmp_path / "srv2.db"))
    srv   = KMIPServer(store, shim, port=port, allow_plaintext=True)
    srv.start_background()

    _await_listener(srv, port)

    yield store, port

    srv._running = False
    if srv._sock:
        try:
            srv._sock.close()
        except Exception:
            pass
