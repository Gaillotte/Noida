"""
Runnable entry point for the existing KMIP server.

``KMIPServer`` takes a metadata store and a PKCS#11 shim as constructor
arguments and has no ``__main__`` block, so the package cannot be started as
a service on its own. This module supplies only that wiring — it constructs
the same objects the test suite does and calls ``start()``. No KMIP behaviour
is defined here.

Run with::

    python -m app.kmip_server_main
"""

import logging
import os
import signal
import sys

from kmip_pkcs11.metadata.store import MetadataStore
from kmip_pkcs11.pkcs11_shim.shim import PKCS11Shim
from kmip_pkcs11.server.server import KMIPServer

from .config import settings
from .kmip_identity import KmipIdentityMirror
from .portal_store import PortalStore

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("kmip-server")


def main() -> int:
    log.info("Opening metadata store (%s)",
             "postgresql" if settings.database_url.startswith("postgres") else "sqlite")
    store = MetadataStore(settings.database_url)

    log.info("Loading PKCS#11 module %s (token '%s')",
             settings.pkcs11_library, settings.pkcs11_token)
    shim = PKCS11Shim(settings.pkcs11_library, settings.pkcs11_token, settings.pkcs11_pin)
    # Deliberately not initialized here. KMIPServer.start() does it, inside the
    # process that will actually use the token — a child that inherits an
    # already-initialized PKCS#11 library is undefined behaviour, so opening it
    # before a worker forks is exactly the wrong place.

    # Identity: the engine authenticates against its own kmip_identities table,
    # which portal administration projects into. Reconciling at startup fixes
    # role drift and reports any portal user who has no KMIP credential yet —
    # see KmipIdentityMirror for why that cannot be fixed automatically.
    portal = PortalStore(settings.database_url)
    KmipIdentityMirror(portal, store).reconcile()

    tls_cert = os.getenv("KMIP_TLS_CERT") or None
    tls_key = os.getenv("KMIP_TLS_KEY") or None

    # TLS is required unless explicitly waived. The engine enforces this itself
    # now — the same policy, and the same reasoning, that this module used to
    # apply before calling it. Passing the flag through and letting start() be
    # the one place that decides avoids two checks that can disagree.
    allow_plaintext = os.getenv("KMIP_ALLOW_PLAINTEXT", "false").lower() == "true"

    server = KMIPServer(
        store=store,
        shim=shim,
        host=os.getenv("KMIP_BIND", "0.0.0.0"),
        port=int(os.getenv("KMIP_PORT", "5696")),
        tls_cert=tls_cert,
        tls_key=tls_key,
        tls_ca=os.getenv("KMIP_TLS_CA") or None,
        require_client_cert=os.getenv("KMIP_REQUIRE_CLIENT_CERT", "false").lower() == "true",
        allow_plaintext=allow_plaintext,
    )

    def shutdown(signum, _frame):
        # Containers are stopped with SIGTERM; without a handler the process
        # is killed mid-request and the PKCS#11 session is never finalised.
        log.info("Signal %s received, shutting down", signum)
        try:
            server.stop()
        finally:
            shim.finalize()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # start() logs the listener itself, once it is actually bound. Announcing it
    # here as well claimed the server was up before the TLS check that can
    # refuse to start it.
    server.start()          # blocks
    return 0


if __name__ == "__main__":
    sys.exit(main())
