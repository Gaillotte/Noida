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
from .kmip_identity import PortalAuthenticator, make_audit_sink
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
    shim.initialize()

    # Identity: portal accounts, not the shared PIN.
    portal = PortalStore(settings.database_url)
    authenticator = PortalAuthenticator(
        portal=portal,
        metadata=store,
        # Off by default. Enable only while migrating existing KMIP clients;
        # every use logs a warning naming it as the weak path.
        allow_pin_fallback=os.getenv("KMIP_ALLOW_PIN_FALLBACK", "false").lower() == "true",
        shim=shim,
    )

    tls_cert = os.getenv("KMIP_TLS_CERT") or None
    tls_key = os.getenv("KMIP_TLS_KEY") or None

    # TLS is required unless explicitly waived.
    #
    # Inverted from the engine's original default, where TLS was simply
    # absent unless configured. The specification requires it, and key
    # management traffic in the clear is not a reasonable default — so a
    # plaintext listener now takes a deliberate, named act rather than an
    # omission nobody notices.
    allow_plaintext = os.getenv("KMIP_ALLOW_PLAINTEXT", "false").lower() == "true"
    if not tls_cert:
        if not allow_plaintext:
            log.error(
                "KMIP TLS is not configured. Set KMIP_TLS_CERT and KMIP_TLS_KEY, or "
                "set KMIP_ALLOW_PLAINTEXT=true to accept plaintext deliberately. "
                "Refusing to start a plaintext key-management listener by default."
            )
            return 2
        log.warning(
            "KMIP is listening in PLAINTEXT on port %s because KMIP_ALLOW_PLAINTEXT=true. "
            "Credentials and key metadata cross the network unprotected.",
            os.getenv("KMIP_PORT", "5696"),
        )

    server = KMIPServer(
        store=store,
        shim=shim,
        host=os.getenv("KMIP_BIND", "0.0.0.0"),
        port=int(os.getenv("KMIP_PORT", "5696")),
        tls_cert=tls_cert,
        tls_key=tls_key,
        tls_ca=os.getenv("KMIP_TLS_CA") or None,
        require_client_cert=os.getenv("KMIP_REQUIRE_CLIENT_CERT", "false").lower() == "true",
        authenticator=authenticator,
        audit_sink=make_audit_sink(portal),
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

    log.info("KMIP server listening on %s:%s",
             os.getenv("KMIP_BIND", "0.0.0.0"), os.getenv("KMIP_PORT", "5696"))
    server.start()          # blocks
    return 0


if __name__ == "__main__":
    sys.exit(main())
