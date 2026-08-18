"""`kmip-server` — run the KMIP server from a configuration file.

Installed as a console script, so a deployment is a config file and a service
unit rather than a Python program someone has to write and maintain.
"""

import argparse
import logging
import signal
import sys
import threading

from ..config import KMIPConfig, ConfigError
from ..metadata.store import MetadataStore
from ..observability import Metrics, HealthServer, configure_logging
from ..pkcs11_shim.shim import PKCS11Shim
from ..server.server import KMIPServer
from ..server.workers import WorkerPool, default_worker_count
from ..lifecycle.dual_control import DualControlPolicy
from ..lifecycle.governance import KeyLifecycleScheduler

log = logging.getLogger("kmip.server")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kmip-server",
        description="Run a KMIP 2.1 server backed by a PKCS#11 HSM.",
    )
    p.add_argument("-c", "--config", required=True, metavar="PATH",
                   help="path to the YAML configuration file")
    p.add_argument("--check", action="store_true",
                   help="validate the configuration and exit without serving")
    return p


def _readiness(server: KMIPServer, shim: PKCS11Shim, store: MetadataStore):
    """Readiness means this instance can actually serve a request right now:
    the KMIP port is open, the HSM session is usable, and the database answers.

    The listener check matters more than it looks. Startup opens the HSM
    session, provisions the master key and converts any cleartext blobs before
    it binds, which on a large token takes seconds — long enough for an
    orchestrator to route traffic at a port that is not open yet. Checked on
    demand rather than cached, so a token that disappears is reported."""
    def check():
        if not server.is_serving():
            return False, {"kmip_listener": "not yet accepting connections"}
        detail = {}
        try:
            detail["mechanisms"] = len(shim.get_mechanism_list())
        except Exception as e:
            return False, {"hsm": f"unavailable: {e}"}
        try:
            detail["schema_version"] = store.schema_version()
        except Exception as e:
            return False, {"database": f"unavailable: {e}"}
        return True, detail
    return check


def _build_scheduler(config, store, shim, metrics):
    if not config.get("governance", "enabled"):
        return None
    return KeyLifecycleScheduler(
        store, shim,
        warn_days=config.get("governance", "warn_days"),
        auto_rotate=config.get("governance", "auto_rotate"),
        interval_seconds=config.get("governance", "scan_interval_seconds"),
        metrics=metrics,
    )


def _run_workers(config, pin: str, workers: int) -> int:
    """Pre-fork worker pool.

    The parent binds the socket and forks before any PKCS#11 call, because a
    child that inherits an initialized PKCS#11 library is undefined behaviour
    per the specification. Each child then builds its own store, shim and
    server, so nothing crosses the fork except the listening socket."""
    pool = WorkerPool(
        host=config.get("server", "host"),
        port=config.get("server", "port"),
        workers=workers,
        serve=lambda sock, index: _serve_in_worker(config, pin, sock, index),
    )

    stopping = threading.Event()

    def shutdown(signum, _frame):
        log.info("Received signal %s, stopping workers", signum)
        stopping.set()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    pool.bind()
    pool.start()
    log.info("kmip-server ready with %d worker(s)", workers)

    supervisor = threading.Thread(target=pool.supervise, daemon=True)
    supervisor.start()
    try:
        while not stopping.wait(0.5):
            pass
    finally:
        pool.stop()
    return 0


def _serve_in_worker(config, pin: str, sock, index: int):
    """Runs inside a forked child: everything PKCS#11-touching starts here."""
    metrics = Metrics()
    store = MetadataStore(config.get("storage", "database"))
    shim = PKCS11Shim(config.get("hsm", "library"),
                      config.get("hsm", "token_label"), pin)
    server = KMIPServer(
        store, shim,
        host=config.get("server", "host"),
        port=config.get("server", "port"),
        tls_cert=config.get("tls", "cert"),
        tls_key=config.get("tls", "key"),
        tls_ca=config.get("tls", "ca"),
        require_client_cert=config.get("tls", "require_client_cert"),
        max_request_size=config.get("server", "max_request_size"),
        handshake_timeout=config.get("server", "handshake_timeout"),
        allow_plaintext=config.get("server", "allow_plaintext"),
        metrics=metrics,
        dual_control=DualControlPolicy.from_config(config),
    )

    # Only worker 0 runs the lifecycle scheduler. Cryptoperiod enforcement is
    # a whole-deployment job, not a per-connection one, so running it in every
    # worker would just have them race to deactivate the same keys.
    if index == 0:
        scheduler = _build_scheduler(config, store, shim, metrics)
        if scheduler:
            scheduler.start()

    # Only worker 0 serves health and metrics: they bind a single port, so
    # every worker trying would leave all but one failing to start. This means
    # the metrics reflect one worker's share of traffic — noted in the docs,
    # and the reason aggregate counters belong in an external collector.
    if index == 0 and config.get("observability", "enabled"):
        HealthServer(metrics, _readiness(server, shim, store),
                     host=config.get("observability", "host"),
                     port=config.get("observability", "port")).start()

    server.start(sock=sock)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        config = KMIPConfig.from_file(args.config)
    except ConfigError as e:
        # Logging isn't configured yet — a config error must still be visible.
        print(f"kmip-server: configuration error: {e}", file=sys.stderr)
        return 2

    configure_logging(level=config.get("logging", "level"),
                      fmt=config.get("logging", "format"))

    try:
        pin = config.resolve_pin()
    except ConfigError as e:
        log.error("Configuration error: %s", e)
        return 2

    if args.check:
        log.info("Configuration at %s is valid", args.config)
        return 0

    workers = config.get("server", "workers")
    if workers is None:
        workers = default_worker_count()
    if workers > 1:
        return _run_workers(config, pin, workers)

    metrics = Metrics()
    store = MetadataStore(config.get("storage", "database"))
    shim = PKCS11Shim(config.get("hsm", "library"),
                      config.get("hsm", "token_label"), pin)

    server = KMIPServer(
        store, shim,
        host=config.get("server", "host"),
        port=config.get("server", "port"),
        tls_cert=config.get("tls", "cert"),
        tls_key=config.get("tls", "key"),
        tls_ca=config.get("tls", "ca"),
        require_client_cert=config.get("tls", "require_client_cert"),
        max_request_size=config.get("server", "max_request_size"),
        handshake_timeout=config.get("server", "handshake_timeout"),
        allow_plaintext=config.get("server", "allow_plaintext"),
        metrics=metrics,
        dual_control=DualControlPolicy.from_config(config),
    )

    scheduler = _build_scheduler(config, store, shim, metrics)
    if scheduler:
        scheduler.start()

    health = None
    if config.get("observability", "enabled"):
        health = HealthServer(metrics, _readiness(server, shim, store),
                              host=config.get("observability", "host"),
                              port=config.get("observability", "port"))

    stopping = threading.Event()

    def shutdown(signum, _frame):
        log.info("Received signal %s, shutting down", signum)
        stopping.set()

    def reload_certificates(signum, _frame):
        # SIGHUP is the conventional "re-read what you can without restarting"
        # signal, and a renewed certificate is the thing worth re-reading.
        log.info("Received SIGHUP, reloading TLS material")
        try:
            server.reload_tls()
        except Exception:
            log.exception("TLS reload failed; continuing with the previous certificate")

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, reload_certificates)

    try:
        server.start_background()
        if health:
            health.start()
    except Exception:
        log.exception("Failed to start")
        return 1

    log.info("kmip-server ready")
    try:
        while not stopping.wait(0.5):
            pass
    finally:
        if scheduler:
            scheduler.stop()
        if health:
            health.stop()
        server.stop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
