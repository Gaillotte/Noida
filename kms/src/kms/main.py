"""
KMS entry point — starts the FastAPI REST server and the async KMIP server.
"""
import asyncio
import logging
import sys

import uvicorn

from kms.config import settings


def _configure_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )


async def _run_kmip(dispatcher) -> None:
    from kms.kmip.server import KmipServer

    use_tls = all([
        settings.tls_cert_file,
        settings.tls_key_file,
        settings.tls_ca_file,
    ])
    server = KmipServer(dispatcher=dispatcher, use_tls=use_tls)
    await server.start()


async def _main() -> None:
    _configure_logging()
    log = logging.getLogger("kms.main")
    log.info("Starting KMS server (API port=%d, KMIP port=%d)", settings.api_port, settings.kmip_port)

    from kms.kmip.operations import KmipDispatcher
    dispatcher = KmipDispatcher()

    # FastAPI app — run in a thread via uvicorn
    config = uvicorn.Config(
        "kms.api.app:app",
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level.lower(),
        loop="asyncio",
    )
    api_server = uvicorn.Server(config)

    # Run both concurrently
    await asyncio.gather(
        api_server.serve(),
        _run_kmip(dispatcher),
    )


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
