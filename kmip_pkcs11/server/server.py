"""
KMIP TCP server.

Transport: raw TCP (optionally TLS-wrapped).
Message framing: 4-byte big-endian length prefix followed by TTLV bytes.
This matches the KMIP spec transport binding (port 5696).
"""

import logging
import socket
import ssl
import struct
import threading
from typing import Optional

from ..core.enums import Tag, ResultStatus, ResultReason
from ..core.ttlv import (
    TTLVItem, decode_one, encode_structure, encode_enumeration,
    encode_integer, encode_text_string
)
from ..core.exceptions import KMIPError, InvalidMessage
from ..metadata.store import MetadataStore
from ..pkcs11_shim.shim import PKCS11Shim
from ..operations.dispatcher import OperationDispatcher

log = logging.getLogger(__name__)


class KMIPServer:
    """
    Single-threaded KMIP server with thread-per-client handling.
    Supports plain TCP and TLS (mTLS).
    """

    def __init__(
        self,
        store: MetadataStore,
        shim: PKCS11Shim,
        host: str = "127.0.0.1",
        port: int = 5696,
        tls_cert: Optional[str] = None,
        tls_key:  Optional[str] = None,
        tls_ca:   Optional[str] = None,
        require_client_cert: bool = False,
    ):
        self._store  = store
        self._shim   = shim
        self._host   = host
        self._port   = port
        self._tls_cert = tls_cert
        self._tls_key  = tls_key
        self._tls_ca   = tls_ca
        self._require_client_cert = require_client_cert
        self._dispatcher = OperationDispatcher(store, shim)
        self._sock: Optional[socket.socket] = None
        self._running = False

    # ── public API ────────────────────────────────────────────────────────────

    def start(self):
        self._shim.initialize()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._host, self._port))
        self._sock.listen(16)
        self._running = True
        log.info("KMIP server listening on %s:%d", self._host, self._port)
        self._accept_loop()

    def start_background(self):
        t = threading.Thread(target=self.start, daemon=True)
        t.start()
        return t

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        self._shim.finalize()
        log.info("KMIP server stopped")

    # ── accept loop ──────────────────────────────────────────────────────────

    def _accept_loop(self):
        self._sock.settimeout(1.0)
        while self._running:
            try:
                conn, addr = self._sock.accept()
                log.debug("New connection from %s", addr)
                conn = self._wrap_tls(conn)
                t = threading.Thread(
                    target=self._handle_client, args=(conn, addr), daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _wrap_tls(self, conn: socket.socket) -> socket.socket:
        if not self._tls_cert:
            return conn
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self._tls_cert, self._tls_key)
        if self._tls_ca:
            ctx.load_verify_locations(self._tls_ca)
            if self._require_client_cert:
                ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx.wrap_socket(conn, server_side=True)

    # ── client handler ───────────────────────────────────────────────────────

    def _handle_client(self, conn: socket.socket, addr):
        identity = self._get_identity(conn)
        try:
            conn.settimeout(60.0)
            while True:
                raw = self._recv_message(conn)
                if raw is None:
                    break
                response = self._process(raw, identity)
                self._send_message(conn, response)
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
            pass
        except Exception as e:
            log.exception("Error handling client %s: %s", addr, e)
        finally:
            try:
                conn.close()
            except Exception:
                pass
            log.debug("Connection closed: %s", addr)

    @staticmethod
    def _get_identity(conn) -> str:
        if isinstance(conn, ssl.SSLSocket):
            cert = conn.getpeercert()
            if cert:
                for rdn in cert.get("subject", []):
                    for k, v in rdn:
                        if k == "commonName":
                            return v
        return "anonymous"

    @staticmethod
    def _recv_message(conn: socket.socket) -> Optional[bytes]:
        """Read a length-prefixed KMIP message."""
        # KMIP uses no explicit framing in the spec, but implementations
        # commonly prefix with a 4-byte big-endian total length.
        # We read the first 8 bytes (header of first TTLV item) and use
        # the length field to read the rest.
        try:
            header = _recvall(conn, 8)
            if not header:
                return None
            # bytes 4-7 = length of the value (Structure value)
            length = struct.unpack_from('>I', header, 4)[0]
            padded = (length + 7) & ~7
            rest   = _recvall(conn, padded)
            if rest is None:
                return None
            return header + rest
        except (socket.timeout, OSError):
            return None

    @staticmethod
    def _send_message(conn: socket.socket, data: bytes):
        conn.sendall(data)

    def _process(self, raw: bytes, identity: str) -> bytes:
        try:
            request = decode_one(raw)
        except Exception as e:
            log.warning("Failed to decode KMIP request: %s", e)
            return _error_response(ResultReason.InvalidMessage, str(e))

        try:
            return self._build_response(request, identity)
        except Exception as e:
            log.exception("Request processing error: %s", e)
            return _error_response(ResultReason.GeneralFailure, str(e))

    def _build_response(self, request: TTLVItem, identity: str) -> bytes:
        # Parse request header (protocol version, batch count)
        header = request.get(Tag.RequestHeader)
        pv     = header.get(Tag.ProtocolVersion) if header else None
        major  = pv.get(Tag.ProtocolVersionMajor).value if pv else 2
        minor  = pv.get(Tag.ProtocolVersionMinor).value if pv else 1

        # Process each batch item
        batch_items_bytes = b""
        for item in request.get_all(Tag.BatchItem):
            batch_items_bytes += self._dispatcher.dispatch(item, identity)

        # Build response header
        resp_header = encode_structure(
            Tag.ResponseHeader,
            _encode_version(major, minor)
            + encode_integer(Tag.BatchCount, len(request.get_all(Tag.BatchItem)))
        )

        return encode_structure(
            Tag.ResponseMessage,
            resp_header + batch_items_bytes
        )


# ── helpers ──────────────────────────────────────────────────────────────────

def _recvall(conn: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _encode_version(major: int, minor: int) -> bytes:
    pv = encode_integer(Tag.ProtocolVersionMajor, major)
    pv += encode_integer(Tag.ProtocolVersionMinor, minor)
    return encode_structure(Tag.ProtocolVersion, pv)


def _error_response(reason: int, message: str) -> bytes:
    batch_item = encode_structure(
        Tag.BatchItem,
        encode_enumeration(Tag.ResultStatus, ResultStatus.OperationFailed)
        + encode_enumeration(Tag.ResultReason, reason)
        + encode_text_string(Tag.ResultMessage, message[:256])
    )
    header = encode_structure(
        Tag.ResponseHeader,
        _encode_version(2, 1)
        + encode_integer(Tag.BatchCount, 1)
    )
    return encode_structure(Tag.ResponseMessage, header + batch_item)
