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

from ..core.enums import (
    Tag, ResultStatus, ResultReason, CredentialType, BatchErrorContinuationOption
)
from ..core.ttlv import (
    TTLVItem, decode_one, encode_structure, encode_enumeration,
    encode_integer, encode_text_string
)
from ..core.exceptions import KMIPError, InvalidMessage, AuthenticationFailed
from ..metadata.store import MetadataStore
from ..pkcs11_shim.shim import PKCS11Shim
from ..operations.dispatcher import OperationDispatcher

log = logging.getLogger(__name__)

# Largest request body accepted off the wire. The length prefix is
# attacker-controlled and read before any authentication, so without a ceiling
# a single unauthenticated client can declare a multi-gigabyte body and make
# the server allocate toward it. 1 MiB is far above any legitimate KMIP
# message, including Register with a large key.
DEFAULT_MAX_REQUEST_SIZE = 1024 * 1024

# Cap on how long a client may take to complete a TLS handshake.
DEFAULT_HANDSHAKE_TIMEOUT = 10.0


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
        max_request_size: int = DEFAULT_MAX_REQUEST_SIZE,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
    ):
        self._store  = store
        self._shim   = shim
        self._host   = host
        self._port   = port
        self._tls_cert = tls_cert
        self._tls_key  = tls_key
        self._tls_ca   = tls_ca
        self._require_client_cert = require_client_cert
        self._max_request_size = max_request_size
        self._handshake_timeout = handshake_timeout
        self._dispatcher = OperationDispatcher(store, shim)
        self._sock: Optional[socket.socket] = None
        self._running = False

    # ── public API ────────────────────────────────────────────────────────────

    def start(self):
        self._shim.initialize()
        self._enable_blob_encryption()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._host, self._port))
        self._sock.listen(16)
        self._running = True
        log.info("KMIP server listening on %s:%d", self._host, self._port)
        self._accept_loop()

    def _enable_blob_encryption(self):
        """Attach an HSM-backed master key to the metadata store, so secret
        payloads with no PKCS#11 object behind them (SecretData, OpaqueObject,
        SplitKey shares) are enveloped at rest rather than written in the
        clear. Provisions the master key on first start and converts any
        pre-existing cleartext rows."""
        if getattr(self._store, "_cipher", None) is not None:
            return
        from ..metadata.blob_cipher import BlobCipher
        self._store._cipher = BlobCipher(self._shim)
        converted = self._store.encrypt_existing_blobs()
        if converted:
            log.info("Converted %d cleartext key blob(s) to encrypted at rest", converted)

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
                # The TLS handshake deliberately does NOT happen here. It
                # blocks until the peer completes it, so performing it on the
                # accept loop lets one client that connects and then stalls
                # hold up every subsequent connection. It runs on the worker
                # thread instead, under a timeout.
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
        conn.settimeout(self._handshake_timeout)
        return ctx.wrap_socket(conn, server_side=True)

    # ── client handler ───────────────────────────────────────────────────────

    def _handle_client(self, conn: socket.socket, addr):
        try:
            conn = self._wrap_tls(conn)
        except (ssl.SSLError, socket.timeout, OSError) as e:
            log.warning("TLS handshake failed for %s: %s", addr, e)
            try:
                conn.close()
            except Exception:
                pass
            return

        identity = self._get_identity(conn)
        try:
            conn.settimeout(60.0)
            while True:
                try:
                    raw = self._recv_message(conn)
                except InvalidMessage as e:
                    # Oversized frame: answer with a proper KMIP failure, then
                    # drop the connection rather than resynchronising a stream
                    # whose framing we no longer trust.
                    self._send_message(conn, _error_response(ResultReason.InvalidMessage, str(e)))
                    break
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

    def _get_identity(self, conn) -> str:
        """Derive a connection-level identity from a client certificate.

        Only trusted when the certificate was actually required and verified
        against the configured CA — otherwise the subject is just as
        self-asserted as an unauthenticated username would be."""
        if isinstance(conn, ssl.SSLSocket) and self._require_client_cert and self._tls_ca:
            cert = conn.getpeercert()
            if cert:
                for rdn in cert.get("subject", []):
                    for k, v in rdn:
                        if k == "commonName":
                            return v
        return "anonymous"

    def _recv_message(self, conn: socket.socket) -> Optional[bytes]:
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
            if length > self._max_request_size:
                # Refuse before reading a single byte of the body — this runs
                # ahead of authentication, so it is the only thing standing
                # between an anonymous client and unbounded allocation.
                log.warning(
                    "Rejecting request declaring %d bytes (max %d)",
                    length, self._max_request_size,
                )
                raise InvalidMessage(
                    f"Request size {length} exceeds maximum {self._max_request_size}"
                )
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
            # The decoder raises bare ValueError/struct.error/UnicodeDecodeError
            # whose text describes our parser internals, not the client's
            # mistake — log it, don't ship it.
            log.warning("Failed to decode KMIP request: %s", e)
            return _error_response(ResultReason.InvalidMessage, "Malformed KMIP request")

        try:
            return self._build_response(request, identity)
        except KMIPError as e:
            # KMIPError messages are authored by this codebase and are safe
            # and useful to return ("Object 'x' not found").
            log.warning("Request processing error: %s", e)
            return _error_response(e.reason, str(e))
        except Exception:
            # Anything else is an unexpected internal fault. The full traceback
            # goes to the log; the client gets a reason code and nothing that
            # discloses paths, types, or internal state.
            log.exception("Unhandled error processing request from identity %r", identity)
            return _error_response(ResultReason.GeneralFailure, "Internal server error")

    def _build_response(self, request: TTLVItem, identity: str) -> bytes:
        # Parse request header (protocol version, batch count)
        header = request.get(Tag.RequestHeader)
        pv     = header.get(Tag.ProtocolVersion) if header else None
        major  = pv.get(Tag.ProtocolVersionMajor).value if pv else 2
        minor  = pv.get(Tag.ProtocolVersionMinor).value if pv else 1

        # Credential-based auth (UsernameAndPassword) overrides the TLS-cert
        # identity when present; raises AuthenticationFailed on bad credentials.
        identity = self._authenticate(header, identity)

        continuation_item = header.get(Tag.BatchErrorContinuationOption) if header else None
        continuation = continuation_item.value if continuation_item else BatchErrorContinuationOption.Continue
        if continuation == BatchErrorContinuationOption.Undo:
            raise KMIPError(
                "BatchErrorContinuationOption=Undo is not supported",
                reason=ResultReason.FeatureNotSupported,
            )
        # BatchOrderOption (sequential vs any-order) is accepted but doesn't
        # change behavior — this server always processes items in listed
        # order, which satisfies either setting.

        max_size_item = header.get(Tag.MaximumResponseSize) if header else None
        max_size = max_size_item.value if max_size_item else None

        # Process each batch item, honoring BatchErrorContinuationOption=Stop
        batch_items_bytes = b""
        processed = 0
        for item in request.get_all(Tag.BatchItem):
            item_bytes = self._dispatcher.dispatch(item, identity)
            batch_items_bytes += item_bytes
            processed += 1
            if continuation == BatchErrorContinuationOption.Stop:
                item_view = decode_one(item_bytes)
                status_item = item_view.get(Tag.ResultStatus)
                if status_item and status_item.value == ResultStatus.OperationFailed:
                    break

        # Build response header
        resp_header = encode_structure(
            Tag.ResponseHeader,
            _encode_version(major, minor)
            + encode_integer(Tag.BatchCount, processed)
        )

        response = encode_structure(
            Tag.ResponseMessage,
            resp_header + batch_items_bytes
        )

        if max_size is not None and len(response) > max_size:
            raise KMIPError(
                f"Response size {len(response)} exceeds MaximumResponseSize {max_size}",
                reason=ResultReason.ResponseTooLarge,
            )

        return response

    def _authenticate(self, header, fallback_identity: str) -> str:
        """Parse an optional Authentication/Credential from the request header
        and resolve it to an authenticated identity.

        Only CredentialType.UsernameAndPassword is supported. The password is
        verified against that specific identity's own scrypt-hashed credential
        in the metadata store (MetadataStore.create_identity provisions them).

        It used to be checked against the shared PKCS#11 token PIN, which meant
        the username was an unauthenticated claim: anyone holding the PIN could
        present themselves as any user — including one carrying the admin role —
        and every ownership and grant decision downstream inherited that. The
        PIN now authenticates the server to the HSM and nothing else.

        Falls back to the connection identity ("anonymous", or a verified mTLS
        subject) when no Credential is present."""
        if header is None:
            return fallback_identity
        auth_item = header.get(Tag.Authentication)
        if auth_item is None:
            return fallback_identity
        cred_item = auth_item.get(Tag.Credential)
        if cred_item is None:
            return fallback_identity

        type_item = cred_item.get(Tag.CredentialType)
        cred_type = type_item.value if type_item else None
        if cred_type != CredentialType.UsernameAndPassword:
            raise AuthenticationFailed(f"CredentialType {cred_type!r} is not supported")

        value_item = cred_item.get(Tag.CredentialValue)
        if value_item is None:
            raise AuthenticationFailed("CredentialValue is required")
        username_item = value_item.get(Tag.Username)
        if username_item is None:
            raise AuthenticationFailed("Username is required")
        password_item = value_item.get(Tag.Password)
        password = password_item.value if password_item else ""

        if not self._store.verify_identity(username_item.value, password):
            # Deliberately does not distinguish unknown identity from wrong
            # password, and does not echo the username back to the client.
            log.warning("Authentication failed for identity %r", username_item.value)
            raise AuthenticationFailed("Invalid credentials")
        return username_item.value


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
