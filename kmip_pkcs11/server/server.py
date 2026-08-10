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
        authenticator=None,
        audit_sink=None,
    ):
        """
        :param authenticator: optional ``callable(username, password) -> bool``
            verifying a real per-user credential. When omitted the password is
            compared against the token PIN, which authenticates the PIN rather
            than the user — see ``_authenticate``. Left optional so existing
            callers and the test suite keep their current behaviour.
        :param audit_sink: optional callable receiving one dict per operation.
            Passed to the dispatcher so every KMIP operation is recorded at the
            single point they all pass through.
        """
        self._store  = store
        self._shim   = shim
        self._authenticator = authenticator
        self._audit_sink = audit_sink
        self._host   = host
        self._port   = port
        self._tls_cert = tls_cert
        self._tls_key  = tls_key
        self._tls_ca   = tls_ca
        self._require_client_cert = require_client_cert
        self._dispatcher = OperationDispatcher(store, shim, audit_sink=audit_sink)
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

    def _audit_auth_failure(self, header, message: str) -> None:
        """Records a rejected KMIP authentication.

        Reports the username that was *claimed*, which is the useful fact: a
        run of failures against one account name is what a brute-force attempt
        looks like. Never raises — an audit problem must not become the
        client's error.
        """
        if self._audit_sink is None:
            return

        claimed = None
        try:
            auth = header.get(Tag.Authentication) if header else None
            credential = auth.get(Tag.Credential) if auth else None
            value = credential.get(Tag.CredentialValue) if credential else None
            username = value.get(Tag.Username) if value else None
            claimed = username.value if username else None
        except Exception:                       # noqa: BLE001
            pass

        try:
            self._audit_sink({
                "action": "kmip.Authenticate",
                "username": claimed,
                "object_uid": None,
                "result": "FAILURE",
                "detail": message,
                "provider": "KMIP",
            })
        except Exception:                       # noqa: BLE001 - see docstring
            log.exception("Could not record a KMIP authentication failure")

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
        except KMIPError as e:
            log.warning("Request processing error: %s", e)
            return _error_response(e.reason, str(e))
        except Exception as e:
            log.exception("Request processing error: %s", e)
            return _error_response(ResultReason.GeneralFailure, str(e))

    def _build_response(self, request: TTLVItem, identity: str) -> bytes:
        # Parse request header (protocol version, batch count)
        header = request.get(Tag.RequestHeader)
        pv     = header.get(Tag.ProtocolVersion) if header else None
        major  = pv.get(Tag.ProtocolVersionMajor).value if pv else 2
        minor  = pv.get(Tag.ProtocolVersionMinor).value if pv else 1

        # Credential-based auth (UsernameAndPassword) overrides the TLS-cert
        # identity when present; raises AuthenticationFailed on bad credentials.
        #
        # A rejection is audited here rather than left to the dispatcher: it
        # never reaches the dispatcher, so a failed sign-in would otherwise be
        # the one security event that leaves no record — precisely the event
        # worth keeping.
        try:
            identity = self._authenticate(header, identity)
        except AuthenticationFailed as e:
            self._audit_auth_failure(header, str(e))
            raise

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
        """Parse an optional Authentication/Credential from the request
        header. Only CredentialType.UsernameAndPassword is supported; the
        password is checked against the configured PKCS#11 token PIN — the
        one shared secret this server already trusts for HSM access, reused
        here as the KMIP-level credential. Falls back to the connection's
        TLS-cert identity (or "anonymous") when no Credential is present."""
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

        username = username_item.value

        # An injected authenticator is preferred over the shared PIN.
        #
        # Checking the password against the token PIN authenticates *the PIN*,
        # not the user: every caller presents the same secret, and the username
        # beside it is simply believed. Since authorization keys off that
        # username — including the admin role — anyone holding the PIN can
        # assert any identity. An authenticator verifies the pair, so the
        # identity that access control then uses has actually been proven.
        if self._authenticator is not None:
            if not self._authenticator(username, password):
                raise AuthenticationFailed(f"Invalid credentials for user '{username}'")
            return username

        if not self._shim.verify_pin(password):
            raise AuthenticationFailed(f"Invalid credentials for user '{username}'")
        return username


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
