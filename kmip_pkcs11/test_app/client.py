"""
KMIP test client — connects to the KMIP server over TCP and exercises
all major operations: Create, Get, Encrypt, Decrypt, Locate, Activate,
Revoke, Destroy, Query, DiscoverVersions.
"""

import logging
import socket
import struct
import ssl
from typing import Optional, List

from ..core.enums import (
    Tag, Type, Operation, ObjectType, CryptographicAlgorithm,
    CryptographicUsageMask, BlockCipherMode, ResultStatus, QueryFunction,
    State
)
from ..core.ttlv import (
    TTLVItem, decode_one,
    encode_structure, encode_enumeration, encode_integer,
    encode_text_string, encode_byte_string, encode_boolean
)

log = logging.getLogger(__name__)


class KMIPClient:
    """Simple synchronous KMIP 2.1 client over TCP."""

    PROTOCOL_VERSION = (2, 1)

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5696,
        tls_cert: Optional[str] = None,
        tls_key:  Optional[str] = None,
        tls_ca:   Optional[str] = None,
    ):
        self._host    = host
        self._port    = port
        self._tls_cert = tls_cert
        self._tls_key  = tls_key
        self._tls_ca   = tls_ca
        self._sock: Optional[socket.socket] = None
        self._batch_counter = 0

    # ── connection ────────────────────────────────────────────────────────────

    def connect(self):
        raw = socket.create_connection((self._host, self._port), timeout=10)
        if self._tls_cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_cert_chain(self._tls_cert, self._tls_key)
            if self._tls_ca:
                ctx.load_verify_locations(self._tls_ca)
            else:
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
            self._sock = ctx.wrap_socket(raw, server_hostname=self._host)
        else:
            self._sock = raw
        log.debug("Connected to KMIP server at %s:%d", self._host, self._port)

    def close(self):
        if self._sock:
            self._sock.close()
            self._sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()

    # ── operations ────────────────────────────────────────────────────────────

    def discover_versions(self) -> List[tuple]:
        payload = b""
        resp    = self._request(Operation.DiscoverVersions, payload)
        versions = []
        for pv in resp.get_all(Tag.ProtocolVersion):
            major = pv.get(Tag.ProtocolVersionMajor)
            minor = pv.get(Tag.ProtocolVersionMinor)
            if major and minor:
                versions.append((major.value, minor.value))
        return versions

    def query(self, functions: Optional[List[int]] = None) -> dict:
        payload = b""
        for f in (functions or [
            QueryFunction.QueryOperations,
            QueryFunction.QueryObjects,
            QueryFunction.QueryServerInformation,
        ]):
            payload += encode_enumeration(Tag.QueryFunction, f)

        resp = self._request(Operation.Query, payload)
        ops  = [i.value for i in resp.get_all(Tag.Operations)]
        objs = [i.value for i in resp.get_all(Tag.ObjectTypes)]
        vi_item = resp.get(Tag.VendorIdentification)
        return {
            "operations":   ops,
            "object_types": objs,
            "vendor":       vi_item.value if vi_item else "",
        }

    def create(
        self,
        algorithm: int = CryptographicAlgorithm.AES,
        length: int = 256,
        usage_mask: int = CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt,
        name: Optional[str] = None,
        extractable: bool = False,
    ) -> str:
        attrs = (
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, algorithm))
            + _attr("Cryptographic Length",    encode_integer(Tag.AttributeValue, length))
            + _attr("Cryptographic Usage Mask", encode_integer(Tag.AttributeValue, usage_mask))
        )
        if name:
            name_val = encode_text_string(Tag.NameValue, name)
            attrs   += _attr("Name", encode_structure(Tag.AttributeValue, name_val))
        if extractable:
            attrs += _attr("Extractable", encode_boolean(Tag.AttributeValue, True))

        tmpl    = encode_structure(Tag.TemplateAttribute, attrs)
        payload = (
            encode_enumeration(Tag.ObjectType, ObjectType.SymmetricKey)
            + tmpl
        )
        resp = self._request(Operation.Create, payload)
        uid_item = resp.get(Tag.UniqueIdentifier)
        if uid_item is None:
            raise RuntimeError("Create: no UniqueIdentifier in response")
        return uid_item.value

    def create_key_pair(
        self,
        algorithm: int = CryptographicAlgorithm.RSA,
        length: int = 2048,
        name: Optional[str] = None,
    ):
        common_attrs = (
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, algorithm))
            + _attr("Cryptographic Length",  encode_integer(Tag.AttributeValue, length))
        )
        if name:
            name_val      = encode_text_string(Tag.NameValue, name)
            common_attrs += _attr("Name", encode_structure(Tag.AttributeValue, name_val))

        payload = encode_structure(Tag.TemplateAttribute, common_attrs)
        resp    = self._request(Operation.CreateKeyPair, payload)

        uids = [i.value for i in resp.get_all(Tag.UniqueIdentifier)]
        if len(uids) < 2:
            raise RuntimeError(f"CreateKeyPair: expected 2 UIDs, got {uids}")
        return uids[0], uids[1]  # pub_uid, priv_uid

    def get(self, uid: str) -> TTLVItem:
        payload = encode_text_string(Tag.UniqueIdentifier, uid)
        return self._request(Operation.Get, payload)

    def get_attributes(self, uid: str, names: Optional[List[str]] = None) -> dict:
        payload = encode_text_string(Tag.UniqueIdentifier, uid)
        if names:
            for n in names:
                payload += encode_text_string(Tag.AttributeName, n)
        resp = self._request(Operation.GetAttributes, payload)
        result = {}
        for attr in resp.get_all(Tag.Attribute):
            name_item  = attr.get(Tag.AttributeName)
            value_item = attr.get(Tag.AttributeValue)
            if name_item:
                result[name_item.value] = value_item.value if value_item else None
        return result

    def locate(
        self,
        object_type: Optional[int] = None,
        state: Optional[int] = None,
        name: Optional[str] = None,
        algorithm: Optional[int] = None,
    ) -> List[str]:
        payload = b""
        if object_type is not None:
            payload += encode_enumeration(Tag.ObjectType, object_type)
        if state is not None:
            payload += encode_enumeration(Tag.State, state)
        if name is not None or algorithm is not None:
            attrs = b""
            if name:
                name_val  = encode_text_string(Tag.NameValue, name)
                attrs    += _attr("Name", encode_structure(Tag.AttributeValue, name_val))
            if algorithm:
                attrs += _attr("Cryptographic Algorithm",
                               encode_enumeration(Tag.AttributeValue, algorithm))
            payload += encode_structure(Tag.Attributes, attrs)

        resp = self._request(Operation.Locate, payload)
        return [i.value for i in resp.get_all(Tag.UniqueIdentifier)]

    def activate(self, uid: str) -> str:
        payload = encode_text_string(Tag.UniqueIdentifier, uid)
        resp    = self._request(Operation.Activate, payload)
        return resp.get(Tag.UniqueIdentifier).value

    def revoke(self, uid: str, reason: int = 5, message: str = "") -> str:
        rev_reason = (
            encode_enumeration(Tag.RevocationReasonCode, reason)
            + encode_text_string(Tag.RevocationMessage, message)
        )
        payload = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_structure(Tag.RevocationReason, rev_reason)
        )
        resp = self._request(Operation.Revoke, payload)
        return resp.get(Tag.UniqueIdentifier).value

    def destroy(self, uid: str) -> str:
        payload = encode_text_string(Tag.UniqueIdentifier, uid)
        resp    = self._request(Operation.Destroy, payload)
        return resp.get(Tag.UniqueIdentifier).value

    def encrypt(
        self,
        uid: str,
        plaintext: bytes,
        iv: Optional[bytes] = None,
        mode: int = BlockCipherMode.CBC,
    ) -> tuple:
        payload = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_byte_string(Tag.Data, plaintext)
        )
        if iv:
            payload += encode_byte_string(Tag.IVCounterNonce, iv)

        resp       = self._request(Operation.Encrypt, payload)
        ct_item    = resp.get(Tag.Data)
        iv_out     = resp.get(Tag.IVCounterNonce)
        tag_item   = resp.get(Tag.AuthenticatedEncryptionTag)
        return (
            ct_item.value if ct_item else b"",
            iv_out.value  if iv_out  else iv,
            tag_item.value if tag_item else None,
        )

    def decrypt(
        self,
        uid: str,
        ciphertext: bytes,
        iv: Optional[bytes] = None,
        auth_tag: Optional[bytes] = None,
        mode: int = BlockCipherMode.CBC,
    ) -> bytes:
        payload = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_byte_string(Tag.Data, ciphertext)
        )
        if iv:
            payload += encode_byte_string(Tag.IVCounterNonce, iv)
        if auth_tag:
            payload += encode_byte_string(Tag.AuthenticatedEncryptionTag, auth_tag)

        resp    = self._request(Operation.Decrypt, payload)
        pt_item = resp.get(Tag.Data)
        return pt_item.value if pt_item else b""

    def add_attribute(self, uid: str, name: str, value: str) -> str:
        attr_inner = (
            encode_text_string(Tag.AttributeName, name)
            + encode_text_string(Tag.AttributeValue, value)
        )
        payload = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_structure(Tag.Attribute, attr_inner)
        )
        resp = self._request(Operation.AddAttribute, payload)
        return resp.get(Tag.UniqueIdentifier).value

    # ── low-level transport ────────────────────────────────────────────────────

    def _request(self, operation: int, payload_bytes: bytes) -> TTLVItem:
        request = self._build_request(operation, payload_bytes)
        self._send(request)
        raw      = self._recv()
        response = decode_one(raw)
        return self._unwrap_response(response, operation)

    def _build_request(self, operation: int, payload_bytes: bytes) -> bytes:
        self._batch_counter += 1
        batch_id = self._batch_counter.to_bytes(4, 'big')

        pv = (
            encode_integer(Tag.ProtocolVersionMajor, self.PROTOCOL_VERSION[0])
            + encode_integer(Tag.ProtocolVersionMinor, self.PROTOCOL_VERSION[1])
        )
        header = encode_structure(
            Tag.RequestHeader,
            encode_structure(Tag.ProtocolVersion, pv)
            + encode_integer(Tag.BatchCount, 1)
        )
        batch_item = encode_structure(
            Tag.BatchItem,
            encode_enumeration(Tag.Operation, operation)
            + encode_byte_string(Tag.UniqueBatchItemID, batch_id)
            + encode_structure(Tag.RequestPayload, payload_bytes)
        )
        return encode_structure(Tag.RequestMessage, header + batch_item)

    def _send(self, data: bytes):
        self._sock.sendall(data)

    def _recv(self) -> bytes:
        header = _recvall(self._sock, 8)
        if not header:
            raise RuntimeError("Server closed connection")
        length = struct.unpack_from('>I', header, 4)[0]
        padded = (length + 7) & ~7
        rest   = _recvall(self._sock, padded)
        return header + rest

    @staticmethod
    def _unwrap_response(response: TTLVItem, operation: int) -> TTLVItem:
        for batch_item in response.get_all(Tag.BatchItem):
            op_item     = batch_item.get(Tag.Operation)
            status_item = batch_item.get(Tag.ResultStatus)

            if status_item and status_item.value != ResultStatus.Success:
                reason_item  = batch_item.get(Tag.ResultReason)
                message_item = batch_item.get(Tag.ResultMessage)
                reason  = reason_item.value  if reason_item  else 0
                message = message_item.value if message_item else "Unknown error"
                raise KMIPClientError(f"Operation failed (reason={reason}): {message}")

            payload = batch_item.get(Tag.ResponsePayload)
            return payload if payload else TTLVItem(Tag.ResponsePayload, 0x01, None, [])

        raise RuntimeError("No BatchItem in response")


class KMIPClientError(Exception):
    pass


# ── helpers ──────────────────────────────────────────────────────────────────

def _attr(name: str, value_bytes: bytes) -> bytes:
    return encode_structure(
        Tag.Attribute,
        encode_text_string(Tag.AttributeName, name) + value_bytes
    )


def _recvall(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("Connection closed mid-message")
        buf.extend(chunk)
    return bytes(buf)
