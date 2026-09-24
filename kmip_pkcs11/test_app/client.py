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
    State, CredentialType
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
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self._host    = host
        self._port    = port
        self._tls_cert = tls_cert
        self._tls_key  = tls_key
        self._tls_ca   = tls_ca
        self._username = username
        self._password = password
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
        objs = [i.value for i in resp.get_all(Tag.ObjectType)]
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
        sensitive: bool = True,
        activate: bool = True,
    ) -> str:
        attrs = (
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, algorithm))
            + _attr("Cryptographic Length",    encode_integer(Tag.AttributeValue, length))
            + _attr("Cryptographic Usage Mask", encode_integer(Tag.AttributeValue, usage_mask))
            # Sent explicitly rather than left to the server default, so a caller
            # can choose it. The handler has always accepted the attribute; the
            # client simply never offered a way to set it, which meant the one
            # control the portal exposes for it could not survive the move to
            # the KMIP path.
            + _attr("Sensitive", encode_boolean(Tag.AttributeValue, sensitive))
        )
        # Ask for PreActive when the caller does not want the key usable yet,
        # so Activate has something to act on. Sent only in that case, leaving
        # the default request byte-for-byte as it was.
        if not activate:
            attrs += _attr("State", encode_enumeration(Tag.AttributeValue, State.PreActive))
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
        usage_mask: Optional[int] = None,
        curve: Optional[int] = None,
    ):
        common_attrs = (
            _attr("Cryptographic Algorithm", encode_enumeration(Tag.AttributeValue, algorithm))
            + _attr("Cryptographic Length",  encode_integer(Tag.AttributeValue, length))
        )
        # What the pair may be used for - Sign, Verify, DeriveKey. Omitted
        # entirely when not given, so the handler's own default still applies.
        if usage_mask is not None:
            common_attrs += _attr("Cryptographic Usage Mask",
                                  encode_integer(Tag.AttributeValue, usage_mask))
        # An elliptic curve is carried inside Cryptographic Domain Parameters,
        # not as a length: for EC the curve *is* the size. Without this an EC
        # key pair could not be created over KMIP at all, whatever the caller
        # asked for.
        if curve is not None:
            common_attrs += _attr(
                "Cryptographic Domain Parameters",
                encode_structure(Tag.AttributeValue,
                                 encode_enumeration(Tag.RecommendedCurve, curve)))
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
            + _block_cipher_mode(mode)
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
            + _block_cipher_mode(mode)
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


    # ── operations added for full coverage ────────────────────────────────────
    #
    # Every method below was written against the corresponding handler in
    # kmip_pkcs11/operations/, not against the specification: the handler is
    # what will actually parse the request, so its `payload.get(Tag.X)` calls
    # and its MissingData messages are the contract that matters here.
    #
    # They are deliberately thin. This client exists to exercise the wire
    # protocol, so each one builds the payload, sends it and returns the
    # response items rather than interpreting them.

    # ── lifecycle: identifier only ────────────────────────────────────────────

    def archive(self, uid: str) -> str:
        """Archive: object keeps its State but becomes metadata-only."""
        resp = self._request(Operation.Archive,
                             encode_text_string(Tag.UniqueIdentifier, uid))
        return resp.get(Tag.UniqueIdentifier).value

    def recover(self, uid: str) -> str:
        """Recover: the inverse of Archive."""
        resp = self._request(Operation.Recover,
                             encode_text_string(Tag.UniqueIdentifier, uid))
        return resp.get(Tag.UniqueIdentifier).value

    def obtain_lease(self, uid: str) -> dict:
        """ObtainLease: permission to keep using an object for a period."""
        resp = self._request(Operation.ObtainLease,
                             encode_text_string(Tag.UniqueIdentifier, uid))
        return {
            "uid": _v(resp, Tag.UniqueIdentifier),
            "lease_time": _v(resp, Tag.LeaseTime),
            "last_change_date": _v(resp, Tag.LastChangeDate),
        }

    def get_attribute_list(self, uid: str) -> list:
        """GetAttributeList: the attribute *names* an object carries."""
        resp = self._request(Operation.GetAttributeList,
                             encode_text_string(Tag.UniqueIdentifier, uid))
        return [i.value for i in resp.get_all(Tag.AttributeName)]

    def export(self, uid: str) -> TTLVItem:
        """Export: same response shape as Get, and the same refusal for a
        non-extractable key - which is every key this system creates by
        default."""
        return self._request(Operation.Export,
                             encode_text_string(Tag.UniqueIdentifier, uid))

    # ── attributes ────────────────────────────────────────────────────────────

    def set_attribute(self, uid: str, name: str, value: str) -> str:
        """SetAttribute takes AttributeName/AttributeValue at the top level,
        unlike Add/Modify/Delete which wrap them in an Attribute structure."""
        payload = (
            encode_text_string(Tag.UniqueIdentifier, uid)
            + encode_text_string(Tag.AttributeName, name)
            + encode_text_string(Tag.AttributeValue, value)
        )
        resp = self._request(Operation.SetAttribute, payload)
        return _v(resp, Tag.UniqueIdentifier)

    def modify_attribute(self, uid: str, name: str, value: str,
                         index: int = 0) -> str:
        inner = (encode_text_string(Tag.AttributeName, name)
                 + encode_text_string(Tag.AttributeValue, value)
                 + encode_integer(Tag.AttributeIndex, index))
        payload = (encode_text_string(Tag.UniqueIdentifier, uid)
                   + encode_structure(Tag.Attribute, inner))
        resp = self._request(Operation.ModifyAttribute, payload)
        return _v(resp, Tag.UniqueIdentifier)

    def delete_attribute(self, uid: str, name: str, index: int = 0) -> str:
        inner = (encode_text_string(Tag.AttributeName, name)
                 + encode_integer(Tag.AttributeIndex, index))
        payload = (encode_text_string(Tag.UniqueIdentifier, uid)
                   + encode_structure(Tag.Attribute, inner))
        resp = self._request(Operation.DeleteAttribute, payload)
        return _v(resp, Tag.UniqueIdentifier)

    def adjust_attribute(self, uid: str, name: str, adjustment: int,
                         value: Optional[int] = None) -> str:
        """AdjustAttribute: increment/decrement rather than replace."""
        inner = encode_text_string(Tag.AttributeName, name)
        if value is not None:
            inner += encode_integer(Tag.AttributeValue, value)
        payload = (encode_text_string(Tag.UniqueIdentifier, uid)
                   + encode_structure(Tag.Attribute, inner)
                   + encode_enumeration(Tag.AdjustmentType, adjustment))
        resp = self._request(Operation.AdjustAttribute, payload)
        return _v(resp, Tag.UniqueIdentifier)

    # ── cryptographic services ────────────────────────────────────────────────

    def sign(self, uid: str, data: bytes, hashing_algorithm: int) -> bytes:
        params = encode_structure(
            Tag.CryptographicParameters,
            encode_enumeration(Tag.HashingAlgorithm, hashing_algorithm))
        payload = (encode_text_string(Tag.UniqueIdentifier, uid)
                   + encode_byte_string(Tag.Data, data) + params)
        resp = self._request(Operation.Sign, payload)
        return _v(resp, Tag.SignatureData)

    def signature_verify(self, uid: str, data: bytes, signature: bytes,
                         hashing_algorithm: int) -> int:
        params = encode_structure(
            Tag.CryptographicParameters,
            encode_enumeration(Tag.HashingAlgorithm, hashing_algorithm))
        payload = (encode_text_string(Tag.UniqueIdentifier, uid)
                   + encode_byte_string(Tag.Data, data)
                   + encode_byte_string(Tag.SignatureData, signature) + params)
        resp = self._request(Operation.SignatureVerify, payload)
        return _v(resp, Tag.ValidityIndicator)

    def mac(self, uid: str, data: bytes) -> bytes:
        payload = (encode_text_string(Tag.UniqueIdentifier, uid)
                   + encode_byte_string(Tag.Data, data))
        resp = self._request(Operation.MAC, payload)
        return _v(resp, Tag.MACData)

    def mac_verify(self, uid: str, data: bytes, mac_data: bytes) -> int:
        payload = (encode_text_string(Tag.UniqueIdentifier, uid)
                   + encode_byte_string(Tag.Data, data)
                   + encode_byte_string(Tag.MACData, mac_data))
        resp = self._request(Operation.MACVerify, payload)
        return _v(resp, Tag.ValidityIndicator)

    def hash(self, data: bytes, hashing_algorithm: int) -> bytes:
        """Hash needs no key - CryptographicParameters/HashingAlgorithm only."""
        params = encode_structure(
            Tag.CryptographicParameters,
            encode_enumeration(Tag.HashingAlgorithm, hashing_algorithm))
        resp = self._request(Operation.Hash,
                             encode_byte_string(Tag.Data, data) + params)
        return _v(resp, Tag.Data)

    def rng_retrieve(self, length: int) -> bytes:
        """RNGRetrieve: random bytes from the token. 1..65536."""
        resp = self._request(Operation.RNGRetrieve,
                             encode_integer(Tag.DataLength, length))
        return _v(resp, Tag.Data)

    def rng_seed(self, seed: bytes) -> int:
        resp = self._request(Operation.RNGSeed,
                             encode_byte_string(Tag.Data, seed))
        return _v(resp, Tag.DataLength)

    def validate(self, uids: Optional[list] = None,
                 certificates: Optional[list] = None) -> int:
        """Validate a certificate chain, by identifier or by value.
        Returns a ValidityIndicator."""
        payload = b""
        for uid in (uids or []):
            payload += encode_text_string(Tag.UniqueIdentifier, uid)
        for der in (certificates or []):
            payload += encode_structure(
                Tag.Certificate, encode_byte_string(Tag.CertificateValue, der))
        resp = self._request(Operation.Validate, payload)
        return _v(resp, Tag.ValidityIndicator)

    # ── derivation, certification, re-keying ──────────────────────────────────

    def rekey(self, uid: str, name: Optional[str] = None) -> str:
        """ReKey: a fresh symmetric key, cross-linked to the one it replaces."""
        payload = encode_text_string(Tag.UniqueIdentifier, uid) + _template(name)
        resp = self._request(Operation.ReKey, payload)
        return _v(resp, Tag.UniqueIdentifier)

    def rekey_key_pair(self, private_uid: str, name: Optional[str] = None):
        payload = encode_text_string(Tag.UniqueIdentifier, private_uid) + _template(name)
        resp = self._request(Operation.ReKeyKeyPair, payload)
        uids = [i.value for i in resp.get_all(Tag.UniqueIdentifier)]
        return tuple(uids[:2]) if len(uids) >= 2 else tuple(uids)

    def certify(self, public_uid: str, name: Optional[str] = None) -> str:
        """Certify: issue a certificate over an existing public key."""
        payload = encode_text_string(Tag.UniqueIdentifier, public_uid) + _template(name)
        resp = self._request(Operation.Certify, payload)
        return _v(resp, Tag.UniqueIdentifier)

    def recertify(self, certificate_uid: str, name: Optional[str] = None) -> str:
        payload = encode_text_string(Tag.UniqueIdentifier, certificate_uid) + _template(name)
        resp = self._request(Operation.ReCertify, payload)
        return _v(resp, Tag.UniqueIdentifier)

    def derive_key(self, uid: str, derivation_method: int,
                   derivation_data: bytes, name: Optional[str] = None) -> str:
        params = encode_structure(
            Tag.DerivationParameters,
            encode_byte_string(Tag.DerivationData, derivation_data))
        payload = (encode_text_string(Tag.UniqueIdentifier, uid)
                   + encode_enumeration(Tag.DerivationMethod, derivation_method)
                   + params + _template(name))
        resp = self._request(Operation.DeriveKey, payload)
        return _v(resp, Tag.UniqueIdentifier)

    # ── split keys ────────────────────────────────────────────────────────────

    def create_split_key(self, parts: int, threshold: int, method: int,
                         name: Optional[str] = None) -> list:
        payload = (encode_integer(Tag.SplitKeyParts, parts)
                   + encode_integer(Tag.SplitKeyThreshold, threshold)
                   + encode_enumeration(Tag.SplitKeyMethod, method)
                   + _template(name))
        resp = self._request(Operation.CreateSplitKey, payload)
        return [i.value for i in resp.get_all(Tag.UniqueIdentifier)]

    def join_split_key(self, part_uids: list, name: Optional[str] = None) -> str:
        payload = b""
        for uid in part_uids:
            payload += encode_text_string(Tag.UniqueIdentifier, uid)
        payload += _template(name)
        resp = self._request(Operation.JoinSplitKey, payload)
        return _v(resp, Tag.UniqueIdentifier)

    # ── bringing material in ──────────────────────────────────────────────────

    def register(self, object_type: int, key_material: bytes = b"",
                 certificate: bytes = b"", name: Optional[str] = None) -> str:
        """Register an object the server did not generate.

        SymmetricKey and SecretData both arrive as a KeyBlock; a Certificate
        arrives as a Certificate structure. OpaqueObject is deliberately absent:
        register.py reads it via `hasattr(Tag, 'OpaqueObject')` and this engine's
        Tag enum has no such member, so that branch can never fire and offering
        it here would be offering something that silently registers nothing.
        """
        payload = encode_enumeration(Tag.ObjectType, object_type)
        if key_material:
            payload += _key_block(key_material)
        if certificate:
            payload += encode_structure(
                Tag.Certificate, encode_byte_string(Tag.CertificateValue, certificate))
        payload += _template(name)
        resp = self._request(Operation.Register, payload)
        return _v(resp, Tag.UniqueIdentifier)

    def import_object(self, uid: str, object_type: int, key_material: bytes = b"",
                      replace_existing: bool = False) -> str:
        """Import: like Register, but the caller chooses the identifier.
        Named import_object because `import` is a Python keyword."""
        payload = (encode_text_string(Tag.UniqueIdentifier, uid)
                   + encode_enumeration(Tag.ObjectType, object_type)
                   + encode_boolean(Tag.ReplaceExisting, replace_existing))
        if key_material:
            payload += _key_block(key_material)
        resp = self._request(Operation.Import, payload)
        return _v(resp, Tag.UniqueIdentifier)

    # ── usage accounting ──────────────────────────────────────────────────────

    def check(self, uid: str, usage_limits_count: Optional[int] = None,
              usage_mask: Optional[int] = None,
              state: Optional[int] = None) -> dict:
        """Check whether an object may be used as proposed, without using it."""
        payload = encode_text_string(Tag.UniqueIdentifier, uid)
        if usage_limits_count is not None:
            payload += encode_integer(Tag.UsageLimitsCount, usage_limits_count)
        if usage_mask is not None:
            payload += encode_integer(Tag.CryptographicUsageMask, usage_mask)
        if state is not None:
            payload += encode_enumeration(Tag.State, state)
        resp = self._request(Operation.Check, payload)
        return {"uid": _v(resp, Tag.UniqueIdentifier),
                "usage_limits_count": _v(resp, Tag.UsageLimitsCount)}

    def get_usage_allocation(self, uid: str, count: int = 1) -> str:
        payload = (encode_text_string(Tag.UniqueIdentifier, uid)
                   + encode_integer(Tag.UsageLimitsCount, count))
        resp = self._request(Operation.GetUsageAllocation, payload)
        return _v(resp, Tag.UniqueIdentifier)

    # ── low-level transport ────────────────────────────────────────────────────

    def _request(self, operation: int, payload_bytes: bytes) -> TTLVItem:
        request = self._build_request(operation, payload_bytes)
        self._send(request)
        raw      = self._recv()
        response = decode_one(raw)
        return self._unwrap_response(response, operation)

    def _build_request(self, operation: int, payload_bytes: bytes) -> bytes:
        return self._build_batch_request([(operation, payload_bytes)])

    def _build_batch_request(
        self,
        items: List[tuple],
        batch_error_continuation: Optional[int] = None,
        max_response_size: Optional[int] = None,
    ) -> bytes:
        """Build a RequestMessage with one or more BatchItems. `items` is a
        list of (operation, payload_bytes) tuples."""
        pv = (
            encode_integer(Tag.ProtocolVersionMajor, self.PROTOCOL_VERSION[0])
            + encode_integer(Tag.ProtocolVersionMinor, self.PROTOCOL_VERSION[1])
        )
        header_fields = encode_structure(Tag.ProtocolVersion, pv)

        if self._username is not None:
            cred_value = (
                encode_text_string(Tag.Username, self._username)
                + encode_text_string(Tag.Password, self._password or "")
            )
            credential = encode_structure(
                Tag.Credential,
                encode_enumeration(Tag.CredentialType, CredentialType.UsernameAndPassword)
                + encode_structure(Tag.CredentialValue, cred_value)
            )
            header_fields += encode_structure(Tag.Authentication, credential)

        if batch_error_continuation is not None:
            header_fields += encode_enumeration(Tag.BatchErrorContinuationOption, batch_error_continuation)
        if max_response_size is not None:
            header_fields += encode_integer(Tag.MaximumResponseSize, max_response_size)

        header_fields += encode_integer(Tag.BatchCount, len(items))
        header = encode_structure(Tag.RequestHeader, header_fields)

        batch_bytes = b""
        for operation, payload_bytes in items:
            self._batch_counter += 1
            batch_id = self._batch_counter.to_bytes(4, 'big')
            batch_bytes += encode_structure(
                Tag.BatchItem,
                encode_enumeration(Tag.Operation, operation)
                + encode_byte_string(Tag.UniqueBatchItemID, batch_id)
                + encode_structure(Tag.RequestPayload, payload_bytes)
            )
        return encode_structure(Tag.RequestMessage, header + batch_bytes)

    def raw_batch_request(
        self,
        items: List[tuple],
        batch_error_continuation: Optional[int] = None,
        max_response_size: Optional[int] = None,
    ) -> TTLVItem:
        """Send a multi-item batch request and return the decoded
        ResponseMessage as-is (no unwrap/raise) — for tests inspecting
        per-item results or whole-message-level errors directly."""
        request = self._build_batch_request(items, batch_error_continuation, max_response_size)
        self._send(request)
        raw = self._recv()
        return decode_one(raw)

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

def _block_cipher_mode(mode: int) -> bytes:
    """Encode the requested mode as CryptographicParameters.

    The server reads the mode from here and defaults to CBC when it is absent,
    so omitting this made the `mode` argument silently do nothing — asking for
    GCM got you CBC, with no error to say so."""
    return encode_structure(
        Tag.CryptographicParameters,
        encode_enumeration(Tag.CryptographicParameters_BlockCipherMode, mode),
    )


def _v(item: TTLVItem, tag: int):
    """Value of `tag` in a response, or None when the server omitted it.

    Responses are sparse by design - an optional field simply is not there -
    so reaching through .get(...).value directly turns a legitimate omission
    into an AttributeError several frames from the cause.
    """
    found = item.get(tag) if item is not None else None
    return found.value if found is not None else None


def _key_block(material: bytes) -> bytes:
    """The KeyBlock that Register and Import expect around raw material:
    KeyBlock > KeyValue > KeyMaterial, which is what register.py unwraps."""
    return encode_structure(
        Tag.KeyBlock,
        encode_structure(Tag.KeyValue,
                         encode_byte_string(Tag.KeyMaterial, material)))


def _template(name=None) -> bytes:
    """A TemplateAttribute carrying an optional Name, which is all the
    operations that accept one need from the client side."""
    if not name:
        return b""
    return encode_structure(
        Tag.TemplateAttribute,
        _attr("Name", encode_structure(Tag.AttributeValue,
                                       encode_text_string(Tag.NameValue, name))))


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
