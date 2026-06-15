"""
Async KMIP TCP server (KMIP 2.1).

Architecture
------------
KmipServer
  - Listens on settings.kmip_host:settings.kmip_port (default 0.0.0.0:5696)
  - Optionally wraps connections in TLS (required in production)
  - Reads length-prefixed KMIP messages from the wire
  - Delegates every request to KmipDispatcher.dispatch()
  - Writes the response bytes back

KmipDispatcher
  - Parses the RequestMessage
  - Routes to the appropriate handle_<operation>() method
  - Returns a serialised ResponseMessage

The dispatcher's handle_* methods are implemented with full request parsing
and response construction here.  Business logic (key creation, storage, etc.)
is delegated to a KeyManager instance whose interface is described via type
stubs in this module; the real implementation lives in kms.core.manager.
"""

from __future__ import annotations

import asyncio
import logging
import os
import ssl
import struct
from datetime import datetime, timezone
from typing import Any

from ..config import settings
from .enums import (
    ItemType,
    ObjectState,
    ObjectType,
    Operation,
    ProfileName,
    ResultReason,
    ResultStatus,
    Tag,
)
from .messages import (
    build_error_item,
    build_response_item,
    build_response_message,
    get_batch_item_id,
    get_batch_item_operation,
    get_request_payload,
    parse_request_message,
)
from .ttlv import (
    TlvItem,
    encode_item,
    find_all_children,
    find_child,
    get_int,
    get_text,
    make_enum,
    make_int,
    make_structure,
    make_text,
    make_bytes,
    make_datetime,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# KeyManager stub (actual implementation in kms.core.manager)
# ---------------------------------------------------------------------------
# These stubs describe the interface expected by KmipDispatcher so that the
# dispatcher can be tested independently of the real key-manager.


class KeyManagerStub:  # pragma: no cover
    """Minimal interface stub for kms.core.manager.KeyManager.

    Replace with the real KeyManager at startup by passing an instance to
    KmipDispatcher.__init__.
    """

    async def create_symmetric_key(
        self,
        algorithm: str,
        length: int,
        usage_mask: int,
        name: str | None,
        object_group: str | None,
        **kwargs: Any,
    ) -> str:
        raise NotImplementedError

    async def create_key_pair(
        self,
        algorithm: str,
        length: int | None,
        curve: str | None,
        usage_mask_private: int,
        usage_mask_public: int,
        name: str | None,
        **kwargs: Any,
    ) -> tuple[str, str]:  # (private_uid, public_uid)
        raise NotImplementedError

    async def register_object(
        self,
        object_type: str,
        object_data: dict[str, Any],
        name: str | None,
        **kwargs: Any,
    ) -> str:
        raise NotImplementedError

    async def get_object(self, uid: str, **kwargs: Any) -> dict[str, Any]:
        raise NotImplementedError

    async def get_attributes(
        self, uid: str, attribute_names: list[str] | None, **kwargs: Any
    ) -> dict[str, Any]:
        raise NotImplementedError

    async def get_attribute_list(self, uid: str, **kwargs: Any) -> list[str]:
        raise NotImplementedError

    async def set_attribute(
        self, uid: str, attribute_name: str, attribute_value: Any, **kwargs: Any
    ) -> None:
        raise NotImplementedError

    async def locate_objects(self, filters: dict[str, Any], **kwargs: Any) -> list[str]:
        raise NotImplementedError

    async def activate_object(self, uid: str, **kwargs: Any) -> None:
        raise NotImplementedError

    async def revoke_object(
        self, uid: str, reason_code: int, reason_message: str | None, **kwargs: Any
    ) -> None:
        raise NotImplementedError

    async def destroy_object(self, uid: str, **kwargs: Any) -> None:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# KmipDispatcher
# ---------------------------------------------------------------------------


class KmipDispatcher:
    """Parses and dispatches KMIP request messages.

    Parameters
    ----------
    key_manager:
        An object that implements the KeyManagerStub interface.  Pass the
        real kms.core.manager.KeyManager in production.
    server_vendor_id:
        Vendor identification string returned in Query responses.
    """

    # Supported operations advertised in Query responses
    _SUPPORTED_OPERATIONS: list[Operation] = [
        Operation.DISCOVER_VERSIONS,
        Operation.QUERY,
        Operation.CREATE,
        Operation.CREATE_KEY_PAIR,
        Operation.REGISTER,
        Operation.LOCATE,
        Operation.GET,
        Operation.GET_ATTRIBUTES,
        Operation.GET_ATTRIBUTE_LIST,
        Operation.SET_ATTRIBUTE,
        Operation.ACTIVATE,
        Operation.REVOKE,
        Operation.DESTROY,
    ]

    _SUPPORTED_VERSIONS: list[tuple[int, int]] = [(2, 1), (2, 0), (1, 4), (1, 3)]

    def __init__(
        self,
        key_manager: Any | None = None,
        server_vendor_id: str = "KMS Python KMIP 2.1 Server",
    ) -> None:
        self._km = key_manager or KeyManagerStub()
        self._vendor_id = server_vendor_id

    # ------------------------------------------------------------------
    # Top-level dispatch
    # ------------------------------------------------------------------

    async def dispatch(
        self,
        request_bytes: bytes,
        peer_cert: dict | None,
    ) -> bytes:
        """Parse *request_bytes* and dispatch each batch item.

        Returns the encoded ResponseMessage bytes.
        """
        try:
            parsed = parse_request_message(request_bytes)
        except Exception as exc:
            logger.warning("Failed to parse KMIP request: %s", exc)
            error_item = build_error_item(
                operation=Operation.QUERY,  # best-effort placeholder
                reason=ResultReason.INVALID_MESSAGE,
                message=f"Message parse error: {exc}",
            )
            return build_response_message([error_item])

        response_items: list[TlvItem] = []

        for batch_item in parsed["batch_items"]:
            batch_id = get_batch_item_id(batch_item)
            try:
                operation = get_batch_item_operation(batch_item)
            except Exception as exc:
                logger.warning("Cannot extract operation from BatchItem: %s", exc)
                response_items.append(
                    build_error_item(
                        operation=Operation.QUERY,
                        reason=ResultReason.INVALID_MESSAGE,
                        message=f"Cannot determine operation: {exc}",
                        batch_id=batch_id,
                    )
                )
                continue

            payload = get_request_payload(batch_item)
            try:
                response_payload = await self._dispatch_operation(
                    operation, payload, peer_cert
                )
                response_items.append(
                    build_response_item(
                        operation=operation,
                        status=ResultStatus.SUCCESS,
                        payload=response_payload,
                        batch_id=batch_id,
                    )
                )
            except KmipOperationError as exc:
                logger.info(
                    "KMIP operation %s failed: [%s] %s",
                    operation.name,
                    exc.reason.name,
                    exc.message,
                )
                response_items.append(
                    build_error_item(
                        operation=operation,
                        reason=exc.reason,
                        message=exc.message,
                        batch_id=batch_id,
                    )
                )
            except Exception as exc:
                logger.exception("Unexpected error dispatching %s", operation.name)
                response_items.append(
                    build_error_item(
                        operation=operation,
                        reason=ResultReason.CRYPTOGRAPHIC_FAILURE,
                        message=f"Internal server error: {type(exc).__name__}",
                        batch_id=batch_id,
                    )
                )

        return build_response_message(response_items)

    async def _dispatch_operation(
        self,
        operation: Operation,
        payload: TlvItem | None,
        peer_cert: dict | None,
    ) -> TlvItem | None:
        """Route to the correct handler method."""
        handlers = {
            Operation.DISCOVER_VERSIONS: self.handle_discover_versions,
            Operation.QUERY: self.handle_query,
            Operation.CREATE: self.handle_create,
            Operation.CREATE_KEY_PAIR: self.handle_create_key_pair,
            Operation.REGISTER: self.handle_register,
            Operation.LOCATE: self.handle_locate,
            Operation.GET: self.handle_get,
            Operation.GET_ATTRIBUTES: self.handle_get_attributes,
            Operation.GET_ATTRIBUTE_LIST: self.handle_get_attribute_list,
            Operation.SET_ATTRIBUTE: self.handle_set_attribute,
            Operation.ACTIVATE: self.handle_activate,
            Operation.REVOKE: self.handle_revoke,
            Operation.DESTROY: self.handle_destroy,
        }
        handler = handlers.get(operation)
        if handler is None:
            raise KmipOperationError(
                ResultReason.OPERATION_NOT_SUPPORTED,
                f"Operation {operation.name} is not supported by this server",
            )
        return await handler(payload, peer_cert)

    # ------------------------------------------------------------------
    # Operation handlers
    # ------------------------------------------------------------------

    async def handle_discover_versions(
        self, payload: TlvItem | None, peer_cert: dict | None
    ) -> TlvItem:
        """Return the list of supported protocol versions.

        Request payload (optional): zero or more ProtocolVersion structures
        indicating which versions the client wants to check.  If absent,
        return all supported versions.
        """
        requested: list[tuple[int, int]] = []
        if payload is not None:
            for pv in find_all_children(payload, Tag.PROTOCOL_VERSION):
                major_item = find_child(pv, Tag.PROTOCOL_VERSION_MAJOR)
                minor_item = find_child(pv, Tag.PROTOCOL_VERSION_MINOR)
                if major_item is not None and minor_item is not None:
                    requested.append((get_int(major_item), get_int(minor_item)))

        if requested:
            versions = [v for v in self._SUPPORTED_VERSIONS if v in requested]
        else:
            versions = self._SUPPORTED_VERSIONS

        children: list[TlvItem] = []
        for major, minor in versions:
            children.append(
                make_structure(
                    Tag.PROTOCOL_VERSION,
                    [
                        make_int(Tag.PROTOCOL_VERSION_MAJOR, major),
                        make_int(Tag.PROTOCOL_VERSION_MINOR, minor),
                    ],
                )
            )

        return make_structure(Tag.RESPONSE_PAYLOAD, children)

    async def handle_query(
        self, payload: TlvItem | None, peer_cert: dict | None
    ) -> TlvItem:
        """Return server capabilities.

        Query Function values (per KMIP spec):
          1 = Query Operations
          2 = Query Objects
          3 = Query Server Information
          4 = Query Application Namespaces
          5 = Query Extension List
          6 = Query Extension Map
          7 = Query Attestation Types
          8 = Query RNGs
          9 = Query Validations
          10 = Query Profiles
          11 = Query Capabilities
          12 = Query Client Registration Methods
        We respond to all query functions by populating everything we support.
        """
        children: list[TlvItem] = []

        # Operations
        for op in self._SUPPORTED_OPERATIONS:
            children.append(make_enum(Tag.OPERATION, int(op)))

        # Vendor identification
        children.append(make_text(Tag.VENDOR_IDENTIFICATION, self._vendor_id))

        # Server information (minimal)
        children.append(
            make_structure(
                Tag.SERVER_INFORMATION,
                [make_text(Tag.VENDOR_IDENTIFICATION, self._vendor_id)],
            )
        )

        # Supported profiles
        for profile in (
            ProfileName.BASELINE_SERVER_TLS12_KMIPv2_1,
            ProfileName.COMPLETE_SERVER_TLS12_KMIPv2_1,
        ):
            children.append(
                make_structure(
                    Tag.PROFILE_INFORMATION,
                    [make_enum(Tag.PROFILE_NAME, int(profile))],
                )
            )

        return make_structure(Tag.RESPONSE_PAYLOAD, children)

    async def handle_create(
        self, payload: TlvItem | None, peer_cert: dict | None
    ) -> TlvItem:
        """Handle a Create (symmetric key) request.

        Expected payload::

            RequestPayload {
                ObjectType (Enumeration)        -- must be SymmetricKey
                Attributes {
                    CryptographicAlgorithm (Enumeration)
                    CryptographicLength (Integer)
                    CryptographicUsageMask (Integer)
                    [Name { NameValue, NameType }]
                    ...
                }
            }
        """
        if payload is None:
            raise KmipOperationError(ResultReason.MISSING_DATA, "Create payload is required")

        object_type_item = find_child(payload, Tag.OBJECT_TYPE)
        if object_type_item is None:
            raise KmipOperationError(ResultReason.MISSING_DATA, "ObjectType is required")
        object_type = get_int(object_type_item)
        if object_type != ObjectType.SYMMETRIC_KEY:
            raise KmipOperationError(
                ResultReason.INVALID_OBJECT_TYPE,
                f"Create only supports SymmetricKey, got ObjectType={object_type}",
            )

        attrs = find_child(payload, Tag.COMMON_ATTRIBUTES) or find_child(
            payload, Tag.ATTRIBUTE
        )
        # KMIP 2.x uses Attributes (tag COMMON_ATTRIBUTES=0x420020) to
        # enclose template attributes; fall back to searching the payload root
        attr_parent = attrs if attrs is not None else payload

        algorithm = _extract_enum_from_attrs(attr_parent, Tag.CRYPTOGRAPHIC_ALGORITHM)
        if algorithm is None:
            raise KmipOperationError(
                ResultReason.MISSING_DATA, "CryptographicAlgorithm is required"
            )

        length = _extract_int_from_attrs(attr_parent, Tag.CRYPTOGRAPHIC_LENGTH)
        if length is None:
            raise KmipOperationError(
                ResultReason.MISSING_DATA, "CryptographicLength is required"
            )

        usage_mask = _extract_int_from_attrs(attr_parent, Tag.CRYPTOGRAPHIC_USAGE_MASK)
        if usage_mask is None:
            usage_mask = 0

        name = _extract_name_from_attrs(attr_parent)
        object_group = _extract_text_from_attrs(attr_parent, Tag.OBJECT_GROUP)

        from .enums import CryptographicAlgorithm  # noqa: PLC0415

        try:
            algo_name = CryptographicAlgorithm(algorithm).name
        except ValueError:
            algo_name = str(algorithm)

        uid = await self._km.create_symmetric_key(
            algorithm=algo_name,
            length=length,
            usage_mask=usage_mask,
            name=name,
            object_group=object_group,
        )

        return make_structure(
            Tag.RESPONSE_PAYLOAD,
            [
                make_enum(Tag.OBJECT_TYPE, int(ObjectType.SYMMETRIC_KEY)),
                make_text(Tag.UNIQUE_IDENTIFIER, uid),
            ],
        )

    async def handle_create_key_pair(
        self, payload: TlvItem | None, peer_cert: dict | None
    ) -> TlvItem:
        """Handle a CreateKeyPair request.

        Expected payload::

            RequestPayload {
                CommonAttributes / PrivateKeyAttributes / PublicKeyAttributes {
                    CryptographicAlgorithm
                    CryptographicLength / RecommendedCurve
                    CryptographicUsageMask
                    [Name]
                }
            }
        """
        if payload is None:
            raise KmipOperationError(
                ResultReason.MISSING_DATA, "CreateKeyPair payload is required"
            )

        # Attributes may be under CommonAttributes or the payload root
        common_attrs = find_child(payload, Tag.COMMON_ATTRIBUTES) or payload
        private_attrs = find_child(payload, Tag.ATTRIBUTE) or common_attrs
        public_attrs = common_attrs

        algorithm = _extract_enum_from_attrs(common_attrs, Tag.CRYPTOGRAPHIC_ALGORITHM)
        if algorithm is None:
            raise KmipOperationError(
                ResultReason.MISSING_DATA, "CryptographicAlgorithm is required"
            )

        length = _extract_int_from_attrs(common_attrs, Tag.CRYPTOGRAPHIC_LENGTH)
        curve = _extract_enum_from_attrs(common_attrs, Tag.RECOMMENDED_CURVE)

        priv_usage = _extract_int_from_attrs(private_attrs, Tag.CRYPTOGRAPHIC_USAGE_MASK) or 0
        pub_usage = _extract_int_from_attrs(public_attrs, Tag.CRYPTOGRAPHIC_USAGE_MASK) or 0

        name = _extract_name_from_attrs(common_attrs)

        from .enums import CryptographicAlgorithm as CAlg, RecommendedCurve  # noqa: PLC0415

        try:
            algo_name = CAlg(algorithm).name
        except ValueError:
            algo_name = str(algorithm)

        curve_name: str | None = None
        if curve is not None:
            try:
                curve_name = RecommendedCurve(curve).name
            except ValueError:
                curve_name = str(curve)

        private_uid, public_uid = await self._km.create_key_pair(
            algorithm=algo_name,
            length=length,
            curve=curve_name,
            usage_mask_private=priv_usage,
            usage_mask_public=pub_usage,
            name=name,
        )

        return make_structure(
            Tag.RESPONSE_PAYLOAD,
            [
                make_text(Tag.PRIVATE_KEY_UNIQUE_IDENTIFIER, private_uid),
                make_text(Tag.PUBLIC_KEY_UNIQUE_IDENTIFIER, public_uid),
            ],
        )

    async def handle_register(
        self, payload: TlvItem | None, peer_cert: dict | None
    ) -> TlvItem:
        """Handle a Register request (import an existing object).

        Supports registering SymmetricKey, Certificate, SecretData,
        PrivateKey, and PublicKey objects.
        """
        if payload is None:
            raise KmipOperationError(
                ResultReason.MISSING_DATA, "Register payload is required"
            )

        object_type_item = find_child(payload, Tag.OBJECT_TYPE)
        if object_type_item is None:
            raise KmipOperationError(ResultReason.MISSING_DATA, "ObjectType is required")
        object_type = get_int(object_type_item)

        # Build an object_data dict from the payload for the key manager
        object_data: dict[str, Any] = {
            "object_type": object_type,
        }

        # Attempt to extract key block / certificate value
        sym_key = find_child(payload, Tag.SYMMETRIC_KEY)
        priv_key = find_child(payload, Tag.PRIVATE_KEY)
        pub_key = find_child(payload, Tag.PUBLIC_KEY)
        cert = find_child(payload, Tag.CERTIFICATE)
        secret = find_child(payload, Tag.SECRET_DATA)

        if sym_key is not None:
            object_data["key_block"] = _extract_key_block(sym_key)
        elif priv_key is not None:
            object_data["key_block"] = _extract_key_block(priv_key)
        elif pub_key is not None:
            object_data["key_block"] = _extract_key_block(pub_key)
        elif cert is not None:
            cert_val_item = find_child(cert, Tag.CERTIFICATE_VALUE)
            if cert_val_item is not None:
                assert isinstance(cert_val_item.value, bytes)
                object_data["certificate_value"] = cert_val_item.value
        elif secret is not None:
            object_data["key_block"] = _extract_key_block(secret)

        common_attrs = find_child(payload, Tag.COMMON_ATTRIBUTES) or payload
        name = _extract_name_from_attrs(common_attrs)

        uid = await self._km.register_object(
            object_type=str(object_type),
            object_data=object_data,
            name=name,
        )

        return make_structure(
            Tag.RESPONSE_PAYLOAD,
            [make_text(Tag.UNIQUE_IDENTIFIER, uid)],
        )

    async def handle_locate(
        self, payload: TlvItem | None, peer_cert: dict | None
    ) -> TlvItem:
        """Handle a Locate request.

        Supported filters: ObjectType, State, Name, CryptographicAlgorithm.
        """
        filters: dict[str, Any] = {}

        if payload is not None:
            obj_type_item = find_child(payload, Tag.OBJECT_TYPE)
            if obj_type_item is not None:
                filters["object_type"] = get_int(obj_type_item)

            state_item = find_child(payload, Tag.STATE)
            if state_item is not None:
                filters["state"] = get_int(state_item)

            algo_item = find_child(payload, Tag.CRYPTOGRAPHIC_ALGORITHM)
            if algo_item is not None:
                filters["cryptographic_algorithm"] = get_int(algo_item)

            for name_item in find_all_children(payload, Tag.NAME):
                nv = find_child(name_item, Tag.NAME_VALUE)
                if nv is not None:
                    filters.setdefault("names", []).append(get_text(nv))

            group_item = find_child(payload, Tag.OBJECT_GROUP)
            if group_item is not None:
                filters["object_group"] = get_text(group_item)

            max_items_item = find_child(payload, Tag.MAXIMUM_ITEMS)
            if max_items_item is not None:
                filters["maximum_items"] = get_int(max_items_item)

            offset_item = find_child(payload, Tag.OFFSET_ITEMS)
            if offset_item is not None:
                filters["offset_items"] = get_int(offset_item)

        uids = await self._km.locate_objects(filters=filters)

        children: list[TlvItem] = [
            make_text(Tag.UNIQUE_IDENTIFIER, uid) for uid in uids
        ]
        return make_structure(Tag.RESPONSE_PAYLOAD, children)

    async def handle_get(
        self, payload: TlvItem | None, peer_cert: dict | None
    ) -> TlvItem:
        """Handle a Get request: retrieve the key/object material."""
        if payload is None:
            raise KmipOperationError(ResultReason.MISSING_DATA, "Get payload is required")

        uid_item = find_child(payload, Tag.UNIQUE_IDENTIFIER)
        if uid_item is None:
            raise KmipOperationError(ResultReason.MISSING_DATA, "UniqueIdentifier is required")
        uid = get_text(uid_item)

        key_format_item = find_child(payload, Tag.KEY_FORMAT_TYPE)
        key_format: int | None = None
        if key_format_item is not None:
            key_format = get_int(key_format_item)

        obj = await self._km.get_object(uid, key_format_type=key_format)

        return _build_get_response_payload(uid, obj)

    async def handle_get_attributes(
        self, payload: TlvItem | None, peer_cert: dict | None
    ) -> TlvItem:
        """Handle a GetAttributes request."""
        if payload is None:
            raise KmipOperationError(
                ResultReason.MISSING_DATA, "GetAttributes payload is required"
            )

        uid_item = find_child(payload, Tag.UNIQUE_IDENTIFIER)
        if uid_item is None:
            raise KmipOperationError(ResultReason.MISSING_DATA, "UniqueIdentifier is required")
        uid = get_text(uid_item)

        # Attribute names requested (KMIP 2.x uses AttributeReference / text list)
        attr_names: list[str] = []
        for attr_ref in find_all_children(payload, Tag.ATTRIBUTE_REFERENCE):
            if attr_ref.type == ItemType.TEXT_STRING:
                attr_names.append(get_text(attr_ref))
            elif attr_ref.type == ItemType.STRUCTURE:
                an = find_child(attr_ref, Tag.ATTRIBUTE_NAME)
                if an is not None:
                    attr_names.append(get_text(an))
        # Legacy KMIP 1.x: Attribute Name items
        for an_item in find_all_children(payload, Tag.ATTRIBUTE_NAME):
            attr_names.append(get_text(an_item))

        attrs = await self._km.get_attributes(
            uid, attribute_names=attr_names or None
        )

        return _build_get_attributes_payload(uid, attrs)

    async def handle_get_attribute_list(
        self, payload: TlvItem | None, peer_cert: dict | None
    ) -> TlvItem:
        """Handle a GetAttributeList request."""
        uid: str | None = None
        if payload is not None:
            uid_item = find_child(payload, Tag.UNIQUE_IDENTIFIER)
            if uid_item is not None:
                uid = get_text(uid_item)

        if uid is None:
            raise KmipOperationError(ResultReason.MISSING_DATA, "UniqueIdentifier is required")

        attr_names = await self._km.get_attribute_list(uid)

        children: list[TlvItem] = [make_text(Tag.UNIQUE_IDENTIFIER, uid)]
        for name in attr_names:
            children.append(make_text(Tag.ATTRIBUTE_NAME, name))

        return make_structure(Tag.RESPONSE_PAYLOAD, children)

    async def handle_set_attribute(
        self, payload: TlvItem | None, peer_cert: dict | None
    ) -> TlvItem:
        """Handle a SetAttribute request (KMIP 2.x style)."""
        if payload is None:
            raise KmipOperationError(
                ResultReason.MISSING_DATA, "SetAttribute payload is required"
            )

        uid_item = find_child(payload, Tag.UNIQUE_IDENTIFIER)
        if uid_item is None:
            raise KmipOperationError(ResultReason.MISSING_DATA, "UniqueIdentifier is required")
        uid = get_text(uid_item)

        # KMIP 2.x: NewAttribute structure
        new_attr = find_child(payload, Tag.NEW_ATTRIBUTE)
        if new_attr is None:
            # KMIP 1.x: Attribute structure with AttributeName / AttributeValue
            attr = find_child(payload, Tag.ATTRIBUTE)
            if attr is None:
                raise KmipOperationError(ResultReason.MISSING_DATA, "Attribute is required")
            an_item = find_child(attr, Tag.ATTRIBUTE_NAME)
            av_item = find_child(attr, Tag.ATTRIBUTE_VALUE)
            if an_item is None:
                raise KmipOperationError(ResultReason.MISSING_DATA, "AttributeName is required")
            attr_name = get_text(an_item)
            attr_value: Any = av_item
        else:
            # NewAttribute has a single child whose tag IS the attribute name
            assert isinstance(new_attr.value, list)
            if not new_attr.value:
                raise KmipOperationError(
                    ResultReason.MISSING_DATA, "NewAttribute must have at least one child"
                )
            child = new_attr.value[0]
            try:
                attr_name = Tag(child.tag).name
            except ValueError:
                attr_name = f"0x{child.tag:06X}"
            attr_value = child

        await self._km.set_attribute(uid, attr_name, attr_value)

        return make_structure(
            Tag.RESPONSE_PAYLOAD,
            [make_text(Tag.UNIQUE_IDENTIFIER, uid)],
        )

    async def handle_activate(
        self, payload: TlvItem | None, peer_cert: dict | None
    ) -> TlvItem:
        """Handle an Activate request."""
        uid = _require_unique_identifier(payload, "Activate")
        await self._km.activate_object(uid)
        return make_structure(
            Tag.RESPONSE_PAYLOAD,
            [make_text(Tag.UNIQUE_IDENTIFIER, uid)],
        )

    async def handle_revoke(
        self, payload: TlvItem | None, peer_cert: dict | None
    ) -> TlvItem:
        """Handle a Revoke request."""
        if payload is None:
            raise KmipOperationError(ResultReason.MISSING_DATA, "Revoke payload is required")

        uid_item = find_child(payload, Tag.UNIQUE_IDENTIFIER)
        if uid_item is None:
            raise KmipOperationError(ResultReason.MISSING_DATA, "UniqueIdentifier is required")
        uid = get_text(uid_item)

        reason_code: int = 1  # UNSPECIFIED
        reason_message: str | None = None

        revocation_reason = find_child(payload, Tag.REVOCATION_REASON)
        if revocation_reason is not None:
            rc_item = find_child(revocation_reason, Tag.REVOCATION_REASON_CODE)
            if rc_item is not None:
                reason_code = get_int(rc_item)
            rm_item = find_child(revocation_reason, Tag.REVOCATION_MESSAGE)
            if rm_item is not None:
                reason_message = get_text(rm_item)

        await self._km.revoke_object(uid, reason_code, reason_message)

        return make_structure(
            Tag.RESPONSE_PAYLOAD,
            [make_text(Tag.UNIQUE_IDENTIFIER, uid)],
        )

    async def handle_destroy(
        self, payload: TlvItem | None, peer_cert: dict | None
    ) -> TlvItem:
        """Handle a Destroy request."""
        uid = _require_unique_identifier(payload, "Destroy")
        await self._km.destroy_object(uid)
        return make_structure(
            Tag.RESPONSE_PAYLOAD,
            [make_text(Tag.UNIQUE_IDENTIFIER, uid)],
        )


# ---------------------------------------------------------------------------
# KmipOperationError
# ---------------------------------------------------------------------------


class KmipOperationError(Exception):
    """Raised by handler methods to signal a KMIP-level failure."""

    def __init__(self, reason: ResultReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


# ---------------------------------------------------------------------------
# KmipServer
# ---------------------------------------------------------------------------

# Number of bytes in the fixed outer TTLV header: 8 bytes.
# For a Structure item the header is [3B tag][1B type][4B length], and the
# length field tells us how many additional bytes to read.
_TTLV_HEADER_SIZE = 8


class KmipServer:
    """Async KMIP server that listens for TTLV-encoded requests.

    Parameters
    ----------
    dispatcher:
        A KmipDispatcher (or compatible object) to handle requests.
    use_tls:
        If True (default), wrap all connections in TLS using the certificate
        and key files from settings.  Set to False for plaintext development
        mode (never in production).
    require_client_cert:
        If True (and use_tls=True), enforce mutual TLS; clients must present
        a certificate signed by the configured CA.
    """

    def __init__(
        self,
        dispatcher: KmipDispatcher,
        use_tls: bool = True,
        require_client_cert: bool = False,
    ) -> None:
        self._dispatcher = dispatcher
        self._use_tls = use_tls
        self._require_client_cert = require_client_cert
        self._server: asyncio.AbstractServer | None = None

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Build and return an SSLContext from the configured cert/key files."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        cert_file = settings.tls_cert_file
        key_file = settings.tls_key_file
        ca_file = settings.tls_ca_file

        if not os.path.isfile(cert_file):
            raise FileNotFoundError(
                f"TLS certificate file not found: {cert_file!r}. "
                "Generate certs or set tls_cert_file in your .env"
            )
        if not os.path.isfile(key_file):
            raise FileNotFoundError(
                f"TLS key file not found: {key_file!r}. "
                "Generate certs or set tls_key_file in your .env"
            )

        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)

        if self._require_client_cert:
            if not os.path.isfile(ca_file):
                raise FileNotFoundError(
                    f"TLS CA file not found: {ca_file!r}. "
                    "Required for mutual TLS. Set tls_ca_file in your .env"
                )
            ctx.load_verify_locations(cafile=ca_file)
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            # Load CA for optional client cert verification if file exists
            if os.path.isfile(ca_file):
                ctx.load_verify_locations(cafile=ca_file)
            ctx.verify_mode = ssl.CERT_OPTIONAL

        return ctx

    async def start(self) -> None:
        """Start the KMIP server and begin accepting connections."""
        ssl_ctx: ssl.SSLContext | None = None
        if self._use_tls:
            ssl_ctx = self._build_ssl_context()
            mode = "TLS"
        else:
            mode = "plaintext (development)"
            logger.warning(
                "KMIP server starting in PLAINTEXT mode — do NOT use in production!"
            )

        host = settings.kmip_host
        port = settings.kmip_port

        self._server = await asyncio.start_server(
            self._handle_connection,
            host=host,
            port=port,
            ssl=ssl_ctx,
        )

        addrs = ", ".join(str(sock.getsockname()) for sock in self._server.sockets)
        logger.info("KMIP server listening on %s (%s)", addrs, mode)

        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        """Gracefully stop the server."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            logger.info("KMIP server stopped")

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle one client connection (one or many requests)."""
        peer = writer.get_extra_info("peername", "<unknown>")
        peer_cert: dict | None = None
        if self._use_tls:
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj is not None:
                peer_cert = ssl_obj.getpeercert()

        logger.debug("KMIP connection from %s (cert=%s)", peer, bool(peer_cert))

        try:
            await self._serve_connection(reader, writer, peer_cert)
        except asyncio.IncompleteReadError:
            logger.debug("Client %s disconnected mid-message", peer)
        except Exception as exc:
            logger.warning("Error serving KMIP client %s: %s", peer, exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            logger.debug("KMIP connection from %s closed", peer)

    async def _serve_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer_cert: dict | None,
    ) -> None:
        """Read KMIP messages in a loop until the connection closes."""
        while True:
            # --- Read the 8-byte TTLV header of the outer RequestMessage ---
            header_bytes = await reader.readexactly(_TTLV_HEADER_SIZE)

            # The TTLV header is: [3-byte tag | 1-byte type][4-byte length]
            # We only need the length field to know how many more bytes to read.
            length = struct.unpack_from(">I", header_bytes, 4)[0]

            # Read the rest of the message (the Structure body)
            body_bytes = await reader.readexactly(length)

            request_bytes = header_bytes + body_bytes

            response_bytes = await self._dispatcher.dispatch(
                request_bytes, peer_cert
            )

            writer.write(response_bytes)
            await writer.drain()


# ---------------------------------------------------------------------------
# Private helpers used by dispatcher handlers
# ---------------------------------------------------------------------------


def _require_unique_identifier(payload: TlvItem | None, op: str) -> str:
    """Extract UniqueIdentifier from payload or raise KmipOperationError."""
    if payload is None:
        raise KmipOperationError(
            ResultReason.MISSING_DATA, f"{op} payload is required"
        )
    uid_item = find_child(payload, Tag.UNIQUE_IDENTIFIER)
    if uid_item is None:
        raise KmipOperationError(
            ResultReason.MISSING_DATA, "UniqueIdentifier is required"
        )
    return get_text(uid_item)


def _extract_enum_from_attrs(parent: TlvItem, tag: int) -> int | None:
    """Find the first child with *tag* in *parent* and return its integer value."""
    item = find_child(parent, tag)
    if item is None:
        return None
    return get_int(item)


def _extract_int_from_attrs(parent: TlvItem, tag: int) -> int | None:
    """Find the first child with *tag* in *parent* and return its integer value."""
    item = find_child(parent, tag)
    if item is None:
        return None
    return get_int(item)


def _extract_text_from_attrs(parent: TlvItem, tag: int) -> str | None:
    """Find the first child with *tag* in *parent* and return its text value."""
    item = find_child(parent, tag)
    if item is None:
        return None
    return get_text(item)


def _extract_name_from_attrs(parent: TlvItem) -> str | None:
    """Extract the first Name.NameValue from *parent*, if any."""
    name_item = find_child(parent, Tag.NAME)
    if name_item is None:
        return None
    nv = find_child(name_item, Tag.NAME_VALUE)
    if nv is None:
        return None
    return get_text(nv)


def _extract_key_block(obj_item: TlvItem) -> dict[str, Any]:
    """Extract key block fields from a key-bearing structure."""
    result: dict[str, Any] = {}
    key_block = find_child(obj_item, Tag.KEY_BLOCK)
    if key_block is None:
        return result

    kft = find_child(key_block, Tag.KEY_FORMAT_TYPE)
    if kft is not None:
        result["key_format_type"] = get_int(kft)

    alg = find_child(key_block, Tag.CRYPTOGRAPHIC_ALGORITHM)
    if alg is not None:
        result["cryptographic_algorithm"] = get_int(alg)

    length = find_child(key_block, Tag.CRYPTOGRAPHIC_LENGTH)
    if length is not None:
        result["cryptographic_length"] = get_int(length)

    key_value = find_child(key_block, Tag.KEY_VALUE)
    if key_value is not None:
        km = find_child(key_value, Tag.KEY_MATERIAL)
        if km is not None and isinstance(km.value, bytes):
            result["key_material"] = km.value

    return result


def _build_get_response_payload(uid: str, obj: dict[str, Any]) -> TlvItem:
    """Build a Get ResponsePayload from key-manager object dict.

    The *obj* dict from the key manager should contain at minimum:
      - "object_type" (str or int)
      - "key_material" (bytes) — for key objects
      - "cryptographic_algorithm" (str or int)
      - "cryptographic_length" (int)
      - "key_format_type" (str or int)
      - "certificate_value" (bytes) — for Certificate objects
    """
    from .enums import KeyFormatType, ObjectType as OT

    object_type_raw = obj.get("object_type")
    # Normalize object type to int
    try:
        if isinstance(object_type_raw, str):
            # e.g. "SymmetricKey" -> look up by name
            object_type_int = next(
                v for v in OT if v.name.replace("_", " ").lower() == object_type_raw.lower()
                   or v.name.lower() == object_type_raw.lower()
            )
        else:
            object_type_int = int(object_type_raw) if object_type_raw is not None else int(OT.SYMMETRIC_KEY)
    except (StopIteration, TypeError, ValueError):
        object_type_int = int(OT.SYMMETRIC_KEY)

    key_material = obj.get("key_material", b"")
    algo = obj.get("cryptographic_algorithm", 0)
    algo_int = algo if isinstance(algo, int) else 0
    length = obj.get("cryptographic_length", 0)
    kft = obj.get("key_format_type", int(KeyFormatType.RAW))
    kft_int = kft if isinstance(kft, int) else int(KeyFormatType.RAW)

    if object_type_int == OT.CERTIFICATE:
        cert_value = obj.get("certificate_value", b"")
        cert_type = obj.get("certificate_type", 1)  # default X.509
        obj_structure = make_structure(
            Tag.CERTIFICATE,
            [
                make_enum(Tag.CERTIFICATE_TYPE, int(cert_type)),
                make_bytes(Tag.CERTIFICATE_VALUE, cert_value),
            ],
        )
        return make_structure(
            Tag.RESPONSE_PAYLOAD,
            [
                make_enum(Tag.OBJECT_TYPE, object_type_int),
                make_text(Tag.UNIQUE_IDENTIFIER, uid),
                obj_structure,
            ],
        )

    # Key object: build KeyBlock
    key_material_item = make_structure(
        Tag.KEY_VALUE,
        [make_bytes(Tag.KEY_MATERIAL, key_material)],
    )
    key_block_children: list[TlvItem] = [
        make_enum(Tag.KEY_FORMAT_TYPE, kft_int),
        key_material_item,
    ]
    if algo_int:
        key_block_children.append(make_enum(Tag.CRYPTOGRAPHIC_ALGORITHM, algo_int))
    if length:
        key_block_children.append(make_int(Tag.CRYPTOGRAPHIC_LENGTH, length))

    # Determine the wrapper tag for the key object
    tag_map = {
        int(OT.SYMMETRIC_KEY): Tag.SYMMETRIC_KEY,
        int(OT.PRIVATE_KEY): Tag.PRIVATE_KEY,
        int(OT.PUBLIC_KEY): Tag.PUBLIC_KEY,
        int(OT.SECRET_DATA): Tag.SECRET_DATA,
    }
    outer_tag = tag_map.get(object_type_int, Tag.SYMMETRIC_KEY)

    obj_structure = make_structure(
        outer_tag,
        [make_structure(Tag.KEY_BLOCK, key_block_children)],
    )

    return make_structure(
        Tag.RESPONSE_PAYLOAD,
        [
            make_enum(Tag.OBJECT_TYPE, object_type_int),
            make_text(Tag.UNIQUE_IDENTIFIER, uid),
            obj_structure,
        ],
    )


def _build_get_attributes_payload(uid: str, attrs: dict[str, Any]) -> TlvItem:
    """Build a GetAttributes ResponsePayload.

    The *attrs* dict maps attribute name strings to Python values.
    Supported attribute names (case-insensitive):
      UniqueIdentifier, ObjectType, State, CryptographicAlgorithm,
      CryptographicLength, CryptographicUsageMask, InitialDate,
      ActivationDate, DeactivationDate, LastChangeDate, DestroyDate,
      Name, ObjectGroup.
    """
    from .enums import ObjectState, ObjectType as OT

    children: list[TlvItem] = [make_text(Tag.UNIQUE_IDENTIFIER, uid)]

    # Helper: add an attribute child
    def _add(tag: int, item: TlvItem) -> None:
        children.append(item)

    for raw_name, value in attrs.items():
        name = raw_name.lower().replace(" ", "_").replace("-", "_")

        if name == "unique_identifier":
            pass  # already added above
        elif name == "object_type":
            _add(Tag.OBJECT_TYPE, make_enum(Tag.OBJECT_TYPE, int(value)))
        elif name == "state":
            _add(Tag.STATE, make_enum(Tag.STATE, int(value)))
        elif name == "cryptographic_algorithm":
            _add(
                Tag.CRYPTOGRAPHIC_ALGORITHM,
                make_enum(Tag.CRYPTOGRAPHIC_ALGORITHM, int(value)),
            )
        elif name == "cryptographic_length":
            _add(Tag.CRYPTOGRAPHIC_LENGTH, make_int(Tag.CRYPTOGRAPHIC_LENGTH, int(value)))
        elif name == "cryptographic_usage_mask":
            _add(
                Tag.CRYPTOGRAPHIC_USAGE_MASK,
                make_int(Tag.CRYPTOGRAPHIC_USAGE_MASK, int(value)),
            )
        elif name == "initial_date" and isinstance(value, datetime):
            _add(Tag.INITIAL_DATE, make_datetime(Tag.INITIAL_DATE, value))
        elif name == "activation_date" and isinstance(value, datetime):
            _add(Tag.ACTIVATION_DATE, make_datetime(Tag.ACTIVATION_DATE, value))
        elif name == "deactivation_date" and isinstance(value, datetime):
            _add(Tag.DEACTIVATION_DATE, make_datetime(Tag.DEACTIVATION_DATE, value))
        elif name == "last_change_date" and isinstance(value, datetime):
            _add(Tag.LAST_CHANGE_DATE, make_datetime(Tag.LAST_CHANGE_DATE, value))
        elif name == "destroy_date" and isinstance(value, datetime):
            _add(Tag.DESTROY_DATE, make_datetime(Tag.DESTROY_DATE, value))
        elif name in ("name", "names"):
            # value is a list of (name_value, name_type) tuples or bare strings
            names_list: list[Any] = value if isinstance(value, list) else [value]
            for n in names_list:
                if isinstance(n, tuple):
                    nv, nt = n[0], n[1] if len(n) > 1 else 1
                else:
                    nv, nt = str(n), 1
                children.append(
                    make_structure(
                        Tag.NAME,
                        [
                            make_text(Tag.NAME_VALUE, nv),
                            make_enum(Tag.NAME_TYPE, int(nt)),
                        ],
                    )
                )
        elif name == "object_group" and value:
            _add(Tag.OBJECT_GROUP, make_text(Tag.OBJECT_GROUP, str(value)))

    return make_structure(Tag.RESPONSE_PAYLOAD, children)
