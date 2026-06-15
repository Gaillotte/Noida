"""
KMIP operation dispatcher — wires the KMIP protocol layer to the KMS core.
Implements KmipDispatcher, which is imported by kmip/server.py.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from kms.db.session import AsyncSessionLocal
from kms.core.manager import KeyManager, LocateFilter
from kms.audit.logger import record as audit_record

_log = logging.getLogger("kms.kmip.ops")

_manager = KeyManager()

# These imports are resolved once the sibling modules are present.
# They use string-based late imports to avoid circular deps at module load.


def _import_kmip():
    from kms.kmip.enums import (
        Tag, Operation, ResultStatus, ResultReason, ObjectType,
        CryptographicAlgorithm, ObjectState, KeyFormatType,
        NameType, LinkType, CryptographicUsageMask,
    )
    from kms.kmip.ttlv import (
        TlvItem, make_structure, make_int, make_enum, make_long,
        make_text, make_bytes, make_datetime, find_child,
        find_all_children, get_int, get_text, get_bytes,
    )
    from kms.kmip.messages import (
        build_response_item, build_error_item,
        build_response_message, parse_request_message,
    )
    return locals()


class KmipDispatcher:
    """
    Handles parsed KMIP requests and returns encoded KMIP response bytes.
    One instance is shared across all connections.
    """

    SUPPORTED_VERSIONS = [(2, 1), (2, 0), (1, 4), (1, 2)]
    VENDOR_ID = "KMS-OpenSource"
    SERVER_NAME = "KMS"

    async def dispatch(self, request_bytes: bytes, peer_cert: dict | None) -> bytes:
        k = _import_kmip()
        parse = k["parse_request_message"]
        build_resp = k["build_response_message"]
        build_err = k["build_error_item"]
        ResultStatus = k["ResultStatus"]
        ResultReason = k["ResultReason"]
        Operation = k["Operation"]

        try:
            parsed = parse(request_bytes)
        except Exception as exc:
            _log.warning("Failed to parse KMIP request: %s", exc)
            err = build_err(
                Operation.QUERY,
                ResultReason.INVALID_MESSAGE,
                f"Parse error: {exc}",
            )
            return build_resp([err])

        batch_items = parsed.get("batch_items", [])
        response_items = []

        async with AsyncSessionLocal() as session:
            for item in batch_items:
                try:
                    resp = await self._dispatch_item(item, peer_cert, session, k)
                    response_items.append(resp)
                except Exception as exc:
                    _log.exception("KMIP operation error")
                    op = self._extract_operation(item, k)
                    bid = self._extract_batch_id(item, k)
                    err = build_err(
                        op,
                        ResultReason.CRYPTOGRAPHIC_FAILURE,
                        str(exc),
                        bid,
                    )
                    response_items.append(err)
            await session.commit()

        return build_resp(response_items)

    def _extract_operation(self, item, k) -> Any:
        Tag = k["Tag"]
        find_child = k["find_child"]
        get_int = k["get_int"]
        Operation = k["Operation"]
        op_item = find_child(item, Tag.OPERATION)
        if op_item:
            try:
                return Operation(get_int(op_item))
            except Exception:
                pass
        return Operation.QUERY

    def _extract_batch_id(self, item, k) -> bytes | None:
        Tag = k["Tag"]
        find_child = k["find_child"]
        get_bytes = k["get_bytes"]
        bid_item = find_child(item, Tag.UNIQUE_BATCH_ITEM_ID)
        if bid_item:
            try:
                return get_bytes(bid_item)
            except Exception:
                pass
        return None

    async def _dispatch_item(
        self, item, peer_cert: dict | None, session: AsyncSession, k
    ):
        Tag = k["Tag"]
        Operation = k["Operation"]
        find_child = k["find_child"]
        get_int = k["get_int"]
        get_bytes = k["get_bytes"]
        build_error_item = k["build_error_item"]
        ResultReason = k["ResultReason"]

        op_item = find_child(item, Tag.OPERATION)
        payload_item = find_child(item, Tag.REQUEST_PAYLOAD)
        bid = self._extract_batch_id(item, k)

        if not op_item:
            return build_error_item(
                Operation.QUERY, ResultReason.INVALID_MESSAGE, "Missing Operation tag", bid
            )

        op = Operation(get_int(op_item))
        actor = self._actor_from_cert(peer_cert)

        handler_map = {
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

        handler = handler_map.get(op)
        if not handler:
            return build_error_item(
                op, ResultReason.OPERATION_NOT_SUPPORTED, f"Operation {op.name} not supported", bid
            )

        response_payload = await handler(payload_item, peer_cert, session, k, bid)
        return response_payload

    def _actor_from_cert(self, peer_cert: dict | None) -> str:
        if peer_cert:
            subject = peer_cert.get("subject", {})
            cn_tuples = [v for rdn in subject for k, v in [rdn] if k == "commonName"]
            if cn_tuples:
                return cn_tuples[0]
        return "anonymous-kmip"

    # -----------------------------------------------------------------------
    # Operation handlers
    # -----------------------------------------------------------------------

    async def handle_discover_versions(self, payload, peer_cert, session, k, bid):
        Tag = k["Tag"]
        make_structure = k["make_structure"]
        make_int = k["make_int"]
        build_response_item = k["build_response_item"]
        ResultStatus = k["ResultStatus"]
        Operation = k["Operation"]

        version_items = []
        for major, minor in self.SUPPORTED_VERSIONS:
            version_items.append(
                make_structure(Tag.PROTOCOL_VERSION, [
                    make_int(Tag.PROTOCOL_VERSION_MAJOR, major),
                    make_int(Tag.PROTOCOL_VERSION_MINOR, minor),
                ])
            )

        resp_payload = make_structure(Tag.RESPONSE_PAYLOAD, version_items)
        return build_response_item(
            Operation.DISCOVER_VERSIONS, ResultStatus.SUCCESS, resp_payload, batch_id=bid
        )

    async def handle_query(self, payload, peer_cert, session, k, bid):
        Tag = k["Tag"]
        make_structure = k["make_structure"]
        make_text = k["make_text"]
        make_enum = k["make_enum"]
        build_response_item = k["build_response_item"]
        ResultStatus = k["ResultStatus"]
        Operation = k["Operation"]

        operations = [
            Operation.DISCOVER_VERSIONS, Operation.QUERY,
            Operation.CREATE, Operation.CREATE_KEY_PAIR, Operation.REGISTER,
            Operation.LOCATE, Operation.GET, Operation.GET_ATTRIBUTES,
            Operation.GET_ATTRIBUTE_LIST, Operation.SET_ATTRIBUTE,
            Operation.ACTIVATE, Operation.REVOKE, Operation.DESTROY,
        ]
        ObjectType = k["ObjectType"]
        object_types = [
            ObjectType.SYMMETRIC_KEY, ObjectType.PRIVATE_KEY, ObjectType.PUBLIC_KEY,
            ObjectType.CERTIFICATE, ObjectType.SECRET_DATA,
        ]

        children = [make_text(Tag.VENDOR_IDENTIFICATION, self.VENDOR_ID)]
        for op in operations:
            children.append(make_enum(Tag.OPERATION, op))
        for ot in object_types:
            children.append(make_enum(Tag.OBJECT_TYPE, ot))

        resp_payload = make_structure(Tag.RESPONSE_PAYLOAD, children)
        return build_response_item(
            Operation.QUERY, ResultStatus.SUCCESS, resp_payload, batch_id=bid
        )

    async def handle_create(self, payload, peer_cert, session, k, bid):
        Tag = k["Tag"]
        find_child = k["find_child"]
        find_all_children = k["find_all_children"]
        get_int = k["get_int"]
        get_text = k["get_text"]
        make_structure = k["make_structure"]
        make_text = k["make_text"]
        build_response_item = k["build_response_item"]
        build_error_item = k["build_error_item"]
        ResultStatus = k["ResultStatus"]
        ResultReason = k["ResultReason"]
        Operation = k["Operation"]
        CryptographicAlgorithm = k["CryptographicAlgorithm"]

        if not payload:
            return build_error_item(Operation.CREATE, ResultReason.MISSING_DATA, "No payload", bid)

        algo_item = find_child(payload, Tag.CRYPTOGRAPHIC_ALGORITHM)
        length_item = find_child(payload, Tag.CRYPTOGRAPHIC_LENGTH)
        usage_item = find_child(payload, Tag.CRYPTOGRAPHIC_USAGE_MASK)

        if not algo_item or not length_item:
            return build_error_item(Operation.CREATE, ResultReason.MISSING_DATA, "Missing algorithm or length", bid)

        algo_val = get_int(algo_item)
        length_val = get_int(length_item)
        usage_val = get_int(usage_item) if usage_item else 0x0C

        try:
            algo_name = CryptographicAlgorithm(algo_val).name
        except ValueError:
            return build_error_item(Operation.CREATE, ResultReason.INVALID_FIELD, f"Unknown algorithm {algo_val}", bid)

        algo_str = {
            "AES": "AES", "THREE_DES": "3DES", "CHACHA20": "ChaCha20",
        }.get(algo_name, algo_name)

        names = self._extract_names(payload, k)
        group_item = find_child(payload, Tag.OBJECT_GROUP)
        obj_group = get_text(group_item) if group_item else None

        actor = self._actor_from_cert(peer_cert)
        obj = await _manager.create_symmetric_key(
            session,
            algorithm=algo_str,
            length=length_val,
            usage_mask=usage_val,
            names=names,
            object_group=obj_group,
            owner=actor,
        )

        await audit_record(
            session, actor=actor, operation="Create", protocol="KMIP",
            object_id=obj.id, result="Success",
            details={"algorithm": algo_str, "length": length_val},
        )

        resp_payload = make_structure(Tag.RESPONSE_PAYLOAD, [
            make_text(Tag.UNIQUE_IDENTIFIER, obj.id),
        ])
        return build_response_item(Operation.CREATE, ResultStatus.SUCCESS, resp_payload, batch_id=bid)

    async def handle_create_key_pair(self, payload, peer_cert, session, k, bid):
        Tag = k["Tag"]
        find_child = k["find_child"]
        get_int = k["get_int"]
        get_text = k["get_text"]
        make_structure = k["make_structure"]
        make_text = k["make_text"]
        build_response_item = k["build_response_item"]
        build_error_item = k["build_error_item"]
        ResultStatus = k["ResultStatus"]
        ResultReason = k["ResultReason"]
        Operation = k["Operation"]
        CryptographicAlgorithm = k["CryptographicAlgorithm"]
        RecommendedCurve = k.get("RecommendedCurve")

        if not payload:
            return build_error_item(Operation.CREATE_KEY_PAIR, ResultReason.MISSING_DATA, "No payload", bid)

        algo_item = find_child(payload, Tag.CRYPTOGRAPHIC_ALGORITHM)
        if not algo_item:
            return build_error_item(Operation.CREATE_KEY_PAIR, ResultReason.MISSING_DATA, "Missing algorithm", bid)

        algo_val = get_int(algo_item)
        try:
            algo_name = CryptographicAlgorithm(algo_val).name
        except ValueError:
            return build_error_item(Operation.CREATE_KEY_PAIR, ResultReason.INVALID_FIELD, f"Unknown algo {algo_val}", bid)

        length_item = find_child(payload, Tag.CRYPTOGRAPHIC_LENGTH)
        length_val = get_int(length_item) if length_item else 2048

        curve_item = find_child(payload, Tag.RECOMMENDED_CURVE)
        curve_str = None
        if curve_item and RecommendedCurve:
            try:
                curve_enum_val = RecommendedCurve(get_int(curve_item))
                _curve_name_map = {
                    "P_256": "P-256", "P_384": "P-384", "P_521": "P-521",
                    "CURVE25519": "X25519",
                }
                curve_str = _curve_name_map.get(curve_enum_val.name, "P-256")
            except ValueError:
                curve_str = "P-256"

        priv_usage_item = find_child(payload, Tag.CRYPTOGRAPHIC_USAGE_MASK)
        pub_usage_item = find_child(payload, Tag.CRYPTOGRAPHIC_USAGE_MASK)
        priv_usage = get_int(priv_usage_item) if priv_usage_item else 0x01
        pub_usage = get_int(pub_usage_item) if pub_usage_item else 0x02

        group_item = find_child(payload, Tag.OBJECT_GROUP)
        obj_group = get_text(group_item) if group_item else None

        algo_str_map = {"RSA": "RSA", "EC": "EC", "ECDSA": "EC", "ED25519": "Ed25519", "ED448": "Ed448"}
        algo_str = algo_str_map.get(algo_name, "RSA")

        actor = self._actor_from_cert(peer_cert)
        priv_obj, pub_obj = await _manager.create_key_pair(
            session,
            algorithm=algo_str,
            length=length_val,
            curve=curve_str or "P-256",
            private_usage_mask=priv_usage,
            public_usage_mask=pub_usage,
            object_group=obj_group,
            owner=actor,
        )

        await audit_record(
            session, actor=actor, operation="CreateKeyPair", protocol="KMIP",
            object_id=priv_obj.id, result="Success",
            details={"algorithm": algo_str, "pub_id": pub_obj.id},
        )

        resp_payload = make_structure(Tag.RESPONSE_PAYLOAD, [
            make_text(Tag.PRIVATE_KEY_UNIQUE_IDENTIFIER, priv_obj.id),
            make_text(Tag.PUBLIC_KEY_UNIQUE_IDENTIFIER, pub_obj.id),
        ])
        return build_response_item(
            Operation.CREATE_KEY_PAIR, ResultStatus.SUCCESS, resp_payload, batch_id=bid
        )

    async def handle_register(self, payload, peer_cert, session, k, bid):
        Tag = k["Tag"]
        find_child = k["find_child"]
        get_int = k["get_int"]
        get_text = k["get_text"]
        get_bytes = k["get_bytes"]
        make_structure = k["make_structure"]
        make_text = k["make_text"]
        build_response_item = k["build_response_item"]
        build_error_item = k["build_error_item"]
        ResultStatus = k["ResultStatus"]
        ResultReason = k["ResultReason"]
        Operation = k["Operation"]
        ObjectType = k["ObjectType"]

        if not payload:
            return build_error_item(Operation.REGISTER, ResultReason.MISSING_DATA, "No payload", bid)

        otype_item = find_child(payload, Tag.OBJECT_TYPE)
        if not otype_item:
            return build_error_item(Operation.REGISTER, ResultReason.MISSING_DATA, "Missing ObjectType", bid)

        otype_val = get_int(otype_item)
        _otype_map = {
            ObjectType.SYMMETRIC_KEY: "SymmetricKey",
            ObjectType.PRIVATE_KEY: "PrivateKey",
            ObjectType.PUBLIC_KEY: "PublicKey",
            ObjectType.CERTIFICATE: "Certificate",
            ObjectType.SECRET_DATA: "SecretData",
            ObjectType.OPAQUE_DATA: "OpaqueObject",
        }
        object_type_str = _otype_map.get(ObjectType(otype_val), "OpaqueObject")

        key_block = find_child(payload, Tag.KEY_BLOCK)
        key_material_bytes = None
        cert_value_bytes = None
        algo_str = None
        length_val = None
        usage_val = 0

        if key_block:
            key_value = find_child(key_block, Tag.KEY_VALUE)
            if key_value:
                km_item = find_child(key_value, Tag.KEY_MATERIAL)
                if km_item:
                    key_material_bytes = get_bytes(km_item)

            algo_item = find_child(key_block, Tag.CRYPTOGRAPHIC_ALGORITHM)
            if algo_item:
                from kms.kmip.enums import CryptographicAlgorithm
                try:
                    algo_str = CryptographicAlgorithm(get_int(algo_item)).name
                except ValueError:
                    pass

            length_item = find_child(key_block, Tag.CRYPTOGRAPHIC_LENGTH)
            if length_item:
                length_val = get_int(length_item)

        cert_item = find_child(payload, Tag.CERTIFICATE)
        if cert_item:
            cv = find_child(cert_item, Tag.CERTIFICATE_VALUE)
            if cv:
                cert_value_bytes = get_bytes(cv)

        usage_item = find_child(payload, Tag.CRYPTOGRAPHIC_USAGE_MASK)
        if usage_item:
            usage_val = get_int(usage_item)

        names = self._extract_names(payload, k)
        actor = self._actor_from_cert(peer_cert)

        obj = await _manager.register_object(
            session,
            object_type=object_type_str,
            algorithm=algo_str,
            length=length_val,
            usage_mask=usage_val,
            key_material=key_material_bytes,
            certificate_value=cert_value_bytes,
            names=names,
            owner=actor,
        )

        await audit_record(
            session, actor=actor, operation="Register", protocol="KMIP",
            object_id=obj.id, result="Success",
            details={"type": object_type_str},
        )

        resp_payload = make_structure(Tag.RESPONSE_PAYLOAD, [
            make_text(Tag.UNIQUE_IDENTIFIER, obj.id),
        ])
        return build_response_item(Operation.REGISTER, ResultStatus.SUCCESS, resp_payload, batch_id=bid)

    async def handle_locate(self, payload, peer_cert, session, k, bid):
        Tag = k["Tag"]
        find_child = k["find_child"]
        get_int = k["get_int"]
        get_text = k["get_text"]
        make_structure = k["make_structure"]
        make_text = k["make_text"]
        build_response_item = k["build_response_item"]
        ResultStatus = k["ResultStatus"]
        Operation = k["Operation"]
        ObjectType = k["ObjectType"]
        ObjectState = k["ObjectState"]
        CryptographicAlgorithm = k["CryptographicAlgorithm"]

        f = LocateFilter()

        if payload:
            otype_item = find_child(payload, Tag.OBJECT_TYPE)
            if otype_item:
                try:
                    f.object_type = {
                        ObjectType.SYMMETRIC_KEY: "SymmetricKey",
                        ObjectType.PRIVATE_KEY: "PrivateKey",
                        ObjectType.PUBLIC_KEY: "PublicKey",
                        ObjectType.CERTIFICATE: "Certificate",
                        ObjectType.SECRET_DATA: "SecretData",
                    }.get(ObjectType(get_int(otype_item)))
                except ValueError:
                    pass

            state_item = find_child(payload, Tag.STATE)
            if state_item:
                try:
                    f.state = {
                        ObjectState.PRE_ACTIVE: "Pre-Active",
                        ObjectState.ACTIVE: "Active",
                        ObjectState.DEACTIVATED: "Deactivated",
                        ObjectState.COMPROMISED: "Compromised",
                        ObjectState.DESTROYED: "Destroyed",
                        ObjectState.DESTROYED_COMPROMISED: "Destroyed Compromised",
                    }.get(ObjectState(get_int(state_item)))
                except ValueError:
                    pass

            algo_item = find_child(payload, Tag.CRYPTOGRAPHIC_ALGORITHM)
            if algo_item:
                try:
                    name = CryptographicAlgorithm(get_int(algo_item)).name
                    f.algorithm = {"AES": "AES", "RSA": "RSA", "EC": "EC"}.get(name, name)
                except ValueError:
                    pass

            group_item = find_child(payload, Tag.OBJECT_GROUP)
            if group_item:
                f.object_group = get_text(group_item)

            max_item = find_child(payload, Tag.MAXIMUM_ITEMS)
            if max_item:
                f.max_items = get_int(max_item)

            offset_item = find_child(payload, Tag.OFFSET_ITEMS)
            if offset_item:
                f.offset_items = get_int(offset_item)

        uids = await _manager.locate_objects(session, f)

        uid_items = [make_text(Tag.UNIQUE_IDENTIFIER, uid) for uid in uids]
        resp_payload = make_structure(Tag.RESPONSE_PAYLOAD, uid_items)
        return build_response_item(Operation.LOCATE, ResultStatus.SUCCESS, resp_payload, batch_id=bid)

    async def handle_get(self, payload, peer_cert, session, k, bid):
        Tag = k["Tag"]
        find_child = k["find_child"]
        get_text = k["get_text"]
        make_structure = k["make_structure"]
        make_text = k["make_text"]
        make_enum = k["make_enum"]
        make_bytes = k["make_bytes"]
        build_response_item = k["build_response_item"]
        build_error_item = k["build_error_item"]
        ResultStatus = k["ResultStatus"]
        ResultReason = k["ResultReason"]
        Operation = k["Operation"]
        ObjectType = k["ObjectType"]

        if not payload:
            return build_error_item(Operation.GET, ResultReason.MISSING_DATA, "No payload", bid)

        uid_item = find_child(payload, Tag.UNIQUE_IDENTIFIER)
        if not uid_item:
            return build_error_item(Operation.GET, ResultReason.MISSING_DATA, "Missing UniqueIdentifier", bid)

        uid = get_text(uid_item)
        actor = self._actor_from_cert(peer_cert)

        obj = await _manager.get_object(session, uid, include_value=True)
        if not obj:
            return build_error_item(Operation.GET, ResultReason.ITEM_NOT_FOUND, f"Object {uid} not found", bid)

        if obj.state in ("Destroyed", "Destroyed Compromised"):
            return build_error_item(Operation.GET, ResultReason.ITEM_NOT_FOUND, "Object is destroyed", bid)

        _otype_enum_map = {
            "SymmetricKey": ObjectType.SYMMETRIC_KEY,
            "PrivateKey": ObjectType.PRIVATE_KEY,
            "PublicKey": ObjectType.PUBLIC_KEY,
            "Certificate": ObjectType.CERTIFICATE,
            "SecretData": ObjectType.SECRET_DATA,
        }
        otype = _otype_enum_map.get(obj.object_type, ObjectType.SYMMETRIC_KEY)

        # Build Key Block
        key_material = getattr(obj, "_decrypted_value", None) or b""
        key_block_children = [
            make_enum(Tag.KEY_FORMAT_TYPE, 0x00000001),  # Raw
            make_structure(Tag.KEY_VALUE, [
                make_bytes(Tag.KEY_MATERIAL, key_material),
            ]),
        ]
        if obj.cryptographic_algorithm:
            from kms.kmip.enums import CryptographicAlgorithm
            _algo_rev = {"AES": CryptographicAlgorithm.AES, "RSA": CryptographicAlgorithm.RSA,
                         "EC": CryptographicAlgorithm.EC, "Ed25519": CryptographicAlgorithm.ED25519}
            algo_enum = _algo_rev.get(obj.cryptographic_algorithm, CryptographicAlgorithm.AES)
            key_block_children.append(make_enum(Tag.CRYPTOGRAPHIC_ALGORITHM, algo_enum))
        if obj.cryptographic_length:
            key_block_children.append(make_enum(Tag.CRYPTOGRAPHIC_LENGTH, obj.cryptographic_length))

        key_block = make_structure(Tag.KEY_BLOCK, key_block_children)

        # Wrap in typed object
        sym_key = make_structure(Tag.SYMMETRIC_KEY, [key_block])

        resp_payload = make_structure(Tag.RESPONSE_PAYLOAD, [
            make_enum(Tag.OBJECT_TYPE, otype),
            make_text(Tag.UNIQUE_IDENTIFIER, uid),
            sym_key,
        ])

        await audit_record(
            session, actor=actor, operation="Get", protocol="KMIP",
            object_id=uid, result="Success",
        )
        return build_response_item(Operation.GET, ResultStatus.SUCCESS, resp_payload, batch_id=bid)

    async def handle_get_attributes(self, payload, peer_cert, session, k, bid):
        Tag = k["Tag"]
        find_child = k["find_child"]
        find_all_children = k["find_all_children"]
        get_text = k["get_text"]
        make_structure = k["make_structure"]
        make_text = k["make_text"]
        make_enum = k["make_enum"]
        make_int = k["make_int"]
        make_long = k["make_long"]
        make_datetime = k["make_datetime"]
        build_response_item = k["build_response_item"]
        build_error_item = k["build_error_item"]
        ResultStatus = k["ResultStatus"]
        ResultReason = k["ResultReason"]
        Operation = k["Operation"]

        if not payload:
            return build_error_item(Operation.GET_ATTRIBUTES, ResultReason.MISSING_DATA, "No payload", bid)

        uid_item = find_child(payload, Tag.UNIQUE_IDENTIFIER)
        if not uid_item:
            return build_error_item(Operation.GET_ATTRIBUTES, ResultReason.MISSING_DATA, "Missing UID", bid)

        uid = get_text(uid_item)
        attr_name_items = find_all_children(payload, Tag.ATTRIBUTE_NAME)
        attr_names = [get_text(i) for i in attr_name_items] if attr_name_items else None

        attrs = await _manager.get_attributes(session, uid, attr_names)
        if attrs is None:
            return build_error_item(Operation.GET_ATTRIBUTES, ResultReason.ITEM_NOT_FOUND, f"Object {uid} not found", bid)

        attr_items = []
        for name, value in attrs.items():
            if value is None:
                continue
            if isinstance(value, str):
                val_item = make_text(Tag.ATTRIBUTE_VALUE, value)
            elif isinstance(value, int):
                val_item = make_int(Tag.ATTRIBUTE_VALUE, value)
            elif isinstance(value, datetime):
                val_item = make_datetime(Tag.ATTRIBUTE_VALUE, value)
            else:
                val_item = make_text(Tag.ATTRIBUTE_VALUE, str(value))

            attr_items.append(make_structure(Tag.ATTRIBUTE, [
                make_text(Tag.ATTRIBUTE_NAME, name),
                val_item,
            ]))

        resp_payload = make_structure(Tag.RESPONSE_PAYLOAD, [
            make_text(Tag.UNIQUE_IDENTIFIER, uid),
            *attr_items,
        ])
        return build_response_item(Operation.GET_ATTRIBUTES, ResultStatus.SUCCESS, resp_payload, batch_id=bid)

    async def handle_get_attribute_list(self, payload, peer_cert, session, k, bid):
        Tag = k["Tag"]
        find_child = k["find_child"]
        get_text = k["get_text"]
        make_structure = k["make_structure"]
        make_text = k["make_text"]
        build_response_item = k["build_response_item"]
        build_error_item = k["build_error_item"]
        ResultStatus = k["ResultStatus"]
        ResultReason = k["ResultReason"]
        Operation = k["Operation"]

        if not payload:
            return build_error_item(Operation.GET_ATTRIBUTE_LIST, ResultReason.MISSING_DATA, "No payload", bid)

        uid_item = find_child(payload, Tag.UNIQUE_IDENTIFIER)
        if not uid_item:
            return build_error_item(Operation.GET_ATTRIBUTE_LIST, ResultReason.MISSING_DATA, "Missing UID", bid)

        uid = get_text(uid_item)
        attrs = await _manager.get_attributes(session, uid)
        if attrs is None:
            return build_error_item(Operation.GET_ATTRIBUTE_LIST, ResultReason.ITEM_NOT_FOUND, f"Object {uid} not found", bid)

        name_items = [make_text(Tag.ATTRIBUTE_NAME, n) for n in attrs.keys()]
        resp_payload = make_structure(Tag.RESPONSE_PAYLOAD, [
            make_text(Tag.UNIQUE_IDENTIFIER, uid),
            *name_items,
        ])
        return build_response_item(Operation.GET_ATTRIBUTE_LIST, ResultStatus.SUCCESS, resp_payload, batch_id=bid)

    async def handle_set_attribute(self, payload, peer_cert, session, k, bid):
        Tag = k["Tag"]
        find_child = k["find_child"]
        get_text = k["get_text"]
        get_int = k["get_int"]
        make_structure = k["make_structure"]
        make_text = k["make_text"]
        build_response_item = k["build_response_item"]
        build_error_item = k["build_error_item"]
        ResultStatus = k["ResultStatus"]
        ResultReason = k["ResultReason"]
        Operation = k["Operation"]

        if not payload:
            return build_error_item(Operation.SET_ATTRIBUTE, ResultReason.MISSING_DATA, "No payload", bid)

        uid_item = find_child(payload, Tag.UNIQUE_IDENTIFIER)
        attr_item = find_child(payload, Tag.ATTRIBUTE)

        if not uid_item or not attr_item:
            return build_error_item(Operation.SET_ATTRIBUTE, ResultReason.MISSING_DATA, "Missing UID or Attribute", bid)

        uid = get_text(uid_item)
        name_item = find_child(attr_item, Tag.ATTRIBUTE_NAME)
        val_item = find_child(attr_item, Tag.ATTRIBUTE_VALUE)

        if not name_item or not val_item:
            return build_error_item(Operation.SET_ATTRIBUTE, ResultReason.INVALID_FIELD, "Malformed Attribute", bid)

        attr_name = get_text(name_item)
        from kms.kmip.ttlv import ItemType
        if val_item.type == ItemType.TEXT_STRING:
            attr_val = get_text(val_item)
        elif val_item.type in (ItemType.INTEGER, ItemType.ENUMERATION):
            attr_val = get_int(val_item)
        else:
            attr_val = get_text(val_item)

        actor = self._actor_from_cert(peer_cert)
        await _manager.set_attribute(session, uid, attr_name, attr_val)
        await audit_record(
            session, actor=actor, operation="SetAttribute", protocol="KMIP",
            object_id=uid, result="Success", details={"attr": attr_name},
        )

        resp_payload = make_structure(Tag.RESPONSE_PAYLOAD, [
            make_text(Tag.UNIQUE_IDENTIFIER, uid),
        ])
        return build_response_item(Operation.SET_ATTRIBUTE, ResultStatus.SUCCESS, resp_payload, batch_id=bid)

    async def handle_activate(self, payload, peer_cert, session, k, bid):
        Tag = k["Tag"]
        find_child = k["find_child"]
        get_text = k["get_text"]
        make_structure = k["make_structure"]
        make_text = k["make_text"]
        build_response_item = k["build_response_item"]
        build_error_item = k["build_error_item"]
        ResultStatus = k["ResultStatus"]
        ResultReason = k["ResultReason"]
        Operation = k["Operation"]

        if not payload:
            return build_error_item(Operation.ACTIVATE, ResultReason.MISSING_DATA, "No payload", bid)

        uid_item = find_child(payload, Tag.UNIQUE_IDENTIFIER)
        if not uid_item:
            return build_error_item(Operation.ACTIVATE, ResultReason.MISSING_DATA, "Missing UID", bid)

        uid = get_text(uid_item)
        actor = self._actor_from_cert(peer_cert)

        try:
            await _manager.activate(session, uid)
        except ValueError as e:
            return build_error_item(Operation.ACTIVATE, ResultReason.INVALID_OBJECT_TYPE, str(e), bid)

        await audit_record(session, actor=actor, operation="Activate", protocol="KMIP", object_id=uid, result="Success")

        resp_payload = make_structure(Tag.RESPONSE_PAYLOAD, [
            make_text(Tag.UNIQUE_IDENTIFIER, uid),
        ])
        return build_response_item(Operation.ACTIVATE, ResultStatus.SUCCESS, resp_payload, batch_id=bid)

    async def handle_revoke(self, payload, peer_cert, session, k, bid):
        Tag = k["Tag"]
        find_child = k["find_child"]
        get_text = k["get_text"]
        get_int = k["get_int"]
        make_structure = k["make_structure"]
        make_text = k["make_text"]
        build_response_item = k["build_response_item"]
        build_error_item = k["build_error_item"]
        ResultStatus = k["ResultStatus"]
        ResultReason = k["ResultReason"]
        Operation = k["Operation"]
        RevocationReasonCode = k.get("RevocationReasonCode")

        if not payload:
            return build_error_item(Operation.REVOKE, ResultReason.MISSING_DATA, "No payload", bid)

        uid_item = find_child(payload, Tag.UNIQUE_IDENTIFIER)
        if not uid_item:
            return build_error_item(Operation.REVOKE, ResultReason.MISSING_DATA, "Missing UID", bid)

        uid = get_text(uid_item)
        reason_str = "Unspecified"
        msg_str = ""

        rev_item = find_child(payload, Tag.REVOCATION_REASON)
        if rev_item:
            code_item = find_child(rev_item, Tag.REVOCATION_REASON_CODE)
            msg_item = find_child(rev_item, Tag.REVOCATION_MESSAGE)
            if code_item and RevocationReasonCode:
                try:
                    reason_str = RevocationReasonCode(get_int(code_item)).name
                except ValueError:
                    pass
            if msg_item:
                msg_str = get_text(msg_item)

        actor = self._actor_from_cert(peer_cert)

        try:
            await _manager.revoke(session, uid, reason=reason_str, message=msg_str)
        except ValueError as e:
            return build_error_item(Operation.REVOKE, ResultReason.INVALID_OBJECT_TYPE, str(e), bid)

        await audit_record(
            session, actor=actor, operation="Revoke", protocol="KMIP",
            object_id=uid, result="Success", details={"reason": reason_str},
        )

        resp_payload = make_structure(Tag.RESPONSE_PAYLOAD, [
            make_text(Tag.UNIQUE_IDENTIFIER, uid),
        ])
        return build_response_item(Operation.REVOKE, ResultStatus.SUCCESS, resp_payload, batch_id=bid)

    async def handle_destroy(self, payload, peer_cert, session, k, bid):
        Tag = k["Tag"]
        find_child = k["find_child"]
        get_text = k["get_text"]
        make_structure = k["make_structure"]
        make_text = k["make_text"]
        build_response_item = k["build_response_item"]
        build_error_item = k["build_error_item"]
        ResultStatus = k["ResultStatus"]
        ResultReason = k["ResultReason"]
        Operation = k["Operation"]

        if not payload:
            return build_error_item(Operation.DESTROY, ResultReason.MISSING_DATA, "No payload", bid)

        uid_item = find_child(payload, Tag.UNIQUE_IDENTIFIER)
        if not uid_item:
            return build_error_item(Operation.DESTROY, ResultReason.MISSING_DATA, "Missing UID", bid)

        uid = get_text(uid_item)
        actor = self._actor_from_cert(peer_cert)

        try:
            await _manager.destroy(session, uid)
        except ValueError as e:
            return build_error_item(Operation.DESTROY, ResultReason.INVALID_OBJECT_TYPE, str(e), bid)

        await audit_record(
            session, actor=actor, operation="Destroy", protocol="KMIP",
            object_id=uid, result="Success",
        )

        resp_payload = make_structure(Tag.RESPONSE_PAYLOAD, [
            make_text(Tag.UNIQUE_IDENTIFIER, uid),
        ])
        return build_response_item(Operation.DESTROY, ResultStatus.SUCCESS, resp_payload, batch_id=bid)

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _extract_names(self, payload, k) -> list[dict]:
        Tag = k["Tag"]
        find_all_children = k["find_all_children"]
        find_child = k["find_child"]
        get_text = k["get_text"]
        get_int = k["get_int"]
        NameType = k.get("NameType")

        name_structs = find_all_children(payload, Tag.NAME) if payload else []
        names = []
        for ns in name_structs:
            val_item = find_child(ns, Tag.NAME_VALUE)
            type_item = find_child(ns, Tag.NAME_TYPE)
            if val_item:
                ntype = "Uninterpreted"
                if type_item and NameType:
                    try:
                        ntype = NameType(get_int(type_item)).name.title()
                    except ValueError:
                        pass
                names.append({"value": get_text(val_item), "type": ntype})
        return names
