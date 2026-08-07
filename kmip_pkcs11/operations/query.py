"""Handle KMIP Query operation — report server capabilities."""

import logging
from ..core.enums import (
    Tag, Operation, ObjectType, QueryFunction
)
from ..core.ttlv import encode_enumeration, encode_text_string

log = logging.getLogger(__name__)

SUPPORTED_OPERATIONS = [
    Operation.Create, Operation.CreateKeyPair, Operation.Register,
    Operation.Get, Operation.GetAttributes, Operation.GetAttributeList,
    Operation.AddAttribute, Operation.DeleteAttribute,
    Operation.ModifyAttribute, Operation.SetAttribute, Operation.AdjustAttribute,
    Operation.Locate, Operation.Destroy,
    Operation.Activate, Operation.Revoke, Operation.Encrypt, Operation.Decrypt,
    Operation.Sign, Operation.SignatureVerify,
    Operation.RNGRetrieve,
    Operation.MAC, Operation.MACVerify, Operation.Hash,
    Operation.Import, Operation.Export,
    Operation.DeriveKey,
    Operation.Certify, Operation.Validate,
    Operation.Archive, Operation.Recover,
    Operation.ObtainLease, Operation.GetUsageAllocation, Operation.Check,
    Operation.Query, Operation.DiscoverVersions,
]

SUPPORTED_OBJECT_TYPES = [
    ObjectType.SymmetricKey, ObjectType.PublicKey, ObjectType.PrivateKey,
    ObjectType.SecretData, ObjectType.OpaqueObject, ObjectType.Certificate,
]


def handle(payload, identity: str, store, shim) -> bytes:
    response = b""

    query_functions = []
    if payload is not None:
        for qf_item in payload.get_all(Tag.QueryFunction):
            query_functions.append(qf_item.value)

    if not query_functions:
        query_functions = [
            QueryFunction.QueryOperations,
            QueryFunction.QueryObjects,
            QueryFunction.QueryServerInformation,
        ]

    for qf in query_functions:
        if qf == QueryFunction.QueryOperations:
            for op in SUPPORTED_OPERATIONS:
                response += encode_enumeration(Tag.Operations, op)

        elif qf == QueryFunction.QueryObjects:
            for ot in SUPPORTED_OBJECT_TYPES:
                response += encode_enumeration(Tag.ObjectTypes, ot)

        elif qf == QueryFunction.QueryServerInformation:
            response += encode_text_string(Tag.VendorIdentification, "kmip_pkcs11 v1.0")

    return response
