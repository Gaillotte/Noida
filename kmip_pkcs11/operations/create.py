"""Handle KMIP Create operation — generate a symmetric key on the HSM."""

import logging
from ..core.enums import Tag, ObjectType, CryptographicAlgorithm, State, CryptographicUsageMask
from ..core.ttlv import encode_text_string, encode_structure
from ..core.exceptions import MissingData, InvalidField

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("Create requires a request payload")

    # Object type
    otype_item = payload.get(Tag.ObjectType)
    if otype_item is None or otype_item.value != ObjectType.SymmetricKey:
        raise InvalidField("Create only supports SymmetricKey object type")

    # Template attributes
    tmpl = payload.get(Tag.TemplateAttribute) or payload.get(Tag.Attributes)
    attrs = _parse_attributes(tmpl)

    algorithm  = attrs.get("algorithm")
    length     = attrs.get("length")
    usage_mask = attrs.get("usage_mask", CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt)
    names      = attrs.get("names", [])
    sensitive  = attrs.get("sensitive", True)
    extractable = attrs.get("extractable", False)

    if algorithm is None:
        raise MissingData("CryptographicAlgorithm is required")
    if length is None:
        raise MissingData("CryptographicLength is required")

    encrypt = bool(usage_mask & CryptographicUsageMask.Encrypt)
    decrypt = bool(usage_mask & CryptographicUsageMask.Decrypt)
    wrap    = bool(usage_mask & CryptographicUsageMask.WrapKey)
    unwrap  = bool(usage_mask & CryptographicUsageMask.UnwrapKey)

    label   = names[0] if names else f"kmip-sym-{algorithm}-{length}"
    _, cka_id = shim.generate_symmetric_key(
        algorithm=algorithm,
        length_bits=length,
        label=label,
        extractable=extractable,
        sensitive=sensitive,
        encrypt=encrypt,
        decrypt=decrypt,
        wrap=wrap,
        unwrap=unwrap,
    )

    uid = store.create_object(
        object_type=ObjectType.SymmetricKey,
        pkcs11_handle=None,   # cka_id stored as attribute below
        state=State.Active,
        cryptographic_algorithm=algorithm,
        cryptographic_length=length,
        usage_mask=usage_mask,
        sensitive=sensitive,
        extractable=extractable,
        owner_identity=identity,
        names=names,
    )
    # Persist cka_id as attribute for later lookup
    store.add_attribute(uid, "_pkcs11_cka_id", cka_id.hex())

    log.info("Created SymmetricKey uid=%s alg=%d len=%d", uid, algorithm, length)
    return encode_text_string(Tag.UniqueIdentifier, uid)


def _parse_attributes(tmpl_item) -> dict:
    result = {}
    if tmpl_item is None:
        return result

    for attr in tmpl_item.get_all(Tag.Attribute):
        name_item  = attr.get(Tag.AttributeName)
        value_item = attr.get(Tag.AttributeValue)
        if name_item is None or value_item is None:
            continue
        name = name_item.value

        if name == "Cryptographic Algorithm":
            result["algorithm"] = value_item.value
        elif name == "Cryptographic Length":
            result["length"] = value_item.value
        elif name == "Cryptographic Usage Mask":
            result["usage_mask"] = value_item.value
        elif name == "Sensitive":
            result["sensitive"] = bool(value_item.value)
        elif name == "Extractable":
            result["extractable"] = bool(value_item.value)
        elif name == "Name":
            if "names" not in result:
                result["names"] = []
            # Value may be a structure {NameValue, NameType} or a plain string
            if hasattr(value_item, 'children') and value_item.children:
                nv = value_item.get(Tag.NameValue)
                result["names"].append(nv.value if nv else str(value_item.value))
            else:
                result["names"].append(str(value_item.value))

    return result
