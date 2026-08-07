"""Handle KMIP CreateKeyPair operation."""

import logging
from ..core.enums import Tag, ObjectType, State, CryptographicUsageMask, RecommendedCurve, CryptographicAlgorithm
from ..core.ttlv import encode_text_string, encode_structure
from ..core.exceptions import MissingData, InvalidField
from .create import _parse_attributes

log = logging.getLogger(__name__)

_KEY_AGREEMENT_ALGORITHMS = {CryptographicAlgorithm.DH, CryptographicAlgorithm.ECDH}

# KMIP RecommendedCurve → OpenSSL curve name (python-pkcs11 util.ec.encode_named_curve_parameters)
CURVE_TO_NAME = {
    RecommendedCurve.P_192:     'secp192r1',
    RecommendedCurve.P_224:     'secp224r1',
    RecommendedCurve.P_256:     'secp256r1',
    RecommendedCurve.P_384:     'secp384r1',
    RecommendedCurve.P_521:     'secp521r1',
    RecommendedCurve.SECP256K1: 'secp256k1',
}


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("CreateKeyPair requires a request payload")

    # Parse common and per-key attributes
    common_tmpl  = payload.get(Tag.TemplateAttribute)
    pub_tmpl     = payload.get(Tag.PublicKeyAttributes)
    priv_tmpl    = payload.get(Tag.PrivateKeyAttributes)

    common_attrs = _parse_attributes(common_tmpl)
    pub_attrs    = _parse_attributes(pub_tmpl)
    priv_attrs   = _parse_attributes(priv_tmpl)

    # Merge: common → specific
    algorithm  = pub_attrs.get("algorithm") or common_attrs.get("algorithm")
    length     = pub_attrs.get("length")    or common_attrs.get("length", 2048)
    default_mask = (CryptographicUsageMask.KeyAgreement if algorithm in _KEY_AGREEMENT_ALGORITHMS
                     else CryptographicUsageMask.Verify)
    pub_mask   = pub_attrs.get("usage_mask",  default_mask)
    priv_mask  = priv_attrs.get(
        "usage_mask",
        CryptographicUsageMask.KeyAgreement if algorithm in _KEY_AGREEMENT_ALGORITHMS
        else CryptographicUsageMask.Sign,
    )
    names      = pub_attrs.get("names") or common_attrs.get("names", [])
    curve_enum = (pub_attrs.get("recommended_curve")
                  or common_attrs.get("recommended_curve")
                  or RecommendedCurve.P_256)

    if algorithm is None:
        raise MissingData("CryptographicAlgorithm is required")

    pub_uid, priv_uid = create_key_pair_objects(
        algorithm, length, curve_enum, pub_mask, priv_mask, names, identity, store, shim
    )

    payload_bytes = (
        encode_text_string(Tag.UniqueIdentifier, pub_uid)
        + encode_text_string(Tag.UniqueIdentifier, priv_uid)
    )
    return payload_bytes


def create_key_pair_objects(algorithm, length, curve_enum, pub_mask, priv_mask, names,
                             identity, store, shim):
    """Shared by CreateKeyPair and ReKeyKeyPair — generates the PKCS#11 key
    pair and the two managed objects, cross-linked to each other."""
    curve_name = CURVE_TO_NAME.get(curve_enum)
    if curve_name is None:
        raise InvalidField(f"Unsupported RecommendedCurve {curve_enum!r}")

    label = names[0] if names else f"kmip-kp-{algorithm}"

    pub_cka_id, priv_cka_id = shim.generate_key_pair(
        algorithm=algorithm,
        key_length=length,
        curve=curve_name,
        label=label,
        sign=bool(priv_mask & CryptographicUsageMask.Sign),
        verify=bool(pub_mask & CryptographicUsageMask.Verify),
        derive=bool(priv_mask & CryptographicUsageMask.KeyAgreement) or algorithm in _KEY_AGREEMENT_ALGORITHMS,
    )

    pub_uid = store.create_object(
        object_type=ObjectType.PublicKey,
        pkcs11_handle=None,
        state=State.Active,
        cryptographic_algorithm=algorithm,
        cryptographic_length=length,
        usage_mask=pub_mask,
        sensitive=False,
        extractable=True,
        owner_identity=identity,
        names=[n + "_pub" for n in names] or [label + "_pub"],
    )
    store.add_attribute(pub_uid, "_pkcs11_cka_id", pub_cka_id.hex())

    priv_uid = store.create_object(
        object_type=ObjectType.PrivateKey,
        pkcs11_handle=None,
        state=State.Active,
        cryptographic_algorithm=algorithm,
        cryptographic_length=length,
        usage_mask=priv_mask,
        sensitive=True,
        extractable=False,
        owner_identity=identity,
        names=[n + "_priv" for n in names] or [label + "_priv"],
    )
    store.add_attribute(priv_uid, "_pkcs11_cka_id", priv_cka_id.hex())

    # Cross-link the two objects
    store.add_attribute(pub_uid,  "Link_PrivateKey", priv_uid)
    store.add_attribute(priv_uid, "Link_PublicKey",  pub_uid)

    log.info("Created KeyPair pub=%s priv=%s alg=%d", pub_uid, priv_uid, algorithm)
    return pub_uid, priv_uid
