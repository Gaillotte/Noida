"""Handle KMIP ReKeyKeyPair operation — create a new key pair inheriting the
attributes of an existing one, cross-linked to it for lineage tracking.

The specific EC curve used by the original pair isn't separately persisted
(only algorithm + bit length are), so unless the request explicitly supplies
Cryptographic Domain Parameters, the new pair defaults to P-256 for EC/ECDH
algorithms regardless of what curve the original used. This mirrors the
approximations already made elsewhere in this server (e.g. ObtainLease's
LastChangeDate).
"""

import logging
from ..core.enums import Tag, ObjectType, RecommendedCurve
from ..core.ttlv import encode_text_string
from ..core.exceptions import ItemNotFound, MissingData, InvalidField
from .create import _parse_attributes
from .create_keypair import create_key_pair_objects

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("ReKeyKeyPair requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier (of the PrivateKey to rekey) is required")
    old_priv_uid = uid_item.value

    old_priv = store.get_object(old_priv_uid)
    if old_priv is None:
        raise ItemNotFound(f"Object '{old_priv_uid}' not found")
    if old_priv["object_type"] != ObjectType.PrivateKey:
        raise InvalidField("ReKeyKeyPair requires the UniqueIdentifier of a PrivateKey")

    pub_links = store.get_attribute(old_priv_uid, "Link_PublicKey")
    if not pub_links:
        raise ItemNotFound("No paired PublicKey found for the given PrivateKey")
    old_pub_uid = pub_links[0]
    old_pub = store.get_object(old_pub_uid)
    if old_pub is None:
        raise ItemNotFound(f"Paired PublicKey '{old_pub_uid}' not found")

    common_tmpl = payload.get(Tag.TemplateAttribute)
    pub_tmpl    = payload.get(Tag.PublicKeyAttributes)
    priv_tmpl   = payload.get(Tag.PrivateKeyAttributes)
    common_attrs = _parse_attributes(common_tmpl)
    pub_attrs    = _parse_attributes(pub_tmpl)
    priv_attrs   = _parse_attributes(priv_tmpl)

    algorithm  = pub_attrs.get("algorithm") or common_attrs.get("algorithm") or old_priv["cryptographic_algorithm"]
    length     = pub_attrs.get("length") or common_attrs.get("length") or old_priv["cryptographic_length"]
    pub_mask   = pub_attrs.get("usage_mask", old_pub["usage_mask"])
    priv_mask  = priv_attrs.get("usage_mask", old_priv["usage_mask"])
    names      = pub_attrs.get("names") or common_attrs.get("names", [])
    curve_enum = (pub_attrs.get("recommended_curve")
                  or common_attrs.get("recommended_curve")
                  or RecommendedCurve.P_256)

    new_pub_uid, new_priv_uid = create_key_pair_objects(
        algorithm, length, curve_enum, pub_mask, priv_mask, names, identity, store, shim
    )

    store.add_attribute(old_priv_uid, "Link_ReplacementKey", new_priv_uid)
    store.add_attribute(new_priv_uid, "Link_ReplacedKey", old_priv_uid)
    store.add_attribute(old_pub_uid, "Link_ReplacementKey", new_pub_uid)
    store.add_attribute(new_pub_uid, "Link_ReplacedKey", old_pub_uid)

    log.info("ReKeyKeyPair %s/%s -> %s/%s", old_pub_uid, old_priv_uid, new_pub_uid, new_priv_uid)
    return (
        encode_text_string(Tag.UniqueIdentifier, new_pub_uid)
        + encode_text_string(Tag.UniqueIdentifier, new_priv_uid)
    )
