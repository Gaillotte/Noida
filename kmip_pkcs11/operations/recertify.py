"""Handle KMIP ReCertify operation — issue a fresh certificate for the same
PublicKey an existing Certificate was issued for, cross-linked to it."""

import logging
from ..core.enums import Tag, ObjectType
from ..core.ttlv import encode_text_string
from ..core.exceptions import ItemNotFound, MissingData, InvalidField
from .create import _parse_attributes
from .certify import certify_public_key

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("ReCertify requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier (of the Certificate to recertify) is required")
    old_cert_uid = uid_item.value

    old_cert = store.get_object(old_cert_uid)
    if old_cert is None:
        raise ItemNotFound(f"Object '{old_cert_uid}' not found")
    if old_cert["object_type"] != ObjectType.Certificate:
        raise InvalidField("ReCertify requires the UniqueIdentifier of a Certificate")

    pub_links = store.get_attribute(old_cert_uid, "Link_PublicKey")
    if not pub_links:
        raise ItemNotFound("No linked PublicKey found for the given Certificate")
    pub_uid = pub_links[0]

    tmpl  = payload.get(Tag.TemplateAttribute) or payload.get(Tag.Attributes)
    attrs = _parse_attributes(tmpl)
    names = attrs.get("names", [])

    new_cert_uid = certify_public_key(pub_uid, names, identity, store, shim)

    store.add_attribute(old_cert_uid, "Link_ReplacementCertificate", new_cert_uid)
    store.add_attribute(new_cert_uid, "Link_ReplacedCertificate", old_cert_uid)

    log.info("ReCertified %s -> %s (PublicKey %s)", old_cert_uid, new_cert_uid, pub_uid)
    return encode_text_string(Tag.UniqueIdentifier, new_cert_uid)
