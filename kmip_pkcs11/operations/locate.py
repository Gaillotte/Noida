"""Handle KMIP Locate operation — search objects by attribute criteria."""

import logging
from ..core.enums import Tag, ObjectType, State
from ..core.ttlv import encode_text_string, encode_structure, encode_integer
from ..core.exceptions import MissingData
from .create import _parse_attributes

log = logging.getLogger(__name__)


def handle(payload, identity: str, store, shim) -> bytes:
    max_items = None
    filter_obj_type = None
    filter_state    = None
    filter_name     = None
    filter_algo     = None
    filter_length   = None

    if payload is not None:
        max_item_node = payload.get(Tag.MaximumItems)
        if max_item_node:
            max_items = max_item_node.value

        otype_node = payload.get(Tag.ObjectType)
        if otype_node:
            filter_obj_type = otype_node.value

        state_node = payload.get(Tag.State)
        if state_node:
            filter_state = state_node.value

        # Attributes may be in a TemplateAttribute or inline
        tmpl = payload.get(Tag.Attributes) or payload.get(Tag.TemplateAttribute)
        if tmpl:
            attrs = _parse_attributes(tmpl)
            filter_algo   = attrs.get("algorithm")
            filter_length = attrs.get("length")
            names         = attrs.get("names", [])
            filter_name   = names[0] if names else None

    uids = store.locate(
        object_type=filter_obj_type,
        state=filter_state,
        name=filter_name,
        cryptographic_algorithm=filter_algo,
        cryptographic_length=filter_length,
        max_items=max_items,
    )

    log.debug("Locate found %d objects", len(uids))

    payload_bytes = b""
    for uid in uids:
        payload_bytes += encode_text_string(Tag.UniqueIdentifier, uid)

    return payload_bytes
