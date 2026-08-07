"""Handle KMIP Certify operation — issue a self-signed X.509 certificate for
an existing RSA key pair, built with asn1crypto and signed on the HSM.

No general-purpose crypto library (e.g. `cryptography`) is available in this
environment, so the certificate is assembled by hand with asn1crypto (DER
structures only, no crypto) and the TBSCertificate is signed via the same
PKCS#11 shim.sign() path used by the Sign operation.
"""

import os
import logging
import datetime
from pkcs11 import Mechanism
from ..core.enums import Tag, ObjectType, State, CryptographicAlgorithm, CertificateType
from ..core.ttlv import encode_text_string
from ..core.exceptions import ItemNotFound, MissingData, InvalidField, OperationNotSupported
from ..lifecycle.state_machine import check_usage_allowed
from .create import _parse_attributes

log = logging.getLogger(__name__)

_VALIDITY_DAYS = 365


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("Certify requires a request payload")

    uid_item = payload.get(Tag.UniqueIdentifier)
    if uid_item is None:
        raise MissingData("UniqueIdentifier (of the PublicKey to certify) is required")
    pub_uid = uid_item.value

    obj = store.get_object(pub_uid)
    if obj is None:
        raise ItemNotFound(f"Object '{pub_uid}' not found")
    if obj["object_type"] != ObjectType.PublicKey:
        raise InvalidField("Certify requires the UniqueIdentifier of a PublicKey")

    algorithm = obj.get("cryptographic_algorithm")
    if algorithm != CryptographicAlgorithm.RSA:
        raise OperationNotSupported(f"Certify currently only supports RSA, got algorithm {algorithm}")

    check_usage_allowed(obj["state"], "get", archived=bool(obj.get("archived")))

    priv_links = store.get_attribute(pub_uid, "Link_PrivateKey")
    if not priv_links:
        raise ItemNotFound("No paired PrivateKey found; cannot self-sign the certificate")
    priv_uid = priv_links[0]
    priv_obj = store.get_object(priv_uid)
    if priv_obj is None:
        raise ItemNotFound(f"Paired PrivateKey '{priv_uid}' not found")
    check_usage_allowed(priv_obj["state"], "sign", archived=bool(priv_obj.get("archived")))

    pub_cka_ids  = store.get_attribute(pub_uid, "_pkcs11_cka_id")
    priv_cka_ids = store.get_attribute(priv_uid, "_pkcs11_cka_id")
    if not pub_cka_ids or not priv_cka_ids:
        raise ItemNotFound("PKCS#11 handle not found")
    pub_cka_id  = bytes.fromhex(pub_cka_ids[0])
    priv_cka_id = bytes.fromhex(priv_cka_ids[0])

    tmpl  = payload.get(Tag.TemplateAttribute) or payload.get(Tag.Attributes)
    attrs = _parse_attributes(tmpl)
    names = attrs.get("names", [])
    subject_cn = names[0] if names else f"kmip-cert-{pub_uid}"

    cert_der = _build_self_signed_cert(shim, pub_cka_id, priv_cka_id, subject_cn)

    uid = store.create_object(
        object_type=ObjectType.Certificate,
        state=State.Active,
        owner_identity=identity,
        raw_key_value=cert_der,
        extractable=True,
        sensitive=False,
        names=names,
    )
    store.add_attribute(uid, "_certificate_type", CertificateType.X509)
    store.add_attribute(uid, "Link_PublicKey", pub_uid)
    store.add_attribute(pub_uid, "Link_Certificate", uid)

    log.info("Certified PublicKey %s -> Certificate %s", pub_uid, uid)
    return encode_text_string(Tag.UniqueIdentifier, uid)


def _build_self_signed_cert(shim, pub_cka_id: bytes, priv_cka_id: bytes, subject_cn: str) -> bytes:
    from asn1crypto import x509
    from asn1crypto.keys import RSAPublicKey, PublicKeyInfo
    from asn1crypto.algos import SignedDigestAlgorithm

    pub_der = shim.get_public_key_der(pub_cka_id)
    spki = PublicKeyInfo.wrap(RSAPublicKey.load(pub_der), 'rsa')

    name = x509.Name.build({'common_name': subject_cn})
    now   = datetime.datetime.now(datetime.timezone.utc)
    later = now + datetime.timedelta(days=_VALIDITY_DAYS)
    sig_algo = SignedDigestAlgorithm({'algorithm': 'sha256_rsa'})

    tbs = x509.TbsCertificate({
        'version': 'v1',
        'serial_number': int.from_bytes(os.urandom(16), 'big') >> 1,
        'signature': sig_algo,
        'issuer': name,
        'validity': x509.Validity({
            'not_before': x509.Time({'general_time': now}),
            'not_after':  x509.Time({'general_time': later}),
        }),
        'subject': name,
        'subject_public_key_info': spki,
    })

    signature = shim.sign(priv_cka_id, tbs.dump(), mechanism=Mechanism.SHA256_RSA_PKCS)

    cert = x509.Certificate({
        'tbs_certificate': tbs,
        'signature_algorithm': sig_algo,
        'signature_value': signature,
    })
    return cert.dump()
