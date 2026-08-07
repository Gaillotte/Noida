"""Handle KMIP Validate operation — check a certificate (or chain) for time
validity and signature correctness.

No general-purpose crypto library is available, so certificates are parsed
with asn1crypto (DER structures only, no crypto) and signatures are checked
by temporarily importing the issuer's RSA public key onto the HSM and
verifying through the same PKCS#11 shim.verify() path used by
SignatureVerify. Only RSA-signed certificates are supported.
"""

import logging
import datetime
from pkcs11 import Mechanism, ObjectClass as ObjClass
from ..core.enums import Tag, ObjectType, CryptographicAlgorithm, KeyFormatType, ValidityIndicator
from ..core.ttlv import encode_enumeration
from ..core.exceptions import ItemNotFound, MissingData, InvalidField

log = logging.getLogger(__name__)

_HASH_TO_MECH = {
    'sha1':   Mechanism.SHA1_RSA_PKCS,
    'sha224': Mechanism.SHA224_RSA_PKCS,
    'sha256': Mechanism.SHA256_RSA_PKCS,
    'sha384': Mechanism.SHA384_RSA_PKCS,
    'sha512': Mechanism.SHA512_RSA_PKCS,
}


def handle(payload, identity: str, store, shim) -> bytes:
    if payload is None:
        raise MissingData("Validate requires a request payload")

    der_list = []

    uid_items = payload.get_all(Tag.UniqueIdentifier)
    if uid_items:
        for item in uid_items:
            uid = item.value
            obj = store.get_object(uid)
            if obj is None:
                raise ItemNotFound(f"Object '{uid}' not found")
            if obj["object_type"] != ObjectType.Certificate:
                raise InvalidField(f"'{uid}' is not a Certificate")
            der_list.append(obj.get("raw_key_value") or b"")
    else:
        for cert_item in payload.get_all(Tag.Certificate):
            value_item = cert_item.get(Tag.CertificateValue)
            if value_item is None:
                raise MissingData("CertificateValue is required")
            der_list.append(value_item.value)

    if not der_list:
        raise MissingData("Validate requires UniqueIdentifier(s) or Certificate(s)")

    indicator = _validate_chain(shim, der_list)
    log.debug("Validate result=%s for %d certificate(s)", indicator.name, len(der_list))
    return encode_enumeration(Tag.ValidityIndicator, indicator)


def _validate_chain(shim, der_list) -> ValidityIndicator:
    from asn1crypto import x509

    try:
        certs = [x509.Certificate.load(der) for der in der_list]
    except Exception:
        return ValidityIndicator.Invalid

    now = datetime.datetime.now(datetime.timezone.utc)
    for cert in certs:
        validity = cert['tbs_certificate']['validity']
        not_before = validity['not_before'].native
        not_after  = validity['not_after'].native
        if not (not_before <= now <= not_after):
            return ValidityIndicator.Invalid

    # Chain is ordered leaf-first; each cert is verified against the next
    # (its issuer). The last entry — or the only entry — verifies against
    # its own embedded public key (self-signed).
    for i, cert in enumerate(certs):
        issuer_cert = certs[i + 1] if i + 1 < len(certs) else cert
        result = _verify_cert_signature(shim, cert, issuer_cert)
        if result is None:
            return ValidityIndicator.Unknown
        if result is False:
            return ValidityIndicator.Invalid

    return ValidityIndicator.Valid


def _verify_cert_signature(shim, cert, issuer_cert):
    """Returns True/False, or None if the algorithm isn't supported (Unknown)."""
    if issuer_cert.public_key['algorithm']['algorithm'].native != 'rsa':
        return None
    mech = _HASH_TO_MECH.get(cert.hash_algo)
    if cert.signature_algo != 'rsassa_pkcs1v15' or mech is None:
        return None

    rsa_pub_der = issuer_cert.public_key['public_key'].parsed.dump()
    ephemeral_id = shim.import_public_key(
        CryptographicAlgorithm.RSA, rsa_pub_der, KeyFormatType.PKCS1,
        label="validate-ephemeral", verify=True,
    )
    try:
        return shim.verify(ephemeral_id, cert['tbs_certificate'].dump(), cert.signature, mechanism=mech)
    except Exception:
        return False
    finally:
        try:
            shim.destroy_object(ephemeral_id, ObjClass.PUBLIC_KEY)
        except Exception:
            pass
