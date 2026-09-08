"""
A KMIP client application: the API connects to the engine as a real client.

Every other KMIP route in this API calls the engine's handlers *in-process*.
That is fast and right for the portal's own features, but it exercises none of
the protocol — no TTLV encoding, no per-request authentication, no dispatcher,
no hash-chained audit entry. So it cannot be used to test the thing customers
actually integrate against.

This module opens a genuine TCP connection to the KMIP server on 5696 and
speaks TTLV, exactly as a third-party client would. Operations run here appear
in `kmip_audit` with the API container's address as the peer, and are subject
to the same authentication and authorization as any other client.

**The form is derived, not written.** `describe()` reads
`inspect.signature()` off each `KMIPClient` method, so the parameters a browser
is asked for are the parameters the client actually takes. Adding a method to
the client puts it in the client application with no change here; changing a signature
changes the form. Forty-one hand-written forms would be wrong within a week —
this codebase has already been caught out by hardcoded operation lists twice.
"""

import ast
import datetime
import enum
import inspect
import logging
import re
import time
import typing
from typing import Any, Callable, Dict, List, Optional

from kmip_pkcs11.core.enums import (
    CertificateType, CryptographicAlgorithm, CryptographicUsageMask,
    DerivationMethod, HashingAlgorithm, KeyFormatType, NameType, ObjectType,
    Operation, RecommendedCurve, ResultReason, ResultStatus,
    RevocationReasonCode, SplitKeyMethod, State, ValidityIndicator,
)
from kmip_pkcs11.test_app.client import KMIPClient, KMIPClientError

log = logging.getLogger(__name__)

# Operation name -> the KMIPClient method that performs it. Derived where the
# names line up (Archive -> archive, GetAttributeList -> get_attribute_list),
# with the handful of exceptions listed explicitly rather than special-cased in
# the loop, so the exceptions are visible.
_RENAMED = {
    "Import": "import_object",     # `import` is a Python keyword
    "ReKey": "rekey",              # _snake would give "re_key"
    "MAC": "mac",
    "MACVerify": "mac_verify",
    "RNGRetrieve": "rng_retrieve",
    "RNGSeed": "rng_seed",
    "ReKeyKeyPair": "rekey_key_pair",
    "ReCertify": "recertify",
}


def _snake(name: str) -> str:
    out = []
    for i, ch in enumerate(name):
        if ch.isupper() and i and not name[i - 1].isupper():
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


def _method_for(operation: str) -> Optional[Callable]:
    attr = _RENAMED.get(operation, _snake(operation))
    return getattr(KMIPClient, attr, None)


class _TracingClient(KMIPClient):
    """A KMIP client that records the bytes it puts on the wire.

    The client application's whole value is being able to show a customer what actually
    travelled, rather than asserting it. Overriding the two transport methods
    captures that at the only place it is unambiguous - after encoding, before
    the socket - without the client itself carrying any presentation concern.

    Bounded on purpose: a Get response can carry a whole certificate, and this
    is a diagnostic panel, not a packet capture.
    """

    MAX_CAPTURE = 512      # bytes retained per frame

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.trace = []

    def _send(self, data: bytes):
        self.trace.append({"direction": "sent", "bytes": len(data),
                           "hex": data[:self.MAX_CAPTURE].hex(),
                           "truncated": len(data) > self.MAX_CAPTURE})
        return super()._send(data)

    def _recv(self) -> bytes:
        data = super()._recv()
        self.trace.append({"direction": "received", "bytes": len(data),
                           "hex": data[:self.MAX_CAPTURE].hex(),
                           "truncated": len(data) > self.MAX_CAPTURE})
        return data


# What a parameter *means*, for the handful whose name is a KMIP term rather
# than plain English. `uid` alone appears in 24 of the 41 methods, and "uid *"
# on its own tells a first-time user nothing about where the value comes from.
# Keyed by parameter name so it stays derived: a method that takes `uid` gets
# the explanation without being listed anywhere.
_HINTS = {
    "uid": "the object's KMIP Unique Identifier - click the identifier under a "
           "key's label on the Keys page to copy it, or take it from the result "
           "of a Create, Register or Locate here",
    "uids": "several Unique Identifiers",
    "private_uid": "Unique Identifier of the private key",
    "public_uid": "Unique Identifier of the public key",
    "certificate_uid": "Unique Identifier of a Certificate object",
    "part_uids": "Unique Identifiers of the split-key parts",
    "usage_mask": "what the key may be used for; the request carries the sum "
                  "of the boxes ticked",
}


def _field(param: inspect.Parameter) -> Dict[str, Any]:
    """One form field, described from the parameter itself."""
    annotation = param.annotation
    required = param.default is inspect.Parameter.empty

    # Optional[X] is Union[X, None]; take X so the browser gets a usable type
    # rather than being told "typing.Optional[str]".
    origin = typing.get_origin(annotation)
    if origin is typing.Union:
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        annotation = args[0] if args else str

    kind = {str: "text", int: "number", bool: "checkbox",
            bytes: "bytes", list: "list"}.get(annotation, "text")

    default = None if required else param.default
    if isinstance(default, bytes):
        default = default.decode("utf-8", "replace")
    elif default is not None and not isinstance(default, (str, int, float, bool)):
        default = int(default) if isinstance(default, int) else str(default)

    # An enum parameter is a number only in the encoding. `algorithm` is
    # annotated `int` but its default is `CryptographicAlgorithm.AES`, so the
    # enum is right there in the signature - taking it from the default first,
    # and from the parameter name only when there is no default, keeps this
    # derived rather than a second list of what means what.
    enum_cls = None
    if isinstance(param.default, enum.Enum):
        enum_cls = type(param.default)
    elif kind == "number":
        enum_cls = _enum_for(param.name)
    choices = None
    flag_cls = _FLAGS_BY_KEY.get(normalised(param.name)) if kind == "number" else None
    if flag_cls is not None:
        # A mask is a set, not a choice, so it cannot be a dropdown. Its default
        # is `Encrypt | Decrypt`, which Python collapses to a plain int - which
        # is why the enum cannot be read off the signature the way `algorithm`
        # can, and why this one key is listed.
        kind = "flags"
        choices = [{"value": int(member), "label": member.name}
                   for member in flag_cls]
    elif enum_cls is not None:
        kind = "enum"
        choices = [{"value": int(member), "label": member.name}
                   for member in enum_cls]

    return {
        "name": param.name,
        "type": kind,
        "required": required,
        "default": default,
        "choices": choices,
        # bytes fields accept either, because a UID is text and a signature is
        # not; the browser cannot know which the user means.
        "hint": (_HINTS.get(param.name)
                 or ("text, or 0x-prefixed hex" if kind == "bytes"
                     else "comma-separated" if kind == "list" else None)),
    }


def describe() -> List[Dict[str, Any]]:
    """Every operation the client application can drive, with its form."""
    out = []
    for op in Operation:
        method = _method_for(op.name)
        if method is None:
            continue
        params = list(inspect.signature(method).parameters.values())[1:]  # drop self
        out.append({
            "operation": op.name,
            "method": method.__name__,
            "doc": (inspect.getdoc(method) or "").split("\n\n")[0],
            "fields": [_field(p) for p in params],
        })
    return sorted(out, key=lambda o: o["operation"])


def _coerce(raw: Any, field: Dict[str, Any]) -> Any:
    """Turn one submitted form value into what the client method expects."""
    kind = field["type"]
    if raw is None or raw == "":
        return None
    if kind in ("number", "enum", "flags"):
        return int(raw)
    if kind == "checkbox":
        return raw if isinstance(raw, bool) else str(raw).lower() in ("1", "true", "on")
    if kind == "bytes":
        text = str(raw)
        # 0x lets a caller supply a signature or digest, which has no sensible
        # text form; anything else is taken literally so `data=hello` works.
        return bytes.fromhex(text[2:]) if text.startswith("0x") else text.encode()
    if kind == "list":
        return [p.strip() for p in str(raw).split(",") if p.strip()]
    return str(raw)


def _jsonable(value: Any) -> Any:
    """Responses carry bytes and TTLV items; make them printable without
    pretending they are something else."""
    if isinstance(value, (bytes, bytearray)):
        return {"__bytes__": len(value), "hex": bytes(value).hex()}
    if isinstance(value, datetime.datetime):
        return value.isoformat(timespec="seconds")
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


# Which KMIP enum gives meaning to which result key. `Query` answers with
# `operations: [1, 2, 3, ...]`, which is faithful to the wire and useless to
# read - the numbers are the whole answer only if you have the spec open.
# Keyed by the name the client already uses, and resolved against the engine's
# own enums, so a decoded name can never disagree with what the engine meant.
_ENUM_BY_KEY = {
    "operations": Operation,
    "operation": Operation,
    "object_types": ObjectType,
    "object_type": ObjectType,
    "state": State,
    "algorithm": CryptographicAlgorithm,
    "cryptographic_algorithm": CryptographicAlgorithm,
    "hashing_algorithm": HashingAlgorithm,
    "key_format_type": KeyFormatType,
    "certificate_type": CertificateType,
    "revocation_reason": RevocationReasonCode,
    "derivation_method": DerivationMethod,
    "recommended_curve": RecommendedCurve,
    "split_key_method": SplitKeyMethod,
    "validity_indicator": ValidityIndicator,
    "result_reason": ResultReason,
    "result_status": ResultStatus,
    # Input-side only: `revoke(reason=5)` and `create_split_key(method=...)`
    # are annotated int with a plain-int default, so the enum cannot be
    # read off the signature the way `algorithm` can.
    "reason": RevocationReasonCode,
    "method": SplitKeyMethod,
}

# Seconds since the epoch, as KMIP dates are. `lease_time` is deliberately not
# here: it is a duration, and showing it as a date in 1970 would be worse than
# showing the number.
# Bitmask enums: several values at once, so they get checkboxes rather than a
# dropdown, and the request carries their sum.
_FLAGS_BY_KEY = {
    "usage_mask": CryptographicUsageMask,
    "cryptographic_usage_mask": CryptographicUsageMask,
}

_DATE_KEYS = {"last_change_date", "initial_date", "activation_date",
              "deactivation_date", "destroy_date", "compromise_date",
              "process_start_date", "protect_stop_date"}


def normalised(key: str) -> str:
    """One spelling for a result key, whichever side named it."""
    return str(key).strip().lower().replace(" ", "_")


def _enum_for(key: str):
    """The enum a result key belongs to, if any.

    Keys reach us in two spellings: the client's own snake_case (`object_types`)
    and KMIP's canonical attribute names, which GetAttributes returns verbatim
    (`Object Type`, `Cryptographic Algorithm`). Normalising both to one form
    means the table below stays a single list rather than two.
    """
    return _ENUM_BY_KEY.get(normalised(key))


def _enum_name(enum_cls, value: Any) -> str:
    """`Create (1)` - the name for a person, the number for the protocol."""
    try:
        return f"{enum_cls(value).name} ({int(value)})"
    except (ValueError, KeyError, TypeError):
        return str(value)


def _readable(result: Any) -> List[Dict[str, Any]]:
    """A flat, label/value view of a result, for people rather than machines.

    Deliberately alongside the raw JSON, never instead of it. This page exists
    to show a customer exactly what the protocol did, so anything that reshapes
    the answer has to sit next to the answer, not replace it.
    """
    def value_for(key: str, value: Any) -> str:
        enum_cls = _enum_for(key)
        if enum_cls is not None:
            if isinstance(value, list):
                return ", ".join(_enum_name(enum_cls, v) for v in value) or "none"
            return _enum_name(enum_cls, value)
        if key in _DATE_KEYS and isinstance(value, (int, float)) and value:
            return (datetime.datetime.fromtimestamp(value, datetime.timezone.utc)
                    .isoformat(timespec="seconds"))
        # KMIP spells it "Cryptographic Usage Mask"; the client's own parameter
        # is just `usage_mask`. Both mean the same bitmask.
        if normalised(key) in ("usage_mask", "cryptographic_usage_mask") and \
                isinstance(value, int):
            flags = [f.name for f in CryptographicUsageMask if int(f) & value]
            return f"{', '.join(flags) or 'none'} ({value})"
        # KMIP `Name` is a structure - the text plus how to read it - and it
        # reaches us already flattened to a string. Unpack it when it is
        # recognisably that structure, and leave it alone when it is not.
        if isinstance(value, str) and value.startswith("{") and "'value'" in value:
            try:
                parsed = ast.literal_eval(value)
            except (ValueError, SyntaxError):
                return value
            if isinstance(parsed, dict) and "value" in parsed:
                kind = parsed.get("type")
                named = _enum_name(NameType, kind) if kind is not None else None
                return f"{parsed['value']}" + (f" [{named}]" if named else "")
            return value
        if isinstance(value, dict) and "__bytes__" in value:
            hexed = value.get("hex", "")
            return (f"{value['__bytes__']} bytes"
                    + (f" - {hexed[:64]}..." if len(hexed) > 64 else f" - {hexed}"))
        if isinstance(value, list):
            return "\n".join(str(v) for v in value) or "none"
        if value is None:
            return "null"
        return str(value)

    if result is None:
        return [{"label": "Result",
                 "value": "The operation succeeded and returns no data."}]
    if isinstance(result, dict) and "__bytes__" in result:
        return [{"label": "Bytes returned", "value": value_for("_", result)}]
    if isinstance(result, dict):
        rows = []
        for key, value in result.items():
            row = {"label": key.replace("_", " ").capitalize(),
                   "value": value_for(key, value)}
            if isinstance(value, list):
                row["count"] = len(value)
            rows.append(row)
        return rows
    if isinstance(result, (list, tuple)):
        return [{"label": "Returned", "count": len(result),
                 "value": "\n".join(str(v) for v in result) or "none"}]
    return [{"label": "Result", "value": str(result)}]


def _refusal(message: str) -> List[Dict[str, Any]]:
    """Decode a KMIP refusal into something a reader can act on.

    The client raises with the reason code embedded - "Operation failed
    (reason=23): Key is not extractable". The code is the part that is
    unambiguous across implementations and the part nobody can read, so it is
    resolved here against the engine's own ResultReason.
    """
    match = re.search(r"reason=(\d+)", message)
    rows = [{"label": "Outcome", "value": "Refused by the server"}]
    if match:
        rows.append({"label": "Result reason",
                     "value": _enum_name(ResultReason, int(match.group(1)))})
    detail = message.split(":", 1)[1].strip() if ":" in message else message
    rows.append({"label": "Detail", "value": detail})
    return rows


def execute(operation: str, arguments: Dict[str, Any], *, host: str, port: int,
            username: str, password: str) -> Dict[str, Any]:
    """Run one operation as a KMIP client and return what the server said.

    A KMIP-level refusal is a result, not a failure: `Get` on a non-extractable
    key is the engine behaving correctly, and the application should show that
    rather than a stack trace. Only a transport problem is an error.
    """
    spec = next((o for o in describe() if o["operation"] == operation), None)
    if spec is None:
        raise ValueError(f"{operation!r} is not an operation this client application can drive")

    by_name = {f["name"]: f for f in spec["fields"]}
    kwargs = {}
    for name, raw in (arguments or {}).items():
        if name not in by_name:
            continue                      # ignore stray form fields
        coerced = _coerce(raw, by_name[name])
        if coerced is not None:
            kwargs[name] = coerced

    missing = [f["name"] for f in spec["fields"] if f["required"] and f["name"] not in kwargs]
    if missing:
        raise ValueError(f"{operation} requires: {', '.join(missing)}")

    client = _TracingClient(host=host, port=port, username=username, password=password)
    started = time.monotonic()
    client.connect()

    def _wire(outcome: Dict[str, Any]) -> Dict[str, Any]:
        """Attach what actually crossed the network, so the claim is checkable."""
        outcome["transport"] = {
            "protocol": "KMIP 2.1 over TTLV",
            "endpoint": f"{host}:{port}",
            "note": "a TCP socket carrying binary TTLV - not HTTP, not REST",
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            # connect() authenticates, so the first frames are that exchange.
            "frames": client.trace,
        }
        return outcome

    try:
        result = getattr(client, spec["method"])(**kwargs)
        payload = _jsonable(result)
        return _wire({"ok": True, "operation": operation, "result": payload,
                      "readable": _readable(payload)})
    except KMIPClientError as e:
        # The server understood and declined. Report it as the answer it is -
        # decoded, because a refusal is the result most worth understanding and
        # "reason=23" is the least readable thing on the page.
        reason = re.search(r"reason=(\d+)", str(e))
        return _wire({"ok": False, "operation": operation, "refused": True,
                      "error": str(e), "readable": _refusal(str(e)),
                      # Numeric as well as decoded: a caller deciding what to do
                      # next needs to test the code, not match on prose.
                      "reason_code": int(reason.group(1)) if reason else None})
    finally:
        try:
            client.close()
        except Exception:                 # noqa: BLE001 - closing must not mask the result
            log.debug("KMIP client application: error closing the connection", exc_info=True)
