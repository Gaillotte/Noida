"""
Records which KMIP operation each REST endpoint corresponds to, and puts that
in the OpenAPI documentation.

The endpoint names are REST-shaped (`POST /api/kmip/objects`) and the protocol's
are not (`Create`), so a reader of /api/docs has no way to line the two up —
which matters, because the REST API is *not* KMIP and the difference is easy to
miss. This decorator states the correspondence on the endpoint itself.

Two kinds of correspondence, kept distinct because conflating them would be a
lie of exactly the sort this module exists to prevent:

``invokes``
    The endpoint really does call the engine's handler for that KMIP operation,
    in-process. The same code runs as when a KMIP client sends it over 5696 —
    but *without* the OperationDispatcher, so no hash-chained audit entry, no
    per-request KMIP authentication and no dual control. Those are the REST
    layer's own concerns (JWT, roles, portal audit).

``equivalent``
    No handler runs. The endpoint reads the metadata store directly, and the
    named operation is only the closest thing in the protocol. Saying "invokes
    Locate" here would imply access-control filtering and audit that do not
    happen on this path.

Operation names are checked against the engine's own ``Operation`` enum when
this module is imported, so a typo, or an operation the engine drops in a
future sync, fails loudly at startup rather than leaving the documentation
quietly wrong.
"""

from typing import Callable, Iterable, Optional

from kmip_pkcs11.core.enums import Operation

_VALID = {op.name for op in Operation}


class UnknownKMIPOperation(ValueError):
    """A documented operation that the KMIP specification does not define."""


def _check(names: Iterable[str]) -> None:
    unknown = sorted(set(names) - _VALID)
    if unknown:
        raise UnknownKMIPOperation(
            f"Not KMIP 2.1 operations: {', '.join(unknown)}. "
            f"Valid names come from kmip_pkcs11.core.enums.Operation."
        )


def kmip_op(invokes: Optional[Iterable[str]] = None,
            equivalent: Optional[Iterable[str]] = None,
            note: Optional[str] = None) -> Callable:
    """Append the KMIP correspondence to an endpoint's OpenAPI description.

    FastAPI takes the description from the docstring, so this extends it rather
    than replacing it — the prose written on the endpoint survives.
    """
    invokes = list(invokes or [])
    equivalent = list(equivalent or [])
    _check(invokes + equivalent)

    def decorate(func: Callable) -> Callable:
        lines = ["", "---", "", "**KMIP correspondence**", ""]
        if invokes:
            ops = ", ".join(f"`{o}`" for o in invokes)
            lines += [
                f"* Invokes the engine's handler for {ops}, in-process.",
                "  The same code a KMIP client reaches over port 5696 — but this path",
                "  **bypasses the `OperationDispatcher`**, so there is no hash-chained",
                "  `kmip_audit` entry, no per-request KMIP authentication and no dual",
                "  control. This endpoint's own JWT, role check and portal audit apply",
                "  instead.",
            ]
        if equivalent:
            ops = ", ".join(f"`{o}`" for o in equivalent)
            lines += [
                f"* No KMIP handler runs. Reads the metadata store directly; the closest",
                f"  operation in the protocol is {ops}.",
            ]
        if note:
            lines += ["", note]
        lines += [
            "",
            "> This is a JSON/HTTP endpoint, not KMIP. A KMIP client cannot call it,",
            "> and it sends no TTLV. See `GET /api/kmip/operations` for what the engine",
            "> implements over the wire.",
        ]
        func.__doc__ = (func.__doc__ or "").rstrip() + "\n" + "\n".join(lines)
        # Kept machine-readable too, so a test or a generated document can assert
        # the mapping rather than re-deriving it from prose.
        func.kmip_invokes = tuple(invokes)
        func.kmip_equivalent = tuple(equivalent)
        return func

    return decorate


def rest_index(routes: Iterable) -> dict:
    """Invert the annotations: KMIP operation -> the REST endpoints that reach it.

    Built by walking the application's own route table and reading the
    attributes :func:`kmip_op` left on each handler, so it reports what is
    actually wired up. A hand-written table here would claim an endpoint that
    had been renamed or removed — the failure this whole module exists to avoid.

    Returns ``{operation_name: [{"method", "path", "kind"}, ...]}`` where *kind*
    is ``"invokes"`` (the handler really runs) or ``"equivalent"`` (the endpoint
    reads the store directly and this is only the nearest operation).
    """
    index: dict = {}
    for route in routes:
        endpoint = getattr(route, "endpoint", None)
        if endpoint is None:
            continue
        path = getattr(route, "path", "")
        methods = sorted(getattr(route, "methods", []) - {"HEAD", "OPTIONS"})
        for kind, attr in (("invokes", "kmip_invokes"),
                           ("equivalent", "kmip_equivalent")):
            for op in getattr(endpoint, attr, ()):  # absent on unannotated routes
                for method in methods:
                    index.setdefault(op, []).append(
                        {"method": method, "path": path, "kind": kind})
    return index


# The service-level description for /api/docs. Stated once, at the top, because
# "is this KMIP?" is the first question the endpoint names provoke.
API_DESCRIPTION = """
Management API for the CryptoHub Lite platform.

**This is not the KMIP interface.** It is ordinary JSON over HTTP with a JWT.
The KMIP 2.1 protocol is a binary TTLV stream on **port 5696** — a different
port, a different wire format, and a different authentication model. Endpoints
under `/api/kmip/...` are named for the objects they return, not the protocol.

Both routes end at the same engine (`kmip_pkcs11`), the same metadata store and
the same HSM token, which is why a key created either way is the same object.
They differ in what wraps the call, and every endpoint below states which KMIP
operation it corresponds to and whether a handler actually runs.

`GET /api/kmip/operations` reports what the engine implements over the wire,
read from the dispatcher's handler table.
"""
