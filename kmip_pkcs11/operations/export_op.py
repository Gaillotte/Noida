"""Handle KMIP Export operation (v2.0+) — retrieve a managed object's material.

Response shape is identical to Get; this server does not implement key
wrapping, so Export and Get behave the same way here.
"""

from . import get as get_op

handle = get_op.handle
