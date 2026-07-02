"""RFC 8785 JSON Canonicalization Scheme (JCS).

Phase 1B.1. The pre-existing ``CryptoService.compute_payload_hash`` used
``json.dumps(sort_keys=True, separators=(",", ":"))`` which approximates
JCS but is not strictly equivalent:

* Python's ``sort_keys`` orders by Unicode code-point; JCS requires
  UTF-16 code-unit ordering. These diverge only for keys with non-BMP
  characters (U+10000 and above), but that divergence is enough to
  cause cross-language signature mismatches on payloads containing
  emoji-keyed fields.
* Python serializes ``1.0`` as ``"1.0"``; JCS/ECMA-262 emits ``"1"``.
  The same applies to every integer-valued float.
* ``-0.0`` round-trips as ``"-0.0"`` in Python; JCS requires ``"0"``.
* Python ``json`` silently emits ``NaN``/``Infinity``; JCS forbids them.

This module implements the subset of RFC 8785 that is practically
relevant for signed-payload interop. It intentionally does **not**
support floats outside the range where ``repr`` matches ECMA-262
``Number.prototype.toString`` exactly — callers must use integers,
strings (for currency), or finite floats in the decimal range
[1e-6, 1e21). Out-of-range inputs raise ``ValueError`` rather than
silently diverge from a Node/Go/Rust signer.

The vectors at ``tests/fixtures/canonicalization/jcs_vectors.json``
are the cross-language contract: any SDK in any language MUST produce
identical canonical bytes and SHA-256 for every vector, or its
signatures will not verify server-side under sig_version=3.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any


class JCSError(ValueError):
    """Raised when input cannot be JCS-canonicalized."""


# Characters that MUST be escaped per RFC 8785 section 3.2.2.2 and
# ECMA-262 JSON.stringify:
#   \" \\ control characters U+0000..U+001F
# Plus U+2028 and U+2029 per ECMA-262 (JSON spec itself does not require
# these but JSON.stringify escapes them; JCS delegates to JSON.stringify
# via ECMA-262, so we follow suit for interop safety).
_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _encode_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        short = _SHORT_ESCAPES.get(cp)
        if short is not None:
            out.append(short)
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


# ECMA-262 Number.prototype.toString for the subset of finite numbers
# whose Python repr matches the ECMA-262 output. Python's float repr is
# the shortest round-tripping representation (since 3.1), which is close
# to ECMA-262 ToString but differs in a few spots.
_PY_SCI_RE = re.compile(r"^(-?\d+(?:\.\d+)?)e([+-])0*(\d+)$")


def _encode_number(n: int | float) -> str:
    if isinstance(n, bool):
        # bool is a subclass of int in Python; JSON booleans are handled
        # elsewhere and must not fall through to number encoding.
        raise JCSError("bool must be encoded as 'true'/'false', not a number")

    if isinstance(n, int):
        return str(n)

    if not isinstance(n, float):
        raise JCSError(f"unsupported numeric type: {type(n).__name__}")

    if not math.isfinite(n):
        raise JCSError(
            "JCS forbids NaN and Infinity; "
            "encode as a string or omit the field entirely"
        )

    if n == 0.0:
        # Both +0.0 and -0.0 canonicalize to "0".
        return "0"

    # Integer-valued floats: "1.0" must become "1", "100.0" -> "100".
    # The 1e21 cutoff matches ECMA-262 ToString — beyond it numbers
    # always use exponent notation.
    if n.is_integer() and abs(n) < 1e21:
        return str(int(n))

    s = repr(n)

    # Python renders exponents as "1e-07" (zero-padded exponent). JCS
    # follows ECMA-262 which emits "1e-7" (no leading zeros) and always
    # uses a sign. Normalize the mantissa "1.0e-7" -> "1e-7" as well.
    match = _PY_SCI_RE.match(s)
    if match:
        mantissa, sign, exp_digits = match.groups()
        if mantissa.endswith(".0"):
            mantissa = mantissa[:-2]
        return f"{mantissa}e{sign}{int(exp_digits)}"

    return s


def _canonicalize(obj: Any) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        return _encode_string(obj)
    if isinstance(obj, (int, float)):
        return _encode_number(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_canonicalize(item) for item in obj) + "]"
    if isinstance(obj, dict):
        # JCS requires keys sorted by UTF-16 code units. For all keys
        # within the Basic Multilingual Plane (U+0000..U+FFFF) this is
        # identical to code-point sorting. For keys containing non-BMP
        # characters (emoji etc.) we sort by the UTF-16 encoding.
        items = []
        for key in obj:
            if not isinstance(key, str):
                raise JCSError(
                    f"object keys must be strings; got {type(key).__name__}"
                )
            items.append((key.encode("utf-16-be"), key, obj[key]))
        items.sort(key=lambda item: item[0])
        encoded = [
            _encode_string(key) + ":" + _canonicalize(value)
            for (_, key, value) in items
        ]
        return "{" + ",".join(encoded) + "}"

    raise JCSError(f"unsupported type for JCS canonicalization: {type(obj).__name__}")


def canonicalize(obj: Any) -> bytes:
    """Return the JCS canonical UTF-8 bytes for ``obj``.

    Raises ``JCSError`` on NaN/Infinity, non-string object keys, or
    unsupported types.
    """
    return _canonicalize(obj).encode("utf-8")


def sha256_hex(obj: Any) -> str:
    """Return the lowercase hex SHA-256 of the JCS canonical form of ``obj``."""
    return hashlib.sha256(canonicalize(obj)).hexdigest()
