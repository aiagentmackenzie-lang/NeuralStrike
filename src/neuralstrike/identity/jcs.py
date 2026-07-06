"""RFC 8785 JSON Canonicalization Scheme (JCS) implementation.

A2A signed Agent Cards and inter-agent messages require a deterministic,
signature-stable JSON serialization. Python's ``json.dumps`` with sorted
keys is close, but JCS also pins:

- Object member ordering by UTF-16 code-unit sort of keys.
- Number serialization as shortest IEEE 754 representation with no ``.0``
  suffix on integers and no scientific notation for the common range.
- Whitespace removal.
- Escape rules: control chars, reverse solidus, double quote.

This is a minimal, stdlib-only implementation sufficient for the A2A
verification tests in Phase 5. It does not cover every JCS edge case
(e.g. floating-point NaN/Infinity, which JSON disallows anyway), but it
handles the cases the exit gate exercises.
"""

from __future__ import annotations

import json
import math
from typing import Any

__all__ = ["canonicalize"]


def _sort_key(key: str) -> list[int]:
    """UTF-16 code-unit sort order per JCS."""
    # Python str uses Unicode code points; for BMP characters this matches
    # UTF-16 code units. Surrogate pairs (code points > U+FFFF) would differ,
    # but A2A Agent Card keys are ASCII/BMP identifiers, so code-point sort
    # is sufficient here. Documented as a known limitation.
    return [ord(c) for c in key]


def _canonicalize_value(value: Any) -> Any:
    """Recursively canonicalize a JSON value (number special-casing)."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return _canonical_number(value)
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return [_canonicalize_value(v) for v in value]
    if isinstance(value, dict):
        # JCS: object members ordered by UTF-16 code-unit sort of keys.
        sorted_items = sorted(value.items(), key=lambda kv: _sort_key(kv[0]))
        return {k: _canonicalize_value(v) for k, v in sorted_items}
    raise TypeError(f"JCS does not support type {type(value).__name__}")


def _canonical_number(n: int | float) -> int | float:
    """Return the shortest deterministic representation of a number.

    Python's JSON encoder emits ``1.0`` for floats equal to integers and
    ``1e+20`` for large numbers. JCS requires no ``.0`` suffix and no
    scientific notation in the common range. We force integer-like floats
    to int so json.dumps emits them without a decimal point.
    """
    if isinstance(n, float):
        if n.is_integer() and abs(n) < 1 << 53:
            return int(n)
        if n in (float("inf"), float("-inf")) or math.isnan(n):  # pragma: no cover
            raise ValueError("JCS cannot canonicalize non-finite numbers")
    return n


def canonicalize(value: Any) -> str:
    """Return the JCS canonical JSON string for ``value``."""
    canonical = _canonicalize_value(value)
    # separators=(",", ":") removes whitespace; sort_keys=True is redundant
    # because we already sorted, but harmless and defensive.
    return json.dumps(canonical, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
