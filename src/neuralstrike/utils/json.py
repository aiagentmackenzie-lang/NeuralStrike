"""Strict data-only JSON decoding for local protocol/evidence boundaries."""

from __future__ import annotations

import json
import math
from typing import Any


class StrictJSONError(ValueError):
    """JSON has ambiguous keys or non-finite constants; diagnostic omits data."""


def strict_json(data: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise StrictJSONError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(value: str) -> Any:
        raise StrictJSONError("non-finite JSON constant")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise StrictJSONError("non-finite JSON number")
        return parsed

    return json.loads(
        data, object_pairs_hook=unique, parse_constant=invalid_constant, parse_float=finite_float
    )
