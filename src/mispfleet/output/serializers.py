"""Deterministic machine-readable serialization (JSON, JSONL, YAML)."""

from __future__ import annotations

import io
import json
import math
from typing import Any, Literal

from pydantic import BaseModel
from pydantic_core import to_jsonable_python
from ruamel.yaml import YAML

SCHEMA_VERSION = "1.0"

OutputFormat = Literal["table", "json", "jsonl", "yaml"]


def jsonable(data: Any) -> Any:
    """Convert models and containers into JSON-compatible primitives."""
    if isinstance(data, BaseModel):
        # Dumped in python mode on purpose: mode="json" turns a set into a
        # list in iteration order, so the sorting and the non-finite-float
        # handling below never saw the contents of any model — and every
        # payload here is a model. Deterministic output was not.
        return jsonable(data.model_dump())
    if isinstance(data, dict):
        keyed = {str(key): jsonable(value) for key, value in data.items()}
        if len(keyed) != len(data):
            raise ValueError("mapping keys collide once stringified; records would be lost")
        return keyed
    if isinstance(data, list | tuple | set | frozenset):
        items = [jsonable(item) for item in data]
        if isinstance(data, set | frozenset):
            return sorted(items, key=str)
        return items
    if isinstance(data, float) and not math.isfinite(data):
        # json.dumps would emit bare NaN/Infinity, which no RFC 8259 parser
        # accepts; the value is unknown, so say so in valid JSON.
        return None
    # Leaves that python mode leaves as objects (datetime, UUID, Enum, Url).
    return to_jsonable_python(data)


def document(operation: str, payload: Any, **extra: Any) -> dict[str, Any]:
    """Wrap a payload in the versioned output envelope."""
    body: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "operation": operation}
    body.update(jsonable(extra))
    merged = jsonable(payload)
    if isinstance(merged, dict):
        body.update(merged)
    else:
        body["data"] = merged
    return body


def serialize(data: Any, output_format: Literal["json", "jsonl", "yaml"]) -> str:
    """Serialize an envelope (or record list for JSONL) deterministically."""
    payload = jsonable(data)
    if output_format == "json":
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if output_format == "jsonl":
        records = payload if isinstance(payload, list) else [payload]
        return "".join(json.dumps(record, sort_keys=True) + "\n" for record in records)
    stream = io.StringIO()
    yaml = YAML(typ="safe")
    yaml.default_flow_style = False
    yaml.dump(payload, stream)
    return stream.getvalue()
