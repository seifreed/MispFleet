"""Deterministic machine-readable serialization (JSON, JSONL, YAML)."""

from __future__ import annotations

import io
import json
from typing import Any, Literal

from pydantic import BaseModel
from ruamel.yaml import YAML

SCHEMA_VERSION = "1.0"

OutputFormat = Literal["table", "json", "jsonl", "yaml"]


def jsonable(data: Any) -> Any:
    """Convert models and containers into JSON-compatible primitives."""
    if isinstance(data, BaseModel):
        return data.model_dump(mode="json")
    if isinstance(data, dict):
        return {str(key): jsonable(value) for key, value in data.items()}
    if isinstance(data, list | tuple | set | frozenset):
        items = [jsonable(item) for item in data]
        if isinstance(data, set | frozenset):
            return sorted(items, key=str)
        return items
    return data


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
