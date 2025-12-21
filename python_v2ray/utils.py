from dataclasses import asdict, fields, is_dataclass
from enum import Enum
from typing import Any


def prune_empty_containers(data: Any) -> Any:
    if is_dataclass(data):
        result = {}
        for f in fields(data):
            value = getattr(data, f.name)
            cleaned = prune_empty_containers(value)
            if cleaned is not None and cleaned not in ["", [], {}]:
                result[f.name] = cleaned
        return result
    if isinstance(data, list):
        return [
            prune_empty_containers(item)
            for item in data
            if item is not None and item not in ["", [], {}]
        ]
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            cleaned = prune_empty_containers(value)
            if cleaned is not None and cleaned not in ["", [], {}]:
                result[key] = cleaned
        return result
    return data


def _snake_to_camel(s: str) -> str:
    parts = s.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def to_camel_case(obj):
    if isinstance(obj, Enum):
        return to_camel_case(obj.value)
    if isinstance(obj, dict):
        return {_snake_to_camel(k): to_camel_case(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [to_camel_case(i) for i in obj]
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    if hasattr(obj, "__dict__"):
        return to_camel_case(asdict(obj))
    return obj
