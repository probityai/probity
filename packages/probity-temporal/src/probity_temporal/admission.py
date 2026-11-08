"""Argument admission: refuse, before any digest is taken, a value whose JSON form is ambiguous or
could hide something the activity receives.

The digest an approver signs is taken over the exact JSON Temporal writes into history, so what is
approved is what is sent. Admission adds the other half: a value is admitted only when that JSON is a
faithful, reproducible picture of the Python value, so an approver who recomputes the digest from
the source value gets the same bytes and a reviewer reading history sees every field the code sees.
"""

from __future__ import annotations

import dataclasses
import math
from collections.abc import Mapping, Sequence
from typing import Any

MAX_DEPTH = 32
INT_MIN, INT_MAX = -(2**63), 2**63 - 1


class NotAdmissible(ValueError):  # noqa: N818 - a refusal with a stable reason
    def __init__(self, reason: str, path: str) -> None:
        super().__init__(f"{reason} at {path or '$'}")
        self.reason = reason
        self.path = path


def admit(args: Sequence[Any]) -> None:
    """Raise ``NotAdmissible`` naming the first value that cannot be signed faithfully."""
    for i, value in enumerate(args):
        _admit(value, f"$[{i}]", 0)


def _admit(value: Any, path: str, depth: int) -> None:  # noqa: C901, PLR0911, PLR0912 - one branch per JSON kind
    if depth > MAX_DEPTH:
        raise NotAdmissible("too_deep", path)
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if not INT_MIN <= value <= INT_MAX:
            raise NotAdmissible("int_out_of_64_bit_range", path)
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise NotAdmissible("float_not_finite", path)
        return
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise NotAdmissible("bytes_form_depends_on_converter", path)
    if isinstance(value, (set, frozenset)):
        raise NotAdmissible("set_has_no_stable_order", path)
    if _is_pydantic(value):
        _admit_model(value, path, depth)
        return
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        for f in dataclasses.fields(value):
            _admit(getattr(value, f.name), f"{path}.{f.name}", depth + 1)
        return
    if isinstance(value, Mapping):
        seen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise NotAdmissible("key_not_a_string", f"{path}[{key!r}]")
            if key in seen:
                raise NotAdmissible("keys_collide", f"{path}[{key!r}]")
            seen[key] = item
            _admit(item, f"{path}[{key!r}]", depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _admit(item, f"{path}[{i}]", depth + 1)
        return
    raise NotAdmissible(f"unsupported_type_{type(value).__name__}", path)


def _is_pydantic(value: Any) -> bool:
    return hasattr(type(value), "__pydantic_fields__") and hasattr(type(value), "__pydantic_serializer__")


def _admit_model(model: Any, path: str, depth: int) -> None:  # noqa: C901 - one refusal per way a model hides a value
    cls = type(model)
    from pydantic import BaseModel, SecretBytes, SecretStr  # noqa: PLC0415 - only when a model is passed

    if cls.model_dump is not BaseModel.model_dump or cls.model_dump_json is not BaseModel.model_dump_json:
        raise NotAdmissible("model_dump_overridden", path)
    decorators = getattr(cls, "__pydantic_decorators__", None)
    if decorators is not None and (decorators.field_serializers or decorators.model_serializers):
        raise NotAdmissible("custom_serializer", path)
    if getattr(cls, "__pydantic_computed_fields__", None):
        raise NotAdmissible("computed_field", path)
    if (getattr(cls, "model_config", {}) or {}).get("json_encoders"):
        raise NotAdmissible("json_encoders", path)
    if getattr(model, "__pydantic_extra__", None):
        raise NotAdmissible("extra_fields", path)
    names: dict[str, str] = {}
    for name, info in cls.__pydantic_fields__.items():
        if info.exclude:
            raise NotAdmissible("excluded_field", f"{path}.{name}")
        wire = info.serialization_alias or info.alias or name
        if wire in names:
            raise NotAdmissible("serialized_names_collide", f"{path}.{name}")
        names[wire] = name
        value = getattr(model, name)
        if isinstance(value, (SecretStr, SecretBytes)):
            raise NotAdmissible("secret_value_hidden", f"{path}.{name}")
        _admit(value, f"{path}.{name}", depth + 1)
