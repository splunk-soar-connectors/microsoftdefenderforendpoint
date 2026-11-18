# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Build nested SDK output models from the original app's datapath schema."""

import keyword
import re
from functools import cache
from typing import Any

from pydantic import create_model

from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput

from .legacy_output_fields import FIELD_SCHEMAS


class ConnectorOutput(PermissiveActionOutput):
    """Preserve raw API values while publishing typed legacy datapaths.

    The legacy connector added API dictionaries directly to ``action_result.data``.
    PermissiveActionOutput retains those values without coercing or dropping fields,
    while the concrete annotations below provide SDK-compatible manifest types.
    """


class _FieldNode:
    def __init__(self) -> None:
        self.children: dict[str, _FieldNode] = {}
        self.list_depth = 0
        self.metadata: dict[str, Any] | None = None


_FIELD_SCHEMAS: dict[str, dict[str, list[dict[str, Any]]]] = FIELD_SCHEMAS
# These annotations describe the SOAR datapaths. ConnectorOutput's permissive
# serializer preserves the original API JSON types and extra fields at runtime.
_TYPE_MAP = {"string": str, "numeric": float, "boolean": bool}


def _insert_path(
    root: _FieldNode, segments: list[str], metadata: dict[str, Any]
) -> None:
    node = root
    wildcard_depth = 0
    for segment in segments:
        if segment == "*":
            wildcard_depth += 1
            node.list_depth = max(node.list_depth, wildcard_depth)
            continue
        node = node.children.setdefault(segment, _FieldNode())
        wildcard_depth = 0
    node.metadata = metadata


def _safe_field_name(name: str, used: set[str]) -> str:
    safe_name = re.sub(r"\W", "_", name).lstrip("_")
    if not safe_name or safe_name[0].isdigit():
        safe_name = f"field_{safe_name}"
    if keyword.iskeyword(safe_name) or safe_name.startswith("model_"):
        safe_name = f"field_{safe_name}"
    base_name = safe_name
    suffix = 2
    while safe_name in used:
        safe_name = f"{base_name}_{suffix}"
        suffix += 1
    used.add(safe_name)
    return safe_name


def _build_model(name: str, root: _FieldNode) -> type[ActionOutput]:
    model_fields: dict[str, tuple[Any, Any]] = {}
    used_names: set[str] = set()
    original_order = {
        field_name: index for index, field_name in enumerate(root.children)
    }

    def column_order(node: _FieldNode) -> int | None:
        values = []
        if node.metadata and "column_order" in node.metadata:
            values.append(node.metadata["column_order"])
        values.extend(
            order
            for child in node.children.values()
            if (order := column_order(child)) is not None
        )
        return min(values) if values else None

    ordered_children = sorted(
        root.children.items(),
        key=lambda item: (
            column_order(item[1]) is None,
            column_order(item[1])
            if column_order(item[1]) is not None
            else original_order[item[0]],
        ),
    )
    for source_name, node in ordered_children:
        field_name = _safe_field_name(source_name, used_names)
        if node.children:
            field_type: Any = _build_model(f"{name}_{field_name.title()}Output", node)
        else:
            data_type = (node.metadata or {}).get("data_type", "string")
            field_type = _TYPE_MAP.get(data_type, str)

        for _ in range(node.list_depth):
            field_type = list[field_type]
        annotation = field_type | None

        metadata = node.metadata or {}
        output_field_args: dict[str, Any] = {"alias": source_name}
        if "contains" in metadata:
            output_field_args["cef_types"] = metadata["contains"]
        if "example_values" in metadata:
            output_field_args["example_values"] = metadata["example_values"]
        if "column_name" in metadata:
            output_field_args["column_name"] = metadata["column_name"]

        model_fields[field_name] = (annotation, OutputField(**output_field_args))

    return create_model(
        name, __base__=ConnectorOutput, __module__=__name__, **model_fields
    )


def _build_action_model(action_id: str, section: str) -> type[ActionOutput]:
    root = _FieldNode()
    prefix = "action_result.data.*." if section == "data" else "action_result.summary."
    for field in _FIELD_SCHEMAS.get(action_id, {}).get(section, []):
        path = field["data_path"]
        if not path.startswith(prefix):
            continue
        raw_segments = path[len(prefix) :].split(".")
        segments = []
        index = 0
        while index < len(raw_segments):
            if raw_segments[index : index + 2] == ["@odata", "context"]:
                segments.append("@odata.context")
                index += 2
            else:
                segments.append(raw_segments[index])
                index += 1
        _insert_path(root, segments, field)

    model_name = f"{''.join(part.title() for part in action_id.split('_'))}{section.title()}Output"
    return _build_model(model_name, root)


@cache
def get_action_output_types(
    action_id: str,
) -> tuple[type[ActionOutput], type[ActionOutput]]:
    """Return per-action data and summary models with legacy nested datapaths."""
    return (
        _build_action_model(action_id, "data"),
        _build_action_model(action_id, "summary"),
    )
