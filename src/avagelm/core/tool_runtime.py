"""The small tool gate I can plug into another Python app."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Callable

from avagelm.core.provenance import Decision, Provenance, Trust


ToolHandler = Callable[..., Any]


@dataclass(frozen=True)
class RegisteredTool:
    name: str
    description: str
    parameters: dict[str, Any]
    handler: ToolHandler


@dataclass(frozen=True)
class ToolResult:
    decision: Decision
    result: Any = None
    error: str | None = None


def _schema_error(value: Any, schema: dict[str, Any], path: str = "arguments") -> str | None:
    """Validate the common JSON Schema fields used by tool arguments."""
    expected = schema.get("type")
    type_checks = {
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
        "boolean": lambda item: isinstance(item, bool),
        "null": lambda item: item is None,
    }
    if expected in type_checks and not type_checks[expected](value):
        return f"{path}_must_be_{expected}"
    if "enum" in schema and value not in schema["enum"]:
        return f"{path}_not_in_allowed_values"
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            return f"{path}_is_too_short"
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            return f"{path}_is_too_long"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            return f"{path}_is_below_minimum"
        if "maximum" in schema and value > schema["maximum"]:
            return f"{path}_is_above_maximum"
    if isinstance(value, list):
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            return f"{path}_has_too_many_items"
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                issue = _schema_error(item, item_schema, f"{path}[{index}]")
                if issue:
                    return issue
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                return f"{path}_missing_{key}"
        if schema.get("additionalProperties", True) is False:
            extra = set(value) - set(properties)
            if extra:
                return f"{path}_has_unknown_fields"
        for key, item in value.items():
            child_schema = properties.get(key)
            if isinstance(child_schema, dict):
                issue = _schema_error(item, child_schema, f"{path}.{key}")
                if issue:
                    return issue
    return None


class GuardedToolRegistry:
    """Register app-owned functions and check their source before running them.

    This is the bit another Python app can reuse: send the model's tool proposal
    through ``execute`` instead of calling the function directly.
    """

    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}

    def register(self, name: str, description: str, parameters: dict[str, Any],
                 handler: ToolHandler) -> None:
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]{0,63}", name):
            raise ValueError("Tool names must start with a letter and use letters, numbers, or underscores")
        if name in self._tools:
            raise ValueError(f"Tool {name!r} is already registered")
        if parameters.get("type") != "object":
            raise ValueError("Tool parameters must use a JSON object schema")
        if not callable(handler):
            raise TypeError("Tool handler must be callable")
        self._tools[name] = RegisteredTool(name, description, parameters, handler)

    def model_tools(self) -> list[dict[str, Any]]:
        """Return tool descriptions for Ollama or an OpenAI-compatible endpoint."""
        return [{"type": "function", "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters,
        }} for tool in self._tools.values()]

    def authorize(self, name: str, arguments: dict[str, Any], provenance: Provenance) -> Decision:
        if name not in self._tools:
            return Decision(False, "tool_not_allowlisted", provenance)
        if provenance.trust != Trust.TRUSTED:
            return Decision(False, f"tool_requires_trusted_provenance:{provenance.trust.value}", provenance)
        if not isinstance(arguments, dict):
            return Decision(False, "arguments_must_be_object", provenance)
        issue = _schema_error(arguments, self._tools[name].parameters)
        if issue:
            return Decision(False, f"arguments_fail_schema:{issue}", provenance)
        return Decision(True, "trusted_provenance_and_schema_valid", provenance)

    def execute(self, name: str, arguments: dict[str, Any], provenance: Provenance) -> ToolResult:
        decision = self.authorize(name, arguments, provenance)
        if not decision.allowed:
            return ToolResult(decision)
        try:
            result = self._tools[name].handler(**arguments)
            return ToolResult(decision, result=result)
        except Exception as exc:
            return ToolResult(decision, error=f"{type(exc).__name__}: {exc}")
