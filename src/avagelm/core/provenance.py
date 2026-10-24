"""Context provenance and least-authority mock tool gateway."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Trust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Provenance:
    source_id: str
    trust: Trust
    spans: tuple[tuple[int, int], ...] = ()
    note: str = ""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    provenance: Provenance


class PolicyGateway:
    """Deny privileged synthetic tool proposals in tainted/unknown contexts.

    This is an application-level provenance policy. It does not claim access to
    hidden model token activations; callers attach source/span metadata at ingress.
    """

    RESTRICTED = {"export_demo_records"}

    def authorize(self, tool_name: str, provenance: Provenance, arguments: dict[str, Any]) -> Decision:
        if tool_name not in self.RESTRICTED:
            return Decision(False, "tool_not_allowlisted", provenance)
        if provenance.trust != Trust.TRUSTED:
            return Decision(False, f"restricted_tool_requires_trusted_provenance:{provenance.trust.value}", provenance)
        if arguments != {"record_type": "sample"}:
            return Decision(False, "arguments_fail_strict_schema", provenance)
        return Decision(True, "trusted_provenance_and_schema_valid", provenance)


def execute_mock_tool(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Side-effect-free tool returning synthetic, non-sensitive fixture data."""
    if tool_name != "export_demo_records" or arguments != {"record_type": "sample"}:
        return {"error": "unknown tool or invalid arguments"}
    return {"records": [{"id": "DEMO-001", "status": "synthetic", "value": 7}], "classification": "fixture_only"}
