from pathlib import Path
from typing import Any, Union, Optional
import yaml


class PolicyEngine:
    def __init__(self, policy_path: Union[str, Path]):
        self.policy_path = Path(policy_path)
        self.policy = self._load()

    def _load(self) -> dict[str, Any]:
        with self.policy_path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def get(self, dotted_path: str, default=None):
        value = self.policy
        for part in dotted_path.split("."):
            if not isinstance(value, dict) or part not in value:
                return default
            value = value[part]
        return value

    @property
    def policy_id(self) -> str:
        return self.policy.get("policy_id", "unknown-policy")

    def fallback_json(self) -> dict[str, Any]:
        return self.get("fallback.json", {
            "answer": self.get("fallback.message", "Request blocked by policy."),
            "citations": [],
            "confidence": "low",
            "next_action": "Please revise your request."
        })

    def schema_name(self, request_schema_name: Optional[str] = None) -> str:
        return request_schema_name or self.get("output_guardrails.schema_name", "support_answer")
