from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from jsonschema import Draft202012Validator
from .models import GuardrailViolation
from .policy_engine import PolicyEngine


PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"reveal\s+(the\s+)?(system|developer)\s+(prompt|message|instructions)",
    r"print\s+(the\s+)?(system|developer)\s+(prompt|message|instructions)",
    r"you\s+are\s+now\s+(dan|do anything now)",
    r"jailbreak",
    r"bypass\s+(safety|policy|guardrails|filters)",
    r"pretend\s+you\s+are\s+not\s+bound",
    r"act\s+as\s+an\s+unrestricted",
]

TOXIC_PATTERNS = [
    r"\b(kill yourself)\b",
    r"\b(racial slur)\b",
    r"\b(exterminate|dehumanize)\s+(all|every)\b",
]


def luhn_check(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def find_pii(text: str, enabled_entities: list[str]) -> list[GuardrailViolation]:
    violations: list[GuardrailViolation] = []

    if "credit_card" in enabled_entities:
        for match in re.finditer(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)", text):
            candidate = match.group(0)
            if luhn_check(candidate):
                violations.append(GuardrailViolation(
                    stage="input",
                    code="pii_credit_card",
                    message="Possible credit card number detected.",
                    severity="critical",
                    evidence=mask(candidate),
                ))

    if "email" in enabled_entities:
        for match in re.finditer(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", text, re.I):
            violations.append(GuardrailViolation(
                stage="input",
                code="pii_email",
                message="Email address detected.",
                severity="medium",
                evidence=mask(match.group(0)),
            ))

    if "phone" in enabled_entities:
        phone_regex = r"(?<!\d)(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?!\d)"
        for match in re.finditer(phone_regex, text):
            violations.append(GuardrailViolation(
                stage="input",
                code="pii_phone",
                message="Phone number detected.",
                severity="medium",
                evidence=mask(match.group(0)),
            ))

    if "canadian_sin" in enabled_entities:
        # Canadian SIN is 9 digits and uses a Luhn-style check.
        for match in re.finditer(r"(?<!\d)\d{3}[ -]?\d{3}[ -]?\d{3}(?!\d)", text):
            candidate = match.group(0)
            if luhn_check(candidate):
                violations.append(GuardrailViolation(
                    stage="input",
                    code="pii_canadian_sin",
                    message="Possible Canadian SIN detected.",
                    severity="critical",
                    evidence=mask(candidate),
                ))

    if "us_ssn" in enabled_entities:
        for match in re.finditer(r"\b\d{3}-\d{2}-\d{4}\b", text):
            violations.append(GuardrailViolation(
                stage="input",
                code="pii_us_ssn",
                message="Possible US SSN detected.",
                severity="critical",
                evidence=mask(match.group(0)),
            ))

    return violations


def mask(value: str) -> str:
    clean = value.strip()
    if len(clean) <= 4:
        return "*" * len(clean)
    return clean[:2] + "*" * max(4, len(clean) - 4) + clean[-2:]


def validate_input(text: str, policy: PolicyEngine) -> list[GuardrailViolation]:
    violations: list[GuardrailViolation] = []

    max_chars = policy.get("input_guardrails.max_input_chars", 12000)
    if len(text) > max_chars:
        violations.append(GuardrailViolation(
            stage="input",
            code="input_too_large",
            message=f"Input exceeds configured maximum of {max_chars} characters.",
            severity="high",
        ))

    if policy.get("input_guardrails.block_prompt_injection", True):
        lowered = text.lower()
        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, lowered):
                violations.append(GuardrailViolation(
                    stage="input",
                    code="prompt_injection",
                    message="Potential prompt injection or jailbreak attempt detected.",
                    severity="critical",
                    evidence=pattern,
                ))

    pii_cfg = policy.get("input_guardrails.block_pii", {})
    if pii_cfg.get("enabled", False):
        violations.extend(find_pii(text, pii_cfg.get("entities", [])))

    blocked_topics = policy.get("business_rules.blocked_topics", [])
    for topic in blocked_topics:
        if topic.lower() in text.lower():
            violations.append(GuardrailViolation(
                stage="policy",
                code="blocked_topic",
                message=f"Blocked topic detected: {topic}",
                severity="high",
                evidence=topic,
            ))

    return violations


def parse_json(raw: str) -> tuple[Any | None, list[GuardrailViolation]]:
    try:
        return json.loads(raw), []
    except json.JSONDecodeError as exc:
        return None, [GuardrailViolation(
            stage="schema",
            code="invalid_json",
            message=f"Response is not valid JSON: {exc.msg}",
            severity="high",
        )]


def validate_schema(data: Any, schema_path: Path) -> list[GuardrailViolation]:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    violations = []
    for error in sorted(validator.iter_errors(data), key=lambda e: e.path):
        path = ".".join(str(p) for p in error.path) or "$"
        violations.append(GuardrailViolation(
            stage="schema",
            code="schema_validation_failed",
            message=f"{path}: {error.message}",
            severity="high",
        ))
    return violations


def validate_output(raw: str, policy: PolicyEngine, schema_path: Path, user_text: str) -> tuple[Any | None, list[GuardrailViolation]]:
    violations: list[GuardrailViolation] = []

    data = raw
    if policy.get("output_guardrails.require_json", True):
        parsed, json_violations = parse_json(raw)
        violations.extend(json_violations)
        if json_violations:
            return None, violations
        data = parsed
        violations.extend(validate_schema(data, schema_path))

    if policy.get("output_guardrails.block_toxic_content", True):
        output_text = raw.lower()
        for pattern in TOXIC_PATTERNS:
            if re.search(pattern, output_text):
                violations.append(GuardrailViolation(
                    stage="output",
                    code="toxic_content",
                    message="Toxic or abusive content detected in model output.",
                    severity="critical",
                    evidence=pattern,
                ))

    for competitor in policy.get("business_rules.blocked_competitors", []):
        if competitor.lower() in raw.lower():
            violations.append(GuardrailViolation(
                stage="policy",
                code="blocked_competitor",
                message=f"Output discusses a blocked competitor: {competitor}",
                severity="high",
                evidence=competitor,
            ))

    if policy.get("output_guardrails.require_citations", False) and isinstance(data, dict):
        citations = data.get("citations", [])
        if not citations:
            violations.append(GuardrailViolation(
                stage="output",
                code="missing_citations",
                message="Output requires at least one citation.",
                severity="medium",
            ))

    return data, violations
