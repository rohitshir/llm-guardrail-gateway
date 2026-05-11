# LLM Guardrail Gateway – Project Summary

This is an educational AI safety middleware prototype that sits between users and LLMs.

## Key Capabilities

- Input guardrails for prompt injection, jailbreak patterns, blocked topics, and sample PII detection
- YAML-based policy configuration
- Mock LLM and optional OpenAI LLM adapter
- Output validation using JSON Schema
- Retry handling for invalid model responses
- Safe fallback response when validation fails
- SQLite-backed audit trail
- Browser-based demo UI and audit dashboard

## Positioning

This project is an educational prototype, not a production-grade compliance platform.
