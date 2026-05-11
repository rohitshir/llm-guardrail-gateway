# LLM Guardrail Gateway

A lightweight middleware/API gateway that sits between users and any LLM provider. It enforces:

- Input guardrails: prompt injection, jailbreak attempts, PII leakage, blocked topics
- Output guardrails: valid JSON, schema validation, toxicity checks, citations, competitor restrictions
- YAML policy engine for non-engineer configurable rules
- Auto-retry with correction prompt
- Safe fallback if validation still fails

## Why this architecture

This is implemented as a deterministic gateway, not just a system prompt. The middleware checks user input before the LLM call and validates the model response after the LLM call.

## Project structure

```text
llm_guardrail_gateway/
  app/
    main.py
    llm_gateway.py
    models.py
    policy_engine.py
    validators.py
  policies/
    default_policy.yaml
  schemas/
    support_answer.schema.json
  tests/
  requirements.txt
  .env.example
```

## Run locally

```bash
cd llm_guardrail_gateway
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

## Test with mock LLM

```bash
curl -X POST "http://127.0.0.1:8000/v1/guarded-chat"   -H "Content-Type: application/json"   -d '{
    "model": "mock",
    "messages": [
      {"role": "user", "content": "Explain our refund process and cite sources."}
    ]
  }'
```

Expected response:

```json
{
  "status": "allowed",
  "policy_id": "default-enterprise-policy",
  "model": "mock",
  "violations": [],
  "response": {
    "answer": "Mock response generated for...",
    "citations": ["internal-policy:default"],
    "confidence": "medium",
    "next_action": "Review the response and connect a real LLM provider when ready."
  }
}
```

## Test PII blocking

```bash
curl -X POST "http://127.0.0.1:8000/v1/guarded-chat"   -H "Content-Type: application/json"   -d '{
    "model": "mock",
    "messages": [
      {"role": "user", "content": "My card is 4111 1111 1111 1111. Can you summarize this?"}
    ]
  }'
```

Expected response status:

```json
"status": "blocked"
```

## Connect a real LLM

1. Uncomment `litellm` in `requirements.txt`
2. Install requirements again
3. Add your API key to `.env`
4. Pass a real model name, for example:

```json
{
  "model": "openai/gpt-4o-mini",
  "messages": [
    {"role": "user", "content": "Return a structured support response."}
  ]
}
```

## Example YAML policy

```yaml
business_rules:
  blocked_topics:
    - medical advice
    - legal advice
  blocked_competitors:
    - CompetitorOne
    - CompetitorTwo

output_guardrails:
  require_json: true
  schema_name: support_answer
  require_citations: true
```

## Production hardening checklist

- Replace regex-only PII checks with Microsoft Presidio or a similar NLP + pattern-based PII engine.
- Add per-tenant policies and policy versioning.
- Store audit logs with redacted input/output only.
- Add role-based policy editing.
- Add moderation provider integration for toxicity and self-harm risk.
- Add semantic topic classifier instead of only keyword-based topic blocking.
- Add OpenTelemetry tracing.
- Add rate limiting and abuse detection.
- Add human-review queue for high-risk blocked attempts.
- Encrypt policy files and logs at rest.
