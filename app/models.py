from typing import Any, Literal, Optional
from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1)


class GuardedChatRequest(BaseModel):
    model: str = Field(default="mock", description="LLM model name. Use 'mock' for local testing.")
    messages: list[ChatMessage]
    policy_id: str = "default"
    schema_name: Optional[str] = None
    temperature: float = 0
    max_retries: Optional[int] = None


class GuardrailViolation(BaseModel):
    stage: Literal["input", "output", "policy", "schema"]
    code: str
    message: str
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    evidence: Optional[str] = None


class GuardedChatResponse(BaseModel):
    status: Literal["allowed", "blocked", "fallback"]
    policy_id: str
    model: str
    violations: list[GuardrailViolation] = []
    response: Optional[Any] = None
    raw_response: Optional[str] = None
    attempts: int = 0
