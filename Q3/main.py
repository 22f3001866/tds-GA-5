from typing import Any, Literal

from fastapi import FastAPI
from pydantic import BaseModel

from policy import evaluate_tool_call

app = FastAPI(title="Agent Guardrail Hook")


class GuardrailResponse(BaseModel):
    decision: Literal["allow", "block"]
    reason: str


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "guardrail", "status": "ok"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/", response_model=GuardrailResponse)
@app.post("/guardrail", response_model=GuardrailResponse)
def guardrail(payload: dict[str, Any]) -> GuardrailResponse:
    decision, reason = evaluate_tool_call(payload)
    return GuardrailResponse(decision=decision, reason=reason)
