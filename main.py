import sys
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

Q3_DIR = Path(__file__).resolve().parent / "Q3"
sys.path.insert(0, str(Q3_DIR))

from policy import evaluate_tool_call  # noqa: E402

app = FastAPI(title="GA5 Services")


class ProrationRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: int = Field(ge=0)
    days_in_actual_month: int = Field(ge=1)
    spec: str


class ProrationResponse(BaseModel):
    charge: float


class GuardrailResponse(BaseModel):
    decision: Literal["allow", "block"]
    reason: str


def calculate_charge(
    old_price: float,
    new_price: float,
    days_remaining: int,
    days_in_actual_month: int,
    spec: str,
) -> float:
    price_diff = new_price - old_price

    if spec == "v1":
        return price_diff * (days_remaining / 30)
    if spec == "v2":
        return price_diff * (days_remaining / days_in_actual_month)

    raise ValueError(f"Unsupported spec: {spec}")


def _guardrail_response(payload: dict[str, Any]) -> GuardrailResponse:
    decision, reason = evaluate_tool_call(payload)
    return GuardrailResponse(decision=decision, reason=reason)


def _proration_response(payload: dict[str, Any]) -> ProrationResponse:
    request = ProrationRequest(**payload)
    try:
        charge = calculate_charge(
            request.old_price,
            request.new_price,
            request.days_remaining,
            request.days_in_actual_month,
            request.spec,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ProrationResponse(charge=charge)


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "ga5", "status": "ok"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/")
async def post_root(request: Request) -> GuardrailResponse | ProrationResponse:
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body.") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object.")

    if "tool" in payload:
        return _guardrail_response(payload)
    if "old_price" in payload:
        return _proration_response(payload)

    raise HTTPException(
        status_code=400,
        detail="Unrecognized payload. Expected guardrail or proration fields.",
    )


@app.post("/prorate", response_model=ProrationResponse)
def prorate(request: ProrationRequest) -> ProrationResponse:
    return _proration_response(request.model_dump())


@app.post("/guardrail", response_model=GuardrailResponse)
async def guardrail(request: Request) -> GuardrailResponse:
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body.") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object.")

    return _guardrail_response(payload)
