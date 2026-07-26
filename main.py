import importlib.util
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

ROOT_DIR = Path(__file__).resolve().parent
Q3_DIR = ROOT_DIR / "Q3"
Q4_DIR = ROOT_DIR / "Q4"
Q5_DIR = ROOT_DIR / "Q5"


def _load_symbol(module_path: Path, module_name: str, symbol: str) -> Any:
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, symbol)


evaluate_tool_call = _load_symbol(Q3_DIR / "policy.py", "q3_policy", "evaluate_tool_call")
scan_skill = _load_symbol(Q4_DIR / "scanner.py", "q4_scanner", "scan_skill")
evaluate_run_control = _load_symbol(Q5_DIR / "policy.py", "q5_policy", "evaluate_run_control")

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


class ScanResponse(BaseModel):
    categories: list[str]


class RunControlResponse(BaseModel):
    decision: Literal["continue", "halt"]
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


def _scan_response(payload: dict[str, Any]) -> ScanResponse:
    skill = payload.get("skill", "")
    if not isinstance(skill, str):
        raise HTTPException(status_code=400, detail="Field 'skill' must be a string.")
    return ScanResponse(categories=scan_skill(skill))


def _run_guard_response(payload: dict[str, Any]) -> RunControlResponse:
    decision, reason = evaluate_run_control(payload)
    return RunControlResponse(decision=decision, reason=reason)


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
async def post_root(
    request: Request,
) -> GuardrailResponse | ProrationResponse | ScanResponse | RunControlResponse:
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body.") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object.")

    if "budget_tokens" in payload and "steps" in payload:
        return _run_guard_response(payload)
    if "skill" in payload:
        return _scan_response(payload)
    if "tool" in payload:
        return _guardrail_response(payload)
    if "old_price" in payload:
        return _proration_response(payload)

    raise HTTPException(
        status_code=400,
        detail="Unrecognized payload. Expected run guard, skill, guardrail, or proration fields.",
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


@app.post("/scan", response_model=ScanResponse)
async def scan(request: Request) -> ScanResponse:
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body.") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object.")

    return _scan_response(payload)


@app.post("/run-guard", response_model=RunControlResponse)
async def run_guard(request: Request) -> RunControlResponse:
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body.") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object.")

    return _run_guard_response(payload)
