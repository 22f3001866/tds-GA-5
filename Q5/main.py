from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from policy import evaluate_run_control

app = FastAPI(title="Run Budget and Loop Guard")


class RunControlResponse(BaseModel):
    decision: Literal["continue", "halt"]
    reason: str


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "run-guard", "status": "ok"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/", response_model=RunControlResponse)
@app.post("/run-guard", response_model=RunControlResponse)
async def run_guard(request: Request) -> RunControlResponse:
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body.") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object.")

    decision, reason = evaluate_run_control(payload)
    return RunControlResponse(decision=decision, reason=reason)
