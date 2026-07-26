from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from policy import handle_request
from setup_files import setup_files


@asynccontextmanager
async def lifespan(_app: FastAPI):
    setup_files()
    yield


app = FastAPI(title="Red-Team Guardrail", lifespan=lifespan)


class GuardrailResponse(BaseModel):
    action: str
    reason: str
    result: Any | None = None


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "redteam-guardrail", "status": "ok"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/", response_model=GuardrailResponse)
@app.post("/guardrail", response_model=GuardrailResponse)
async def guardrail(request: Request) -> GuardrailResponse:
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body.") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object.")

    response = await handle_request(payload)
    return GuardrailResponse(**response)
