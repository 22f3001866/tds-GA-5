from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from scanner import scan_skill

app = FastAPI(title="Skill Safety Scanner")


class ScanResponse(BaseModel):
    categories: list[str]


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "skill-scanner", "status": "ok"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/", response_model=ScanResponse)
@app.post("/scan", response_model=ScanResponse)
async def scan(request: Request) -> ScanResponse:
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body.") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object.")

    skill = payload.get("skill")
    if not isinstance(skill, str):
        raise HTTPException(status_code=400, detail="Field 'skill' must be a string.")

    return ScanResponse(categories=scan_skill(skill))
