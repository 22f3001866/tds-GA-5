from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI()


class ProrationRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: int = Field(ge=0)
    days_in_actual_month: int = Field(ge=1)
    spec: str


class ProrationResponse(BaseModel):
    charge: float


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


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "proration", "status": "ok"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/", response_model=ProrationResponse)
@app.post("/prorate", response_model=ProrationResponse)
def prorate(request: ProrationRequest) -> ProrationResponse:
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
