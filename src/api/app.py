from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

from api.database import init_db, get_predictions, get_stats, update_label

app = FastAPI(title="Attack Detection Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()


class LabelUpdate(BaseModel):
    label: str  # "Normal" | "Attack"


@app.get("/api/stats")
def stats(
    date_from: Optional[str] = Query(None, description="YYYY-MM-DD"),
    date_to:   Optional[str] = Query(None, description="YYYY-MM-DD"),
):
    return get_stats(date_from, date_to)


@app.get("/api/predictions")
def predictions(
    date_from: Optional[str] = Query(None),
    date_to:   Optional[str] = Query(None),
    page:      int            = Query(1, ge=1),
    page_size: int            = Query(50, ge=1, le=200),
):
    return get_predictions(date_from, date_to, page, page_size)


@app.patch("/api/predictions/{prediction_id}/label")
def label_prediction(prediction_id: int, body: LabelUpdate):
    if body.label not in ("Normal", "Attack"):
        raise HTTPException(status_code=400, detail="label must be 'Normal' or 'Attack'")
    update_label(prediction_id, body.label)
    return {"ok": True, "id": prediction_id, "label": body.label}


@app.get("/healthz")
def health():
    return {"status": "ok"}