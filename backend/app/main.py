import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import database as db
from .config import settings
from .services.pipeline import analyze_payload
from .services.qr_decoder import QRDecodeError, decode_qr


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="QRShield API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=list(settings.allowed_origins),
                   allow_methods=["GET", "POST"], allow_headers=["*"])

_hits: dict[str, deque] = defaultdict(deque)


def rate_limit(request: Request):
    ip = request.client.host if request.client else "unknown"
    now, q = time.time(), _hits[ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= settings.rate_limit_per_min:
        raise HTTPException(429, "Too many checks. Wait a minute and try again.")
    q.append(now)


class UrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class FeedbackRequest(BaseModel):
    helpful: bool


def _run(payload: str, source: str, extra: dict | None = None) -> dict:
    try:
        report = analyze_payload(payload)
    except ValueError as e:
        raise HTTPException(400, str(e))
    report["id"] = db.save_scan(source, report)
    report.update(extra or {})
    return report


@app.get("/api/health")
def health():
    return {"status": "ok", "network_checks": settings.enable_network,
            "feeds": {"google_safe_browsing": bool(settings.gsb_api_key),
                      "virustotal": bool(settings.vt_api_key), "urlhaus": bool(settings.urlhaus_key)}}


@app.post("/api/analyze/url", dependencies=[Depends(rate_limit)])
def analyze_url_endpoint(body: UrlRequest):
    return _run(body.url, "paste")


@app.post("/api/analyze/image", dependencies=[Depends(rate_limit)])
def analyze_image_endpoint(file: UploadFile = File(...)):
    data = file.file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(413, "Image is larger than 5 MB.")
    try:
        codes = decode_qr(data)
    except QRDecodeError as e:
        raise HTTPException(422, str(e))
    return _run(codes[0], "image", {"codes_found": len(codes), "other_codes": codes[1:4]})


@app.get("/api/history")
def history(limit: int = 20):
    return db.list_scans(max(1, min(limit, 100)))


@app.get("/api/scans/{scan_id}")
def scan(scan_id: int):
    report = db.get_scan(scan_id)
    if not report:
        raise HTTPException(404, "Scan not found.")
    return report


@app.post("/api/scans/{scan_id}/feedback")
def feedback(scan_id: int, body: FeedbackRequest):
    if not db.set_feedback(scan_id, body.helpful):
        raise HTTPException(404, "Scan not found.")
    return {"ok": True}


@app.get("/api/stats")
def stats():
    return db.stats()
