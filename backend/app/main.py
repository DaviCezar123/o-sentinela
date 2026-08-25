import os
import time
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from dotenv import load_dotenv

from .analysis import analyze_information, analyze_password, analyze_site, calculate_expression, generate_password
from .intelligence import capabilities, enrich_information, enrich_password, enrich_site
from .schemas import (
    AnalysisResponse,
    CalculatorRequest,
    CalculatorResponse,
    GeneratePasswordRequest,
    GeneratedPasswordResponse,
    InformationRequest,
    PasswordRequest,
    SiteRequest,
)

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def _rate_limit_from_environment() -> int:
    try:
        return max(10, int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")))
    except ValueError:
        return 60


class ApiRateLimitMiddleware(BaseHTTPMiddleware):
    """Limite simples por IP para proteger o servidor e as cotas das fontes externas."""

    def __init__(self, app, limit_per_minute: int) -> None:
        super().__init__(app)
        self.limit_per_minute = max(10, limit_per_minute)
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    async def dispatch(self, request: Request, call_next):
        if request.method != "POST" or not request.url.path.startswith("/api/"):
            return await call_next(request)
        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        with self._lock:
            events = self._events[client]
            while events and events[0] <= now - 60:
                events.popleft()
            if len(events) >= self.limit_per_minute:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Muitas análises em pouco tempo. Aguarde um minuto e tente novamente."},
                )
            events.append(now)
        return await call_next(request)


app = FastAPI(
    title="O Sentinela API",
    version="1.2.0",
    description="API educativa de triagem para URLs, informações e senhas. Não substitui fontes especializadas.",
)

origins = [origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["POST", "GET"], allow_headers=["Content-Type"])
app.add_middleware(ApiRateLimitMiddleware, limit_per_minute=_rate_limit_from_environment())


@app.get("/health", tags=["sistema"])
def health() -> dict[str, str]:
    return {"status": "ok", "version": app.version}


@app.get("/api/intelligence/status", tags=["sistema"])
def intelligence_status() -> dict[str, object]:
    return {
        "online_features": capabilities(),
        "message": "Recursos online só são usados quando configurados no servidor; chaves nunca são enviadas ao navegador.",
    }


@app.post("/api/site/analyze", response_model=AnalysisResponse)
def site(request: SiteRequest):
    return enrich_site(analyze_site(request.url), request.url)


@app.post("/api/information/analyze", response_model=AnalysisResponse)
def information(request: InformationRequest):
    return enrich_information(analyze_information(request.text), request.text)


@app.post("/api/password/analyze", response_model=AnalysisResponse)
def password(request: PasswordRequest):
    return enrich_password(analyze_password(request.password), request.password)


@app.post("/api/password/generate", response_model=GeneratedPasswordResponse)
def password_generator(request: GeneratePasswordRequest):
    return generate_password(request.strength, request.theme, request.length)


@app.post("/api/calculator/evaluate", response_model=CalculatorResponse)
def calculator(request: CalculatorRequest):
    try:
        return calculate_expression(request.expression)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=f"Não foi possível calcular: {error}") from error
