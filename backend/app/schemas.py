from typing import Literal

from pydantic import BaseModel, Field


class SiteRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2_048)


class InformationRequest(BaseModel):
    text: str = Field(min_length=4, max_length=1_500)


class PasswordRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class GeneratePasswordRequest(BaseModel):
    strength: Literal["fraca", "media", "forte"]
    theme: str = Field(default="", max_length=40)
    length: int = Field(default=16, ge=8, le=64)


class CalculatorRequest(BaseModel):
    expression: str = Field(min_length=1, max_length=120)


class AnalysisResponse(BaseModel):
    score: int = Field(ge=0, le=100)
    status: str
    level: Literal["safe", "warning", "danger", "neutral"]
    summary: str
    reasons: list[str]
    disclaimer: str
    normalized_input: str | None = None
    sources: list[dict[str, str]] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"] = "low"
    methods: list[str] = Field(default_factory=list)
    checked_at: int | None = None
    score_display: str | None = Field(default=None, max_length=40)
    metric_label: str = Field(default="RESULTADO", max_length=40)


class GeneratedPasswordResponse(BaseModel):
    password: str
    warning: str
    tips: list[str] = Field(default_factory=list)


class CalculatorResponse(BaseModel):
    expression: str
    normalized_expression: str
    result: float
    display: str
    fraction: str | None = None
