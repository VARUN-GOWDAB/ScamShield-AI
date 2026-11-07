"""Pydantic request and response models for the API."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EvidenceType(str, Enum):
    EMAIL = "EMAIL"
    SMS = "SMS"
    ADVERTISEMENT = "ADVERTISEMENT"


class AnalyzeRequest(BaseModel):
    evidence_type: EvidenceType
    content: str = Field(..., min_length=1, max_length=20_000)

    @field_validator("content")
    def content_must_not_be_whitespace(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Content must not be empty or whitespace-only.")
        return value


class RiskLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INCONCLUSIVE = "INCONCLUSIVE"


class AnalysisIndicator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_quote: str
    explanation: str

    @field_validator("evidence_quote", "explanation")
    @classmethod
    def values_must_not_be_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Indicator fields must not be empty.")
        return value


class ScamAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_level: RiskLevel
    scam_type: str
    summary: str
    indicators: list[AnalysisIndicator]
    recommended_actions: list[str]
    limitations: list[str]

    @field_validator("scam_type", "summary")
    @classmethod
    def text_fields_must_not_be_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Analysis text fields must not be empty.")
        return value

    @field_validator("recommended_actions", "limitations")
    @classmethod
    def lists_must_contain_non_empty_text(cls, value: list[str]) -> list[str]:
        if not value or any(not item.strip() for item in value):
            raise ValueError("Provide non-empty actions and limitations.")
        return value


class CaseResponse(BaseModel):
    case_id: str
    evidence_type: EvidenceType
    analysis_status: str
    created_at: datetime
    evidence_sha256: str | None = None
    evidence_collected_at: datetime | None = None
    analysis_provider: str | None = None
    risk_level: RiskLevel | None = None
    scam_type: str | None = None
    summary: str | None = None
    indicators: list[AnalysisIndicator] | None = None
    recommended_actions: list[str] | None = None
    limitations: list[str] | None = None


class CaseDetailResponse(CaseResponse):
    original_content: str


class AnalyzeResponse(CaseResponse):
    message: str


class CaseAnalysisResponse(CaseResponse):
    message: str


class HealthResponse(BaseModel):
    status: str


class IntegrityVerificationResponse(BaseModel):
    case_id: str
    integrity_status: str
    original_sha256: str | None = None
    calculated_sha256: str | None = None
    evidence_collected_at: datetime | None = None
    verified_at: datetime
    message: str


class EvidenceEventResponse(BaseModel):
    event_id: str
    event_type: str
    event_timestamp: datetime
    details: str
