"""HTTP routes for health checks and investigation cases."""

from fastapi import APIRouter, HTTPException, status

from backend.app import config
from backend.app.schemas import (
    AnalyzeRequest,
    CaseDetailResponse,
    CaseAnalysisResponse,
    CaseResponse,
    EvidenceEventResponse,
    HealthResponse,
    IntegrityVerificationResponse,
)
from backend.app.services import analysis_service
from backend.app.services import case_service

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["health"])
def health_check() -> HealthResponse:
    """Report that the API process is available."""
    return HealthResponse(status="ok")


@router.post(
    "/api/v1/analyze",
    response_model=CaseAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["cases"],
)
def create_investigation(request: AnalyzeRequest) -> CaseAnalysisResponse:
    """Preserve submitted evidence and analyze it with the configured provider."""
    case = case_service.create_case(
        evidence_type=request.evidence_type.value,
        original_content=request.content,
    )
    try:
        provider, result = analysis_service.analyze_content(
            evidence_type=request.evidence_type.value,
            content=request.content,
        )
        analyzed_case = case_service.save_analysis(case["case_id"], provider, result)
        if analyzed_case is None:
            raise RuntimeError("The newly created investigation could not be updated.")
    except analysis_service.AnalysisError as error:
        provider = config.AI_PROVIDER.strip().lower()
        case_service.mark_analysis_failed(case["case_id"], provider, str(error))
        if isinstance(error, analysis_service.AnalysisConfigurationError):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(error),
            ) from error
        if isinstance(error, analysis_service.AnalysisTimeoutError):
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail=str(error),
            ) from error
        if isinstance(error, analysis_service.AnalysisRateLimitError):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=str(error),
            ) from error
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(error),
        ) from error

    return CaseAnalysisResponse(
        **analyzed_case,
        message=(
            "Mock analysis result; no content assessment was performed."
            if provider == "mock"
            else "Advisory AI analysis completed; this is not proof of fraud."
        ),
    )


@router.get("/api/v1/cases", response_model=list[CaseResponse], tags=["cases"])
def list_investigations() -> list[CaseResponse]:
    """Return all stored investigation records."""
    return [CaseResponse(**case) for case in case_service.get_all_cases()]


@router.get(
    "/api/v1/cases/{case_id}",
    response_model=CaseDetailResponse,
    tags=["cases"],
)
def get_investigation(case_id: str) -> CaseDetailResponse:
    """Return the full details for one investigation record."""
    case = case_service.get_case(case_id)
    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found.",
        )
    return CaseDetailResponse(**case)


@router.post(
    "/api/v1/cases/{case_id}/verify-integrity",
    response_model=IntegrityVerificationResponse,
    tags=["forensics"],
)
def verify_case_integrity(case_id: str) -> IntegrityVerificationResponse:
    """Compare stored evidence with its originally recorded SHA-256 baseline."""
    result = case_service.verify_case(case_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found.",
        )
    return IntegrityVerificationResponse(**result)


@router.get(
    "/api/v1/cases/{case_id}/events",
    response_model=list[EvidenceEventResponse],
    tags=["forensics"],
)
def get_case_event_history(case_id: str) -> list[EvidenceEventResponse]:
    """Return all forensic events for a case in chronological order."""
    events = case_service.get_case_events(case_id)
    if events is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found.",
        )
    return [EvidenceEventResponse(**event) for event in events]
