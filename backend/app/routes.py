"""HTTP routes for health checks, investigations, and forensic reports."""

import hmac
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from fastapi.security import APIKeyHeader

from backend.app import config
from backend.app.database import database_is_ready
from backend.app.schemas import (
    AnalyzeRequest,
    CaseAnalysisResponse,
    CaseDetailResponse,
    CaseResponse,
    EvidenceEventResponse,
    HealthResponse,
    IntegrityVerificationResponse,
    ReadyResponse,
    ReanalyzeRequest,
    ReportResponse,
)
from backend.app.services import analysis_service, case_service, report_service

logger = logging.getLogger("scamshield.api")
router = APIRouter()
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(provided: str | None = Depends(api_key_header)) -> None:
    """Require the configured key. Open access remains the local default."""
    expected = config.SCAMSHIELD_API_KEY
    if not expected:
        return
    if provided is None or not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid X-API-Key header is required.",
        )


def _analysis_message(provider: str) -> str:
    if provider == "mock":
        return "Mock analysis result; no content assessment was performed."
    return "Advisory AI analysis completed; this is not proof of fraud."


def _analysis_http_error(error: analysis_service.AnalysisError) -> HTTPException:
    if isinstance(error, analysis_service.AnalysisConfigurationError):
        code = status.HTTP_503_SERVICE_UNAVAILABLE
    elif isinstance(error, analysis_service.AnalysisTimeoutError):
        code = status.HTTP_504_GATEWAY_TIMEOUT
    elif isinstance(error, analysis_service.AnalysisRateLimitError):
        code = status.HTTP_429_TOO_MANY_REQUESTS
    else:
        code = status.HTTP_502_BAD_GATEWAY
    return HTTPException(status_code=code, detail=str(error))


def _download_filename(case_id: str, report_id: str) -> str:
    """Build a header-safe PDF filename from stored identifiers."""
    def safe(value: str, limit: int) -> str:
        cleaned = "".join(char if char.isalnum() or char in "-_" else "_" for char in value)
        return (cleaned or "report")[:limit]

    return f"scamshield-{safe(case_id, 64)}-{safe(report_id, 8)}.pdf"


def _run_analysis(
    case: dict, *, preserve_completed_on_failure: bool = False
) -> CaseAnalysisResponse:
    """Analyze preserved evidence and translate provider failures to HTTP errors."""
    case_id = case["case_id"]
    try:
        provider, result = analysis_service.analyze_content(
            evidence_type=case["evidence_type"],
            content=case["original_content"],
        )
        if preserve_completed_on_failure:
            case_service.record_analysis_replacement(case)
        analyzed_case = case_service.save_analysis(case_id, provider, result)
        if analyzed_case is None:
            raise RuntimeError("The investigation could not be updated.")
    except analysis_service.AnalysisError as error:
        provider = config.AI_PROVIDER.strip().lower() or "unconfigured"
        case_service.mark_analysis_failed(
            case_id,
            provider,
            str(error),
            preserve_completed=preserve_completed_on_failure,
        )
        message = str(error)
        if preserve_completed_on_failure:
            message = f"{message} The previous completed analysis was kept."
        http_error = _analysis_http_error(error)
        http_error.detail = {"message": message, "case_id": case_id}
        logger.info(
            "Analysis failed case_id=%s provider=%s status=%s",
            case_id,
            provider,
            http_error.status_code,
        )
        raise http_error from error

    logger.info("Analysis completed case_id=%s provider=%s", case_id, provider)
    return CaseAnalysisResponse(**analyzed_case, message=_analysis_message(provider))


def _report_response(record: dict) -> ReportResponse:
    return ReportResponse(
        report_id=record["report_id"],
        case_id=record["case_id"],
        content_sha256=record["content_sha256"],
        generated_at=record["generated_at"],
        download_path=(
            f"/api/v1/cases/{record['case_id']}/reports/{record['report_id']}"
        ),
    )


@router.get("/health", response_model=HealthResponse, tags=["health"])
def health_check() -> HealthResponse:
    """Report that the API process is available."""
    return HealthResponse(status="ok")


@router.get("/health/ready", response_model=ReadyResponse, tags=["health"])
def readiness_check() -> ReadyResponse:
    """Report whether the API can read and write its database."""
    if not database_is_ready():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is unavailable.",
        )
    return ReadyResponse(status="ok", database="ok")


@router.post(
    "/api/v1/analyze",
    response_model=CaseAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["cases"],
    dependencies=[Depends(require_api_key)],
)
def create_investigation(request: AnalyzeRequest) -> CaseAnalysisResponse:
    """Preserve submitted evidence and analyze it with the configured provider."""
    case = case_service.create_case(
        evidence_type=request.evidence_type.value,
        original_content=request.content,
    )
    return _run_analysis(case)


@router.post(
    "/api/v1/cases/{case_id}/analyze",
    response_model=CaseAnalysisResponse,
    tags=["cases"],
    dependencies=[Depends(require_api_key)],
)
def reanalyze_investigation(
    case_id: str, request: ReanalyzeRequest
) -> CaseAnalysisResponse:
    """Run analysis again. Completed results are kept unless replacement is requested."""
    case = case_service.get_case(case_id)
    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found.",
        )
    if case["analysis_status"] == "ANALYSIS_COMPLETED" and not request.replace_completed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Analysis has already been completed for this case. Preserve "
                "different content as a new investigation, or request replacement "
                "of the completed advisory result."
            ),
        )
    replacing_completed = case["analysis_status"] == "ANALYSIS_COMPLETED"
    return _run_analysis(
        case, preserve_completed_on_failure=replacing_completed
    )


@router.get(
    "/api/v1/cases",
    response_model=list[CaseResponse],
    tags=["cases"],
    dependencies=[Depends(require_api_key)],
)
def list_investigations(
    limit: int | None = Query(default=None, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[CaseResponse]:
    """Return stored investigation records, newest first."""
    return [
        CaseResponse(**case)
        for case in case_service.get_all_cases(limit=limit, offset=offset)
    ]


@router.get(
    "/api/v1/cases/{case_id}",
    response_model=CaseDetailResponse,
    tags=["cases"],
    dependencies=[Depends(require_api_key)],
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
    dependencies=[Depends(require_api_key)],
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
    dependencies=[Depends(require_api_key)],
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


@router.post(
    "/api/v1/cases/{case_id}/reports",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["reports"],
    dependencies=[Depends(require_api_key)],
)
def create_case_report(case_id: str) -> ReportResponse:
    """Verify the case, render an advisory PDF, and store its digest."""
    record = report_service.generate_case_report(case_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found.",
        )
    logger.info("Report generated case_id=%s report_id=%s", case_id, record["report_id"])
    return _report_response(record)


@router.get(
    "/api/v1/cases/{case_id}/reports",
    response_model=list[ReportResponse],
    tags=["reports"],
    dependencies=[Depends(require_api_key)],
)
def list_case_reports(case_id: str) -> list[ReportResponse]:
    """Return report metadata for a case, newest first."""
    records = case_service.list_reports(case_id)
    if records is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found.",
        )
    return [_report_response(record) for record in records]


@router.get(
    "/api/v1/cases/{case_id}/reports/{report_id}",
    tags=["reports"],
    dependencies=[Depends(require_api_key)],
)
def download_case_report(case_id: str, report_id: str) -> FileResponse:
    """Download one stored PDF report."""
    record = case_service.get_report(case_id, report_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found.",
        )
    path = report_service.resolve_report_path(record["filename"])
    if path is None or not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file is missing from storage.",
        )
    return FileResponse(
        path,
        media_type="application/pdf",
        filename=_download_filename(case_id, report_id),
    )
