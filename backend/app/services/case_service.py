"""Database operations for investigation cases."""

from typing import Any
from uuid import uuid4

from backend.app.database import get_connection
from backend.app.services.forensic_service import (
    generate_sha256,
    get_utc_timestamp,
    verify_integrity,
)
from backend.app.services.analysis_service import (
    analysis_from_storage,
    analysis_to_storage,
)

ANALYSIS_PENDING = "PENDING_AI_ANALYSIS"


def create_case(evidence_type: str, original_content: str) -> dict[str, Any]:
    """Create a pending investigation record and return its stored fields."""
    case = {
        "case_id": str(uuid4()),
        "evidence_type": evidence_type,
        "original_content": original_content,
        "analysis_status": ANALYSIS_PENDING,
        "risk_level": None,
        "scam_type": None,
        "summary": None,
        "indicators": None,
        "recommended_actions": None,
        "limitations": None,
        "analysis_provider": None,
        "created_at": get_utc_timestamp(),
        "evidence_sha256": generate_sha256(original_content),
        "evidence_collected_at": get_utc_timestamp(),
    }

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO cases (
                case_id, evidence_type, original_content, analysis_status,
                risk_level, scam_type, summary, created_at,
                evidence_sha256, evidence_collected_at, indicators,
                recommended_actions, limitations, analysis_provider
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case["case_id"],
                case["evidence_type"],
                case["original_content"],
                case["analysis_status"],
                case["risk_level"],
                case["scam_type"],
                case["summary"],
                case["created_at"],
                case["evidence_sha256"],
                case["evidence_collected_at"],
                case["indicators"],
                case["recommended_actions"],
                case["limitations"],
                case["analysis_provider"],
            ),
        )
        connection.execute(
            """
            INSERT INTO evidence_events (
                event_id, case_id, event_type, event_timestamp, details
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                case["case_id"],
                "EVIDENCE_COLLECTED",
                case["evidence_collected_at"],
                "Original submitted content was recorded with its SHA-256 baseline.",
            ),
        )
    return case


def get_all_cases(
    limit: int | None = None, offset: int = 0
) -> list[dict[str, Any]]:
    """Return cases, newest first. Omit limit to return the full list."""
    query = """
        SELECT case_id, evidence_type, analysis_status,
               risk_level, scam_type, summary, created_at,
               evidence_sha256, evidence_collected_at, indicators,
               recommended_actions, limitations, analysis_provider
        FROM cases
        ORDER BY created_at DESC, case_id DESC
    """
    parameters: list[Any] = []
    if limit is not None:
        query += " LIMIT ? OFFSET ?"
        parameters.extend([limit, offset])
    elif offset:
        query += " LIMIT -1 OFFSET ?"
        parameters.append(offset)

    with get_connection() as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [analysis_from_storage(dict(row)) for row in rows]


def get_case(case_id: str) -> dict[str, Any] | None:
    """Return a case by its unique identifier, or None if it does not exist."""
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT case_id, evidence_type, original_content, analysis_status,
                   risk_level, scam_type, summary, created_at,
                   evidence_sha256, evidence_collected_at, indicators,
                   recommended_actions, limitations, analysis_provider
            FROM cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()
    return analysis_from_storage(dict(row)) if row is not None else None


def save_analysis(
    case_id: str, provider: str, result: Any
) -> dict[str, Any] | None:
    """Persist validated provider results and a completion event atomically."""
    stored_result = analysis_to_storage(result)
    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE cases
            SET risk_level = ?, scam_type = ?, summary = ?, indicators = ?,
                recommended_actions = ?, limitations = ?, analysis_provider = ?,
                analysis_status = ?
            WHERE case_id = ?
            """,
            (
                stored_result["risk_level"],
                stored_result["scam_type"],
                stored_result["summary"],
                stored_result["indicators"],
                stored_result["recommended_actions"],
                stored_result["limitations"],
                provider,
                "ANALYSIS_COMPLETED",
                case_id,
            ),
        )
        if cursor.rowcount == 0:
            return None
        connection.execute(
            """
            INSERT INTO evidence_events (
                event_id, case_id, event_type, event_timestamp, details
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                case_id,
                "AI_ANALYSIS_COMPLETED",
                get_utc_timestamp(),
                f"Analysis completed using the {provider} provider.",
            ),
        )
    return get_case(case_id)


def mark_analysis_failed(
    case_id: str,
    provider: str,
    details: str,
    *,
    preserve_completed: bool = False,
) -> None:
    """Record an analysis failure without changing the preserved evidence.

    A failed replacement keeps the previous completed advisory result.
    """
    with get_connection() as connection:
        if not preserve_completed:
            connection.execute(
                """
                UPDATE cases
                SET analysis_status = ?, analysis_provider = ?, risk_level = NULL,
                    scam_type = NULL, summary = NULL, indicators = NULL,
                    recommended_actions = NULL, limitations = NULL
                WHERE case_id = ?
                """,
                ("ANALYSIS_FAILED", provider, case_id),
            )
        connection.execute(
            """
            INSERT INTO evidence_events (
                event_id, case_id, event_type, event_timestamp, details
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                case_id,
                "AI_ANALYSIS_FAILED",
                get_utc_timestamp(),
                details,
            ),
        )


def verify_case(case_id: str) -> dict[str, Any] | None:
    """Verify a case's evidence and record the attempt atomically."""
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT case_id, original_content, evidence_sha256,
                   evidence_collected_at
            FROM cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()
        if row is None:
            return None

        verified_at = get_utc_timestamp()
        if row["evidence_sha256"] is None:
            integrity_status = "UNAVAILABLE"
            original_sha256 = None
            calculated_sha256 = None
            event_type = "INTEGRITY_UNAVAILABLE"
            message = (
                "Integrity verification is unavailable because this legacy case "
                "has no recorded SHA-256 baseline."
            )
            details = message
        else:
            matches, calculated_sha256 = verify_integrity(
                row["original_content"], row["evidence_sha256"]
            )
            integrity_status = "VERIFIED" if matches else "FAILED"
            original_sha256 = row["evidence_sha256"]
            event_type = f"INTEGRITY_{integrity_status}"
            message = (
                "Stored evidence matches its recorded SHA-256 baseline."
                if matches
                else "Stored evidence does not match its recorded SHA-256 baseline."
            )
            details = (
                f"{message} Calculated SHA-256: {calculated_sha256}."
            )

        connection.execute(
            """
            INSERT INTO evidence_events (
                event_id, case_id, event_type, event_timestamp, details
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (str(uuid4()), case_id, event_type, verified_at, details),
        )

    return {
        "case_id": case_id,
        "integrity_status": integrity_status,
        "original_sha256": original_sha256,
        "calculated_sha256": calculated_sha256,
        "evidence_collected_at": row["evidence_collected_at"],
        "verified_at": verified_at,
        "message": message,
    }


def get_case_events(case_id: str) -> list[dict[str, Any]] | None:
    """Return a case's event history in chronological order, or None if absent."""
    with get_connection() as connection:
        case = connection.execute(
            "SELECT 1 FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if case is None:
            return None

        rows = connection.execute(
            """
            SELECT event_id, event_type, event_timestamp, details
            FROM evidence_events
            WHERE case_id = ?
            ORDER BY event_timestamp ASC, rowid ASC
            """,
            (case_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def record_analysis_replacement(case: dict[str, Any]) -> None:
    """Record that a completed advisory result is about to be replaced."""
    summary = case.get("summary") or "No summary was stored."
    details = (
        "Completed analysis was replaced by a new provider run. "
        f"Prior provider: {case.get('analysis_provider') or 'not recorded'}. "
        f"Prior risk level: {case.get('risk_level') or 'not recorded'}. "
        f"Prior summary: {summary}"
    )
    if len(details) > 2000:
        details = details[:1999] + "…"
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO evidence_events (
                event_id, case_id, event_type, event_timestamp, details
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                case["case_id"],
                "ANALYSIS_REPLACED",
                get_utc_timestamp(),
                details,
            ),
        )


def record_report(
    report_id: str,
    case_id: str,
    filename: str,
    content_sha256: str,
    generated_at: str,
) -> dict[str, Any] | None:
    """Store report metadata and a generation event. Return None if the case is gone."""
    with get_connection() as connection:
        case = connection.execute(
            "SELECT 1 FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if case is None:
            return None
        connection.execute(
            """
            INSERT INTO reports (
                report_id, case_id, filename, content_sha256, generated_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (report_id, case_id, filename, content_sha256, generated_at),
        )
        connection.execute(
            """
            INSERT INTO evidence_events (
                event_id, case_id, event_type, event_timestamp, details
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                case_id,
                "REPORT_GENERATED",
                generated_at,
                f"PDF report {report_id} generated. SHA-256: {content_sha256}.",
            ),
        )
    return {
        "report_id": report_id,
        "case_id": case_id,
        "filename": filename,
        "content_sha256": content_sha256,
        "generated_at": generated_at,
    }


def list_reports(case_id: str) -> list[dict[str, Any]] | None:
    """Return reports for a case, newest first, or None when the case does not exist."""
    with get_connection() as connection:
        case = connection.execute(
            "SELECT 1 FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if case is None:
            return None
        rows = connection.execute(
            """
            SELECT report_id, case_id, filename, content_sha256, generated_at
            FROM reports
            WHERE case_id = ?
            ORDER BY generated_at DESC, report_id DESC
            """,
            (case_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_report(case_id: str, report_id: str) -> dict[str, Any] | None:
    """Return one stored report, or None when it does not belong to the case."""
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT report_id, case_id, filename, content_sha256, generated_at
            FROM reports
            WHERE case_id = ? AND report_id = ?
            """,
            (case_id, report_id),
        ).fetchone()
    return dict(row) if row is not None else None
