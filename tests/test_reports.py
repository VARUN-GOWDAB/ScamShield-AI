"""PDF report generation and download tests."""

import hashlib
import io
import sqlite3

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

from backend.app import config
from backend.app.main import app
from backend.app.services.report_service import (
    build_report_document,
    document_plaintext,
    ensure_fonts,
    resolve_report_path,
)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", tmp_path / "reports.sqlite3")
    monkeypatch.setattr(config, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(config, "AI_PROVIDER", "mock")
    monkeypatch.setattr(config, "SCAMSHIELD_API_KEY", "")
    with TestClient(app) as test_client:
        yield test_client


def _reader_text(pdf_bytes: bytes) -> str:
    reader = PdfReader(io.BytesIO(pdf_bytes))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def test_report_document_preserves_exact_evidence_and_states_limits():
    content = "Exact text \n with  double spaces."
    _, mono = ensure_fonts()
    document = build_report_document(
        {
            "case_id": "case-1",
            "evidence_type": "EMAIL",
            "analysis_status": "ANALYSIS_COMPLETED",
            "analysis_provider": "mock",
            "created_at": "2026-11-07T00:00:00+00:00",
            "evidence_collected_at": "2026-11-07T00:00:00+00:00",
            "evidence_sha256": "abc123",
            "original_content": content,
            "risk_level": "INCONCLUSIVE",
            "scam_type": "Not assessed by mock provider",
            "summary": "Mock provider is enabled.",
            "indicators": [],
            "recommended_actions": ["Review the content manually before taking action."],
            "limitations": ["This is a mock result and does not analyze the submitted content."],
        },
        [],
        {
            "integrity_status": "VERIFIED",
            "message": "Stored evidence matches its recorded SHA-256 baseline.",
            "original_sha256": "abc123",
            "calculated_sha256": "abc123",
            "verified_at": "2026-11-07T00:00:01+00:00",
        },
        "2026-11-07T00:00:02+00:00",
        mono,
    )
    text = document_plaintext(document)

    assert document.evidence_text == content
    assert "Exact text" in document.evidence_display
    assert "does not prove" in text
    assert "certified chain of custody" in text
    assert "abc123" in text
    assert "mock provider did not assess" in text
    assert "2026-11-07T00:00:02+00:00" in text


def test_report_document_marks_characters_the_font_cannot_draw():
    _, mono = ensure_fonts()
    document = build_report_document(
        {
            "case_id": "unicode-case",
            "evidence_type": "SMS",
            "analysis_status": "ANALYSIS_FAILED",
            "analysis_provider": None,
            "created_at": "2026-11-07T00:00:00+00:00",
            "evidence_collected_at": "2026-11-07T00:00:00+00:00",
            "evidence_sha256": "hash",
            "original_content": "Prüfung 🌍",
            "risk_level": None,
            "scam_type": None,
            "summary": None,
            "indicators": None,
            "recommended_actions": None,
            "limitations": None,
        },
        [],
        {
            "integrity_status": "VERIFIED",
            "message": "Stored evidence matches its recorded SHA-256 baseline.",
            "original_sha256": "hash",
            "calculated_sha256": "hash",
            "verified_at": "2026-11-07T00:00:01+00:00",
        },
        "2026-11-07T00:00:02+00:00",
        mono,
    )

    assert document.evidence_text == "Prüfung 🌍"
    assert "Prüfung" in document.evidence_display
    assert "[U+1F30D]" in document.evidence_display
    assert "No advisory analysis is stored" in document_plaintext(document)


def test_long_lines_are_wrapped_for_display_only():
    _, mono = ensure_fonts()
    content = "A" * 150
    document = build_report_document(
        {
            "case_id": "long-case",
            "evidence_type": "SMS",
            "analysis_status": "ANALYSIS_COMPLETED",
            "analysis_provider": "mock",
            "created_at": "2026-11-07T00:00:00+00:00",
            "evidence_collected_at": "2026-11-07T00:00:00+00:00",
            "evidence_sha256": "hash",
            "original_content": content,
            "risk_level": "LOW",
            "scam_type": "Unsolicited offer",
            "summary": "Short summary.",
            "indicators": [],
            "recommended_actions": ["Ignore the offer."],
            "limitations": ["Advisory only."],
        },
        [],
        {
            "integrity_status": "VERIFIED",
            "message": "ok",
            "original_sha256": "hash",
            "calculated_sha256": "hash",
            "verified_at": "2026-11-07T00:00:01+00:00",
        },
        "2026-11-07T00:00:02+00:00",
        mono,
    )

    assert document.evidence_text == content
    assert "\n" in document.evidence_display
    assert document.evidence_display.replace("\n", "") == content
    assert "wrapped for display" in document_plaintext(document)


def test_generate_report_stores_digest_and_downloadable_pdf(client):
    content = "Please review this suspicious message.\nDo not click http://phish.example."
    created = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "EMAIL", "content": content},
    )
    case_id = created.json()["case_id"]

    response = client.post(f"/api/v1/cases/{case_id}/reports")

    assert response.status_code == 201
    report = response.json()
    assert report["case_id"] == case_id
    assert report["download_path"] == f"/api/v1/cases/{case_id}/reports/{report['report_id']}"
    download = client.get(report["download_path"])
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("application/pdf")
    assert download.content.startswith(b"%PDF")
    assert hashlib.sha256(download.content).hexdigest() == report["content_sha256"]
    text = _reader_text(download.content)
    assert case_id in text
    assert "does not prove" in text
    assert "Advisory" in text

    events = client.get(f"/api/v1/cases/{case_id}/events").json()
    assert [event["event_type"] for event in events] == [
        "EVIDENCE_COLLECTED",
        "AI_ANALYSIS_COMPLETED",
        "INTEGRITY_VERIFIED",
        "REPORT_GENERATED",
    ]
    assert report["content_sha256"] in events[-1]["details"]
    stored = client.get(f"/api/v1/cases/{case_id}").json()
    assert stored["original_content"] == content


def test_second_report_is_listed_newest_first(client):
    created = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "SMS", "content": "A second look at this text."},
    )
    case_id = created.json()["case_id"]
    first = client.post(f"/api/v1/cases/{case_id}/reports")
    second = client.post(f"/api/v1/cases/{case_id}/reports")

    listed = client.get(f"/api/v1/cases/{case_id}/reports")

    assert first.status_code == 201
    assert second.status_code == 201
    assert listed.status_code == 200
    assert [item["report_id"] for item in listed.json()] == [
        second.json()["report_id"],
        first.json()["report_id"],
    ]


def test_missing_case_report_returns_404(client):
    assert client.post("/api/v1/cases/missing/reports").status_code == 404
    assert client.get("/api/v1/cases/missing/reports").status_code == 404
    assert client.get("/api/v1/cases/missing/reports/also-missing").status_code == 404


def test_missing_report_file_returns_404(client, tmp_path):
    created = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "ADVERTISEMENT", "content": "Limited offer text."},
    )
    case_id = created.json()["case_id"]
    report = client.post(f"/api/v1/cases/{case_id}/reports").json()
    path = tmp_path / "reports" / f"{report['report_id']}.pdf"
    path.unlink()

    response = client.get(report["download_path"])

    assert response.status_code == 404
    assert response.json()["detail"] == "Report file is missing from storage."


def test_tampered_evidence_is_reported_as_failed(client, tmp_path):
    created = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "SMS", "content": "Original wording."},
    )
    case_id = created.json()["case_id"]
    connection = sqlite3.connect(tmp_path / "reports.sqlite3")
    connection.execute(
        "UPDATE cases SET original_content = ? WHERE case_id = ?",
        ("Changed wording.", case_id),
    )
    connection.commit()
    connection.close()

    response = client.post(f"/api/v1/cases/{case_id}/reports")

    assert response.status_code == 201
    events = client.get(f"/api/v1/cases/{case_id}/events").json()
    assert events[-2]["event_type"] == "INTEGRITY_FAILED"
    assert client.get(f"/api/v1/cases/{case_id}").json()["original_content"] == (
        "Changed wording."
    )


def test_legacy_case_report_keeps_unavailable_integrity(client, tmp_path):
    connection = sqlite3.connect(tmp_path / "reports.sqlite3")
    connection.execute(
        """
        INSERT INTO cases (
            case_id, evidence_type, original_content, analysis_status, created_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            "legacy-report",
            "EMAIL",
            "Legacy evidence.",
            "PENDING_AI_INTEGRATION",
            "2026-01-01T00:00:00+00:00",
        ),
    )
    connection.commit()
    connection.close()

    response = client.post("/api/v1/cases/legacy-report/reports")

    assert response.status_code == 201
    events = client.get("/api/v1/cases/legacy-report/events").json()
    assert [event["event_type"] for event in events] == [
        "INTEGRITY_UNAVAILABLE",
        "REPORT_GENERATED",
    ]
    assert client.get("/api/v1/cases/legacy-report").json()["evidence_sha256"] is None


def test_report_path_rejects_names_that_leave_the_reports_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "REPORTS_DIR", tmp_path / "reports")

    assert resolve_report_path("..\\outside.pdf") is None
    assert resolve_report_path("../outside.pdf") is None
    assert resolve_report_path("nested/file.pdf") is None
    assert resolve_report_path("") is None
