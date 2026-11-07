"""Operational API behavior: retries, access control, and readiness."""

import pytest
from fastapi.testclient import TestClient

from backend.app import config
from backend.app.main import app
from backend.app.services import analysis_service


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", tmp_path / "operations.sqlite3")
    monkeypatch.setattr(config, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(config, "AI_PROVIDER", "mock")
    monkeypatch.setattr(config, "SCAMSHIELD_API_KEY", "")
    with TestClient(app) as test_client:
        yield test_client


def test_readiness_checks_the_database(client):
    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


def test_security_headers_are_present(client):
    response = client.get("/health")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"


def test_case_list_honors_limit(client):
    for content in ("First preserved item.", "Second preserved item."):
        assert client.post(
            "/api/v1/analyze",
            json={"evidence_type": "EMAIL", "content": content},
        ).status_code == 201

    response = client.get("/api/v1/cases", params={"limit": 1})

    assert response.status_code == 200
    assert len(response.json()) == 1


def test_completed_analysis_is_not_replaced_unless_requested(client):
    created = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "SMS", "content": "Keep this advisory result."},
    )
    case_id = created.json()["case_id"]

    rejected = client.post(f"/api/v1/cases/{case_id}/analyze", json={})
    replaced = client.post(
        f"/api/v1/cases/{case_id}/analyze",
        json={"replace_completed": True},
    )

    assert rejected.status_code == 409
    assert replaced.status_code == 200
    assert replaced.json()["analysis_status"] == "ANALYSIS_COMPLETED"
    events = client.get(f"/api/v1/cases/{case_id}/events").json()
    assert [event["event_type"] for event in events] == [
        "EVIDENCE_COLLECTED",
        "AI_ANALYSIS_COMPLETED",
        "ANALYSIS_REPLACED",
        "AI_ANALYSIS_COMPLETED",
    ]
    assert "Prior provider: mock" in events[2]["details"]


def test_failed_analysis_can_be_run_again(client, monkeypatch):
    monkeypatch.setattr(config, "AI_PROVIDER", "openai")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "")
    failed = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "EMAIL", "content": "Stored before the provider failed."},
    )
    assert failed.status_code == 503
    case_id = failed.json()["detail"]["case_id"]

    monkeypatch.setattr(config, "AI_PROVIDER", "mock")
    retried = client.post(f"/api/v1/cases/{case_id}/analyze", json={})

    assert retried.status_code == 200
    assert retried.json()["analysis_status"] == "ANALYSIS_COMPLETED"
    assert retried.json()["analysis_provider"] == "mock"
    stored = client.get(f"/api/v1/cases/{case_id}").json()
    assert stored["original_content"] == "Stored before the provider failed."


def test_failed_replacement_keeps_the_completed_analysis(client, monkeypatch):
    created = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "EMAIL", "content": "Keep the first advisory result."},
    )
    case_id = created.json()["case_id"]
    monkeypatch.setattr(
        analysis_service,
        "analyze_content",
        lambda **kwargs: (_ for _ in ()).throw(
            analysis_service.AnalysisProviderError("The AI provider request failed.")
        ),
    )

    response = client.post(
        f"/api/v1/cases/{case_id}/analyze",
        json={"replace_completed": True},
    )

    assert response.status_code == 502
    assert "previous completed analysis was kept" in response.json()["detail"]["message"]
    stored = client.get(f"/api/v1/cases/{case_id}").json()
    assert stored["analysis_status"] == "ANALYSIS_COMPLETED"
    assert stored["risk_level"] == "INCONCLUSIVE"
    assert stored["original_content"] == "Keep the first advisory result."
    events = [event["event_type"] for event in client.get(f"/api/v1/cases/{case_id}/events").json()]
    assert events == [
        "EVIDENCE_COLLECTED",
        "AI_ANALYSIS_COMPLETED",
        "AI_ANALYSIS_FAILED",
    ]


def test_case_list_does_not_include_evidence_text(client):
    content = "This exact text stays off the list."
    created = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "SMS", "content": content},
    )

    listed = client.get("/api/v1/cases").json()[0]

    assert listed["case_id"] == created.json()["case_id"]
    assert "original_content" not in listed
    assert content not in str(listed)
    detail = client.get(f"/api/v1/cases/{listed['case_id']}").json()
    assert detail["original_content"] == content


def test_report_download_name_strips_unsafe_characters(client, tmp_path):
    connection_path = tmp_path / "operations.sqlite3"
    import sqlite3

    connection = sqlite3.connect(connection_path)
    connection.execute(
        """
        INSERT INTO cases (
            case_id, evidence_type, original_content, analysis_status, created_at,
            evidence_sha256, evidence_collected_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            'odd"id',
            "EMAIL",
            "Named carefully.",
            "ANALYSIS_COMPLETED",
            "2026-01-01T00:00:00+00:00",
            "abc",
            "2026-01-01T00:00:00+00:00",
        ),
    )
    connection.commit()
    connection.close()

    created = client.post("/api/v1/cases/odd%22id/reports")
    assert created.status_code == 201
    download = client.get(created.json()["download_path"])
    disposition = download.headers["content-disposition"]
    assert download.status_code == 200
    assert "scamshield-odd_id" in disposition
    assert "\r" not in disposition
    assert "\n" not in disposition


def test_missing_case_cannot_be_reanalyzed(client):
    response = client.post("/api/v1/cases/missing/analyze", json={})

    assert response.status_code == 404


def test_api_key_protects_case_routes_and_leaves_health_open(client, monkeypatch):
    monkeypatch.setattr(config, "SCAMSHIELD_API_KEY", "local-test-key")

    open_health = client.get("/health")
    missing = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "SMS", "content": "Should not be stored."},
    )
    wrong = client.post(
        "/api/v1/analyze",
        headers={"X-API-Key": "wrong-key"},
        json={"evidence_type": "SMS", "content": "Should not be stored."},
    )
    accepted = client.post(
        "/api/v1/analyze",
        headers={"X-API-Key": "local-test-key"},
        json={"evidence_type": "SMS", "content": "Stored with the right key."},
    )

    assert open_health.status_code == 200
    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert accepted.status_code == 201
    listed = client.get(
        "/api/v1/cases", headers={"X-API-Key": "local-test-key"}
    ).json()
    assert len(listed) == 1
    assert listed[0]["case_id"] == accepted.json()["case_id"]


def test_provider_failure_detail_names_the_preserved_case(client, monkeypatch):
    monkeypatch.setattr(
        analysis_service,
        "analyze_content",
        lambda **kwargs: (_ for _ in ()).throw(
            analysis_service.AnalysisRateLimitError("The AI provider rate limit was reached.")
        ),
    )

    response = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "EMAIL", "content": "Keep this after the limit."},
    )

    assert response.status_code == 429
    assert response.json()["detail"]["case_id"]
    assert "rate limit" in response.json()["detail"]["message"]
