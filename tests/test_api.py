"""API tests using an isolated temporary SQLite database."""

import pytest
from fastapi.testclient import TestClient

from backend.app import config
from backend.app.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", tmp_path / "test_cases.sqlite3")
    monkeypatch.setattr(config, "AI_PROVIDER", "mock")
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint_returns_ok(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert client.get("/docs").status_code == 200
    assert client.get("/redoc").status_code == 200


def test_valid_request_creates_mock_analysis_record(client):
    content = "Please review this suspicious message."
    response = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "EMAIL", "content": content},
    )

    assert response.status_code == 201
    result = response.json()
    assert result["case_id"]
    assert result["analysis_status"] == "ANALYSIS_COMPLETED"
    assert result["analysis_provider"] == "mock"
    assert result["risk_level"] == "INCONCLUSIVE"
    assert "Mock analysis" in result["message"]
    assert result["indicators"] == []

    case_response = client.get(f"/api/v1/cases/{result['case_id']}")
    assert case_response.status_code == 200
    assert case_response.json()["original_content"] == content


def test_invalid_evidence_type_is_rejected(client):
    response = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "LETTER", "content": "Review this content."},
    )

    assert response.status_code == 422


@pytest.mark.parametrize("content", ["", "   \t\n"])
def test_empty_or_whitespace_content_is_rejected(client, content):
    response = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "SMS", "content": content},
    )

    assert response.status_code == 422


def test_content_over_maximum_length_is_rejected(client):
    response = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "SMS", "content": "x" * 20_001},
    )

    assert response.status_code == 422


def test_case_can_be_retrieved_by_case_id(client):
    create_response = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "SMS", "content": "Check the sender."},
    )
    case_id = create_response.json()["case_id"]

    response = client.get(f"/api/v1/cases/{case_id}")

    assert response.status_code == 200
    assert response.json()["case_id"] == case_id
    assert response.json()["evidence_type"] == "SMS"


def test_nonexistent_case_returns_404(client):
    response = client.get("/api/v1/cases/not-a-real-case")

    assert response.status_code == 404


def test_multiple_cases_can_be_retrieved(client):
    for evidence_type, content in (
        ("EMAIL", "First item."),
        ("ADVERTISEMENT", "Second item."),
    ):
        response = client.post(
            "/api/v1/analyze",
            json={"evidence_type": evidence_type, "content": content},
        )
        assert response.status_code == 201

    response = client.get("/api/v1/cases")

    assert response.status_code == 200
    assert len(response.json()) == 2
    assert {case["evidence_type"] for case in response.json()} == {
        "EMAIL",
        "ADVERTISEMENT",
    }
