"""Analysis-provider tests without external API or network access."""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from backend.app import config
from backend.app.main import app
from backend.app.schemas import ScamAnalysis
from backend.app.services import analysis_service


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", tmp_path / "analysis.sqlite3")
    monkeypatch.setattr(config, "AI_PROVIDER", "mock")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "")
    monkeypatch.setattr(config, "OPENAI_MODEL", "")
    with TestClient(app) as test_client:
        yield test_client


def valid_analysis(content="Your account is locked"):
    return {
        "risk_level": "HIGH",
        "scam_type": "Possible account phishing",
        "summary": "The message uses an account threat and requests action.",
        "indicators": [
            {
                "evidence_quote": content,
                "explanation": "The text creates urgency about account access.",
            }
        ],
        "recommended_actions": ["Verify through the service's official channel."],
        "limitations": ["This is advisory and does not prove fraud."],
    }


def test_mock_provider_returns_explicit_inconclusive_result(client):
    response = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "SMS", "content": "Please review this message."},
    )

    assert response.status_code == 201
    result = response.json()
    assert result["analysis_provider"] == "mock"
    assert result["risk_level"] == "INCONCLUSIVE"
    assert "no content assessment" in result["message"]
    assert "does not analyze" in result["limitations"][0]


def test_openai_responses_api_request_is_mocked_and_uses_structured_output(
    monkeypatch,
):
    requested = {}

    class FakeResponses:
        def create(self, **kwargs):
            requested.update(kwargs)
            return SimpleNamespace(
                output_text=json.dumps(valid_analysis(), ensure_ascii=False)
            )

    class FakeClient:
        responses = FakeResponses()

    monkeypatch.setattr(config, "AI_PROVIDER", "openai")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "test-key-not-a-real-secret")
    monkeypatch.setattr(config, "OPENAI_MODEL", "test-model")
    monkeypatch.setattr(
        analysis_service, "_create_openai_client", lambda: FakeClient()
    )

    provider, result = analysis_service.analyze_content(
        "SMS", "Your account is locked"
    )

    assert provider == "openai"
    assert isinstance(result, ScamAnalysis)
    assert result.risk_level == "HIGH"
    assert requested["model"] == "test-model"
    assert requested["store"] is False
    assert requested["tools"] == []
    assert "untrusted data" in requested["instructions"]
    assert json.loads(requested["input"]) == {
        "evidence_type": "SMS",
        "submitted_content": "Your account is locked",
    }
    schema = requested["text"]["format"]["schema"]
    assert schema["additionalProperties"] is False
    assert schema["required"] == list(schema["properties"])
    assert all(
        definition.get("additionalProperties") is False
        for definition in schema["$defs"].values()
        if definition.get("type") == "object"
    )


@pytest.mark.parametrize(
    "output",
    [
        '{"risk_level":"CERTAIN","scam_type":"x","summary":"x",'
        '"indicators":[],"recommended_actions":["x"],"limitations":["x"]}',
        '{"not":"the analysis schema"}',
        "not json",
    ],
)
def test_malformed_openai_results_are_rejected(monkeypatch, output):
    class FakeResponses:
        def create(self, **kwargs):
            return SimpleNamespace(output_text=output)

    class FakeClient:
        responses = FakeResponses()

    monkeypatch.setattr(config, "AI_PROVIDER", "openai")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(config, "OPENAI_MODEL", "test-model")
    monkeypatch.setattr(
        analysis_service, "_create_openai_client", lambda: FakeClient()
    )

    with pytest.raises(analysis_service.InvalidAnalysisResponse):
        analysis_service.analyze_content("EMAIL", "evidence")


def test_unquoted_or_nonliteral_evidence_indicator_is_rejected(monkeypatch):
    class FakeResponses:
        def create(self, **kwargs):
            return SimpleNamespace(output_text=json.dumps(valid_analysis("invented text")))

    class FakeClient:
        responses = FakeResponses()

    monkeypatch.setattr(config, "AI_PROVIDER", "openai")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(config, "OPENAI_MODEL", "test-model")
    monkeypatch.setattr(
        analysis_service, "_create_openai_client", lambda: FakeClient()
    )

    with pytest.raises(analysis_service.InvalidAnalysisResponse):
        analysis_service.analyze_content("EMAIL", "Actual evidence.")


def test_openai_mode_requires_configuration(client, monkeypatch):
    monkeypatch.setattr(config, "AI_PROVIDER", "openai")

    response = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "EMAIL", "content": "Stored before API call."},
    )

    assert response.status_code == 503
    case = client.get("/api/v1/cases").json()[0]
    assert case["analysis_status"] == "ANALYSIS_FAILED"
    assert case["evidence_sha256"]
    events = client.get(f"/api/v1/cases/{case['case_id']}/events").json()
    assert events[-1]["event_type"] == "AI_ANALYSIS_FAILED"


def test_provider_timeout_returns_gateway_timeout_and_preserves_case(
    client, monkeypatch
):
    monkeypatch.setattr(config, "AI_PROVIDER", "openai")
    monkeypatch.setattr(
        analysis_service,
        "analyze_content",
        lambda **kwargs: (_ for _ in ()).throw(
            analysis_service.AnalysisTimeoutError("The AI provider request timed out.")
        ),
    )

    response = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "EMAIL", "content": "Preserve this content."},
    )

    assert response.status_code == 504
    case = client.get("/api/v1/cases").json()[0]
    detail = client.get(f"/api/v1/cases/{case['case_id']}").json()
    assert case["analysis_status"] == "ANALYSIS_FAILED"
    assert detail["original_content"] == "Preserve this content."


@pytest.mark.parametrize(
    ("exception", "expected_error"),
    [
        (
            analysis_service.openai.APITimeoutError(request=Mock()),
            analysis_service.AnalysisTimeoutError,
        ),
        (
            analysis_service.openai.APIConnectionError(request=Mock()),
            analysis_service.AnalysisProviderError,
        ),
        (
            analysis_service.openai.RateLimitError(
                "rate limited",
                response=Mock(status_code=429, headers={}),
                body={},
            ),
            analysis_service.AnalysisRateLimitError,
        ),
    ],
)
def test_openai_sdk_transport_errors_are_normalized(
    monkeypatch, exception, expected_error
):
    class FakeResponses:
        def create(self, **kwargs):
            raise exception

    class FakeClient:
        responses = FakeResponses()

    monkeypatch.setattr(config, "AI_PROVIDER", "openai")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(config, "OPENAI_MODEL", "test-model")
    monkeypatch.setattr(
        analysis_service, "_create_openai_client", lambda: FakeClient()
    )

    with pytest.raises(expected_error):
        analysis_service.analyze_content("EMAIL", "evidence")
