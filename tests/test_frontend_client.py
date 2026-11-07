"""Tests for the workstation API client."""

import json

import pytest
import requests

from frontend.api_client import ApiError, ScamShieldClient


class FakeResponse:
    def __init__(self, status_code, payload=None, content=None):
        self.status_code = status_code
        self._payload = payload
        if content is not None:
            self.content = content
        elif payload is None:
            self.content = b""
        else:
            self.content = json.dumps(payload).encode("utf-8")
        self.text = self.content.decode("utf-8", errors="replace")

    def json(self):
        if self._payload is None:
            raise ValueError("response is not JSON")
        return self._payload


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def request(self, method, url, headers=None, timeout=None, **kwargs):
        self.calls.append(
            {"method": method, "url": url, "headers": headers, "timeout": timeout, "kwargs": kwargs}
        )
        if self.error:
            raise self.error
        return self.response


def test_client_sends_api_key_and_parses_analysis():
    session = FakeSession(
        FakeResponse(201, {"case_id": "case-1", "analysis_status": "ANALYSIS_COMPLETED"})
    )
    client = ScamShieldClient(
        "http://127.0.0.1:8000/", api_key="secret", session=session
    )

    result = client.analyze("EMAIL", "Evidence text")

    assert result["case_id"] == "case-1"
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "http://127.0.0.1:8000/api/v1/analyze"
    assert call["headers"]["X-API-Key"] == "secret"
    assert call["kwargs"]["json"] == {
        "evidence_type": "EMAIL",
        "content": "Evidence text",
    }


def test_client_extracts_case_id_from_provider_errors():
    session = FakeSession(
        FakeResponse(
            503,
            {"detail": {"message": "OPENAI_API_KEY is not configured.", "case_id": "kept"}},
        )
    )
    client = ScamShieldClient("http://api.example", session=session)

    with pytest.raises(ApiError) as caught:
        client.analyze("SMS", "Evidence")

    assert caught.value.status_code == 503
    assert caught.value.case_id == "kept"
    assert "OPENAI_API_KEY" in caught.value.message


def test_client_reports_that_the_api_could_not_be_reached():
    session = FakeSession(error=requests.ConnectionError("refused"))
    client = ScamShieldClient("http://127.0.0.1:8000", session=session)

    with pytest.raises(ApiError) as caught:
        client.health()

    assert caught.value.status_code == 0
    assert "could not be reached" in caught.value.message


def test_client_downloads_pdf_bytes():
    session = FakeSession(FakeResponse(200, content=b"%PDF-1.4"))
    client = ScamShieldClient("http://127.0.0.1:8000", session=session)

    assert client.download_report("case-1", "report-1").startswith(b"%PDF")
    assert session.calls[0]["url"].endswith("/api/v1/cases/case-1/reports/report-1")
