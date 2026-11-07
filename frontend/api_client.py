"""HTTP client for the ScamShield AI backend."""

from typing import Any

import requests


class ApiError(Exception):
    """A non-success response from the ScamShield API."""

    def __init__(self, status_code: int, message: str, case_id: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.case_id = case_id


class ScamShieldClient:
    """Call the local investigation API."""

    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        timeout: float = 60,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key.strip()
        self.timeout = timeout
        self.session = session or requests.Session()

    def health(self) -> dict[str, Any]:
        return self._json("GET", "/health", timeout=5)

    def ready(self) -> dict[str, Any]:
        return self._json("GET", "/health/ready", timeout=5)

    def analyze(self, evidence_type: str, content: str) -> dict[str, Any]:
        return self._json(
            "POST",
            "/api/v1/analyze",
            json={"evidence_type": evidence_type, "content": content},
        )

    def reanalyze(self, case_id: str, replace_completed: bool = False) -> dict[str, Any]:
        return self._json(
            "POST",
            f"/api/v1/cases/{case_id}/analyze",
            json={"replace_completed": replace_completed},
        )

    def list_cases(self) -> list[dict[str, Any]]:
        return self._json("GET", "/api/v1/cases")

    def get_case(self, case_id: str) -> dict[str, Any]:
        return self._json("GET", f"/api/v1/cases/{case_id}")

    def verify(self, case_id: str) -> dict[str, Any]:
        return self._json("POST", f"/api/v1/cases/{case_id}/verify-integrity")

    def events(self, case_id: str) -> list[dict[str, Any]]:
        return self._json("GET", f"/api/v1/cases/{case_id}/events")

    def create_report(self, case_id: str) -> dict[str, Any]:
        return self._json("POST", f"/api/v1/cases/{case_id}/reports")

    def list_reports(self, case_id: str) -> list[dict[str, Any]]:
        return self._json("GET", f"/api/v1/cases/{case_id}/reports")

    def download_report(self, case_id: str, report_id: str) -> bytes:
        response = self._send(
            "GET", f"/api/v1/cases/{case_id}/reports/{report_id}"
        )
        return response.content

    def _json(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self._send(method, path, **kwargs)
        if not response.content:
            return None
        return response.json()

    def _send(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        headers = dict(kwargs.pop("headers", {}) or {})
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        timeout = kwargs.pop("timeout", self.timeout)
        try:
            response = self.session.request(
                method,
                f"{self.base_url}{path}",
                headers=headers,
                timeout=timeout,
                **kwargs,
            )
        except requests.RequestException as error:
            raise ApiError(0, "The API could not be reached.") from error
        if response.status_code >= 400:
            message, case_id = _error_detail(response)
            raise ApiError(response.status_code, message, case_id)
        return response


def _error_detail(response: requests.Response) -> tuple[str, str | None]:
    try:
        payload = response.json()
    except ValueError:
        text = response.text.strip()
        return text or f"The API returned HTTP {response.status_code}.", None

    detail = payload.get("detail") if isinstance(payload, dict) else payload
    if isinstance(detail, dict):
        return (
            str(detail.get("message") or detail),
            detail.get("case_id"),
        )
    if isinstance(detail, list):
        messages = []
        for item in detail:
            if isinstance(item, dict) and item.get("msg"):
                messages.append(str(item["msg"]))
            else:
                messages.append(str(item))
        return "; ".join(messages) or f"HTTP {response.status_code}", None
    if detail:
        return str(detail), None
    return f"The API returned HTTP {response.status_code}.", None
