"""Forensic service and API tests using temporary SQLite databases."""

import hashlib
import sqlite3
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from backend.app import config
from backend.app.database import initialize_database
from backend.app.main import app
from backend.app.services.forensic_service import (
    generate_sha256,
    get_utc_timestamp,
    verify_integrity,
)


@pytest.fixture
def client(tmp_path, monkeypatch):
    database_path = tmp_path / "forensic_cases.sqlite3"
    monkeypatch.setattr(config, "DATABASE_PATH", database_path)
    monkeypatch.setattr(config, "AI_PROVIDER", "mock")
    with TestClient(app) as test_client:
        yield test_client


def test_sha256_matches_known_input():
    assert generate_sha256("abc") == hashlib.sha256(b"abc").hexdigest()


def test_identical_content_produces_identical_hashes():
    assert generate_sha256("same evidence") == generate_sha256("same evidence")


def test_different_content_produces_different_hashes():
    assert generate_sha256("first") != generate_sha256("second")


def test_whitespace_changes_are_detected():
    assert generate_sha256("line one\nline two") != generate_sha256(
        "line one\n\nline two"
    )
    matches, calculated = verify_integrity("text ", generate_sha256("text"))
    assert not matches
    assert calculated == generate_sha256("text ")


def test_unicode_content_is_hashed_as_utf8():
    content = "Prüfung — こんにちは 🌍"
    expected = hashlib.sha256(content.encode("utf-8")).hexdigest()

    assert generate_sha256(content) == expected


def test_utc_timestamp_is_iso8601_and_timezone_aware():
    timestamp = datetime.fromisoformat(get_utc_timestamp())

    assert timestamp.tzinfo is not None
    assert timestamp.utcoffset().total_seconds() == 0


def test_new_case_has_hash_and_utc_collection_timestamp(client):
    response = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "EMAIL", "content": "Exact text \n with spaces."},
    )

    assert response.status_code == 201
    case = client.get(f"/api/v1/cases/{response.json()['case_id']}").json()
    assert case["evidence_sha256"] == generate_sha256(case["original_content"])
    collected_at = datetime.fromisoformat(case["evidence_collected_at"])
    assert collected_at.tzinfo is not None
    assert collected_at.utcoffset().total_seconds() == 0


def test_unchanged_evidence_verifies_as_verified(client):
    create_response = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "SMS", "content": "Unmodified evidence."},
    )

    response = client.post(
        f"/api/v1/cases/{create_response.json()['case_id']}/verify-integrity"
    )

    assert response.status_code == 200
    result = response.json()
    assert result["integrity_status"] == "VERIFIED"
    assert result["original_sha256"] == result["calculated_sha256"]
    assert result["evidence_collected_at"]
    assert result["verified_at"]


def test_modified_stored_evidence_verifies_as_failed(client, tmp_path):
    create_response = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "SMS", "content": "Original content."},
    )
    case_id = create_response.json()["case_id"]
    connection = sqlite3.connect(tmp_path / "forensic_cases.sqlite3")
    connection.execute(
        "UPDATE cases SET original_content = ? WHERE case_id = ?",
        ("Modified content.", case_id),
    )
    connection.commit()
    connection.close()

    response = client.post(f"/api/v1/cases/{case_id}/verify-integrity")

    assert response.status_code == 200
    assert response.json()["integrity_status"] == "FAILED"
    assert response.json()["original_sha256"] != response.json()["calculated_sha256"]
    assert client.get(f"/api/v1/cases/{case_id}").json()[
        "original_content"
    ] == "Modified content."


def test_nonexistent_case_integrity_verification_returns_404(client):
    response = client.post("/api/v1/cases/missing/verify-integrity")

    assert response.status_code == 404


def test_legacy_case_without_hash_is_not_given_a_baseline(client, tmp_path):
    connection = sqlite3.connect(tmp_path / "forensic_cases.sqlite3")
    connection.execute(
        """
        INSERT INTO cases (
            case_id, evidence_type, original_content, analysis_status, created_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        ("legacy-case", "EMAIL", "Legacy evidence.", "PENDING_AI_INTEGRATION", "2026-01-01T00:00:00+00:00"),
    )
    connection.commit()
    connection.close()

    response = client.post("/api/v1/cases/legacy-case/verify-integrity")

    assert response.status_code == 200
    result = response.json()
    assert result["integrity_status"] == "UNAVAILABLE"
    assert result["original_sha256"] is None
    assert result["calculated_sha256"] is None
    assert "no recorded SHA-256 baseline" in result["message"]
    assert client.get("/api/v1/cases/legacy-case").json()["evidence_sha256"] is None


def test_evidence_events_are_created_and_returned_chronologically(client):
    create_response = client.post(
        "/api/v1/analyze",
        json={"evidence_type": "ADVERTISEMENT", "content": "Check these claims."},
    )
    case_id = create_response.json()["case_id"]
    client.post(f"/api/v1/cases/{case_id}/verify-integrity")

    response = client.get(f"/api/v1/cases/{case_id}/events")

    assert response.status_code == 200
    events = response.json()
    assert [event["event_type"] for event in events] == [
        "EVIDENCE_COLLECTED",
        "AI_ANALYSIS_COMPLETED",
        "INTEGRITY_VERIFIED",
    ]
    assert events == sorted(events, key=lambda event: event["event_timestamp"])
    assert all(event["event_id"] and event["details"] for event in events)


def test_event_history_for_nonexistent_case_returns_404(client):
    assert client.get("/api/v1/cases/missing/events").status_code == 404


def test_database_migration_is_idempotent_and_preserves_legacy_case(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "legacy.sqlite3"
    monkeypatch.setattr(config, "DATABASE_PATH", database_path)
    connection = sqlite3.connect(database_path)
    connection.execute(
        """
        CREATE TABLE cases (
            case_id TEXT PRIMARY KEY,
            evidence_type TEXT NOT NULL,
            original_content TEXT NOT NULL,
            analysis_status TEXT NOT NULL,
            risk_level TEXT,
            scam_type TEXT,
            summary TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        INSERT INTO cases (
            case_id, evidence_type, original_content, analysis_status, created_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        ("legacy", "EMAIL", "Do not change this text.", "PENDING_AI_INTEGRATION", "2026-01-01T00:00:00+00:00"),
    )
    connection.commit()
    connection.close()

    initialize_database()
    initialize_database()

    connection = sqlite3.connect(database_path)
    row = connection.execute(
        "SELECT case_id, original_content, evidence_sha256, evidence_collected_at "
        "FROM cases WHERE case_id = ?",
        ("legacy",),
    ).fetchone()
    columns = [
        column[1] for column in connection.execute("PRAGMA table_info(cases)")
    ]
    foreign_keys = connection.execute("PRAGMA foreign_key_list(evidence_events)").fetchall()
    assert connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 1
    connection.close()

    assert row == ("legacy", "Do not change this text.", None, None)
    assert columns.count("evidence_sha256") == 1
    assert columns.count("evidence_collected_at") == 1
    assert len(foreign_keys) == 1
