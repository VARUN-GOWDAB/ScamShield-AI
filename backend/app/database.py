"""SQLite connection management and database initialization."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from backend.app import config


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """Open a database connection and close it when the operation is complete."""
    database_path = Path(config.DATABASE_PATH)
    database_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(database_path, timeout=5.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    try:
        connection.execute("PRAGMA journal_mode = WAL")
    except sqlite3.DatabaseError:
        pass
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    """Create the schema and add forensic columns to existing cases tables."""
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                evidence_type TEXT NOT NULL
                    CHECK (evidence_type IN ('EMAIL', 'SMS', 'ADVERTISEMENT')),
                original_content TEXT NOT NULL,
                analysis_status TEXT NOT NULL,
                risk_level TEXT,
                scam_type TEXT,
                summary TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        existing_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(cases)")
        }
        forensic_columns = {
            "evidence_sha256": "TEXT",
            "evidence_collected_at": "TEXT",
            "indicators": "TEXT",
            "recommended_actions": "TEXT",
            "limitations": "TEXT",
            "analysis_provider": "TEXT",
        }
        for column_name, column_type in forensic_columns.items():
            if column_name not in existing_columns:
                connection.execute(
                    f"ALTER TABLE cases ADD COLUMN {column_name} {column_type}"
                )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_events (
                event_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_timestamp TEXT NOT NULL,
                details TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                report_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_evidence_events_case_id
            ON evidence_events (case_id, event_timestamp)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_reports_case_id
            ON reports (case_id, generated_at)
            """
        )


def database_is_ready() -> bool:
    """Return whether a trivial query can be executed."""
    try:
        with get_connection() as connection:
            connection.execute("SELECT 1").fetchone()
    except sqlite3.Error:
        return False
    return True
