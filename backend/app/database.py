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

    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
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
