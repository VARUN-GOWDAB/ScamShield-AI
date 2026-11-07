"""Reusable helpers for preserving and checking evidence metadata."""

import hashlib
import hmac
from datetime import datetime, timezone


def generate_sha256(content: str) -> str:
    """Return the SHA-256 hex digest of the exact UTF-8 encoded text."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def get_utc_timestamp() -> str:
    """Return the current timezone-aware UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def verify_integrity(content: str, original_sha256: str) -> tuple[bool, str]:
    """Compare stored evidence to its recorded hash and return match plus digest."""
    calculated_sha256 = generate_sha256(content)
    matches = hmac.compare_digest(calculated_sha256, original_sha256)
    return matches, calculated_sha256
