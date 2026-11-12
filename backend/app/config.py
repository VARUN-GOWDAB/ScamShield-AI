"""Application configuration loaded from environment variables."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[2]
APP_VERSION = "1.0.0"

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "")
AI_PROVIDER = os.getenv("AI_PROVIDER", "mock")


def _path_from_env(name: str, default: Path) -> Path:
    """Return an expanded path from the environment, or the project default."""
    configured = os.getenv(name, "").strip()
    if not configured:
        return default
    return Path(configured).expanduser()


DATABASE_PATH = _path_from_env("DATABASE_PATH", PROJECT_ROOT / "storage" / "scamshield.db")
REPORTS_DIR = _path_from_env("REPORTS_DIR", PROJECT_ROOT / "reports")
SCAMSHIELD_API_KEY = os.getenv("SCAMSHIELD_API_KEY", "").strip()
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").strip() or "INFO"
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "").split(",")
    if origin.strip()
]
