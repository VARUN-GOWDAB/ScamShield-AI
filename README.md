# ScamShield AI

**AI-Generated Scam Content Detector**

ScamShield AI is a planned web application for reviewing suspicious emails, SMS messages, and online advertisements for potential scam and phishing indicators. Its analysis will be advisory and will not establish definitive proof that content is fraudulent or AI-generated.

## Project objectives

- Analyze submitted email, SMS, and advertisement text for potential scam and phishing indicators.
- Preserve submitted text as investigation evidence.
- Record a SHA-256 hash and UTC evidence collection timestamp.
- Store investigation records in SQLite and support later integrity verification.
- Generate downloadable PDF forensic reports.
- Use an existing AI model through an API; this project will not train a machine-learning model.

The project is being implemented in stages; the current implementation status is below.

## Planned technology stack

- Python
- FastAPI backend
- Streamlit frontend
- OpenAI Python SDK Responses API for backend advisory analysis
- SQLite for investigation records
- Python `hashlib` for SHA-256 hashing
- ReportLab for PDF reports
- Pydantic for data validation
- python-dotenv for environment configuration
- pytest for testing

## Project architecture

```text
ScamShield-AI/
├── backend/
│   └── app/
│       ├── __init__.py
│       ├── config.py
│       ├── database.py
│       ├── main.py
│       ├── routes.py
│       ├── schemas.py
│       └── services/
│           ├── __init__.py
│           ├── analysis_service.py
│           ├── case_service.py
│           └── forensic_service.py
├── frontend/
│   (reserved for a later stage)
├── tests/
│   ├── test_api.py
│   ├── test_analysis.py
│   └── test_forensics.py
├── storage/
├── reports/
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

The backend contains the API, configuration, SQLite connection management, schemas, and analysis, case, and forensic services. The frontend will contain the Streamlit user interface in a later stage. Tests cover backend behavior, while `storage/` and `reports/` are reserved for local investigation data and generated reports.

## Current implementation status

**Stage 4 — Backend AI analysis**

The backend supports `mock` and `openai` analysis providers. New submissions are preserved with their forensic metadata before analysis. The OpenAI provider uses the official SDK Responses API and validates structured results before saving them. Mock results are clearly labeled and inconclusive; they do not analyze the submitted content. Integrity verification and forensic event history remain available. The Streamlit frontend and PDF reports remain planned.

## Windows setup and run

Run these commands in PowerShell from the project root:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Start the backend from the project root:

```powershell
python -m uvicorn backend.app.main:app --reload
```

The interactive API documentation is available at `http://127.0.0.1:8000/docs`; ReDoc is at `http://127.0.0.1:8000/redoc`.

The `.env` file is for local configuration and is excluded from version control. For offline use, keep `AI_PROVIDER=mock`; no key or model is required. To use the OpenAI API, configure `AI_PROVIDER=openai`, set `OPENAI_API_KEY` to your own key, and set `OPENAI_MODEL` to a model available to your account. The project does not assume or provide a model name. API calls are made only by the backend. Optionally set `DATABASE_PATH` to use a different SQLite file. Never commit API keys.

## API examples

Create and analyze an investigation:

```http
POST /api/v1/analyze
Content-Type: application/json
```

```json
{
  "evidence_type": "EMAIL",
  "content": "Suspicious message text goes here."
}
```

The `201 Created` response includes the case ID, forensic metadata, `analysis_status`, `analysis_provider`, and structured analysis fields:

```json
{
  "case_id": "generated-identifier",
  "analysis_status": "ANALYSIS_COMPLETED",
  "analysis_provider": "mock",
  "risk_level": "INCONCLUSIVE",
  "scam_type": "Not assessed by mock provider",
  "summary": "Mock provider is enabled. No scam assessment or content analysis was performed.",
  "indicators": [],
  "recommended_actions": ["Review the content manually before taking action."],
  "limitations": ["This is a mock result and does not analyze the submitted content."]
}
```

In OpenAI mode, each indicator includes an exact `evidence_quote` from the submitted text and an explanation. The result also includes recommended actions and limitations. Results are advisory: they do not prove fraud or determine whether text was AI-generated. The service does not visit URLs or provide confidence scores.

If analysis fails, the evidence is still retained, its status becomes `ANALYSIS_FAILED`, and an event is recorded. The request returns an appropriate error: `429` for rate limits, `502` for provider or malformed-response errors, `503` for configuration errors, or `504` for timeouts. List cases with `GET /api/v1/cases` or retrieve one with `GET /api/v1/cases/{case_id}`.

Verify evidence with `POST /api/v1/cases/{case_id}/verify-integrity`. The response contains an `integrity_status` (`VERIFIED`, `FAILED`, or `UNAVAILABLE` for legacy records), the stored and recalculated hash where available, and verification timestamps. View collection and verification history with `GET /api/v1/cases/{case_id}/events`. A missing case returns `404 Not Found`.

## Forensic evidence handling

SHA-256 is a cryptographic hash function that maps input bytes to a fixed-size hexadecimal digest. For each new investigation, the service hashes the exact submitted text encoded as UTF-8. It does not normalize whitespace, punctuation, casing, newlines, or Unicode. A later integrity check hashes the currently stored content and compares that digest with the recorded baseline using a constant-time comparison.

The evidence collection timestamp is generated at submission using a timezone-aware UTC clock and stored in ISO 8601 form. Verification attempts also receive UTC timestamps and are recorded as evidence events. `VERIFIED` means the current stored text hashes to the recorded baseline; `FAILED` means the hashes differ. A `FAILED` result does not repair or overwrite the evidence. Existing Stage 2 cases have no fabricated timestamp or hash; their integrity status is `UNAVAILABLE` until a baseline is collected through a new submission.

The database migration adds nullable forensic columns to the existing `cases` table and creates `evidence_events`; it does not recreate the cases table, rewrite existing content, or fabricate legacy metadata. It is safe to run repeatedly.

These hashes can help detect changes relative to the stored baseline, but storing both evidence and hash in the same SQLite database does not make that database tamper-proof: someone able to alter the database could change both. The hash alone does not prove when or by whom evidence was collected. This application does not claim certified chain of custody or independently verified collection time.
