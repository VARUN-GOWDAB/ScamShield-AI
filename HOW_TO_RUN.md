# How to run ScamShield AI

ScamShield AI is a local investigation workstation. One API process stores the evidence. The Streamlit app talks only to that API. Results are advisory: they do not prove fraud, and they do not decide whether text was written by AI.

Use mock mode until you choose to add your own OpenAI key.

## What you need

- Windows PowerShell, or Docker with Docker Compose
- Python 3.12 or newer for a local run
- No API key for mock mode

## Run on Windows

From the project root:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
.\scripts\start.ps1
```

The script creates `.env` from `.env.example` when `.env` is missing, then starts both processes.

- Workstation: http://127.0.0.1:8501
- API docs: http://127.0.0.1:8000/docs
- Readiness: http://127.0.0.1:8000/health/ready

If port 8000 or 8501 is already in use, the script stops and tells you. Close the old window, or stop that process, and run it again.

You can also start the two processes yourself after activating the virtual environment:

```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
python -m streamlit run frontend/app.py --server.address 127.0.0.1 --server.port 8501
```

## First use

1. Open http://127.0.0.1:8501.
2. Confirm the sidebar says the API is connected.
3. Choose an evidence type, paste the message, and choose **Preserve and analyze**.
4. Open the investigation, choose **Verify integrity**, then **Generate PDF report**.

Mock mode stores the text and returns a labeled inconclusive result. It does not read the message. The sidebar can load a fictional example so you can try the screens.

## Use a live model

Edit `.env`:

```text
AI_PROVIDER=openai
OPENAI_API_KEY=your-own-key
OPENAI_MODEL=a-model-your-account-can-use
```

Restart the API after changing `.env`. The model key stays on the backend. The workstation does not send it to the browser. Pick a model that supports the OpenAI Responses API with structured output. This project does not choose one for you.

## Protect the API

Leave `SCAMSHIELD_API_KEY` empty when only this computer uses the app.

Before another computer can reach the API, set the same value in two places:

- `SCAMSHIELD_API_KEY` in the backend `.env`
- The workstation sidebar, or `SCAMSHIELD_API_KEY` for the Streamlit process

The workstation reads `.env` from the project root. API routes then require this header:

```http
X-API-Key: the-same-value
```

`/health` and `/health/ready` stay open so a process check can run without the key.

## Other settings

| Setting | Purpose |
| --- | --- |
| `DATABASE_PATH` | SQLite file. The default is `storage/scamshield.db`. |
| `REPORTS_DIR` | Folder for PDF reports. The default is `reports/`. |
| `SCAMSHIELD_API_URL` | Where the workstation finds the API. The default is `http://127.0.0.1:8000`. |
| `LOG_LEVEL` | Backend log level. Logs record case and report ids, not evidence text or secrets. |
| `CORS_ORIGINS` | Comma-separated browser origins. Leave this empty for the Streamlit workstation. |

Do not commit `.env`.

## Run the tests

From the project root, with the virtual environment active:

```powershell
python -m pytest
```

The tests use temporary databases. They do not call OpenAI.

## Run with Docker

From the project root:

```powershell
docker compose up --build
```

- Workstation: http://127.0.0.1:8501
- API: http://127.0.0.1:8000/docs

The database and PDF files stay in the `scamshield-data` volume. Docker Compose reads `AI_PROVIDER`, `OPENAI_API_KEY`, `OPENAI_MODEL`, and `SCAMSHIELD_API_KEY` from the shell or from a `.env` file in this folder.

Set `SCAMSHIELD_API_KEY` before you publish port 8000 beyond your own machine. Put TLS in front of the containers for any network other than localhost. Run one API process for a database file.

## Stop it

Close the two PowerShell windows opened by `scripts\start.ps1`.

For Docker:

```powershell
docker compose down
```

`docker compose down` keeps the volume. `docker compose down -v` deletes the database and the stored PDFs.

## If it does not start

- `API could not be reached` in the sidebar means the API window is not running, or `SCAMSHIELD_API_URL` points somewhere else.
- `401` means the sidebar key does not match `SCAMSHIELD_API_KEY`.
- `503` with `AI_PROVIDER=openai` means the key or the model name is missing.
- A completed case stays completed until you turn on **Replace a completed analysis**. A failed replacement keeps the earlier result.
- Evidence text and its SHA-256 live in the same SQLite file. The hash shows whether the stored text changed. It is not a certified chain of custody.
