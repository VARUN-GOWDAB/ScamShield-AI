FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    AI_PROVIDER=mock \
    DATABASE_PATH=/data/scamshield.db \
    REPORTS_DIR=/data/reports

WORKDIR /app

RUN adduser --disabled-password --gecos "" appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY frontend ./frontend
COPY .streamlit ./.streamlit

RUN mkdir -p /data/reports && chown -R appuser:appuser /app /data

USER appuser

EXPOSE 8000 8501

CMD ["python", "-m", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
