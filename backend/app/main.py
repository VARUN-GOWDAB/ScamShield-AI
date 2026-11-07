"""FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app import config
from backend.app.database import initialize_database
from backend.app.routes import router

logger = logging.getLogger("scamshield")


def configure_logging() -> None:
    """Configure process logging once, without printing secrets or evidence."""
    level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    initialize_database()
    logger.info(
        "ScamShield AI %s started provider=%s",
        config.APP_VERSION,
        config.AI_PROVIDER,
    )
    yield


def create_app() -> FastAPI:
    """Build the API application."""
    configure_logging()
    application = FastAPI(
        title="ScamShield AI API",
        version=config.APP_VERSION,
        description=(
            "Backend API for preserving suspicious email, SMS, and advertisement "
            "content, producing advisory scam analysis, and issuing PDF reports. "
            "Results are advisory and are not proof of fraud."
        ),
        lifespan=lifespan,
    )
    if config.CORS_ORIGINS:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=config.CORS_ORIGINS,
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    @application.middleware("http")
    async def add_security_headers(request: Request, call_next):
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("Unhandled request failure path=%s", request.url.path)
            raise
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        logger.info(
            "%s %s -> %s",
            request.method,
            request.url.path,
            response.status_code,
        )
        return response

    @application.exception_handler(Exception)
    async def unhandled_exception(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled application error: %s", exc.__class__.__name__)
        return JSONResponse(
            status_code=500,
            content={"detail": "An unexpected error occurred."},
        )

    application.include_router(router)
    return application


app = create_app()
