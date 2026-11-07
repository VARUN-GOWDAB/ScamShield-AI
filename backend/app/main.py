"""FastAPI application entry point."""

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI

from backend.app.database import initialize_database
from backend.app.routes import router


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    initialize_database()
    yield


app = FastAPI(
    title="ScamShield AI API",
    description=(
        "Backend API for preserving suspicious email, SMS, and advertisement "
        "content and producing advisory scam analysis with the configured provider."
    ),
    lifespan=lifespan,
)
app.include_router(router)
