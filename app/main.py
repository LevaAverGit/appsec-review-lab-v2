from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes_reports import router as reports_router
from app.api.routes_secure import router as secure_router
from app.api.routes_vulnerable import router as vulnerable_router
from app.core.config import Settings
from app.db.database import init_db, seed_db


def create_app(db_path: str | None = None) -> FastAPI:
    settings = Settings()
    if db_path is not None:
        settings.db_path = db_path

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db(settings.db_path)
        seed_db(settings.db_path)
        yield

    app = FastAPI(
        title="AppSec Review Lab",
        description=(
            "Controlled lab demonstrating 8 common web vulnerabilities with "
            "secure counterparts, mapped to the OWASP Top 10 and OWASP API "
            "Security Top 10. Not a production application."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.db_path = settings.db_path

    app.include_router(vulnerable_router)
    app.include_router(secure_router)
    app.include_router(reports_router)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
