import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from kms.api.routes import auth as auth_routes
from kms.api.routes import keys as keys_routes
from kms.api.routes import clients as clients_routes
from kms.api.routes import audit as audit_routes
from kms.api.routes import admin as admin_routes

_log = logging.getLogger("kms.api")
_WEB_DIR = Path(__file__).parent.parent.parent.parent / "web"


def create_app() -> FastAPI:
    app = FastAPI(
        title="KMS API",
        version="1.0.0",
        description="Key Management System — REST API (KMIP 2.1 compatible)",
        openapi_url="/api/v1/openapi.json",
        docs_url="/api/v1/docs",
        redoc_url="/api/v1/redoc",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(auth_routes.router, prefix="/api/v1/auth", tags=["Authentication"])
    app.include_router(keys_routes.router, prefix="/api/v1/keys", tags=["Keys & Objects"])
    app.include_router(clients_routes.router, prefix="/api/v1/clients", tags=["KMIP Clients"])
    app.include_router(audit_routes.router, prefix="/api/v1/audit", tags=["Audit"])
    app.include_router(admin_routes.router, prefix="/api/v1/admin", tags=["Administration"])

    static_dir = _WEB_DIR / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_ui():
        index = _WEB_DIR / "index.html"
        if index.exists():
            return FileResponse(str(index))
        return HTMLResponse("<h1>KMS</h1><p>Web UI not found.</p>")

    @app.on_event("startup")
    async def startup():
        from kms.db.session import create_tables
        await create_tables()
        _log.info("Database tables ensured")
        try:
            from kms.core.hsm import get_hsm
            hsm = await get_hsm()
            await hsm.ensure_kek()
            _log.info("HSM KEK ready")
        except Exception as exc:
            _log.warning("HSM init failed (non-fatal in dev): %s", exc)
        await _bootstrap_admin()

    return app


async def _bootstrap_admin() -> None:
    from kms.config import settings
    from kms.db.session import AsyncSessionLocal
    from kms.db.models import User
    from kms.auth.jwt_handler import hash_password
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).limit(1))
        if result.scalar_one_or_none() is not None:
            return
        admin = User(
            username=settings.bootstrap_admin_user,
            hashed_password=hash_password(settings.bootstrap_admin_password),
            role="sec_admin",
            is_active=True,
        )
        session.add(admin)
        await session.commit()
        _log.info("Bootstrap admin '%s' created", settings.bootstrap_admin_user)


app = create_app()
