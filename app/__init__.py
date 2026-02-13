# app/__init__.py
import time
import re
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from contextlib import asynccontextmanager

from fastapi_csrf_jinja.middleware import FastAPICSRFJinjaMiddleware
from starlette.middleware.sessions import SessionMiddleware 
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config import SECRET_KEY, APP_ENV, ALLOWED_HOSTS, IS_TESTING
from app.dependencies import limiter
from app.utils.logging import logger
from app.routers import auth, admin, inventory, projects, storage, labs, search, templates_mgmt, files, home

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.start_time = time.time()
    logger.info(f"LIMS Lite starting in {APP_ENV} mode")
    yield
    logger.info("LIMS Lite shutting down")

def create_app() -> FastAPI:
    app = FastAPI(title="LIMS Lite", version="1.1.0", lifespan=lifespan)

    # --- 1. ROUTERS & STATICS ---
    app.include_router(auth.router)
    app.include_router(admin.router)
    app.include_router(inventory.router)
    app.include_router(projects.router)
    app.include_router(storage.router)
    app.include_router(labs.router)
    app.include_router(search.router)
    app.include_router(templates_mgmt.router)
    app.include_router(files.router)
    app.include_router(home.router)
    app.mount("/static", StaticFiles(directory="static"), name="static")

    # --- 2. MIDDLEWARE (Order is critical: Bottom-up for Requests) ---

    # C. LOGGING (Runs last for requests, first for responses)
    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        logger.info(f"{request.method} {request.url.path} status={response.status_code} {process_time:.3f}s")
        return response

    # B. CSRF PROTECTION (Middle layer)
    if not IS_TESTING:
        app.add_middleware(
            FastAPICSRFJinjaMiddleware,
            secret=SECRET_KEY,
            exempt_urls=[re.compile(r"/api/.*")] 
        )

    # DEBUG LOGGING (Inserted between Session and CSRF)
    @app.middleware("http")
    async def debug_csrf(request: Request, call_next):
        if request.method == "POST":
            # We must use a try/except because reading the form consumes the stream
            # and might interfere with the actual route if not handled carefully.
            logger.info(f"DEBUG: Headers: {dict(request.headers)}")
            logger.info(f"DEBUG: Cookies: {dict(request.cookies)}")
        return await call_next(request)

    # A. SESSION MIDDLEWARE (Runs FIRST for requests)
    app.add_middleware(
        SessionMiddleware, 
        secret_key=SECRET_KEY,
        session_cookie="lims_session",
        max_age=86400,
        same_site="lax",
        https_only=APP_ENV == "production"
    )

    if APP_ENV == "production":
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    return app

app = create_app()