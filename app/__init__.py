# app/__init__.py
import time
import logging
import re

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

from contextlib import asynccontextmanager

from starlette_csrf import CSRFMiddleware  # Requires 'pip install starlette-csrf'
from starlette.middleware.sessions import SessionMiddleware  # Plural 'sessions'
from starlette.middleware.trustedhost import TrustedHostMiddleware

# Import internal modules
from app.config import SECRET_KEY, APP_ENV, ALLOWED_HOSTS, IS_TESTING
from app.dependencies import limiter
from app.utils.logging import logger
# REMOVED: from app.utils.tasks import run_scheduler
# REMOVED: import threading

# Import Routers
from app.routers import auth, admin, inventory, projects, storage, labs, search, templates_mgmt, files, home


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- STARTUP LOGIC ---
    app.state.start_time = time.time()
    logger.info(f"LIMS Lite starting in {APP_ENV} mode")
    # If you still want the scheduler thread (though we discussed moving it)
    # threading.Thread(target=run_scheduler, daemon=True).start()
    
    yield  # The app runs while this is yielding
    
    # --- SHUTDOWN LOGIC ---
    logger.info("LIMS Lite shutting down")


def create_app() -> FastAPI:
    """
    Initializes and configures the FastAPI application.
    Logic migrated and organized from the original main.py.
    """
    app = FastAPI(
        title="LIMS Lite",
        description="A modular Laboratory Management System",
        version="1.1.0",
        lifespan = lifespan
    )

    # --- MIDDLEWARE CONFIGURATION ---

    # 1. Session Middleware (Secure Cookies)

    if not IS_TESTING:
        # 2. CSRF Protection
        app.add_middleware(
            CSRFMiddleware,
            secret=SECRET_KEY,
            exempt_urls=[re.compile(r"/api/.*")] 
        )
        
    app.add_middleware(
        SessionMiddleware, 
        secret_key=SECRET_KEY,
        session_cookie="lims_session",
        max_age=86400,  # 24 hours
        same_site="lax",
        https_only=APP_ENV == "production"
    )


    # 3. Trusted Host (Production only)
    if APP_ENV == "production":
        app.add_middleware(
            TrustedHostMiddleware, 
            allowed_hosts=ALLOWED_HOSTS
        )

    # 4. Rate Limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # 5. Security Headers Custom Middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        if APP_ENV == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # 6. Request Logging Middleware
    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        logger.info(
            f"{request.method} {request.url.path} "
            f"status={response.status_code} duration={process_time:.3f}s"
        )
        return response

    # --- ROUTER INCLUSION ---
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

    return app


app = create_app()