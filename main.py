import shutil
import os
import glob
import re
import uuid
import threading
import time
import zipfile
from datetime import datetime, timedelta
from typing import Optional
import random
import json
import qrcode
import psutil

import logging
from logging.handlers import RotatingFileHandler
import sys

from starlette.middleware.csrf import CSRFMiddleware
from werkzeug.utils import secure_filename
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.sessions import SessionMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import mimetypes
from pathlib import Path
from io import BytesIO
from fastapi import FastAPI, Request, Form, Depends, HTTPException, Body, UploadFile, File, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, Session, select, or_, and_, func

# Import your models
from models import Box, Sample, Freezer, AuditLog, Attachment, Booking, Lab, User, Project, Experiment, ExperimentLink, ExperimentTemplate, Consumable, InviteCode, OrderRequest, SampleLineageLink


try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)

# Configure logging
def setup_logging():
    """Configure application logging."""
    log_level = logging.DEBUG if APP_ENV == "development" else logging.INFO
    
    # Format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler (rotating)
    file_handler = RotatingFileHandler(
        'logs/lims.log',
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Silence noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    
    return logging.getLogger(__name__)

# Initialize logger
logger = setup_logging()

# Sentry for production error tracking
if os.environ.get("SENTRY_DSN") and APP_ENV == "production":
    import sentry_sdk
    from sentry_sdk.integrations.fastapi import FastApiIntegration
    
    sentry_sdk.init(
        dsn=os.environ.get("SENTRY_DSN"),
        environment=APP_ENV,
        traces_sample_rate=0.1,  # 10% of transactions
        integrations=[FastApiIntegration()],
    )
    logger.info("Sentry error tracking initialized")

# --- CONFIGURATION ---
SECRET_KEY = os.environ.get("LIMS_SECRET")
APP_ENV = os.environ.get("APP_ENV", "development")

# Security check: Don't let the app start in production without a real secret
if not SECRET_KEY:
    if APP_ENV == "production":
        raise RuntimeError("LIMS_SECRET environment variable is not set!")
    else:
        SECRET_KEY = "dev_only_secret" # Fallback for local testing only

ALGORITHM = "HS256"
LICENSE_LIMIT = int(os.environ.get("LICENSE_LIMIT", 5))

# ADD THIS: Dynamic Base URL for QR codes
BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")

# Folders for Multi-Tenancy (Ensures they are created)
DB_FOLDER = os.environ.get("DB_FOLDER", "customer_dbs")
UPLOAD_BASE = os.environ.get("UPLOAD_BASE", "uploads")
BACKUP_DIR = os.environ.get("BACKUP_DIR", "backups")

for folder in [DB_FOLDER, UPLOAD_BASE, BACKUP_DIR]:
    os.makedirs(folder, exist_ok=True)

pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],  # Argon2 primary, bcrypt fallback
    deprecated="auto",
    argon2__memory_cost=65536,  # 64 MB
    argon2__time_cost=3,
    argon2__parallelism=4
)

def verify_password(plain: str, hashed: str) -> bool:
    """Verify password and rehash if using deprecated scheme."""
    return pwd_context.verify(plain, hashed)

def get_password_hash(password: str) -> str:
    """Hash password using Argon2."""
    return pwd_context.hash(password)

def needs_rehash(hashed: str) -> bool:
    """Check if hash needs to be updated (e.g., from bcrypt to argon2)."""
    return pwd_context.needs_update(hashed)

app = FastAPI()
# Mount uploads root (In production, use a proxy or specific file serve route for security)
templates = Jinja2Templates(directory="templates")

# CORS Configuration
allowed_origins = ["https://*.limslite.com", "https://limslite.com"] if APP_ENV == "production" else ["*"]

app.add_middleware(
    CSRFMiddleware,
    secret=SECRET_KEY,
    exempt_urls=["/webhooks/*", "/api/*"]  # Exempt API endpoints
)

# Session middleware for secure cookies
app.add_middleware(
    SessionMiddleware, 
    secret_key=SECRET_KEY,
    session_cookie="lims_session",
    max_age=86400,  # 24 hours
    same_site="lax",
    https_only=APP_ENV == "production"
)

# Trusted host middleware (production only)
if APP_ENV == "production":
    app.add_middleware(
        TrustedHostMiddleware, 
        allowed_hosts=["*.limslite.com", "limslite.com"]
    )

# Rate limiter
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    
    # Prevent XSS
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # HSTS (force HTTPS)
    if APP_ENV == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    
    # CSP (Content Security Policy)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self';"
    )
    
    return response

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests for audit trail."""
    start_time = time.time()
    
    response = await call_next(request)
    
    process_time = time.time() - start_time
    logger.info(
        f"{request.method} {request.url.path} "
        f"status={response.status_code} "
        f"duration={process_time:.3f}s "
        f"ip={request.client.host}"
    )
    
    return response

# --- MULTI-TENANCY HELPERS ---

def get_subdomain(request: Request) -> str:
    # Look for proxy headers first, then the direct host
    host = request.headers.get("x-forwarded-host", request.headers.get("host", ""))
    
    # Bypass subdomain logic during local dev
    if ("localhost" in host or "127.0.0.1" in host) and APP_ENV != "production":
        return os.environ.get("DEV_TENANT", "devlab")
    
    parts = host.split('.')
    # If using biolab.limslite.de, len(parts) is 3. parts[0] is 'biolab'
    if len(parts) > 2:
        return parts[0]
    return "www"

def get_lab_name(request: Request):
    """Sanitizes subdomain to be a safe filename."""
    sub = get_subdomain(request)
    if not sub or sub == "www":
        return None
    # Allow only alphanumeric and underscores
    return re.sub(r'[^a-zA-Z0-9_]', '', sub)

def get_db_path(lab_name: str):
    if not lab_name: return None
    return os.path.join(DB_FOLDER, f"{lab_name}.db")

def get_upload_dir(lab_name: str):
    path = os.path.join(UPLOAD_BASE, lab_name)
    os.makedirs(path, exist_ok=True)
    return path

def get_session(request: Request):
    """
    Dependency that yields a database session SPECIFIC to the requested subdomain.
    Autocreates DB and seeds it if it doesn't exist.
    """
    lab_name = get_lab_name(request)
    
    if not lab_name:
        yield None
        return

    db_path = get_db_path(lab_name)
    sqlite_url = f"sqlite:///{db_path}"
    
    # Use StaticPool for SQLite to prevent threading issues with multiple files
    engine = create_engine(sqlite_url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
    
    # Auto-Migration
    SQLModel.metadata.create_all(engine)
    
    with Session(engine) as session:
        # SEEDING: If this is a brand new lab, give them defaults
        if not session.exec(select(Freezer)).first():
            session.add(Freezer(name="Main Fridge (-20°C)", location="Hallway"))
            session.add(Lab(name="General Lab", location="Room 101", resources="Bench 1, Microscope, Centrifuge"))
            # Note: We don't create a user here; the first user to register becomes Admin
            session.commit()
        yield session

# --- AUTH HELPERS ---
def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)
def get_password_hash(password): return pwd_context.hash(password)
def create_access_token(data: dict, lab_name: str): 
    to_encode = data.copy()
    # Add the lab scope to the token
    to_encode.update({
        "exp": datetime.utcnow() + timedelta(days=7),
        "scope": lab_name  # <--- CRITICAL SECURITY FIX
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.webp',  # Images/docs
    '.xlsx', '.xls', '.csv', '.tsv',  # Spreadsheets
    '.txt', '.md', '.docx', '.doc',  # Text files
    '.zip'  # Archives
}

# Max file size (10MB default)
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", 10 * 1024 * 1024))

def validate_and_secure_filename(file: UploadFile) -> str:
    """
    Validate file upload and return secured filename.
    Raises HTTPException if validation fails.
    """
    # Check file size
    file.file.seek(0, 2)  # Seek to end
    file_size = file.file.tell()
    file.file.seek(0)  # Reset to start
    
    if file_size > MAX_FILE_SIZE:
        max_mb = MAX_FILE_SIZE / 1024 / 1024
        raise HTTPException(
            status_code=400, 
            detail=f"File too large. Maximum size: {max_mb:.1f}MB"
        )
    
    if file_size == 0:
        raise HTTPException(status_code=400, detail="Empty file uploaded")
    
    # Check extension
    filename = file.filename or "unnamed"
    ext = os.path.splitext(filename)[1].lower()
    
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400, 
            detail=f"File type '{ext}' not allowed. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
        )
    
    # Secure the filename (prevent directory traversal)
    secured = secure_filename(filename)
    
    # Add timestamp to prevent overwrites
    name, ext = os.path.splitext(secured)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_filename = f"{name}_{timestamp}{ext}"
    
    return unique_filename

async def get_current_user(request: Request, session: Session = Depends(get_session)):
    if not session: return None
    token = request.cookies.get("access_token")
    if not token: return None
    
    try:
        if token.startswith("Bearer "): token = token.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        token_scope = payload.get("scope") # <--- Get the lab name from token
        
        # FIX: Reject if token belongs to a different lab
        current_lab = get_lab_name(request)
        if token_scope != current_lab:
            return None # Invalid for this tenant
            
        if username is None: return None
    except JWTError: return None
    
    return session.exec(select(User).where(User.username == username)).first()

async def login_required(request: Request, user: User = Depends(get_current_user)):
    if not user: raise HTTPException(status_code=status.HTTP_307_TEMPORARY_REDIRECT, headers={"Location": "/login"})
    return user

async def admin_required(user: User = Depends(login_required)):
    if user.role != "Admin": raise HTTPException(status_code=403, detail="Admin privileges required")
    return user

@app.get("/files/{tenant}/{filename:path}")
async def serve_file(
    tenant: str, 
    filename: str, 
    request: Request,
    user: User = Depends(login_required),
    session: Session = Depends(get_session)
):
    """
    Securely serve files only to authenticated users of the correct tenant.
    Prevents directory traversal and cross-tenant access.
    """
    # Verify user is accessing their own tenant's files
    current_tenant = get_lab_name(request)
    if tenant != current_tenant:
        raise HTTPException(status_code=403, detail="Access denied to this tenant's files")
    
    # Construct file path
    file_path = os.path.join(UPLOAD_BASE, tenant, filename)
    
    # Check file exists
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    # Prevent directory traversal attacks
    real_path = os.path.realpath(file_path)
    base_path = os.path.realpath(os.path.join(UPLOAD_BASE, tenant))
    
    if not real_path.startswith(base_path):
        logger.warning(f"Directory traversal attempt: {filename} by {user.username}")
        raise HTTPException(status_code=403, detail="Invalid file path")
    
    # Determine content type
    content_type, _ = mimetypes.guess_type(file_path)
    if content_type is None:
        content_type = "application/octet-stream"
    
    return FileResponse(
        file_path, 
        media_type=content_type,
        filename=Path(filename).name
    )

def log_action(session: Session, action: str, user: User, details: str = "", sample_id: int = None, consumable_id: int = None):
    session.add(AuditLog(action=action, user_name=user.username, details=details, sample_id=sample_id, consumable_id=consumable_id))
    session.commit()

# --- BACKUP SYSTEM (TENANT AWARE) ---
def create_lab_backup(lab_name: str, prefix="auto"):
    """Zips the specific lab's DB and Upload folder."""
    db_path = get_db_path(lab_name)
    if not os.path.exists(db_path): return None
    
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"backup_{lab_name}_{prefix}_{timestamp}.zip"
    filepath = os.path.join(BACKUP_DIR, filename)
    
    with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add Database (renamed to database.db for portability)
        zipf.write(db_path, arcname="database.db")
        
        # Add Uploads
        lab_upload_dir = get_upload_dir(lab_name)
        for root, dirs, files in os.walk(lab_upload_dir):
            for file in files:
                # Store relative to the lab's upload root
                rel_path = os.path.relpath(os.path.join(root, file), UPLOAD_BASE)
                zipf.write(os.path.join(root, file), arcname=os.path.join("uploads", rel_path))
                
    return filename

def run_scheduler():
    """Background thread: Daily Backup for ALL labs."""
    print("--- Backup Scheduler Started ---")
    while True:
        now = datetime.now()
        # Run at 03:00 AM
        if now.hour == 3 and now.minute == 0:
            print(f"[{now}] Running Global Auto-Backup...")
            # Iterate all DBs found in the folder
            for db_file in glob.glob(os.path.join(DB_FOLDER, "*.db")):
                lab_name = os.path.basename(db_file).replace(".db", "")
                create_lab_backup(lab_name, "daily")
            
            # Prune old backups (Keep last 100 files total)
            backups = sorted(glob.glob(os.path.join(BACKUP_DIR, "*.zip")), key=os.path.getmtime)
            while len(backups) > 100:
                os.remove(backups.pop(0))
                
            time.sleep(65)
        else:
            time.sleep(60)

@app.on_event("startup")
def on_startup():
    # Start the backup scheduler
    threading.Thread(target=run_scheduler, daemon=True).start()

# --- GAMIFICATION ---
def update_biomass(session: Session, user: User):
    today = datetime.now()
    start = today - timedelta(days=today.weekday())
    start = start.replace(hour=0, minute=0, second=0)
    end = start + timedelta(days=7)
    
    bookings = session.exec(select(Booking).where(and_(
        Booking.user_name == user.username, 
        Booking.start_time >= start, 
        Booking.start_time < end
    ))).all()
    
    mins = sum([(b.end_time - b.start_time).total_seconds()/60 for b in bookings if b.end_time < datetime.now()])
    user.petri_score = max(10, int(mins / 3))
    session.add(user); session.commit()

@app.get("/health")
async def health_check(session: Session = Depends(get_session)):
    """
    Health check endpoint for load balancers and monitoring.
    Returns 200 if healthy, 503 if unhealthy.
    """
    try:
        # Test database connection
        if session:
            session.exec(select(User).limit(1))
        
        return JSONResponse({
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0",
            "environment": APP_ENV
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=503, 
            detail="Service unhealthy"
        )

@app.get("/metrics")
async def metrics():
    """
    Basic metrics endpoint.
    For production, use Prometheus client library.
    """
    return JSONResponse({
        "version": "1.0.0",
        "uptime_seconds": time.time() - app.state.start_time if hasattr(app.state, 'start_time') else 0,
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent
    })

@app.on_event("startup")
async def startup_event():
    """Run on application startup."""
    app.state.start_time = time.time()
    logger.info(f"LIMS application starting in {APP_ENV} mode")
    
    # Log configuration (without secrets)
    logger.info(f"Database folder: {DB_FOLDER}")
    logger.info(f"Upload folder: {UPLOAD_BASE}")
    logger.info(f"License limit: {LICENSE_LIMIT}")

@app.on_event("shutdown")
async def shutdown_event():
    """Run on application shutdown."""
    logger.info("LIMS application shutting down")

# ================= ROUTES =================

# --- LANDING PAGE (SaaS Sales Page) ---
@app.get("/", response_class=HTMLResponse)
def root_router(request: Request, user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    lab_name = get_lab_name(request)
    
    # CASE 1: Visitor on www.limslite.com -> Show Signup
    if not lab_name:
        return """
        <html>
        <head><title>Create LIMS</title><style>body{font-family:sans-serif;text-align:center;padding:50px;background:#f4f4f4;} form{background:white;padding:30px;display:inline-block;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);} input{padding:10px;border:1px solid #ddd;border-radius:4px;} button{padding:10px 20px;background:#333;color:white;border:none;border-radius:4px;cursor:pointer;}</style></head>
        <body>
            <h1>🧪 LIMS Lite SaaS</h1>
            <p>Create a dedicated inventory & booking system for your lab in seconds.</p>
            <form action="/create_lab" method="post">
                <label>Choose your subdomain:</label><br><br>
                <input type="text" name="lab_name" placeholder="biolab" pattern="[a-zA-Z0-9]+" required> 
                <strong>.limslite.com</strong><br><br>
                <button>🚀 Create My Lab</button>
            </form>
        </body>
        </html>
        """
    
    # CASE 2: User on biolab.limslite.com but not logged in -> Login
    if not user:
        return RedirectResponse("/login")
        
    # CASE 3: User logged in -> Dashboard
    return dashboard_view(request, user, session)

@app.post("/create_lab")
def create_lab_endpoint(request: Request, lab_name: str = Form(...), licenses: int = Form(5)):
    # Sanitize
    clean_name = re.sub(r'[^a-zA-Z0-9]', '', lab_name).lower()
    if len(clean_name) < 3: return "Name too short"
    
    # Check if taken
    db_path = get_db_path(clean_name)
    if os.path.exists(db_path):
        return f"Lab '{clean_name}' already exists! Try logging in at {clean_name}.yourdomain.com"
    
    # Initialize DB and Seed Defaults
    sqlite_url = f"sqlite:///{db_path}"
    engine = create_engine(sqlite_url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    
    with Session(engine) as session:
        session.add(Freezer(name="Main Fridge", location="Lab"))
        # UPDATED: Set the user_limit based on the signup choice
        session.add(Lab(name="Main Lab", location="Room 1", user_limit=licenses)) 
        session.commit()
        
    return f"Lab Created! Go to http://{clean_name}.yourdomain.com"

# --- DASHBOARD LOGIC ---
def dashboard_view(request, user, session):
    update_biomass(session, user)
    leaderboard = session.exec(select(User).order_by(User.petri_score.desc()).limit(5)).all()
    stats = {"boxes": len(session.exec(select(Box)).all()), "samples": len(session.exec(select(Sample)).all()), "alerts": len(session.exec(select(Sample).where(Sample.is_low_stock==True)).all())}
    freezers = session.exec(select(Freezer)).all()
    today = datetime.now(); next_week = today + timedelta(days=7)
    upcoming_exps = session.exec(select(Experiment).where(and_(Experiment.date >= today, Experiment.date <= next_week)).order_by(Experiment.date)).all()
    upcoming_bookings = session.exec(select(Booking).where(and_(Booking.start_time >= today, Booking.start_time <= next_week)).order_by(Booking.start_time)).all()
    agenda = []
    for e in upcoming_exps: agenda.append({"type": "experiment", "date": e.date, "title": e.name, "desc": e.status, "link": f"/projects/{e.project_id}"})
    for b in upcoming_bookings: agenda.append({"type": "booking", "date": b.start_time, "title": b.resource, "desc": f"{b.start_time.strftime('%H:%M')} - {b.end_time.strftime('%H:%M')}", "link": f"/calendar/{b.lab_id}"})
    agenda.sort(key=lambda x: x["date"])
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user, "freezers": freezers, "stats": stats, "agenda": agenda, "leaderboard": leaderboard})

# --- AUTH ROUTES ---

@app.post("/login")
@limiter.limit("5/minute")  # Only 5 attempts per minute per IP
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session)
):
    if not session:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Service unavailable"
        })
    
    # Add delay to slow down brute force (even on failed attempts)
    await asyncio.sleep(0.5)
    
    user = session.exec(select(User).where(User.username == username)).first()
    
    if not user or not verify_password(password, user.hashed_password):
        # Log failed attempt
        logger.warning(f"Failed login attempt for user: {username} from IP: {request.client.host}")
        
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid credentials"
        })
    
    # Update last active
    user.last_active = datetime.now()
    session.add(user)
    session.commit()
    
    # Create JWT token with tenant scope
    lab_name = get_lab_name(request)
    token = create_access_token({"sub": user.username}, lab_name)
    
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        "access_token", 
        f"Bearer {token}",
        httponly=True,  # Prevent XSS access
        secure=APP_ENV == "production",  # HTTPS only in prod
        samesite="lax",
        max_age=604800  # 7 days
    )
    
    logger.info(f"Successful login: {username} from IP: {request.client.host}")
    
    return response

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request): return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == username)).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {"request": {}, "error": "Invalid credentials"})
    
    # FIX: Include the current lab name in the token
    lab_name = get_lab_name(request)
    access_token = create_access_token(data={"sub": user.username}, lab_name=lab_name)
    
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return resp

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, code: str = None, session: Session = Depends(get_session)):
    if not session: return RedirectResponse("/") 
    user_count = session.exec(select(func.count(User.id))).one()
    return templates.TemplateResponse("register.html", {"request": request, "code": code, "is_first": (user_count == 0)})

@app.post("/register")
@limiter.limit("3/hour")  # Only 3 registrations per hour per IP
async def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    invite_code: str = Form(None),
    session: Session = Depends(get_session)
):
    if not session:
        return RedirectResponse("/login", status_code=303)
    
    # Validate password strength
    if len(password) < 8:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Password must be at least 8 characters",
            "is_first": not session.exec(select(User)).first()
        })
    
    # Check for common patterns
    common_passwords = ['password', '12345678', 'qwerty', 'admin123']
    if password.lower() in common_passwords:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Password too common. Choose a stronger password.",
            "is_first": not session.exec(select(User)).first()
        })
    
    # Check if username already exists
    if session.exec(select(User).where(User.username == username)).first():
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Username already taken",
            "is_first": False
        })
    # 1. Check current user count
    user_count = session.exec(select(func.count(User.id))).one()
    
    # 2. Fetch the lab configuration to get the specific seat limit
    lab_config = session.exec(select(Lab)).first()
    current_limit = lab_config.user_limit if lab_config else 5
    
    # The first person to sign up is always the Admin
    role = "Admin" if user_count == 0 else "User"
    
    # Logic for everyone EXCEPT the first Admin
    if user_count > 0:
        # Check if they provided an invite code
        if not invite_code: 
            return templates.TemplateResponse("register.html", {
                "request": request, 
                "error": "Invite Code Required for new users."
            })
        
        # Validate the invite code
        valid_code = session.exec(
            select(InviteCode).where(
                InviteCode.code == invite_code, 
                InviteCode.is_used == False
            )
        ).first()
        
        if not valid_code: 
            return templates.TemplateResponse("register.html", {
                "request": request, 
                "error": "Invalid or already used Invite Code."
            })
        
        # ENFORCEMENT: Check against the database-driven limit
        if user_count >= current_limit: 
            return templates.TemplateResponse("register.html", {
                "request": request, 
                "error": f"Plan Limit Reached. This lab is limited to {current_limit} users."
            })
            
        # Mark code as used
        valid_code.is_used = True
        session.add(valid_code)

    # 3. Create the User
    colors = ["#FF5252", "#448AFF", "#69F0AE", "#E040FB", "#FFAB40", "#FFFF00", "#00E5FF"]
    new_user = User(
        username=username, 
        hashed_password=get_password_hash(password), # Assuming this helper exists in your main.py
        role=role, 
        petri_color=random.choice(colors)
    )
    
    session.add(new_user)
    session.commit()
    
    return RedirectResponse(url="/login", status_code=303)

@app.get("/logout")
def logout(): resp = RedirectResponse(url="/login", status_code=303); resp.delete_cookie("access_token"); return resp

# --- ADMIN PANEL ---
@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, user: User = Depends(admin_required), session: Session = Depends(get_session)):
    invites = session.exec(select(InviteCode).where(InviteCode.is_used == False)).all()
    users = session.exec(select(User)).all()
    
    lab_name = get_lab_name(request)
    backups = []
    # Find tenant specific backups
    pattern = os.path.join(BACKUP_DIR, f"backup_{lab_name}_*.zip")
    for path in sorted(glob.glob(pattern), reverse=True):
        stat = os.stat(path)
        backups.append({
            "name": os.path.basename(path),
            "size": f"{stat.st_size / 1024 / 1024:.2f} MB",
            "time": datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
        })

    return templates.TemplateResponse("admin.html", {
        "request": request, "user": user, "invites": invites, 
        "users": users, "limit": LICENSE_LIMIT, "usage": (len(users)/LICENSE_LIMIT)*100,
        "backups": backups
    })

@app.post("/admin/generate_invite")
def generate_invite(user: User = Depends(admin_required), session: Session = Depends(get_session)):
    if session.exec(select(func.count(User.id))).one() >= LICENSE_LIMIT: return RedirectResponse("/admin", 303)
    session.add(InviteCode(code=str(uuid.uuid4())[:8].upper(), created_by=user.username)); session.commit()
    return RedirectResponse("/admin", 303)

@app.post("/admin/delete_user")
def delete_user(user_id: int = Form(...), admin: User = Depends(admin_required), session: Session = Depends(get_session)):
    u = session.get(User, user_id)
    if u and u.id != admin.id: session.delete(u); session.commit()
    return RedirectResponse("/admin", 303)

@app.post("/admin/toggle_role")
def toggle_user_role(user_id: int = Form(...), admin: User = Depends(admin_required), session: Session = Depends(get_session)):
    u = session.get(User, user_id)
    if u and u.id != admin.id:
        u.role = "User" if u.role == "Admin" else "Admin"
        session.add(u); session.commit()
    return RedirectResponse("/admin", 303)

@app.post("/admin/backup/create")
def manual_backup(request: Request, user: User = Depends(admin_required)):
    create_lab_backup(get_lab_name(request), "manual")
    return RedirectResponse("/admin", 303)

@app.get("/admin/backup/download/{filename}")
def download_backup(filename: str, user: User = Depends(admin_required)):
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(path): raise HTTPException(404)
    return FileResponse(path, filename=filename)

@app.post("/admin/backup/restore_local")
def restore_local(request: Request, filename: str = Form(...), user: User = Depends(admin_required), session: Session = Depends(get_session)):
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(path): return "File not found"
    
    lab_name = get_lab_name(request)
    db_path = get_db_path(lab_name)
    upload_dir = get_upload_dir(lab_name)
    
    session.close() # Close connection to allow overwrite
    
    try:
        with zipfile.ZipFile(path, 'r') as zipf:
            zipf.extract("database.db", path="temp_restore")
            shutil.move("temp_restore/database.db", db_path)
            
            for file in zipf.namelist():
                if file.startswith("uploads/"):
                    zipf.extract(file, path="temp_restore")
            
            if os.path.exists(f"temp_restore/uploads/{lab_name}"):
                if os.path.exists(upload_dir): shutil.rmtree(upload_dir)
                shutil.move(f"temp_restore/uploads/{lab_name}", upload_dir)
                
            shutil.rmtree("temp_restore", ignore_errors=True)
    except Exception as e:
        return f"Error: {e}"
        
    return RedirectResponse("/", 303)

@app.post("/admin/backup/restore")
async def restore_upload(request: Request, file: UploadFile = File(...), user: User = Depends(admin_required), session: Session = Depends(get_session)):
    # Simple restore from upload: save to temp zip, reuse local restore logic
    temp_name = f"temp_{get_lab_name(request)}.zip"
    temp_path = os.path.join(BACKUP_DIR, temp_name)
    with open(temp_path, "wb") as f: shutil.copyfileobj(file.file, f)
    return restore_local(request, temp_name, user, session)

# --- STANDARD ROUTES (Sample, Uploads, Inventory, etc.) ---
# UPDATED: Uploads must use get_upload_dir(get_lab_name(request))

@app.post("/api/experiment/upload")
async def upload_exp_file(request: Request, experiment_id: int = Form(...), file: UploadFile = File(...), user: User = Depends(login_required), session: Session = Depends(get_session)):
    upload_dir = get_upload_dir(get_lab_name(request))
    filename = f"EXP_{experiment_id}_{file.filename}"
    loc = os.path.join(upload_dir, filename)
    
    with open(loc, "wb") as b: shutil.copyfileobj(file.file, b)
    # Store RELATIVE path in DB so links work
    rel_path = os.path.join("uploads", get_lab_name(request), filename)
    
    session.add(Attachment(experiment_id=experiment_id, filename=file.filename, filepath=rel_path))
    session.commit()
    return RedirectResponse(url=f"/projects/{session.get(Experiment, experiment_id).project_id}", status_code=303)

@app.get("/experiment/{id}/run", response_class=HTMLResponse)
def run_experiment_view(request: Request, id: int, user: User = Depends(login_required), session: Session = Depends(get_session)):
    exp = session.get(Experiment, id)
    if not exp: raise HTTPException(404)
    
    # 1. Parse Protocol into Steps (Split by new line)
    steps = []
    if exp.protocol:
        raw_lines = exp.protocol.split('\n')
        steps = [line.strip() for line in raw_lines if line.strip()]
    
    # 2. Load Progress
    progress = {}
    try:
        if exp.progress_json:
            progress = json.loads(exp.progress_json)
    except:
        progress = {}

    return templates.TemplateResponse("run_protocol.html", {
        "request": request, 
        "exp": exp, 
        "steps": steps, 
        "progress": progress,
        "user": user
    })

@app.post("/api/experiment/save_progress")
def save_experiment_progress(exp_id: int = Body(...), progress: str = Body(...), user: User = Depends(login_required), session: Session = Depends(get_session)):
    exp = session.get(Experiment, exp_id)
    if not exp: return {"status": "error"}
    
    exp.progress_json = progress # Save the raw JSON string
    exp.status = "In Progress" # Auto-update status
    session.add(exp)
    session.commit()
    return {"status": "success"}

@app.post("/api/experiment/upload")
async def upload_file(
    file: UploadFile = File(...),
    experiment_id: int = Form(...),
    user: User = Depends(login_required),
    session: Session = Depends(get_session),
    request: Request = None
):
    # VALIDATE FILE FIRST
    secured_filename = validate_and_secure_filename(file)
    
    # Get tenant-specific upload directory
    tenant = get_lab_name(request)
    upload_dir = get_upload_dir(tenant)
    
    # Save file securely
    file_path = os.path.join(upload_dir, secured_filename)
    
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    
    # Store in database with relative path
    attachment = Attachment(
        filename=secured_filename,
        filepath=f"{tenant}/{secured_filename}",  # Relative path
        experiment_id=experiment_id
    )
    session.add(attachment)
    session.commit()
    
    logger.info(f"File uploaded: {secured_filename} by {user.username}")
    
    return {"status": "success", "filename": secured_filename}

# ... Standard Routes below are SAFE to reuse from before because they rely on 'session' dependency
@app.get("/search")
def search(request: Request, q: str, user: User = Depends(login_required), session: Session = Depends(get_session)):
    samples = session.exec(select(Sample).where(or_(Sample.name.ilike(f"%{q}%"), Sample.lot_number.ilike(f"%{q}%")))).all()
    items = session.exec(select(Consumable).where(Consumable.name.ilike(f"%{q}%"))).all()
    exps = session.exec(select(Experiment).where(Experiment.name.ilike(f"%{q}%"))).all()
    tmpls = session.exec(select(ExperimentTemplate).where(ExperimentTemplate.name.ilike(f"%{q}%"))).all()
    return templates.TemplateResponse("search_results.html", {"request": request, "query": q, "user": user, "results": {"samples": samples, "inventory": items, "exps": exps, "tmpls": tmpls}})

@app.get("/api/search_autocomplete")
def search_auto(q: str, session: Session = Depends(get_session)):
    results = []
    
    # 1. SAMPLES (Now including ID)
    samples = session.exec(select(Sample).where(or_(Sample.name.ilike(f"%{q}%"), Sample.lot_number.ilike(f"%{q}%"))).limit(5)).all()
    for s in samples: 
        results.append({
            "id": s.id,  # <--- ADDED THIS
            "category": "Sample", 
            "name": s.name, 
            "info": f"in {s.box.name if s.box else 'Unboxed'}", 
            "url": f"/box/{s.box_id}?highlight={s.id}" if s.box else "#", 
            "icon": "fa-vial", 
            "color": "#ff4b4b"
        })

    # 2. INVENTORY ITEMS
    items = session.exec(select(Consumable).where(Consumable.name.ilike(f"%{q}%")).limit(3)).all()
    for i in items: 
        results.append({
            "id": i.id, # Added for consistency
            "category": "Item", 
            "name": i.name, 
            "info": f"{i.quantity} {i.unit}", 
            "url": "/inventory", 
            "icon": "fa-box-open", 
            "color": "#FF9800"
        })

    # 3. EXPERIMENTS
    exps = session.exec(select(Experiment).where(Experiment.name.ilike(f"%{q}%")).limit(3)).all()
    for e in exps: 
        results.append({
            "id": e.id,
            "category": "Experiment", 
            "name": e.name, 
            "info": e.status, 
            "url": f"/projects/{e.project_id}", 
            "icon": "fa-flask", 
            "color": "#2196F3"
        })

    return JSONResponse(results)

# --- MERGED INVENTORY & ORDERS ROUTES ---

@app.get("/inventory", response_class=HTMLResponse)
def view_inventory(request: Request, user: User = Depends(login_required), session: Session = Depends(get_session)):
    # 1. Fetch Inventory Items
    items = session.exec(select(Consumable)).all()
    
    # 2. Fetch Orders (Admins see all, Users see theirs)
    if user.role == "Admin":
        orders = session.exec(select(OrderRequest).where(OrderRequest.status != "Received").order_by(OrderRequest.created_at)).all()
        history = session.exec(select(OrderRequest).where(OrderRequest.status == "Received").order_by(OrderRequest.updated_at.desc()).limit(20)).all()
    else:
        orders = session.exec(select(OrderRequest).where(and_(OrderRequest.requester == user.username, OrderRequest.status != "Received"))).all()
        history = session.exec(select(OrderRequest).where(and_(OrderRequest.requester == user.username, OrderRequest.status == "Received")).limit(10)).all()

    return templates.TemplateResponse("inventory.html", {
        "request": request, 
        "user": user, 
        "items": items,
        "orders": orders,
        "history": history
    })

# Action: Create Request (Redirects to Inventory now)
@app.post("/orders/request")
def create_request(item_name: str = Form(...), url: str = Form(None), qty: int = Form(1), reason: str = Form(None), user: User = Depends(login_required), session: Session = Depends(get_session)):
    req = OrderRequest(item_name=item_name, url=url, quantity=qty, reason=reason, requester=user.username)
    session.add(req)
    log_action(session, "Requested Item", user, f"Requested {item_name}")
    session.commit()
    return RedirectResponse("/inventory?tab=orders", status_code=303)

# Action: Update Status (Redirects to Inventory now)
@app.post("/orders/update_status")
def update_order_status(req_id: int = Form(...), status: str = Form(...), user: User = Depends(admin_required), session: Session = Depends(get_session)):
    req = session.get(OrderRequest, req_id)
    if not req:
        return RedirectResponse("/inventory?tab=orders", status_code=303)

    # MAGIC: Auto-Stock Logic when marking as "Received"
    if status == "Received" and req.status != "Received":
        # 1. Search for existing item by name (Exact Match)
        existing_item = session.exec(select(Consumable).where(Consumable.name == req.item_name)).first()
        
        if existing_item:
            # SCENARIO A: Item exists -> Update Stock
            old_qty = existing_item.quantity
            existing_item.quantity += req.quantity
            existing_item.order_flag = False # Clear "Order Needed" flag if it was on
            
            session.add(existing_item)
            log_action(session, "Auto-Restock", user, f"Added +{req.quantity} to '{existing_item.name}' (Order Recv)", consumable_id=existing_item.id)
        else:
            # SCENARIO B: New Item -> Create it
            new_item = Consumable(
                name=req.item_name,
                quantity=req.quantity,
                category="General",       # Default category
                location="Receiving Area",# Default location
                unit="units",
                min_level=5,
                buy_url=req.url
            )
            session.add(new_item)
            # Flush to generate ID for logging
            session.flush() 
            log_action(session, "Auto-Create", user, f"Created new item '{req.item_name}' (Order Recv)", consumable_id=new_item.id)

    # 2. Standard Status Update
    req.status = status
    req.updated_at = datetime.now()
    
    # Log the order change
    log_action(session, "Order Update", user, f"Set '{req.item_name}' to {status}")
    
    session.add(req)
    session.commit()
    
    return RedirectResponse("/inventory?tab=orders", status_code=303)

@app.get("/inventory/export_csv")
def export_inventory_csv(user: User = Depends(login_required), session: Session = Depends(get_session)):
    items = session.exec(select(Consumable)).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Name', 'Category', 'Location', 'Quantity', 'Unit', 'Min Level', 'Order Needed'])
    for i in items:
        writer.writerow([i.name, i.category, i.location, i.quantity, i.unit, i.min_level, "Yes" if i.order_flag else "No"])
    mem = io.BytesIO(); mem.write(output.getvalue().encode('utf-8')); mem.seek(0)
    return StreamingResponse(mem, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=inventory_export.csv"})

@app.get("/api/inventory/history/{id}")
def get_inventory_history(id: int, session: Session = Depends(get_session)):
    logs = session.exec(select(AuditLog).where(AuditLog.consumable_id == id).order_by(AuditLog.timestamp.desc())).all()
    return JSONResponse([{"user": l.user_name, "action": l.action, "details": l.details, "time": l.timestamp.strftime('%Y-%m-%d %H:%M')} for l in logs])

@app.post("/inventory/create")
def create_item(name: str = Form(...), category: str = Form(...), quantity: int = Form(...), unit: str = Form(...), location: str = Form(...), min_level: int = Form(...), buy_url: str = Form(None), user: User = Depends(login_required), session: Session = Depends(get_session)):
    item = Consumable(name=name, category=category, quantity=quantity, unit=unit, location=location, min_level=min_level, buy_url=buy_url)
    session.add(item); session.commit(); log_action(session, "Created", user, f"Initial Qty: {quantity}", consumable_id=item.id)
    return RedirectResponse("/inventory", status_code=303)

@app.post("/inventory/update_details")
def update_item_details(id: int = Form(...), name: str = Form(...), category: str = Form(...), location: str = Form(...), min_level: int = Form(...), buy_url: str = Form(None), user: User = Depends(login_required), session: Session = Depends(get_session)):
    item = session.get(Consumable, id)
    if item:
        item.name = name; item.category = category; item.location = location; item.min_level = min_level; item.buy_url = buy_url
        session.add(item); log_action(session, "Updated Info", user, f"Changed meta details", consumable_id=item.id); session.commit()
    return RedirectResponse("/inventory", status_code=303)

@app.post("/inventory/update_qty")
def update_item_qty(id: int = Body(...), change: int = Body(...), user: User = Depends(login_required), session: Session = Depends(get_session)):
    item = session.get(Consumable, id)
    if item:
        old = item.quantity; item.quantity += change; session.add(item)
        log_action(session, "Qty Change", user, f"Changed by {change} ({old} -> {item.quantity})", consumable_id=item.id); session.commit()
        return {"status": "success", "new_qty": item.quantity}
    return {"status": "error"}

@app.post("/inventory/set_qty")
def set_item_qty(id: int = Body(...), qty: int = Body(...), user: User = Depends(login_required), session: Session = Depends(get_session)):
    item = session.get(Consumable, id)
    if item:
        old = item.quantity; item.quantity = qty; session.add(item)
        log_action(session, "Qty Set", user, f"Manually set to {qty} (was {old})", consumable_id=item.id); session.commit()
        return {"status": "success", "new_qty": item.quantity}
    return {"status": "error"}

@app.post("/inventory/flag_order")
def flag_item_order(id: int = Body(...), flag: bool = Body(...), user: User = Depends(login_required), session: Session = Depends(get_session)):
    item = session.get(Consumable, id)
    if item:
        item.order_flag = flag; session.add(item)
        log_action(session, "Order Flag", user, f"Marked as {'Order Needed' if flag else 'Ordered/OK'}", consumable_id=item.id); session.commit()
        return {"status": "success"}
    return {"status": "error"}

@app.post("/inventory/delete")
def delete_item(id: int = Form(...), user: User = Depends(admin_required), session: Session = Depends(get_session)): 
    item = session.get(Consumable, id)
    if item:
        for l in item.logs: session.delete(l)
        session.delete(item); session.commit()
    return RedirectResponse("/inventory", status_code=303)

@app.get("/templates", response_class=HTMLResponse)
def templates_list(request: Request, user: User = Depends(login_required), session: Session = Depends(get_session)):
    return templates.TemplateResponse("templates_list.html", {"request": request, "templates": session.exec(select(ExperimentTemplate)).all(), "user": user})

@app.post("/templates/create")
def create_template(name: str = Form(...), description: str = Form(None), protocol: str = Form(None), user: User = Depends(admin_required), session: Session = Depends(get_session)): 
    session.add(ExperimentTemplate(name=name, description=description, protocol=protocol)); session.commit()
    return RedirectResponse(url="/templates", status_code=303)

@app.post("/templates/update")
def update_template(id: int = Form(...), name: str = Form(...), description: str = Form(None), protocol: str = Form(None), user: User = Depends(admin_required), session: Session = Depends(get_session)): 
    t = session.get(ExperimentTemplate, id)
    if t: t.name = name; t.description = description; t.protocol = protocol; session.add(t); session.commit()
    return RedirectResponse(url="/templates", status_code=303)

@app.post("/templates/delete")
def delete_template(id: int = Form(...), user: User = Depends(admin_required), session: Session = Depends(get_session)): 
    t = session.get(ExperimentTemplate, id)
    if t: session.delete(t); session.commit()
    return RedirectResponse(url="/templates", status_code=303)

@app.get("/projects", response_class=HTMLResponse)
def projects_list(request: Request, user: User = Depends(login_required), session: Session = Depends(get_session)):
    return templates.TemplateResponse("projects_list.html", {"request": request, "projects": session.exec(select(Project)).all(), "user": user})

@app.get("/projects/{project_id}", response_class=HTMLResponse)
def view_project(request: Request, project_id: int, user: User = Depends(login_required), session: Session = Depends(get_session)):
    project = session.get(Project, project_id)
    if not project: return RedirectResponse("/projects")
    labs = session.exec(select(Lab)).all()
    lab_resources = {l.id: [r.strip() for r in l.resources.split(',')] if l.resources else [] for l in labs}
    links = session.exec(select(ExperimentLink).where(ExperimentLink.project_id == project_id)).all()
    tmpls = session.exec(select(ExperimentTemplate)).all()
    for exp in project.experiments: 
        for s in exp.samples: _ = s.box 
        _ = exp.bookings
        _ = exp.attachments
    return templates.TemplateResponse("project_view.html", {"request": request, "project": project, "user": user, "labs": labs, "lab_resources": lab_resources, "links": links, "templates": tmpls})

@app.post("/projects/create")
def create_project(name: str = Form(...), description: str = Form(None), user: User = Depends(login_required), session: Session = Depends(get_session)):
    session.add(Project(name=name, description=description, owner=user.username)); session.commit()
    return RedirectResponse(url="/projects", status_code=303)

@app.post("/experiments/create")
def create_experiment(name: str = Form(...), project_id: int = Form(...), description: str = Form(None), template_id: int = Form(0), user: User = Depends(login_required), session: Session = Depends(get_session)):
    import random
    protocol_content = None
    if template_id > 0:
        tmpl = session.get(ExperimentTemplate, template_id)
        if tmpl: description = description or tmpl.description; protocol_content = tmpl.protocol
    session.add(Experiment(name=name, project_id=project_id, description=description, protocol=protocol_content, pos_x=random.randint(50, 400), pos_y=random.randint(50, 300)))
    session.commit()
    return RedirectResponse(url=f"/projects/{project_id}", status_code=303)

@app.post("/api/experiment/move")
def move_experiment_api(id: int = Body(...), x: int = Body(...), y: int = Body(...), user: User = Depends(login_required), session: Session = Depends(get_session)):
    exp = session.get(Experiment, id)
    if exp: exp.pos_x = x; exp.pos_y = y; session.add(exp); session.commit(); return {"status": "success"}
    return {"status": "error"}

@app.post("/api/experiment/update_details")
def update_experiment_details(id: int = Body(...), description: str = Body(...), protocol: str = Body(...), status: str = Body(...), date: str = Body(None), user: User = Depends(login_required), session: Session = Depends(get_session)):
    exp = session.get(Experiment, id)
    if exp: 
        exp.description = description; exp.protocol = protocol; exp.status = status
        if date: exp.date = datetime.fromisoformat(date)
        session.add(exp); session.commit()
        return {"status": "success"}
    return {"status": "error"}

@app.post("/api/experiment/link")
def link_experiment_api(project_id: int = Body(...), source_id: int = Body(...), target_id: int = Body(...), user: User = Depends(login_required), session: Session = Depends(get_session)):
    session.add(ExperimentLink(project_id=project_id, source_id=source_id, target_id=target_id)); session.commit()
    return {"status": "success"}

@app.post("/api/experiment/add_sample")
def add_sample_to_exp(experiment_id: int = Body(...), sample_id: int = Body(...), user: User = Depends(login_required), session: Session = Depends(get_session)):
    s = session.get(Sample, sample_id)
    if s: s.experiment_id = experiment_id; session.add(s); session.commit(); return {"status": "success", "name": s.name, "loc": s.box.name if s.box else "Unboxed"}
    return {"status": "error"}

@app.post("/api/experiment/remove_sample")
def remove_sample_from_exp(sample_id: int = Body(...), user: User = Depends(login_required), session: Session = Depends(get_session)):
    s = session.get(Sample, sample_id)
    if s: s.experiment_id = None; session.add(s); session.commit(); return {"status": "success"}
    return {"status": "error"}

@app.get("/experiments/{experiment_id}/report", response_class=HTMLResponse)
def generate_experiment_report(request: Request, experiment_id: int, user: User = Depends(login_required), session: Session = Depends(get_session)):
    exp = session.get(Experiment, experiment_id)
    if not exp: return HTTPException(status_code=404, detail="Experiment not found")
    _ = exp.samples; _ = exp.attachments; _ = exp.bookings
    return templates.TemplateResponse("experiment_report.html", {"request": request, "exp": exp, "user": user})

@app.get("/box/{box_id}", response_class=HTMLResponse)
def view_box(request: Request, box_id: int, user: User = Depends(login_required), session: Session = Depends(get_session)):
    box = session.get(Box, box_id)
    if not box: raise HTTPException(status_code=404)
    experiments = session.exec(select(Experiment)).all()
    grid_map = {(s.row_idx, s.col_idx): s for s in box.samples}
    for s in box.samples: _ = s.parents; _ = s.children
    return templates.TemplateResponse("box_view.html", {"request": request, "box": box, "grid_map": grid_map, "experiments": experiments, "user": user})

@app.get("/box/{box_id}/label", response_class=HTMLResponse)
def print_box_label(request: Request, box_id: int, user: User = Depends(login_required), session: Session = Depends(get_session)):
    box = session.get(Box, box_id)
    if not box: raise HTTPException(status_code=404, detail="Box not found")
    return templates.TemplateResponse("label_box.html", {"request": request, "box": box})

@app.get("/box/{box_id}/print_samples", response_class=HTMLResponse)
def print_box_samples(request: Request, box_id: int, user: User = Depends(login_required), session: Session = Depends(get_session)):
    box = session.get(Box, box_id)
    if not box: raise HTTPException(status_code=404)
    
    # Sort samples: Row 1 Col 1, Row 1 Col 2, etc.
    sorted_samples = sorted(box.samples, key=lambda s: (s.row_idx, s.col_idx))
    
    return templates.TemplateResponse("print_box_samples.html", {
        "request": request, 
        "box": box, 
        "samples": sorted_samples
    })

@app.post("/box/{box_id}/import_csv")
async def import_box_csv(box_id: int, file: UploadFile = File(...), user: User = Depends(login_required), session: Session = Depends(get_session)):
    box = session.get(Box, box_id)
    if not box: raise HTTPException(status_code=404)
    content = await file.read()
    try: text = content.decode('utf-8')
    except: text = content.decode('latin-1')
    reader = csv.DictReader(io.StringIO(text))
    occupied = {(s.row_idx, s.col_idx) for s in box.samples}
    current_row, current_col = 1, 1
    def get_next_empty():
        nonlocal current_row, current_col
        while current_row <= box.rows:
            while current_col <= box.cols:
                if (current_row, current_col) not in occupied: return current_row, current_col
                current_col += 1
            current_col = 1; current_row += 1
        return None, None
    count = 0
    for row in reader:
        data = {k.lower().strip(): v for k, v in row.items() if k}
        name = data.get('name')
        if not name: continue
        r = int(data.get('row')) if data.get('row') else None
        c = int(data.get('col')) if data.get('col') else None
        if not r or not c:
            r, c = get_next_empty()
            if not r: break 
        if (r, c) in occupied: continue
        s = Sample(name=name, box_id=box.id, row_idx=r, col_idx=c, sample_type=data.get('type', 'Other'), lot_number=data.get('lot'), notes=data.get('notes'))
        session.add(s); occupied.add((r,c)); count += 1
    log_action(session, "Bulk Import", user, f"Imported {count} samples", sample_id=None)
    session.commit()
    return RedirectResponse(f"/box/{box_id}", status_code=303)

@app.post("/box/{box_id}/add_sample")
def add_sample(
    box_id: int, 
    name: str = Form(...), 
    sample_type: str = Form("Other"), 
    row: int = Form(...), 
    col: int = Form(...), 
    experiment_id: int = Form(None), 
    notes: str = Form(None), 
    amount_left: str = Form(None), 
    expiry_date: str = Form(None), 
    host_species: str = Form(None), 
    resistance: str = Form(None), 
    passage_number: int = Form(None), 
    lot: str = Form(None), 
    parent_ids: str = Form(None), # Changed: Receives "1,5,10"
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    # 1. Check if slot is taken
    if session.exec(select(Sample).where(Sample.box_id==box_id, Sample.row_idx==row, Sample.col_idx==col)).first(): 
        return "Slot occupied"
    
    exp_id = experiment_id if experiment_id and experiment_id > 0 else None
    
    # 2. Parse Parent IDs and Inherit Data
    p_list = []
    if parent_ids:
        try:
            # Convert "1,5,9" -> [1, 5, 9]
            p_list = [int(p) for p in parent_ids.split(',') if p.strip()]
        except ValueError:
            pass # Handle parse errors gracefully

    # Logic: Inherit details from the FIRST parent found (if new fields are empty)
    if p_list:
        first_parent = session.get(Sample, p_list[0])
        if first_parent:
            if not sample_type or sample_type == "Other": sample_type = first_parent.sample_type
            if not host_species: host_species = first_parent.host_species
            if not resistance: resistance = first_parent.resistance

    # 3. Create the New Sample (Without Parents first)
    new_sample = Sample(
        name=name, 
        lot_number=lot, 
        sample_type=sample_type, 
        notes=notes, 
        amount_left=amount_left, 
        expiry_date=expiry_date, 
        host_species=host_species, 
        resistance=resistance, 
        passage_number=passage_number, 
        box_id=box_id, 
        row_idx=row, 
        col_idx=col, 
        experiment_id=exp_id
        # parent_id is REMOVED
    )
    session.add(new_sample)
    session.commit()
    session.refresh(new_sample) # Get the new ID
    
    # 4. Create Lineage Links (Many-to-Many)
    for pid in p_list:
        # Check if parent actually exists to prevent foreign key errors
        if session.get(Sample, pid):
            link = SampleLineageLink(parent_id=pid, child_id=new_sample.id)
            session.add(link)
    
    # 5. Log & Redirect
    log_action(session, "Created", user, f"In Box {box_id}", sample_id=new_sample.id)
    session.commit()
    
    return RedirectResponse(url=f"/box/{box_id}", status_code=303)

# --- UPDATE SAMPLE & LINEAGE ---
@app.post("/sample/update")
def update_sample(
    sample_id: int = Form(...),
    name: str = Form(...),
    sample_type: str = Form(...),
    lot: str = Form(None),
    notes: str = Form(None),
    is_low_stock: bool = Form(False),
    experiment_id: int = Form(0),
    parent_ids: str = Form(None), # NEW: Receives "1,5,8"
    user: User = Depends(login_required),
    session: Session = Depends(get_session)
):
    sample = session.get(Sample, sample_id)
    if not sample: return RedirectResponse("/", status_code=303)
    
    # 1. Update Standard Fields
    sample.name = name
    sample.sample_type = sample_type
    sample.lot_number = lot
    sample.notes = notes
    sample.is_low_stock = is_low_stock
    sample.experiment_id = experiment_id if experiment_id > 0 else None
    
    session.add(sample)
    
    # 2. Update Lineage (The "Reset & Re-link" Strategy)
    # First, remove ALL existing parent links for this child
    old_links = session.exec(select(SampleLineageLink).where(SampleLineageLink.child_id == sample_id)).all()
    for link in old_links:
        session.delete(link)
        
    # Second, create the new links
    if parent_ids:
        # Parse "1,5,8" -> [1, 5, 8]
        try:
            new_pids = [int(p) for p in parent_ids.split(',') if p.strip()]
            for pid in new_pids:
                # Prevent self-parenting loop
                if pid != sample_id:
                    session.add(SampleLineageLink(parent_id=pid, child_id=sample_id))
        except ValueError:
            pass # Ignore bad data
            
    log_action(session, "Updated", user, f"Updated sample {name} lineage", sample_id=sample.id)
    session.commit()
    
    return RedirectResponse(f"/box/{sample.box_id}", status_code=303)

@app.post("/sample/delete")
def delete_sample(sample_id: int = Form(...), user: User = Depends(login_required), session: Session = Depends(get_session)):
    s = session.get(Sample, sample_id); bid = s.box_id
    if s:
        for l in s.logs: session.delete(l)
        for a in s.attachments: session.delete(a)
        session.delete(s); session.commit()
    return RedirectResponse(f"/box/{bid}", 303)

@app.get("/sample/{sample_id}/label", response_class=HTMLResponse)
def print_sample_label(request: Request, sample_id: int, user: User = Depends(login_required), session: Session = Depends(get_session)):
    sample = session.get(Sample, sample_id)
    if not sample: raise HTTPException(status_code=404, detail="Sample not found")
    return templates.TemplateResponse("label_print.html", {"request": request, "sample": sample})

@app.get("/labs")
def view_labs(request: Request, user: User = Depends(login_required), session: Session = Depends(get_session)):
    return templates.TemplateResponse("lab_list.html", {"request": request, "labs": session.exec(select(Lab)).all(), "user": user})

@app.post("/labs/create")
def create_lab(
    name: str = Form(...), 
    location: str = Form(...), 
    user_limit: int = Form(5), # ADDED
    user: User = Depends(admin_required), 
    session: Session = Depends(get_session)
): 
    # Create the lab with the chosen limit
    new_lab = Lab(name=name, location=location, user_limit=user_limit)
    session.add(new_lab)
    session.commit()
    return RedirectResponse("/labs", 303)

@app.post("/labs/update")
def update_lab(id: int = Form(...), name: str = Form(...), location: str = Form(...), resources: str = Form(...), user: User = Depends(admin_required), session: Session = Depends(get_session)): 
    lab = session.get(Lab, id)
    if lab:
        lab.name = name; lab.location = location; lab.resources = resources
        session.add(lab); session.commit()
    return RedirectResponse("/labs", 303)

@app.post("/labs/delete")
def delete_lab(id: int = Form(...), user: User = Depends(admin_required), session: Session = Depends(get_session)): 
    lab = session.get(Lab, id)
    if lab: session.delete(lab); session.commit()
    return RedirectResponse("/labs", 303)

@app.get("/calendar/{lab_id}")
def view_cal(request: Request, lab_id: int, user: User = Depends(login_required), session: Session = Depends(get_session)):
    lab = session.get(Lab, lab_id)
    if not lab: return RedirectResponse("/labs")
    res_list = [r.strip() for r in lab.resources.split(',')] if lab.resources else []
    return templates.TemplateResponse("calendar.html", {"request": request, "lab": lab, "resources": res_list, "user": user})

@app.get("/api/bookings")
def get_bookings(lab_id: int, session: Session = Depends(get_session)):
    return JSONResponse([{"id": b.id, "title": f"{b.resource}: {b.user_name}", "start": b.start_time.isoformat(), "end": b.end_time.isoformat(), "backgroundColor": ("#28a745" if "Microscope" in b.resource else ("#dc3545" if "Hood" in b.resource else "#3788d8")), "extendedProps": {"resource": b.resource, "user": b.user_name}} for b in session.exec(select(Booking).where(Booking.lab_id == lab_id)).all()])

@app.post("/api/bookings/create")
def create_booking(title: str = Body(...), resource: str = Body(...), start: str = Body(...), end: str = Body(...), lab_id: int = Body(...), experiment_id: int = Body(None), user: User = Depends(login_required), session: Session = Depends(get_session)):
    session.add(Booking(title=title, resource=resource, start_time=datetime.fromisoformat(start.replace("Z","")), end_time=datetime.fromisoformat(end.replace("Z","")), user_name=user.username, lab_id=lab_id, experiment_id=experiment_id)); session.commit()
    return {"status": "success"}

@app.post("/api/bookings/delete")
def delete_booking(id: int = Body(..., embed=True), user: User = Depends(login_required), session: Session = Depends(get_session)):
    session.delete(session.get(Booking, id)); session.commit(); return {"status": "success"}

@app.post("/freezer/create")
def create_freezer(name: str = Form(...), location: str = Form(...), user: User = Depends(admin_required), session: Session = Depends(get_session)): 
    session.add(Freezer(name=name, location=location)); session.commit(); return RedirectResponse("/", 303)

@app.post("/box/create")
def create_box(name: str = Form(...), freezer_id: int = Form(...), rows: int = Form(9), cols: int = Form(9), shelf: str = Form(...), color: str = Form(...), icon: str = Form(...), label_text: str = Form(None), user: User = Depends(admin_required), session: Session = Depends(get_session)): 
    session.add(Box(name=name, rows=rows, cols=cols, freezer_id=freezer_id, shelf=shelf, color=color, icon=icon, label_text=label_text)); session.commit(); return RedirectResponse("/", 303)

@app.post("/box/update")
def update_box(box_id: int = Form(...), name: str = Form(...), shelf: str = Form(...), color: str = Form(...), icon: str = Form(...), label_text: str = Form(None), user: User = Depends(admin_required), session: Session = Depends(get_session)): 
    b = session.get(Box, box_id); b.name=name; b.shelf=shelf; b.color=color; b.icon=icon; b.label_text=label_text; session.add(b); session.commit(); return RedirectResponse(f"/box/{box_id}", 303)

@app.post("/box/delete")
def delete_box(box_id: int = Form(...), user: User = Depends(admin_required), session: Session = Depends(get_session)): 
    b = session.get(Box, box_id); [session.delete(s) for s in b.samples]; session.delete(b); session.commit(); return RedirectResponse("/", 303)

@app.post("/api/box/move")
def move_box_api(box_id: int = Body(...), new_freezer_id: int = Body(...), user: User = Depends(login_required), session: Session = Depends(get_session)):
    b = session.get(Box, box_id); nf = session.get(Freezer, new_freezer_id); 
    for s in b.samples: log_action(session, "Box Moved", user, f"To {nf.name if nf else 'Unknown'}", sample_id=s.id)
    b.freezer_id = new_freezer_id; session.add(b); session.commit(); return {"status": "success"}

@app.post("/api/sample/move")
def move_sample_api(sample_id: int = Body(...), new_row: int = Body(...), new_col: int = Body(...), user: User = Depends(login_required), session: Session = Depends(get_session)):
    s = session.get(Sample, sample_id); old = f"{s.row_idx},{s.col_idx}"
    if session.exec(select(Sample).where(Sample.box_id==s.box_id, Sample.row_idx==new_row, Sample.col_idx==new_col)).first(): return {"status": "error"}
    s.row_idx=new_row; s.col_idx=new_col; session.add(s); log_action(session, "Moved", user, f"From {old}", sample_id=s.id); session.commit(); return {"status": "success"}

@app.get("/api/qrcode/{type}/{id}")
def generate_qr(type: str, id: int, session: Session = Depends(get_session)):
    # Verify item exists
    if type == "box":
        item = session.get(Box, id)
        url = f"/box/{id}"
    elif type == "sample":
        item = session.get(Sample, id)
        url = f"/box/{item.box_id}?highlight={id}" # Deep link to sample
    else:
        raise HTTPException(404)

    if not item: raise HTTPException(404)

    # Generate QR
    # In production, use your full domain: https://biolab.limslite.com/...
    full_url = f"{BASE_URL}{url}" 
    
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(full_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save to buffer
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)
    
    return StreamingResponse(buf, media_type="image/png")

@app.get("/sample/{id}/lineage", response_class=HTMLResponse)
def view_lineage(request: Request, id: int, user: User = Depends(login_required), session: Session = Depends(get_session)):
    root = session.get(Sample, id)
    if not root: raise HTTPException(404)
    
    nodes_def = {} 
    edges_list = set()
    node_styles = []
    
    def sanitize(text): return str(text).replace('[', '(').replace(']', ')').replace('"', "'")
    
    # Helper to style nodes
    def style_node(s):
        sType = s.sample_type.lower() if s.sample_type else "other"
        if "plasmid" in sType: node_styles.append(f"class S{s.id} plasmid;")
        elif "cell" in sType: node_styles.append(f"class S{s.id} cell;")
        elif "antibody" in sType: node_styles.append(f"class S{s.id} antibody;")
        else: node_styles.append(f"class S{s.id} other;")

    def add_node(s):
        nodes_def[s.id] = f"S{s.id}[\"{sanitize(s.name)}\"]"
        style_node(s)

    # 1. Add Root
    add_node(root)
    
    # 2. Walk UP (Ancestors)
    # We use a queue to walk up multiple branches
    queue = [root]
    visited = {root.id}
    
    while queue:
        current = queue.pop(0)
        # Find all parents of this sample
        links = session.exec(select(SampleLineageLink).where(SampleLineageLink.child_id == current.id)).all()
        
        for link in links:
            parent = session.get(Sample, link.parent_id)
            if parent:
                add_node(parent)
                edges_list.add(f"S{parent.id} --> S{current.id}")
                
                if parent.id not in visited:
                    visited.add(parent.id)
                    queue.append(parent)

    # 3. Walk DOWN (Descendants)
    queue = [root]
    visited_down = {root.id}
    depth = 0
    
    while queue and depth < 3: # Limit depth
        next_layer = []
        for p in queue:
            links = session.exec(select(SampleLineageLink).where(SampleLineageLink.parent_id == p.id)).all()
            for link in links:
                child = session.get(Sample, link.child_id)
                if child:
                    add_node(child)
                    edges_list.add(f"S{p.id} --> S{child.id}")
                    if child.id not in visited_down:
                        visited_down.add(child.id)
                        next_layer.append(child)
        queue = next_layer
        depth += 1

    # Build Graph String (Same as before)
    chart_lines = ["graph TD", "classDef plasmid fill:#e3f2fd,stroke:#2196f3,stroke-width:2px;", "classDef cell fill:#e8f5e9,stroke:#4caf50,stroke-width:2px;", "classDef other fill:#ffffff,stroke:#999,stroke-width:1px,stroke-dasharray: 5 5;", "classDef current fill:#333,stroke:#000,stroke-width:3px,color:#fff;"]
    
    for n in nodes_def.values(): chart_lines.append(f"    {n}")
    for e in edges_list: chart_lines.append(f"    {e}")
    for s in node_styles: chart_lines.append(f"    {s}")
    chart_lines.append(f"class S{root.id} current;")
    
    return templates.TemplateResponse("lineage.html", {"request": request, "user": user, "sample": root, "chart_def": "\n".join(chart_lines)})