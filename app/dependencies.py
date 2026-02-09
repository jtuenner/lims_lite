# app/dependencies.py
import os
import re
import logging
from typing import Generator, Optional
from fastapi import Request, Depends, HTTPException, status
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from sqlmodel import Session, select
from slowapi import Limiter
from slowapi.util import get_remote_address

# Import configurations, models, and database logic
from app.config import SECRET_KEY, ALGORITHM, APP_ENV, UPLOAD_BASE, DEV_TENANT
from app.models import User
from app.database import get_tenant_session

logger = logging.getLogger(__name__)

# --- SHARED RESOURCES ---

# Initialize Jinja2 templates and the rate limiter
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# --- MULTI-TENANCY HELPERS ---

def get_subdomain(request: Request) -> str:
    """
    Extracts the subdomain from the request host to identify the tenant.
    Logic migrated from main.py.
    """
    host = request.headers.get("x-forwarded-host", request.headers.get("host", ""))
    
    # Bypass subdomain logic during local development if configured
    if ("localhost" in host or "127.0.0.1" in host) and APP_ENV != "production":
        return DEV_TENANT or "devlab"
    
    parts = host.split('.')
    if len(parts) > 2:
        return parts[0]
    return "www"

def get_lab_name(request: Request) -> Optional[str]:
    """
    Sanitizes the subdomain to ensure it is a safe string for file paths and DB names.
    """
    sub = get_subdomain(request)
    if not sub or sub == "www":
        return None
    return re.sub(r'[^a-zA-Z0-9_]', '', sub)

def get_upload_dir(lab_name: str) -> str:
    """
    Returns the path to the tenant-specific upload directory, creating it if necessary.
    """
    path = os.path.join(UPLOAD_BASE, lab_name)
    os.makedirs(path, exist_ok=True)
    return path

# --- FASTAPI DEPENDENCIES ---

def get_session(request: Request) -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a database session scoped to the current tenant.
    """
    lab_name = get_lab_name(request)
    if not lab_name:
        raise HTTPException(status_code=400, detail="Invalid lab tenant")
    
    # Utilize the session generator from database.py
    yield from get_tenant_session(lab_name)

async def get_current_user(request: Request, session: Session = Depends(get_session)) -> Optional[User]:
    """
    Retrieves the authenticated user from the JWT token stored in cookies.
    Verifies that the token's scope matches the current tenant.
    """
    token = request.cookies.get("access_token")
    if not token:
        return None
    
    try:
        # Strip Bearer prefix if present
        if token.startswith("Bearer "):
            token = token.split(" ")[1]
            
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_scope: str = payload.get("scope")
        
        # Security check: Ensure the token belongs to the active lab tenant
        current_lab = get_lab_name(request)
        if token_scope != current_lab:
            logger.warning(f"Cross-tenant access attempt by {username}")
            return None
            
        if username is None:
            return None
            
        return session.exec(select(User).where(User.username == username)).first()
    except JWTError:
        return None

async def login_required(user: Optional[User] = Depends(get_current_user)):
    """
    Guard dependency that redirects unauthenticated users to the login page.
    """
    if not user:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT, 
            headers={"Location": "/login"}
        )
    return user

async def admin_required(user: User = Depends(login_required)):
    """
    Guard dependency that restricts access to users with the 'Admin' role.
    """
    if user.role != "Admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user