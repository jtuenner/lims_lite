# app/utils/security.py
import os
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from werkzeug.utils import secure_filename
from fastapi import UploadFile, HTTPException

# Import configuration from your new structure
from app.config import (
    SECRET_KEY, 
    ALGORITHM, 
    ALLOWED_EXTENSIONS, 
    MAX_FILE_SIZE
)

# --- PASSWORD HASHING ---
# Using Argon2 as the primary hasher with bcrypt fallback for legacy support
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto",
    argon2__memory_cost=65536,  # 64 MB
    argon2__time_cost=3,
    argon2__parallelism=4
)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain text password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generates a secure Argon2 hash for a password."""
    return pwd_context.hash(password)

def needs_rehash(hashed: str) -> bool:
    """Checks if a hash was created with a deprecated scheme."""
    return pwd_context.needs_update(hashed)

# --- JWT TOKEN LOGIC ---

def create_access_token(data: dict, lab_name: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a JWT access token scoped to a specific lab tenant.
    This ensures that a token for 'Lab A' cannot be used to access 'Lab B'.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=7)
    
    # Critical security fix: Include the lab scope (tenant) in the token
    to_encode.update({
        "exp": expire,
        "scope": lab_name
    })
    
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- FILE SECURITY & VALIDATION ---

def validate_and_secure_filename(file: UploadFile) -> str:
    """
    Validates file uploads to prevent security issues and returns a safe filename.
    Checks:
    1. File size limits.
    2. Allowed file extensions.
    3. Filename sanitation (prevents directory traversal).
    """
    # 1. Check file size
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
    
    # 2. Check extension against whitelist
    filename = file.filename or "unnamed"
    ext = os.path.splitext(filename)[1].lower()
    
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400, 
            detail=f"File type '{ext}' not allowed."
        )
    
    # 3. Secure the filename to prevent path traversal
    sanitized_name = secure_filename(filename)
    
    # 4. Append timestamp to ensure uniqueness and prevent overwriting
    name, ext = os.path.splitext(sanitized_name)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{name}_{timestamp}{ext}"