# app/routers/files.py
import os
import mimetypes
from pathlib import Path
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import FileResponse

from app.config import UPLOAD_BASE
from app.models import User
from app.dependencies import get_session, login_required, get_lab_name, logger

router = APIRouter(tags=["files"])

@router.get("/files/{tenant}/{filename:path}")
async def serve_file(
    tenant: str, 
    filename: str, 
    request: Request,
    user: User = Depends(login_required)
):
    """
    Securely serves files only to authenticated users of the correct tenant.
    Prevents directory traversal and cross-tenant data leakage.
    """
    current_tenant = get_lab_name(request)
    if tenant != current_tenant:
        raise HTTPException(status_code=403, detail="Access denied to this tenant's files")
    
    file_path = os.path.join(UPLOAD_BASE, tenant, filename)
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    # Security: Verify real path to prevent traversal attacks (../)
    real_path = os.path.realpath(file_path)
    base_path = os.path.realpath(os.path.join(UPLOAD_BASE, tenant))
    
    if not real_path.startswith(base_path):
        logger.warning(f"Directory traversal attempt: {filename} by {user.username}")
        raise HTTPException(status_code=403, detail="Invalid file path")
    
    content_type, _ = mimetypes.guess_type(file_path)
    return FileResponse(
        file_path, 
        media_type=content_type or "application/octet-stream",
        filename=Path(filename).name
    )