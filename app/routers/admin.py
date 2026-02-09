# app/routers/admin.py
import os
import glob
import uuid
import zipfile
import shutil
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, Form, HTTPException, Request, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from sqlmodel import Session, select, func

# Import models, dependencies, and config from your new modules
from app.models import User, InviteCode, Lab
from app.dependencies import admin_required, get_session, get_lab_name, templates
from app.config import LICENSE_LIMIT, BACKUP_DIR, DB_FOLDER, UPLOAD_BASE

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(admin_required)]
)

# --- BACKUP HELPERS ---
def create_lab_backup(lab_name: str, prefix="auto"):
    """
    Zips the specific lab's database and upload folder. 
    Logic migrated from original main.py.
    """
    db_path = os.path.join(DB_FOLDER, f"{lab_name}.db")
    if not os.path.exists(db_path):
        return None
    
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"backup_{lab_name}_{prefix}_{timestamp}.zip"
    filepath = os.path.join(BACKUP_DIR, filename)
    
    with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add Database
        zipf.write(db_path, arcname="database.db")
        
        # Add Uploads
        lab_upload_dir = os.path.join(UPLOAD_BASE, lab_name)
        for root, dirs, files in os.walk(lab_upload_dir):
            for file in files:
                rel_path = os.path.relpath(os.path.join(root, file), UPLOAD_BASE)
                zipf.write(os.path.join(root, file), arcname=os.path.join("uploads", rel_path))
                
    return filename

# --- ADMIN ROUTES ---

@router.get("/", response_class=HTMLResponse)
async def admin_page(request: Request, user: User = Depends(admin_required), session: Session = Depends(get_session)):
    """Renders the admin management panel."""
    invites = session.exec(select(InviteCode).where(InviteCode.is_used == False)).all()
    users = session.exec(select(User)).all()
    
    lab_name = get_lab_name(request)
    backups = []
    
    # Locate tenant-specific backups
    pattern = os.path.join(BACKUP_DIR, f"backup_{lab_name}_*.zip")
    for path in sorted(glob.glob(pattern), reverse=True):
        stat = os.stat(path)
        backups.append({
            "name": os.path.basename(path),
            "size": f"{stat.st_size / 1024 / 1024:.2f} MB",
            "time": datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
        })

    return templates.TemplateResponse("admin.html", {
        "request": request, 
        "user": user, 
        "invites": invites, 
        "users": users, 
        "limit": LICENSE_LIMIT, 
        "usage": (len(users) / LICENSE_LIMIT) * 100,
        "backups": backups
    })

@router.post("/generate_invite")
async def generate_invite(user: User = Depends(admin_required), session: Session = Depends(get_session)):
    """Generates a unique invite code if the license limit is not reached."""
    if session.exec(select(func.count(User.id))).one() >= LICENSE_LIMIT:
        return RedirectResponse("/admin", status_code=303)
        
    session.add(InviteCode(code=str(uuid.uuid4())[:8].upper(), created_by=user.username))
    session.commit()
    return RedirectResponse("/admin", status_code=303)

@router.post("/delete_user")
async def delete_user(user_id: int = Form(...), admin: User = Depends(admin_required), session: Session = Depends(get_session)):
    """Removes a user from the system, excluding the current admin."""
    u = session.get(User, user_id)
    if u and u.id != admin.id:
        session.delete(u)
        session.commit()
    return RedirectResponse("/admin", status_code=303)

@router.post("/toggle_role")
async def toggle_user_role(user_id: int = Form(...), admin: User = Depends(admin_required), session: Session = Depends(get_session)):
    """Promotes or demotes a user between 'User' and 'Admin' roles."""
    u = session.get(User, user_id)
    if u and u.id != admin.id:
        u.role = "User" if u.role == "Admin" else "Admin"
        session.add(u)
        session.commit()
    return RedirectResponse("/admin", status_code=303)

# --- BACKUP ROUTES ---

@router.post("/backup/create")
async def manual_backup(request: Request):
    """Triggers a manual backup for the current lab tenant."""
    create_lab_backup(get_lab_name(request), "manual")
    return RedirectResponse("/admin", status_code=303)

@router.get("/backup/download/{filename}")
async def download_backup(filename: str):
    """Securely serves a backup zip file for download."""
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Backup file not found")
    return FileResponse(path, filename=filename)

@router.post("/backup/restore_local")
async def restore_local(request: Request, filename: str = Form(...), session: Session = Depends(get_session)):
    """
    Restores the lab's state from a locally stored backup file. 
    Warning: This overwrites current data.
    """
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Restore file not found")
    
    lab_name = get_lab_name(request)
    db_path = os.path.join(DB_FOLDER, f"{lab_name}.db")
    upload_dir = os.path.join(UPLOAD_BASE, lab_name)
    
    session.close() # Close connection to allow file overwrite
    
    try:
        with zipfile.ZipFile(path, 'r') as zipf:
            zipf.extract("database.db", path="temp_restore")
            shutil.move("temp_restore/database.db", db_path)
            
            # Extract and move uploads
            for file in zipf.namelist():
                if file.startswith("uploads/"):
                    zipf.extract(file, path="temp_restore")
            
            tenant_upload_src = f"temp_restore/uploads/{lab_name}"
            if os.path.exists(tenant_upload_src):
                if os.path.exists(upload_dir):
                    shutil.rmtree(upload_dir)
                shutil.move(tenant_upload_src, upload_dir)
                
            shutil.rmtree("temp_restore", ignore_errors=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Restore failed: {str(e)}")
        
    return RedirectResponse("/", status_code=303)

@router.post("/backup/restore")
async def restore_upload(request: Request, file: UploadFile = File(...), session: Session = Depends(get_session)):
    """Restores data from a zip file uploaded by the administrator."""
    temp_name = f"temp_{get_lab_name(request)}.zip"
    temp_path = os.path.join(BACKUP_DIR, temp_name)
    
    with open(temp_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
        
    return await restore_local(request, temp_name, session)