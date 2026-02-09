# app/utils/tasks.py
import os
import glob
import time
import zipfile
import logging
from datetime import datetime, timedelta
from sqlmodel import Session, select, and_

# Import configuration and models from your new structure
from app.config import DB_FOLDER, BACKUP_DIR, UPLOAD_BASE
from app.models import Booking, User

logger = logging.getLogger(__name__)

def create_lab_backup(lab_name: str, prefix="auto"):
    """
    Zips the specific lab's database and upload folder.
    This logic is centralized here so it can be called by both the 
    background scheduler and the admin router.
    """
    db_path = os.path.join(DB_FOLDER, f"{lab_name}.db")
    if not os.path.exists(db_path):
        return None
    
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"backup_{lab_name}_{prefix}_{timestamp}.zip"
    filepath = os.path.join(BACKUP_DIR, filename)
    
    # Ensure the backup directory exists
    os.makedirs(BACKUP_DIR, exist_ok=True)
    
    with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add Database (renamed for portability within the archive)
        zipf.write(db_path, arcname="database.db")
        
        # Add Lab-specific Uploads
        lab_upload_dir = os.path.join(UPLOAD_BASE, lab_name)
        if os.path.exists(lab_upload_dir):
            for root, dirs, files in os.walk(lab_upload_dir):
                for file in files:
                    # Store files relative to the lab's upload root
                    rel_path = os.path.relpath(os.path.join(root, file), UPLOAD_BASE)
                    zipf.write(os.path.join(root, file), arcname=os.path.join("uploads", rel_path))
                
    return filename

def run_scheduler():
    """
    Background loop that runs daily maintenance tasks for all tenants.
    Logic migrated from the original main.py background thread.
    """
    logger.info("--- Backup Scheduler Started ---")
    while True:
        now = datetime.now()
        
        # Maintenance window: Run at 03:00 AM daily
        if now.hour == 3 and now.minute == 0:
            logger.info(f"[{now}] Running Global Auto-Backup and Pruning...")
            
            # 1. Iterate all tenant databases found in the folder
            db_files = glob.glob(os.path.join(DB_FOLDER, "*.db"))
            for db_file in db_files:
                lab_name = os.path.basename(db_file).replace(".db", "")
                try:
                    create_lab_backup(lab_name, "daily")
                except Exception as e:
                    logger.error(f"Failed to backup tenant {lab_name}: {e}")
            
            # 2. Prune old backups (Keep the last 100 zip files total)
            try:
                backups = sorted(
                    glob.glob(os.path.join(BACKUP_DIR, "*.zip")), 
                    key=os.path.getmtime
                )
                while len(backups) > 100:
                    os.remove(backups.pop(0))
            except Exception as e:
                logger.error(f"Failed to prune old backups: {e}")
            
            # Sleep extra to ensure the 03:00 window is passed
            time.sleep(65)
        else:
            # Check the clock every minute
            time.sleep(60)

def update_biomass_score(session: Session, user: User):
    """
    Calculates and updates a user's gamification score (petri_score)
    based on their lab activity over the last 7 days.
    """
    today = datetime.now()
    
    # Identify the start of the current week (Monday at midnight)
    start = today - timedelta(days=today.weekday())
    start = start.replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=7)
    
    # Query all bookings for this user within the week
    bookings = session.exec(
        select(Booking).where(and_(
            Booking.user_name == user.username, 
            Booking.start_time >= start, 
            Booking.start_time < end
        ))
    ).all()
    
    # Sum the duration of all bookings that have already finished
    total_minutes = 0
    for b in bookings:
        if b.end_time < today:
            duration = (b.end_time - b.start_time).total_seconds() / 60
            total_minutes += duration
    
    # Update score: Base of 10 plus 1 point per 3 minutes of activity
    user.petri_score = max(10, int(total_minutes / 3))
    session.add(user)
    session.commit()