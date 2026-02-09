# app/utils/logging.py
import logging
import sys
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime
from sqlmodel import Session

# Import models and config from your new structure
from app.models import AuditLog, User
from app.config import APP_ENV

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

def setup_logging():
    """
    Configures application-wide logging with both file and console handlers.
    Logic migrated from original main.py.
    """
    # Determine log level based on environment
    log_level = logging.DEBUG if APP_ENV == "development" else logging.INFO
    
    # Define standard format for log entries
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler: Rotates after 10MB, keeps 5 old logs
    file_handler = RotatingFileHandler(
        'logs/lims.log',
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    
    # Console handler: Outputs to standard out
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    
    # Configure the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Reduce noise from underlying libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    
    return logging.getLogger(__name__)

# Initialize the application logger
logger = setup_logging()

def log_action(
    session: Session, 
    action: str, 
    user: User, 
    details: str = "", 
    sample_id: int = None, 
    consumable_id: int = None
):
    """
    Records a high-level action into the database AuditLog for tracking changes.
    Logic migrated from original main.py.
    """
    new_log = AuditLog(
        action=action, 
        user_name=user.username, 
        details=details, 
        sample_id=sample_id, 
        consumable_id=consumable_id,
        timestamp=datetime.now()
    )
    session.add(new_log)
    session.commit()