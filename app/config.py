# app/config.py
import os
from pathlib import Path

# --- CORE SETTINGS ---
# Environment: 'development' or 'production'
APP_ENV = os.environ.get("APP_ENV", "development")
DEV_TENANT = os.environ.get("DEV_TENANT", "devlab")

IS_TESTING = os.environ.get("IS_TESTING", "false").lower() == "true"

# Security: Secret key for JWT and session signing
SECRET_KEY = os.environ.get("LIMS_SECRET")
if not SECRET_KEY:
    if APP_ENV == "production":
        raise RuntimeError("LIMS_SECRET environment variable is not set!")
    SECRET_KEY = "dev_only_secret"  # Fallback for local testing only

ALGORITHM = "HS256"

# --- DOMAIN & NETWORKING ---
# Base URL used for generating deep-links in QR codes
BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")

# Allowed hosts for production security
if APP_ENV == "production":
    ALLOWED_HOSTS = ["*.limslite.com", "limslite.com"]
else:
    ALLOWED_HOSTS = ["*"]

# --- MULTI-TENANCY & STORAGE ---
# Database and file system paths
DB_FOLDER = os.environ.get("DB_FOLDER", "customer_dbs")
UPLOAD_BASE = os.environ.get("UPLOAD_BASE", "uploads")
BACKUP_DIR = os.environ.get("BACKUP_DIR", "backups")

# --- LICENSING & LIMITS ---
# Default user seat limit per lab instance
LICENSE_LIMIT = int(os.environ.get("LICENSE_LIMIT", 5))

# Maximum allowed file upload size (default 10MB)
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", 10 * 1024 * 1024))

# --- FILE SECURITY ---
# Whitelist of allowed file extensions for uploads
ALLOWED_EXTENSIONS = {
    '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.webp',  # Documents and images
    '.xlsx', '.xls', '.csv', '.tsv',                  # Spreadsheets
    '.txt', '.md', '.docx', '.doc',                  # Text files
    '.zip'                                           # Archives
}

# --- INITIALIZATION ---
# Ensure required directories exist on the server
for folder in [DB_FOLDER, UPLOAD_BASE, BACKUP_DIR, "logs"]:
    os.makedirs(folder, exist_ok=True)