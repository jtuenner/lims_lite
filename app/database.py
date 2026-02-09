# app/database.py
import os
import re
from typing import Generator, Optional
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, Session, create_engine, select

# Import configuration and models
from app.config import DB_FOLDER, APP_ENV
from app.models import Freezer, Lab

def get_db_path(lab_name: str) -> str:
    """Constructs the absolute path to a tenant's SQLite database file."""
    return os.path.join(DB_FOLDER, f"{lab_name}.db")

def get_engine(lab_name: str):
    """
    Creates a SQLAlchemy engine for a specific tenant.
    Uses StaticPool to maintain a single connection for SQLite 
    across multiple threads, which is necessary for multi-tenant file access.
    """
    db_path = get_db_path(lab_name)
    sqlite_url = f"sqlite:///{db_path}"
    
    return create_engine(
        sqlite_url, 
        connect_args={"check_same_thread": False}, 
        poolclass=StaticPool
    )

def seed_defaults(session: Session, lab_name: str):
    """
    Seeds a brand new lab database with default equipment and configuration.
    This ensures new tenants have a working environment immediately.
    """
    # Check if a Freezer already exists to avoid duplicate seeding
    if not session.exec(select(Freezer)).first():
        session.add(Freezer(name="Main Fridge (-20°C)", location="Hallway"))
        session.add(Lab(
            name=f"{lab_name.capitalize()} Lab", 
            location="Main Hall", 
            resources="Bench 1, Microscope, Centrifuge"
        ))
        session.commit()

def init_tenant_db(lab_name: str):
    """
    Ensures the database tables exist and are seeded for a specific tenant.
    This is called dynamically when a user accesses a subdomain.
    """
    engine = get_engine(lab_name)
    
    # Create all tables defined in models.py
    SQLModel.metadata.create_all(engine)
    
    with Session(engine) as session:
        seed_defaults(session, lab_name)

def get_tenant_session(lab_name: str) -> Generator[Session, None, None]:
    """
    Yields a database session scoped to a specific lab tenant.
    This is the core of the multi-tenancy system.
    """
    # Ensure the DB is ready before yielding the session
    init_tenant_db(lab_name)
    
    engine = get_engine(lab_name)
    with Session(engine) as session:
        yield session