# tests/conftest.py
import os
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlalchemy.pool import StaticPool

# --- 1. ENVIRONMENT (MUST BE ABSOLUTE TOP) ---
os.environ["IS_TESTING"] = "true" 
os.environ["APP_ENV"] = "testing"
os.environ["DEV_TENANT"] = "testlab" 
os.environ["LIMS_SECRET"] = "test_secret_key"

# --- 2. IMPORTS ---
from app import app # Import directly from the package
from app.dependencies import get_session, limiter
from app.models import User, Lab, Freezer, Box
from app.utils.security import get_password_hash, create_access_token

TEST_LAB_NAME = "testlab"

limiter.enabled = False

@pytest.fixture(name="session")
def session_fixture():
    """Creates a fresh in-memory SQLite database for each test."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    
    with Session(engine) as session:
        # Seed core tenant data
        session.add(Lab(name="Test Lab", location="Room 101", user_limit=2))
        fridge = Freezer(name="Test Fridge", location="Hallway")
        session.add(fridge)
        session.commit()
        session.refresh(fridge)
        
        session.add(Box(name="Box A1", freezer_id=fridge.id, rows=9, cols=9))
        session.commit()
        yield session
    
    SQLModel.metadata.drop_all(engine)

@pytest.fixture(name="client")
def client_fixture(session: Session):
    """Returns a TestClient with the database session overridden."""
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app, base_url=f"http://{TEST_LAB_NAME}.localhost")
    yield client
    app.dependency_overrides.clear()

@pytest.fixture(name="admin_token")
def admin_token_fixture(session: Session):
    """Creates an Admin and returns their access token."""
    user = User(username="admin_joe", hashed_password=get_password_hash("pass123"), role="Admin")
    session.add(user)
    session.commit()
    return create_access_token({"sub": "admin_joe"}, lab_name=TEST_LAB_NAME)

@pytest.fixture(name="user_token")
def user_token_fixture(session: Session):
    """Creates a regular User and returns their access token."""
    user = User(username="user_jane", hashed_password=get_password_hash("pass123"), role="User")
    session.add(user)
    session.commit()
    return create_access_token({"sub": "user_jane"}, lab_name=TEST_LAB_NAME)