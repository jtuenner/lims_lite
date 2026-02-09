# tests/conftest.py
import pytest
import os
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlalchemy.pool import StaticPool

# Import your app and key dependencies
from main import app
from app.dependencies import get_session, get_current_user
from app.models import User, Lab
from app.utils.security import get_password_hash, create_access_token

from fastapi.testclient import TestClient

os.environ["IS_TESTING"] = "true" 
os.environ["APP_ENV"] = "testing"

# 1. Setup a standard "Test Lab" for all tests
TEST_LAB_NAME = "testlab"

# 2. Create an in-memory SQLite database (fast & disposable)
# We use StaticPool to share the same connection across threads/requests
engine = create_engine(
    "sqlite://", 
    connect_args={"check_same_thread": False}, 
    poolclass=StaticPool
)

@pytest.fixture(name="session")
def session_fixture():
    """Creates a new database session for a test and rolls it back afterwards."""
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        # Seed required data
        session.add(Lab(name="Test Lab", location="Test Room", user_limit=10))
        session.commit()
        yield session
    SQLModel.metadata.drop_all(engine)

@pytest.fixture(name="client")
def client_fixture(session: Session):
    """
    Returns a TestClient that forces the app to use our TEST database
    instead of looking for real files on disk.
    """
    
    # OVERRIDE the get_session dependency to use our in-memory DB
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    
    # Create the client with a fake host to trigger tenant detection
    client = TestClient(app, base_url=f"http://{TEST_LAB_NAME}.localhost")
    yield client
    
    # Clean up overrides
    app.dependency_overrides.clear()

@pytest.fixture(name="auth_headers")
def auth_headers_fixture(client, session):
    """Creates a test user and returns a valid JWT token header."""
    user = User(
        username="tester", 
        hashed_password=get_password_hash("password123"),
        role="Admin"
    )
    session.add(user)
    session.commit()
    
    # Generate token for the test tenant
    token = create_access_token({"sub": "tester"}, lab_name=TEST_LAB_NAME)
    
    return token