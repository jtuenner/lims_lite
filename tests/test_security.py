# tests/test_security.py
import pytest
from app.models import User
from app.utils.security import create_access_token
from sqlmodel import select

def test_cross_tenant_isolation(client, session):
    """
    Scenario: User 'hacker' from 'evil_lab' tries to access 'testlab' data.
    """
    # Create a user who belongs to 'evil_lab'
    hacker_token = create_access_token({"sub": "hacker"}, lab_name="evil_lab")
    
    client.cookies.set("access_token", hacker_token)
    
    # Try to access inventory of 'testlab' (client base_url is testlab.localhost)
    response = client.get("/inventory", follow_redirects=False)
    
    # Should be redirected to login because the token scope mismatch
    assert response.status_code in [303, 307]
    assert "/login" in response.headers["location"]

def test_admin_route_protection(client, user_token):
    """Standard user cannot access admin panel."""
    # Add the Bearer prefix to the cookie
    client.cookies.set("access_token", f"Bearer {user_token}")
    
    # Add the trailing slash to avoid the 307 redirect to /admin/
    response = client.get("/admin/", follow_redirects=False)
    
    assert response.status_code == 403