# tests/test_auth.py
from app.models import User, InviteCode, Lab

def test_login_success(client, user_token):
    # We test the endpoint logic, not the UI rendering
    response = client.get("/", cookies={"access_token": user_token})
    assert response.status_code == 200

def test_login_failure(client):
    response = client.post("/login", data={"username": "wrong", "password": "wrong"})
    assert "Invalid credentials" in response.text

def test_registration_flow(client, session):
    """Test full registration lifecycle with invite codes."""
    # 1. First user becomes Admin automatically (no code needed)
    client.post("/register", data={"username": "admin1", "password": "password123"})
    assert session.exec(select(User).where(User.username == "admin1")).first().role == "Admin"

    # 2. Setup invite code
    code = InviteCode(code="INVITE123", created_by="admin1")
    session.add(code)
    session.commit()

    # 3. Second user needs code
    response = client.post("/register", data={
        "username": "user2", "password": "password123", "invite_code": "WRONG"
    })
    assert "Invalid or used Invite Code" in response.text

    # 4. Correct code works
    response = client.post("/register", data={
        "username": "user2", "password": "password123", "invite_code": "INVITE123"
    })
    assert response.status_code == 303 # Redirect to login
    
    # 5. Code is now used
    response = client.post("/register", data={
        "username": "user3", "password": "password123", "invite_code": "INVITE123"
    })
    assert "Invalid or used Invite Code" in response.text