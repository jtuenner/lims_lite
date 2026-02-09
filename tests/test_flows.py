# tests/test_flows.py

def test_landing_page(client):
    """Test that the landing page loads on the root domain."""
    # Note: We use a "www" base_url to simulate no subdomain
    response = client.get("http://localhost/")
    assert response.status_code == 200
    assert "LIMS Lite" in response.text

def test_create_lab_flow(client):
    """Test the lab creation logic."""
    response = client.post("http://localhost/create_lab", data={
        "lab_name": "newstartuplab",
        "licenses": 5
    })
    assert response.status_code == 200
    assert "Lab Created" in response.text

def test_inventory_flow(client, auth_headers):
    """Test the full inventory lifecycle."""
    # Create item
    response = client.post(
        "/inventory/create",
        data={
            "name": "Test Beaker",
            "category": "Glassware",
            "quantity": 10,
            "unit": "pcs",
            "location": "Shelf A",
            "min_level": 2
        },
        cookies={"access_token": auth_headers},
        follow_redirects=False # Crucial for verifying the 303 redirect
    )
    assert response.status_code == 303 
    assert "/inventory" in response.headers["location"]

def test_security_isolation(client, session):
    """Ensure an unauthenticated user is redirected to login."""
    # Add follow_redirects=False
    response = client.get("/inventory", follow_redirects=False)
    
    # Now it will correctly see the 307 redirect
    assert response.status_code in [303, 307]
    assert "/login" in response.headers["location"]