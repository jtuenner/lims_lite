# tests/test_inventory.py
from app.models import Consumable, OrderRequest
from sqlmodel import select

def test_create_and_search_item(client, user_token):
    # Create
    client.cookies.set("access_token", user_token)
    client.post("/inventory/create", data={
        "name": "Ethanol 70%", "category": "Reagents", "quantity": 5, 
        "unit": "L", "location": "Flammables Cabinet", "min_level": 2
    })
    
    # Search
    response = client.get("/search?q=Ethanol")
    assert "Ethanol 70%" in response.text

def test_procurement_workflow(client, admin_token, session):
    """Test User Request -> Admin Approve -> Auto-Restock."""
    client.cookies.set("access_token", admin_token)
    
    # 1. Create Request
    client.post("/orders/request", data={
        "item_name": "New Antibody", "qty": 2, "reason": "Experiment X"
    })
    order = session.exec(select(OrderRequest)).first()
    assert order.status == "Pending"

    # 2. Admin Receives Order (Auto-restock trigger)
    client.post("/orders/update_status", data={
        "req_id": order.id, "status": "Received"
    })
    
    # 3. Verify Item was automatically created in inventory
    item = session.exec(select(Consumable).where(Consumable.name == "New Antibody")).first()
    assert item is not None
    assert item.quantity == 2