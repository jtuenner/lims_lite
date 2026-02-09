# tests/test_storage.py
from app.models import Box, Sample
from sqlmodel import select

def test_add_sample_collision(client, user_token, session):
    client.cookies.set("access_token", user_token)
    box = session.exec(select(Box)).first()

    # 1. Add sample to A1 (1,1)
    response = client.post(f"/box/{box.id}/add_sample", data={
        "name": "Sample A", "row": 1, "col": 1, "sample_type": "DNA"
    }, follow_redirects=False) # ADD THIS: Stop at the 303 redirect
    
    assert response.status_code == 303 # This will now pass

    # 2. Try adding to same slot
    # Here, we WANT to see the error message in the response text (200 OK)
    response = client.post(f"/box/{box.id}/add_sample", data={
        "name": "Sample B", "row": 1, "col": 1, "sample_type": "DNA"
    })
    assert "Slot occupied" in response.text

def test_sample_lineage(client, user_token, session):
    """Test Parent -> Child relationship."""
    client.cookies.set("access_token", user_token)
    box = session.exec(select(Box)).first()

    # Create Parent
    client.post(f"/box/{box.id}/add_sample", data={
        "name": "Parent Cell", "row": 1, "col": 1, "sample_type": "Cell Line"
    })
    parent = session.exec(select(Sample).where(Sample.name == "Parent Cell")).first()

    # Create Child linked to Parent
    client.post(f"/box/{box.id}/add_sample", data={
        "name": "Child Clone", "row": 1, "col": 2, "sample_type": "Cell Line",
        "parent_ids": str(parent.id)
    })
    
    child = session.exec(select(Sample).where(Sample.name == "Child Clone")).first()
    assert child.parents[0].id == parent.id