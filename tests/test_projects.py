# tests/test_projects.py
from app.models import Project, Experiment

def test_project_lifecycle(client, user_token, session):
    client.cookies.set("access_token", user_token)

    # 1. Create Project
    client.post("/projects/create", data={"name": "Cancer Research"})
    project = session.exec(select(Project)).first()

    # 2. Add Experiment to Canvas
    client.post("/experiments/create", data={
        "name": "Western Blot 1", "project_id": project.id, "description": "Initial check"
    })
    exp = session.exec(select(Experiment)).first()
    assert exp.project_id == project.id

    # 3. Move Experiment (API)
    response = client.post("/api/experiment/move", json={
        "id": exp.id, "x": 100, "y": 200
    })
    assert response.json()["status"] == "success"
    
    session.refresh(exp)
    assert exp.pos_x == 100