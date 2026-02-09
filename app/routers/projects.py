# app/routers/projects.py
import json
import os
import shutil
import random
from datetime import datetime
from fastapi import APIRouter, Depends, Form, Body, Request, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select, and_

# Import models, dependencies, and utilities
from app.models import Project, Experiment, ExperimentLink, ExperimentTemplate, Lab, Attachment, Sample, User
from app.dependencies import get_session, login_required, templates, get_lab_name, get_upload_dir
from app.utils.security import validate_and_secure_filename # Assuming this utility exists

router = APIRouter(tags=["projects"])

# --- PROJECT ROUTES ---

@router.get("/projects", response_class=HTMLResponse)
async def projects_list(
    request: Request, 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Renders the list of all active research projects."""
    projects = session.exec(select(Project)).all()
    return templates.TemplateResponse("projects_list.html", {
        "request": request, 
        "projects": projects, 
        "user": user
    })

@router.get("/projects/{project_id}", response_class=HTMLResponse)
async def view_project(
    request: Request, 
    project_id: int, 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Renders the experiment canvas view for a specific project."""
    project = session.get(Project, project_id)
    if not project:
        return RedirectResponse("/projects")
    
    # Load related data for the canvas
    labs = session.exec(select(Lab)).all()
    lab_resources = {l.id: [r.strip() for r in l.resources.split(',')] if l.resources else [] for l in labs}
    links = session.exec(select(ExperimentLink).where(ExperimentLink.project_id == project_id)).all()
    tmpls = session.exec(select(ExperimentTemplate)).all()
    
    # Ensure relationships are loaded for the template
    for exp in project.experiments: 
        for s in exp.samples: _ = s.box 
        _ = exp.bookings
        _ = exp.attachments
        
    return templates.TemplateResponse("project_view.html", {
        "request": request, 
        "project": project, 
        "user": user, 
        "labs": labs, 
        "lab_resources": lab_resources, 
        "links": links, 
        "templates": tmpls
    })

@router.post("/projects/create")
async def create_project(
    name: str = Form(...), 
    description: str = Form(None), 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Creates a new research project."""
    session.add(Project(name=name, description=description, owner=user.username))
    session.commit()
    return RedirectResponse(url="/projects", status_code=303)

# --- EXPERIMENT CANVAS ROUTES ---

@router.post("/experiments/create")
async def create_experiment(
    name: str = Form(...), 
    project_id: int = Form(...), 
    description: str = Form(None), 
    template_id: int = Form(0), 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Adds a new experiment card to the project canvas, optionally loading from a template."""
    protocol_content = None
    if template_id > 0:
        tmpl = session.get(ExperimentTemplate, template_id)
        if tmpl:
            description = description or tmpl.description
            protocol_content = tmpl.protocol
            
    session.add(Experiment(
        name=name, 
        project_id=project_id, 
        description=description, 
        protocol=protocol_content, 
        pos_x=random.randint(50, 400), 
        pos_y=random.randint(50, 300)
    ))
    session.commit()
    return RedirectResponse(url=f"/projects/{project_id}", status_code=303)

@router.post("/api/experiment/move")
async def move_experiment_api(
    id: int = Body(...), 
    x: int = Body(...), 
    y: int = Body(...), 
    session: Session = Depends(get_session)
):
    """Updates the X/Y coordinates of an experiment card on the canvas."""
    exp = session.get(Experiment, id)
    if exp:
        exp.pos_x = x
        exp.pos_y = y
        session.add(exp)
        session.commit()
        return {"status": "success"}
    return {"status": "error"}

@router.post("/api/experiment/update_details")
async def update_experiment_details(
    id: int = Body(...), 
    description: str = Body(...), 
    protocol: str = Body(...), 
    status: str = Body(...), 
    date: str = Body(None), 
    session: Session = Depends(get_session)
):
    """Updates the core details and protocol of an experiment."""
    exp = session.get(Experiment, id)
    if exp: 
        exp.description = description
        exp.protocol = protocol
        exp.status = status
        if date:
            exp.date = datetime.fromisoformat(date)
        session.add(exp)
        session.commit()
        return {"status": "success"}
    return {"status": "error"}

@router.post("/api/experiment/link")
async def link_experiment_api(
    project_id: int = Body(...), 
    source_id: int = Body(...), 
    target_id: int = Body(...), 
    session: Session = Depends(get_session)
):
    """Creates a visual and logical link between two experiments."""
    session.add(ExperimentLink(project_id=project_id, source_id=source_id, target_id=target_id))
    session.commit()
    return {"status": "success"}

# --- PROTOCOL EXECUTION & REPORTING ---

@router.get("/experiment/{id}/run", response_class=HTMLResponse)
async def run_experiment_view(
    request: Request, 
    id: int, 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Renders the step-by-step interactive protocol execution view."""
    exp = session.get(Experiment, id)
    if not exp:
        raise HTTPException(status_code=404)
    
    # Parse the protocol text into discrete steps
    steps = [line.strip() for line in (exp.protocol or "").split('\n') if line.strip()]
    
    progress = {}
    if exp.progress_json:
        try:
            progress = json.loads(exp.progress_json)
        except json.JSONDecodeError:
            progress = {}

    return templates.TemplateResponse("run_protocol.html", {
        "request": request, 
        "exp": exp, 
        "steps": steps, 
        "progress": progress,
        "user": user
    })

@router.post("/api/experiment/save_progress")
async def save_experiment_progress(
    exp_id: int = Body(...), 
    progress: str = Body(...), 
    session: Session = Depends(get_session)
):
    """Autosaves the current progress and notes from an active protocol run."""
    exp = session.get(Experiment, exp_id)
    if not exp:
        return {"status": "error"}
    
    exp.progress_json = progress
    exp.status = "In Progress"
    session.add(exp)
    session.commit()
    return {"status": "success"}

@router.get("/experiments/{experiment_id}/report", response_class=HTMLResponse)
async def generate_experiment_report(
    request: Request, 
    experiment_id: int, 
    session: Session = Depends(get_session)
):
    """Generates a printable summary report of the experiment."""
    exp = session.get(Experiment, experiment_id)
    if not exp:
        raise HTTPException(status_code=404, detail="Experiment not found")
    return templates.TemplateResponse("experiment_report.html", {"request": request, "exp": exp})

# --- SAMPLES & ATTACHMENTS ---

@router.post("/api/experiment/add_sample")
async def add_sample_to_exp(
    experiment_id: int = Body(...), 
    sample_id: int = Body(...), 
    session: Session = Depends(get_session)
):
    """Links an existing sample to an experiment."""
    s = session.get(Sample, sample_id)
    if s:
        s.experiment_id = experiment_id
        session.add(s)
        session.commit()
        return {"status": "success", "name": s.name, "loc": s.box.name if s.box else "Unboxed"}
    return {"status": "error"}

@router.post("/api/experiment/upload")
async def upload_experiment_file(
    request: Request,
    experiment_id: int = Form(...),
    file: UploadFile = File(...),
    session: Session = Depends(get_session)
):
    """Securely uploads and attaches a document or image to an experiment."""
    secured_filename = validate_and_secure_filename(file)
    tenant = get_lab_name(request)
    upload_dir = get_upload_dir(tenant)
    
    file_path = os.path.join(upload_dir, secured_filename)
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    
    attachment = Attachment(
        filename=secured_filename,
        filepath=f"{tenant}/{secured_filename}",
        experiment_id=experiment_id
    )
    session.add(attachment)
    session.commit()
    return {"status": "success", "filename": secured_filename}