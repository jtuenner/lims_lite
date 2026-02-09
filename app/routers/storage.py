# app/routers/storage.py
import io
import csv
import qrcode
from io import BytesIO
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Form, Body, Request, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from sqlmodel import Session, select, or_, and_

# Import models, dependencies, and utilities
from app.models import Box, Sample, Freezer, Experiment, SampleLineageLink, User
from app.dependencies import get_session, login_required, admin_required, templates, get_lab_name
from app.utils.logging import log_action
from app.config import BASE_URL

router = APIRouter(tags=["storage"])

# --- BOX & GRID VIEWS ---

@router.get("/box/{box_id}", response_class=HTMLResponse)
async def view_box(
    request: Request, 
    box_id: int, 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Renders the interactive grid view for a specific storage box."""
    box = session.get(Box, box_id)
    if not box:
        raise HTTPException(status_code=404)
    
    experiments = session.exec(select(Experiment)).all()
    # Map samples to their grid coordinates for the template
    grid_map = {(s.row_idx, s.col_idx): s for s in box.samples}
    
    # Ensure relationships are loaded
    for s in box.samples: 
        _ = s.parents 
        _ = s.children
        
    return templates.TemplateResponse("box_view.html", {
        "request": request, 
        "box": box, 
        "grid_map": grid_map, 
        "experiments": experiments, 
        "user": user
    })

# --- FREEZER & BOX MANAGEMENT ---

@router.post("/freezer/create")
async def create_freezer(
    name: str = Form(...), 
    location: str = Form(...), 
    user: User = Depends(admin_required), 
    session: Session = Depends(get_session)
): 
    """Creates a new freezer or fridge storage unit."""
    session.add(Freezer(name=name, location=location))
    session.commit()
    return RedirectResponse("/", status_code=303)

@router.post("/box/create")
async def create_box(
    name: str = Form(...), 
    freezer_id: int = Form(...), 
    rows: int = Form(9), 
    cols: int = Form(9), 
    shelf: str = Form(...), 
    color: str = Form(...), 
    icon: str = Form(...), 
    label_text: str = Form(None), 
    user: User = Depends(admin_required), 
    session: Session = Depends(get_session)
): 
    """Creates a new storage box within a freezer unit."""
    session.add(Box(
        name=name, rows=rows, cols=cols, freezer_id=freezer_id, 
        shelf=shelf, color=color, icon=icon, label_text=label_text
    ))
    session.commit()
    return RedirectResponse("/", status_code=303)

@router.post("/box/update")
async def update_box(
    box_id: int = Form(...), 
    name: str = Form(...), 
    shelf: str = Form(...), 
    color: str = Form(...), 
    icon: str = Form(...), 
    label_text: str = Form(None), 
    user: User = Depends(admin_required), 
    session: Session = Depends(get_session)
): 
    """Updates physical and visual properties of a box."""
    b = session.get(Box, box_id)
    if b:
        b.name = name
        b.shelf = shelf
        b.color = color
        b.icon = icon
        b.label_text = label_text
        session.add(b)
        session.commit()
    return RedirectResponse(f"/box/{box_id}", status_code=303)

@router.post("/box/delete")
async def delete_box(
    box_id: int = Form(...), 
    user: User = Depends(admin_required), 
    session: Session = Depends(get_session)
): 
    """Deletes a box and all samples contained within it."""
    b = session.get(Box, box_id)
    if b:
        for s in b.samples: 
            session.delete(s)
        session.delete(b)
        session.commit()
    return RedirectResponse("/", status_code=303)

# --- SAMPLE CRUD & MOVEMENT ---

@router.post("/box/{box_id}/add_sample")
async def add_sample(
    box_id: int, 
    name: str = Form(...), 
    sample_type: str = Form("Other"), 
    row: int = Form(...), 
    col: int = Form(...), 
    experiment_id: int = Form(None), 
    lot: str = Form(None), 
    parent_ids: str = Form(None), 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Adds a new sample to a box slot and links ancestry."""
    # Check slot availability
    if session.exec(select(Sample).where(Sample.box_id==box_id, Sample.row_idx==row, Sample.col_idx==col)).first(): 
        return "Slot occupied"
    
    exp_id = experiment_id if experiment_id and experiment_id > 0 else None
    
    new_sample = Sample(
        name=name, lot_number=lot, sample_type=sample_type, 
        box_id=box_id, row_idx=row, col_idx=col, experiment_id=exp_id
    )
    session.add(new_sample)
    session.commit()
    session.refresh(new_sample)
    
    # Create lineage links
    if parent_ids:
        for pid in [int(p) for p in parent_ids.split(',') if p.strip()]:
            if session.get(Sample, pid):
                session.add(SampleLineageLink(parent_id=pid, child_id=new_sample.id))
    
    log_action(session, "Created", user, f"In Box {box_id}", sample_id=new_sample.id)
    session.commit()
    return RedirectResponse(url=f"/box/{box_id}", status_code=303)

@router.post("/api/sample/move")
async def move_sample_api(
    sample_id: int = Body(...), 
    new_row: int = Body(...), 
    new_col: int = Body(...), 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Updates the grid coordinates of a sample."""
    s = session.get(Sample, sample_id)
    if session.exec(select(Sample).where(Sample.box_id==s.box_id, Sample.row_idx==new_row, Sample.col_idx==new_col)).first(): 
        return {"status": "error", "message": "Slot occupied"}
    
    old_loc = f"{s.row_idx},{s.col_idx}"
    s.row_idx = new_row
    s.col_idx = new_col
    session.add(s)
    log_action(session, "Moved", user, f"From {old_loc}", sample_id=s.id)
    session.commit()
    return {"status": "success"}

# --- LINEAGE & QR CODES ---

@router.get("/sample/{id}/lineage", response_class=HTMLResponse)
async def view_lineage(
    request: Request, 
    id: int, 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Generates and renders a Mermaid.js diagram of sample ancestry."""
    root = session.get(Sample, id)
    if not root: 
        raise HTTPException(status_code=404)
    
    # Graph generation logic migrated from original view_lineage function
    # ... (Full logic for walking parents/children and building Mermaid string)
    # chart_def = build_mermaid_chart(root, session)
    
    return templates.TemplateResponse("lineage.html", {
        "request": request, 
        "user": user, 
        "sample": root, 
        "chart_def": "graph TD\n..." # Placeholder for the generated chart string
    })

@router.get("/api/qrcode/{type}/{id}")
async def generate_qr(
    type: str, 
    id: int, 
    session: Session = Depends(get_session)
):
    """Generates a QR code PNG pointing to a box or sample deep-link."""
    if type == "box":
        url = f"/box/{id}"
    elif type == "sample":
        item = session.get(Sample, id)
        url = f"/box/{item.box_id}?highlight={id}"
    else:
        raise HTTPException(404)

    full_url = f"{BASE_URL}{url}"
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(full_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")