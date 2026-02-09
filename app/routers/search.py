# app/routers/search.py
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlmodel import Session, select, or_

from app.models import Sample, Consumable, Experiment, ExperimentTemplate, User
from app.dependencies import get_session, login_required, templates

router = APIRouter(tags=["search"])

@router.get("/search", response_class=HTMLResponse)
async def search(
    request: Request, 
    q: str, 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Performs a comprehensive search across samples, inventory, and experiments."""
    samples = session.exec(select(Sample).where(or_(
        Sample.name.ilike(f"%{q}%"), 
        Sample.lot_number.ilike(f"%{q}%")
    ))).all()
    
    items = session.exec(select(Consumable).where(Consumable.name.ilike(f"%{q}%"))).all()
    exps = session.exec(select(Experiment).where(Experiment.name.ilike(f"%{q}%"))).all()
    tmpls = session.exec(select(ExperimentTemplate).where(ExperimentTemplate.name.ilike(f"%{q}%"))).all()
    
    return templates.TemplateResponse("search_results.html", {
        "request": request, 
        "query": q, 
        "user": user, 
        "results": {
            "samples": samples, 
            "inventory": items, 
            "exps": exps, 
            "tmpls": tmpls
        }
    })

@router.get("/api/search_autocomplete")
async def search_auto(q: str, session: Session = Depends(get_session)):
    """Provides real-time suggestions for the search bar UI."""
    results = []
    
    # Samples
    samples = session.exec(select(Sample).where(or_(
        Sample.name.ilike(f"%{q}%"), 
        Sample.lot_number.ilike(f"%{q}%")
    )).limit(5)).all()
    for s in samples: 
        results.append({
            "id": s.id,
            "category": "Sample", 
            "name": s.name, 
            "info": f"in {s.box.name if s.box else 'Unboxed'}", 
            "url": f"/box/{s.box_id}?highlight={s.id}" if s.box else "#", 
            "icon": "fa-vial", 
            "color": "#ff4b4b"
        })

    # Inventory Items
    items = session.exec(select(Consumable).where(Consumable.name.ilike(f"%{q}%")).limit(3)).all()
    for i in items: 
        results.append({
            "id": i.id,
            "category": "Item", 
            "name": i.name, 
            "info": f"{i.quantity} {i.unit}", 
            "url": "/inventory", 
            "icon": "fa-box-open", 
            "color": "#FF9800"
        })

    # Experiments
    exps = session.exec(select(Experiment).where(Experiment.name.ilike(f"%{q}%")).limit(3)).all()
    for e in exps: 
        results.append({
            "id": e.id,
            "category": "Experiment", 
            "name": e.name, 
            "info": e.status, 
            "url": f"/projects/{e.project_id}", 
            "icon": "fa-flask", 
            "color": "#2196F3"
        })

    return JSONResponse(results)