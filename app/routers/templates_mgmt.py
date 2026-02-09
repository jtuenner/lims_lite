# app/routers/templates_mgmt.py
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.models import ExperimentTemplate, User
from app.dependencies import get_session, login_required, admin_required, templates

router = APIRouter(prefix="/templates", tags=["templates"])

@router.get("/", response_class=HTMLResponse)
async def templates_list(
    request: Request, 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Lists all available experiment protocol templates."""
    tmpls = session.exec(select(ExperimentTemplate)).all()
    return templates.TemplateResponse("templates_list.html", {
        "request": request, 
        "templates": tmpls, 
        "user": user
    })

@router.post("/create")
async def create_template(
    name: str = Form(...), 
    description: str = Form(None), 
    protocol: str = Form(None), 
    user: User = Depends(admin_required), 
    session: Session = Depends(get_session)
): 
    """Creates a new protocol template (Admin only)."""
    session.add(ExperimentTemplate(name=name, description=description, protocol=protocol))
    session.commit()
    return RedirectResponse(url="/templates", status_code=303)

@router.post("/update")
async def update_template(
    id: int = Form(...), 
    name: str = Form(...), 
    description: str = Form(None), 
    protocol: str = Form(None), 
    user: User = Depends(admin_required), 
    session: Session = Depends(get_session)
): 
    """Updates an existing protocol template."""
    t = session.get(ExperimentTemplate, id)
    if t: 
        t.name = name
        t.description = description
        t.protocol = protocol
        session.add(t)
        session.commit()
    return RedirectResponse(url="/templates", status_code=303)

@router.post("/delete")
async def delete_template(
    id: int = Form(...), 
    user: User = Depends(admin_required), 
    session: Session = Depends(get_session)
): 
    """Removes a template from the system."""
    t = session.get(ExperimentTemplate, id)
    if t: 
        session.delete(t)
        session.commit()
    return RedirectResponse(url="/templates", status_code=303)