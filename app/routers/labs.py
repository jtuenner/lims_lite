# app/routers/labs.py
from datetime import datetime
from fastapi import APIRouter, Depends, Form, Body, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from sqlmodel import Session, select

# Import models, dependencies, and utilities from your new structure
from app.models import Lab, Booking, User
from app.dependencies import get_session, login_required, admin_required, templates
from app.utils.logging import log_action

router = APIRouter(tags=["labs"])

# --- LAB MANAGEMENT ROUTES ---

@router.get("/labs", response_class=HTMLResponse)
async def view_labs(
    request: Request, 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Renders the list of all available labs and their equipment."""
    labs = session.exec(select(Lab)).all()
    return templates.TemplateResponse("lab_list.html", {
        "request": request, 
        "labs": labs, 
        "user": user
    })

@router.post("/labs/create")
async def create_lab(
    name: str = Form(...), 
    location: str = Form(...), 
    user_limit: int = Form(5), 
    user: User = Depends(admin_required), 
    session: Session = Depends(get_session)
): 
    """Creates a new lab space with a specific user seat limit."""
    new_lab = Lab(name=name, location=location, user_limit=user_limit)
    session.add(new_lab)
    session.commit()
    return RedirectResponse("/labs", status_code=303)

@router.post("/labs/update")
async def update_lab(
    id: int = Form(...), 
    name: str = Form(...), 
    location: str = Form(...), 
    resources: str = Form(...), 
    user: User = Depends(admin_required), 
    session: Session = Depends(get_session)
): 
    """Updates lab details and the list of available equipment/resources."""
    lab = session.get(Lab, id)
    if lab:
        lab.name = name
        lab.location = location
        lab.resources = resources
        session.add(lab)
        session.commit()
    return RedirectResponse("/labs", status_code=303)

@router.post("/labs/delete")
async def delete_lab(
    id: int = Form(...), 
    user: User = Depends(admin_required), 
    session: Session = Depends(get_session)
): 
    """Deletes a lab and its associated equipment records."""
    lab = session.get(Lab, id)
    if lab:
        session.delete(lab)
        session.commit()
    return RedirectResponse("/labs", status_code=303)

# --- CALENDAR & BOOKING ROUTES ---

@router.get("/calendar/{lab_id}", response_class=HTMLResponse)
async def view_calendar(
    request: Request, 
    lab_id: int, 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Renders the FullCalendar view for a specific lab's equipment."""
    lab = session.get(Lab, lab_id)
    if not lab:
        return RedirectResponse("/labs")
    
    # Parse comma-separated resources for the booking dropdown
    res_list = [r.strip() for r in lab.resources.split(',')] if lab.resources else []
    
    return templates.TemplateResponse("calendar.html", {
        "request": request, 
        "lab": lab, 
        "resources": res_list, 
        "user": user
    })

@router.get("/api/bookings")
async def get_bookings_api(lab_id: int, session: Session = Depends(get_session)):
    """API endpoint for FullCalendar to fetch scheduled events for a lab."""
    bookings = session.exec(select(Booking).where(Booking.lab_id == lab_id)).all()
    
    events = []
    for b in bookings:
        # Determine event color based on the resource type
        color = "#3788d8"  # Default blue
        if "Microscope" in b.resource:
            color = "#28a745"  # Green
        elif "Hood" in b.resource:
            color = "#dc3545"  # Red
            
        events.append({
            "id": b.id,
            "title": f"{b.resource}: {b.user_name}",
            "start": b.start_time.isoformat(),
            "end": b.end_time.isoformat(),
            "backgroundColor": color,
            "extendedProps": {
                "resource": b.resource,
                "user": b.user_name
            }
        })
    return JSONResponse(events)

@router.post("/api/bookings/create")
async def create_booking(
    title: str = Body(...), 
    resource: str = Body(...), 
    start: str = Body(...), 
    end: str = Body(...), 
    lab_id: int = Body(...), 
    experiment_id: int = Body(None), 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Schedules a new equipment booking slot."""
    new_booking = Booking(
        title=title, 
        resource=resource, 
        # Clean the incoming ISO string for SQLite compatibility
        start_time=datetime.fromisoformat(start.replace("Z", "")), 
        end_time=datetime.fromisoformat(end.replace("Z", "")), 
        user_name=user.username, 
        lab_id=lab_id, 
        experiment_id=experiment_id
    )
    session.add(new_booking)
    session.commit()
    return {"status": "success"}

@router.post("/api/bookings/delete")
async def delete_booking(
    id: int = Body(..., embed=True), 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Cancels an existing equipment booking."""
    booking = session.get(Booking, id)
    if booking:
        session.delete(booking)
        session.commit()
        return {"status": "success"}
    return {"status": "error", "message": "Booking not found"}