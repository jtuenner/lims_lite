# app/routers/home.py
import re
import os
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select, and_, create_engine, SQLModel
from sqlalchemy.pool import StaticPool

from app.models import User, Lab, Freezer, Box, Sample, Experiment, Booking
from app.dependencies import get_session, get_current_user, get_lab_name, templates
from app.database import get_db_path
from app.utils.tasks import update_biomass_score

router = APIRouter(tags=["home"])

@router.get("/", response_class=HTMLResponse)
async def root_router(
    request: Request, 
    user: User = Depends(get_current_user), 
    session: Session = Depends(get_session)
):
    """
    Logic migrated from original main.py.
    Decides whether to show the SaaS landing page, the login page, or the dashboard.
    """
    lab_name = get_lab_name(request)
    
    # CASE 1: Visitor on the main domain (no subdomain) -> Show SaaS Landing Page
    if not lab_name:
        return templates.TemplateResponse("landing.html", {"request": request})
    
    # CASE 2: User on a lab subdomain but not logged in -> Redirect to Login
    if not user:
        return RedirectResponse("/login")
        
    # CASE 3: User logged in -> Show the Lab Dashboard
    return await dashboard_view(request, user, session)

async def dashboard_view(request, user, session):
    """Generates the data for the main laboratory dashboard."""
    # Update the user's gamification score
    update_biomass_score(session, user)
    
    # Fetch overview stats
    leaderboard = session.exec(select(User).order_by(User.petri_score.desc()).limit(5)).all()
    stats = {
        "boxes": len(session.exec(select(Box)).all()), 
        "samples": len(session.exec(select(Sample)).all()), 
        "alerts": len(session.exec(select(Sample).where(Sample.is_low_stock == True)).all())
    }
    
    freezers = session.exec(select(Freezer)).all()
    today = datetime.now()
    next_week = today + timedelta(days=7)
    
    # Compile the agenda (Experiments and Bookings)
    upcoming_exps = session.exec(
        select(Experiment)
        .where(and_(Experiment.date >= today, Experiment.date <= next_week))
        .order_by(Experiment.date)
    ).all()
    
    upcoming_bookings = session.exec(
        select(Booking)
        .where(and_(Booking.start_time >= today, Booking.start_time <= next_week))
        .order_by(Booking.start_time)
    ).all()
    
    agenda = []
    for e in upcoming_exps:
        agenda.append({
            "type": "experiment", "date": e.date, "title": e.name, 
            "desc": e.status, "link": f"/projects/{e.project_id}"
        })
    for b in upcoming_bookings:
        agenda.append({
            "type": "booking", "date": b.start_time, "title": b.resource, 
            "desc": f"{b.start_time.strftime('%H:%M')} - {b.end_time.strftime('%H:%M')}", 
            "link": f"/calendar/{b.lab_id}"
        })
    agenda.sort(key=lambda x: x["date"])
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request, 
        "user": user, 
        "freezers": freezers, 
        "stats": stats, 
        "agenda": agenda, 
        "leaderboard": leaderboard
    })

@router.post("/create_lab")
async def create_lab_endpoint(lab_name: str = Form(...), licenses: int = Form(5)):
    """Handles the creation of a new lab instance/tenant."""
    clean_name = re.sub(r'[^a-zA-Z0-9]', '', lab_name).lower()
    if len(clean_name) < 3: 
        return "Name too short"
    
    db_path = get_db_path(clean_name)
    if os.path.exists(db_path):
        return f"Lab '{clean_name}' already exists!"
    
    # Initialize the new tenant database
    sqlite_url = f"sqlite:///{db_path}"
    engine = create_engine(sqlite_url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    
    with Session(engine) as session:
        session.add(Freezer(name="Main Fridge", location="Lab"))
        session.add(Lab(name="Main Lab", location="Room 1", user_limit=licenses)) 
        session.commit()
        
    return f"Lab Created! Access it at http://{clean_name}.yourdomain.com"