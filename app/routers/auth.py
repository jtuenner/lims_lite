# app/routers/auth.py
import random
import asyncio
from datetime import datetime
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select, func
from slowapi import Limiter
from slowapi.util import get_remote_address

# Import models, dependencies, and utilities from your new structure
from app.models import User, InviteCode, Lab
from app.dependencies import get_session, get_current_user, get_lab_name, templates, limiter
from app.utils.security import verify_password, get_password_hash, create_access_token
from app.config import LICENSE_LIMIT, APP_ENV

router = APIRouter(tags=["authentication"])

# --- LOGIN ROUTES ---

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Renders the login page."""
    csrf_token = request.session.get("csrf_token", "")
    return templates.TemplateResponse("login.html", {
        "request": request,
        "csrf_token": csrf_token
    })

@router.post("/login")
@limiter.limit("5/minute")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    session: Session = Depends(get_session)
):
    """Handles user login with rate limiting and secure cookie placement."""
    
    # Validate CSRF token
    session_token = request.session.get("csrf_token", "")
    if not csrf_token or csrf_token != session_token:
        csrf_token_new = request.session.get("csrf_token", "")
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid security token. Please try again.",
            "csrf_token": csrf_token_new
        }, status_code=403)
    
    if not session:
        csrf_token_new = request.session.get("csrf_token", "")
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Service unavailable",
            "csrf_token": csrf_token_new
        })
    
    # Slight delay to mitigate timing attacks
    await asyncio.sleep(0.5)
    
    user = session.exec(select(User).where(User.username == username)).first()
    
    if not user or not verify_password(password, user.hashed_password):
        csrf_token_new = request.session.get("csrf_token", "")
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid credentials",
            "csrf_token": csrf_token_new
        })
    
    # Update last active timestamp
    user.last_active = datetime.now()
    session.add(user)
    session.commit()
    
    # Create JWT token scoped to the current tenant
    lab_name = get_lab_name(request)
    token = create_access_token({"sub": user.username}, lab_name)
    
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        "access_token", 
        f"Bearer {token}",
        httponly=True,
        secure=APP_ENV == "production",
        samesite="lax",
        max_age=604800  # 7 days
    )
    
    return response

# --- REGISTRATION ROUTES ---

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, code: str = None, session: Session = Depends(get_session)):
    if not session:
        return RedirectResponse("/") 
    
    user_count = session.exec(select(func.count(User.id))).one()
    csrf_token = request.session.get("csrf_token", "")
    
    return templates.TemplateResponse("register.html", {
        "request": request, 
        "code": code, 
        "is_first": (user_count == 0),
        "csrf_token": csrf_token
    })

@router.post("/register")
@limiter.limit("3/hour")
async def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    invite_code: str = Form(None),
    session: Session = Depends(get_session)
):
    """Handles new user registration, enforcing invite codes and license limits."""
    
    # Validate CSRF token
    session_token = request.session.get("csrf_token", "")
    if not csrf_token or csrf_token != session_token:
        csrf_token_new = request.session.get("csrf_token", "")
        user_count = session.exec(select(func.count(User.id))).one() if session else 0
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Invalid security token. Please try again.",
            "is_first": (user_count == 0),
            "csrf_token": csrf_token_new
        }, status_code=403)
    
    if not session:
        return RedirectResponse("/login", status_code=303)
    
    csrf_token_new = request.session.get("csrf_token", "")
    user_count = session.exec(select(func.count(User.id))).one()
    
    # Basic password validation
    if len(password) < 8:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Password must be at least 8 characters",
            "is_first": (user_count == 0),
            "csrf_token": csrf_token_new
        })
    
    # Check if username is already taken
    if session.exec(select(User).where(User.username == username)).first():
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Username already taken",
            "is_first": False,
            "csrf_token": csrf_token_new
        })

    lab_config = session.exec(select(Lab)).first()
    current_limit = lab_config.user_limit if lab_config else LICENSE_LIMIT
    
    role = "Admin" if user_count == 0 else "User"
    
    # Enforce invite codes for non-admin users
    if user_count > 0:
        if not invite_code: 
            return templates.TemplateResponse("register.html", {
                "request": request, 
                "error": "Invite Code Required.",
                "csrf_token": csrf_token_new
            })
        
        valid_code = session.exec(
            select(InviteCode).where(
                InviteCode.code == invite_code, 
                InviteCode.is_used == False
            )
        ).first()
        
        if not valid_code: 
            return templates.TemplateResponse("register.html", {
                "request": request, 
                "error": "Invalid or used Invite Code.",
                "csrf_token": csrf_token_new
            })
        
        # Enforce seat limits
        if user_count >= current_limit: 
            return templates.TemplateResponse("register.html", {
                "request": request, 
                "error": f"Limit Reached ({current_limit} seats).",
                "csrf_token": csrf_token_new
            })
            
        valid_code.is_used = True
        session.add(valid_code)

    # Create new user with a random gamification color
    colors = ["#FF5252", "#448AFF", "#69F0AE", "#E040FB", "#FFAB40", "#FFFF00", "#00E5FF"]
    new_user = User(
        username=username, 
        hashed_password=get_password_hash(password),
        role=role, 
        petri_color=random.choice(colors)
    )
    
    session.add(new_user)
    session.commit()
    
    return RedirectResponse(url="/login", status_code=303)

# --- LOGOUT ROUTE ---

@router.get("/logout")
async def logout():
    """Logs the user out by deleting the session cookie."""
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response