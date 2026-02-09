# app/routers/inventory.py
import io
import csv
from datetime import datetime
from fastapi import APIRouter, Depends, Form, Body, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, JSONResponse
from sqlmodel import Session, select, and_, or_

# Import models, dependencies, and utilities
from app.models import Consumable, OrderRequest, AuditLog, User
from app.dependencies import get_session, login_required, admin_required, templates
from app.utils.logging import log_action # Assuming log_action is moved to utils

router = APIRouter(tags=["inventory"])

# --- VIEW ROUTES ---

@router.get("/inventory", response_class=HTMLResponse)
async def view_inventory(
    request: Request, 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """
    Renders the consolidated inventory and orders dashboard.
    Logic adapted from main.py.
    """
    # Fetch all inventory items
    items = session.exec(select(Consumable)).all()
    
    # Procurement logic: Admins see all, Users see their own requests
    if user.role == "Admin":
        orders = session.exec(
            select(OrderRequest)
            .where(OrderRequest.status != "Received")
            .order_by(OrderRequest.created_at)
        ).all()
        history = session.exec(
            select(OrderRequest)
            .where(OrderRequest.status == "Received")
            .order_by(OrderRequest.updated_at.desc())
            .limit(20)
        ).all()
    else:
        orders = session.exec(
            select(OrderRequest)
            .where(and_(OrderRequest.requester == user.username, OrderRequest.status != "Received"))
        ).all()
        history = session.exec(
            select(OrderRequest)
            .where(and_(OrderRequest.requester == user.username, OrderRequest.status == "Received"))
            .limit(10)
        ).all()

    return templates.TemplateResponse("inventory.html", {
        "request": request, 
        "user": user, 
        "items": items,
        "orders": orders,
        "history": history
    })

# --- PROCUREMENT (ORDER) ROUTES ---

@router.post("/orders/request")
async def create_request(
    item_name: str = Form(...), 
    url: str = Form(None), 
    qty: int = Form(1), 
    reason: str = Form(None), 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Submits a new procurement request."""
    req = OrderRequest(
        item_name=item_name, 
        url=url, 
        quantity=qty, 
        reason=reason, 
        requester=user.username
    )
    session.add(req)
    log_action(session, "Requested Item", user, f"Requested {item_name}")
    session.commit()
    return RedirectResponse("/inventory?tab=orders", status_code=303)

@router.post("/orders/update_status")
async def update_order_status(
    req_id: int = Form(...), 
    status: str = Form(...), 
    user: User = Depends(admin_required), 
    session: Session = Depends(get_session)
):
    """
    Updates order status and performs auto-stocking upon receipt.
    Logic migrated from main.py.
    """
    req = session.get(OrderRequest, req_id)
    if not req:
        return RedirectResponse("/inventory?tab=orders", status_code=303)

    # Automatic Stocking Logic
    if status == "Received" and req.status != "Received":
        existing_item = session.exec(
            select(Consumable).where(Consumable.name == req.item_name)
        ).first()
        
        if existing_item:
            existing_item.quantity += req.quantity
            existing_item.order_flag = False 
            session.add(existing_item)
            log_action(session, "Auto-Restock", user, f"Added +{req.quantity} to '{existing_item.name}'", consumable_id=existing_item.id)
        else:
            new_item = Consumable(
                name=req.item_name,
                quantity=req.quantity,
                category="General",
                location="Receiving Area",
                unit="units",
                min_level=5,
                buy_url=req.url
            )
            session.add(new_item)
            session.flush() 
            log_action(session, "Auto-Create", user, f"Created item '{req.item_name}' via order", consumable_id=new_item.id)

    req.status = status
    req.updated_at = datetime.now()
    log_action(session, "Order Update", user, f"Set '{req.item_name}' to {status}")
    session.add(req)
    session.commit()
    
    return RedirectResponse("/inventory?tab=orders", status_code=303)

# --- STOCK MANAGEMENT ROUTES ---

@router.post("/inventory/create")
async def create_item(
    name: str = Form(...), 
    category: str = Form(...), 
    quantity: int = Form(...), 
    unit: str = Form(...), 
    location: str = Form(...), 
    min_level: int = Form(...), 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Adds a new consumable to the inventory."""
    item = Consumable(
        name=name, 
        category=category, 
        quantity=quantity, 
        unit=unit, 
        location=location, 
        min_level=min_level
    )
    session.add(item)
    session.commit()
    log_action(session, "Created", user, f"Initial Qty: {quantity}", consumable_id=item.id)
    return RedirectResponse("/inventory", status_code=303)

@router.post("/inventory/set_qty")
async def set_item_qty(
    id: int = Body(...), 
    qty: int = Body(...), 
    user: User = Depends(login_required), 
    session: Session = Depends(get_session)
):
    """Directly updates the quantity of an item."""
    item = session.get(Consumable, id)
    if item:
        old = item.quantity
        item.quantity = qty
        session.add(item)
        log_action(session, "Qty Set", user, f"Manually set to {qty} (was {old})", consumable_id=item.id)
        session.commit()
        return {"status": "success", "new_qty": item.quantity}
    return {"status": "error"}

@router.post("/inventory/delete")
async def delete_item(
    id: int = Form(...), 
    user: User = Depends(admin_required), 
    session: Session = Depends(get_session)
): 
    """Removes an item and its associated logs."""
    item = session.get(Consumable, id)
    if item:
        # Clean up related audit logs first
        for l in item.logs: 
            session.delete(l)
        session.delete(item)
        session.commit()
    return RedirectResponse("/inventory", status_code=303)

# --- API & EXPORT ROUTES ---

@router.get("/api/inventory/history/{id}")
async def get_inventory_history(id: int, session: Session = Depends(get_session)):
    """Returns the audit trail for a specific item."""
    logs = session.exec(
        select(AuditLog)
        .where(AuditLog.consumable_id == id)
        .order_by(AuditLog.timestamp.desc())
    ).all()
    return JSONResponse([
        {
            "user": l.user_name, 
            "action": l.action, 
            "details": l.details, 
            "time": l.timestamp.strftime('%Y-%m-%d %H:%M')
        } for l in logs
    ])

@router.get("/inventory/export_csv")
async def export_inventory_csv(session: Session = Depends(get_session)):
    """Generates a CSV export of the current stock levels."""
    items = session.exec(select(Consumable)).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Name', 'Category', 'Location', 'Quantity', 'Unit', 'Min Level', 'Order Needed'])
    
    for i in items:
        writer.writerow([
            i.name, i.category, i.location, i.quantity, i.unit, i.min_level, 
            "Yes" if i.order_flag or i.quantity <= i.min_level else "No"
        ])
    
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8'))
    mem.seek(0)
    
    return StreamingResponse(
        mem, 
        media_type="text/csv", 
        headers={"Content-Disposition": "attachment; filename=inventory_export.csv"}
    )