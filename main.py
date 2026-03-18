from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn
import time
import secrets
from database import engine, SessionLocal
from sqlalchemy.orm import Session
from sqlalchemy import desc
import models
import schemas
import auth
from simple_ai import GroqService
from dotenv import load_dotenv
import os
import datetime
from rate_limit import rate_limiter
from security import prompt_filter, input_validator, ip_blacklister, audit_logger

# Load environment variables
load_dotenv()

# Create database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI Gateway API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Trusted Hosts
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1"],
)

# Static files and templates
app.mount("/static", StaticFiles(directory="app_static"), name="static")
templates = Jinja2Templates(directory="app_templates")

# AI Service
groq_api_key = os.getenv("GROQ_API_KEY")
ai_service = GroqService(groq_api_key) if groq_api_key else None

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Get current user from token
def get_current_user_from_token(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.replace("Bearer ", "")
    return auth.get_current_user(token, db)

# ==================== PAGE ROUTES ====================

@app.get("/")
def root():
    return {"message": "Go to /login or /signup or /admin"}

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.get("/chat", response_class=HTMLResponse)
def chat_page(request: Request):
    return templates.TemplateResponse("chat.html", {"request": request})

# ==================== ADMIN DASHBOARD (FIXED WITH TOKEN PARAM) ====================

@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, token: str = None, db: Session = Depends(get_db)):
    # Check if token is in query param (from new window)
    if token:
        user = auth.get_current_user(token, db)
    else:
        # Check if token is in header (normal request)
        user = get_current_user_from_token(request, db)
    
    if not user or not user.is_admin:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Admin access required"})
    
    # Get statistics
    total_users = db.query(models.User).count()
    total_chats = db.query(models.APIRequest).count()
    total_blocked = db.query(models.BlockedPrompt).count()
    
    # Get recent users
    recent_users = db.query(models.User).order_by(desc(models.User.created_at)).limit(5).all()
    
    # Get recent chats
    recent_chats = db.query(models.APIRequest).order_by(desc(models.APIRequest.timestamp)).limit(10).all()
    
    # Get blocked prompts
    blocked_prompts = db.query(models.BlockedPrompt).order_by(desc(models.BlockedPrompt.timestamp)).limit(10).all()
    
    # Get all users for management
    all_users = db.query(models.User).all()
    
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "user": user,
        "total_users": total_users,
        "total_chats": total_chats,
        "total_blocked": total_blocked,
        "recent_users": recent_users,
        "recent_chats": recent_chats,
        "blocked_prompts": blocked_prompts,
        "all_users": all_users
    })

# API endpoint to toggle user active status (admin only)
@app.post("/admin/toggle-user/{user_id}")
def toggle_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    admin = get_current_user_from_token(request, db)
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.is_active = not user.is_active
    db.commit()
    
    return {"success": True, "is_active": user.is_active}

# API endpoint to delete user (admin only)
@app.post("/admin/delete-user/{user_id}")
def delete_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    admin = get_current_user_from_token(request, db)
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Don't allow deleting yourself
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    db.delete(user)
    db.commit()
    
    return {"success": True}

# ==================== API ROUTES ====================

@app.post("/login-api")
def login(user_data: dict, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "127.0.0.1"
    
    ip_allowed, ip_message = ip_blacklister.check_ip(ip)
    if not ip_allowed:
        audit_logger.log_login_attempt(db, user_data.get('email'), False, ip, f"IP blocked: {ip_message}")
        raise HTTPException(status_code=403, detail=ip_message)
    
    user = auth.authenticate_user(db, user_data.get('email'), user_data.get('password'))
    
    if not user:
        ip_blacklister.add_to_temp_blacklist(ip)
        audit_logger.log_login_attempt(db, user_data.get('email'), False, ip, "Invalid credentials")
        return {"success": False, "message": "Invalid email or password"}
    
    if not user.is_active:
        audit_logger.log_login_attempt(db, user_data.get('email'), False, ip, "Account deactivated")
        return {"success": False, "message": "Account is deactivated"}
    
    access_token = auth.create_access_token(
        data={"sub": str(user.id), "email": user.email, "username": user.username}
    )
    
    audit_logger.log_login_attempt(db, user_data.get('email'), True, ip, "Login successful")
    
    return {
        "success": True,
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "api_key": user.api_key,
        "is_admin": user.is_admin
    }

@app.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "")
        auth.blacklisted_tokens.add(token)
    return {"success": True, "message": "Logged out successfully"}

@app.post("/signup-api")
def signup(user_data: dict, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "127.0.0.1"
    
    ip_allowed, ip_message = ip_blacklister.check_ip(ip)
    if not ip_allowed:
        raise HTTPException(status_code=403, detail=ip_message)
    
    # Check if first user ever - make them admin
    is_first_user = db.query(models.User).count() == 0
    
    existing = db.query(models.User).filter(
        (models.User.username == user_data.get('username')) | 
        (models.User.email == user_data.get('email'))
    ).first()
    
    if existing:
        if existing.username == user_data.get('username'):
            raise HTTPException(status_code=400, detail="Username already taken")
        else:
            raise HTTPException(status_code=400, detail="Email already registered")
    
    user = auth.create_user(
        db, 
        user_data.get('username'), 
        user_data.get('email'), 
        user_data.get('password')
    )
    
    if not user:
        raise HTTPException(status_code=400, detail="Registration failed")
    
    # First user becomes admin
    if is_first_user:
        user.is_admin = True
        db.commit()
    
    audit_logger.log_signup(db, user.id, user.email, ip)
    return {"message": "User created successfully", "is_admin": user.is_admin}

@app.post("/chat")
def chat(prompt: str, api_key: str, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "127.0.0.1"
    
    token_user = get_current_user_from_token(request, db)
    if not token_user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    ip_allowed, ip_message = ip_blacklister.check_ip(ip)
    if not ip_allowed:
        raise HTTPException(status_code=403, detail=ip_message)
    
    user = db.query(models.User).filter(models.User.api_key == api_key).first()
    if not user or user.id != token_user.id:
        ip_blacklister.add_to_temp_blacklist(ip)
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is deactivated")
    
    valid_input, input_message = input_validator.validate(prompt)
    if not valid_input:
        blocked = models.BlockedPrompt(
            user_id=user.id,
            username=user.username,
            prompt=prompt,
            reason=f"Input validation: {input_message}",
            ip_address=ip
        )
        db.add(blocked)
        audit_logger.log_blocked_prompt(db, user.id, user.username, prompt, input_message, ip)
        db.commit()
        raise HTTPException(status_code=400, detail=input_message)
    
    allowed, filter_reason = prompt_filter.check_prompt(prompt)
    if not allowed:
        blocked = models.BlockedPrompt(
            user_id=user.id,
            username=user.username,
            prompt=prompt,
            reason=f"Content filter: {filter_reason}",
            ip_address=ip
        )
        db.add(blocked)
        audit_logger.log_blocked_prompt(db, user.id, user.username, prompt, filter_reason, ip)
        ip_blacklister.add_to_temp_blacklist(ip)
        db.commit()
        raise HTTPException(status_code=403, detail="Prompt contains blocked content")
    
    try:
        limits = rate_limiter.check_limit(db, user)
    except HTTPException as e:
        blocked = models.BlockedPrompt(
            user_id=user.id,
            username=user.username,
            prompt=prompt,
            reason=f"Rate limit: {e.detail}",
            ip_address=ip
        )
        db.add(blocked)
        audit_logger.log_blocked_prompt(db, user.id, user.username, prompt, f"Rate limit: {e.detail}", ip)
        db.commit()
        raise e
    
    if not ai_service:
        raise HTTPException(status_code=503, detail="AI service not configured")
    
    request_id = f"req_{secrets.token_urlsafe(8)}"
    
    db_request = models.APIRequest(
        request_id=request_id,
        user_id=user.id,
        username=user.username,
        api_key=api_key,
        prompt=prompt,
        ip_address=ip,
        was_blocked=False
    )
    db.add(db_request)
    db.commit()
    
    start_time = time.time()
    try:
        response = ai_service.generate(prompt)
        latency = int((time.time() - start_time) * 1000)
        
        db_request.response = response
        db_request.latency_ms = latency
        db.commit()
        
        return {
            "request_id": request_id,
            "response": response,
            "latency_ms": latency,
            "limits": limits
        }
    except Exception as e:
        db_request.response = f"Error: {str(e)}"
        db.commit()
        audit_logger.log_error(db, "ai_error", str(e), ip)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/test-db")
def test_db(db: Session = Depends(get_db)):
    return {
        "users": db.query(models.User).count(),
        "requests": db.query(models.APIRequest).count(),
        "blocked": db.query(models.BlockedPrompt).count(),
        "audit": db.query(models.AuditLog).count()
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)