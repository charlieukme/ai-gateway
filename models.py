from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from database import Base
import datetime

# Session storage for blacklisted tokens
blacklisted_tokens = set()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String, nullable=False)
    api_key = Column(String, unique=True, index=True)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Rate limiting fields
    requests_today = Column(Integer, default=0)
    last_request_time = Column(DateTime, nullable=True)
    last_minute_requests = Column(Integer, default=0)
    last_minute_reset = Column(DateTime, nullable=True)
    
class APIRequest(Base):
    __tablename__ = "api_requests"
    
    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String, unique=True, index=True)
    user_id = Column(Integer, index=True)
    username = Column(String)
    api_key = Column(String, index=True)
    prompt = Column(Text)
    response = Column(Text, nullable=True)
    was_blocked = Column(Boolean, default=False)
    block_reason = Column(String, nullable=True)
    ip_address = Column(String)
    latency_ms = Column(Integer, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
class BlockedPrompt(Base):
    __tablename__ = "blocked_prompts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    username = Column(String)
    prompt = Column(Text)
    reason = Column(String)
    ip_address = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    action = Column(String, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    user_email = Column(String, nullable=True)
    success = Column(Boolean, default=True)
    ip_address = Column(String, nullable=True)
    details = Column(Text, nullable=True)