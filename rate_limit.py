from datetime import datetime, timedelta
from fastapi import HTTPException
from sqlalchemy.orm import Session
import models

class RateLimiter:
    def __init__(self):
        self.daily_limit = 50
        self.minute_limit = 10
    
    def check_limit(self, db: Session, user):
        now = datetime.utcnow()
        
        if user.last_request_time:
            if now.date() > user.last_request_time.date():
                user.requests_today = 0
                user.last_minute_requests = 0
        
        if user.requests_today >= self.daily_limit:
            tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0)
            wait_seconds = (tomorrow - now).seconds
            raise HTTPException(
                status_code=429,
                detail=f"Daily limit exceeded. Try again in {wait_seconds} seconds."
            )
        
        if not user.last_minute_reset:
            user.last_minute_reset = now
            user.last_minute_requests = 0
        
        if now - user.last_minute_reset > timedelta(minutes=1):
            user.last_minute_reset = now
            user.last_minute_requests = 0
        
        if user.last_minute_requests >= self.minute_limit:
            wait_seconds = 60 - (now - user.last_minute_reset).seconds
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Please wait {wait_seconds} seconds."
            )
        
        user.requests_today += 1
        user.last_minute_requests += 1
        user.last_request_time = now
        db.commit()
        
        return {
            "daily_remaining": self.daily_limit - user.requests_today,
            "minute_remaining": self.minute_limit - user.last_minute_requests
        }

rate_limiter = RateLimiter()