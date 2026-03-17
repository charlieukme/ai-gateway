import re
from datetime import datetime, timedelta
from fastapi import HTTPException
from sqlalchemy.orm import Session
import models

class PromptFilter:
    def __init__(self):
        self.blocked_patterns = [
            r'\b(fuck|shit|asshole|bitch|cunt|dick)\b',
            r'\b(hack|exploit|bypass|inject|sql injection|malware|virus|ransomware)\b',
            r'\b(crack|keygen|pirate|stolen credit card)\b',
            r'\b(porn|sex|nude|xxx|adult content|onlyfans)\b',
            r'\b(credit card number|ssn|social security|passport|license number)\b',
            r'\b(bank account|routing number|address|phone number|private key)\b',
            r'\b(how to make bomb|how to kill|self harm|suicide)\b',
            r'\b(illegal drugs|cocaine|heroin|meth)\b'
        ]
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.blocked_patterns]
    
    def check_prompt(self, prompt):
        prompt_lower = prompt.lower()
        for pattern in self.compiled_patterns:
            if pattern.search(prompt_lower):
                return False, "Prompt contains blocked content"
        return True, "Allowed"

class InputValidator:
    def __init__(self):
        self.max_length = 2000
        self.min_length = 2
    
    def validate(self, prompt):
        if not prompt or not prompt.strip():
            return False, "Prompt cannot be empty"
        if len(prompt.strip()) < self.min_length:
            return False, f"Prompt too short"
        if len(prompt) > self.max_length:
            return False, f"Prompt too long"
        if prompt.isupper() and len(prompt) > 20:
            return False, "Please don't use ALL CAPS"
        if re.search(r'(.)\1{10,}', prompt):
            return False, "Too many repeated characters"
        return True, "Valid"

class IPBlacklister:
    def __init__(self):
        self.max_failures = 5
        self.temp_blacklist = {}
        self.permanent_blacklist = set()
    
    def add_to_temp_blacklist(self, ip):
        now = datetime.utcnow()
        if ip not in self.temp_blacklist:
            self.temp_blacklist[ip] = [1, now]
        else:
            fail_count, first_fail = self.temp_blacklist[ip]
            if now - first_fail > timedelta(hours=24):
                self.temp_blacklist[ip] = [1, now]
            else:
                fail_count += 1
                self.temp_blacklist[ip] = [fail_count, first_fail]
                if fail_count >= self.max_failures:
                    self.permanent_blacklist.add(ip)
                    del self.temp_blacklist[ip]
                    return True
        return False
    
    def check_ip(self, ip):
        if ip in self.permanent_blacklist:
            return False, "IP is permanently banned"
        if ip in self.temp_blacklist:
            fail_count, first_fail = self.temp_blacklist[ip]
            now = datetime.utcnow()
            if now - first_fail <= timedelta(hours=24):
                return False, f"IP temporarily blocked"
            else:
                del self.temp_blacklist[ip]
        return True, "IP allowed"

class AuditLogger:
    def log_login_attempt(self, db: Session, email: str, success: bool, ip: str, reason: str = ""):
        audit = models.AuditLog(
            action="login_attempt",
            user_email=email,
            success=success,
            ip_address=ip,
            details=reason
        )
        db.add(audit)
        db.commit()
    
    def log_signup(self, db: Session, user_id: int, email: str, ip: str):
        audit = models.AuditLog(
            action="user_signup",
            user_id=user_id,
            user_email=email,
            success=True,
            ip_address=ip,
            details="New user registered"
        )
        db.add(audit)
        db.commit()
    
    def log_blocked_prompt(self, db: Session, user_id: int, username: str, prompt: str, reason: str, ip: str):
        audit = models.AuditLog(
            action="blocked_prompt",
            user_id=user_id,
            user_email=username,
            success=False,
            ip_address=ip,
            details=f"Blocked: {reason}"
        )
        db.add(audit)
        db.commit()
    
    def log_error(self, db: Session, error_type: str, details: str, ip: str = ""):
        audit = models.AuditLog(
            action="system_error",
            success=False,
            ip_address=ip,
            details=f"{error_type}: {details}"
        )
        db.add(audit)
        db.commit()

prompt_filter = PromptFilter()
input_validator = InputValidator()
ip_blacklister = IPBlacklister()
audit_logger = AuditLogger()