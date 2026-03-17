import hashlib
import secrets
from sqlalchemy.orm import Session
import models
from datetime import datetime, timedelta
from jose import JWTError, jwt

# JWT Configuration
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Blacklisted tokens
blacklisted_tokens = set()

def get_password_hash(password):
    salt = secrets.token_hex(16)
    hash_obj = hashlib.sha256((password + salt).encode())
    return f"{salt}${hash_obj.hexdigest()}"

def verify_password(plain_password, hashed_password):
    try:
        salt, hash_value = hashed_password.split('$')
        test_hash = hashlib.sha256((plain_password + salt).encode()).hexdigest()
        return test_hash == hash_value
    except:
        return False

def authenticate_user(db: Session, email: str, password: str):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_user(db: Session, username: str, email: str, password: str):
    existing = db.query(models.User).filter(
        (models.User.username == username) | (models.User.email == email)
    ).first()
    
    if existing:
        return None
    
    api_key = f"ak_{secrets.token_urlsafe(16)}"
    
    db_user = models.User(
        username=username,
        email=email,
        hashed_password=get_password_hash(password),
        api_key=api_key
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def get_current_user(token: str, db: Session):
    if token in blacklisted_tokens:
        return None
    payload = verify_token(token)
    if not payload:
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    return db.query(models.User).filter(models.User.id == user_id).first()