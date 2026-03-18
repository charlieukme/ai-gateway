import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Check if running on Vercel
if os.environ.get('VERCEL'):
    # Use /tmp directory on Vercel (writable but temporary)
    SQLALCHEMY_DATABASE_URL = "sqlite:///tmp/ai_gateway.db"
else:
    # Local development
    SQLALCHEMY_DATABASE_URL = "sqlite:///./ai_gateway.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()