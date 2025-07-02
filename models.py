# models.py
from sqlalchemy import Column, Integer, String, DateTime
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    last_payment_id = Column(String, nullable=True)
    access_valid_until = Column(DateTime, nullable=True)