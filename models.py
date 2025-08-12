# models.py - UPDATED FOR FINGERPRINT MIGRATION

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    access_valid_until = Column(DateTime(timezone=True), nullable=True)
    last_payment_id = Column(String, nullable=True)
    is_admin = Column(Boolean, default=False)
    
    # Relationship to audits
    audits = relationship("Audit", back_populates="owner", cascade="all, delete-orphan")


class Audit(Base):
    __tablename__ = "audits"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    company_name = Column(String, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    report_url = Column(String, nullable=True)
    
    # Relationships
    owner = relationship("User", back_populates="audits")
    findings = relationship(
        "AuditFinding", 
        back_populates="audit",  # Changed from audit_run to audit for clarity
        cascade="all, delete-orphan",
        lazy="joined"  # Eager loading for migration
    )


class AuditFinding(Base):
    __tablename__ = "audit_findings"

    id = Column(Integer, primary_key=True, index=True)
    audit_id = Column(Integer, ForeignKey("audits.id"), nullable=False)
    issue_type = Column(String, index=True, nullable=False)
    details = Column(JSONB, nullable=False)
    fingerprint = Column(String, index=True, nullable=True)  # Made nullable for migration
    is_repeat = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    # Relationship
    audit = relationship("Audit", back_populates="findings")  # Changed from audit_run to audit