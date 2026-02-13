"""
SECaaS Insider Threat Detection - User Model

Represents users in the system, linked to roles.
"""
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from backend.database import Base

class User(Base):
    """
    User model representing system users.
    
    Attributes:
        user_id: Unique identifier (e.g., 'staff001')
        role_id: Foreign key to roles table
        status: User status (active/inactive)
    
    Relationships:
        role: Linked Role object
        activity_logs: List of ActivityLog entries
        alerts: List of Alert entries
    """
    __tablename__ = "users"
    
    user_id = Column(String(50), primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.role_id"), nullable=False)
    status = Column(String(20), nullable=False, default="active")
    
    # Relationships
    role = relationship("Role", back_populates="users")
    activity_logs = relationship("ActivityLog", back_populates="user")
    alerts = relationship("Alert", back_populates="user")
    
    def __repr__(self):
        return f"<User(user_id='{self.user_id}', role_id={self.role_id}, status='{self.status}')>"

