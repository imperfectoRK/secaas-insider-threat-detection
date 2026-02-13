"""
SECaaS Insider Threat Detection - Role Model

Represents user roles in the system.
Each role defines a set of permissions and behavioral baselines.
"""
from sqlalchemy import Column, Integer, String, Text
from backend.database import Base

class Role(Base):
    """
    Role model for defining user roles.
    
    Attributes:
        role_id: Unique identifier (auto-increment)
        role_name: Unique name (e.g., 'admin', 'manager', 'staff')
        description: Human-readable description of the role
    
    Relationships:
        users: List of User objects with this role
        policies: List of RolePolicy objects
        baseline: RoleBaseline object
    """
    __tablename__ = "roles"
    
    role_id = Column(Integer, primary_key=True, autoincrement=True)
    role_name = Column(String(50), unique=True, nullable=False)
    description = Column(Text)
    
    # Relationships
    users = relationship("User", back_populates="role")
    policies = relationship("RolePolicy", back_populates="role")
    baseline = relationship("RoleBaseline", back_populates="role", uselist=False)
    
    def __repr__(self):
        return f"<Role(role_id={self.role_id}, role_name='{self.role_name}')>"

