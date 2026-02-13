"""
SECaaS Insider Threat Detection - Role Policy Model

Stores allowed (action, resource) pairs for each role.
"""
from sqlalchemy import Column, Integer, String, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from backend.database import Base

class RolePolicy(Base):
    """
    Role policy model for defining allowed actions per role.
    
    Attributes:
        policy_id: Unique identifier
        role_id: Foreign key to roles table
        action: Allowed action (READ, WRITE, UPDATE, DELETE)
        resource: Resource this policy applies to
    
    Relationships:
        role: Linked Role object
    """
    __tablename__ = "role_policies"
    
    policy_id = Column(Integer, primary_key=True, autoincrement=True)
    role_id = Column(Integer, ForeignKey("roles.role_id"), nullable=False)
    action = Column(String(10), nullable=False)  # READ, WRITE, UPDATE, DELETE
    resource = Column(String(100), nullable=False)
    
    # Relationships
    role = relationship("Role", back_populates="policies")
    
    # Ensure unique combination of role_id, action, resource
    __table_args__ = (
        UniqueConstraint('role_id', 'action', 'resource', name='uq_role_action_resource'),
    )
    
    def __repr__(self):
        return f"<RolePolicy(role_id={self.role_id}, action='{self.action}', resource='{self.resource}')>"

