"""
SECaaS Insider Threat Detection - Role Baseline Model

Stores behavioral baselines for each role.
Used for detecting deviations from normal behavior.
"""
from sqlalchemy import Column, Integer, Numeric, ForeignKey
from sqlalchemy.orm import relationship
from backend.database import Base

class RoleBaseline(Base):
    """
    Role baseline model for storing normal behavioral patterns.
    
    Attributes:
        role_id: Foreign key to roles table (primary key - one baseline per role)
        avg_records_per_access: Expected average records accessed per action
        avg_access_per_day: Expected average number of accesses per day
        normal_start_hour: Start of normal operating hours (0-23)
        normal_end_hour: End of normal operating hours (0-23)
    
    Relationships:
        role: Linked Role object
    """
    __tablename__ = "role_baselines"
    
    role_id = Column(Integer, ForeignKey("roles.role_id"), primary_key=True)
    avg_records_per_access = Column(Numeric(10, 2), nullable=False)
    avg_access_per_day = Column(Integer, nullable=False)
    normal_start_hour = Column(Integer, nullable=False)
    normal_end_hour = Column(Integer, nullable=False)
    
    # Relationships
    role = relationship("Role", back_populates="baseline")
    
    def __repr__(self):
        return f"<RoleBaseline(role_id={self.role_id}, avg_records={self.avg_records_per_access})>"

