"""
SECaaS Insider Threat Detection - Activity Log Model

Records user activities for behavioral analysis and threat detection.
"""
from sqlalchemy import Column, Integer, String, DateTime, Numeric, ForeignKey
from sqlalchemy.orm import relationship
from backend.database import Base

class ActivityLog(Base):
    """
    Activity log model for tracking user actions.
    
    Attributes:
        log_id: Unique identifier
        user_id: Foreign key to users table
        action: Type of action (READ, WRITE, UPDATE, DELETE)
        resource: Resource accessed
        records_accessed: Number of records accessed
        access_time: Timestamp of the activity
        source_ip: IP address of the source
    
    Relationships:
        user: Linked User object
    """
    __tablename__ = "activity_logs"
    
    log_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(50), ForeignKey("users.user_id"), nullable=False)
    action = Column(String(10), nullable=False)  # READ, WRITE, UPDATE, DELETE
    resource = Column(String(100), nullable=False)
    records_accessed = Column(Integer, nullable=False, default=0)
    access_time = Column(DateTime, nullable=False)
    source_ip = Column(String(45))
    
    # Relationships
    user = relationship("User", back_populates="activity_logs")
    
    def __repr__(self):
        return f"<ActivityLog(log_id={self.log_id}, user_id='{self.user_id}', action='{self.action}')>"

