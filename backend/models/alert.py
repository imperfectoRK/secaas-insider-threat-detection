"""
SECaaS Insider Threat Detection - Alert Model

Stores generated security alerts with risk scores and explanations.
"""
from sqlalchemy import Column, Integer, String, Numeric, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from backend.database import Base

class Alert(Base):
    """
    Alert model for storing security alerts.
    
    Attributes:
        alert_id: Unique identifier
        user_id: Foreign key to users table
        risk_score: Calculated risk score (0-100)
        alert_level: LOW, MEDIUM, or HIGH
        reasons: Human-readable explanation of why alert was triggered
        generated_at: Timestamp when alert was generated
    
    Relationships:
        user: Linked User object
    """
    __tablename__ = "alerts"
    
    alert_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(50), ForeignKey("users.user_id"), nullable=False)
    risk_score = Column(Numeric(5, 2), nullable=False)
    alert_level = Column(String(10), nullable=False)
    reasons = Column(Text, nullable=False)
    generated_at = Column(DateTime, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="alerts")
    
    def __repr__(self):
        return f"<Alert(alert_id={self.alert_id}, user_id='{self.user_id}', level='{self.alert_level}')>"

