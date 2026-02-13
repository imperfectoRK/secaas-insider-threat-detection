"""
SECaaS Insider Threat Detection - User Risk Schemas

Pydantic schemas for user risk posture API.
"""
from datetime import datetime
from pydantic import BaseModel, Field

class UserRiskResponse(BaseModel):
    """
    Response schema for GET /getUserRisk/{user_id} endpoint.
    
    Attributes:
        user_id: User identifier
        role: User's role name
        current_risk_score: Latest risk score
        risk_level: Risk severity level
        last_alert_time: Timestamp of most recent alert (if any)
    """
    user_id: str = Field(..., example="staff001", description="User identifier")
    role: str = Field(..., example="staff", description="User's role name")
    current_risk_score: float = Field(..., example=90.0, description="Current risk score")
    risk_level: str = Field(..., example="HIGH", description="Risk severity level")
    last_alert_time: datetime | None = Field(None, example="2026-02-02T22:14:02", description="Last alert timestamp")

