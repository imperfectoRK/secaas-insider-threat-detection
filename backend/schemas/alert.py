"""
SECaaS Insider Threat Detection - Alert Schemas

Pydantic schemas for alert-related API endpoints.
"""
from datetime import datetime
from pydantic import BaseModel, Field

class AlertResponse(BaseModel):
    """
    Response schema for GET /getAlerts endpoint.
    
    Attributes:
        alert_id: Unique identifier of the alert
        user_id: User who triggered the alert
        risk_score: Calculated risk score
        alert_level: Severity level (LOW, MEDIUM, HIGH)
        reasons: Human-readable explanation
        generated_at: Timestamp when alert was generated
    """
    alert_id: int = Field(..., example=12, description="Alert identifier")
    user_id: str = Field(..., example="staff001", description="User who triggered the alert")
    risk_score: float = Field(..., example=90.0, description="Calculated risk score")
    alert_level: str = Field(..., example="HIGH", description="Alert severity level")
    reasons: str = Field(..., example="Unauthorized resource access; Excessive records; Off-hour access", description="Explanation of alert")
    generated_at: datetime = Field(..., example="2026-02-02T22:14:02", description="When alert was generated")

class AlertFilter(BaseModel):
    """
    Filter parameters for GET /getAlerts endpoint.
    All parameters are optional.
    """
    user_id: str | None = Field(None, example="staff001", description="Filter by user ID")
    alert_level: str | None = Field(None, example="HIGH", description="Filter by alert level (LOW, MEDIUM, HIGH)")
    from_time: datetime | None = Field(None, example="2026-02-01T00:00:00", description="Filter alerts from this time")
    to_time: datetime | None = Field(None, example="2026-02-03T00:00:00", description="Filter alerts until this time")

