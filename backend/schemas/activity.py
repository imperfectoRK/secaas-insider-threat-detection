"""
SECaaS Insider Threat Detection - Activity Log Schemas

Pydantic schemas for activity logging API.
"""
from datetime import datetime
from pydantic import BaseModel, Field

class ActivityLogRequest(BaseModel):
    """
    Request schema for POST /logActivity endpoint.
    
    Attributes:
        user_id: Unique identifier of the user performing the action
        action: Type of action (READ, WRITE, UPDATE, DELETE)
        resource: Resource being accessed
        records_accessed: Number of records accessed
        access_time: Timestamp of the activity
        source_ip: IP address of the source
    """
    user_id: str = Field(..., example="staff001", description="User identifier")
    action: str = Field(..., example="READ", description="Action type (READ, WRITE, UPDATE, DELETE)")
    resource: str = Field(..., example="Finance_Reports", description="Resource being accessed")
    records_accessed: int = Field(default=0, ge=0, example=5200, description="Number of records accessed")
    access_time: datetime = Field(..., example="2026-02-02T22:14:00", description="Timestamp of activity")
    source_ip: str = Field(default=None, example="10.10.1.5", description="Source IP address")

class ActivityLogResponse(BaseModel):
    """
    Response schema for POST /logActivity endpoint.
    
    Attributes:
        status: Processing status
        risk_score: Calculated risk score (0-100)
        alert_generated: Whether an alert was generated
    """
    status: str = Field(..., example="processed", description="Processing status")
    risk_score: int = Field(..., ge=0, le=100, example=90, description="Calculated risk score (0-100)")
    alert_generated: bool = Field(..., example=True, description="Whether an alert was generated")

class ActivityLogCreate(BaseModel):
    """
    Schema for creating activity log records in the database.
    """
    user_id: str
    action: str
    resource: str
    records_accessed: int
    access_time: datetime
    source_ip: str | None = None

