"""
SECaaS Insider Threat Detection - Main FastAPI Application

Security as a Service (SECaaS) for Detecting Insider Threats in Cloud Applications
using Role-Based Behavior Profiling.

This module implements the three core APIs:
1. POST /logActivity - Real-time log ingestion with threat detection
2. GET /getAlerts - Query alerts with optional filters
3. GET /getUserRisk/{user_id} - User risk posture assessment

Author: SECaaS System
Version: 1.0.0
"""
from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.config import APP_HOST, APP_PORT
from backend.database import get_db, init_db
from backend.models import User, Role, Alert
from backend.schemas import ActivityLogRequest, ActivityLogResponse, AlertResponse, UserRiskResponse
from backend.services.risk_detector import RiskDetector, get_risk_detector

# Initialize FastAPI application
app = FastAPI(
    title="SECaaS - Insider Threat Detection API",
    description="""
    Security as a Service (SECaaS) for Detecting Insider Threats in Cloud Applications
    using Role-Based Behavior Profiling.
    
    ## Core Features
    
    - **Real-time Log Ingestion**: POST /logActivity ingests activity logs and performs
      instant threat detection based on role-based behavior profiling.
    
    - **Alert Management**: GET /getAlerts allows querying security alerts with flexible
      filters for user_id, alert_level, and time range.
    
    - **Risk Posture Assessment**: GET /getUserRisk/{user_id} provides a user's current
      risk posture based on recent activities and alerts.
    
    ## Threat Detection Mechanisms
    
    The system implements explainable threat detection through:
    
    1. **Policy Violation Detection**: Checks if (action, resource) is authorized for user's role
    2. **Excessive Records Access**: Detects unusual volume of data access
    3. **Off-Hour Access**: Identifies access outside normal operating hours
    4. **Frequency Analysis**: Detects abnormal access frequency patterns
    
    ## Alert Levels
    
    - **LOW**: Risk score 70-79
    - **MEDIUM**: Risk score 80-89
    - **HIGH**: Risk score 90+
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Initialize database tables on startup
@app.on_event("startup")
def startup_event():
    """Initialize database tables on application startup."""
    init_db()
    print("SECaaS Insider Threat Detection API started successfully")


# =============================================================================
# API 1: POST /logActivity
# =============================================================================

@app.post(
    "/logActivity",
    response_model=ActivityLogResponse,
    tags=["Activity Logging"],
    summary="Ingest activity log and perform threat detection",
    description="""
    Ingests a user activity log entry and performs real-time insider threat detection.
    
    The system will:
    1. Validate that the user exists and is active
    2. Fetch the user's role and associated baseline
    3. Check for policy violations
    4. Detect excessive records access
    5. Identify off-hour access patterns
    6. Analyze access frequency
    7. Calculate overall risk score
    8. Log the activity
    9. Generate alert if risk score >= threshold (70)
    
    Returns the processing status, calculated risk score, and whether an alert was generated.
    """
)
def log_activity(
    activity: ActivityLogRequest,
    db: Session = Depends(get_db)
) -> ActivityLogResponse:
    """
    Process an activity log entry with threat detection.
    
    Args:
        activity: Activity log data including user_id, action, resource, etc.
        db: Database session
        
    Returns:
        ActivityLogResponse with status, risk_score, and alert_generated flag
    """
    # Get risk detector service
    detector = get_risk_detector(db)
    
    # Calculate risk score based on role-based behavior profiling
    risk_score, reasons = detector.calculate_risk_score(
        user_id=activity.user_id,
        action=activity.action,
        resource=activity.resource,
        records_accessed=activity.records_accessed,
        access_time=activity.access_time
    )
    
    # Create activity log entry
    detector.create_activity_log(
        user_id=activity.user_id,
        action=activity.action,
        resource=activity.resource,
        records_accessed=activity.records_accessed,
        access_time=activity.access_time,
        source_ip=activity.source_ip
    )
    
    # Check if alert should be generated
    alert_generated = False
    if detector.should_generate_alert(risk_score):
        alert_generated = True
        
        # Determine alert level
        alert_level = detector.get_alert_level(risk_score)
        
        # Create alert entry
        detector.create_alert(
            user_id=activity.user_id,
            risk_score=risk_score,
            alert_level=alert_level,
            reasons=reasons
        )
        
        print(f"[ALERT] User {activity.user_id} generated {alert_level} alert (score: {risk_score})")
    
    return ActivityLogResponse(
        status="processed",
        risk_score=risk_score,
        alert_generated=alert_generated
    )


# =============================================================================
# API 2: GET /getAlerts
# =============================================================================

@app.get(
    "/getAlerts",
    response_model=List[AlertResponse],
    tags=["Alert Management"],
    summary="Query security alerts",
    description="""
    Retrieves security alerts matching the specified filters.
    
    All parameters are optional. If no filters are provided, returns all alerts
    ordered by generation time (newest first).
    
    Supports filtering by:
    - user_id: Specific user
    - alert_level: LOW, MEDIUM, or HIGH
    - from_time: Alerts generated after this time
    - to_time: Alerts generated before this time
    """
)
def get_alerts(
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    alert_level: Optional[str] = Query(None, description="Filter by alert level (LOW, MEDIUM, HIGH)"),
    from_time: Optional[datetime] = Query(None, description="Filter alerts from this time"),
    to_time: Optional[datetime] = Query(None, description="Filter alerts until this time"),
    db: Session = Depends(get_db)
) -> List[AlertResponse]:
    """
    Query alerts with optional filters.
    
    Args:
        user_id: Optional user ID filter
        alert_level: Optional alert level filter
        from_time: Optional start time filter
        to_time: Optional end time filter
        db: Database session
        
    Returns:
        List of matching AlertResponse objects
    """
    # Build query filters
    query = db.query(Alert)
    
    if user_id:
        query = query.filter(Alert.user_id == user_id)
    
    if alert_level:
        # Validate alert level
        if alert_level.upper() not in ["LOW", "MEDIUM", "HIGH"]:
            raise HTTPException(
                status_code=400,
                detail="Invalid alert_level. Must be LOW, MEDIUM, or HIGH"
            )
        query = query.filter(Alert.alert_level == alert_level.upper())
    
    if from_time:
        query = query.filter(Alert.generated_at >= from_time)
    
    if to_time:
        query = query.filter(Alert.generated_at <= to_time)
    
    # Order by generated_at DESC (newest first)
    alerts = query.order_by(desc(Alert.generated_at)).all()
    
    # Convert to response schema
    return [
        AlertResponse(
            alert_id=alert.alert_id,
            user_id=alert.user_id,
            risk_score=float(alert.risk_score),
            alert_level=alert.alert_level,
            reasons=alert.reasons,
            generated_at=alert.generated_at
        )
        for alert in alerts
    ]


# =============================================================================
# API 3: GET /getUserRisk/{user_id}
# =============================================================================

@app.get(
    "/getUserRisk/{user_id}",
    response_model=UserRiskResponse,
    tags=["Risk Assessment"],
    summary="Get user risk posture",
    description="""
    Retrieves the current risk posture for a specific user.
    
    Returns:
    - User's assigned role
    - Current risk score (based on most recent alert)
    - Risk level (LOW, MEDIUM, HIGH)
    - Timestamp of most recent alert (if any)
    
    This endpoint is useful for SOC dashboards and security monitoring.
    """
)
def get_user_risk(
    user_id: str,
    db: Session = Depends(get_db)
) -> UserRiskResponse:
    """
    Get current risk posture for a user.
    
    Args:
        user_id: User identifier
        db: Database session
        
    Returns:
        UserRiskResponse with user's current risk posture
    """
    # Fetch user and role
    user = db.query(User).filter(User.user_id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=404,
            detail=f"User '{user_id}' not found"
        )
    
    # Get user's role name
    role = db.query(Role).filter(Role.role_id == user.role_id).first()
    role_name = role.role_name if role else "unknown"
    
    # Get most recent alert
    latest_alert = db.query(Alert).filter(
        Alert.user_id == user_id
    ).order_by(desc(Alert.generated_at)).first()
    
    # Determine current risk score and level
    if latest_alert:
        current_risk_score = float(latest_alert.risk_score)
        risk_level = latest_alert.alert_level
        last_alert_time = latest_alert.generated_at
    else:
        # No alerts - user is considered low risk
        current_risk_score = 0.0
        risk_level = "LOW"
        last_alert_time = None
    
    return UserRiskResponse(
        user_id=user_id,
        role=role_name,
        current_risk_score=current_risk_score,
        risk_level=risk_level,
        last_alert_time=last_alert_time
    )


# =============================================================================
# Health Check Endpoint
# =============================================================================

@app.get(
    "/health",
    tags=["Health"],
    summary="Health check",
    description="Returns API health status"
)
def health_check():
    """Simple health check endpoint."""
    return {
        "status": "healthy",
        "service": "SECaaS Insider Threat Detection",
        "version": "1.0.0"
    }


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=APP_HOST,
        port=APP_PORT,
        reload=True
    )

