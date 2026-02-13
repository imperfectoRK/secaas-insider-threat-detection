"""
SECaaS Insider Threat Detection - Risk Detection Service

Core detection logic for insider threat identification.
Implements role-based behavior profiling and risk scoring.
"""
from typing import Optional, Tuple, List
from sqlalchemy.orm import Session
from sqlalchemy import and_, func
from datetime import datetime, timedelta

from backend.config import RISK_SCORE_THRESHOLD, RISK_WEIGHTS, ALERT_LEVELS
from backend.models import Role, User, ActivityLog, RoleBaseline, Alert

class RiskDetector:
    """
    Risk detection engine for insider threat identification.
    
    Implements role-based behavior profiling by:
    1. Checking policy violations
    2. Detecting excessive records access
    3. Identifying off-hour access patterns
    4. Analyzing access frequency
    5. Aggregating risk scores
    
    Attributes:
        db: Database session
    """
    
    def __init__(self, db: Session):
        """Initialize risk detector with database session."""
        self.db = db
    
    def get_user_and_role(self, user_id: str) -> Tuple[Optional[User], Optional[Role]]:
        """
        Fetch user and their associated role.
        
        Args:
            user_id: User identifier
            
        Returns:
            Tuple of (User, Role) or (None, None) if not found
        """
        user = self.db.query(User).filter(User.user_id == user_id).first()
        if not user:
            return None, None
        
        role = self.db.query(Role).filter(Role.role_id == user.role_id).first()
        return user, role
    
    def check_policy_violation(self, role_id: int, action: str, resource: str) -> Tuple[bool, str]:
        """
        Check if the (action, resource) combination is allowed for the role.
        
        Args:
            role_id: Role identifier
            action: Action type (READ, WRITE, UPDATE, DELETE)
            resource: Resource being accessed
            
        Returns:
            Tuple of (is_violation: bool, reason: str)
        """
        from backend.models import RolePolicy
        
        # Check if policy exists for this role, action, and resource
        policy = self.db.query(RolePolicy).filter(
            and_(
                RolePolicy.role_id == role_id,
                RolePolicy.action == action,
                RolePolicy.resource == resource
            )
        ).first()
        
        if policy:
            return False, ""
        
        return True, f"Unauthorized {action} access to {resource}"
    
    def check_excessive_records(
        self, 
        role_baseline: Optional[RoleBaseline], 
        records_accessed: int
    ) -> Tuple[int, str]:
        """
        Detect excessive records access compared to baseline.
        
        Args:
            role_baseline: Role baseline data
            records_accessed: Number of records accessed in this activity
            
        Returns:
            Tuple of (risk_score_contribution, reason)
        """
        if not role_baseline:
            # No baseline defined - assume moderate risk
            return 0, ""
        
        baseline_avg = float(role_baseline.avg_records_per_access)
        
        # Calculate how many standard deviations above baseline
        # Using a simple multiplier approach for explainability
        if baseline_avg > 0:
            ratio = records_accessed / baseline_avg
            
            if ratio > 10:
                return RISK_WEIGHTS["excessive_records"], f"Extreme records access ({records_accessed} vs baseline {baseline_avg})"
            elif ratio > 5:
                return int(RISK_WEIGHTS["excessive_records"] * 0.8), f"Excessive records access ({records_accessed} vs baseline {baseline_avg})"
            elif ratio > 2:
                return int(RISK_WEIGHTS["excessive_records"] * 0.5), f"Elevated records access ({records_accessed} vs baseline {baseline_avg})"
        
        return 0, ""
    
    def check_off_hour_access(
        self, 
        role_baseline: Optional[RoleBaseline], 
        access_time: datetime
    ) -> Tuple[int, str]:
        """
        Detect access outside normal operating hours.
        
        Args:
            role_baseline: Role baseline data
            access_time: Timestamp of the access
            
        Returns:
            Tuple of (risk_score_contribution, reason)
        """
        if not role_baseline:
            return 0, ""
        
        hour = access_time.hour
        
        # Check if outside normal hours
        if hour < role_baseline.normal_start_hour or hour > role_baseline.normal_end_hour:
            # Calculate how far outside normal hours
            if hour < role_baseline.normal_start_hour:
                hours_outside = role_baseline.normal_start_hour - hour
            else:
                hours_outside = hour - role_baseline.normal_end_hour
            
            if hours_outside >= 4:
                return RISK_WEIGHTS["off_hour_access"], f"Severe off-hour access at {access_time.strftime('%H:%M')}"
            elif hours_outside >= 2:
                return int(RISK_WEIGHTS["off_hour_access"] * 0.7), f"Off-hour access at {access_time.strftime('%H:%M')}"
            else:
                return int(RISK_WEIGHTS["off_hour_access"] * 0.5), f"Early/late access at {access_time.strftime('%H:%M')}"
        
        return 0, ""
    
    def check_access_frequency(
        self, 
        user_id: str, 
        role_baseline: Optional[RoleBaseline], 
        access_time: datetime
    ) -> Tuple[int, str]:
        """
        Detect abnormally high access frequency.
        
        Args:
            user_id: User identifier
            role_baseline: Role baseline data
            access_time: Timestamp of the access
            
        Returns:
            Tuple of (risk_score_contribution, reason)
        """
        if not role_baseline:
            return 0, ""
        
        # Count accesses in the current day
        day_start = access_time.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        
        access_count = self.db.query(ActivityLog).filter(
            and_(
                ActivityLog.user_id == user_id,
                ActivityLog.access_time >= day_start,
                ActivityLog.access_time < day_end
            )
        ).count()
        
        baseline_avg = role_baseline.avg_access_per_day
        
        if baseline_avg > 0:
            ratio = access_count / baseline_avg
            
            if ratio > 3:
                return RISK_WEIGHTS["high_frequency"], f"Extremely high access frequency ({access_count} today)"
            elif ratio > 2:
                return int(RISK_WEIGHTS["high_frequency"] * 0.7), f"Elevated access frequency ({access_count} today)"
            elif ratio > 1.5:
                return int(RISK_WEIGHTS["high_frequency"] * 0.5), f"Increased access frequency ({access_count} today)"
        
        return 0, ""
    
    def calculate_risk_score(
        self,
        user_id: str,
        action: str,
        resource: str,
        records_accessed: int,
        access_time: datetime
    ) -> Tuple[int, List[str]]:
        """
        Calculate overall risk score for an activity.
        
        This is the main risk scoring function that:
        1. Validates user exists and is active
        2. Fetches user's role and baseline
        3. Checks for policy violations
        4. Checks for excessive records
        5. Checks for off-hour access
        6. Checks for high frequency access
        7. Aggregates all risk factors
        
        Args:
            user_id: User identifier
            action: Action type
            resource: Resource accessed
            records_accessed: Number of records accessed
            access_time: Timestamp of access
            
        Returns:
            Tuple of (total_risk_score, List of reasons)
        """
        reasons = []
        total_score = 0
        
        # Step 1: Validate user exists and is active
        user, role = self.get_user_and_role(user_id)
        if not user:
            return 100, ["User not found"]
        
        if user.status != "active":
            return 100, [f"User account is {user.status}"]
        
        # Step 2: Fetch role baseline
        role_baseline = self.db.query(RoleBaseline).filter(
            RoleBaseline.role_id == user.role_id
        ).first()
        
        # Step 3: Check policy violation
        is_violation, violation_reason = self.check_policy_violation(
            user.role_id, action, resource
        )
        if is_violation:
            total_score += RISK_WEIGHTS["policy_violation"]
            reasons.append(violation_reason)
        
        # Step 4: Check excessive records
        records_score, records_reason = self.check_excessive_records(
            role_baseline, records_accessed
        )
        total_score += records_score
        if records_reason:
            reasons.append(records_reason)
        
        # Step 5: Check off-hour access
        hour_score, hour_reason = self.check_off_hour_access(
            role_baseline, access_time
        )
        total_score += hour_score
        if hour_reason:
            reasons.append(hour_reason)
        
        # Step 6: Check access frequency
        freq_score, freq_reason = self.check_access_frequency(
            user_id, role_baseline, access_time
        )
        total_score += freq_score
        if freq_reason:
            reasons.append(freq_reason)
        
        # Cap score at 100
        total_score = min(total_score, 100)
        
        return total_score, reasons
    
    def get_alert_level(self, risk_score: int) -> str:
        """
        Determine alert level based on risk score.
        
        Args:
            risk_score: Calculated risk score
            
        Returns:
            Alert level string (LOW, MEDIUM, HIGH)
        """
        for level, (low, high) in ALERT_LEVELS.items():
            if low <= risk_score <= high:
                return level
        
        # Default to HIGH for scores above 90
        return "HIGH" if risk_score >= 90 else "MEDIUM"
    
    def should_generate_alert(self, risk_score: int) -> bool:
        """
        Determine if an alert should be generated.
        
        Args:
            risk_score: Calculated risk score
            
        Returns:
            True if alert should be generated
        """
        return risk_score >= RISK_SCORE_THRESHOLD
    
    def create_activity_log(
        self,
        user_id: str,
        action: str,
        resource: str,
        records_accessed: int,
        access_time: datetime,
        source_ip: Optional[str]
    ) -> ActivityLog:
        """
        Create a new activity log entry.
        
        Args:
            user_id: User identifier
            action: Action type
            resource: Resource accessed
            records_accessed: Number of records accessed
            access_time: Timestamp of access
            source_ip: Source IP address
            
        Returns:
            Created ActivityLog object
        """
        activity_log = ActivityLog(
            user_id=user_id,
            action=action,
            resource=resource,
            records_accessed=records_accessed,
            access_time=access_time,
            source_ip=source_ip
        )
        
        self.db.add(activity_log)
        self.db.commit()
        self.db.refresh(activity_log)
        
        return activity_log
    
    def create_alert(
        self,
        user_id: str,
        risk_score: int,
        alert_level: str,
        reasons: List[str]
    ) -> Alert:
        """
        Create a new alert entry.
        
        Args:
            user_id: User identifier
            risk_score: Calculated risk score
            alert_level: Alert severity level
            reasons: List of risk reasons
            
        Returns:
            Created Alert object
        """
        alert = Alert(
            user_id=user_id,
            risk_score=risk_score,
            alert_level=alert_level,
            reasons="; ".join(reasons)
        )
        
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        
        return alert


def get_risk_detector(db: Session) -> RiskDetector:
    """
    Factory function to get RiskDetector instance.
    
    Args:
        db: Database session
        
    Returns:
        RiskDetector instance
    """
    return RiskDetector(db)

