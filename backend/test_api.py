"""
SECaaS Insider Threat Detection - Test Script

This script tests the core functionality of the SECaaS system.
Run this after initializing the database and starting the API server.
"""
import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"

def test_health():
    """Test health endpoint."""
    print("Testing /health endpoint...")
    response = requests.get(f"{BASE_URL}/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    print(f"✅ Health check passed: {data}")

def test_log_activity_high_risk():
    """Test logging an activity that should trigger a high risk alert."""
    print("\nTesting /logActivity with HIGH risk scenario...")
    
    activity = {
        "user_id": "staff001",
        "action": "READ",
        "resource": "Finance_Reports",  # Not allowed for staff role
        "records_accessed": 5200,  # Much higher than baseline (5.0)
        "access_time": "2026-02-02T22:14:00",  # Outside normal hours (9-17)
        "source_ip": "10.10.1.5"
    }
    
    response = requests.post(
        f"{BASE_URL}/logActivity",
        json=activity,
        headers={"Content-Type": "application/json"}
    )
    
    assert response.status_code == 200
    data = response.json()
    print(f"Response: {json.dumps(data, indent=2)}")
    
    assert data["status"] == "processed"
    assert data["risk_score"] >= 70  # Should trigger alert
    assert data["alert_generated"] == True
    print("✅ High risk activity test passed!")

def test_log_activity_low_risk():
    """Test logging an activity that should not trigger an alert."""
    print("\nTesting /logActivity with LOW risk scenario...")
    
    activity = {
        "user_id": "staff001",
        "action": "READ",
        "resource": "General_Documents",  # Allowed for staff
        "records_accessed": 3,  # Close to baseline (5.0)
        "access_time": "2026-02-02T10:00:00",  # Within normal hours (9-17)
        "source_ip": "10.10.1.5"
    }
    
    response = requests.post(
        f"{BASE_URL}/logActivity",
        json=activity,
        headers={"Content-Type": "application/json"}
    )
    
    assert response.status_code == 200
    data = response.json()
    print(f"Response: {json.dumps(data, indent=2)}")
    
    assert data["status"] == "processed"
    assert data["risk_score"] < 70  # Should NOT trigger alert
    assert data["alert_generated"] == False
    print("✅ Low risk activity test passed!")

def test_get_alerts():
    """Test getting alerts."""
    print("\nTesting /getAlerts endpoint...")
    response = requests.get(f"{BASE_URL}/getAlerts")
    
    assert response.status_code == 200
    alerts = response.json()
    print(f"Retrieved {len(alerts)} alerts")
    for alert in alerts[:3]:  # Show first 3 alerts
        print(f"  - Alert {alert['alert_id']}: {alert['alert_level']} (score: {alert['risk_score']})")
    print("✅ Get alerts test passed!")

def test_get_alerts_with_filters():
    """Test getting alerts with filters."""
    print("\nTesting /getAlerts with filters...")
    
    # Filter by user
    response = requests.get(f"{BASE_URL}/getAlerts", params={"user_id": "staff001"})
    assert response.status_code == 200
    alerts = response.json()
    print(f"Found {len(alerts)} alerts for staff001")
    
    # Filter by level
    response = requests.get(f"{BASE_URL}/getAlerts", params={"alert_level": "HIGH"})
    assert response.status_code == 200
    alerts = response.json()
    print(f"Found {len(alerts)} HIGH level alerts")
    print("✅ Filtered alerts test passed!")

def test_get_user_risk():
    """Test getting user risk posture."""
    print("\nTesting /getUserRisk/{user_id} endpoint...")
    
    response = requests.get(f"{BASE_URL}/getUserRisk/staff001")
    assert response.status_code == 200
    data = response.json()
    print(f"Response: {json.dumps(data, indent=2)}")
    
    assert "user_id" in data
    assert "role" in data
    assert "current_risk_score" in data
    assert "risk_level" in data
    print("✅ Get user risk test passed!")

def test_get_user_risk_not_found():
    """Test getting risk for non-existent user."""
    print("\nTesting /getUserRisk for non-existent user...")
    
    response = requests.get(f"{BASE_URL}/getUserRisk/nonexistent_user")
    assert response.status_code == 404
    print("✅ User not found test passed!")

def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("SECaaS Insider Threat Detection - Test Suite")
    print("=" * 60)
    
    try:
        test_health()
        test_log_activity_high_risk()
        test_log_activity_low_risk()
        test_get_alerts()
        test_get_alerts_with_filters()
        test_get_user_risk()
        test_get_user_risk_not_found()
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return 1
    except requests.exceptions.ConnectionError:
        print("\n❌ CONNECTION ERROR: Make sure the API server is running!")
        print(f"   Start the server with: python backend/main.py")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(run_all_tests())

