"""
SECaaS Insider Threat Detection - Configuration Settings

Environment-based configuration for local development and testing.
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database Configuration
DATABASE_HOST = os.getenv("DATABASE_HOST", "localhost")
DATABASE_PORT = int(os.getenv("DATABASE_PORT", 5432))
DATABASE_NAME = os.getenv("DATABASE_NAME", "secaas_db")
DATABASE_USER = os.getenv("DATABASE_USER", "postgres")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD", "postgres")

# Build database URL for SQLAlchemy
DATABASE_URL = f"postgresql://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_NAME}"

# Risk Detection Configuration
RISK_SCORE_THRESHOLD = 70  # Alert trigger threshold

# Alert Levels Configuration
ALERT_LEVELS = {
    "LOW": (70, 79),
    "MEDIUM": (80, 89),
    "HIGH": (90, 100)
}

# Risk Score Weights (can be tuned)
RISK_WEIGHTS = {
    "policy_violation": 40,      # High weight - unauthorized access
    "excessive_records": 20,      # Medium weight - data exfiltration indicator
    "off_hour_access": 25,        # Medium-high - suspicious timing
    "high_frequency": 15         # Lower weight - could be legitimate burst
}

# Application Configuration
APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("APP_PORT", 8000))
DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

