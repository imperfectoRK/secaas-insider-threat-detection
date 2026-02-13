# SECaaS – Role-Aware Insider Threat Detection System

## Overview

Security as a Service (SECaaS) for Detecting Insider Threats in Cloud Applications using Role-Based Behavior Profiling.

This backend service implements a minimal but complete insider threat detection system with three core APIs for real-time log ingestion, alert management, and user risk assessment.

## Features

### Real-Time Threat Detection
- **Policy Violation Detection**: Checks if user actions are authorized based on role policies
- **Excessive Records Access**: Detects unusual data access volumes
- **Off-Hour Access**: Identifies access outside normal operating hours
- **Frequency Analysis**: Detects abnormal access patterns

### Explainable Alerts
- Human-readable risk explanations
- Risk scores (0-100)
- Alert levels: LOW (70-79), MEDIUM (80-89), HIGH (90+)

### Role-Based Behavior Profiling
- Baseline metrics per role (avg records, access frequency, normal hours)
- Context-aware risk scoring
- Behavioral deviation detection

## Quick Start

### Prerequisites
- Python 3.8+
- PostgreSQL 12+
- pip

### Installation

1. **Clone and navigate to project directory**
```bash
cd /home/rk/Desktop/RahulKumar_Sem2/DB/secaas-insider-threat-detection
```

2. **Create virtual environment (recommended)**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate   # Windows
```

3. **Install dependencies**
```bash
cd backend
pip install -r requirements.txt
```

4. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your database credentials
```

5. **Create PostgreSQL database**
```bash
# Connect to PostgreSQL
psql -U postgres

# Create database
CREATE DATABASE secaas_db;

# Exit psql
\q
```

6. **Run database schema**
```bash
# Run the schema SQL file
psql -U postgres -d secaas_db -f ../schema.sql
```

7. **Initialize with sample data**
```bash
python init_db.py
```

8. **Start the API server**
```bash
python main.py
```

The API will be available at `http://localhost:8000`

### Using Docker (Alternative)

```bash
# Build and run with Docker Compose
docker-compose up --build
```

## API Documentation

### API 1: POST /logActivity

Real-time log ingestion with insider threat detection.

**Request:**
```json
{
  "user_id": "staff001",
  "action": "READ",
  "resource": "Finance_Reports",
  "records_accessed": 5200,
  "access_time": "2026-02-02T22:14:00",
  "source_ip": "10.10.1.5"
}
```

**Response:**
```json
{
  "status": "processed",
  "risk_score": 90,
  "alert_generated": true
}
```

**Detection Logic:**
1. Validates user exists and is active
2. Fetches user's role and baseline
3. Checks policy violations (action, resource)
4. Compares records_accessed vs baseline avg
5. Checks if access_time is outside normal hours
6. Analyzes daily access frequency
7. Calculates weighted risk score
8. Generates alert if score >= 70

### API 2: GET /getAlerts

Query security alerts with optional filters.

**Parameters:**
- `user_id` (optional): Filter by user
- `alert_level` (optional): LOW, MEDIUM, or HIGH
- `from_time` (optional): Start time filter
- `to_time` (optional): End time filter

**Response:**
```json
[
  {
    "alert_id": 12,
    "user_id": "staff001",
    "risk_score": 90.0,
    "alert_level": "HIGH",
    "reasons": "Unauthorized resource access; Excessive records; Off-hour access",
    "generated_at": "2026-02-02T22:14:02"
  }
]
```

### API 3: GET /getUserRisk/{user_id}

Get user's current risk posture.

**Response:**
```json
{
  "user_id": "staff001",
  "role": "staff",
  "current_risk_score": 90.0,
  "risk_level": "HIGH",
  "last_alert_time": "2026-02-02T22:14:02"
}
```

## API Endpoints Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/logActivity` | Ingest activity with threat detection |
| GET | `/getAlerts` | Query alerts with filters |
| GET | `/getUserRisk/{user_id}` | Get user risk posture |
| GET | `/health` | Health check |

## OpenAPI Documentation

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Project Structure

```
secaas-insider-threat-detection/
├── backend/
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration settings
│   ├── database.py          # Database connection
│   ├── init_db.py           # Database initialization
│   ├── .env.example         # Environment template
│   ├── requirements.txt     # Python dependencies
│   ├── models/              # SQLAlchemy models
│   │   ├── role.py
│   │   ├── user.py
│   │   ├── role_policy.py
│   │   ├── activity_log.py
│   │   ├── role_baseline.py
│   │   └── alert.py
│   ├── schemas/             # Pydantic schemas
│   │   ├── activity.py
│   │   ├── alert.py
│   │   └── user.py
│   └── services/           # Business logic
│       └── risk_detector.py
├── schema.sql               # PostgreSQL schema
└── README.md               # This file
```

## Risk Scoring Weights

| Factor | Weight | Description |
|--------|--------|-------------|
| Policy Violation | 40 | Unauthorized action/resource |
| Off-Hour Access | 25 | Outside normal operating hours |
| Excessive Records | 20 | Data access volume anomaly |
| High Frequency | 15 | Abnormal access frequency |

## Alert Levels

| Level | Score Range | Action |
|-------|-------------|--------|
| LOW | 70-79 | Monitor |
| MEDIUM | 80-89 | Investigate |
| HIGH | 90+ | Immediate action |

## Database Schema

### Tables
1. **roles**: User roles (admin, manager, staff)
2. **users**: Users linked to roles
3. **role_policies**: Allowed (action, resource) per role
4. **activity_logs**: User activity records
5. **role_baselines**: Behavioral baselines per role
6. **alerts**: Generated security alerts

See `schema.sql` for full details.

## Testing

### Manual Testing with curl

```bash
# Test activity logging
curl -X POST "http://localhost:8000/logActivity" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "staff001",
    "action": "READ",
    "resource": "Finance_Reports",
    "records_accessed": 5200,
    "access_time": "2026-02-02T22:14:00",
    "source_ip": "10.10.1.5"
  }'

# Get all alerts
curl "http://localhost:8000/getAlerts"

# Get user risk
curl "http://localhost:8000/getUserRisk/staff001"

# Health check
curl "http://localhost:8000/health"
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| DATABASE_HOST | localhost | PostgreSQL host |
| DATABASE_PORT | 5432 | PostgreSQL port |
| DATABASE_NAME | secaas_db | Database name |
| DATABASE_USER | postgres | Database user |
| DATABASE_PASSWORD | postgres | Database password |
| APP_HOST | 0.0.0.0 | API host |
| APP_PORT | 8000 | API port |
| DEBUG_MODE | false | Debug mode |

## Security Considerations

This is a demonstration system. For production use:
- Add authentication/authorization
- Use encrypted connections
- Implement rate limiting
- Add audit logging
- Use secrets management
- Enable SSL/TLS

## License

MIT License

## References

- Insider Threat Handbooks: https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=496171
- NIST Special Publication 800-53: Security Controls
- Zero Trust Architecture Principles










