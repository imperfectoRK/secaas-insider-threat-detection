-- SECaaS Insider Threat Detection System - Database Schema
-- PostgreSQL syntax

-- 1. ROLES table
CREATE TABLE roles (
    role_id SERIAL PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT
);

-- 2. USERS table
CREATE TABLE users (
    user_id VARCHAR(50) PRIMARY KEY,
    role_id INTEGER NOT NULL REFERENCES roles(role_id),
    status VARCHAR(20) NOT NULL DEFAULT 'active'
);

-- 3. ROLE_POLICIES table
CREATE TABLE role_policies (
    policy_id SERIAL PRIMARY KEY,
    role_id INTEGER NOT NULL REFERENCES roles(role_id),
    action VARCHAR(10) NOT NULL CHECK (action IN ('READ', 'WRITE', 'DELETE')),
    resource VARCHAR(100) NOT NULL
);

-- 4. ACTIVITY_LOGS table
CREATE TABLE activity_logs (
    log_id SERIAL PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL REFERENCES users(user_id),
    role_id INTEGER NOT NULL REFERENCES roles(role_id),
    action VARCHAR(10) NOT NULL,
    resource VARCHAR(100) NOT NULL,
    records_accessed INTEGER DEFAULT 0,
    access_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45) -- IPv4 or IPv6
);

-- 5. ROLE_BASELINES table
CREATE TABLE role_baselines (
    role_id INTEGER PRIMARY KEY REFERENCES roles(role_id),
    avg_records_per_access DECIMAL(10,2),
    avg_access_per_day DECIMAL(10,2),
    normal_start_hour INTEGER CHECK (normal_start_hour >= 0 AND normal_start_hour <= 23),
    normal_end_hour INTEGER CHECK (normal_end_hour >= 0 AND normal_end_hour <= 23)
);

-- 6. ALERTS table
CREATE TABLE alerts (
    alert_id SERIAL PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL REFERENCES users(user_id),
    risk_score DECIMAL(5,2) NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    alert_level VARCHAR(10) NOT NULL CHECK (alert_level IN ('LOW', 'MEDIUM', 'HIGH')),
    reasons TEXT NOT NULL,
    generated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Insert minimal demo data

-- Roles
INSERT INTO roles (role_name, description) VALUES
('admin', 'System administrator with full access'),
('manager', 'Manager with elevated privileges'),
('staff', 'Regular staff member');

-- One user (staff)
INSERT INTO users (user_id, role_id, status) VALUES
('staff001', (SELECT role_id FROM roles WHERE role_name = 'staff'), 'active');

-- One role_baseline entry for staff
INSERT INTO role_baselines (role_id, avg_records_per_access, avg_access_per_day, normal_start_hour, normal_end_hour) VALUES
((SELECT role_id FROM roles WHERE role_name = 'staff'), 5.0, 20.0, 9, 17);
