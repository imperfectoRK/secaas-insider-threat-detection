-- postgreSQL Schema

-- 1. roles table
CREATE TABLE roles
(
    role_id SERIAL PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT
);








-- 2. users table
CREATE TABLE users
(
    user_id VARCHAR(50) PRIMARY KEY,
    role_id INTEGER NOT NULL REFERENCES roles(role_id),
    status VARCHAR(20) NOT NULL DEFAULT 'active'
);





-- 3. ROLE_policies table
CREATE TABLE role_policies (
    policy_id SERIAL PRIMARY KEY,
    role_id INTEGER NOT NULL REFERENCES roles(role_id),
    action VARCHAR(10) NOT NULL CHECK (action IN ('READ', 'WRITE', 'UPDATE', 'DELETE')),
    resource VARCHAR(100) NOT NULL
);





-- 4. activity log table (no redundant role_id)
CREATE TABLE activity_logs (
    log_id SERIAL PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL REFERENCES users(user_id),
    action VARCHAR(10) NOT NULL CHECK (action IN ('READ', 'WRITE', 'UPDATE', 'DELETE')),
    resource VARCHAR(100) NOT NULL,
    records_accessed INTEGER NOT NULL DEFAULT 0,
    access_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45)
);





-- Index for real-time & historical analysis
CREATE INDEX idx_activity_logs_time ON activity_logs(access_time);




-- 5. ROLE_BASELINES table
CREATE TABLE role_baselines (
    role_id INTEGER PRIMARY KEY REFERENCES roles(role_id),
    avg_records_per_access NUMERIC(10,2) NOT NULL,
    avg_access_per_day INTEGER NOT NULL,
    normal_start_hour INTEGER NOT NULL CHECK (normal_start_hour BETWEEN 0 AND 23),
    normal_end_hour INTEGER NOT NULL CHECK (normal_end_hour BETWEEN 0 AND 23)
);





-- 6. ALERTS table
CREATE TABLE alerts (
    alert_id SERIAL PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL REFERENCES users(user_id),
    risk_score NUMERIC(5,2) NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    alert_level VARCHAR(10) NOT NULL CHECK (alert_level IN ('LOW', 'MEDIUM', 'HIGH')),
    reasons TEXT NOT NULL,
    generated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);







-- dummy


INSERT INTO roles (role_name, description) VALUES
('admin', 'System administrator with full access'),
('manager', 'Manager with elevated privileges'),
('staff', 'Regular staff member');

INSERT INTO users (user_id, role_id, status) VALUES
('staff001', (SELECT role_id FROM roles WHERE role_name = 'staff'), 'active');

INSERT INTO role_baselines
(role_id, avg_records_per_access, avg_access_per_day, normal_start_hour, normal_end_hour)
VALUES
((SELECT role_id FROM roles WHERE role_name = 'staff'), 5.0, 20, 9, 17);









