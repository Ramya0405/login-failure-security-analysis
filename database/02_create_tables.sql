-- ============================================================
-- Project: Login Failure & Security Analysis
-- File: 02_create_tables.sql
-- Database: MySQL
-- ============================================================

USE login_security_analysis;


-- ============================================================
-- TABLE 1: users
-- Stores information about registered users
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    user_id INT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    department VARCHAR(50),
    account_status VARCHAR(20) NOT NULL,
    created_date DATE NOT NULL
);


-- ============================================================
-- TABLE 2: ip_addresses
-- Stores information about IP addresses used for login attempts
-- ============================================================

CREATE TABLE IF NOT EXISTS ip_addresses (
    ip_id INT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    country VARCHAR(50),
    city VARCHAR(50),
    isp VARCHAR(100),
    risk_level VARCHAR(20) NOT NULL
);


-- ============================================================
-- TABLE 3: login_attempts
-- Stores every login attempt
-- ============================================================

CREATE TABLE IF NOT EXISTS login_attempts (
    attempt_id INT PRIMARY KEY,

    user_id INT NOT NULL,

    ip_id INT NOT NULL,

    attempt_time DATETIME NOT NULL,

    status VARCHAR(10) NOT NULL,

    failure_reason VARCHAR(100),

    device_type VARCHAR(20),

    -- Foreign key connecting login attempts to users
    CONSTRAINT fk_login_user
        FOREIGN KEY (user_id)
        REFERENCES users(user_id),

    -- Foreign key connecting login attempts to IP addresses
    CONSTRAINT fk_login_ip
        FOREIGN KEY (ip_id)
        REFERENCES ip_addresses(ip_id),

    -- Only SUCCESS or FAILED is allowed
    CONSTRAINT chk_login_status
        CHECK (status IN ('SUCCESS', 'FAILED'))
);


-- ============================================================
-- INDEXES
-- Improve performance for frequent analysis queries
-- ============================================================

CREATE INDEX idx_login_user
ON login_attempts(user_id);


CREATE INDEX idx_login_ip
ON login_attempts(ip_id);


CREATE INDEX idx_login_status
ON login_attempts(status);


CREATE INDEX idx_login_attempt_time
ON login_attempts(attempt_time);


-- ============================================================
-- END OF TABLE CREATION
-- ============================================================
