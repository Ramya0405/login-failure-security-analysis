-- ============================================================
-- Project: Login Failure & Security Analysis
-- File: 01_basic_login_analysis.sql
-- Purpose: Basic login activity analysis
-- Database: MySQL 8+
-- ============================================================

USE login_security_analysis;


-- ============================================================
-- QUERY 1: Total number of login attempts
-- ============================================================

SELECT
    COUNT(*) AS total_login_attempts
FROM login_attempts;


-- ============================================================
-- QUERY 2: Total successful logins
-- ============================================================

SELECT
    COUNT(*) AS successful_logins
FROM login_attempts
WHERE status = 'SUCCESS';


-- ============================================================
-- QUERY 3: Total failed logins
-- ============================================================

SELECT
    COUNT(*) AS failed_logins
FROM login_attempts
WHERE status = 'FAILED';


-- ============================================================
-- QUERY 4: Successful vs failed login attempts
-- ============================================================

SELECT
    status,
    COUNT(*) AS total_attempts
FROM login_attempts
GROUP BY status
ORDER BY total_attempts DESC;


-- ============================================================
-- QUERY 5: Overall login success and failure rate
-- ============================================================

SELECT
    COUNT(*) AS total_attempts,

    SUM(
        CASE
            WHEN status = 'SUCCESS' THEN 1
            ELSE 0
        END
    ) AS successful_logins,

    SUM(
        CASE
            WHEN status = 'FAILED' THEN 1
            ELSE 0
        END
    ) AS failed_logins,

    ROUND(
        100.0 *
        SUM(
            CASE
                WHEN status = 'SUCCESS' THEN 1
                ELSE 0
            END
        ) / COUNT(*),
        2
    ) AS success_rate,

    ROUND(
        100.0 *
        SUM(
            CASE
                WHEN status = 'FAILED' THEN 1
                ELSE 0
            END
        ) / COUNT(*),
        2
    ) AS failure_rate

FROM login_attempts;


-- ============================================================
-- QUERY 6: Login attempts by device type
-- ============================================================

SELECT
    device_type,
    COUNT(*) AS total_attempts
FROM login_attempts
GROUP BY device_type
ORDER BY total_attempts DESC;


-- ============================================================
-- QUERY 7: Successful and failed logins by device
-- ============================================================

SELECT
    device_type,

    COUNT(*) AS total_attempts,

    SUM(
        CASE
            WHEN status = 'SUCCESS' THEN 1
            ELSE 0
        END
    ) AS successful_logins,

    SUM(
        CASE
            WHEN status = 'FAILED' THEN 1
            ELSE 0
        END
    ) AS failed_logins

FROM login_attempts

GROUP BY device_type

ORDER BY failed_logins DESC;


-- ============================================================
-- QUERY 8: Login attempts by failure reason
-- ============================================================

SELECT
    failure_reason,
    COUNT(*) AS total_failures

FROM login_attempts

WHERE status = 'FAILED'

GROUP BY failure_reason

ORDER BY total_failures DESC;


-- ============================================================
-- QUERY 9: Login attempts by date
-- ============================================================

SELECT
    DATE(attempt_time) AS login_date,
    COUNT(*) AS total_attempts

FROM login_attempts

GROUP BY DATE(attempt_time)

ORDER BY login_date;


-- ============================================================
-- QUERY 10: Daily successful vs failed logins
-- ============================================================

SELECT
    DATE(attempt_time) AS login_date,

    SUM(
        CASE
            WHEN status = 'SUCCESS' THEN 1
            ELSE 0
        END
    ) AS successful_logins,

    SUM(
        CASE
            WHEN status = 'FAILED' THEN 1
            ELSE 0
        END
    ) AS failed_logins,

    COUNT(*) AS total_attempts

FROM login_attempts

GROUP BY DATE(attempt_time)

ORDER BY login_date;


-- ============================================================
-- QUERY 11: Login attempts by hour
-- ============================================================

SELECT
    HOUR(attempt_time) AS login_hour,
    COUNT(*) AS total_attempts

FROM login_attempts

GROUP BY HOUR(attempt_time)

ORDER BY login_hour;


-- ============================================================
-- QUERY 12: Failed login attempts by hour
-- ============================================================

SELECT
    HOUR(attempt_time) AS login_hour,
    COUNT(*) AS failed_attempts

FROM login_attempts

WHERE status = 'FAILED'

GROUP BY HOUR(attempt_time)

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 13: Login activity by user
-- ============================================================

SELECT
    user_id,

    COUNT(*) AS total_attempts,

    SUM(
        CASE
            WHEN status = 'SUCCESS' THEN 1
            ELSE 0
        END
    ) AS successful_logins,

    SUM(
        CASE
            WHEN status = 'FAILED' THEN 1
            ELSE 0
        END
    ) AS failed_logins

FROM login_attempts

GROUP BY user_id

ORDER BY total_attempts DESC;


-- ============================================================
-- QUERY 14: Login activity by department
-- Demonstrates JOIN
-- ============================================================

SELECT
    u.department,

    COUNT(la.attempt_id) AS total_attempts,

    SUM(
        CASE
            WHEN la.status = 'SUCCESS' THEN 1
            ELSE 0
        END
    ) AS successful_logins,

    SUM(
        CASE
            WHEN la.status = 'FAILED' THEN 1
            ELSE 0
        END
    ) AS failed_logins

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

GROUP BY u.department

ORDER BY failed_logins DESC;


-- ============================================================
-- QUERY 15: Login activity by account status
-- ============================================================

SELECT
    u.account_status,

    COUNT(la.attempt_id) AS total_attempts,

    SUM(
        CASE
            WHEN la.status = 'SUCCESS' THEN 1
            ELSE 0
        END
    ) AS successful_logins,

    SUM(
        CASE
            WHEN la.status = 'FAILED' THEN 1
            ELSE 0
        END
    ) AS failed_logins

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

GROUP BY u.account_status

ORDER BY failed_logins DESC;


-- ============================================================
-- QUERY 16: Login activity by location
-- Demonstrates JOIN between login_attempts and IP addresses
-- ============================================================

SELECT
    ip.country,
    ip.city,

    COUNT(la.attempt_id) AS total_attempts,

    SUM(
        CASE
            WHEN la.status = 'SUCCESS' THEN 1
            ELSE 0
        END
    ) AS successful_logins,

    SUM(
        CASE
            WHEN la.status = 'FAILED' THEN 1
            ELSE 0
        END
    ) AS failed_logins

FROM login_attempts la

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

GROUP BY
    ip.country,
    ip.city

ORDER BY failed_logins DESC;


-- ============================================================
-- QUERY 17: High-risk IP activity
-- ============================================================

SELECT
    ip.ip_address,
    ip.country,
    ip.city,
    ip.risk_level,

    COUNT(la.attempt_id) AS total_attempts,

    SUM(
        CASE
            WHEN la.status = 'FAILED' THEN 1
            ELSE 0
        END
    ) AS failed_attempts

FROM login_attempts la

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

WHERE ip.risk_level = 'HIGH'

GROUP BY
    ip.ip_address,
    ip.country,
    ip.city,
    ip.risk_level

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 18: Display complete login activity
-- Useful for inspecting the dataset
-- ============================================================

SELECT
    la.attempt_id,
    u.username,
    u.department,
    ip.ip_address,
    ip.city,
    ip.risk_level,
    la.attempt_time,
    la.status,
    la.failure_reason,
    la.device_type

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

ORDER BY la.attempt_time
LIMIT 100;


-- ============================================================
-- END OF BASIC LOGIN ANALYSIS
-- ============================================================
