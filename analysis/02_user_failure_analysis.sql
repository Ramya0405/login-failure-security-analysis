-- ============================================================
-- Project: Login Failure & Security Analysis
-- File: 02_user_failure_analysis.sql
-- Purpose: User-level login failure analysis
-- Database: MySQL 8+
-- ============================================================

USE login_security_analysis;


-- ============================================================
-- QUERY 1: Total failed attempts by each user
-- ============================================================

SELECT
    u.user_id,
    u.username,
    COUNT(la.attempt_id) AS failed_attempts

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

WHERE la.status = 'FAILED'

GROUP BY
    u.user_id,
    u.username

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 2: Users with repeated login failures
-- ============================================================

SELECT
    u.user_id,
    u.username,
    COUNT(la.attempt_id) AS failed_attempts

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

WHERE la.status = 'FAILED'

GROUP BY
    u.user_id,
    u.username

HAVING COUNT(la.attempt_id) >= 5

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 3: User success vs failure statistics
-- ============================================================

SELECT
    u.user_id,
    u.username,

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

GROUP BY
    u.user_id,
    u.username

ORDER BY failed_logins DESC;


-- ============================================================
-- QUERY 4: Most common failure reason for each user
-- ============================================================

SELECT
    u.username,
    la.failure_reason,
    COUNT(*) AS failure_count

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

WHERE la.status = 'FAILED'

GROUP BY
    u.username,
    la.failure_reason

ORDER BY
    u.username,
    failure_count DESC;


-- ============================================================
-- QUERY 5: Users with 10 or more failed attempts
-- ============================================================

SELECT
    u.username,
    COUNT(*) AS failed_attempts

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

WHERE la.status = 'FAILED'

GROUP BY u.username

HAVING COUNT(*) >= 10

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 6: Users with failures from multiple IP addresses
-- ============================================================

SELECT
    u.username,
    COUNT(DISTINCT la.ip_id) AS different_ip_addresses,
    COUNT(*) AS failed_attempts

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

WHERE la.status = 'FAILED'

GROUP BY u.username

HAVING COUNT(DISTINCT la.ip_id) > 1

ORDER BY different_ip_addresses DESC;


-- ============================================================
-- QUERY 7: Failed attempts by department
-- ============================================================

SELECT
    u.department,
    COUNT(*) AS failed_attempts

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

WHERE la.status = 'FAILED'

GROUP BY u.department

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 8: Locked accounts with login failures
-- ============================================================

SELECT
    u.user_id,
    u.username,
    u.account_status,
    COUNT(la.attempt_id) AS failed_attempts

FROM users u

JOIN login_attempts la
    ON u.user_id = la.user_id

WHERE
    u.account_status = 'LOCKED'
    AND la.status = 'FAILED'

GROUP BY
    u.user_id,
    u.username,
    u.account_status

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 9: Users whose failures exceed their successful logins
-- ============================================================

SELECT
    u.username,

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

GROUP BY u.username

HAVING failed_logins > successful_logins

ORDER BY failed_logins DESC;


-- ============================================================
-- QUERY 10: Users with failures from HIGH-risk IP addresses
-- ============================================================

SELECT
    u.username,
    COUNT(*) AS high_risk_failures

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

WHERE
    la.status = 'FAILED'
    AND ip.risk_level = 'HIGH'

GROUP BY u.username

ORDER BY high_risk_failures DESC;


-- ============================================================
-- END OF USER FAILURE ANALYSIS
-- ============================================================
