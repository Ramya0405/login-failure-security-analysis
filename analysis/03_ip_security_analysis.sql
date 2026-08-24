-- ============================================================
-- Project: Login Failure & Security Analysis
-- File: 03_ip_security_analysis.sql
-- Purpose: IP-level security analysis
-- Database: MySQL 8+
-- ============================================================

USE login_security_analysis;


-- ============================================================
-- QUERY 1: Total attempts by IP
-- ============================================================

SELECT
    ip.ip_address,
    COUNT(*) AS total_attempts

FROM login_attempts la

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

GROUP BY ip.ip_address

ORDER BY total_attempts DESC;


-- ============================================================
-- QUERY 2: Failed attempts by IP
-- ============================================================

SELECT
    ip.ip_address,
    COUNT(*) AS failed_attempts

FROM login_attempts la

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

WHERE la.status = 'FAILED'

GROUP BY ip.ip_address

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 3: Suspicious IPs with 10+ failures
-- ============================================================

SELECT
    ip.ip_address,
    ip.country,
    ip.city,
    ip.risk_level,
    COUNT(*) AS failed_attempts

FROM login_attempts la

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

WHERE la.status = 'FAILED'

GROUP BY
    ip.ip_address,
    ip.country,
    ip.city,
    ip.risk_level

HAVING COUNT(*) >= 10

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 4: IP success/failure statistics
-- ============================================================

SELECT
    ip.ip_address,

    COUNT(*) AS total_attempts,

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

GROUP BY ip.ip_address

ORDER BY failed_logins DESC;


-- ============================================================
-- QUERY 5: Users targeted by each IP
-- ============================================================

SELECT
    ip.ip_address,
    COUNT(DISTINCT la.user_id) AS targeted_users,
    COUNT(*) AS total_attempts

FROM login_attempts la

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

GROUP BY ip.ip_address

ORDER BY targeted_users DESC;


-- ============================================================
-- QUERY 6: IPs targeting multiple users with failures
-- ============================================================

SELECT
    ip.ip_address,
    COUNT(DISTINCT la.user_id) AS targeted_users,
    COUNT(*) AS failed_attempts

FROM login_attempts la

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

WHERE la.status = 'FAILED'

GROUP BY ip.ip_address

HAVING COUNT(DISTINCT la.user_id) >= 3

ORDER BY targeted_users DESC;


-- ============================================================
-- QUERY 7: HIGH-risk IP addresses
-- ============================================================

SELECT
    ip.ip_address,
    ip.risk_level,
    COUNT(la.attempt_id) AS total_attempts,

    SUM(
        CASE
            WHEN la.status = 'FAILED' THEN 1
            ELSE 0
        END
    ) AS failed_attempts

FROM ip_addresses ip

LEFT JOIN login_attempts la
    ON ip.ip_id = la.ip_id

WHERE ip.risk_level = 'HIGH'

GROUP BY
    ip.ip_address,
    ip.risk_level

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 8: Failure rate by IP
-- ============================================================

SELECT
    ip.ip_address,

    COUNT(*) AS total_attempts,

    SUM(
        CASE
            WHEN la.status = 'FAILED' THEN 1
            ELSE 0
        END
    ) AS failed_attempts,

    ROUND(
        100.0 *
        SUM(
            CASE
                WHEN la.status = 'FAILED' THEN 1
                ELSE 0
            END
        ) / COUNT(*),
        2
    ) AS failure_rate

FROM login_attempts la

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

GROUP BY ip.ip_address

ORDER BY failure_rate DESC;


-- ============================================================
-- QUERY 9: Suspicious IP and targeted users
-- ============================================================

SELECT
    ip.ip_address,
    ip.risk_level,
    u.username,
    COUNT(*) AS failed_attempts

FROM login_attempts la

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

JOIN users u
    ON la.user_id = u.user_id

WHERE
    la.status = 'FAILED'
    AND ip.risk_level = 'HIGH'

GROUP BY
    ip.ip_address,
    ip.risk_level,
    u.username

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 10: IPs with failures above the average IP failure count
-- Subquery
-- ============================================================

SELECT
    ip.ip_address,
    COUNT(*) AS failed_attempts

FROM login_attempts la

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

WHERE la.status = 'FAILED'

GROUP BY ip.ip_address

HAVING COUNT(*) >
(
    SELECT AVG(ip_failure_count)
    FROM
    (
        SELECT
            ip_id,
            COUNT(*) AS ip_failure_count

        FROM login_attempts

        WHERE status = 'FAILED'

        GROUP BY ip_id
    ) AS ip_stats
)

ORDER BY failed_attempts DESC;


-- ============================================================
-- END OF IP SECURITY ANALYSIS
-- ============================================================
