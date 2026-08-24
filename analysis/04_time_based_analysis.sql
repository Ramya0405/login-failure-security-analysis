-- ============================================================
-- Project: Login Failure & Security Analysis
-- File: 04_time_based_analysis.sql
-- Purpose: Time-based login failure analysis
-- Database: MySQL 8+
-- ============================================================

USE login_security_analysis;


-- ============================================================
-- QUERY 1: Login attempts by hour
-- ============================================================

SELECT
    HOUR(attempt_time) AS login_hour,
    COUNT(*) AS total_attempts

FROM login_attempts

GROUP BY HOUR(attempt_time)

ORDER BY login_hour;


-- ============================================================
-- QUERY 2: Failed attempts by hour
-- ============================================================

SELECT
    HOUR(attempt_time) AS login_hour,
    COUNT(*) AS failed_attempts

FROM login_attempts

WHERE status = 'FAILED'

GROUP BY HOUR(attempt_time)

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 3: Failure rate by hour
-- ============================================================

SELECT
    HOUR(attempt_time) AS login_hour,

    COUNT(*) AS total_attempts,

    SUM(
        CASE
            WHEN status = 'FAILED' THEN 1
            ELSE 0
        END
    ) AS failed_attempts,

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

FROM login_attempts

GROUP BY HOUR(attempt_time)

ORDER BY failure_rate DESC;


-- ============================================================
-- QUERY 4: Daily login activity
-- ============================================================

SELECT
    DATE(attempt_time) AS login_date,
    COUNT(*) AS total_attempts

FROM login_attempts

GROUP BY DATE(attempt_time)

ORDER BY login_date;


-- ============================================================
-- QUERY 5: Daily failed login activity
-- ============================================================

SELECT
    DATE(attempt_time) AS login_date,
    COUNT(*) AS failed_attempts

FROM login_attempts

WHERE status = 'FAILED'

GROUP BY DATE(attempt_time)

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 6: Daily failure rate
-- ============================================================

SELECT
    DATE(attempt_time) AS login_date,

    COUNT(*) AS total_attempts,

    SUM(
        CASE
            WHEN status = 'FAILED' THEN 1
            ELSE 0
        END
    ) AS failed_attempts,

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

FROM login_attempts

GROUP BY DATE(attempt_time)

ORDER BY login_date;


-- ============================================================
-- QUERY 7: Peak failure hour
-- ============================================================

SELECT
    HOUR(attempt_time) AS login_hour,
    COUNT(*) AS failed_attempts

FROM login_attempts

WHERE status = 'FAILED'

GROUP BY HOUR(attempt_time)

ORDER BY failed_attempts DESC

LIMIT 1;


-- ============================================================
-- QUERY 8: Peak failure date
-- ============================================================

SELECT
    DATE(attempt_time) AS login_date,
    COUNT(*) AS failed_attempts

FROM login_attempts

WHERE status = 'FAILED'

GROUP BY DATE(attempt_time)

ORDER BY failed_attempts DESC

LIMIT 1;


-- ============================================================
-- QUERY 9: Failure activity by day of week
-- ============================================================

SELECT
    DAYNAME(attempt_time) AS day_name,
    COUNT(*) AS failed_attempts

FROM login_attempts

WHERE status = 'FAILED'

GROUP BY DAYNAME(attempt_time)

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 10: Business hours vs non-business hours
-- ============================================================

SELECT

    CASE
        WHEN HOUR(attempt_time) BETWEEN 9 AND 18
        THEN 'Business Hours'

        ELSE 'Non-Business Hours'
    END AS time_period,

    COUNT(*) AS total_attempts,

    SUM(
        CASE
            WHEN status = 'FAILED' THEN 1
            ELSE 0
        END
    ) AS failed_attempts

FROM login_attempts

GROUP BY
    CASE
        WHEN HOUR(attempt_time) BETWEEN 9 AND 18
        THEN 'Business Hours'
        ELSE 'Non-Business Hours'
    END

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 11: Suspicious failures outside business hours
-- ============================================================

SELECT
    ip.ip_address,
    COUNT(*) AS failed_attempts

FROM login_attempts la

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

WHERE
    la.status = 'FAILED'
    AND (
        HOUR(la.attempt_time) < 9
        OR HOUR(la.attempt_time) > 18
    )

GROUP BY ip.ip_address

ORDER BY failed_attempts DESC;


-- ============================================================
-- END OF TIME-BASED ANALYSIS
-- ============================================================
