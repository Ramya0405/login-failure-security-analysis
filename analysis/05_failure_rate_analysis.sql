-- ============================================================
-- Project: Login Failure & Security Analysis
-- File: 05_failure_rate_analysis.sql
-- Purpose: Failure-rate and anomaly analysis
-- Database: MySQL 8+
-- ============================================================

USE login_security_analysis;


-- ============================================================
-- QUERY 1: Failure rate for every user
-- ============================================================

SELECT
    u.username,

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

JOIN users u
    ON la.user_id = u.user_id

GROUP BY u.username

ORDER BY failure_rate DESC;


-- ============================================================
-- QUERY 2: Users with failure rate above 50%
-- ============================================================

SELECT
    u.username,

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

JOIN users u
    ON la.user_id = u.user_id

GROUP BY u.username

HAVING failure_rate > 50

ORDER BY failure_rate DESC;


-- ============================================================
-- QUERY 3: Users above the average failure rate
-- CTE
-- ============================================================

WITH user_stats AS
(
    SELECT
        user_id,

        COUNT(*) AS total_attempts,

        SUM(
            CASE
                WHEN status = 'FAILED' THEN 1
                ELSE 0
            END
        ) AS failed_attempts

    FROM login_attempts

    GROUP BY user_id
),

user_rates AS
(
    SELECT
        user_id,
        total_attempts,
        failed_attempts,

        100.0 * failed_attempts / total_attempts
        AS failure_rate

    FROM user_stats
)

SELECT
    u.username,
    ur.total_attempts,
    ur.failed_attempts,
    ROUND(ur.failure_rate, 2) AS failure_rate

FROM user_rates ur

JOIN users u
    ON ur.user_id = u.user_id

WHERE ur.failure_rate >
(
    SELECT AVG(failure_rate)
    FROM user_rates
)

ORDER BY ur.failure_rate DESC;


-- ============================================================
-- QUERY 4: Failure rate by department
-- ============================================================

SELECT
    u.department,

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

JOIN users u
    ON la.user_id = u.user_id

GROUP BY u.department

ORDER BY failure_rate DESC;


-- ============================================================
-- QUERY 5: Failure rate by IP
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
-- QUERY 6: Classify users based on failure rate
-- CASE expression
-- ============================================================

SELECT
    u.username,

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
    ) AS failure_rate,

    CASE

        WHEN
            100.0 *
            SUM(
                CASE
                    WHEN la.status = 'FAILED' THEN 1
                    ELSE 0
                END
            ) / COUNT(*) >= 75
        THEN 'HIGH RISK'

        WHEN
            100.0 *
            SUM(
                CASE
                    WHEN la.status = 'FAILED' THEN 1
                    ELSE 0
                END
            ) / COUNT(*) >= 50
        THEN 'MEDIUM RISK'

        ELSE 'LOW RISK'

    END AS risk_category

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

GROUP BY u.username

ORDER BY failure_rate DESC;


-- ============================================================
-- QUERY 7: Failure rate by device
-- ============================================================

SELECT
    device_type,

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

GROUP BY device_type

ORDER BY failure_rate DESC;


-- ============================================================
-- QUERY 8: Failure rate by risk level
-- ============================================================

SELECT
    ip.risk_level,

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

GROUP BY ip.risk_level

ORDER BY failure_rate DESC;


-- ============================================================
-- END OF FAILURE RATE ANALYSIS
-- ============================================================
