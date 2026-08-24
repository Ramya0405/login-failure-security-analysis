-- ============================================================
-- Project: Login Failure & Security Analysis
-- File: 07_advanced_window_functions.sql
-- Purpose: Advanced analysis using SQL window functions
-- Database: MySQL 8+
-- ============================================================

USE login_security_analysis;


-- ============================================================
-- QUERY 1: Rank users by failed login attempts
-- RANK()
-- ============================================================

WITH user_failures AS
(
    SELECT
        user_id,
        COUNT(*) AS failed_attempts

    FROM login_attempts

    WHERE status = 'FAILED'

    GROUP BY user_id
)

SELECT
    u.username,
    uf.failed_attempts,

    RANK() OVER
    (
        ORDER BY uf.failed_attempts DESC
    ) AS failure_rank

FROM user_failures uf

JOIN users u
    ON uf.user_id = u.user_id

ORDER BY failure_rank;


-- ============================================================
-- QUERY 2: Dense rank IP addresses by failures
-- DENSE_RANK()
-- ============================================================

WITH ip_failures AS
(
    SELECT
        ip_id,
        COUNT(*) AS failed_attempts

    FROM login_attempts

    WHERE status = 'FAILED'

    GROUP BY ip_id
)

SELECT
    ip.ip_address,
    ipf.failed_attempts,

    DENSE_RANK() OVER
    (
        ORDER BY ipf.failed_attempts DESC
    ) AS ip_rank

FROM ip_failures ipf

JOIN ip_addresses ip
    ON ipf.ip_id = ip.ip_id

ORDER BY ip_rank;


-- ============================================================
-- QUERY 3: Rank users within each department
-- PARTITION BY
-- ============================================================

WITH user_failures AS
(
    SELECT
        u.user_id,
        u.username,
        u.department,
        COUNT(la.attempt_id) AS failed_attempts

    FROM login_attempts la

    JOIN users u
        ON la.user_id = u.user_id

    WHERE la.status = 'FAILED'

    GROUP BY
        u.user_id,
        u.username,
        u.department
)

SELECT
    username,
    department,
    failed_attempts,

    RANK() OVER
    (
        PARTITION BY department
        ORDER BY failed_attempts DESC
    ) AS department_rank

FROM user_failures

ORDER BY
    department,
    department_rank;


-- ============================================================
-- QUERY 4: Previous login status
-- LAG()
-- ============================================================

SELECT
    u.username,
    la.attempt_time,
    la.status,

    LAG(la.status) OVER
    (
        PARTITION BY la.user_id
        ORDER BY la.attempt_time
    ) AS previous_status

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

ORDER BY
    u.username,
    la.attempt_time;


-- ============================================================
-- QUERY 5: Next login status
-- LEAD()
-- ============================================================

SELECT
    u.username,
    la.attempt_time,
    la.status,

    LEAD(la.status) OVER
    (
        PARTITION BY la.user_id
        ORDER BY la.attempt_time
    ) AS next_status

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

ORDER BY
    u.username,
    la.attempt_time;


-- ============================================================
-- QUERY 6: Detect failure followed by success
-- LAG()
-- ============================================================

WITH login_sequence AS
(
    SELECT
        la.*,

        LAG(status) OVER
        (
            PARTITION BY user_id
            ORDER BY attempt_time
        ) AS previous_status

    FROM login_attempts la
)

SELECT
    u.username,
    ls.attempt_time,
    ls.previous_status,
    ls.status

FROM login_sequence ls

JOIN users u
    ON ls.user_id = u.user_id

WHERE
    ls.previous_status = 'FAILED'
    AND ls.status = 'SUCCESS'

ORDER BY ls.attempt_time;


-- ============================================================
-- QUERY 7: Running count of failed attempts per user
-- ============================================================

SELECT
    u.username,
    la.attempt_time,
    la.status,

    SUM(
        CASE
            WHEN la.status = 'FAILED' THEN 1
            ELSE 0
        END
    ) OVER
    (
        PARTITION BY la.user_id
        ORDER BY la.attempt_time
        ROWS BETWEEN UNBOUNDED PRECEDING
        AND CURRENT ROW
    ) AS running_failed_attempts

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

ORDER BY
    u.username,
    la.attempt_time;


-- ============================================================
-- QUERY 8: Running failure count by IP
-- ============================================================

SELECT
    ip.ip_address,
    la.attempt_time,
    la.status,

    SUM(
        CASE
            WHEN la.status = 'FAILED' THEN 1
            ELSE 0
        END
    ) OVER
    (
        PARTITION BY la.ip_id
        ORDER BY la.attempt_time
        ROWS BETWEEN UNBOUNDED PRECEDING
        AND CURRENT ROW
    ) AS running_ip_failures

FROM login_attempts la

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

ORDER BY
    ip.ip_address,
    la.attempt_time;


-- ============================================================
-- QUERY 9: Compare each user's failures with department average
-- AVG() OVER()
-- ============================================================

WITH user_failures AS
(
    SELECT
        u.user_id,
        u.username,
        u.department,
        COUNT(la.attempt_id) AS failed_attempts

    FROM login_attempts la

    JOIN users u
        ON la.user_id = u.user_id

    WHERE la.status = 'FAILED'

    GROUP BY
        u.user_id,
        u.username,
        u.department
)

SELECT
    username,
    department,
    failed_attempts,

    ROUND(
        AVG(failed_attempts) OVER
        (
            PARTITION BY department
        ),
        2
    ) AS department_average_failures

FROM user_failures

ORDER BY department, failed_attempts DESC;


-- ============================================================
-- QUERY 10: Users above their department average
-- ============================================================

WITH user_failures AS
(
    SELECT
        u.user_id,
        u.username,
        u.department,
        COUNT(la.attempt_id) AS failed_attempts

    FROM login_attempts la

    JOIN users u
        ON la.user_id = u.user_id

    WHERE la.status = 'FAILED'

    GROUP BY
        u.user_id,
        u.username,
        u.department
),

department_stats AS
(
    SELECT
        username,
        department,
        failed_attempts,

        AVG(failed_attempts) OVER
        (
            PARTITION BY department
        ) AS department_average

    FROM user_failures
)

SELECT
    username,
    department,
    failed_attempts,
    ROUND(department_average, 2) AS department_average

FROM department_stats

WHERE failed_attempts > department_average

ORDER BY
    department,
    failed_attempts DESC;


-- ============================================================
-- QUERY 11: Identify the top 3 users by failures
-- ROW_NUMBER()
-- ============================================================

WITH user_failures AS
(
    SELECT
        u.user_id,
        u.username,
        COUNT(*) AS failed_attempts

    FROM login_attempts la

    JOIN users u
        ON la.user_id = u.user_id

    WHERE la.status = 'FAILED'

    GROUP BY
        u.user_id,
        u.username
),

ranked_users AS
(
    SELECT
        username,
        failed_attempts,

        ROW_NUMBER() OVER
        (
            ORDER BY failed_attempts DESC
        ) AS row_num

    FROM user_failures
)

SELECT
    username,
    failed_attempts,
    row_num AS ranking

FROM ranked_users

WHERE row_num <= 3

ORDER BY ranking;


-- ============================================================
-- QUERY 12: Identify the top 3 IPs by failures
-- ============================================================

WITH ip_failures AS
(
    SELECT
        ip.ip_address,
        COUNT(*) AS failed_attempts

    FROM login_attempts la

    JOIN ip_addresses ip
        ON la.ip_id = ip.ip_id

    WHERE la.status = 'FAILED'

    GROUP BY ip.ip_address
),

ranked_ips AS
(
    SELECT
        ip_address,
        failed_attempts,

        ROW_NUMBER() OVER
        (
            ORDER BY failed_attempts DESC
        ) AS row_num

    FROM ip_failures
)

SELECT
    ip_address,
    failed_attempts,
    row_num AS ranking

FROM ranked_ips

WHERE row_num <= 3

ORDER BY ranking;


-- ============================================================
-- QUERY 13: Time between consecutive login attempts
-- TIMESTAMPDIFF + LAG()
-- ============================================================

WITH login_sequence AS
(
    SELECT
        user_id,
        attempt_time,

        LAG(attempt_time) OVER
        (
            PARTITION BY user_id
            ORDER BY attempt_time
        ) AS previous_attempt_time

    FROM login_attempts
)

SELECT
    u.username,
    ls.attempt_time,
    ls.previous_attempt_time,

    TIMESTAMPDIFF(
        MINUTE,
        ls.previous_attempt_time,
        ls.attempt_time
    ) AS minutes_since_previous_attempt

FROM login_sequence ls

JOIN users u
    ON ls.user_id = u.user_id

WHERE ls.previous_attempt_time IS NOT NULL

ORDER BY minutes_since_previous_attempt;


-- ============================================================
-- QUERY 14: Very rapid repeated login attempts
-- Less than 5 minutes apart
-- ============================================================

WITH login_sequence AS
(
    SELECT
        la.*,

        LAG(attempt_time) OVER
        (
            PARTITION BY user_id
            ORDER BY attempt_time
        ) AS previous_attempt_time

    FROM login_attempts la
)

SELECT
    u.username,
    ip.ip_address,
    ls.attempt_time,
    ls.previous_attempt_time,

    TIMESTAMPDIFF(
        MINUTE,
        ls.previous_attempt_time,
        ls.attempt_time
    ) AS minutes_between_attempts,

    ls.status

FROM login_sequence ls

JOIN users u
    ON ls.user_id = u.user_id

JOIN ip_addresses ip
    ON ls.ip_id = ip.ip_id

WHERE
    ls.previous_attempt_time IS NOT NULL
    AND TIMESTAMPDIFF(
        MINUTE,
        ls.previous_attempt_time,
        ls.attempt_time
    ) <= 5

ORDER BY minutes_between_attempts;


-- ============================================================
-- QUERY 15: Final suspicious-user ranking
-- Combines failure count, failure rate and risk classification
-- ============================================================

WITH user_stats AS
(
    SELECT
        u.user_id,
        u.username,

        COUNT(*) AS total_attempts,

        SUM(
            CASE
                WHEN la.status = 'FAILED' THEN 1
                ELSE 0
            END
        ) AS failed_attempts

    FROM login_attempts la

    JOIN users u
        ON la.user_id = u.user_id

    GROUP BY
        u.user_id,
        u.username
),

user_risk AS
(
    SELECT
        user_id,
        username,
        total_attempts,
        failed_attempts,

        ROUND(
            100.0 * failed_attempts / total_attempts,
            2
        ) AS failure_rate

    FROM user_stats
)

SELECT
    username,
    total_attempts,
    failed_attempts,
    failure_rate,

    CASE

        WHEN failure_rate >= 75
             AND failed_attempts >= 10
        THEN 'HIGH RISK'

        WHEN failure_rate >= 50
             OR failed_attempts >= 10
        THEN 'MEDIUM RISK'

        ELSE 'LOW RISK'

    END AS risk_category,

    RANK() OVER
    (
        ORDER BY
            failed_attempts DESC,
            failure_rate DESC
    ) AS overall_risk_rank

FROM user_risk

ORDER BY overall_risk_rank;


-- ============================================================
-- END OF ADVANCED WINDOW FUNCTION ANALYSIS
-- ============================================================
