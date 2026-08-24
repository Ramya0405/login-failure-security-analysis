-- ============================================================
-- Project: Login Failure & Security Analysis
-- File: 06_bruteforce_detection.sql
-- Purpose: Detect potential brute-force login behavior
-- Database: MySQL 8+
-- ============================================================

USE login_security_analysis;


-- ============================================================
-- QUERY 1: Failed attempts by user and IP
-- ============================================================

SELECT
    u.username,
    ip.ip_address,
    COUNT(*) AS failed_attempts

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

WHERE la.status = 'FAILED'

GROUP BY
    u.username,
    ip.ip_address

HAVING COUNT(*) >= 3

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 2: Users receiving failures from HIGH-risk IPs
-- ============================================================

SELECT
    u.username,
    ip.ip_address,
    COUNT(*) AS failed_attempts

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

WHERE
    la.status = 'FAILED'
    AND ip.risk_level = 'HIGH'

GROUP BY
    u.username,
    ip.ip_address

HAVING COUNT(*) >= 3

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 3: Detect 3 failed attempts within 10 minutes
-- ============================================================

SELECT
    la1.user_id,
    u.username,
    la1.ip_id,
    ip.ip_address,
    la1.attempt_time AS first_failure,
    la2.attempt_time AS second_failure,
    la3.attempt_time AS third_failure

FROM login_attempts la1

JOIN login_attempts la2
    ON la1.user_id = la2.user_id
    AND la1.ip_id = la2.ip_id
    AND la2.attempt_time > la1.attempt_time
    AND la2.attempt_time <=
        DATE_ADD(la1.attempt_time, INTERVAL 10 MINUTE)

JOIN login_attempts la3
    ON la2.user_id = la3.user_id
    AND la2.ip_id = la3.ip_id
    AND la3.attempt_time > la2.attempt_time
    AND la3.attempt_time <=
        DATE_ADD(la1.attempt_time, INTERVAL 10 MINUTE)

JOIN users u
    ON la1.user_id = u.user_id

JOIN ip_addresses ip
    ON la1.ip_id = ip.ip_id

WHERE
    la1.status = 'FAILED'
    AND la2.status = 'FAILED'
    AND la3.status = 'FAILED'

ORDER BY first_failure;


-- ============================================================
-- QUERY 4: Failed attempts immediately followed by success
-- Uses LAG()
-- ============================================================

WITH login_sequence AS
(
    SELECT
        la.attempt_id,
        la.user_id,
        la.ip_id,
        la.attempt_time,
        la.status,

        LAG(la.status) OVER
        (
            PARTITION BY la.user_id
            ORDER BY la.attempt_time
        ) AS previous_status

    FROM login_attempts la
)

SELECT
    u.username,
    ls.attempt_time,
    ls.status,
    ls.previous_status

FROM login_sequence ls

JOIN users u
    ON ls.user_id = u.user_id

WHERE
    ls.status = 'SUCCESS'
    AND ls.previous_status = 'FAILED'

ORDER BY ls.attempt_time;


-- ============================================================
-- QUERY 5: Failed attempts followed by success from same IP
-- ============================================================

WITH login_sequence AS
(
    SELECT
        la.attempt_id,
        la.user_id,
        la.ip_id,
        la.attempt_time,
        la.status,

        LAG(la.status) OVER
        (
            PARTITION BY la.user_id, la.ip_id
            ORDER BY la.attempt_time
        ) AS previous_status

    FROM login_attempts la
)

SELECT
    u.username,
    ip.ip_address,
    ls.attempt_time,
    ls.status,
    ls.previous_status

FROM login_sequence ls

JOIN users u
    ON ls.user_id = u.user_id

JOIN ip_addresses ip
    ON ls.ip_id = ip.ip_id

WHERE
    ls.status = 'SUCCESS'
    AND ls.previous_status = 'FAILED'

ORDER BY ls.attempt_time;


-- ============================================================
-- QUERY 6: Count failures before each successful login
-- ============================================================

WITH ordered_logins AS
(
    SELECT
        la.*,

        SUM(
            CASE
                WHEN la.status = 'SUCCESS' THEN 1
                ELSE 0
            END
        ) OVER
        (
            PARTITION BY la.user_id
            ORDER BY la.attempt_time
        ) AS success_group

    FROM login_attempts la
),

failure_groups AS
(
    SELECT
        user_id,
        success_group,
        COUNT(*) AS failures_before_success

    FROM ordered_logins

    WHERE status = 'FAILED'

    GROUP BY
        user_id,
        success_group
)

SELECT
    u.username,
    fg.failures_before_success

FROM failure_groups fg

JOIN users u
    ON fg.user_id = u.user_id

WHERE fg.failures_before_success >= 3

ORDER BY failures_before_success DESC;


-- ============================================================
-- QUERY 7: Suspicious activity from HIGH-risk IPs
-- ============================================================

SELECT
    u.username,
    ip.ip_address,
    ip.risk_level,
    COUNT(*) AS failed_attempts

FROM login_attempts la

JOIN users u
    ON la.user_id = u.user_id

JOIN ip_addresses ip
    ON la.ip_id = ip.ip_id

WHERE
    la.status = 'FAILED'
    AND ip.risk_level = 'HIGH'

GROUP BY
    u.username,
    ip.ip_address,
    ip.risk_level

HAVING COUNT(*) >= 3

ORDER BY failed_attempts DESC;


-- ============================================================
-- QUERY 8: Possible brute-force summary
-- ============================================================

WITH suspicious_activity AS
(
    SELECT
        user_id,
        ip_id,
        COUNT(*) AS failed_attempts

    FROM login_attempts

    WHERE status = 'FAILED'

    GROUP BY
        user_id,
        ip_id
)

SELECT
    u.username,
    ip.ip_address,
    sa.failed_attempts,

    CASE
        WHEN sa.failed_attempts >= 10
             AND ip.risk_level = 'HIGH'
        THEN 'HIGH RISK'

        WHEN sa.failed_attempts >= 5
        THEN 'MEDIUM RISK'

        ELSE 'LOW RISK'

    END AS security_classification

FROM suspicious_activity sa

JOIN users u
    ON sa.user_id = u.user_id

JOIN ip_addresses ip
    ON sa.ip_id = ip.ip_id

WHERE sa.failed_attempts >= 3

ORDER BY sa.failed_attempts DESC;


-- ============================================================
-- END OF BRUTE-FORCE DETECTION
-- ============================================================
