

USE login_security_analysis;


-- 1. INSERT USERS

INSERT INTO users
    (user_id, username, department, account_status, created_date)
VALUES
    (1,  'ramya',      'IT',          'ACTIVE',  '2025-01-10'),
    (2,  'arjun',      'Finance',     'ACTIVE',  '2025-01-15'),
    (3,  'priya',      'HR',          'ACTIVE',  '2025-01-20'),
    (4,  'rahul',      'IT',          'ACTIVE',  '2025-02-01'),
    (5,  'ananya',     'Marketing',   'ACTIVE',  '2025-02-05'),
    (6,  'vikas',      'Sales',       'ACTIVE',  '2025-02-12'),
    (7,  'sneha',      'Finance',     'ACTIVE',  '2025-02-18'),
    (8,  'kiran',      'IT',          'ACTIVE',  '2025-03-01'),
    (9,  'meena',      'HR',          'ACTIVE',  '2025-03-10'),
    (10, 'rohit',      'Sales',       'ACTIVE',  '2025-03-15'),
    (11, 'neha',       'IT',          'ACTIVE',  '2025-03-20'),
    (12, 'sanjay',     'Finance',     'ACTIVE',  '2025-04-01'),
    (13, 'divya',      'Marketing',   'ACTIVE',  '2025-04-05'),
    (14, 'ashwin',     'IT',          'ACTIVE',  '2025-04-12'),
    (15, 'pooja',      'HR',          'ACTIVE',  '2025-04-18'),
    (16, 'manoj',      'Sales',       'ACTIVE',  '2025-05-01'),
    (17, 'kavya',      'Finance',     'ACTIVE',  '2025-05-08'),
    (18, 'naveen',     'IT',          'ACTIVE',  '2025-05-15'),
    (19, 'harini',     'Marketing',   'ACTIVE',  '2025-05-20'),
    (20, 'suresh',     'Sales',       'ACTIVE',  '2025-06-01'),
    (21, 'lakshmi',    'Finance',     'ACTIVE',  '2025-06-05'),
    (22, 'deepak',     'IT',          'ACTIVE',  '2025-06-10'),
    (23, 'swathi',     'HR',          'ACTIVE',  '2025-06-15'),
    (24, 'varun',      'Sales',       'ACTIVE',  '2025-06-20'),
    (25, 'keerthi',    'Marketing',   'ACTIVE',  '2025-07-01'),
    (26, 'aditya',     'IT',          'ACTIVE',  '2025-07-05'),
    (27, 'shreya',     'Finance',     'ACTIVE',  '2025-07-10'),
    (28, 'ganesh',     'Sales',       'ACTIVE',  '2025-07-15'),
    (29, 'aishwarya',  'HR',          'ACTIVE',  '2025-07-20'),
    (30, 'mohan',      'IT',          'LOCKED',  '2025-07-25');


-- 2. INSERT IP ADDRESSES

INSERT INTO ip_addresses
    (ip_id, ip_address, country, city, isp, risk_level)
VALUES
    (1,  '192.168.1.10',  'India', 'Hyderabad',  'Jio',        'LOW'),
    (2,  '192.168.1.11',  'India', 'Bangalore',  'Airtel',     'LOW'),
    (3,  '192.168.1.12',  'India', 'Chennai',    'Jio',        'LOW'),
    (4,  '192.168.1.13',  'India', 'Mumbai',     'Airtel',     'LOW'),
    (5,  '192.168.1.14',  'India', 'Delhi',      'ACT',        'LOW'),
    (6,  '10.0.0.15',     'India', 'Pune',       'Jio',        'LOW'),
    (7,  '10.0.0.16',     'India', 'Kolkata',    'Airtel',     'MEDIUM'),
    (8,  '10.0.0.17',     'India', 'Vijayawada', 'BSNL',       'MEDIUM'),
    (9,  '172.16.0.18',   'India', 'Hyderabad',  'ACT',        'MEDIUM'),
    (10, '172.16.0.19',   'India', 'Bangalore',  'Jio',        'MEDIUM'),

    -- Suspicious IPs
    (11, '45.83.12.101',  'Unknown', 'Unknown', 'Unknown ISP', 'HIGH'),
    (12, '103.21.45.77',   'Unknown', 'Unknown', 'Unknown ISP', 'HIGH'),
    (13, '185.22.91.34',   'Unknown', 'Unknown', 'Unknown ISP', 'HIGH'),
    (14, '91.240.118.22',  'Unknown', 'Unknown', 'Unknown ISP', 'HIGH'),
    (15, '198.51.100.45',  'Unknown', 'Unknown', 'Unknown ISP', 'HIGH');

-- 3. GENERATE 1,000 LOGIN ATTEMPTS

-- The generated data contains:
--
-- 1. Normal successful logins
-- 2. Normal failed logins
-- 3. Repeated failures
-- 4. Suspicious IP activity
-- 5. Failed attempts followed by success
-- 6. Different login hours
-- 7. Different devices
-- 8. Different failure reasons


INSERT INTO login_attempts
(
    attempt_id,
    user_id,
    ip_id,
    attempt_time,
    status,
    failure_reason,
    device_type
)

WITH RECURSIVE numbers AS
(
    SELECT 1 AS n

    UNION ALL

    SELECT n + 1
    FROM numbers
    WHERE n < 1000
)

SELECT

    n AS attempt_id,

    
    CASE
        WHEN n % 20 IN (0,1,2,3) THEN 2
        WHEN n % 20 IN (4,5) THEN 8
        WHEN n % 20 = 6 THEN 15
        WHEN n % 20 = 7 THEN 30
        ELSE ((n - 1) % 26) + 1
    END AS user_id,


    /*
       Assign IP addresses.

       Every 7th attempt uses a suspicious IP.
    */
    CASE
        WHEN n % 31 = 0 THEN 11
        WHEN n % 37 = 0 THEN 12
        WHEN n % 43 = 0 THEN 13
        WHEN n % 53 = 0 THEN 14
        WHEN n % 61 = 0 THEN 15
        ELSE ((n - 1) % 10) + 1
    END AS ip_id,


    /*
       Generate login timestamps.

       Dates range from August 1 to August 20, 2026.
       Hours vary from 00:00 to 23:59.
    */
    TIMESTAMP(
        DATE_ADD(
            '2026-08-01',
            INTERVAL MOD(n, 20) DAY
        ),
        MAKETIME(
            MOD(n * 7, 24),
            MOD(n * 13, 60),
            MOD(n * 17, 60)
        )
    ) AS attempt_time,


    /*
       Generate SUCCESS / FAILED status.

       Approximately 30% of the generated attempts
       are failures.
       
       Suspicious IPs have a much higher failure rate.
    */
    CASE
        WHEN n % 31 = 0 THEN 'FAILED'
        WHEN n % 37 = 0 THEN 'FAILED'
        WHEN n % 43 = 0 THEN 'FAILED'
        WHEN n % 53 = 0 THEN 'FAILED'
        WHEN n % 61 = 0 THEN 'FAILED'

        WHEN n % 10 IN (0,1,2) THEN 'FAILED'

        ELSE 'SUCCESS'
    END AS status,


    /*
       Generate realistic failure reasons.
    */
    CASE

        WHEN n % 31 = 0
          OR n % 37 = 0
          OR n % 43 = 0
          OR n % 53 = 0
          OR n % 61 = 0
        THEN
            CASE MOD(n,4)
                WHEN 0 THEN 'Wrong Password'
                WHEN 1 THEN 'Invalid Username'
                WHEN 2 THEN 'Account Locked'
                ELSE 'Expired Password'
            END

        WHEN n % 10 IN (0,1,2)
        THEN
            CASE MOD(n,4)
                WHEN 0 THEN 'Wrong Password'
                WHEN 1 THEN 'Invalid Username'
                WHEN 2 THEN 'Wrong Password'
                ELSE 'Expired Password'
            END

        ELSE NULL

    END AS failure_reason,


    /*
       Rotate devices.
    */
    CASE MOD(n,3)
        WHEN 0 THEN 'Desktop'
        WHEN 1 THEN 'Mobile'
        ELSE 'Tablet'
    END AS device_type

FROM numbers;


-- ============================================================
-- 4. VERIFY INSERTED DATA
-- ============================================================

SELECT
    COUNT(*) AS total_login_attempts
FROM login_attempts;


SELECT
    COUNT(*) AS total_users
FROM users;


SELECT
    COUNT(*) AS total_ip_addresses
FROM ip_addresses;


-- ============================================================
-- 5. BASIC DATA VALIDATION
-- ============================================================

SELECT
    status,
    COUNT(*) AS total_attempts
FROM login_attempts
GROUP BY status;


SELECT
    failure_reason,
    COUNT(*) AS total_failures
FROM login_attempts
WHERE status = 'FAILED'
GROUP BY failure_reason
ORDER BY total_failures DESC;


-- ============================================================
-- END OF DATA INSERTION
-- ============================================================
