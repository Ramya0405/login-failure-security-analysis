# Login Failure & Security Analysis — Results

## 1. Project Overview

This project analyzes authentication and login activity using MySQL.

The objective is to identify:

- Repeated login failures
- Suspicious IP addresses
- High-risk users
- Peak login-failure hours
- Unusual login patterns
- Potential brute-force behavior
- Failure-rate trends
- User and department-level authentication activity

The dataset contains synthetic login records created specifically for this project.

> Note: The results represent analysis of synthetic data and should not be interpreted as evidence of real-world cyber attacks.

---

# 2. Dataset Summary

| Dataset | Records |
|---|---:|
| Users | 30 |
| IP Addresses | 15 |
| Login Attempts | 1,000 |

### Main Tables

- `users`
- `ip_addresses`
- `login_attempts`

---

# 3. Key Metrics

The project calculates the following authentication metrics:

- Total login attempts
- Successful login attempts
- Failed login attempts
- Success rate
- Failure rate
- Failed attempts per user
- Failed attempts per IP
- Failure rate per user
- Failure rate per IP
- Failure rate by department
- Failure rate by device
- Failure rate by hour
- Failure rate by date

---

# 4. User-Level Findings

The analysis identifies users with unusually high login failures.

Users are classified based on:

- Total login attempts
- Failed login attempts
- Failure percentage
- Number of IP addresses used
- Activity from high-risk IP addresses

### Example interpretation

A user with:

- A high number of failed attempts
- A high failure rate
- Multiple source IP addresses
- Activity from high-risk IP addresses

should be investigated further.

The SQL analysis does not automatically classify such activity as a confirmed attack.

---

# 5. IP Security Findings

IP addresses are analyzed based on:

- Total login attempts
- Failed login attempts
- Failure rate
- Number of users targeted
- Risk level
- User/IP combinations

High-risk IP addresses with repeated failed attempts are highlighted for further investigation.

---

# 6. Time-Based Findings

Login failures are analyzed by:

- Hour
- Date
- Day of week
- Business hours
- Non-business hours

This helps identify periods where authentication failures are concentrated.

Particular attention should be given to:

- Large spikes in failures
- Repeated failures outside normal business hours
- Short periods containing many failed attempts

---

# 7. Failure Reason Analysis

The project analyzes the most common authentication failure reasons.

Possible failure categories include:

- Wrong Password
- Invalid Username
- Account Locked
- Expired Password

Understanding failure reasons helps distinguish normal user mistakes from potentially suspicious activity.

---

# 8. Potential Brute-Force Detection

The project searches for patterns such as:

1. Multiple failed attempts from the same user and IP.
2. Three or more failures within a short period.
3. Failed attempts followed by a successful login.
4. Multiple users being targeted from the same IP.
5. High-risk IP addresses generating repeated failures.

These patterns are treated as **potential indicators**, not confirmed attacks.

---

# 9. SQL Techniques Used

The project demonstrates:

```text
SELECT
WHERE
JOIN
LEFT JOIN
GROUP BY
HAVING
ORDER BY
CASE
COUNT
SUM
AVG
ROUND
Subqueries
CTEs
RANK
DENSE_RANK
ROW_NUMBER
LAG
LEAD
PARTITION BY
Window Functions
DATE()
HOUR()
DAYNAME()
TIMESTAMPDIFF()
DATE_ADD()
