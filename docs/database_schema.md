# Database Schema

## Login Failure & Security Analysis

Database: `login_security_analysis`

DBMS: MySQL 8+

---

## 1. Entity Relationship Diagram

```text
┌──────────────────────────────┐
│            users             │
├──────────────────────────────┤
│ PK  user_id                  │
│     username                 │
│     department               │
│     account_status           │
│     created_date             │
└──────────────┬───────────────┘
               │
               │ 1
               │
               │ N
┌──────────────▼───────────────┐
│       login_attempts         │
├──────────────────────────────┤
│ PK  attempt_id               │
│ FK  user_id                  │
│ FK  ip_id                    │
│     attempt_time             │
│     status                   │
│     failure_reason           │
│     device_type              │
└──────────────┬───────────────┘
               │
               │ N
               │
               │ 1
┌──────────────▼───────────────┐
│        ip_addresses          │
├──────────────────────────────┤
│ PK  ip_id                    │
│     ip_address               │
│     country                  │
│     city                     │
│     isp                      │
│     risk_level               │
└──────────────────────────────┘
