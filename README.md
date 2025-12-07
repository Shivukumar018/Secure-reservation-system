Secure Reservation System with Reverse Proxy

This project implements a secure reservation platform built with FastAPI and Redis. At the core of the system is a custom reverse proxy that inspects and filters all incoming requests before they reach the backend. The proxy provides SQL injection detection, XSS detection, brute force protection, rate limiting, IP blocking, and security logging. A Streamlit dashboard is included for real-time monitoring and analytics.

1. Overview

The system demonstrates how a reservation-based web application can be protected using a lightweight security layer similar to a Web Application Firewall.
Users interact with the frontend while every request is routed through the reverse proxy. The proxy evaluates the payload and blocks anything suspicious. The backend is isolated and only accepts requests that include a valid internal secret header sent by the proxy.

This structure makes the project suitable for academic submissions, cybersecurity demonstrations, and portfolio use.

2. Key Features
Application

User registration and login
Train search simulation
Ticket booking and invoice generation
Persistent booking history
User-friendly HTML and CSS interface

Security (Reverse Proxy)

SQL injection detection
XSS detection
Rate limiting powered by Redis and Lua
Brute force login protection
IP blocking with temporary and permanent modes
Internal secret validation between proxy and backend
Centralized blocking and event logs
Streamlit dashboard for analytics

3. System Architecture

The user interacts with the frontend pages built with HTML and CSS.
All requests are routed to the security reverse proxy.
The proxy inspects each request for SQL injection patterns, XSS payloads, brute force attempts, and rate limit violations.
If malicious behavior is detected, the proxy blocks the request and logs the event.
Safe requests are forwarded to the backend API along with an internal secret header.
The backend performs login, reservation, search, and invoice functions.
SQLite stores user accounts and booking information.
Redis stores security counters, penalty statuses, and rate-limiting data.
A Streamlit-based admin dashboard displays real-time logs and analytics.

4. Folder Structure

mini_project/
│
├── .gitignore
├── README.md
├── start_all_services.bat
│
├── admin/
│   └── admin.py
│
├── backend/
│   └── main.py
│
├── frontend/
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css
│   │   └── img/
│   │       └── qr.png
│   │
│   └── templates/
│       ├── base.html
│       ├── book.html
│       ├── bookings.html
│       ├── dashboard.html
│       ├── index.html
│       ├── invoice.html
│       ├── login.html
│       ├── logout_success.html
│       ├── payment.html
│       ├── register.html
│       ├── search_auth.html
│       └── search_guest.html
│
└── security/
    ├── create_admin.py
    ├── proxy.py
    ├── state.py
    ├── utils.py
    ├── __init__.py
    │
    ├── logs/
    │   ├── sqlite_logger.py
    │   └── __init__.py
    │
    └── protections/
        ├── brute_force.py
        ├── ml_detector.py
        ├── queue_control.py
        ├── rate_limiter.py
        ├── sqli_detector.py
        ├── xss_detector.py
        └── __init__.py


5. Security Modules Overview
SQL Injection Detection

User input is normalized through URL decoding, HTML decoding, Unicode normalization, and SQL comment removal. The detector checks for patterns such as union-based injections, tautologies, stacked queries, encoded payloads, time delays, and hex-based SQL.
Testing accuracy was approximately 97 to 98 percent with minimal false positives.

XSS Detection

This module identifies script tags, event attributes, javascript URLs, SVG and IMG payloads, and encoded or obfuscated attack patterns.
Detection accuracy ranged from 90 to 94 percent.

Rate Limiting

Each IP is limited to 9 requests every 15 seconds.
Exceeding the limit triggers a temporary penalty stored in Redis, and further requests return a 429 error.

Brute Force Protection

Failed login attempts are tracked per user and per IP.
Repeated failures result in temporary or full IP blocks.
All blocks expire automatically after a set duration.

6. Admin Dashboard

The dashboard provides:
Active user counts
Blocked IP list
SQL injection and XSS detection logs
Rate limiter violations
Brute force attempts
Analytics charts
It runs on port 8501.

7. Running the Project

Start Redis using Docker.
Run the start_all_services.bat script.

This launches:
Backend on port 5000
Reverse proxy on port 8000
Admin dashboard on port 8501

8. Testing Examples

SQL Injection
' OR '1'='1
UNION SELECT 1,2,3
Encoded inputs such as %27 OR 1=1

XSS
script tag based injections
javascript URLs
image payloads with onerror

Brute Force
Repeated incorrect login attempts
Rate Limiting
More than 9 requests in 15 seconds

9. License

This project is intended for educational and portfolio purposes.

10. Contributions

You may fork this repository and extend the system.