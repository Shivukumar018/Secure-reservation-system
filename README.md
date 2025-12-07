Secure Reservation System with Reverse Proxy

This project implements a secure reservation platform built with FastAPI and Redis. At the core of the system is a custom reverse proxy that inspects and filters all incoming requests before they reach the backend. The proxy provides SQL injection detection, XSS detection, brute force protection, rate limiting, IP blocking, and security logging. A Streamlit dashboard is included for real-time monitoring and analytics.

1. Overview

This system shows how a reservation-based web application can be protected using a lightweight security layer that acts like a simple Web Application Firewall. Users interact with the frontend, and every request first goes through the reverse proxy. The proxy analyzes the incoming payload and blocks anything that appears suspicious. The backend remains isolated and only accepts requests that include a valid internal secret header that is added by the proxy.
This architecture ensures that unsafe traffic is filtered out before reaching the application.

2. Key Features
The application supports user registration, login, train search, ticket booking, invoice generation, and persistent booking history. It uses a clean interface built with HTML and CSS.

The reverse proxy provides multiple security functions such as SQL injection detection, XSS detection, rate limiting powered by Redis and Lua scripts, brute-force login protection, temporary and permanent IP blocking, and internal secret validation between the proxy and backend. It also logs blocked events and provides analytics through a Streamlit dashboard.

3. System Architecture

Users access the frontend pages built using HTML and CSS. All traffic is routed through the security reverse proxy, which evaluates each request for potential SQL injection attempts, XSS payloads, brute-force patterns, and rate-limit violations. If a request is considered harmful, the proxy blocks it and records the event.
If the request is safe, the proxy forwards it to the backend API along with an internal secret header.

The backend handles all application features including login, searching trains, managing bookings, and generating invoices. User data and booking information are stored in SQLite, while Redis is used to store security counters, penalty values, and rate-limiting data.
A Streamlit-based admin dashboard displays logs, blocked IPs, and real-time analytics.

4. Folder Structure

```
mini_project/
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
```



5. Security Modules Overview
SQL Injection Detection

SQL injection protection works by normalizing user input before analysis. This process includes URL decoding, HTML decoding, Unicode normalization, and the removal of SQL comments. After the input is cleaned, the system checks for common SQLi patterns such as union-based injections, tautologies, stacked queries, encoded payloads, time-delay functions, and hex-encoded SQL. During testing, the detection accuracy was roughly 97 to 98 percent, with very few false positives.

XSS Detection

The XSS detection module scans for script tags, event handler attributes, javascript URLs, SVG and IMG-based attacks, and different forms of encoded or obfuscated payloads. It successfully detects most real-world attack patterns, with a testing accuracy between 90 and 94 percent.

Rate Limiting

Rate limiting ensures that each IP address can send only nine requests every fifteen seconds. If this limit is exceeded, the proxy assigns a temporary penalty to the IP using Redis, and any further requests from that IP receive a 429 error response until the penalty expires.

Brute Force Protection

Brute force protection monitors failed login attempts for both individual users and IP addresses. When repeated failures are detected, the system either slows down the attacker with temporary penalties or blocks the IP entirely for a period of time. All blocks automatically expire after their designated duration.

Admin Dashboard

The admin dashboard provides a real-time view of system activity. It shows the number of active users, the list of blocked IP addresses, recent SQL injection and XSS detection logs, rate limiter violations, and brute-force attempts. It also includes simple analytics charts to help monitor security events. The dashboard runs on port 8501.

6. Running the Project

Start Redis using Docker.

Run the start_all_services.bat script.

This launches:
Backend on port 5000

Reverse proxy on port 8000

Admin dashboard on port 8501

8. Testing Examples

The system can be tested using different types of simulated attacks. For SQL injection, inputs such as ' OR '1'='1, UNION SELECT 1,2,3, and encoded forms like %27 OR 1=1 can be used. For XSS, tests may include script tag injections, javascript URLs, and image payloads containing onerror attributes. Brute force protection can be tested by repeatedly entering incorrect login credentials, while rate limiting can be verified by sending more than nine requests within fifteen seconds.

9. License

This project is intended for educational and portfolio purposes.

10. Contributions

You may fork this repository and extend the system.


The ml_detector.py and queue_control.py modules are present in the codebase for exploratory purposes. They are not active components of the security pipeline and were not part of the mini project's scope or final feature set.