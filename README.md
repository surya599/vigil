# NetPulse – Real-Time Network Monitoring and Management System

NetPulse is a full-stack, enterprise-grade Network Operations Center (NOC) and network device monitoring system built with Python, Django, Django REST Framework, Django Channels, PostgreSQL, Celery, and Redis. It provides real-time availability tracking, latency and packet loss metrics, SNMPv2c/v3 telemetry, dynamic traffic analytics with Chart.js, interactive network topology mapping, and an automated incident alert engine.

---

## Architecture Overview

```
                      +-----------------------------+
                      |     Web Clients (Browser)   |
                      |   Dark-Themed NOC Dashboard |
                      +--------------+--------------+
                                     |
               +---------------------+---------------------+
               | HTTP / REST API                           | WebSockets (WSS)
               v                                           v
      +-----------------+                         +-----------------+
      |  Django / WSGI  |                         |  Daphne / ASGI  |
      +--------+--------+                         +--------+--------+
               |                                           |
               |                                           v
               |                                  +-----------------+
               |                                  |  Channels Redis |
               |                                  +-----------------+
               v                                           ^
+-------------------------------+                          |
|      PostgreSQL Database      |<-------------------------+
|  Devices, Metrics, Incidents  |                          |
+---------------+---------------+                          |
                ^                                          |
                | Writes monitoring metrics                | Broadcasts status
                |                                          |
+---------------+------------------------------------------+--------+
|                      Celery Workers & Beat                        |
|   +--------------------+  +------------------+  +---------------+ |
|   | ICMP Ping Engine   |  | SNMP Telemetry   |  | Alert Engine  | |
|   +--------------------+  +------------------+  +---------------+ |
+-------------------------------------------------------------------+
```

---

## Technology Stack

- **Backend:** Python 3.12, Django 5.x / 6.x, Django REST Framework, Django Channels, Daphne, Celery, Redis
- **Frontend:** HTML5, CSS3, JavaScript, Django Templates, Bootstrap 5, Chart.js, Lucide Icons
- **Database:** PostgreSQL 18 with Django ORM
- **Networking:** ICMP ping utilities (`ping3`), SNMPv2c/SNMPv3 (`pysnmp-lextudio`), IP/CIDR validation
- **Testing:** Pytest, `pytest-django`, Django TestCase

---

## Directory Structure

```
NetPulse/
│
├── config/
│   ├── __init__.py           # Package init exposing Celery app
│   ├── settings/
│   │   ├── __init__.py       # Active settings selector
│   │   ├── base.py           # Core settings, apps, PostgreSQL configuration
│   │   ├── development.py    # Local dev configuration
│   │   └── production.py     # Hardened production settings
│   ├── urls.py               # Root URL router & health check endpoint
│   ├── wsgi.py               # WSGI entrypoint for HTTP
│   ├── asgi.py               # ASGI entrypoint for WebSockets & Channels
│   └── celery.py             # Celery broker & worker configuration
│
├── apps/                     # Modular Django applications
│   ├── __init__.py
│   ├── accounts/             # Authentication & user roles (Phase 2 & 3)
│   ├── devices/              # Device management & IP validation (Phase 2 & 3)
│   ├── monitoring/           # ICMP & SNMP data collection (Phase 2, 5, 6)
│   ├── analytics/            # Bandwidth & historical metrics (Phase 2 & 9)
│   ├── alerts/               # Incident & notification management (Phase 2 & 10)
│   ├── topology/             # Network link topology graph (Phase 2 & 11)
│   └── dashboard/            # NOC dashboard views & APIs (Phase 2 & 4)
│
├── templates/                # Modular Django templates
├── static/                   # Static assets (css, js, images)
│   ├── css/
│   ├── js/
│   └── images/
│
├── tests/                    # Automated test suite
│   ├── __init__.py
│   ├── test_phase1_setup.py  # Pytest suite for Phase 1
│   └── test_django_setup.py  # Django TestCase suite for Phase 1
│
├── .env                      # Local environment secrets (not in git)
├── .env.example              # Template for environment variables
├── .gitignore                # Git ignore rules
├── manage.py                 # Django administrative CLI
├── pytest.ini                # Pytest configuration
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
```

---

## Phase Implementation Roadmap

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | **Project setup, virtual environment, dependencies & PostgreSQL connection** | **COMPLETED** |
| **Phase 2** | **Django applications, database models, relationships & migrations** | **COMPLETED** |
| **Phase 3** | **Authentication, operator/admin roles & device CRUD management** | **COMPLETED** |
| **Phase 4** | **Professional dark NOC dashboard frontend & Django integration** | **COMPLETED** |
| Phase 5 | ICMP monitoring engine (ping, latency, packet loss calculation) | *Upcoming / Next* |
| Phase 6 | SNMP telemetry collection (SNMPv2c/SNMPv3, interface counters, bandwidth) | *Upcoming* |
| Phase 7 | Celery background monitoring engine & Celery Beat scheduling | *Upcoming* |
| Phase 8 | Django Channels & WebSocket real-time broadcast engine | *Upcoming* |
| Phase 9 | Traffic analytics, Chart.js metrics & historical performance | *Upcoming* |
| Phase 10 | Incident alert generation & acknowledgement workflow | *Upcoming* |
| Phase 11 | Interactive network topology graph visualization | *Upcoming* |
| Phase 12 | Comprehensive test suite, security hardening & deployment guide | *Upcoming* |

---

## Verification & Execution Guide

### Automated Testing
Execute the complete test suite (89 automated tests covering Models, Permissions, Auth, CRUD, Views, Chart APIs, and Navigation):
```powershell
.\.venv\Scripts\pytest.exe -v
```

### Manual Verification for Phase 4 (NOC Dashboard & Views)

1. **Start the Development Server:**
   ```powershell
   .\.venv\Scripts\python.exe manage.py runserver
   ```

2. **Login to NetPulse:**
   - Navigate to `http://127.0.0.1:8000/login/`
   - Log in using your credentials (e.g., username `surya` or administrator account).

3. **Verify Dashboard Overview (`/dashboard/`):**
   - 7 live NOC metric cards rendered dynamically from database models:
     - Total Devices, Online, Offline, Avg Latency (ms), Avg Packet Loss (%), Global Uptime (%), and Total Bandwidth Consumption.
   - Dual-line Chart.js bandwidth telemetry (Incoming vs Outgoing Mbps over time).
   - Latency Trend chart (Latency ms vs Packet Loss %).
   - Device Availability Donut chart (Online vs Warning vs Offline).
   - High Priority Unacknowledged Alerts list with inline one-click AJAX acknowledgement.

4. **Verify Sidebar Navigation Links (All 10 Routes):**
   - **Overview:** `/dashboard/`
   - **Network Devices:** `/devices/`
   - **Network Topology:** `/topology/` (Interactive SVG topology canvas with node status, manual vs discovered link styling)
   - **Traffic Analytics:** `/analytics/` (Dynamic bandwidth telemetry and interface breakdowns)
   - **Performance Monitoring:** `/monitoring/performance/` (Device telemetry selector, latency/loss charts, min/avg/max latency cards)
   - **Alerts & Notifications:** `/alerts/` (Active, Unacknowledged, Resolved tabs with acknowledgement/resolution actions)
   - **Monitoring History:** `/monitoring/history/` (Paginated historical metrics log with device and status filters)
   - **Settings:** `/settings/` -> `/alerts/settings/` (Configure latency warning/critical thresholds and packet loss limits)
   - **User Profile:** `/profile/` (Manage name, email, department, contact phone, and view role)
   - **Logout:** `/logout/` (Terminates session and redirects to login)

---

## Manual Verification for Phase 1

1. **Activate the Virtual Environment:**
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

2. **Verify Django System Checks:**
   ```powershell
   python manage.py check
   ```
   *Expected output: `System check identified no issues (0 silenced).`*

3. **Verify PostgreSQL Migrations:**
   ```powershell
   python manage.py migrate
   ```
   *Expected output: confirms connection to `netpulse_db` on PostgreSQL 18.*

4. **Execute Automated Tests:**
   ```powershell
   pytest
   python manage.py test tests
   ```
   *Expected output: All tests pass, demonstrating live database queries and health endpoint validation.*

5. **Run the Development Server:**
   ```powershell
   python manage.py runserver
   ```
   Visit `http://127.0.0.1:8000/api/health/` in your browser.
   *Expected JSON response:*
   ```json
   {
       "status": "online",
       "service": "NetPulse Network Monitoring System",
       "version": "1.0.0",
       "database": "healthy"
   }
   ```
