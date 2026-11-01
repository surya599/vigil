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
| **Phase 5** | **ICMP monitoring engine (ping, latency, packet loss calculation)** | **COMPLETED** |
| **Phase 6** | **SNMP telemetry collection (SNMPv2c/SNMPv3, interface counters, bandwidth)** | **COMPLETED** |
| **Phase 7** | **Celery background monitoring engine & Celery Beat scheduling** | **COMPLETED** |
| **Phase 8** | **Django Channels & WebSocket real-time broadcast engine** | **COMPLETED** |
| **Phase 9** | **Traffic analytics, Chart.js metrics & historical performance** | **COMPLETED** |
| Phase 10 | Incident alert generation & acknowledgement workflow | *Upcoming / Next* |
| Phase 11 | Interactive network topology graph visualization | *Upcoming* |
| Phase 12 | Comprehensive test suite, security hardening & deployment guide | *Upcoming* |

---

## Verification & Execution Guide

### Automated Testing
Execute the complete test suite (173 automated tests covering Models, Permissions, Auth, CRUD, Views, Chart APIs, Navigation, ICMP Engine, SNMP Engine, Celery Background Tasks, Django Channels WebSockets, and Traffic & Performance Analytics):
```powershell
.\.venv\Scripts\pytest.exe -v
```

### Manual Verification for Phase 9 (Traffic Analytics, Chart.js Metrics & Historical Performance)

1. **Explore Traffic Analytics (`/analytics/`):**
   - Switch between time-range filters (`1H`, `6H`, `24H`, `7D`) and filter by a specific monitored device.
   - Inspect the **Top Talker Interfaces (Mbps)** horizontal bar chart and the **Link Utilization** progress bars in the interface table.
   - Click **Export CSV** (`/api/analytics/export-csv/?type=traffic`) to download historical bandwidth snapshots.

2. **Explore Performance Monitoring & SLA History (`/monitoring/performance/`):**
   - View multi-axis Chart.js trends for **Latency (ms)**, **Jitter (ms)**, and **Packet Loss (%)**.
   - Inspect the **Daily SLA Availability (%)** bar chart and download latency or SLA CSV reports (`/api/analytics/export-csv/?type=latency` or `?type=sla`).

### Manual Verification for Phase 8 (Django Channels & WebSocket Real-Time Broadcast Engine)

1. **Start the ASGI Server (Daphne integrated via `runserver`):**
   ```powershell
   .\.venv\Scripts\python.exe manage.py runserver
   ```
   *Because `daphne` is registered at the top of `INSTALLED_APPS`, `manage.py runserver` automatically runs `ASGI/Daphne` supporting both HTTP and WebSockets.*

2. **Verify Live WebSocket Connection on the NOC Dashboard:**
   - Log in and open `http://127.0.0.1:8000/dashboard/`.
   - Observe the top-right status indicator transition to **Live WS** with a green pulse dot, and the bandwidth chart badge update to **WebSocket Live Stream**.
   - Open browser DevTools → Network → WS tab → inspect `/ws/noc/` frames (`noc_snapshot`, `pong`, `device_status_update`, `alert_notification`, `traffic_snapshot_update`).

3. **Trigger a Live Broadcast from Another Terminal:**
   ```powershell
   .\.venv\Scripts\python.exe manage.py run_icmp_check --count 2
   ```
   *Observe the NOC dashboard table and stat cards update instantaneously over WebSocket without page reload.*

### Manual Verification for Phase 7 (Celery Background Tasks & Beat Scheduling)

1. **Start the Celery Worker (Production / Redis Mode):**
   ```powershell
   .\.venv\Scripts\celery.exe -A config worker -l info --pool=solo
   ```

2. **Start the Celery Beat Scheduler:**
   ```powershell
   .\.venv\Scripts\celery.exe -A config beat -l info
   ```
   *Expected periodic schedule:*
   - `icmp-sweep-periodic` (every 30s) → `monitoring.tasks.task_icmp_sweep`
   - `snmp-sweep-periodic` (every 60s) → `monitoring.tasks.task_snmp_sweep`
   - `traffic-snapshot-periodic` (every 60s) → `monitoring.tasks.task_aggregate_traffic_snapshots`
   - `daily-summary-rollup` (every 3600s) → `monitoring.tasks.task_generate_daily_summaries`
   - `prune-old-metrics-daily` (every 86400s) → `monitoring.tasks.task_cleanup_historical_metrics`

3. **Execute Tasks Directly via Django Shell (Eager / Dev Mode):**
   ```powershell
   .\.venv\Scripts\python.exe manage.py shell -c "from monitoring.tasks import task_icmp_sweep, task_aggregate_traffic_snapshots; print(task_icmp_sweep.apply().get()); print(task_aggregate_traffic_snapshots.apply().get())"
   ```

### Manual Verification for Phase 6 (SNMP Telemetry & Interfaces)

1. **Run the Independent SNMP Polling Command:**
   ```powershell
   .\.venv\Scripts\python.exe manage.py run_snmp_poll --timeout 2.0
   ```
   *Expected output: Interrogates all SNMP-enabled devices via SNMPv2c/v3, updates system description and uptime, discovers interfaces (`ifTable`/`ifXTable`), and computes dynamic traffic rates (bps).*

2. **Poll a Specific Host via CLI:**
   ```powershell
   .\.venv\Scripts\python.exe manage.py run_snmp_poll --device-id 1
   ```

3. **Verify On-Demand Web UI SNMP Poll:**
   - Log in and open a device detail page with SNMP enabled (e.g. `http://127.0.0.1:8000/devices/1/`).
   - Click the **Poll SNMP** button in the header.
   - The discovered interfaces, operational states, MAC addresses, speeds, and current traffic rates (In/Out Mbps) are populated in the Network Interfaces table.

4. **Verify On-Demand REST API SNMP Endpoint:**
   ```powershell
   curl -X POST http://127.0.0.1:8000/api/devices/1/snmp-poll/ -H "Content-Type: application/json" -u "surya:Surya@534103"
   ```
   *Returns real-time telemetry JSON containing `sys_description`, `sys_uptime`, and the array of discovered network interfaces.*

### Manual Verification for Phase 5 (ICMP Monitoring Engine)

1. **Run the Independent ICMP Monitoring Command:**
   ```powershell
   .\.venv\Scripts\python.exe manage.py run_icmp_check --count 4 --timeout 1.0
   ```
   *Expected output: Scans registered devices, transmits 4 ICMP echo requests per host, measures round-trip time, calculates packet loss, updates device operational state, and logs `DeviceMetric` records to PostgreSQL.*

2. **Run Continuous Polling Loop (Optional):**
   ```powershell
   .\.venv\Scripts\python.exe manage.py run_icmp_check --continuous --interval 30
   ```

3. **Verify On-Demand Web UI Ping:**
   - Navigate to `http://127.0.0.1:8000/devices/` or a device detail page (e.g., `http://127.0.0.1:8000/devices/1/`).
   - Click the **Ping Device** button.
   - Observe immediate flash banner reporting status, measured RTT (ms), and packet loss percentage.
   - Check the **Monitoring History** tab (`/monitoring/history/`) to verify the new metric entry.

4. **Verify On-Demand REST API Ping:**
   - Execute an authenticated POST request to `/api/devices/<id>/ping/`:
     ```powershell
     curl -X POST http://127.0.0.1:8000/api/devices/1/ping/ -H "Content-Type: application/json" -u "surya:Surya@534103"
     ```
   - Receive real-time telemetry JSON containing `status`, `latency`, `packet_loss`, `jitter`, `consecutive_failures`, and `uptime_percentage`.

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
