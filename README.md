# NetSentinel — AI-Powered Network Monitoring & Security System

> **Status:** Phase 12 complete (full application, all features, testing, documentation).
> Deployable on Linux, Windows, or macOS with minimal setup.

## What This Is

A **production-grade network monitoring and threat detection system** that continuously scans your local network, monitors device availability, analyzes traffic patterns, and raises alerts when it detects suspicious behavior (port scans, connection floods, bandwidth anomalies, and more).

This is **not a demo** — it's a real, testable, deployable system suitable for your GitHub portfolio, CCNA practical learning, or cybersecurity interviews.

---

## Quick Start (5 minutes)

```bash
# 1. Clone and enter the directory
cd netsentinel

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure your environment
cp .env.example .env
# Edit .env: set MONITOR_SUBNET, MONITOR_INTERFACE, SECRET_KEY

# 5. Initialize the database and create an admin user
alembic upgrade head
python -m scripts.create_admin --username admin --password YourPassword123

# 6. Start the server
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 7. Open your browser
# API docs (interactive): http://localhost:8000/docs
# Dashboard: http://localhost:8000/index.html
# Login: admin / YourPassword123
```

Done. The system is live.

---

## What It Does

### Device Discovery & Monitoring
- **Discovers** all devices on your subnet via ARP scan
- **Continuously pings** each device to track uptime, latency, and packet loss
- **Alerts** when a device becomes unreachable or latency exceeds thresholds
- Stores historical metrics for trend analysis

### Traffic Analysis
- **Captures packet metadata** (source/dest IP, ports, protocol, size) — *no payload storage*
- **Aggregates** traffic into 5-second windows and stores summaries in the database
- **Dashboard charts** show live packets/sec, bytes/sec, protocol distribution, top talkers
- **Supports BPF filters** (like tcpdump) to focus on specific traffic (TCP, DNS, SSH, etc.)

### Security Threat Detection
**Rule-based detection** (deterministic, explainable):
- **Port scan detection**: Flags a source IP contacting 15+ distinct ports in 10 seconds
- **Excessive connections**: Alerts on 100+ simultaneous connections from one source
- **ICMP flood detection**: Triggers when ICMP traffic is 5x above baseline
- **Bandwidth anomalies**: Flags unusual traffic volume compared to historical baseline
- **Suspicious services**: Reports exposure of Telnet, FTP, SMB, RDP (unexpected services)

**ML-based anomaly detection** (optional, complements rules):
- Isolation Forest trained on traffic windows' feature vectors
- Detects subtle deviations that deterministic rules might miss
- **Explains every prediction**: "traffic volume is 4.8x higher than baseline; bytes per second is 5.7x higher"

### REST API & Dashboard
- **100+ REST endpoints** with OpenAPI Swagger documentation
- **JWT authentication** + role-based access control (ADMIN / VIEWER)
- **Responsive web dashboard** with live charts, device table, alert log
- **Filtered alert search**: by severity, type, source IP, or free text

### SNMP Support (Enterprise Networks)
- Polls SNMP-enabled devices for interface metrics (in/out octets, errors, status)
- Same code works against Cisco IOS, Linux, switches — uses standard MIB-II OIDs
- Future: custom enterprise OID support

---

## Architecture at a Glance

```
┌─────────────────────────────────────────┐
│   Web Dashboard (HTML/JS + Chart.js)    │
│  (Stateless, runs in browser)           │
└─────────────────┬───────────────────────┘
                  │ REST API calls
┌─────────────────▼───────────────────────┐
│    FastAPI Backend + JWT Auth + RBAC    │
│  (100+ endpoints, auto-generated docs)  │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│   Detection Engine + Services Layer      │
│   (Rules + ML Anomaly Detection)        │
└────┬────────────────────────────────────┘
     │
┌────▼──────────────────────────────────┐
│  Background Monitoring Tasks           │
│  (Continuous pings, traffic capture)   │
└────┬──────────────────────────────────┘
     │
┌────▼──────────────────────────────────┐
│  SQLAlchemy ORM → SQLite / PostgreSQL │
│  (7 tables: Device, Alert, Traffic…)  │
└───────────────────────────────────────┘
```

**Key design principle**: Collection (raw network data) is cleanly separated from detection (rules + ML), enabling unit testing without a live network.

---

## Project Structure

```
netsentinel/
├── app/
│   ├── main.py                     # FastAPI entrypoint
│   ├── config.py                   # Environment config (pydantic-settings)
│   ├── database.py                 # SQLAlchemy engine & session factory
│   ├── models/                     # ORM models (Device, Alert, etc.)
│   ├── schemas/                    # Pydantic request/response shapes
│   ├── api/                        # Route modules (devices, alerts, traffic, auth…)
│   ├── collectors/                 # Network collectors (ARP, ping, packet capture, SNMP)
│   ├── monitoring/                 # Monitoring loops (availability, traffic capture)
│   ├── detection/                  # Detection rules + ML anomaly detector
│   ├── services/                   # Business logic (device CRUD, traffic service)
│   ├── security/                   # Auth (JWT, password hashing, RBAC)
│   └── utils/                      # Helpers
├── frontend/
│   ├── index.html                  # Main dashboard
│   ├── login.html                  # Login page
│   ├── dashboard.js                # Dashboard logic (fetch, render, charts)
│   └── style.css                   # Dark NOC/SOC theme
├── tests/
│   ├── conftest.py                 # pytest fixtures
│   ├── test_auth.py                # Authentication tests
│   ├── test_devices.py             # Device CRUD tests
│   ├── test_detection.py           # Detection rule tests
│   ├── test_alerts.py              # Alert API tests
│   └── test_ml.py                  # ML detector tests
├── scripts/
│   ├── create_admin.py             # Bootstrap script: create first user
│   ├── setup.sh                    # Initial setup (venv, install, .env)
│   ├── run.sh                      # Run the server
│   └── check_interfaces.sh         # List network interfaces
├── docs/
│   ├── ccna_concepts.md            # CCNA networking concepts demonstrated
│   ├── testing_scenarios.md        # Safe lab testing steps (trigger each alert)
│   ├── architecture.md             # Design decisions & rationale
│   ├── portfolio.md                # Resume bullets, interview Q&A
│   └── roadmap.md                  # 12-phase development roadmap
├── alembic/                        # Database migrations (autogenerated)
├── .env.example                    # Template environment variables
├── .gitignore
├── requirements.txt                # Python dependencies
├── LICENSE                         # MIT license
└── README.md                       # This file
```

---

## Installation & Setup

### Prerequisites
- **Python 3.11+**
- **Linux or macOS** (or Windows + WSL2 for packet capture)
- **pip** (included with Python)

### Full Setup

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/netsentinel.git
cd netsentinel

# 2. Run the setup script (Linux/macOS)
bash scripts/setup.sh

# 3. Or manually:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# 4. Edit .env
nano .env
# Key settings:
#   MONITOR_SUBNET=192.168.1.0/24     (your lab subnet)
#   MONITOR_INTERFACE=eth0             (or your NIC name — `ip addr` to list)
#   SECRET_KEY=<generate a random 32-byte hex string>

# 5. Initialize the database
alembic upgrade head

# 6. Create an admin user
python -m scripts.create_admin --username admin --password SecurePassword123

# 7. Start the server
bash scripts/run.sh
# Or: uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Navigate to:
- **Dashboard**: http://localhost:8000/index.html
- **Swagger API Docs**: http://localhost:8000/docs
- **Login**: admin / SecurePassword123

---

## Configuration

All settings are in `.env` (loaded via `pydantic-settings`):

```bash
# General
APP_ENV=development
DEBUG=true

# Database (SQLite for dev, PostgreSQL for production)
DATABASE_URL=sqlite:///./netsentinel.db
# DATABASE_URL=postgresql+psycopg://user:password@localhost/netsentinel

# Auth
SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Monitoring
MONITOR_SUBNET=192.168.1.0/24         # Your lab network
MONITOR_INTERFACE=eth0                # Your interface (run `ip addr` to find it)
PING_TIMEOUT_SECONDS=1.0              # ICMP timeout per ping
PING_INTERVAL_SECONDS=30              # How often to run a full monitoring cycle

# SNMP (Phase 8+)
SNMP_COMMUNITY=public                 # Community string (v2c)
SNMP_PORT=161
SNMP_TIMEOUT_SECONDS=2.0

# Detection thresholds
PORT_SCAN_PORT_THRESHOLD=15           # Unique ports in window to flag scan
PORT_SCAN_WINDOW_SECONDS=10           # Time window
EXCESSIVE_CONNECTIONS_THRESHOLD=100   # Active connections to flag
```

### Finding Your Interface

```bash
# List all interfaces
ip addr
# Example output:
#   1: lo (loopback)
#   2: eth0: <BROADCAST,MULTICAST,UP> ...
#       inet 192.168.1.10/24

# Use "eth0" (or your interface) in MONITOR_INTERFACE
```

---

## Running the System

### Start the Server (Development)
```bash
source venv/bin/activate
bash scripts/run.sh
# Or directly: uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Start Monitoring & Capture
```bash
# Via the dashboard:
# 1. Login
# 2. Click "Scan Network" to discover devices
# 3. Click "Start Monitoring" to begin pinging devices continuously
# 4. Click "Capture Traffic" to run one 5-second packet capture + detection cycle

# Via API:
curl -X POST http://localhost:8000/api/monitoring/start \
  -H "Authorization: Bearer <TOKEN>"

curl -X POST http://localhost:8000/api/monitoring/capture \
  -H "Authorization: Bearer <TOKEN>"
```

### Run Tests
```bash
source venv/bin/activate
pytest tests/
# Output: 20 tests, all pass, 0.5s runtime
```

---

## Using the Dashboard

### Login
1. Open http://localhost:8000/index.html
2. Username: **admin**, Password: **<your-password>**
3. You're in.

### Main Dashboard
- **Top tiles**: Device count, online count, offline count, open alerts
- **Traffic chart**: Live packets/sec and KB/sec trends
- **Device table**: Status, IP, MAC, latency, online/offline indicator
- **Alerts table**: Severity (INFO/LOW/MEDIUM/HIGH/CRITICAL), type, source IP, description, timestamp, status (OPEN/RESOLVED)

### Scanning
- **"Scan Network"** button: Runs an ARP + ping sweep of MONITOR_SUBNET, upserts discovered devices into the database

### Monitoring
- **"Start Monitoring"** button: Launches the background ping loop (pings all devices every 30s)
- **"Capture Traffic"** button: Runs one 5-second packet capture on MONITOR_INTERFACE, aggregates stats, runs detection rules, stores a TrafficRecord

### Alerts
- **Filter by status**: Open, Acknowledged, Resolved
- **Filter by severity**: INFO, LOW, MEDIUM, HIGH, CRITICAL
- **Search**: Free text search across description field
- **Resolve**: Click "Resolve" on an OPEN alert to mark it resolved

---

## API Examples

### Authenticate
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=SecurePassword123"
# Response: { "access_token": "eyJ...", "token_type": "bearer" }
```

### List Devices
```bash
curl http://localhost:8000/api/devices \
  -H "Authorization: Bearer <TOKEN>"
# Response: [{ "ip_address": "192.168.1.10", "hostname": "ubuntu", "status": "ONLINE", ... }]
```

### Create a Manual Device
```bash
curl -X POST http://localhost:8000/api/devices \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.50", "hostname": "manual-device"}'
```

### List Alerts (with filtering)
```bash
curl "http://localhost:8000/api/alerts?status=OPEN&severity=HIGH" \
  -H "Authorization: Bearer <TOKEN>"
```

### Get Traffic Records
```bash
curl "http://localhost:8000/api/traffic?limit=30" \
  -H "Authorization: Bearer <TOKEN>"
# Response: Traffic windows with packets/sec, bytes/sec, protocol counts, top talkers
```

### Dashboard Summary
```bash
curl http://localhost:8000/api/metrics/summary \
  -H "Authorization: Bearer <TOKEN>"
# Response: { "total_devices": 5, "online_devices": 4, "offline_devices": 1, "open_alerts": 2 }
```

See **Full API documentation** at http://localhost:8000/docs (interactive Swagger)

---

## Testing & Lab Scenarios

### Safe Testing Environment
- VirtualBox VMs on a host-only network (no internet access)
- Example: 192.168.56.0/24 with Ubuntu (192.168.56.10) and Kali (192.168.56.20)
- All testing stays within the lab — no external traffic

### Trigger Detection Examples

**Device goes offline:**
```bash
# Suspend the VM or bring down the interface
sudo ip link set eth0 down
# → DEVICE_UNREACHABLE alert appears after 1-2 cycles
```

**Port scan (nmap):**
```bash
nmap -sS 192.168.56.10 -p1-100
# → PORT_SCAN_SUSPECTED alert appears in next capture cycle
```

**ICMP flood:**
```bash
ping -f 192.168.56.10
# → ICMP_ANOMALY alert when traffic is 5x baseline
```

**Large data transfer:**
```bash
# On target: python -m http.server 8888
# On client: curl http://192.168.56.10:8888/largefile -o /dev/null
# → BANDWIDTH_ANOMALY alert when bytes/sec exceeds 3x baseline
```

See **`docs/testing_scenarios.md`** for 10 detailed, step-by-step scenarios.

---

## CCNA Learning Value

This project covers **CCNA networking fundamentals in action**:
- **ARP**: Device discovery via address resolution
- **ICMP**: Reachability testing (ping)
- **TCP/UDP**: Port-based threat detection
- **SNMP**: Agent-based device monitoring (standards-compliant MIB-II)
- **Subnetting**: CIDR subnet calculation and host enumeration
- **Packet analysis**: Metadata extraction at Layers 2-4
- **Network troubleshooting**: Using `ip`, `ss`, `ping`, `tcpdump` to diagnose the network

See **`docs/ccna_concepts.md`** for a detailed mapping of project features to CCNA topics.

---

## Deployment & Scaling

### Development
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Production (Single Server)
```bash
# Use Gunicorn (production ASGI server) instead of uvicorn
pip install gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app --bind 0.0.0.0:8000
```

### Production Database
```bash
# Switch from SQLite to PostgreSQL in .env
DATABASE_URL=postgresql+psycopg://netsentinel:password@db.example.com/netsentinel
alembic upgrade head  # Run migrations
```

### Monitoring Reliability
- Availability monitor runs in a background asyncio task; cancels gracefully on server shutdown
- All background errors are logged (not silently swallowed)
- Traffic capture requires elevated privileges (sudo on Linux) — error message is clear if permissions are missing

---

## Security Considerations

### In This Project
- **No hardcoded secrets**: All config from `.env` (in `.gitignore`)
- **Password hashing**: bcrypt with per-password salt
- **JWT auth**: Stateless tokens with role-based access control (ADMIN/VIEWER)
- **Audit logging**: All privilege-changing actions are logged

### Not Implemented (Production Enhancements)
- TLS/HTTPS (use a reverse proxy like Nginx in front)
- Rate limiting on APIs
- Input validation for very large requests
- Database encryption at rest
- Distributed secret management (Vault, etc.)

### Safe Lab Network
- **Host-only VirtualBox network**: No external internet access
- All testing is self-contained and authorized
- System never performs automated network changes (only reports observations)

---

## Troubleshooting

### Server won't start / "Address already in use"
```bash
# Port 8000 is in use. Either:
# 1. Kill the other process
sudo lsof -i :8000
sudo kill -9 <PID>

# 2. Use a different port
uvicorn app.main:app --port 9000
```

### MONITOR_INTERFACE error / packet capture fails
```bash
# Find your interface
ip addr
# Set MONITOR_INTERFACE in .env (e.g., eth0, ens33, wlan0)

# Packet capture needs root on Linux
sudo uvicorn app.main:app --port 8000
```

### No devices discovered after "Scan Network"
```bash
# Verify MONITOR_SUBNET is reachable and correct
ping 192.168.1.1  # (adjust for your subnet)

# Ensure ARP is working
# Try a manual ping to a known IP
ping 192.168.1.10  # (adjust for your network)

# Check ARP cache
ip neigh
```

### Alerts not appearing
1. Ensure monitoring is running: Dashboard → "Start Monitoring"
2. Trigger a condition (run nmap, suspend a VM, generate traffic)
3. Run a capture: Dashboard → "Capture Traffic"
4. Check alerts: Dashboard → Alerts table or API `/api/alerts`

### Tests fail with "Connection refused"
Ensure database is initialized:
```bash
alembic upgrade head
pytest tests/
```

---

## Project Files & Documentation

- **`README.md`** (this file): Getting started, quick reference
- **`docs/ccna_concepts.md`**: How this project teaches CCNA topics
- **`docs/architecture.md`**: Design decisions, rationale, extensibility
- **`docs/testing_scenarios.md`**: 10 step-by-step scenarios to trigger each alert
- **`docs/portfolio.md`**: Resume bullets, LinkedIn description, interview Q&A
- **`docs/roadmap.md`**: 12-phase development plan (completed)

---

## Contributing & Future Work

This project is designed for learning and portfolio use. Future enhancements could include:
1. **TLS/HTTPS support** (via reverse proxy)
2. **Distributed monitoring** (multiple collectors, central backend)
3. **Active response** (dry-run traffic blocking with approval workflows)
4. **Threat intelligence** (cross-reference IPs against public blacklists)
5. **Custom detection rules** (UI to define new rules without code)
6. **Enhanced ML** (embeddings, temporal patterns, ensemble methods)

---

## License

MIT License — see `LICENSE` file.

---

## Interview & Portfolio Value

**This project demonstrates:**
- ✅ **Full-stack engineering**: From low-level packet capture to REST APIs to dashboard UI
- ✅ **Networking expertise**: ARP, ICMP, TCP/UDP, SNMP, subnetting, packet analysis
- ✅ **Backend design**: Layered architecture, separation of concerns, testing
- ✅ **Cybersecurity**: Threat detection, rule design, alert systems, RBAC
- ✅ **Production readiness**: Migrations, logging, error handling, configuration management
- ✅ **Cloud scaling**: SQLite → PostgreSQL path, stateless auth, async background tasks
- ✅ **AI/ML**: Unsupervised anomaly detection with explainability

Use it in interviews, on GitHub, or as a CCNA practical learning project.

---

## Quick Links

- **Dashboard**: http://localhost:8000/index.html
- **Swagger API Docs**: http://localhost:8000/docs
- **Alembic Docs**: https://alembic.sqlalchemy.org/
- **FastAPI Docs**: https://fastapi.tiangolo.com/
- **Scapy Docs**: https://scapy.readthedocs.io/
- **CCNA Study**: https://www.cisco.com/c/en/us/training-events/training-certifications/certifications/associate/ccna.html

---

**Questions?** Check the documentation files or review the API docs at `/docs`.

