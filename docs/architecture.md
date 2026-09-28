# NetSentinel Architecture Deep-Dive

## Executive Summary

NetSentinel is a production-inspired, layered architecture that cleanly separates:
- **Collection** (raw network signals)
- **Analysis** (metrics and anomalies)
- **Persistence** (long-term storage)
- **Presentation** (REST API + dashboard)

This separation makes the system testable, maintainable, and extensible without touching core logic.

---

## Layered Design

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Dashboard                             │
│                  (HTML/JS/Chart.js)                          │
│                   (Stateless SPA)                            │
└─────────────────────┬───────────────────────────────────────┘
                      │ REST API calls
┌─────────────────────▼───────────────────────────────────────┐
│                    FastAPI Routes                            │
│  /api/devices  /api/alerts  /api/traffic  /api/monitoring   │
│                (JWT auth + RBAC)                             │
└─────────────────────┬───────────────────────────────────────┘
                      │ Database calls (SQLAlchemy ORM)
┌─────────────────────▼───────────────────────────────────────┐
│               Business Logic (Services)                      │
│  traffic_service.run_capture_cycle()                         │
│  availability_monitor_loop()                                 │
│  Device CRUD, Alert resolution                              │
└────┬────────┬────────────────────────────────────────────────┘
     │        │
┌────▼──┐ ┌───▼──────────────────────────────────────────────┐
│ Rules │ │              Detection Logic                      │
│ Engine│ │  port_scan, icmp_anomaly, bandwidth_anomaly      │
│       │ │  excessive_connections, suspicious_services      │
└───────┘ │  ML: Isolation Forest                            │
     │    │  (feeds alerts)                                   │
└────────┬──────────────────────────────────────────────────────┘
         │ Detection results (alerts)
┌────────▼──────────────────────────────────────────────────────┐
│               Database (SQLAlchemy ORM)                       │
│  Device, Interface, TrafficRecord, SecurityAlert             │
│  MonitoringMetric, User, AuditLog                            │
│  (SQLite for dev, PostgreSQL for production)                 │
└───────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│           Background Collectors (Async Tasks)                │
├──────────────┬──────────────────────┬───────────────────────┤
│ Discovery    │ Availability Monitor │ Traffic Capture       │
│ (one-time    │ (periodic: every 30s) │ (periodic or on-     │
│  or periodic)│                       │  demand)              │
└──────────────┴──────────────────────┴───────────────────────┘
       │ Raw network signals (IPs, latencies, packets)
┌──────▼──────────────────────────────────────────────────────┐
│         Network (ICMP, ARP, Scapy, SNMP, system calls)      │
└──────────────────────────────────────────────────────────────┘
```

---

## Design Decisions & Rationale

### 1. **Separation of Collection from Detection**

**Decision:** Collectors (`app/collectors/`) produce raw data (IP addresses, latencies, packets).
Detectors (`app/detection/`) receive structured data and decide what's suspicious.

**Why:**
- **Testability**: Write unit tests for detection logic without a live network
- **Portability**: Swap one collector (e.g., SNMP) for another without touching detection
- **Clarity**: The detection rule says "if 20 ports in 10s" — it doesn't care whether those ports
  came from live packet capture, historical files, or synthetic test data

**Example:**
```python
# Test port-scan rule with synthetic data (no network needed)
window = TrafficWindow(...)
window.unique_dst_ports_by_src["10.0.0.99"] = set(range(1000, 1020))
detect_port_scan(db, window)  # Works perfectly

# In production, the same function runs against real Scapy windows
```

### 2. **Metadata-Only Packet Capture**

**Decision:** Extract source IP, destination IP, ports, protocol, packet size from every packet.
Store nothing about the *payload*.

**Why:**
- **Privacy**: No one can accuse NetSentinel of snooping on packet contents — it provably doesn't collect them
- **Performance**: Metadata is tiny (few KB); payloads would explode the database (TB/day for a busy network)
- **Legality**: Different jurisdictions have different rules about capturing/storing packet data — metadata sidesteps those concerns

**Tradeoff:**
- Can't do deep-packet inspection (DPI) for protocol anomalies
- Can't detect attacks that hide in encrypted payloads (but neither can simple rules anyway — ML on metadata is still useful)

### 3. **Rule-Based + ML (Hybrid)**

**Decision:** Every detection alert includes a deterministic rule *and* optional ML scoring.

**Rule-based example:**
```python
if unique_ports >= 15 in 10 seconds:
    alert("PORT_SCAN", evidence=f"ports={unique_ports}")
```

**ML-based example:**
```python
if isolation_forest.predict(features) == -1:  # anomalous
    alert("ML_ANOMALY", explanation=f"traffic volume is {ratio}x higher than baseline")
```

**Why hybrid:**
- **Explainability**: A rule alert says *why* it triggered (evidence field)
- **Reliability**: Rules don't need historical data; they work on day 1. ML needs a 30-sample baseline
- **Tunability**: Rules are easy to adjust in .env; ML model retrains automatically as more data arrives
- **Audit trail**: An alert's `detection_method` field ("rule:port_scan" vs "ml:isolation_forest") shows its origin

**Interview value:**
- "I deliberately made this a hybrid system because pure ML is hard to defend to non-technical stakeholders.
  A rule says 'here are the 20 ports,' so a human can verify it. The ML layer adds another perspective
  without replacing the deterministic layer."

### 4. **Async Monitoring Loops (Background Tasks)**

**Decision:** Device availability is checked every 30 seconds in an asyncio background task,
not on a per-request basis.

**Why:**
- **Cost**: Pinging every device per request would add massive latency to the API
- **Consistency**: Everyone sees the same "current" status because it's sampled at fixed intervals
- **Scalability**: A background task can hammer a thousand devices; the API stays responsive

**Implementation:**
```python
async def availability_monitor_loop(session_factory):
    while True:
        db = session_factory()
        try:
            check_all_devices(db)  # Pings all devices, records metrics
        finally:
            db.close()
        await asyncio.sleep(30)  # Wait 30 seconds, then repeat
```

Started in `app/main.py`'s lifespan handler, cancelled on shutdown.

**Tradeoff:**
- Device status is at most 30 seconds stale (not real-time)
- Acceptable trade-off for simplicity; high-frequency monitoring (< 1 second) needs a different architecture (Redis, streaming)

### 5. **SQLite → PostgreSQL Migration Path**

**Decision:** Start with SQLite (zero setup), but design the code to swap to PostgreSQL with just a .env change.

**How:**
- All database access goes through SQLAlchemy ORM (`app/models/`)
- `session_factory` and `engine_from_config` abstract the dialect
- `.env` controls the URL: `DATABASE_URL=sqlite:///...` or `postgresql+psycopg://...`

**Why:**
- **Development**: SQLite is instant — no daemon to start, no schema migrations to run
- **Production**: PostgreSQL scales to millions of records, supports concurrent writes, has better query planner
- **Interview value**: "I designed for scale from day 1 — same code runs against SQLite in dev and Postgres in production"

### 6. **Alembic Migrations**

**Decision:** Checked-in migration files (`alembic/versions/`) are the source of truth for schema.

**Why:**
- **Repeatability**: New developer runs `alembic upgrade head`; schema matches production
- **History**: Git log of migrations shows *why* a schema change happened (commit message)
- **Safety**: Alembic can generate migrations automatically (`alembic revision --autogenerate`), catching schema drift

**Tradeoff:**
- For Phase 1-6, could skip migrations and just use `create_all()` — but a real project needs this

### 7. **JWT Authentication (Stateless)**

**Decision:** Tokens are signed JWTs; no session table needed.

**Why:**
- **Scalability**: No session store to query on every request; just verify the signature
- **Statelessness**: Token is self-contained (username + role embedded in it)
- **Expiry**: Built-in token expiration (configurable in .env)

**How:**
```python
token = jwt.encode({"sub": username, "role": role, "exp": expires}, secret_key, "HS256")
# Later:
payload = jwt.decode(token, secret_key, algorithms=["HS256"])
if payload["role"] == "ADMIN": ...
```

**Tradeoff:**
- If a user's role changes, they keep old-role access until their token expires
- Acceptable: expiration is short (60 minutes default), and the role field is checked on *every* protected route

### 8. **Pydantic Schemas (API Layer)**

**Decision:** Separate request/response schemas (`app/schemas/`) from SQLAlchemy models (`app/models/`).

**Why:**
- **Decoupling**: API can evolve independently of the database
  - Add a new field to the database? It doesn't appear in the API response until a schema is updated
  - Deprecate an API field? The database record still has it; the schema just hides it
- **Validation**: Pydantic validates requests before they hit the business logic
- **Serialization**: Pydantic controls what's included in responses (e.g., never expose `hashed_password`)

**Example:**
```python
# Database model (can have any fields)
class User(Base):
    hashed_password: str

# API response schema (doesn't expose the password)
class UserRead(BaseModel):
    username: str
    role: UserRole
    is_active: bool
```

### 9. **Detection Deduplication**

**Decision:** If an OPEN alert of the same type + source_ip exists within a time window, don't create a duplicate.

**Why:**
- **Noise reduction**: A persistent condition (device stays down for 5 minutes) shouldn't generate 10 alerts
- **Attention**: The first alert captures the operator's attention; repeats desensitize them

**Implementation:**
```python
def raise_alert_if_new(db, alert_type, source_ip, ..., dedupe_window_seconds=60):
    # Check for existing OPEN alert of same type/source within the window
    cutoff = datetime.utcnow() - timedelta(seconds=dedupe_window_seconds)
    existing = db.query(SecurityAlert).filter(
        SecurityAlert.alert_type == alert_type,
        SecurityAlert.source_ip == source_ip,
        SecurityAlert.status == AlertStatus.OPEN,
        SecurityAlert.timestamp >= cutoff
    ).first()
    if existing:
        return None  # Suppressed as duplicate
    # ... create new alert ...
```

**Tradeoff:**
- Operator might think the alert is gone (it's not, it's still OPEN)
- Acceptable: operator can check alert table; a persistent alert staying OPEN is more honest than clearing it

---

## Database Schema Design

```
Devices ──┬──→ Interfaces        (1 device has many interfaces)
          │
          ├──→ MonitoringMetrics (1 device has many time-series samples)
          │
          └──→ TrafficRecords    (aggregated traffic windows, not device-specific)

SecurityAlerts ─→ Any alert, keyed by source_ip + timestamp

Users
  ├──→ AuditLog (every login, privilege change, alert resolution)

Indexes:
  - (device_id) on Interfaces, MonitoringMetrics → fast lookup by device
  - (alert_type) on SecurityAlerts → fast filtering by alert type
  - (timestamp) on TrafficRecords, MonitoringMetrics → fast time-range queries
  - (source_ip) on SecurityAlerts → fast lookup by attacker IP
```

**Why no foreign keys on alerts?**
- An alert references a source_ip (string), not a Device ID
- If you filter an alert (RESOLVED → deleted) before the alert is created, there's no FK to enforce
- Alerts are standalone records; they document what happened, not what currently is

---

## Security Decisions

### Password Hashing

**Decision:** bcrypt with automatic per-password salt, 72-byte truncation for long passwords.

**Why:**
- bcrypt's computational cost (tunable "rounds") makes brute force expensive
- Salt prevents rainbow tables (every password gets a unique hash)
- 72-byte limit is bcrypt's hardware limit — document it and truncate, don't error

### JWT Secret

**Decision:** Read from .env (SECRET_KEY), never hardcoded.

**Why:**
- Secrets should never be in source code (even if the repo is private, leaks happen)
- .env is in .gitignore, so it's safe to commit the rest of the repo

### Token Expiry

**Decision:** Access token valid for configurable duration (default 60 minutes), not infinite.

**Why:**
- Stolen token has a bounded window of usefulness
- Long-lived tokens (days/weeks) are only acceptable with refresh-token rotation, which adds complexity

### RBAC Levels

**Decision:** Only ADMIN and VIEWER roles (not 5+ granular roles).

**Why:**
- Start simple: VIEWER can read everything, ADMIN can modify/delete
- Granularity (e.g., "can delete alerts but not devices") is premature
- Easy to add later if needed

---

## Performance Considerations

### Traffic Aggregation (Window-Based)

**Problem:** Storing one row per packet creates 1GB/day of data on a moderately busy network.

**Solution:** Aggregate traffic into 5-second windows (TrafficRecord).

**Tradeoff:**
- Can't query "packets from 10.0.0.5 at 14:32:17.342" (resolution lost)
- Can query "top talkers in the last hour" (good enough)

### Sampling in Availability Monitoring

**Problem:** Pinging 100 devices every 30 seconds is expensive; it adds up.

**Solution:** Run pings sequentially; each device gets ~3-4 pings (configurable).

**Tradeoff:**
- Takes 30-60 seconds per cycle (not instantaneous)
- Good enough for "is this device online" use case

### Connection Pooling

**Decision:** SQLAlchemy engine manages a pool of DB connections; reuse them across requests.

**Why:**
- Creating a new connection per request = overhead (TCP 3-way handshake, auth, etc.)
- Pool keeps 5-20 idle connections ready
- Thread-safe; FastAPI workers safely pull from the pool

---

## Extensibility

### Adding a New Detector

**Steps:**
1. Write a function in `app/detection/security_rules.py` that takes a `TrafficWindow` and `db.Session`
2. Call `raise_alert_if_new(db, ...)` to emit alerts
3. Hook the function into `app/services/traffic_service.run_capture_cycle()`
4. Test with synthetic data (no network needed)

**Example:**
```python
def detect_my_new_threat(db, window):
    if some_condition(window):
        raise_alert_if_new(db, alert_type=AlertType.MY_NEW_THREAT, ...)
```

### Adding a New Data Source

**Steps:**
1. Create `app/collectors/new_source.py` with a function/class that returns structured data
2. Call it from `run_capture_cycle()` or the monitoring loop
3. Store results in existing models (Device, Interface, TrafficRecord, SecurityAlert)
4. No API changes needed

**Example:**
```python
def collect_syslog_alerts(syslog_server):
    return [Alert(...) for msg in syslog_server.fetch_new()]
```

### Adding a New API Route

**Steps:**
1. Create a new file in `app/api/new_resource.py` with a FastAPI router
2. Include the router in `app/main.py` with `app.include_router(router)`
3. Auto-generates Swagger docs at `/docs`

---

## Known Limitations & Future Work

1. **No ML on payload data** — only on aggregated flow statistics
2. **No active response** — system alerts but doesn't block/modify traffic (future: dry-run remediation)
3. **No distributed mode** — single NetSentinel instance, not a cluster
4. **No persistent background tasks** — tasks are in-process; a restart loses state
5. **No DNS-based threat intel** — could integrate with public blacklists (e.g., abuse.ch)

---

## Interview Talking Points

1. **Layering**: "I separated collection from detection so I could unit-test detection without a live network."
2. **Explainability**: "Every ML alert includes plain-language evidence ('traffic is 5x higher than baseline') instead of just a score."
3. **Scale path**: "Code is identical for SQLite (dev) and PostgreSQL (prod) — just change the .env variable."
4. **Auth design**: "Stateless JWT tokens keep the API scalable; no session table to query on every request."
5. **Testing**: "I can trigger any alert in isolation with synthetic data because collection and detection are separate."

These are the design decisions that separate a portfolio project from a homework script.
