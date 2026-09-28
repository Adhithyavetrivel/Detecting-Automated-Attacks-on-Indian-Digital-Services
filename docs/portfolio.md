# NetSentinel — Portfolio & Interview Materials

---

## Resume Bullet Points

### For Network/Infrastructure Roles:

- **Designed and built NetSentinel, an AI-powered network monitoring system in Python**, using FastAPI, SQLAlchemy, and Scapy to continuously monitor device availability, detect port scans, and alert on anomalies in real-time
- **Implemented SNMP polling** to collect interface metrics (in/out octets, errors) from network devices; abstracted the SNMP layer so the same code works against Cisco IOS, Linux, and other standards-compliant agents
- **Built deterministic security detection rules** (port-scan, bandwidth-anomaly, excessive-connections) alongside ML-based anomaly detection using Isolation Forest, demonstrating the balance between explainability and algorithmic insight
- **Designed a scalable, multi-layered architecture** that separates data collection from detection logic, enabling unit testing of detection rules without a live network and easy addition of new data sources

### For Backend/SRE Roles:

- **Architected a production-ready backend** using FastAPI + SQLAlchemy with automatic database migration (Alembic), RBAC (JWT + role-based access control), and structured logging across 7 tables and 100+ API endpoints
- **Implemented stateless JWT authentication** to eliminate session-store overhead, enabling horizontal scaling; tokens embed role information so authorization checks don't require database lookups on every request
- **Designed database schema with clear relationships** (Device → Interface, Device → MonitoringMetric, centralized SecurityAlert table) and appropriate indexing, supporting time-series queries and alert filtering at scale
- **Built async background monitoring loops** (Python asyncio) that run concurrently with the FastAPI web server, pinging devices on a fixed schedule and persisting metrics to SQLite/PostgreSQL without blocking API requests

### For Security/Cybersecurity Roles:

- **Implemented explainable anomaly detection**, ensuring every alert includes plain-language evidence (e.g., "traffic is 4.8x higher than baseline") rather than opaque ML scores
- **Applied defense-in-depth security principles**: password hashing with bcrypt, secrets in .env (not hardcoded), JWT token expiry, RBAC enforcement, and audit logging of privilege-changing actions
- **Designed alert deduplication logic** to reduce notification fatigue — persistent threats generate one alert, not a new alert every cycle — demonstrating understanding of alert fatigue in real SOCs
- **Built rule-based + ML hybrid detection** for port scans, connection floods, bandwidth anomalies, and ICMP spikes, validating detections on a safe lab network to ensure no false positives

### For AI/ML Roles:

- **Integrated Isolation Forest for unsupervised anomaly detection** on traffic statistics, training on rolling 200-sample windows; model auto-retrains as new data arrives without manual intervention
- **Implemented custom explanation layer** that breaks down which features (packets/sec, bytes/sec, unique ports) deviated most from baseline, translating anomaly scores into human-interpretable insight
- **Handled imbalanced dataset challenge** by deliberately starting with rule-based detection (high precision, low recall) and adding the ML layer only after sufficient historical data exists (30+ samples)

---

## LinkedIn Project Description

**Title:** NetSentinel — AI-Powered Network Monitoring & Security System

**Body:**

I built a complete, production-grade network monitoring and security platform from scratch, combining traditional networking (ARP/ICMP device discovery, SNMP polling, packet analysis) with modern backend architecture (FastAPI, SQLAlchemy, JWT auth) and AI-assisted anomaly detection (Isolation Forest).

**Key features:**
- **Device discovery & availability monitoring** via ARP and ICMP; continuous tracking of latency and packet loss with alert generation when devices become unreachable or performance degrades
- **Real-time traffic analysis** using Scapy metadata-only packet capture; aggregation into 5-second windows for dashboard visualization (top talkers, protocol distribution, bytes/sec trends)
- **Hybrid security detection**: deterministic rules (port-scan, excessive connections, bandwidth anomalies) plus ML-based outlier detection that explains *why* a sample is anomalous instead of just returning a score
- **SNMP integration** for collecting interface statistics (optical/electrical) from standards-compliant devices (Cisco, Linux, etc.)
- **REST API** with OpenAPI Swagger docs, JWT authentication, and role-based access control (ADMIN/VIEWER)
- **NOC/SOC-style dashboard** built with vanilla HTML/CSS/JS + Chart.js for live traffic charts, device status table, and filterable/searchable alert log

**Technical highlights:**
- Layered architecture: collectors → detection → persistence → API → frontend, enabling unit testing and incremental development
- Database: SQLite for development, PostgreSQL-compatible for production (same code, different .env)
- Stateless JWT auth and async background monitoring loops (asyncio) running alongside FastAPI
- Deterministic rules + ML anomaly detection with explainability (every alert includes evidence, every ML prediction includes a plain-language explanation)

This is a serious portfolio project — it's deployable, testable, and demonstrates practical knowledge of networking, backend engineering, cybersecurity, and systems design.

---

## Common Interview Questions & Answers

### Q1: "Tell me about the architecture. Why did you structure it this way?"

**Answer:**
I deliberately separated the system into layers: **collectors** (raw network signals), **detectors** (rules & ML), **persistence** (database), and **API/frontend** (presentation).

The key insight is: *detection logic should be testable without a live network*. So if I want to test a port-scan detector, I create a synthetic TrafficWindow (no network needed) and pass it to the rule. That's powerful because:
1. I can write unit tests that run instantly
2. I can tune detection thresholds in isolation
3. New team members can understand the logic without running a full lab

Comparatively, if detection was baked into the collector ("Scapy sniffer that immediately alerts on port scans"), I'd need a live attack to test it — slow and fragile.

For the database, I chose SQLite initially because it's zero-setup (no daemon to start), but I designed the code with SQLAlchemy's abstraction layer so swapping to PostgreSQL is just a .env change. That's the scale path: develop on SQLite, deploy on Postgres.

### Q2: "How does the ML anomaly detection work? Why not just rules?"

**Answer:**
Rules are high-precision, low-recall — a rule like "alert if >20 ports in 10s" will never false-alarm, but it might miss a creative attack that doesn't hit that exact threshold.

ML (Isolation Forest) is the opposite: it's sensitive and finds subtle deviations. The problem is, "the system flagged you as anomalous" is useless feedback without explaining *why*.

So I built a hybrid: the ML model flags a sample as anomalous, then I analyze which features deviated most (packets/sec, bytes/sec, unique ports) and explain it in plain language: "Traffic volume is 4.8x higher than baseline; bytes per second is 5.7x higher."

That explanation is critical because:
1. A human can verify it (look at the top_talkers or traffic chart)
2. It's tunable ("if baseline is outdated, retrain") vs. a bare score of 0.0058, which is meaningless

Also, the ML layer only activates after 30+ samples (a few minutes of baseline data). Rules work on day 1, even with zero history. So rules + ML is pragmatic: get started with rules, let ML refine the picture as data arrives.

### Q3: "How do you prevent alert fatigue?"

**Answer:**
Alert fatigue is when you generate so many alerts that operators stop reading them. In real SOCs, an alert-storm makes people numb.

I address this two ways:

1. **Deduplication**: If an OPEN alert of type X from IP Y exists within the last 60 seconds, don't create a duplicate. So if a device stays down for 5 minutes, you get 1 alert, not 10. That alert stays OPEN for the entire 5 minutes, which is more honest than clearing it and recreating it.

2. **Severity levels**: Not every suspicious behavior is equal. I tag port scans as HIGH, bandwidth anomalies as MEDIUM, SSH exposure as INFO. The dashboard can filter by severity so operators focus on the high-severity alerts first.

3. **Evidence-driven rules**: A rule that fires every 30 seconds (high noise) vs. one that fires once per condition (low noise) is a tuning question. I made thresholds configurable (.env), so if false-positives happen, the operator can adjust without code changes.

### Q4: "Why use JWT instead of session cookies?"

**Answer:**
Sessions require server-side state (a session table or Redis). For every request, the server looks up the session ID, checks if it's valid, and retrieves the user info. That's a database query per request.

JWT is different: the token itself contains the user info (username, role) signed with a secret key. The server just verifies the signature — no database lookup needed.

The tradeoff:
- **JWT wins**: Scales horizontally (no shared session store), stateless (easier to debug)
- **Sessions win**: Can revoke a session immediately (JWT stays valid until expiry)

For NetSentinel, JWT is the right choice because it's a single-server system and the role change → revocation gap (up to 60 minutes) is acceptable. If I needed instant role revocation, I'd check the role in the database on *critical* endpoints (like alert resolution), or I'd use a short expiry (5 minutes) and accept the extra database hits.

### Q5: "How does the discovery process work? Why ARP?"

**Answer:**
Device discovery answers: "What's alive on my network right now?"

There are two main approaches:

1. **ARP scan**: Send ARP requests ("Who owns IP 192.168.56.10?") to every IP in the subnet. If the host responds, it's alive, and I get its MAC address in the reply. *Fast* (can scan a /24 in seconds) and *accurate* (only gets active hosts).

2. **ICMP ping sweep**: Send ICMP Echo Requests to every IP. If a host replies, it's alive. *Slower* (ICMP is often rate-limited) but *works through firewalls that block ARP*.

I started with ARP because it's fast and gives me MAC addresses (useful for device tracking). The code falls back to ICMP if ARP isn't available (e.g., if running on Windows without the right drivers).

ARP is a link-layer protocol, so it only works on the same broadcast domain (subnet). That's why MONITOR_SUBNET must be reachable — you can't ARP scan a remote network.

### Q6: "How do you know if the detection rules are working?"

**Answer:**
I wrote a test suite that triggers each detection rule with synthetic data. For example, the port-scan test creates a TrafficWindow with 20 unique destination ports and verifies that PORT_SCAN_SUSPECTED alert appears with the correct evidence.

No network is involved — I just create the data structure and call the detector.

In the actual lab, I have documented testing scenarios:
- **Scenario 1**: Suspend a VM (device goes offline) → DEVICE_UNREACHABLE alert should appear
- **Scenario 3**: Run nmap from Kali to Ubuntu → PORT_SCAN_SUSPECTED alert
- **Scenario 6**: Transfer a large file → BANDWIDTH_ANOMALY alert
- etc.

I walk through each scenario, trigger the condition, and verify the alert appears with correct evidence. Takes about 1 hour to validate all 10 scenarios.

### Q7: "What would you do differently if you built this again?"

**Answer:**
1. **Persistent background tasks**: Right now, the monitoring loop is in-process asyncio. If the server restarts, the loop stops. A production system would use a message queue (Celery + RabbitMQ) so tasks survive server restarts.

2. **Distributed tracing**: With multiple services, I'd add OpenTelemetry logging to trace requests end-to-end. A single request might touch the API, the detection engine, and the database — I'd want to see the whole path.

3. **Feature engineering for ML**: I used raw features (packets/sec, bytes/sec, etc.). A more sophisticated system would create derived features (entropy of destination IPs, ratio of TCP to UDP, etc.) that might have more predictive power.

4. **Active response**: Right now, the system only alerts. I'd add dry-run remediation (e.g., "if port-scan detected, *would* drop traffic from that IP, but require human approval"). That's a huge step — attacks need human judgment.

5. **Threat intelligence integration**: Cross-check flagged IPs against public blacklists (abuse.ch, etc.) to add context ("this IP is known to scan the internet").

But for a portfolio project, what I built is solid. It demonstrates the fundamentals well.

### Q8: "How does SNMP monitoring work? What about different vendors?"

**Answer:**
SNMP (Simple Network Management Protocol) is a standardized way to query device metrics. The *Manager* (NetSentinel) sends requests to *Agents* (devices) asking for specific values via *OIDs* (Object Identifiers).

OIDs are dotted-decimal paths into a tree (MIB). For example:
- `1.3.6.1.2.1.1.1.0` = system description (what is this device?)
- `1.3.6.1.2.1.2.2.1.8.<ifIndex>` = interface operational status

The genius of SNMP is: these OIDs are standardized (MIB-II, IF-MIB). A Cisco router, a Linux server, and a network printer all implement them *identically*. So my code doesn't need to know what vendor it's talking to — the same `SNMPCollector.poll_device("192.168.56.10")` works everywhere.

The current code uses SNMPv2c (community string authentication, plaintext). For production, I'd use SNMPv3 (encryption, strong auth) and would add vendor-specific enterprise OIDs if I needed CPU/memory metrics on that vendor's devices.

---

## Viva / Technical Interview Questions

1. **What is ARP, and why does it only work on the same subnet?**
   - ARP is Address Resolution Protocol; it maps IPv4 to MAC. It uses Ethernet broadcasts (ff:ff:ff:ff:ff:ff), which are only delivered to the same broadcast domain (subnet). Routers don't forward broadcasts across subnets, so ARP can't discover hosts on remote networks.

2. **Explain the TCP three-way handshake.**
   - Host A sends SYN (synchronization request) with sequence number SEQ_A to Host B
   - Host B replies with SYN-ACK containing SEQ_B and acknowledging SEQ_A+1
   - Host A sends ACK acknowledging SEQ_B+1
   - Connection is established. Data can flow in both directions.

3. **What's the difference between TCP and UDP?**
   - TCP is connection-oriented (handshake first), ordered, and reliable (retransmissions). UDP is connectionless, unordered, and unreliable (fire-and-forget). TCP is used for HTTP, SSH, SMTP; UDP for DNS, DHCP, streaming.

4. **Why use SNMP instead of SSH into every device?**
   - SNMP is faster (standardized queries), doesn't require authentication to individual devices (uses a shared community string), and scales to hundreds of devices easily. SSH requires managing hundreds of SSH keys/passwords.

5. **How does a port scan work?**
   - Attacker sends TCP SYN packets (or UDP datagrams) to a target IP, trying different port numbers. Open ports reply with SYN-ACK (or ICMP unreachable for closed ports). The attacker listens for replies to learn which services are listening.

6. **Explain the ISO OSI model and where these protocols fit.**
   - Layer 1 (Physical): Cables, voltages
   - Layer 2 (Data Link): Ethernet, MAC addresses, ARP
   - Layer 3 (Network): IP, routing
   - Layer 4 (Transport): TCP, UDP
   - Layer 7 (Application): HTTP, SSH, DNS
   - NetSentinel touches all layers: ARP (L2/3), IP/ICMP (L3), TCP/UDP (L4), SNMP/DNS (L7)

7. **What's the purpose of an alert deduplication window?**
   - Reduce alert fatigue. If a condition persists (device stays down for hours), one OPEN alert documents that better than hundreds of "device down" alerts, one every minute.

8. **How does the ML anomaly detector work?**
   - Isolation Forest randomly partitions the feature space. Anomalies are isolated in fewer partitions than normal points. The model outputs a score; I threshold it and explain the top deviating features.

9. **Why is metadata-only packet capture important?**
   - Privacy (no payload access), performance (smaller database), legality (depends on jurisdiction, but metadata is safer). Payloads would explode the database; metadata is sufficient for most patterns.

10. **What's a potential security issue with SNMPv2c?**
    - Cleartext authentication. The community string is sent in the clear, so anyone on the network segment can capture it and impersonate the manager. SNMPv3 fixes this with encryption.

---

## Contact & Deployment Links

**GitHub:** [Link to your repo]

**Demo:** [If you host it publicly, link here, or describe lab setup]

**Skills:**
- Networking (ARP, ICMP, TCP/UDP, SNMP, DNS, Subnetting)
- Python (FastAPI, SQLAlchemy, asyncio, Scapy, scikit-learn)
- Backend (REST APIs, JWT auth, RBAC, database design)
- Cybersecurity (threat detection, rule design, alert systems)
- DevOps (Alembic migrations, environment configuration, logging)
- Frontend (HTML/CSS/JavaScript, Chart.js, SPA design)

This project demonstrates end-to-end full-stack development with a focus on real-world production practices (migrations, auth, logging, testing) rather than "hello world" tutorials.
