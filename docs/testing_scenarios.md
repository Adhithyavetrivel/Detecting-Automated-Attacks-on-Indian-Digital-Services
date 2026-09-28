# NetSentinel Testing Scenarios

All tests are run **only** within an isolated lab environment (VirtualBox host-only network,
localhost, or a controlled private subnet). Never target systems outside your own lab.

---

## Lab Setup

```
Host (Windows/Mac/Linux)
└── VirtualBox Host-Only Network: 192.168.56.0/24
    ├── Ubuntu 22.04 VM      (192.168.56.10) — app server, monitoring target
    ├── Kali Linux VM        (192.168.56.20) — test client, attack simulation
    └── NetSentinel server   (192.168.56.30) — monitoring server (can run on host)
```

---

## Scenario 1: Device Goes Offline

**Setup:**
1. Create two devices via POST /api/devices or scan:
   - 192.168.56.10 (Ubuntu — will stay online)
   - 192.168.56.20 (Kali — will be brought offline)
2. Start monitoring: POST /api/monitoring/start
3. Let it run 2-3 cycles to populate baselines

**Trigger:**
```bash
# On the host or in VirtualBox, suspend the Kali VM
# Or: on the Kali VM, bring down the interface:
sudo ip link set eth0 down
```

**Expected:**
- After 1-2 monitoring cycles, 192.168.56.20 status flips to OFFLINE in the dashboard
- A DEVICE_UNREACHABLE alert (severity HIGH) appears with evidence: "4/4 pings lost"
- Alert is deduplicated — additional cycles don't create new alerts (same alert remains OPEN)

**Reset:**
```bash
sudo ip link set eth0 up
# Or: resume the VM
```
Device status returns to ONLINE, no new alert.

---

## Scenario 2: High Latency

**Setup:**
Same as Scenario 1, monitoring running.

**Trigger:**
Introduce packet loss or delay on the path to 192.168.56.20:
```bash
# On Kali, add 500ms latency to all outgoing traffic
sudo tc qdisc add dev eth0 root netem delay 500ms

# Or, on Ubuntu (the target), add 500ms to responses:
sudo tc qdisc add dev eth0 root netem delay 500ms
```

**Expected:**
- Latency reported in the device list jumps to ~500ms
- HIGH_LATENCY alert (severity MEDIUM) appears with the actual latency value
- Evidence field shows: `avg_latency_ms=500.0`

**Reset:**
```bash
sudo tc qdisc del dev eth0 root
```

---

## Scenario 3: Port Scan Detection

**Setup:**
Monitoring running, both VMs online.

**Trigger:**
From Kali, scan Ubuntu's open ports:
```bash
# Fast SYN scan of the first 100 ports
nmap -sS 192.168.56.10 -p1-100

# Or a UDP scan of DNS/DHCP/SNMP
nmap -sU 192.168.56.10 -p53,67,161
```

**Expected:**
- Once NetSentinel captures traffic from the scan, a PORT_SCAN_SUSPECTED alert (HIGH severity) appears
- Source IP: 192.168.56.20 (Kali)
- Evidence: `unique_destination_ports=<count>` (should be ≥15, depending on scan parameters)
- Dashboard shows the top destination ports contacted (80, 443, 22, etc.) in the traffic chart

**Timing note:**
- Packet capture runs only when POST /api/monitoring/capture is called, or if a background
  capture loop is active
- The port-scan detection runs against that window; if you trigger nmap before capture starts,
  it won't be detected
- This is intentional: capture is privileged (needs root on Linux), so it's manual or on a schedule

**Reset:**
Just stop the nmap scan. No cleanup needed.

---

## Scenario 4: Excessive Connections

**Setup:**
Monitoring running.

**Trigger:**
From Kali, open many simultaneous TCP connections to Ubuntu:
```bash
# Using Python to create 100 connections and hold them open
python3 << 'EOF'
import socket
import time

for i in range(100):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('192.168.56.10', 22))  # SSH port
        print(f"Connection {i} opened")
    except Exception as e:
        print(f"Failed: {e}")

time.sleep(60)  # Hold for 1 minute
EOF

# Or use hping (if installed) to send SYN packets without completing the handshake:
sudo hping3 -S --flood -p 22 192.168.56.10
```

**Expected:**
- The connection count from Kali's IP rises (visible in netstat/ss on Ubuntu)
- EXCESSIVE_CONNECTIONS alert appears (severity MEDIUM)
- Evidence: `connection_count=<count> threshold=100`
- If the threshold is set lower in .env (EXCESSIVE_CONNECTIONS_THRESHOLD=50), it triggers sooner

**Reset:**
Kill the Python script or hping. Connections close automatically (TCP timeout).

---

## Scenario 5: ICMP Flood

**Setup:**
Monitoring running.

**Trigger:**
From Kali, send many ping packets:
```bash
# Flood Ubuntu with pings
ping -f 192.168.56.10

# Or specify a rate:
sudo hping3 -1 --flood 192.168.56.10  # ICMP mode, flood rate

# Or use ping3 (Python) in a loop:
python3 << 'EOF'
import subprocess
import time
for _ in range(1000):
    subprocess.run(['ping', '-c', '1', '192.168.56.10'], stderr=subprocess.DEVNULL)
    time.sleep(0.01)
EOF
```

**Expected:**
- ICMP packet count spikes in the traffic window
- ICMP_ANOMALY alert appears (MEDIUM severity) with evidence: `icmp_per_second=<value> baseline=<baseline> ratio=<x-times-higher>`
- Ratio must be ≥5x above the baseline for the alert to trigger (per `detect_icmp_anomaly()`)

**Reset:**
Ctrl+C the ping or hping.

---

## Scenario 6: High Bandwidth Usage

**Setup:**
Monitoring running. Establish a large file transfer.

**Trigger:**
On Ubuntu, start a simple HTTP server:
```bash
cd /tmp
# Create a 100MB file
dd if=/dev/zero of=largefile.bin bs=1M count=100

# Start a simple HTTP server
python3 -m http.server 8888
```

From Kali, download it:
```bash
# Download the 100MB file, generating sustained traffic
curl http://192.168.56.10:8888/largefile.bin -o /dev/null

# Or use wget with throttling disabled:
wget http://192.168.56.10:8888/largefile.bin -O /dev/null
```

**Expected:**
- Traffic capture shows bytes_per_second spike to (100MB / transfer_time)
- BANDWIDTH_ANOMALY alert (MEDIUM severity) if bytes/sec ≥3x baseline
- Evidence: `bytes_per_second=<value> baseline=<baseline> ratio=<x-times>`

**Reset:**
Ctrl+C the download. Server is still running; you can trigger more downloads to generate more baseline data.

---

## Scenario 7: ML Anomaly Detection

**Setup:**
Monitoring & capture running for ≥5 minutes to build a baseline (30+ windows minimum).
Then trigger a clear anomaly.

**Trigger:**
1. Let the system collect traffic peacefully for a few minutes: `POST /api/monitoring/capture` every 5-10 seconds
2. Then trigger multiple anomalies at once:
   ```bash
   # On Kali:
   nmap -sS 192.168.56.10 -p1-100 &
   ping -f 192.168.56.10 &
   # Meanwhile, on Ubuntu, download a large file from Kali:
   python3 -m http.server 8888
   # And from host, curl to download it
   curl http://192.168.56.10:8888/largefile.bin -o /dev/null
   ```

**Expected:**
- After running POST /api/monitoring/capture with this traffic, the ML detector compares the current window to the 200-sample history
- If packets/sec, bytes/sec, and unique_ports all deviate significantly, ML_ANOMALY alert (MEDIUM severity) appears
- Explanation field breaks down which features deviated most, e.g.:
  `"unique_dst_ports is 3.2x higher than baseline; bytes_per_second is 5.8x higher than baseline."`

**Reset:**
Stop all traffic generators. Next capture window returns to normal patterns; no new alert.

---

## Scenario 8: SNMP Monitoring (Phase 8)

**Setup:**
1. Enable SNMP on Ubuntu (requires snmpd installation):
   ```bash
   sudo apt install -y snmp snmpd
   sudo systemctl start snmpd
   ```
2. On the dashboard, enable SNMP for 192.168.56.10 (PATCH /api/devices/1 with `is_snmp_enabled=true`)
3. The monitoring background task will add SNMP polling to its cycle

**Trigger:**
Just let monitoring run; it will query SNMP automatically.

**Expected:**
- Interfaces for 192.168.56.10 are populated in the database (GET /api/interfaces?device_id=1)
- Interface names (eth0, eth1, etc.), statistics (in_octets, out_octets, in_errors), and status (up/down) appear
- Generate traffic (ping, curl, etc.) and wait for the next SNMP poll — in_octets/out_octets increase

**Reset:**
Disable SNMP or stop snmpd. No cleanup needed.

---

## Scenario 9: Normal Traffic (Baseline Building)

**Setup:**
Fresh database, monitoring running.

**Trigger:**
Just let the system run normally:
```bash
# On Kali or Ubuntu, generate light traffic:
while true; do
  curl http://192.168.56.10:8888/small.txt -o /dev/null 2>/dev/null
  sleep 2
done

# Or just let normal ARP, DNS, SSH keep running
```

**Expected:**
- Traffic records are created with stable packets/bytes per second
- No alerts (or only benign INFO-level alerts)
- After 30+ windows (5-10 minutes), the ML model has a strong baseline
- Subsequent scenarios' anomalies will be clearly flagged against this baseline

**Reset:**
Just stop the traffic script. Continue running for more baseline.

---

## Scenario 10: Denied Access (Auth/RBAC)

**Setup:**
Two users: admin (from Phase 1 setup) and a VIEWER user.

**Trigger:**
```bash
# Create a VIEWER user via admin token
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=<password>" | jq -r .access_token)

curl -X POST http://localhost:8000/api/auth/register \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"viewer1","password":"viewerpass","role":"VIEWER"}'

# Now try to create a device with the VIEWER token:
VIEWER_TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=viewer1&password=viewerpass" | jq -r .access_token)

curl -X POST http://localhost:8000/api/devices \
  -H "Authorization: Bearer $VIEWER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip_address":"10.0.0.5"}'
```

**Expected:**
- VIEWER token can GET /api/devices, /api/alerts, /api/metrics (read-only)
- VIEWER token gets 403 Forbidden on POST /api/devices, POST /api/alerts/{id}/resolve, etc.
- ADMIN token can do anything

**Reset:**
No cleanup needed; roles are enforced per-request.

---

## Monitoring Troubleshooting

**Server won't start:**
- Check .env (especially MONITOR_INTERFACE)
- Check database file isn't locked: `lsof netsentinel.db`
- Check port 8000 isn't in use: `lsof -i :8000`

**Ping failing / no metrics:**
- Confirm device IP is reachable: `ping <ip>` from the host
- Check firewall on the VM (may block ICMP): `sudo ufw allow in icmp` or disable ufw temporarily

**Capture returning zero packets:**
- Confirm you're using root/sudo: packet capture needs raw sockets
- Confirm MONITOR_INTERFACE in .env is correct: `ip addr` to list interfaces
- BPF filter syntax error? Try with no filter first: POST /api/monitoring/capture with default params

**Alerts not firing:**
- Check alert timestamps are recent (POST /api/alerts; sort by timestamp DESC)
- Verify thresholds in .env match your trigger scenario
- Check the AuditLog table for any error messages

**Dashboard shows no devices:**
- Did you run POST /api/devices/scan or manually add devices?
- Check /api/devices returns a list
- Check login token is valid (GET /api/auth/me)

---

## Summary

Each scenario is self-contained and repeatable. By running them, you'll:
1. Gain confidence in the monitoring system's detection logic
2. Build a narrative for interviews: "I triggered a port scan, and here's how the system detected it..."
3. Verify that the system works as designed before asking someone to rely on it

Record screenshots of alerts being triggered — they're excellent portfolio material.
