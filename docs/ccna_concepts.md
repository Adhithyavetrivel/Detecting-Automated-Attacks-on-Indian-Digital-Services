# CCNA Concepts Demonstrated in NetSentinel

This document maps the project's features to the Cisco CCNA R&S (Routing & Switching) curriculum,
showing how building NetSentinel strengthens exam readiness and practical understanding.

## OSI Model & TCP/IP Model

**Concepts demonstrated:**
- **Layer 3 (Network)**: IP addresses, subnetting (MONITOR_SUBNET parsing in IPv4 CIDR notation)
- **Layer 4 (Transport)**: TCP/UDP port detection, connection tracking, TCP flags (SYN/ACK)
- **Layer 2 (Data Link)**: MAC address collection via ARP, MAC address tables

**In NetSentinel:**
- Device discovery uses ARP (Address Resolution Protocol — Layer 3/2 boundary) to map IPv4 → MAC
- Traffic collectors extract Layer 4 port/protocol info; packet capture preserves this distinction
- Alert rules operate on Layer 3/4 patterns (port scan, excessive connections)

---

## ARP (Address Resolution Protocol)

**Concepts:**
- ARP maps IPv4 addresses to MAC addresses on a local network segment
- ARP works only within a broadcast domain (subnet)
- ARP replies populate an ARP cache / neighbor table

**In NetSentinel:**
- `app/collectors/discovery.py` performs an ARP scan of MONITOR_SUBNET to find devices
- ARP replies include MAC addresses, which are stored in Device.mac_address
- Scapy's built-in ARP layer makes this straightforward: `Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(...)`

**Interview context:**
- "I used ARP for discovery because it gives me MAC addresses in one broadcast sweep, much faster
  than pinging the entire subnet. ARP only works on the local LAN; it's why MONITOR_SUBNET must
  be a reachable subnet, not a remote network."

---

## ICMP (Internet Control Message Protocol)

**Concepts:**
- ICMP ping (Echo Request/Reply) is the basis for reachability testing
- ICMP carries diagnostic information: unreachable, time exceeded, parameter problem
- ICMP is unencrypted and can be filtered at firewalls or ACLs

**In NetSentinel:**
- Availability monitoring (Phase 3) pings every device multiple times per cycle
- Each ping samples latency; packet-loss percentage is computed across the multi-ping sample
- ICMP anomaly detection flags unusual volumes of ICMP traffic (possible flood/sweep)

**Interview context:**
- "Ping is the practical way to test if a host is reachable — it's ICMP's intended use. In the
  monitoring loop, I run multiple pings per host so I can distinguish 1/4 packet loss (normal,
  just an occasional drop) from 4/4 (device truly down)."

---

## TCP & UDP

**Concepts:**
- TCP: connection-oriented, three-way handshake (SYN/SYN-ACK/ACK), reliable delivery
- UDP: connectionless, no handshake, fast, used for DNS, DHCP, VoIP
- Port numbers: well-known (0-1023), registered (1024-49151), ephemeral (49152-65535)

**In NetSentinel:**
- Scapy packet capture layers extract TCP and UDP headers separately
- Connection tracking uses netstat/ss (which shows TCP/UDP sockets in various states)
- Port-scan detection looks for a source IP contacting many *different* destination ports —
  the signature of a TCP SYN scan or full-connect scan
- Suspicious service detection flags unexpected exposure of Telnet (23), FTP (21), SSH (22), RDP (3389)

**Interview context:**
- "Port scanning works by flooding a target with TCP SYN packets to many ports. If the port is
  open, the target replies with SYN-ACK; if closed, it sends RST. NetSentinel watches for a
  source IP triggering this pattern (many different ports in a short window) and flags it."

---

## DNS (Domain Name System)

**Concepts:**
- DNS queries (UDP port 53) resolve hostnames to IP addresses
- DNS can be used for reconnaissance (zone transfers, reverse lookups)
- DNS spoofing/poisoning can redirect users to malicious sites

**In NetSentinel:**
- Traffic filtering includes a `"dns"` BPF filter preset (traffic on UDP 53)
- Device discovery optionally does reverse-DNS lookups (gethostbyaddr) to populate Device.hostname
- Future: DNS anomaly detection (unusual query volume, or queries to known malicious domains)

---

## SNMP (Simple Network Management Protocol)

**Concepts:**
- SNMP v2c: community string (shared secret) authenticates manager-to-agent communication
- SNMPv2c is cleartext — never use on untrusted networks; only for managed lab/datacenter
- OIDs (Object Identifiers) address leaf values in the MIB tree (e.g., `1.3.6.1.2.1.2.2.1.8.<ifIndex>` = interface operational status)
- Standard MIB-II is identical across vendors (Cisco IOS, Linux net-snmp, etc.)

**In NetSentinel:**
- Phase 8 (SNMP Monitoring) polls devices via SNMPv2c using standard IF-MIB and system OIDs
- Interface statistics (in_octets, out_octets, in_errors, out_errors) are populated from SNMP walks
- The SNMPCollector is abstracted (`app/collectors/snmp_collector.py`) so the same code works
  against a Cisco router, a Linux server, or a network switch — they all implement the same MIB-II tables

**Interview context:**
- "SNMP lets me query performance metrics without logging into every device individually. A Cisco
  router and a Linux server both expose the same OIDs for interface status, so I don't need
  device-specific logic. SNMPv2c is plaintext, so it's only suitable for a controlled management
  network, not the public internet."

---

## Ethernet, MAC, and Switching

**Concepts:**
- Ethernet frames carry MAC source/destination addresses (Layer 2)
- Switches forward frames based on MAC address tables (learned from source addresses)
- VLAN tagging (802.1Q) segments broadcast domains

**In NetSentinel:**
- Scapy's Ether layer provides source/destination MAC addresses in captured packets
- ARP relies on Ethernet broadcast (dst MAC = ff:ff:ff:ff:ff:ff) within a VLAN/broadcast domain
- Future: VLAN-aware network topology inference (tagged vs. untagged ports)

---

## Network Troubleshooting Commands

The project teaches practical Linux network diagnostics:

```bash
ip addr          # Modern replacement for ifconfig; shows all interfaces & IP addresses
ip route         # Routing table; shows default gateway and subnet routes
ip neigh         # Neighbor/ARP cache; shows IP-to-MAC mappings
ss -tn           # Socket statistics; shows active TCP/UDP connections by state
ping             # ICMP Echo Request; tests reachability
traceroute       # Sends UDP packets with increasing TTL to trace the path to a host
tcpdump          # Packet capture filter syntax (BPF) used by Scapy/tshark
arp -a           # Old-style ARP cache view (arp command deprecated on Linux in favor of ip neigh)
```

**In NetSentinel:**
- `discovery.py` uses `subprocess` to call `ping` and `arping` (or Scapy's ARP layer)
- Monitoring loops use `psutil.net_connections()` to enumerate active sockets (connection count)
- Packet capture sets up BPF filters (same syntax as tcpdump) to focus on specific protocols

---

## Network Monitoring & Alerting

**Concepts:**
- Real-time monitoring requires a baseline of "normal" behavior
- Deviations from baseline → alerts; alerts without human context are noise
- Alert severity levels (INFO, LOW, MEDIUM, HIGH, CRITICAL) help prioritize response

**In NetSentinel:**
- Device availability metrics (latency, packet loss) are continuously sampled and stored
- Rule-based detection compares current metrics to thresholds (e.g., latency > 200ms)
- ML-based detection compares current traffic patterns to a rolling 200-sample history (baseline)
- Every alert includes evidence (the actual numbers that triggered it), not just a verdict

---

## Security: Port Scans & Connection Behavior

**Concepts:**
- Port scanning precedes most network attacks (reconnaissance phase)
- Connection floods (SYN flood) exhaust server resources
- Brute-force login attempts show a pattern: many connections from one source in a short window

**In NetSentinel:**
- `detect_port_scan()`: flags a source IP contacting ≥15 distinct ports in 10 seconds
- `detect_excessive_connections()`: flags a source with ≥100 active connections (tunable)
- Both rules are deterministic (no ML) so they are explainable and easy to tune

---

## Data Link Layer: VLANs & Trunking

**Concepts:**
- VLANs logically segment a physical switch into independent broadcast domains
- 802.1Q trunks carry multiple VLANs over a single physical link (tagged frames)
- Access ports belong to a single VLAN (untagged frames)

**In NetSentinel:**
- Future enhancement: detect VLAN tags in captured packets (Scapy's Dot1Q layer)
- Network topology inference could map which ports are trunks vs. access ports
- Currently, MONITOR_SUBNET and MONITOR_INTERFACE assume a flat network segment

---

## Subnetting (CIDR Notation)

**Concepts:**
- CIDR (Classless Inter-Domain Routing): `/24` = 256 addresses, `/25` = 128 addresses, etc.
- Subnet mask calculates which bits are the network portion, which are the host portion
- Network broadcast address = host bits all 1 (e.g., 192.168.1.255 for 192.168.1.0/24)

**In NetSentinel:**
- `MONITOR_SUBNET` (default: `192.168.1.0/24`) is parsed using Python's `ipaddress` module
- Device discovery iterates over all usable addresses in the subnet (network + 1 to broadcast - 1)
- The `/24` means the first 24 bits are fixed (192.168.1), the last 8 bits vary (0-255)

**Interview context:**
- "A /24 subnet has 256 total addresses, but 2 are reserved: the network address (.0) and broadcast
  (.255). That leaves 254 usable host addresses. If I'm scanning a /24, I'll get replies from
  the real hosts on that segment."

---

## NAT (Network Address Translation)

**Concepts:**
- NAT translates private addresses (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  to public addresses for outbound traffic
- Stateful NAT keeps a translation table; replies are translated back to private addresses
- PAT (Port Address Translation) maps many internal hosts to one public IP by rewriting port numbers

**In NetSentinel:**
- The lab network (VirtualBox host-only) is entirely private (192.168.56.0/24)
- No NAT is involved; device discovery and monitoring work directly without translation
- Future: detect when a host is scanning "outside" the lab (impossible in host-only mode, but
  would indicate either a configuration error or a compromised host)

---

## ACLs (Access Control Lists)

**Concepts:**
- Packet-filtering ACLs on routers/switches enforce allow/deny rules by source IP, destination IP, protocol, port
- Stateful firewalls understand connection state (established, new, etc.)

**In NetSentinel:**
- Detection rules encode "what patterns are suspicious"; they're a form of behavioral ACL
- Example: "if src_ip contacts >15 dst_ports in 10s, block or alert" is an ACL-like rule
- Future: recommend ACL rules based on detected threats

---

## Summary: CCNA Readiness

By building NetSentinel, you demonstrate:

1. **Layer 2/3 understanding**: ARP, MAC addresses, subnetting, device discovery
2. **Layer 4 insight**: TCP/UDP, port numbers, connection tracking
3. **Protocols**: ICMP (ping), SNMP (agent polling), DNS (hostname resolution)
4. **Network administration**: Linux net tools (ip, ss, ping), VLAN/trunk concepts
5. **Security fundamentals**: port scans, connection floods, reconnaissance patterns
6. **Monitoring & alerting**: baselines, thresholds, severity levels
7. **System design**: layered architecture, separation of concerns, database persistence
8. **Automation**: continuous monitoring loops, detection rules as code

In an interview, these project experiences let you discuss *applied* networking knowledge, not just
memorized facts. "I built a network monitoring system" carries more weight than "I know what ARP is."
