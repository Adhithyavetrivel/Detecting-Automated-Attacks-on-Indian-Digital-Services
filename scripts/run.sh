#!/usr/bin/env bash
# Run the NetSentinel API server.
# Packet capture (Scapy) and raw ARP scanning need root — use sudo if you
# plan to use those features; the server itself runs fine without it,
# those specific endpoints will just report a clear permissions error.
set -euo pipefail
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
