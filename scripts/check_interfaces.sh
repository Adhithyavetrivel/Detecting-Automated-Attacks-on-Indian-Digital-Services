#!/usr/bin/env bash
# Quick reference: inspect available network interfaces before setting
# MONITOR_INTERFACE in .env.
echo "== Interfaces (ip addr) =="
ip addr

echo ""
echo "== Routing table (ip route) =="
ip route

echo ""
echo "== ARP/neighbor cache (ip neigh) =="
ip neigh
