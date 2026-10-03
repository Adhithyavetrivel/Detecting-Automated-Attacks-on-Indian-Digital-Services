#!/usr/bin/env bash
# NetSentinel first-time setup for Linux (Ubuntu/Kali).
set -euo pipefail

echo "== NetSentinel setup =="

echo "--> Creating virtual environment"
python3 -m venv venv
source venv/bin/activate

echo "--> Upgrading pip"
pip install --upgrade pip

echo "--> Installing Python dependencies"
pip install -r requirements.txt

echo "--> Checking for tshark (optional, for advanced Wireshark-style analysis)"
if ! command -v tshark &> /dev/null; then
  echo "tshark not found. Install it with: sudo apt install -y tshark"
else
  echo "tshark found."
fi

echo "--> Copying .env.example to .env (edit this before running!)"
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env — edit MONITOR_SUBNET, MONITOR_INTERFACE, SECRET_KEY before running."
else
  echo ".env already exists, leaving it untouched."
fi

echo "--> Running database migrations"
alembic upgrade head

echo ""
echo "Setup complete. Next steps:"
echo "  1. Edit .env with your lab's subnet/interface"
echo "  2. Create an admin user: python -m scripts.create_admin --username admin --password <pw>"
echo "  3. Run the server: bash scripts/run.sh"
