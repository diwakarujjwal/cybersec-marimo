#!/usr/bin/env bash
set -e

# Navigate to project root
cd "$(dirname "$0")"

# Activate virtual environment
source .venv/bin/activate

# Set python path and start CyberLab platform (API + Frontend UI)
export PYTHONPATH=.
echo "🚀 Starting CyberLab Platform on http://localhost:8888 ..."
exec python3 -m uvicorn cyberlab.main:app --host 0.0.0.0 --port 8888 --reload --reload-dir cyberlab

