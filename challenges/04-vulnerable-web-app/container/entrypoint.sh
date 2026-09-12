#!/bin/sh
set -e

exec python3 /workspace/app/app.py --host 0.0.0.0 --port 8080

