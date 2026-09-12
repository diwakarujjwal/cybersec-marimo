#!/bin/sh
set -e

exec marimo edit /workspace/marimo/challenge.py \
    --host 0.0.0.0 \
    --port 8080 \
    --no-token \
    --headless

