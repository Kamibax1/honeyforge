#!/usr/bin/env bash
# Остановка локальных процессов, поднятых run-local.sh
set -uo pipefail
pkill -f "uvicorn app.main:app" || true
pkill -f "node index.js" || true
pkill -f "http.server 8080" || true
echo "stopped"
