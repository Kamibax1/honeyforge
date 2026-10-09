#!/usr/bin/env bash
# Локальный запуск центра HoneyForge без Docker (SQLite вместо PostgreSQL).
set -euo pipefail
cd "$(dirname "$0")/.."

pip install -r center/requirements.txt "bcrypt==4.0.1"
(cd realtime && npm install --omit=dev)

mkdir -p center/data logs

echo "[1/3] Control API  -> http://127.0.0.1:8000  (docs: /docs)"
(cd center && uvicorn app.main:app --host 127.0.0.1 --port 8000 > ../logs/center.log 2>&1 &)

echo "[2/3] Realtime WS  -> ws://127.0.0.1:8090/static/rt"
(cd realtime && RT_PORT=8090 CENTER_URL=http://127.0.0.1:8000 node index.js > ../logs/realtime.log 2>&1 &)

echo "[3/3] UI           -> http://127.0.0.1:8080"
(cd ui && python3 -m http.server 8080 > ../logs/ui.log 2>&1 &)

sleep 3
curl -sf http://127.0.0.1:8000/healthz && echo " — центр готов"
echo "Логин в UI: operator / honeyforge"
echo "Остановка: ./scripts/stop.sh"
