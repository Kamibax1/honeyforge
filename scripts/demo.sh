#!/usr/bin/env bash
# Демо-сценарий «атака → событие в центре» (раздел 7 кейса).
# Требования: запущенный центр (docker compose или scripts/run-local.sh), curl, python3.
#
# Использование:
#   ./scripts/demo.sh [URL_ЦЕНТРА]        # по умолчанию http://127.0.0.1:8000
set -euo pipefail

CENTER="${1:-http://127.0.0.1:8000}"
LOGIN="${HF_ADMIN_LOGIN:-operator}"
PASS="${HF_ADMIN_PASSWORD:-honeyforge}"
UI_DIR="$(cd "$(dirname "$0")/.." && pwd)"

say() { echo -e "\n\033[1;36m==> $*\033[0m"; }

say "1. Логин оператора на $CENTER"
TOKEN=$(curl -sf -X POST "$CENTER/auth/login" \
  -d "username=$LOGIN&password=$PASS" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
AUTH="Authorization: Bearer $TOKEN"

say "2. Создание профиля low (баннеры) и medium (fake-HTTP + fake-SSH)"
PROFILE_LOW=$(curl -sf -X POST "$CENTER/profiles" -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "name": "edge-low-banners", "description": "Эмуляция баннеров портов", "level": "low",
  "services": [
    {"proto":"tcp","port":21,"kind":"ftp","banner":"220 FTP Server ready."},
    {"proto":"tcp","port":23,"kind":"telnet","banner":"Ubuntu 22.04.3 LTS\\nlogin:"},
    {"proto":"tcp","port":25,"kind":"smtp","banner":"220 mail.example.local ESMTP"}
  ]}')
PROFILE_MED=$(curl -sf -X POST "$CENTER/profiles" -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "name": "admin-medium-http-ssh", "description": "Fake-админка + fake-SSH", "level": "medium",
  "services": [
    {"proto":"tcp","port":80,"kind":"http","banner":"nginx/1.24.0"},
    {"proto":"tcp","port":22,"kind":"ssh","banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"}
  ],
  "credentials": [{"username":"admin","password":"P@ssw0rd123","service":"http"}],
  "honeytokens": [{"kind":"api_key","value":"AKIAIOSFODNN7EXAMPLE","note":"fake AWS key"}]
}')
LOW_ID=$(echo "$PROFILE_LOW" | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
MED_ID=$(echo "$PROFILE_MED" | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
echo "profile low id=$LOW_ID, medium id=$MED_ID"

say "3. Регистрация двух ловушек и получение секретов агентов"
HP_LOW=$(curl -sf -X POST "$CENTER/honeypots" -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"name\":\"trap-edge-01\",\"host_addr\":\"10.20.0.11\",\"profile_id\":$LOW_ID}")
HP_MED=$(curl -sf -X POST "$CENTER/honeypots" -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"name\":\"trap-admin-01\",\"host_addr\":\"10.20.0.12\",\"profile_id\":$MED_ID}")
read -r UUID_L SECRET_L <<<"$(echo "$HP_LOW" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['uuid'],d['agent_secret'])")"
read -r UUID_M SECRET_M <<<"$(echo "$HP_MED" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['uuid'],d['agent_secret'])")"
echo "trap low:    uuid=$UUID_L"
echo "trap medium: uuid=$UUID_M"

say "4. Запуск агентов (скрытые процессы) локально"
export HFD_CENTER_URL="$CENTER"
export HFD_AGGREGATOR_KEY="${HF_AGGREGATOR_KEY:-change-me-aggregator-key}"

HF_TRAP_UUID="$UUID_L" HFD_SECRET="$SECRET_L" HFD_STATE=/tmp/hfd-low \
  python3 "$UI_DIR/agent/honeyd/honeyd.py" > /tmp/honeyd-low.log 2>&1 &
PID_L=$!
HF_TRAP_UUID="$UUID_M" HFD_SECRET="$SECRET_M" HFD_STATE=/tmp/hfd-med \
  python3 "$UI_DIR/agent/honeyd/honeyd.py" > /tmp/honeyd-med.log 2>&1 &
PID_M=$!
trap 'kill $PID_L $PID_M 2>/dev/null || true' EXIT
sleep 4

say "5. Атака: сканирование low-ловушки + креды/команды на medium-ловушке"
nc -w1 127.0.0.1 21  </dev/null >/dev/null 2>&1 || true
nc -w1 127.0.0.1 25  </dev/null >/dev/null 2>&1 || true
curl -s -o /dev/null -X POST http://127.0.0.1:80/login \
  -d 'username=admin&password=letmein' || true
curl -s -o /dev/null http://127.0.0.1:80/.env || true
printf 'whoami\ncat /home/www-data/app/.env\nexit\n' | nc -w2 127.0.0.1 22 >/dev/null 2>&1 || true
echo "атаки отправлены, ждём beacon (до 15 c)…"
sleep 15

say "6. События атак в центре"
curl -sf "$CENTER/events?limit=10" -H "$AUTH" | python3 -m json.tool | head -60

say "7. Статусы ловушек (online) и статистика"
curl -sf "$CENTER/honeypots" -H "$AUTH" | python3 -c "
import sys,json
for h in json.load(sys.stdin):
    print(f\"{h['name']:16} level={h.get('level','?'):7} status={h['status']}\")"
curl -sf "$CENTER/stats" -H "$AUTH" | python3 -m json.tool | head -20

say "Готово. Откройте dashboard: http://localhost:8080 (или :8080 у nginx) — лента обновляется по WebSocket."
