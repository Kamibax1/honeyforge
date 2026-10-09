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
    {"proto":"http","port":8080,"kind":"http","banner":"nginx/1.18.0"},
    {"proto":"tcp","port":2222,"kind":"ssh","banner":"SSH-2.0-OpenSSH_8.4p1 Debian-5+ubuntu0.7"}
  ],
  "credentials": [{"username":"admin","password":"P@ssw0rd123"}],
  "honeytokens": [{"kind":"api_key","label":"fake AWS key","value":"AKIAIOSFODNN7EXAMPLE"}],
  "masking": {"beacon_interval_sec": 5, "beacon_jitter_pct": 20}
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
# Агент ходит по маскированному cover_path; локально его принимает либо nginx/realtime-слой,
# либо напрямую центр — проксируем cover_path на центр через мини-мост realtime.
COVER_PROXY="http://127.0.0.1:8090/static/js/analytics.js"
if curl -sf -o /dev/null http://127.0.0.1:8090/healthz 2>/dev/null; then
  export HFD_CENTER_URL="http://127.0.0.1:8090"
else
  export HFD_CENTER_URL="$CENTER"
fi
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
# fake-HTTP админка: неверные креды → алерт-правило brute force, затем чтение /.env
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -X POST http://127.0.0.1:8080/login \
    -d 'user=root&password=hunter'$i || true
done
curl -s -o /dev/null http://127.0.0.1:8080/.env || true
# fake-SSH: баннер + USER/PASS + команды в shell-заглушке
printf 'USER admin\nP@ssw0rd123\nwhoami\ncat /home/www-data/app/.env\nexit\n' \
  | nc -q1 -w3 127.0.0.1 2222 >/dev/null 2>&1 || true
echo "атаки отправлены, ждём beacon (до 20 c)…"
sleep 20

say "6. События атак в центре"
curl -sf "$CENTER/events?limit=10" -H "$AUTH" | python3 -m json.tool | head -60

say "7. Статусы ловушек (online) и статистика"
curl -sf "$CENTER/honeypots" -H "$AUTH" | python3 -c "
import sys,json
for h in json.load(sys.stdin):
    print(f\"{h['name']:16} level={str(h.get('level')) or '?':7} status={h['status']} profile={h.get('profile_name')}\")"
curl -sf "$CENTER/alerts" -H "$AUTH" | python3 -c "
import sys,json
for a in json.load(sys.stdin)[:5]:
    print(f\"alert [{a['rule']}/{a['severity']}] {a['src_ip']}: {a['detail']}\")"
curl -sf "$CENTER/honeytokens" -H "$AUTH" | python3 -c "
import sys,json
for t in json.load(sys.stdin)[:5]:
    print(f\"honeytoken {t['label']!r} triggered={t['triggered']} by={t['triggered_by_ip']}\")"
curl -sf "$CENTER/stats" -H "$AUTH" | python3 -m json.tool | head -20

say "Готово. Откройте dashboard: http://localhost:8080 (или :8080 у nginx) — лента обновляется по WebSocket."
