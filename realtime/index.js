#!/usr/bin/env node
/**
 * HoneyForge Realtime — WebSocket-мост + приёмный прокси (realtime-слой архитектуры).
 *
 * Работает как «аггрегирующий прокси» (proxying layer pattern):
 *   1) принимает beacon'ы от агентов ловушек (маскированный POST на cover_path),
 *      прозрачно ретранслирует тело и заголовки подписи в коллектор центра;
 *   2) центр проверяет HMAC per-node секретом — realtime секреты ловушек не знает;
 *   3) публикует события атак в WebSocket-ленту dashboard в реальном времени.
 *
 * Так Control API центра вообще не торчит наружу: агенты видят только
 * «CDN-подобный» эндпоинт этого слоя, операторы — WS-эндпоинт того же хоста (MASK-2).
 *
 * Зависимости: ws (npm i ws). Node >= 18.
 */
'use strict';

const http = require('http');
const { WebSocketServer, WebSocket } = require('ws');

const PORT = parseInt(process.env.RT_PORT || '8090', 10);
const CENTER = process.env.CENTER_URL || 'http://center:8000';
const AGG_KEY = process.env.HF_AGGREGATOR_KEY || 'change-me-aggregator-key';
const WS_PATH = process.env.RT_WS_PATH || '/static/rt';       // неприметный путь (MASK-2)
const BEACON_PATHS = (process.env.RT_BEACON_PATHS ||
  '/static/js/analytics.js,/collect/beacon').split(',');

// ---------- состояние ----------
const clients = new Set();
let lastId = 0;

function broadcast(obj) {
  const msg = JSON.stringify(obj);
  for (const ws of clients) {
    if (ws.readyState === WebSocket.OPEN) ws.send(msg);
  }
}

function forwardToCenter(bodyBuf, headers) {
  return fetch(CENTER + '/collect/beacon', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-HF-Key': AGG_KEY,
      'X-Ts': headers['x-ts'] || '',
      'X-Sig': headers['x-sig'] || '',
    },
    body: bodyBuf,
  });
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('ok');
  }
  const isBeacon = BEACON_PATHS.some(p => req.url.startsWith(p.trim()));
  if (req.method === 'POST' && isBeacon) {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', async () => {
      try {
        const bodyBuf = Buffer.concat(chunks);
        const r = await forwardToCenter(bodyBuf, req.headers);
        const out = Buffer.from(await r.arrayBuffer());
        let data = {};
        try { data = JSON.parse(out.toString('utf8')); } catch (_) {}
        if (r.status === 200) {
          // лента: публикуем «сырые» события из beacon'а (bodyBuf — открытый JSON
          // или запечатанное тело; для ленты парсим, если это JSON)
          try {
            const parsed = JSON.parse(bodyBuf.toString('utf8'));
            for (const ev of parsed.events || []) {
              lastId += 1;
              broadcast({ id: lastId, type: 'event', trap: parsed.uuid, ts: Date.now() / 1000, ...ev });
            }
          } catch (_) { /* запечатанное тело — лента получит echo из ответа ниже */ }
          for (const ev of (data._echo_events || [])) {
            lastId += 1;
            broadcast({ id: lastId, type: 'event', trap: req.headers['x-node-id'] || '', ts: Date.now() / 1000, ...ev });
          }
          if (data.profile && data.profile.version) {
            lastId += 1;
            broadcast({ id: lastId, type: 'config', version: data.profile.version });
          }
          if (data._triggers && data._triggers.length) {
            lastId += 1;
            broadcast({ id: lastId, type: 'honeytoken_trigger', labels: data._triggers });
          }
        }
        res.writeHead(r.status, { 'Content-Type': 'application/octet-stream' });
        res.end(out);
      } catch (e) {
        res.writeHead(502, { 'Content-Type': 'text/plain' });
        res.end('bad gateway');
      }
    });
    return;
  }
  res.writeHead(404, { 'Content-Type': 'text/html' });
  res.end('<html><body><h1>example-assets CDN</h1><p>static delivery node</p></body></html>');
});

const wss = new WebSocketServer({ server, path: WS_PATH });
wss.on('connection', (ws) => {
  clients.add(ws);
  ws.send(JSON.stringify({ type: 'hello', ts: Date.now(), clients: clients.size }));
  ws.on('close', () => clients.delete(ws));
});

server.listen(PORT, () => console.log(`[realtime] :${PORT} beacon=${BEACON_PATHS} ws=${WS_PATH}`));
