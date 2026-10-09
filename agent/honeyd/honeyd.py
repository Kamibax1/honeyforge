#!/usr/bin/env python3
"""honeyd — скрытый агент ловушки HoneyForge.

Поддерживает уровни взаимодействия low и medium (FR-A1):
  * low   — эмуляция баннеров портов (FTP/SMTP/Telnet/SSH-banner/Elastic/Mongo/Redis);
  * medium — эмуляция логики сервисов: fake-HTTP админка с формами входа,
             fake-SSH с shell-заглушкой и псевдо-ФС, фиксация вводимых кредов
             и команд (FR-A2).

Канал с центром (раздел 9 ТЗ):
  * MASK-1: TLS (в dev допустим self-signed + pinning отпечатка);
  * MASK-2: beacon отправляется POSTом на cover_path вида /static/js/analytics.js
            с Host-заголовком «cdn-подобного» домена; тело — зашифрованный blob,
            размер выравнивается по блоку (не видно паттерна «API-вызовов»);
  * MASK-4: процесс называется неприметно (kworker-подобное имя из профиля),
            в коде/конфиге нет строк honeypot/C2;
  * FR-A3/A4: периодический beacon c jitter (MASK-5), локальный буфер событий
    (SQLite) и досылка при восстановлении канала (идемпотентно по event_uid).

Только stdlib — агент можно запустить на минимальном хосте без зависимостей.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import http.server
import json
import os
import random
import re
import shlex
import socket
import sqlite3
import ssl
import struct
import sys
import threading
import time
import uuid as uuidlib
from urllib.parse import parse_qs

# ----------------------------- утилиты -----------------------------

def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    print(f"[{ts}] {msg}", file=sys.stderr, flush=True)


class XORStream:
    """Лёгкое обфусцирование тела beacon'а поверх TLS (MASK-1 усиление:
    даже внутри TLS содержимое не читается глазами как JSON)."""

    @staticmethod
    def seal(data: bytes, key: str, ts: str) -> bytes:
        """Ключ потока = sha256(secret + "|" + timestamp) — центр восстанавливает
        его из своего БД-секрета ловушки и заголовка X-Ts."""
        kb = hashlib.sha256(f"{key}|{ts}".encode()).digest()
        out = bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))
        return base64.b64encode(out)

    @staticmethod
    def open(data: bytes, key: str, ts: str) -> bytes:
        raw = base64.b64decode(data)
        kb = hashlib.sha256(f"{key}|{ts}".encode()).digest()
        return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(raw))


def pad_to_block(payload: bytes, min_bytes: int, block: int = 64) -> bytes:
    """MASK-5: выравнивание объёма запроса — все beacon'ы кратны block и >= min."""
    need = max(min_bytes, ((len(payload) // block) + 1) * block)
    if len(payload) < need:
        filler = os.urandom(need - len(payload) - 8)
        payload += b"\x00PAD" + filler + struct.pack("<I", need - len(payload))[-2:]
    return payload


# ----------------------------- локальный буфер (FR-A4) -----------------------------

class EventBuffer:
    def __init__(self, path: str, cap: int = 5000):
        self.path = path
        self.cap = cap
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS buf(seq INTEGER PRIMARY KEY AUTOINCREMENT,"
            " uid TEXT UNIQUE, ts REAL, blob TEXT)"
        )
        self.lock = threading.Lock()

    def put(self, ev: dict) -> None:
        with self.lock:
            try:
                self.db.execute("INSERT OR IGNORE INTO buf(uid,ts,blob) VALUES(?,?,?)",
                                (ev["event_uid"], time.time(), json.dumps(ev)))
                self.db.commit()
            finally:
                n = self.db.execute("SELECT COUNT(*) FROM buf").fetchone()[0]
                if n > self.cap:
                    self.db.execute(
                        "DELETE FROM buf WHERE seq IN (SELECT seq FROM buf ORDER BY seq LIMIT ?)",
                        (n - self.cap,))
                    self.db.commit()

    def peek_batch(self, limit: int = 200) -> list[tuple[int, dict]]:
        with self.lock:
            rows = self.db.execute(
                "SELECT seq, blob FROM buf ORDER BY seq LIMIT ?", (limit,)).fetchall()
        return [(r[0], json.loads(r[1])) for r in rows]

    def ack(self, seqs: list[int]) -> None:
        with self.lock:
            self.db.executemany("DELETE FROM buf WHERE seq=?", [(s,) for s in seqs])
            self.db.commit()

    def size(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM buf").fetchone()[0]


# ----------------------------- LOW-уровень: баннеры -----------------------------

LOW_BANNERS = {
    21: b"220 (vsFTPd 3.0.5)\r\n",
    25: b"220 mail01.corp-webhost.net ESMTP Postfix (Ubuntu)\r\n",
    23: b"\r\nDebian GNU/Linux 11\\n \\t \\s\r\nlogin:",
    110: b"+OK POP3 server ready <18367.11234@corp-webhost.net>\r\n",
    143: b"* OK [CAPABILITY IMAP4rev1 LITERAL+] corp-imap ready\r\n",
}


class _TCPServer(threading.Thread):
    """Общий каркас TCP-сервера эмуляции."""

    def __init__(self, port: int, on_conn, proto="tcp"):
        super().__init__(daemon=True)
        self.port, self.on_conn, self.proto = port, on_conn, proto
        self._stop_ev = threading.Event()

    def stop(self):
        self._stop_ev.set()

    def run(self):
        try:
            if self.proto == "udp":
                self._run_udp()
            else:
                self._run_tcp()
        except OSError as e:
            log(f"svc :{self.port} bind fail: {e}")

    def _run_tcp(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen(16)
        srv.settimeout(1.0)
        conns: list[socket.socket] = []
        while not self._stop_ev.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conns.append(conn)
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
        for c in conns:  # рвём висящие сессии, чтобы поток завершился сразу
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        srv.close()

    def _handle(self, conn, addr):
        conn.settimeout(120)
        try:
            self.on_conn(conn, addr, self.port)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _run_udp(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", self.port))
        srv.settimeout(1.0)
        while not self._stop_ev.is_set():
            try:
                data, addr = srv.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            resp = self.on_conn(None, addr, self.port, data)
            if resp is not None:
                try:
                    srv.sendto(resp, addr)
                except OSError:
                    pass
        srv.close()


# ----------------------------- MEDIUM: fake-SSH -----------------------------

FAKE_FS = {
    "/home/www-data": ["app", ".ssh", "backup.sh"],
    "/home/www-data/app": ["config.py", "requirements.txt", ".env"],
    "/home/www-data/.ssh": ["id_rsa", "authorized_keys"],
    "/etc": ["passwd", "shadow", "nginx", "cron.d"],
    "/root": ["restore-db.sh", ".mysql_history"],
}
FAKE_FILES = {
    "/home/www-data/app/.env": (
        "DB_HOST=10.20.3.11\nDB_USER=www_app\nDB_PASS=Str0ng!Passw0rd#2024\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),
    "/home/www-data/.ssh/id_rsa": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU0...\n"
        "-----END OPENSSH PRIVATE KEY-----\n"),
    "/root/restore-db.sh": "#!/bin/bash\nmysqldump -u root -p$DB_ROOT_PASS appdb | gzip > /backups/app.sql.gz\n",
}


class FakeSSHSession:
    """Интерактивная SSH-подобная сессия (medium). Реального криптообмена нет —
    это эмуляция протокола на уровне строк: баннер + auth + shell."""

    def __init__(self, conn, addr, port, creds, tokens, emit, delay_ms, fake_fs=True):
        self.conn, self.addr, self.port = conn, addr, port
        self.creds = creds or []
        self.tokens = tokens or []
        self.emit = emit
        self.delay = max(0.01, delay_ms / 1000.0)
        self.session_uid = str(uuidlib.uuid4())
        self.t_start = time.time()
        self.user = ""
        self.cwd = "/home/www-data"
        self.history = []

    def send(self, s: str):
        try:
            self.conn.sendall(s.encode(errors="replace"))
        except OSError:
            raise ConnectionError

    def readline(self) -> str:
        buf = b""
        while True:
            ch = self.conn.recv(1)
            if not ch:
                raise ConnectionError
            buf += ch
            if ch in (b"\n", b"\r"):
                return buf.decode(errors="replace").strip()

    def run(self):
        src_ip = self.addr[0]
        self.emit("connect", src_ip, self.addr[1], self.port, session_uid=self.session_uid)
        self.send("SSH-2.0-OpenSSH_8.4p1 Debian-5+ubuntu0.7\r\n")
        time.sleep(self.delay)
        # "banner" stage — ожидаем строку USER ...
        try:
            for _ in range(3):
                line = self.readline()
                m = re.match(r"USER\s+(\S+)", line, re.I)
                if m:
                    self.user = m.group(1)
                    self.send("PASS\r\n")
                    pw = self.readline()
                    ok = any(c["username"] == self.user and c["password"] == pw
                             for c in self.creds)
                    self.emit("auth", src_ip, self.addr[1], self.port,
                              username=self.user, password=pw, session_uid=self.session_uid,
                              extra={"success": ok})
                    if not ok:
                        self.send("Permission denied (publickey,password).\r\n")
                        return
                    break
            else:
                return
            self.shell(src_ip)
        except (ConnectionError, TimeoutError, OSError):
            pass
        finally:
            dur = round(time.time() - self.t_start, 2)
            self.emit("session", src_ip, self.addr[1], self.port, session_uid=self.session_uid,
                      extra={"duration_sec": dur, "commands": len(self.history)})

    def shell(self, src_ip):
        self.send(f"Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)\r\n"
                  f"Last login: Mon Aug 11 09:14:02 2025 from 10.20.3.9\r\n")
        while True:
            self.send(f"{self.user}@web01:{self.cwd}$ ")
            cmd_raw = self.readline()
            if not cmd_raw:
                break
            self.history.append(cmd_raw)
            self.emit("command", src_ip, self.addr[1], self.port,
                      payload=cmd_raw, session_uid=self.session_uid)
            out = self.exec_cmd(cmd_raw)
            time.sleep(self.delay * random.uniform(0.5, 2.0))  # MASK-6 реалистичные тайминги
            if out:
                self.send(out if out.endswith("\r\n") else out + "\r\n")

    def exec_cmd(self, cmd: str) -> str:
        try:
            parts = shlex.split(cmd)
        except ValueError:
            parts = cmd.split()
        if not parts:
            return ""
        c, args = parts[0], parts[1:]
        if c in ("exit", "logout"):
            self.send("Connection to 10.20.3.50 closed.\r\n")
            return ""
        if c == "cd":
            tgt = args[0] if args else "/home/www-data"
            if tgt.startswith("/"):
                p = tgt.rstrip("/") or "/"
            elif tgt == "~":
                p = "/home/" + (self.user or "www-data")
            else:
                p = (self.cwd + "/" + tgt).replace("//", "/")
            if p in FAKE_FS or p == "/home" or any(k.startswith(p + "/") for k in FAKE_FS):
                self.cwd = p
                return ""
            return f"bash: cd: {tgt}: No such file or directory"
        if c in ("ls", "dir"):
            d = self.cwd
            if args and not args[0].startswith("-"):
                d = (self.cwd + "/" + args[-1]).replace("//", "/")
            items = FAKE_FS.get(d, [])
            if not items and d in ("/", "/home", "/var", "/tmp", "/usr"):
                items = {" /": ["bin", "boot", "etc", "home", "var", "tmp"],
                         "/home": ["www-data", "deploy"],
                         "/var": ["log", "www", "backups"],
                         "/tmp": [], "/usr": ["bin", "lib", "share"]}[d]
                return "  ".join(items) + "\r\n" if items else ""
            if not items:
                return f"ls: cannot access '{d}': No such file or directory"
            return "  ".join(items)
        if c in ("cat", "head", "more", "less"):
            if not args:
                return "usage: cat [-belnstuv] [file ...]"
            path = args[-1]
            if not path.startswith("/"):
                path = (self.cwd + "/" + path).replace("//", "/")
            content = FAKE_FILES.get(path)
            for tk in self.tokens:
                if content and str(tk.get("value", "")) in content:
                    self._token_hit(path, tk)
            if content is None:
                return f"cat: {path}: No such file or directory"
            return content
        if c == "whoami":
            return self.user or "www-data"
        if c == "id":
            return f"uid=33({self.user or 'www-data'}) gid=33 groups=33,1000"
        if c == "uname":
            return "Linux web01 5.4.0-150-generic #167-Ubuntu SMP x86_64 GNU/Linux"
        if c in ("ps", "top"):
            return ("PID TTY TIME CMD\r\n  1 ? 00:00:01 systemd\r\n"
                    "  742 ? 00:00:00 nginx: master\r\n 9101 pts/0 00:00:00 bash")
        if c in ("ifconfig", "ip"):
            return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>\r\n"
                    "    inet 10.20.3.50 netmask 255.255.255.0 broadcast 10.20.3.255")
        if c == "grep":
            return ""
        if c in ("wget", "curl"):
            return "--2026-01-01 00:00:00--  Resolving... failed: Name or service not known."
        return f"{c}: command not found"

    def _token_hit(self, path, tk):
        self.emit("honeytoken", self.addr[0], self.addr[1], self.port,
                  payload=f"{tk.get('kind')}@{path}", session_uid=self.session_uid,
                  extra={"digest": hashlib.sha256(str(tk.get("value", "")).encode()).hexdigest(),
                         "label": tk.get("label", "")})


# ----------------------------- MEDIUM: fake-HTTP админка -----------------------------

LOGIN_PAGE = """<!doctype html><html><head><title>Corp WebMail — Sign in</title></head>
<body style="font-family:sans-serif;background:#f4f6f8">
<h2 style="text-align:center;margin-top:60px">Corp WebMail</h2>
<form method="POST" action="/login" style="max-width:320px;margin:auto;background:#fff;padding:24px;border-radius:8px">
<input name="user" placeholder="Username" style="width:100%;padding:8px;margin:6px 0"><br>
<input name="pass" type="password" placeholder="Password" style="width:100%;padding:8px;margin:6px 0"><br>
<button style="width:100%;padding:8px">Sign in</button></form></body></html>"""

ADMIN_DASHBOARD = """<!doctype html><html><head><title>Webmail</title></head><body>
<h3>Inbox</h3><ul><li><a href="/read?id=42">Payroll Q4 report (xlsx attached)</a></li>
<li><a href="/read?id=43">VPN config renewal</a></li></ul>
<pre id="creds">DB_PASS=Str0ng!Passw0rd#2024 AWS_ACCESS_KEY_ID=%TOKEN%</pre>
<a href="/logout">Logout</a></body></html>"""


class HttpTrapHandler(http.server.BaseHTTPRequestHandler):
    server_version = "nginx/1.18.0"
    sys_version = ""

    # общие атрибуты назначаются при старте
    creds: list = []
    tokens: list = []
    emit = None  # type: ignore
    trap_port = 0

    def log_message(self, *a):  # глушим stderr-лог стандартного handler'а
        pass

    def _src(self):
        fwd = self.headers.get("X-Forwarded-For")
        ip = (fwd.split(",")[0].strip() if fwd else self.client_address[0])
        return ip, self.client_address[1]

    def do_GET(self):
        ip, sport = self._src()
        self.emit("request", ip, sport, self.trap_port, proto="http",
                  payload=f"GET {self.path} UA={self.headers.get('User-Agent','')}")
        if self.path in ("/", "/login", "/index.php"):
            self._send(200, LOGIN_PAGE)
        elif self.path.startswith("/admin"):
            self._send(401, "Unauthorized", www_auth="Basic realm=\"Corporate\"")
        elif self.path.startswith("/read"):
            tok = str(self.tokens[0]["value"]) if self.tokens else "none"
            self._send(200, ADMIN_DASHBOARD.replace("%TOKEN%", tok))
        elif self.path.startswith("/.env") or "passwd" in self.path:
            body = "APP_ENV=production\nSECRET_KEY=base64:Zm9vYmFyYmF6\r\n"
            for tk in self.tokens:
                if tk.get("kind") in ("env", "api_key", "cred"):
                    body += f"{tk.get('label','TOKEN')}={tk.get('value')}\r\n"
                    self.emit("honeytoken", ip, sport, self.trap_port, proto="http",
                              payload=f"honeytoken:{tk.get('label')}",
                              extra={"digest": hashlib.sha256(str(tk.get("value", "")).encode()).hexdigest()})
            self._send(200, body)
        else:
            self._send(404, "<h1>404 Not Found</h1>")

    def do_POST(self):
        ip, sport = self._src()
        ln = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(ln).decode(errors="replace") if ln else ""
        form = parse_qs(raw)
        user = (form.get("user") or [""])[0]
        pw = (form.get("pass") or [""])[0]
        self.emit("request", ip, sport, self.trap_port, proto="http",
                  payload=f"POST {self.path}")
        if self.path.startswith("/login"):
            ok = any(c["username"] == user and c["password"] == pw for c in self.creds)
            self.emit("auth", ip, sport, self.trap_port, proto="http",
                      username=user, password=pw, extra={"success": ok})
            if ok:
                self.send_response(302)
                self.send_header("Location", "/read?id=42")
                self.end_headers()
            else:
                self._send(401, LOGIN_PAGE.replace("</h2>", "</h2><p style='color:red;text-align:center'>Invalid credentials</p>"))
        else:
            self._send(405, "Method Not Allowed")

    def _send(self, code, body, www_auth=None):
        data = body.encode()
        self.send_response(code)
        if www_auth:
            self.send_header("WWW-Authenticate", www_auth)
        ctype = "text/html; charset=utf-8" if body.lstrip().startswith("<") else "text/plain; charset=utf-8"
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass


# ----------------------------- ядро агента -----------------------------

class Agent:
    def __init__(self, center_url: str, node_id: str, secret: str, aggregator_key: str,
                 state_dir: str, insecure_tls: bool = False):
        self.center = center_url.rstrip("/")
        self.node_id = node_id
        self.secret = secret
        self.akey = aggregator_key
        self.state = state_dir
        os.makedirs(state_dir, exist_ok=True)
        self.buf = EventBuffer(os.path.join(state_dir, "spool.db"))
        self.profile_banner: dict[int, bytes] = {}
        self.cfg: dict = {}
        self.cfg_version = 0
        self.servers: dict[int, _TCPServer] = {}
        self.httpd: http.server.ThreadingHTTPServer | None = None
        self.running = True
        self.insecure_tls = insecure_tls
        self.stats = {"events_emitted": 0}

    # ---------- генерация событий ----------
    def emit(self, etype, src_ip, src_port=None, dst_port=None, proto="tcp",
             username="", password="", payload="", session_uid="", extra=None):
        ev = {
            "event_uid": str(uuidlib.uuid4()),
            "ts_client": time.time(),
            "etype": etype, "proto": proto, "src_ip": src_ip,
            "src_port": src_port, "dst_port": dst_port,
            "username": username[:128], "password": password[:128],
            "payload": payload[:4000], "session_uid": session_uid,
            "extra": extra or {},
        }
        self.buf.put(ev)
        self.stats["events_emitted"] += 1

    # ---------- low-сервисы ----------
    def low_conn(self, conn, addr, port):
        self.emit("connect", addr[0], addr[1], port)
        # приоритет — баннер из профиля, иначе типовой из каталога
        banner = self.profile_banner.get(port) or LOW_BANNERS.get(port)
        if banner:
            try:
                conn.sendall(banner)
                data = conn.recv(256)
                self.emit("request", addr[0], addr[1], port, payload=data.decode(errors="replace"))
                if port == 21:
                    conn.sendall(b"530 Login authentication failed\r\n")
                elif port == 25:
                    conn.sendall(b"554 5.1.8 Relay access denied\r\n")
                else:
                    conn.sendall(b"\r\nLogin incorrect\r\n")
            except OSError:
                pass
        else:
            # «реалистичный» отказ вместо RST-детекта баннера (MASK-6)
            try:
                if port == 22:
                    conn.sendall(b"SSH-2.0-OpenSSH_8.0\r\n")
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def udp_conn(self, _conn, addr, port, data):
        self.emit("scan", addr[0], addr[1], port, proto="udp", payload=data[:200].hex())
        if port == 11211:  # memcached-подобный ответ
            return b"END\r\n"
        return None

    # ---------- применение профиля ----------
    def apply_profile(self, profile: dict):
        new_ver = int(profile.get("version", 0))
        if new_ver == self.cfg_version and self.servers:
            return
        self.cfg = profile
        self.cfg_version = new_ver
        level = profile.get("level", "low")
        services = profile.get("services", [])
        creds = profile.get("creds", [])
        tokens = profile.get("tokens", [])
        # остановить старые
        for srv in self.servers.values():
            srv.stop()
        self.servers.clear()
        if self.httpd:
            threading.Thread(target=self.httpd.shutdown, daemon=True).start()
            self.httpd = None
        if profile.get("logging", {}).get("local_buffer_max_events"):
            self.buf.cap = int(profile["logging"]["local_buffer_max_events"])

        for s in services:
            port = int(s["port"])
            proto = s.get("proto", "tcp")
            banner = s.get("banner", "").encode()
            if proto == "udp":
                srv = _TCPServer(port, self.udp_conn, proto="udp")
            elif level == "low":
                if banner:
                    self.profile_banner[port] = banner
                srv = _TCPServer(port, self.low_conn)
            else:  # medium
                if port in (22, 2222):
                    def sshh(conn, addr, p, creds=creds, tokens=tokens, s=s):
                        self.low_conn(conn, addr, p)
                        FakeSSHSession(conn, addr, p, creds, tokens, self.emit,
                                       s.get("realistic_delay_ms", 120)).run()
                    srv = _TCPServer(port, sshh)
                elif proto == "http" or s.get("kind") == "http" or port in (80, 8080, 8000):
                    continue  # HTTP-админка стартует отдельно ниже
                else:
                    def gen(conn, addr, p, creds=creds, tokens=tokens, s=s):
                        self.low_conn(conn, addr, p)
                        FakeSSHSession(conn, addr, p, creds, tokens, self.emit,
                                       s.get("realistic_delay_ms", 120)).run()
                    srv = _TCPServer(port, gen)
            srv.start()
            self.servers[port] = srv
            log(f"svc listening :{port}/{proto} ({level})")

        http_services = [s for s in services if s.get("proto") == "http" or
                         (level != "low" and s["port"] in (80, 8080, 8000))]
        if http_services and level != "low":
            s0 = http_services[0]
            HttpTrapHandler.creds = creds
            HttpTrapHandler.tokens = tokens
            HttpTrapHandler.emit = lambda *a, **kw: self.emit(*a, **kw)
            HttpTrapHandler.trap_port = int(s0["port"])
            try:
                self.httpd = http.server.ThreadingHTTPServer(("0.0.0.0", int(s0["port"])),
                                                             HttpTrapHandler)
                threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
                log(f"http admin-panel emulated :{s0['port']}")
            except OSError as e:
                log(f"http bind fail: {e}")

    # ---------- beacon ----------
    def _cover_host(self) -> tuple[str, str, int]:
        m = self.cfg.get("masking", {})
        host = self.center.split("://", 1)[-1].split("/")[0]
        scheme = "https" if self.center.startswith("https") else "http"
        port = 443 if scheme == "https" else 80
        if ":" in host:
            host, p = host.split(":")
            port = int(p)
        return scheme, host, port

    def beacon(self) -> dict | None:
        masking = self.cfg.get("masking", {})
        path = masking.get("cover_path", "/static/js/analytics.js")
        batch = self.buf.peek_batch()          # [(seq, ev), ...]
        events = [ev for _, ev in batch]
        body = {
            "uuid": self.node_id,
            "applied_profile_version": self.cfg_version,
            "stats": dict(self.stats, buffer_size=self.buf.size()),
            "events": events,
        }
        ts = str(int(time.time()))
        sealed = XORStream.seal(json.dumps(body).encode(), self.secret, ts).decode()
        # конверт: uuid в открытом виде (нужен центру для выбора ключа), тело — запечатано
        js_blob = pad_to_block(json.dumps({"u": self.node_id, "d": sealed}).encode(),
                               int(masking.get("pad_min_bytes", 256)))
        sig = hmac.new(self.secret.encode(),
                       ts.encode() + b"." + json.dumps(body, sort_keys=True,
                                                       separators=(",", ":")).encode(),
                       hashlib.sha256).hexdigest()
        headers = {
            "Content-Type": "application/octet-stream",
            "Accept": "*/*",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
            "Referer": f"{self.center}/",
            "Origin": self.center,
            "X-HF-Key": self.akey,
            "X-Ts": ts,
            "X-Sig": sig,
        }
        host_hdr = masking.get("cover_host_header")
        scheme, host, port = self._cover_host()
        ctx = None
        if scheme == "https":
            ctx = ssl.create_default_context()
            pin = masking.get("ca_pin_sha256", "")
            if pin or self.insecure_tls or masking.get("tls_verify") is False:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            elif pin:
                def _pin(conn):
                    der = conn.getpeercert(True)
                    fp = hashlib.sha256(der).hexdigest()
                    if fp != pin:
                        raise ssl.SSLError("cert pin mismatch")
                ctx.hostname_checks_common_name = False
        try:
            if scheme == "https":
                conn = http.client.HTTPSConnection(host, port, timeout=15, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=15)
            if host_hdr:
                headers["Host"] = host_hdr
            conn.request("POST", path, body=js_blob, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            conn.close()
            if resp.status != 200:
                log(f"beacon http {resp.status}")
                return None
            try:
                env = json.loads(raw)
                data = json.loads(XORStream.open(env["d"], self.secret, ts))
            except Exception:
                try:
                    data = json.loads(raw)
                except Exception:
                    log("beacon: unreadable response")
                    return None
            if data.get("ok") and events:
                self.buf.ack([seq for seq, _ in batch])
            return data
        except OSError as e:
            log(f"beacon offline: {e.__class__.__name__} (буфер: {self.buf.size()})")
            return None

    def handle_resp(self, resp: dict):
        if resp.get("profile"):
            self.apply_profile(resp["profile"])
        cmds = resp.get("commands", [])
        if "stop" in cmds:
            for srv in self.servers.values():
                srv.stop()
            self.servers.clear()
            log("traps stopped by control")
        elif "start" in cmds and not self.servers and self.cfg:
            self.apply_profile(dict(self.cfg, version=-1))  # форс-рестарт
            log("traps started by control")

    def loop(self):
        interval = float(self.cfg.get("masking", {}).get("beacon_interval_sec", 45))
        while self.running:
            delay = interval
            try:
                resp = self.beacon()
                if resp:
                    delay = float(resp.get("next_beacon_delay_sec", interval))
                    self.handle_resp(resp)
            except Exception as e:
                log(f"beacon error: {e}")
            # MASK-5: джиттер интервала
            jit = float(self.cfg.get("masking", {}).get("beacon_jitter_pct", 35))
            sleep_s = max(3.0, delay * random.uniform(1 - jit / 100, 1 + jit / 100))
            end = time.time() + sleep_s
            while self.running and time.time() < end:
                time.sleep(0.5)

    def stop(self):
        self.running = False


# ----------------------------- main -----------------------------

def main():
    ap = argparse.ArgumentParser(description="telemetry node")
    ap.add_argument("--center", default=os.environ.get("HFD_CENTER_URL", "http://127.0.0.1:8000"))
    ap.add_argument("--node-id", default=os.environ.get("HF_TRAP_UUID", ""))
    ap.add_argument("--secret", default=os.environ.get("HFD_SECRET", ""))
    ap.add_argument("--akey", default=os.environ.get("HFD_AGGREGATOR_KEY", ""))
    ap.add_argument("--state-dir", default=os.environ.get("HFD_STATE", "/tmp/hfd-state"))
    ap.add_argument("--insecure-tls", action="store_true")
    ap.add_argument("--bootstrap-profile", default=os.environ.get("HFD_PROFILE_FILE", ""),
                    help="JSON-файл профиля для автономного демо-режима (без центра)")
    args = ap.parse_args()

    if not args.node_id or not args.secret:
        ap.error("нужны --node-id/--secret (или env HF_TRAP_UUID/HFD_SECRET)")

    ag = Agent(args.center, args.node_id, args.secret, args.akey, args.state_dir,
               insecure_tls=args.insecure_tls)
    if args.bootstrap_profile and os.path.exists(args.bootstrap_profile):
        ag.apply_profile(json.load(open(args.bootstrap_profile)))
    t = threading.Thread(target=ag.loop, daemon=True)
    t.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        ag.stop()
        log(f"shutdown, buffered={ag.buf.size()}")


if __name__ == "__main__":
    main()
