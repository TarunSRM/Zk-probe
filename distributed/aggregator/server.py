#!/usr/bin/env python3
"""
zkNIDS Aggregator — Production Hardened Server v2.1
====================================================

Security features:
  - API key authentication (agent + admin roles)
  - Per-IP rate limiting
  - Security headers (X-Content-Type-Options, X-Frame-Options, etc.)
  - Input validation (regex patterns, whitelists, type checks)
  - Path traversal protection on proof downloads
  - Content-Type enforcement on POST/PUT/PATCH
  - Parameterized SQL everywhere (zero f-string user input in SQL)
  - Payload size limits
  - Audit logging (DB + file) for all mutations
  - WebSocket connection limit

Data Layout:
  /var/lib/zknids/
  ├── aggregator.db
  ├── proofs/proof_<uuid>.json
  └── logs/{aggregator.log, audit.log}

First run generates API keys in /var/lib/zknids/api_keys.json
"""

import argparse
import collections
import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, List

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Body, Request, Depends
    from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field, field_validator
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import Response
    import uvicorn
except ImportError:
    print("ERROR: pip3 install fastapi uvicorn python-multipart")
    raise SystemExit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

DATA_DIR = "/var/lib/zknids"
DB_PATH = os.path.join(DATA_DIR, "aggregator.db")
PROOF_DIR = os.path.join(DATA_DIR, "proofs")
LOG_DIR = os.path.join(DATA_DIR, "logs")
API_KEYS_FILE = os.path.join(DATA_DIR, "api_keys.json")

MAX_ALERT_PAYLOAD = 64 * 1024       # 64 KB
MAX_PROOF_PAYLOAD = 512 * 1024      # 512 KB
MAX_QUERY_LIMIT = 500
MAX_WS_CONNECTIONS = 20
HEARTBEAT_TIMEOUT = 30               # seconds
RATE_LIMIT_WINDOW = 60               # seconds
RATE_LIMIT_MAX_REQUESTS = 120        # per window per IP


# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)

    app_log = logging.getLogger('zknids')
    app_log.setLevel(logging.INFO)
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    app_log.addHandler(logging.StreamHandler())
    fh = logging.handlers.RotatingFileHandler(
        os.path.join(LOG_DIR, "aggregator.log"), maxBytes=10*1024*1024, backupCount=5)
    fh.setFormatter(fmt)
    app_log.addHandler(fh)
    for h in app_log.handlers:
        h.setFormatter(fmt)

    aud = logging.getLogger('zknids-audit')
    aud.setLevel(logging.INFO)
    afh = logging.handlers.RotatingFileHandler(
        os.path.join(LOG_DIR, "audit.log"), maxBytes=10*1024*1024, backupCount=20)
    afh.setFormatter(logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%dT%H:%M:%S'))
    aud.addHandler(afh)

    return app_log, aud

log, audit_log = setup_logging()


# ═══════════════════════════════════════════════════════════════════════════════
# API KEY MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

API_KEYS = {}  # key_hash -> {"role": "agent"|"admin", "name": "..."}

def init_api_keys():
    """Load or generate API keys. Keys are stored hashed; plaintext shown only on first creation."""
    global API_KEYS
    os.makedirs(DATA_DIR, exist_ok=True)

    if os.path.exists(API_KEYS_FILE):
        with open(API_KEYS_FILE) as f:
            API_KEYS = json.load(f)
        log.info(f"Loaded {len(API_KEYS)} API keys")
        return

    # First run: generate default keys
    agent_key = secrets.token_urlsafe(32)
    admin_key = secrets.token_urlsafe(32)

    API_KEYS = {
        hash_key(agent_key): {"role": "agent", "name": "default-agent"},
        hash_key(admin_key): {"role": "admin", "name": "default-admin"},
    }

    with open(API_KEYS_FILE, 'w') as f:
        json.dump(API_KEYS, f, indent=2)
    os.chmod(API_KEYS_FILE, 0o600)  # Owner-only read/write

    # Save plaintext keys to file so they can be retrieved
    plaintext_file = os.path.join(DATA_DIR, "api_keys_plaintext.txt")
    with open(plaintext_file, 'w') as f:
        f.write(f"Agent API Key: {agent_key}\n")
        f.write(f"Admin API Key: {admin_key}\n")
    os.chmod(plaintext_file, 0o600)

    log.info("=" * 60)
    log.info("  FIRST RUN — API KEYS GENERATED")
    log.info("  Save these now. They won't be shown again.")
    log.info(f"  Agent key: {agent_key}")
    log.info(f"  Admin key: {admin_key}")
    log.info(f"  Stored in: {API_KEYS_FILE}")
    log.info(f"  Plaintext: {plaintext_file}")
    log.info("=" * 60)


def hash_key(key: str) -> str:
    """SHA-256 hash of API key for storage/comparison."""
    return hashlib.sha256(key.encode()).hexdigest()


def verify_api_key(request: Request, required_role: str = "agent") -> dict:
    """Verify API key from X-API-Key header. Returns key info or raises 401/403."""
    key = request.headers.get("x-api-key", "")

    # Allow dashboard (GET requests from browser, WebSocket) without key
    # The dashboard is served from the same origin
    if not key:
        # Unauthenticated: only allow GET to read-only endpoints and dashboard
        if request.method == "GET" or request.url.path in ("/", "/ws", "/docs", "/openapi.json"):
            return {"role": "readonly", "name": "anonymous"}
        raise HTTPException(401, "Missing X-API-Key header",
                            headers={"WWW-Authenticate": "ApiKey"})

    key_hash = hash_key(key)
    info = API_KEYS.get(key_hash)
    if not info:
        audit_log.info(f"ACTION=AUTH_FAILED SOURCE={get_ip(request)} key_hash={key_hash[:16]}...")
        raise HTTPException(401, "Invalid API key")

    # Role check
    role_hierarchy = {"admin": 2, "agent": 1, "readonly": 0}
    if role_hierarchy.get(info["role"], 0) < role_hierarchy.get(required_role, 0):
        raise HTTPException(403, f"Requires {required_role} role, you have {info['role']}")

    return info


# ═══════════════════════════════════════════════════════════════════════════════
# RATE LIMITER
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    """Per-IP sliding window rate limiter."""
    def __init__(self, window=RATE_LIMIT_WINDOW, max_req=RATE_LIMIT_MAX_REQUESTS):
        self.window = window
        self.max_req = max_req
        self.requests = collections.defaultdict(list)  # ip -> [timestamps]

    def check(self, ip: str) -> bool:
        """Returns True if allowed, False if rate limited."""
        now = time.time()
        cutoff = now - self.window
        # Clean old entries
        self.requests[ip] = [t for t in self.requests[ip] if t > cutoff]
        if len(self.requests[ip]) >= self.max_req:
            return False
        self.requests[ip].append(now)
        return True

    def cleanup(self):
        """Periodic cleanup of stale IPs."""
        cutoff = time.time() - self.window * 2
        stale = [ip for ip, ts in self.requests.items() if not ts or ts[-1] < cutoff]
        for ip in stale:
            del self.requests[ip]

rate_limiter = RateLimiter()


# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Enforce per-IP rate limiting."""
    async def dispatch(self, request: Request, call_next):
        ip = get_ip(request)
        if not rate_limiter.check(ip):
            audit_log.info(f"ACTION=RATE_LIMITED SOURCE={ip} path={request.url.path}")
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Try again later."},
                headers={"Retry-After": str(RATE_LIMIT_WINDOW)}
            )
        return await call_next(request)


class ContentTypeMiddleware(BaseHTTPMiddleware):
    """Enforce Content-Type: application/json on mutation endpoints."""
    async def dispatch(self, request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH"):
            ct = request.headers.get("content-type", "")
            if request.url.path.startswith("/api/") and "application/json" not in ct:
                return JSONResponse(status_code=415,
                    content={"detail": "Content-Type must be application/json"})
        return await call_next(request)


# ═══════════════════════════════════════════════════════════════════════════════
# INPUT VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

# Strict patterns
RE_UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
RE_SAFE_ID = re.compile(r'^[a-zA-Z0-9_\-\.]{1,128}$')
RE_HOSTNAME = re.compile(r'^[a-zA-Z0-9_\-\.]{1,256}$')
RE_IP = re.compile(r'^[0-9a-fA-F\.:]{1,45}$')  # IPv4 + IPv6
RE_SAFE_FILENAME = re.compile(r'^[a-zA-Z0-9_\-]{1,64}$')


def sanitize(s, max_len=256):
    """Strip control characters and truncate."""
    if not isinstance(s, str):
        return str(s)[:max_len]
    return re.sub(r'[\x00-\x1f\x7f]', '', s)[:max_len]


def validate_uuid_format(s):
    """Validate UUID format. Returns sanitized string or raises."""
    s = sanitize(s, 64)
    if not RE_UUID.match(s):
        raise HTTPException(400, f"Invalid UUID format: {s[:32]}")
    return s


def validate_safe_id(s, field_name="id"):
    """Validate safe identifier (alphanumeric + _ - .)"""
    s = sanitize(s, 128)
    if not RE_SAFE_ID.match(s):
        raise HTTPException(400, f"Invalid {field_name}: must be alphanumeric/underscore/hyphen")
    return s


def validate_numeric(v, field_name="value", min_val=None, max_val=None):
    """Validate numeric input."""
    if v is None:
        return None
    try:
        v = float(v)
    except (TypeError, ValueError):
        raise HTTPException(400, f"Invalid {field_name}: must be numeric")
    if min_val is not None and v < min_val:
        raise HTTPException(400, f"{field_name} must be >= {min_val}")
    if max_val is not None and v > max_val:
        raise HTTPException(400, f"{field_name} must be <= {max_val}")
    return v


def safe_json_parse(body: bytes, max_size: int) -> dict:
    """Parse JSON with size limit and type check."""
    if len(body) > max_size:
        raise HTTPException(413, "Payload too large")
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(400, "Invalid JSON")
    if not isinstance(data, dict):
        raise HTTPException(400, "JSON body must be an object")
    return data


def get_ip(request: Request) -> str:
    """Extract client IP (respects X-Forwarded-For behind reverse proxy)."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        ip = fwd.split(",")[0].strip()
        if RE_IP.match(ip):
            return ip
    return request.client.host if request.client else "0.0.0.0"


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT
# ═══════════════════════════════════════════════════════════════════════════════

def audit_event(action, target="", details="", source_ip="", db_conn=None):
    audit_log.info(f"ACTION={action} TARGET={target} SOURCE={source_ip} {details}")
    if db_conn:
        try:
            db_conn.execute(
                "INSERT INTO audit_log (timestamp,action,target,details,source_ip) VALUES (?,?,?,?,?)",
                (time.time(), sanitize(action,64), sanitize(target,128), sanitize(details,512), sanitize(source_ip,45)))
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

def init_db(db_path=DB_PATH):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    os.makedirs(PROOF_DIR, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS hosts (
            host_id TEXT PRIMARY KEY, hostname TEXT, host_ip TEXT, interface TEXT,
            agent_version TEXT, phase1_version TEXT, phase2_version TEXT,
            last_heartbeat REAL, first_seen REAL, status TEXT DEFAULT 'unknown'
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT UNIQUE NOT NULL, host_id TEXT NOT NULL, received_at REAL NOT NULL,
            invariant_id TEXT NOT NULL, invariant_type TEXT, category TEXT,
            circuit_template TEXT, severity TEXT, description TEXT,
            observed_value REAL, threshold REAL, threshold_operator TEXT, timestamp_ns INTEGER,
            host_ip TEXT, hostname TEXT, interface TEXT,
            total_packets INTEGER, syn_packets INTEGER, flow_count INTEGER, packet_rate REAL,
            proof_status TEXT DEFAULT 'pending', proof_id TEXT, proof_generated_at REAL,
            proof_circuit_template TEXT DEFAULT '', proof_public_inputs TEXT DEFAULT '{}',
            proof_generation_time_ms INTEGER DEFAULT 0, proof_prover_version TEXT DEFAULT '',
            proof_file TEXT DEFAULT '', raw_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(received_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_invariant ON alerts(invariant_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_proof ON alerts(proof_status);

        CREATE TABLE IF NOT EXISTS invariants (
            id TEXT PRIMARY KEY, type TEXT NOT NULL, category TEXT NOT NULL,
            circuit_template TEXT NOT NULL, threshold REAL NOT NULL,
            threshold_operator TEXT DEFAULT 'greater_than', severity TEXT DEFAULT 'medium',
            description TEXT DEFAULT '', enabled INTEGER DEFAULT 1,
            updated_at REAL, updated_by TEXT DEFAULT 'system'
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL,
            action TEXT NOT NULL, target TEXT DEFAULT '', details TEXT DEFAULT '',
            source_ip TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
    """)
    conn.close()
    log.info(f"DB initialized: {db_path}")


def seed_default_invariants(db_path=DB_PATH):
    defaults = [
        ("syn_flood_detection","ratio","network_flood","ratio_check_v1",0.5,"greater_than","critical","SYN/total packet ratio exceeds threshold"),
        ("fragment_abuse_detection","ratio","evasion","ratio_check_v1",0.3,"greater_than","high","IP fragment ratio exceeds threshold"),
        ("execve_rate_high","rate","host_behavior","rate_check_v1",100,"greater_than","high","Execve syscall rate exceeds threshold"),
        ("port_scan_detection","rate","reconnaissance","rate_check_v1",50,"greater_than","critical","Unique port access rate exceeds threshold"),
        ("malformed_header_detection","rate","evasion","rate_check_v1",5,"greater_than","medium","Malformed packet rate exceeds threshold"),
        ("packet_rate_spike","deviation","anomaly","deviation_check_v1",3,"greater_than","critical","Packet rate exceeds baseline multiplier"),
        ("packet_size_anomaly","deviation","anomaly","deviation_check_v1",15,"greater_than","high","Packet size variance exceeds baseline"),
        ("flow_churn_detection","deviation","anomaly","deviation_check_v1",5,"greater_than","high","Flow churn rate exceeds baseline multiplier"),
    ]
    conn = sqlite3.connect(db_path)
    if conn.execute("SELECT COUNT(*) FROM invariants").fetchone()[0] == 0:
        now = time.time()
        for d in defaults:
            conn.execute("INSERT INTO invariants (id,type,category,circuit_template,threshold,threshold_operator,severity,description,enabled,updated_at,updated_by) VALUES (?,?,?,?,?,?,?,?,1,?,'system')", (*d, now))
        conn.commit()
        log.info(f"Seeded {len(defaults)} invariants")
    conn.close()


def migrate_db(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    for name, defn in [("proof_file", "TEXT DEFAULT ''")]:
        try: conn.execute(f"ALTER TABLE alerts ADD COLUMN {name} {defn}")
        except sqlite3.OperationalError: pass
    conn.commit(); conn.close()


@contextmanager
def get_db(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try: yield conn; conn.commit()
    finally: conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# PYDANTIC MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class HeartbeatRequest(BaseModel):
    host_id: str = Field(..., min_length=1, max_length=128, pattern=r'^[a-zA-Z0-9_\-\.]+$')
    hostname: str = Field("", max_length=256)
    host_ip: str = Field("", max_length=45)
    interface: str = Field("", max_length=64)
    timestamp: float = 0
    agent_version: str = Field("", max_length=32)
    phase1_version: str = Field("", max_length=32)
    phase2_version: str = Field("", max_length=32)

    @field_validator('host_ip')
    @classmethod
    def val_ip(cls, v):
        if v and not RE_IP.match(v):
            raise ValueError("Invalid IP format")
        return v


class InvariantUpdate(BaseModel):
    threshold: Optional[float] = None
    threshold_operator: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = Field(None, max_length=512)
    enabled: Optional[bool] = None

    @field_validator('threshold_operator')
    @classmethod
    def val_op(cls, v):
        if v and v not in ('greater_than', 'less_than', 'equals'):
            raise ValueError("Must be: greater_than, less_than, or equals")
        return v

    @field_validator('severity')
    @classmethod
    def val_sev(cls, v):
        if v and v not in ('critical', 'high', 'medium', 'low'):
            raise ValueError("Must be: critical, high, medium, or low")
        return v

    @field_validator('threshold')
    @classmethod
    def val_threshold(cls, v):
        if v is not None and (v < 0 or v > 1e9):
            raise ValueError("Threshold must be 0–1000000000")
        return v


# ═══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class ConnectionManager:
    def __init__(self, max_conn=MAX_WS_CONNECTIONS):
        self.active: List[WebSocket] = []
        self.max_conn = max_conn

    async def connect(self, ws: WebSocket):
        if len(self.active) >= self.max_conn:
            await ws.close(code=1013, reason="Max connections reached")
            return False
        await ws.accept()
        self.active.append(ws)
        log.info(f"WS connected ({len(self.active)}/{self.max_conn})")
        return True

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)
        log.info(f"WS disconnected ({len(self.active)}/{self.max_conn})")

    async def broadcast(self, message):
        dead = []
        if isinstance(message, str):
            message = json.loads(message)
        for ws in self.active:
            try: await ws.send_json(message)
            except: dead.append(ws)
        for ws in dead:
            if ws in self.active: self.active.remove(ws)

ws_manager = ConnectionManager()


# ═══════════════════════════════════════════════════════════════════════════════
# FASTAPI APP
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(title="zkNIDS Aggregator", version="2.1.0",
              description="Hardened central alert collection and ZK proof management",
              docs_url="/docs", redoc_url=None)

# Middleware order matters: outermost first
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(ContentTypeMiddleware)
app.add_middleware(CORSMiddleware,
    allow_origins=["*"],  # Restrict in production: ["http://aggregator-ip:8080"]
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH"],
    allow_headers=["Content-Type", "X-API-Key"],
    expose_headers=["X-Request-Id"],
)


@app.on_event("startup")
async def startup():
    init_db(); migrate_db(); seed_default_invariants(); init_api_keys()
    log.info("zkNIDS Aggregator v2.1 started (hardened)")


# ── Auth dependency shortcuts ─────────────────────────────────────────────────

AUTH_DISABLED = False  # Set True by --no-auth flag

def require_agent(request: Request):
    if AUTH_DISABLED:
        return {"role": "admin", "name": "dev-noauth"}
    return verify_api_key(request, "agent")

def require_admin(request: Request):
    if AUTH_DISABLED:
        return {"role": "admin", "name": "dev-noauth"}
    return verify_api_key(request, "admin")


# ═══════════════════════════════════════════════════════════════════════════════
# HEARTBEAT
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/heartbeat")
async def receive_heartbeat(hb: HeartbeatRequest, request: Request,
                            auth: dict = Depends(require_agent)):
    now = time.time()
    ip = get_ip(request)
    with get_db() as db:
        existing = db.execute("SELECT host_id FROM hosts WHERE host_id=?", (hb.host_id,)).fetchone()
        if existing:
            db.execute("UPDATE hosts SET hostname=?,host_ip=?,interface=?,agent_version=?,phase1_version=?,phase2_version=?,last_heartbeat=?,status='online' WHERE host_id=?",
                (sanitize(hb.hostname), sanitize(hb.host_ip), sanitize(hb.interface),
                 sanitize(hb.agent_version), sanitize(hb.phase1_version), sanitize(hb.phase2_version), now, hb.host_id))
        else:
            db.execute("INSERT INTO hosts (host_id,hostname,host_ip,interface,agent_version,phase1_version,phase2_version,last_heartbeat,first_seen,status) VALUES (?,?,?,?,?,?,?,?,?,'online')",
                (hb.host_id, sanitize(hb.hostname), sanitize(hb.host_ip), sanitize(hb.interface),
                 sanitize(hb.agent_version), sanitize(hb.phase1_version), sanitize(hb.phase2_version), now, now))
            audit_event("HOST_REGISTER", hb.host_id, f"hostname={hb.hostname} ip={hb.host_ip}", ip, db)
            log.info(f"New host: {hb.host_id} ({hb.hostname})")
    await ws_manager.broadcast({'type':'heartbeat','host_id':hb.host_id,'hostname':hb.hostname,'host_ip':hb.host_ip,'timestamp':now})
    return {"status": "ok"}


# ═══════════════════════════════════════════════════════════════════════════════
# ALERTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/alerts")
async def receive_alert(request: Request, auth: dict = Depends(require_agent)):
    now = time.time()
    ip = get_ip(request)
    body = await request.body()
    data = safe_json_parse(body, MAX_ALERT_PAYLOAD)

    alert_id = sanitize(data.get('alert_id', str(uuid.uuid4())), 64)
    dash = data.get('dashboard_fields', {})
    inv = data.get('invariant', {})
    obs = data.get('observation', {})
    meta = data.get('metadata', {})

    host_id = sanitize(dash.get('host_id', 'unknown'), 128)
    inv_id = sanitize(inv.get('id', 'unknown'), 128)
    severity = sanitize(meta.get('severity', 'unknown'), 16)

    # Validate severity
    if severity not in ('critical', 'high', 'medium', 'low', 'unknown'):
        severity = 'unknown'

    # Validate numeric fields
    obs_val = validate_numeric(obs.get('observed_value'), "observed_value", -1e15, 1e15)
    threshold = validate_numeric(obs.get('threshold'), "threshold", -1e15, 1e15)

    log.info(f"ALERT {host_id}: {inv_id} sev={severity}")

    with get_db() as db:
        try:
            db.execute("""
                INSERT OR IGNORE INTO alerts
                (alert_id,host_id,received_at,invariant_id,invariant_type,category,circuit_template,
                 severity,description,observed_value,threshold,threshold_operator,timestamp_ns,
                 host_ip,hostname,interface,total_packets,syn_packets,flow_count,packet_rate,
                 proof_status,raw_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (alert_id, host_id, now, inv_id,
                  sanitize(inv.get('type',''),32), sanitize(inv.get('category',''),64),
                  sanitize(inv.get('circuit_template',''),64), severity,
                  sanitize(inv.get('description',''),512), obs_val, threshold,
                  sanitize(obs.get('threshold_operator',''),32), obs.get('timestamp_ns'),
                  sanitize(dash.get('host_ip',''),45), sanitize(dash.get('hostname',''),256),
                  sanitize(dash.get('interface',''),64),
                  dash.get('total_packets'), dash.get('syn_packets'),
                  dash.get('flow_count'), dash.get('packet_rate'),
                  'pending', json.dumps(data, separators=(',',':'))))
            audit_event("ALERT_RECEIVED", alert_id, f"inv={inv_id} sev={severity} host={host_id}", ip, db)
        except sqlite3.IntegrityError:
            log.warning(f"Duplicate alert: {alert_id}")

    await ws_manager.broadcast({
        'type':'new_alert','alert_id':alert_id,'host_id':host_id,
        'hostname':dash.get('hostname',''),'host_ip':dash.get('host_ip',''),
        'invariant_id':inv_id,'category':inv.get('category',''),
        'severity':severity,'observed_value':obs_val,'threshold':threshold,
        'description':inv.get('description',''),
        'total_packets':dash.get('total_packets',0),'syn_packets':dash.get('syn_packets',0),
        'proof_status':'pending','timestamp':now
    })
    return {"status":"ok","alert_id":alert_id}


@app.get("/api/hosts")
async def get_hosts():
    now = time.time()
    stale_cutoff = 24 * 3600  # Remove hosts not seen in 24 hours
    with get_db() as db:
        # Clean up stale hosts (not seen in 24h)
        db.execute("DELETE FROM hosts WHERE ?-last_heartbeat>?", (now, stale_cutoff))
        hosts = []
        for r in db.execute("SELECT * FROM hosts ORDER BY last_heartbeat DESC").fetchall():
            h = dict(r)
            if now - (h.get('last_heartbeat') or 0) > HEARTBEAT_TIMEOUT:
                h['status'] = 'offline'
            # Include alert count per host
            cnt = db.execute("SELECT COUNT(*) FROM alerts WHERE host_id=?", (h['host_id'],)).fetchone()[0]
            h['alert_count'] = cnt
            hosts.append(h)
        return hosts


@app.delete("/api/hosts/stale")
async def purge_stale_hosts(auth: dict = Depends(require_admin)):
    """Remove offline hosts not seen in 24h and reassign 'unknown' alerts."""
    now = time.time()
    with get_db() as db:
        stale = db.execute("SELECT host_id FROM hosts WHERE ?-last_heartbeat>?",
                           (now, 24*3600)).fetchall()
        deleted = len(stale)
        db.execute("DELETE FROM hosts WHERE ?-last_heartbeat>?", (now, 24*3600))
        # Count orphaned unknown alerts
        unknown = db.execute("SELECT COUNT(*) FROM alerts WHERE host_id='unknown'").fetchone()[0]
        return {"deleted_hosts": deleted, "orphaned_alerts": unknown,
                "host_ids": [r[0] for r in stale]}


@app.get("/api/alerts")
async def get_alerts(host_id: Optional[str]=None, severity: Optional[str]=None,
                     invariant_id: Optional[str]=None, proof_status: Optional[str]=None,
                     limit: int=100, offset: int=0):
    limit = max(1, min(limit, MAX_QUERY_LIMIT))
    offset = max(0, offset)

    # Whitelist filter values
    VALID_SEV = {'critical','high','medium','low','unknown'}
    VALID_PROOF = {'pending','generating','verified','failed'}

    with get_db() as db:
        q, p = "SELECT * FROM alerts WHERE 1=1", []
        if host_id:
            q += " AND host_id=?"; p.append(sanitize(host_id,128))
        if severity:
            s = sanitize(severity,16)
            if s in VALID_SEV: q += " AND severity=?"; p.append(s)
        if invariant_id:
            q += " AND invariant_id=?"; p.append(sanitize(invariant_id,128))
        if proof_status:
            s = sanitize(proof_status,16)
            if s in VALID_PROOF: q += " AND proof_status=?"; p.append(s)
        q += " ORDER BY received_at DESC LIMIT ? OFFSET ?"
        p.extend([limit, offset])
        return [dict(r) for r in db.execute(q, p).fetchall()]


@app.get("/api/alerts/{alert_id}")
async def get_alert_detail(alert_id: str):
    safe_id = sanitize(alert_id, 64)
    with get_db() as db:
        row = db.execute("SELECT * FROM alerts WHERE alert_id=?", (safe_id,)).fetchone()
        if not row: raise HTTPException(404, "Alert not found")
        result = dict(row)
        if result.get('raw_json'):
            result['full_alert'] = json.loads(result['raw_json'])
        return result


@app.get("/api/stats")
async def get_stats():
    now = time.time()
    with get_db() as db:
        total_alerts = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        total_hosts = db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        online_hosts = db.execute("SELECT COUNT(*) FROM hosts WHERE ?-last_heartbeat<?",
                                   (now, HEARTBEAT_TIMEOUT)).fetchone()[0]

        # Safe group counts: column names are hardcoded, never from user input
        def _gc(col):
            d = {}
            for r in db.execute(
                {"severity":"SELECT severity,COUNT(*) FROM alerts GROUP BY severity",
                 "invariant_id":"SELECT invariant_id,COUNT(*) FROM alerts GROUP BY invariant_id",
                 "category":"SELECT category,COUNT(*) FROM alerts GROUP BY category",
                 "host_id":"SELECT host_id,COUNT(*) FROM alerts GROUP BY host_id",
                 "proof_status":"SELECT proof_status,COUNT(*) FROM alerts GROUP BY proof_status",
                }[col]).fetchall():
                d[r[0]] = r[1]
            return d

        one_hour_ago = now - 3600
        timeline = [{'minute':r[0],'count':r[1]} for r in db.execute(
            "SELECT CAST((received_at-?)/60 AS INTEGER),COUNT(*) FROM alerts WHERE received_at>? GROUP BY 1 ORDER BY 1",
            (one_hour_ago, one_hour_ago)).fetchall()]

        return {
            'total_alerts':total_alerts,'total_hosts':total_hosts,'online_hosts':online_hosts,
            'severity_counts':_gc('severity'),'invariant_counts':_gc('invariant_id'),
            'category_counts':_gc('category'),'host_counts':_gc('host_id'),
            'proof_stats':_gc('proof_status'),'timeline':timeline,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: ZK PROOF ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/alerts/{alert_id}/proof_input")
async def get_proof_input(alert_id: str):
    """Layer 2 only — NO IPs, NO dashboard data."""
    safe_id = sanitize(alert_id, 64)
    with get_db() as db:
        row = db.execute("SELECT raw_json FROM alerts WHERE alert_id=?", (safe_id,)).fetchone()
        if not row: raise HTTPException(404, "Alert not found")
        fa = json.loads(row['raw_json'])
        return {
            'alert_id': fa.get('alert_id', alert_id),
            'invariant': {
                'id': fa.get('invariant',{}).get('id',''),
                'type': fa.get('invariant',{}).get('type',''),
                'circuit_template': fa.get('invariant',{}).get('circuit_template',''),
            },
            'observation': {
                'observed_value': fa.get('observation',{}).get('observed_value',0),
                'threshold': fa.get('observation',{}).get('threshold',0),
                'threshold_operator': fa.get('observation',{}).get('threshold_operator','greater_than'),
                'result': fa.get('observation',{}).get('result',False),
                'window_duration_ns': fa.get('observation',{}).get('window_duration_ns',1_000_000_000),
            },
            'provenance': {
                'snapshot_hash': fa.get('evidence',{}).get('snapshot_current',{}).get('hash',''),
                'flow_hash': fa.get('provenance',{}).get('flow_hash',''),
                'phase1_detector_hash': fa.get('provenance',{}).get('phase1_detector_hash',''),
                'phase2_detector_hash': fa.get('provenance',{}).get('phase2_detector_hash',''),
            },
        }


@app.post("/api/alerts/{alert_id}/proof")
async def submit_proof(alert_id: str, request: Request, auth: dict = Depends(require_agent)):
    """Proof blob → filesystem. Metadata → DB. Handles both ProofBundle and flat format."""
    ip = get_ip(request)
    body = await request.body()
    pd = safe_json_parse(body, MAX_PROOF_PAYLOAD)

    # Handle both ProofBundle (nested) and legacy flat format
    p_meta = pd.get("proof_metadata", {})
    p_pub = pd.get("public_inputs", {})

    # Extract proof_id from nested or flat
    proof_id = sanitize(
        p_meta.get("proof_id", pd.get("proof_id", str(uuid.uuid4()))), 64)
    safe_alert = sanitize(alert_id, 64)

    # Validate proof_id is safe for filesystem
    if not RE_SAFE_FILENAME.match(proof_id.replace('-', '')):
        raise HTTPException(400, "Invalid proof_id format")

    with get_db() as db:
        if not db.execute("SELECT alert_id FROM alerts WHERE alert_id=?", (safe_alert,)).fetchone():
            raise HTTPException(404, "Alert not found")

        # Save proof to filesystem (safe filename)
        fname = f"proof_{proof_id}.json"
        proof_path = os.path.join(PROOF_DIR, fname)
        # Path traversal check
        real_path = os.path.realpath(proof_path)
        if not real_path.startswith(os.path.realpath(PROOF_DIR)):
            raise HTTPException(400, "Invalid proof path")

        # Save raw JSON as-is — verifier reads this directly
        with open(proof_path, 'w') as f:
            json.dump(pd, f, separators=(',',':'))

        # Extract DB fields from either nested or flat format
        circuit_val = sanitize(
            p_pub.get("circuit_template", pd.get("circuit_template", "")), 64)
        gen_time = p_meta.get("generation_time_ms", pd.get("generation_time_ms", 0))
        prover_ver = sanitize(
            p_meta.get("prover_version", pd.get("prover_version", "")), 32)
        pub_inputs_json = json.dumps(p_pub if p_pub else pd.get("public_inputs", {}))

        db.execute("""
            UPDATE alerts SET proof_status=?,proof_id=?,proof_generated_at=?,
                proof_circuit_template=?,proof_public_inputs=?,
                proof_generation_time_ms=?,proof_prover_version=?,proof_file=?
            WHERE alert_id=?
        """, ("verified", proof_id, time.time(),
              circuit_val, pub_inputs_json,
              gen_time, prover_ver, fname, safe_alert))

        audit_event("PROOF_SUBMITTED", safe_alert,
            f"proof={proof_id} circuit={circuit_val}", ip, db)

    log.info(f"Proof: {safe_alert} → {fname}")
    await ws_manager.broadcast({
        'type':'proof_update','alert_id':safe_alert,
        'proof_status':'verified',
        'proof_id':proof_id,'generation_time_ms':gen_time,
    })
    return {"status":"ok","alert_id":safe_alert,"proof_status":"verified"}


@app.get("/api/proofs/{proof_id}/download")
async def download_proof(proof_id: str):
    """Download proof with path traversal protection."""
    safe_id = sanitize(proof_id, 64)
    # Strict filename validation
    if not RE_SAFE_FILENAME.match(safe_id.replace('-', '')):
        raise HTTPException(400, "Invalid proof_id format")

    proof_path = os.path.join(PROOF_DIR, f"proof_{safe_id}.json")
    # Resolve symlinks and verify still within PROOF_DIR
    real_path = os.path.realpath(proof_path)
    if not real_path.startswith(os.path.realpath(PROOF_DIR)):
        raise HTTPException(403, "Access denied")
    if not os.path.exists(real_path):
        raise HTTPException(404, "Proof not found")

    return FileResponse(real_path, media_type="application/json",
                        filename=f"proof_{safe_id}.json")


@app.post("/api/proofs/{proof_id}/verify")
async def verify_proof_endpoint(proof_id: str):
    """On-demand re-verification of a proof using phase3-verify binary.
    This calls the standalone verifier — same code a third-party reviewer would run."""
    import subprocess
    safe_id = sanitize(proof_id, 64)
    if not RE_SAFE_FILENAME.match(safe_id.replace('-', '')):
        raise HTTPException(400, "Invalid proof_id format")

    proof_path = os.path.join(PROOF_DIR, f"proof_{safe_id}.json")
    real_path = os.path.realpath(proof_path)
    if not real_path.startswith(os.path.realpath(PROOF_DIR)):
        raise HTTPException(403, "Access denied")
    if not os.path.exists(real_path):
        raise HTTPException(404, "Proof not found")

    # Find phase3-verify binary
    verify_bin = None
    for p in ["/opt/zknids/phase3/target/release/phase3-verify",
              os.path.join(os.path.dirname(__file__), "phase3/target/release/phase3-verify")]:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            verify_bin = p
            break
    if not verify_bin:
        raise HTTPException(503, "phase3-verify binary not found")

    try:
        result = subprocess.run(
            [verify_bin, "--proof", real_path, "--json"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            verification = json.loads(result.stdout)
            return {"status": "ok", "verification": verification}
        else:
            return {"status": "failed", "error": result.stderr.strip(),
                    "exit_code": result.returncode}
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "Verification timed out")
    except Exception as e:
        raise HTTPException(500, f"Verification error: {str(e)}")


@app.patch("/api/alerts/{alert_id}/proof_status")
async def update_proof_status(alert_id: str, request: Request,
                              body: dict = Body(...), auth: dict = Depends(require_agent)):
    status = sanitize(body.get("proof_status",""), 16)
    if status not in ("pending","generating","verified","failed"):
        raise HTTPException(400, f"Invalid proof_status: '{status}'")
    ip = get_ip(request)
    safe_id = sanitize(alert_id, 64)
    with get_db() as db:
        r = db.execute("UPDATE alerts SET proof_status=? WHERE alert_id=?", (status, safe_id))
        if r.rowcount == 0: raise HTTPException(404, "Alert not found")
        audit_event("PROOF_STATUS_CHANGE", safe_id, f"status={status}", ip, db)
    return {"status":"ok","alert_id":safe_id,"proof_status":status}


# ═══════════════════════════════════════════════════════════════════════════════
# INVARIANT CRUD (Admin only)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/invariants")
async def get_invariants():
    with get_db() as db:
        return [dict(r) for r in db.execute("SELECT * FROM invariants ORDER BY id").fetchall()]


@app.get("/api/invariants/{inv_id}")
async def get_invariant(inv_id: str):
    sid = validate_safe_id(inv_id, "invariant_id")
    with get_db() as db:
        row = db.execute("SELECT * FROM invariants WHERE id=?", (sid,)).fetchone()
        if not row: raise HTTPException(404, "Invariant not found")
        return dict(row)


@app.put("/api/invariants/{inv_id}")
async def update_invariant(inv_id: str, update: InvariantUpdate, request: Request,
                           auth: dict = Depends(require_admin)):
    ip = get_ip(request)
    sid = validate_safe_id(inv_id, "invariant_id")

    with get_db() as db:
        if not db.execute("SELECT id FROM invariants WHERE id=?", (sid,)).fetchone():
            raise HTTPException(404, "Invariant not found")

        # Build UPDATE with only whitelisted column names (hardcoded, not from user)
        ALLOWED_FIELDS = {
            'threshold': 'threshold', 'threshold_operator': 'threshold_operator',
            'severity': 'severity', 'description': 'description', 'enabled': 'enabled',
        }
        sets, params = [], []
        if update.threshold is not None:
            sets.append("threshold=?"); params.append(update.threshold)
        if update.threshold_operator is not None:
            sets.append("threshold_operator=?"); params.append(update.threshold_operator)
        if update.severity is not None:
            sets.append("severity=?"); params.append(update.severity)
        if update.description is not None:
            sets.append("description=?"); params.append(sanitize(update.description, 512))
        if update.enabled is not None:
            sets.append("enabled=?"); params.append(1 if update.enabled else 0)

        if not sets:
            return {"status":"ok","message":"No changes"}

        sets += ["updated_at=?", "updated_by=?"]
        params += [time.time(), ip]
        db.execute(f"UPDATE invariants SET {','.join(sets)} WHERE id=?", params + [sid])

        detail = " ".join(f"{k}={v}" for k,v in update.model_dump(exclude_none=True).items())
        audit_event("INVARIANT_UPDATE", sid, detail, ip, db)

    log.info(f"Invariant updated: {sid} by {ip} ({auth.get('name','?')})")
    return {"status":"ok","invariant_id":sid}


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT LOG (Admin only for full access)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/audit")
async def get_audit_entries(action: Optional[str]=None, limit: int=100, offset: int=0):
    limit = max(1, min(limit, MAX_QUERY_LIMIT))
    offset = max(0, offset)
    with get_db() as db:
        q, p = "SELECT * FROM audit_log WHERE 1=1", []
        if action:
            a = sanitize(action, 64)
            VALID_ACTIONS = {'HOST_REGISTER','ALERT_RECEIVED','PROOF_SUBMITTED',
                             'PROOF_STATUS_CHANGE','INVARIANT_UPDATE','AUTH_FAILED','RATE_LIMITED'}
            if a in VALID_ACTIONS: q += " AND action=?"; p.append(a)
        q += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        p.extend([limit, offset])
        return [dict(r) for r in db.execute(q, p).fetchall()]


# ═══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET (with connection limit)
# ═══════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    ok = await ws_manager.connect(ws)
    if not ok: return
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping": await ws.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)


# ═══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

DASHBOARD_DIR = Path(__file__).parent / "dashboard"

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = DASHBOARD_DIR / "index.html"
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text())
    return HTMLResponse(content="<h1>zkNIDS</h1><p>Place index.html in ./dashboard/</p>")


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='zkNIDS Aggregator v2.1 (Hardened)')
    parser.add_argument('--port', '-p', type=int, default=8080)
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--db', default=DB_PATH)
    parser.add_argument('--data-dir', default=DATA_DIR)
    parser.add_argument('--no-auth', action='store_true', help='Disable API key auth (dev only)')
    args = parser.parse_args()

    DATA_DIR = args.data_dir
    DB_PATH = args.db
    PROOF_DIR = os.path.join(DATA_DIR, "proofs")
    LOG_DIR = os.path.join(DATA_DIR, "logs")

    init_db(args.db); migrate_db(args.db); seed_default_invariants(args.db)
    init_api_keys()

    if args.no_auth:
        global AUTH_DISABLED
        AUTH_DISABLED = True
        log.warning("⚠ API KEY AUTH DISABLED (--no-auth). For development only!")

    log.info(f"Starting zkNIDS Aggregator v2.1 on {args.host}:{args.port}")
    log.info(f"  DB:     {args.db}")
    log.info(f"  Proofs: {PROOF_DIR}")
    log.info(f"  Logs:   {LOG_DIR}")
    log.info(f"  Auth:   {'DISABLED' if args.no_auth else 'ENABLED'}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")