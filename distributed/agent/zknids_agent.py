#!/usr/bin/env python3
"""
zkNIDS Agent — Heartbeat + Alert Forwarder v2.2
=================================================

Runs on each monitored host alongside Phase 1 (eBPF) and Phase 2 (detector).
Sends periodic heartbeats and forwards alerts to the aggregator.

Changes v2.2:
  - Fixed: host_id auto-generation uses IP as differentiator (not MAC)
  - Fixed: detect_version handles directories vs files properly
  - Fixed: host identity injected into every alert for proper dashboard display
  - Fixed: interface auto-detected (prefers second NIC for monitoring)

Usage:
  python3 zknids_agent.py --config /etc/zknids/agent.conf
  python3 zknids_agent.py --aggregator http://10.0.0.50:8080 --api-key <key>
  ZKNIDS_API_KEY=<key> python3 zknids_agent.py
"""

import argparse
import hashlib
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: pip3 install requests")
    raise SystemExit(1)


# ─── Configuration ────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "aggregator_url": "http://10.0.0.50:8080",
    "api_key": "",
    "host_id": "",
    "interface": "",
    "heartbeat_interval": 10,
    "alert_watch_dir": "/var/lib/zknids/alerts",
    "alert_archive_dir": "/var/lib/zknids/alerts/sent",
    "retry_max": 5,
    "retry_base_delay": 1,
    "log_file": "/var/log/zknids-agent.log",
}

AGENT_VERSION = "agent-v2.2.0"
log = logging.getLogger("zknids-agent")


def setup_logging(log_file=None, verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
    log.setLevel(level)
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    log.addHandler(ch)
    if log_file:
        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            fh = logging.FileHandler(log_file)
            fh.setFormatter(fmt)
            log.addHandler(fh)
        except OSError:
            pass


# ─── Host Detection ──────────────────────────────────────────────────────────

def get_primary_ip():
    """Get the primary IP address of this host (not 127.0.0.1).
    Uses a UDP socket trick to find the outbound interface IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("10.0.0.50", 80))  # doesn't actually send data
        ip = s.getsockname()[0]
        s.close()
        if ip and ip != "127.0.0.1":
            return ip
    except Exception:
        pass
    # Fallback: iterate addresses
    try:
        hostname = socket.gethostname()
        addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
        for addr in addrs:
            ip = addr[4][0]
            if ip != "127.0.0.1":
                return ip
    except Exception:
        pass
    return "0.0.0.0"


def generate_host_id():
    """Generate a unique host_id from hostname + primary IP.
    
    FIXED (Issue 2): Uses IP instead of MAC because QEMU VMs get different
    MACs on reboot, but static IPs (10.0.0.10, 10.0.0.20) remain stable.
    """
    hostname = socket.gethostname()
    ip = get_primary_ip()
    if ip and ip != "0.0.0.0":
        return hashlib.sha256(f"{hostname}-{ip}".encode()).hexdigest()[:16]
    # Fallback to MAC-based
    mac = uuid.getnode()
    return hashlib.sha256(f"{hostname}-{mac}".encode()).hexdigest()[:16]


def detect_interface():
    """Auto-detect the best network interface for monitoring.
    
    FIXED (Issue 1): Prefers the second interface (ens4/eth1) since
    ens3/eth0 is typically management. Falls back to first non-loopback.
    """
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True, text=True, timeout=5
        )
        interfaces = []
        for line in result.stdout.strip().split('\n'):
            parts = line.split(': ')
            if len(parts) >= 2:
                name = parts[1].split('@')[0]
                if name not in ('lo',) and not name.startswith(('docker', 'br-', 'veth', 'virbr')):
                    interfaces.append(name)
        
        # Prefer second interface (monitoring NIC) if available
        if len(interfaces) >= 2:
            return interfaces[1]
        elif interfaces:
            return interfaces[0]
    except Exception:
        pass
    return "eth0"


def detect_version(name, paths):
    """Detect version by hashing a binary file.
    
    FIXED (Issue 4): Handles directories properly — looks for known binary
    files inside directories instead of trying to open() a directory.
    """
    # Known binary names to look for inside directories
    sub_paths = [
        "userspace/collector/phase1_loader",   # Phase 1
        "phase1_loader",                       # Phase 1 flat
        "zkNIDS_phase2/__init__.py",           # Phase 2 package
        "__init__.py",                         # Phase 2 flat
        "__main__.py",                         # Phase 2 entry
    ]
    
    for p in paths:
        try:
            target = None
            
            if os.path.isfile(p):
                # Direct file path — hash it
                target = p
            elif os.path.isdir(p):
                # Directory — search for known binaries inside
                for sub in sub_paths:
                    candidate = os.path.join(p, sub)
                    if os.path.isfile(candidate):
                        target = candidate
                        break
            
            if target and os.path.isfile(target):
                h = hashlib.sha256(open(target, 'rb').read()).hexdigest()[:12]
                return f"{name}-{h}"
        except (OSError, PermissionError):
            continue
    return f"{name}-unknown"


def detect_phase1_version():
    return detect_version("phase1", [
        "/opt/zknids/phase1/userspace/collector/phase1_loader",
        "/opt/zknids/phase1",
    ])


def detect_phase2_version():
    return detect_version("phase2", [
        "/opt/zknids/phase2/zkNIDS_phase2/__init__.py",
        "/opt/zknids/phase2",
    ])


# ─── HTTP Client ─────────────────────────────────────────────────────────────

class AggregatorClient:
    def __init__(self, base_url, api_key="", retry_max=5, retry_base_delay=1):
        self.base_url = base_url.rstrip('/')
        self.retry_max = retry_max
        self.retry_base_delay = retry_base_delay
        self.session = requests.Session()
        self.session.headers["Content-Type"] = "application/json"
        if api_key:
            self.session.headers["X-API-Key"] = api_key
        # Store host identity for alert injection
        self._host_id = ""
        self._hostname = ""
        self._host_ip = ""

    def _request(self, method, path, **kwargs):
        url = f"{self.base_url}{path}"
        for attempt in range(self.retry_max):
            try:
                resp = self.session.request(method, url, timeout=10, **kwargs)
                if resp.status_code == 429:
                    wait = int(resp.headers.get("Retry-After", 60))
                    log.warning(f"Rate limited. Waiting {wait}s...")
                    time.sleep(wait)
                    continue
                return resp
            except (requests.ConnectionError, requests.Timeout) as e:
                delay = self.retry_base_delay * (2 ** attempt)
                if attempt < self.retry_max - 1:
                    log.warning(f"Request failed (attempt {attempt+1}). Retry in {delay}s...")
                    time.sleep(delay)
                else:
                    log.error(f"All {self.retry_max} attempts failed: {e}")
        return None

    def send_heartbeat(self, host_id, hostname, host_ip, interface,
                       agent_ver, phase1_ver, phase2_ver):
        # Cache identity for alert injection
        self._host_id = host_id
        self._hostname = hostname
        self._host_ip = host_ip
        payload = {
            "host_id": host_id, "hostname": hostname, "host_ip": host_ip,
            "interface": interface, "timestamp": time.time(),
            "agent_version": agent_ver, "phase1_version": phase1_ver,
            "phase2_version": phase2_ver,
        }
        resp = self._request("POST", "/api/heartbeat", json=payload)
        if resp and resp.status_code == 200:
            return True
        if resp:
            log.warning(f"Heartbeat failed: {resp.status_code}")
        return False

    def send_alert(self, alert_data):
        resp = self._request("POST", "/api/alerts", json=alert_data)
        if resp and resp.status_code == 200:
            return resp.json().get("alert_id")
        if resp:
            log.warning(f"Alert failed: {resp.status_code}")
        return None


# ─── Alert Watcher ────────────────────────────────────────────────────────────

def process_alert_dir(client, watch_dir, archive_dir):
    """Watch for alert JSON files and forward to aggregator.
    
    FIXED: Injects host identity (host_id, hostname, host_ip) into every
    alert's dashboard_fields so the aggregator knows which agent generated it.
    """
    if not os.path.isdir(watch_dir):
        return 0
    sent = 0
    for fname in sorted(os.listdir(watch_dir)):
        if not fname.endswith('.json'):
            continue
        fpath = os.path.join(watch_dir, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath) as f:
                data = json.load(f)
            if 'alert_id' not in data:
                data['alert_id'] = str(uuid.uuid4())
            # Inject agent identity into alert before sending
            if 'dashboard_fields' not in data:
                data['dashboard_fields'] = {}
            data['dashboard_fields']['host_id'] = client._host_id
            data['dashboard_fields']['hostname'] = client._hostname
            data['dashboard_fields']['host_ip'] = client._host_ip
            aid = client.send_alert(data)
            if aid:
                log.info(f"Alert sent: {aid} ({fname})")
                os.makedirs(archive_dir, exist_ok=True)
                os.rename(fpath, os.path.join(archive_dir, fname))
                sent += 1
            else:
                log.warning(f"Failed to send {fname}")
        except json.JSONDecodeError:
            log.error(f"Invalid JSON: {fpath}")
        except Exception as e:
            log.error(f"Error processing {fpath}: {e}")
    return sent


# ─── Config ───────────────────────────────────────────────────────────────────

def load_config(path):
    cfg = dict(DEFAULT_CONFIG)
    if path and os.path.exists(path):
        with open(path) as f:
            cfg.update(json.load(f))
        log.info(f"Config: {path}")
    return cfg


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="zkNIDS Agent v2.2")
    parser.add_argument('--config', '-c', default='/etc/zknids/agent.conf')
    parser.add_argument('--aggregator', '-a')
    parser.add_argument('--api-key', '-k')
    parser.add_argument('--interface', '-i')
    parser.add_argument('--host-id')
    parser.add_argument('--heartbeat-interval', type=int)
    parser.add_argument('--alert-dir')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--once', action='store_true',
                        help='One heartbeat + process alerts, then exit')
    args = parser.parse_args()

    cfg = load_config(args.config)
    # CLI overrides
    for attr, key in [('aggregator','aggregator_url'), ('api_key','api_key'),
                      ('interface','interface'), ('host_id','host_id'),
                      ('heartbeat_interval','heartbeat_interval'),
                      ('alert_dir','alert_watch_dir')]:
        val = getattr(args, attr, None)
        if val is not None:
            cfg[key] = val
    # Env override
    env_key = os.environ.get('ZKNIDS_API_KEY')
    if env_key:
        cfg['api_key'] = env_key

    # Auto-detect host_id if not set
    if not cfg['host_id']:
        cfg['host_id'] = generate_host_id()

    # Auto-detect interface if not set
    if not cfg['interface']:
        cfg['interface'] = detect_interface()

    setup_logging(cfg.get('log_file'), args.verbose)

    hostname = socket.gethostname()
    host_ip = get_primary_ip()
    p1v = detect_phase1_version()
    p2v = detect_phase2_version()

    log.info(f"zkNIDS Agent v2.2 | host={cfg['host_id']} | {hostname} ({host_ip})")
    log.info(f"  Aggregator: {cfg['aggregator_url']} | Auth: {'key' if cfg['api_key'] else 'NONE'}")
    log.info(f"  Phase1: {p1v} | Phase2: {p2v} | Interface: {cfg['interface']}")

    os.makedirs(cfg['alert_watch_dir'], exist_ok=True)
    os.makedirs(cfg['alert_archive_dir'], exist_ok=True)

    client = AggregatorClient(cfg['aggregator_url'], cfg['api_key'],
                              cfg.get('retry_max', 5), cfg.get('retry_base_delay', 1))

    if args.once:
        ok = client.send_heartbeat(cfg['host_id'], hostname, host_ip,
                                   cfg['interface'], AGENT_VERSION, p1v, p2v)
        log.info(f"Heartbeat: {'OK' if ok else 'FAILED'}")
        sent = process_alert_dir(client, cfg['alert_watch_dir'], cfg['alert_archive_dir'])
        log.info(f"Alerts forwarded: {sent}")
        return

    # Graceful shutdown
    running = True
    def stop(signum, frame):
        nonlocal running
        log.info("Shutting down...")
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    last_hb = 0
    hb_int = cfg['heartbeat_interval']
    log.info(f"Main loop started (heartbeat every {hb_int}s)")

    while running:
        now = time.time()
        if now - last_hb >= hb_int:
            client.send_heartbeat(cfg['host_id'], hostname, host_ip,
                                  cfg['interface'], AGENT_VERSION, p1v, p2v)
            last_hb = now
        sent = process_alert_dir(client, cfg['alert_watch_dir'], cfg['alert_archive_dir'])
        if sent:
            log.info(f"Forwarded {sent} alert(s)")
        time.sleep(min(2, hb_int / 2))


if __name__ == '__main__':
    main()