#!/usr/bin/env python3
# Сверка выгрузки version.sh с базой уязвимостей OSV (api.osv.dev) + журнал с цепочкой хэшей.
#   python3 check.py <выгрузка.txt>      -> отчёт report_<host>.md, файлы в журнале
#   python3 check.py add <файл> "<что>"  -> добавить любой файл (лог сессии) в журнал
#   python3 check.py verify              -> проверить цепочку журнала и файлы
import sys, os, re, json, hashlib, datetime, urllib.request, urllib.parse, collections
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import jlog
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
JOURNAL = os.environ.get("WH_JOURNAL", os.path.join(HERE, "journal.tsv"))
OSV = "https://api.osv.dev/v1"
ZERO = "0" * 64


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def last_hash():
    if not os.path.exists(JOURNAL):
        return ZERO
    lines = [l for l in open(JOURNAL, encoding="utf-8").read().splitlines() if l.strip()]
    return lines[-1].split("\t")[-1] if lines else ZERO


def add(path, what):
    rel = os.path.relpath(os.path.realpath(path), HERE)
    h = jlog.append(what, rel, sha(path))
    print("журнал:", what, rel, "->", h[:16])
    return h


def verify():
    if not os.path.exists(JOURNAL):
        print("журнал пуст: записей ещё нет"); return 0
    prev, n, bad = ZERO, 0, 0
    for i, l in enumerate(open(JOURNAL, encoding="utf-8").read().splitlines(), 1):
        if not l.strip():
            continue
        p = l.split("\t")
        if len(p) != 6:
            print("БИТАЯ СТРОКА журнала:", i); return 1
        if p[4] != prev or hashlib.sha256("\t".join(p[:5]).encode()).hexdigest() != p[5]:
            print("ЦЕПОЧКА НАРУШЕНА: строка", i)
            return 1
        filerec = not p[1].startswith(("инструмент", "команда", "человек", "капсула", "клятва", "откат"))
        if filerec:
            f = os.path.join(HERE, p[2])
            if not os.path.exists(f):
                print("ФАЙЛ ПРОПАЛ:", p[2]); bad += 1
            elif sha(f) != p[3]:
                print("ФАЙЛ ИЗМЕНЁН после записи:", p[2]); bad += 1
        prev, n = p[5], n + 1
    print("журнал: записей", n, "| цепочка цела" if not bad else "| изменённых файлов: %d" % bad, "| итоговый хэш", prev)
    return 1 if bad else 0


def post(path, data):
    r = urllib.request.Request(OSV + path, data=json.dumps(data).encode(), headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(r, timeout=90).read())


def get(path):
    return json.loads(urllib.request.urlopen(OSV + path, timeout=30).read())


def parse(path):
    sec, cur = collections.defaultdict(list), None
    for line in open(path, encoding="utf-8", errors="replace").read().splitlines():
        m = re.match(r"^== (\w+)", line)
        if m:
            cur = m.group(1); continue
        if cur:
            sec[cur].append(line.rstrip("\r"))
    return sec


def ecosystem(sec):
    osr = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', "\n".join(sec["host"]), re.M))
    i, v, full = osr.get("ID", "").lower(), osr.get("VERSION_ID", ""), osr.get("VERSION", "")
    name = osr.get("PRETTY_NAME", i + " " + v)
    if i == "debian":
        return "Debian:" + v.split(".")[0], name
    if i == "ubuntu":
        return ("Ubuntu:%s:LTS" % v if "LTS" in full else "Ubuntu:" + v), name
    if i == "almalinux":
        return "AlmaLinux:" + v.split(".")[0], name
    if i == "rocky":
        return "Rocky Linux:" + v.split(".")[0], name
    return None, name


def packages(sec, rpm):
    seen = {}
    for l in sec["packages"]:
        p = l.split()
        if len(p) < 2:
            continue
        n, v = p[0], p[1]
        if not rpm and len(p) > 2 and p[2]:
            n = p[2].split("(")[0]          # Debian/Ubuntu: OSV ведёт исходные пакеты
        seen.setdefault((n, v), []).append(p[0])
    return seen


def query(eco, keys):
    found = {}
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        r = post("/querybatch", {"queries": [{"package": {"name": n, "ecosystem": eco}, "version": v} for n, v in chunk]})
        for (n, v), res in zip(chunk, r.get("results", [])):
            ids = [x["id"] for x in res.get("vulns", [])]
            tok = res.get("next_page_token")
            while tok:
                more = post("/query", {"package": {"name": n, "ecosystem": eco}, "version": v, "page_token": tok})
                ids += [x["id"] for x in more.get("vulns", [])]
                tok = more.get("next_page_token")
            if ids:
                found[(n, v)] = ids
    return found


def detail(vid):
    try:
        return get("/vulns/" + urllib.parse.quote(vid))
    except Exception as e:
        return {"id": vid, "error": str(e)[:80]}


def vkey(v):
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", v)]


def fixed_in(d, n, eco):
    exact, loose = [], []
    for a in d.get("affected", []):
        pk = a.get("package", {})
        e = pk.get("ecosystem", "")
        if pk.get("name") != n or e.split(":")[0] != eco.split(":")[0]:
            continue
        fx = [ev["fixed"] for r in a.get("ranges", []) for ev in r.get("events", []) if "fixed" in ev]
        (exact if e == eco else loose if e == eco.split(":")[0] else []).extend(fx)
    out = exact or loose
    return max(out, key=vkey) if out else None


def label(d):
    for s in d.get("severity", []) or []:
        if s.get("type") == "Ubuntu":
            return s.get("score", "")
    ds = (d.get("database_specific") or {}).get("severity")
    if ds:
        return str(ds).lower()
    return "бюллетень" if re.match(r"^(DSA|DLA|USN|ALSA|RLSA)-", d.get("id", "")) else ""


def cves(d):
    al = [a for a in [d.get("id", "")] + d.get("aliases", []) + d.get("upstream", []) if a.startswith("CVE-")]
    return sorted(set(al))


def hygiene(sec):
    c = {}
    for l in sec.get("config", []):
        k, _, v = l.partition(" ")
        c[k] = v.strip()
    if not c:
        return []
    out = []
    def flag(level, text):
        out.append((level, text))
    r = c.get("sshd_PermitRootLogin", "default").lower()
    if r == "yes":
        flag("ВЫСОКИЙ", "SSH: вход root разрешён (PermitRootLogin yes) — поставить no или prohibit-password")
    pa = c.get("sshd_PasswordAuthentication", "default").lower()
    if pa in ("yes", "default"):
        flag("СРЕДНИЙ", "SSH: вход по паролю включён (%s) — перейти на ключи, PasswordAuthentication no" % pa)
    if c.get("sshd_X11Forwarding", "").lower() == "yes":
        flag("НИЗКИЙ", "SSH: X11Forwarding yes — на сервере не нужен")
    if c.get("reboot_required") == "yes":
        flag("ВЫСОКИЙ", "обновления установлены, но сервер НЕ перезагружен — работает старое ядро/библиотеки")
    try:
        up = int(c.get("uptime_days", "0"))
        if up > 60:
            flag("СРЕДНИЙ", "без перезагрузки %d дней — обновления ядра не применяются" % up)
    except ValueError:
        pass
    if c.get("auto_updates") == "none":
        flag("СРЕДНИЙ", "автообновлений безопасности нет (unattended-upgrades / dnf-automatic)")
    u0 = c.get("uid0_users", "").split()
    if [x for x in u0 if x != "root"]:
        flag("ВЫСОКИЙ", "кроме root есть учётки с UID 0: " + ", ".join(x for x in u0 if x != "root"))
    lu = c.get("login_users", "").split()
    if lu:
        flag("ИНФО", "учётки с оболочкой входа (%d): %s — проверить, все ли нужны" % (len(lu), ", ".join(lu[:15])))
    risky = {"111": "rpcbind", "2049": "NFS", "3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis", "27017": "MongoDB",
             "9200": "Elasticsearch", "11211": "memcached", "2375": "Docker API без TLS", "5900": "VNC", "3389": "RDP",
             "8080": "веб-админка/прокси", "10250": "kubelet", "23": "telnet", "21": "FTP", "445": "SMB", "139": "NetBIOS"}
    open_all = set()
    for l in sec.get("listening", []):
        m = re.search(r"(0\.0\.0\.0|\[::\]|\*):(\d+)\s", l + " ")
        if m and m.group(2) in risky:
            open_all.add(m.group(2))
    for port in sorted(open_all, key=int):
        flag("СРЕДНИЙ", "порт %s (%s) слушает на ВСЕХ адресах — закрыть или ограничить фаерволом" % (port, risky[port]))
    if c.get("firewall") == "unknown":
        flag("СРЕДНИЙ", "локальный фаервол не найден (ufw/firewalld/nftables)")
    flag("ИНФО", "ядро запущено: %s · фаервол: %s · автообновления: %s" % (c.get("kernel_running", "?"), c.get("firewall", "?"), c.get("auto_updates", "?")))
    return out


def windows(path, sec):
    host = (sec["host"][0].strip() if sec["host"] else "host") or "host"
    sw = [l for l in sec.get("packages_windows", []) if l.strip()]
    hf = [l for l in sec.get("hotfixes", []) if l.strip()]
    rep = os.path.join(HERE, "report_%s.md" % re.sub(r"[^\w.-]", "_", host))
    L = ["# Проверка ПО (Windows) — %s" % host, "", "Метод: только чтение (version.ps1). Сверка OSV для Windows не поддерживается — список ПО и обновлений для ручной сверки.", "",
         "## Система", "", "```"] + sec.get("host", [])[1:] + ["```", "", "## Последние обновления Windows (hotfix)", ""] + ["- " + x for x in hf[:15]] + \
        ["", "## Установленное ПО (%d)" % len(sw), "", "| программа | версия | издатель |", "|---|---|---|"] + ["| " + x.replace(" | ", " | ") + " |" for x in sw]
    open(rep, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print("Windows: программ %d, последних обновлений: %s" % (len(sw), hf[0] if hf else "нет данных"))
    print("отчёт:", rep); add(path, "выгрузка Windows " + host); add(rep, "отчёт Windows " + host)
    return 0


_PRIO = None


def prio_load():
    """CISA KEV (эксплуатируются в атаках) + EPSS (вероятность эксплуатации за 30 дней) — офлайн из tools/cache."""
    global _PRIO
    if _PRIO is not None:
        return _PRIO
    kev, epss, meta = {}, {}, []
    kp = os.path.join(HERE, "tools", "cache", "kev.json")
    ep = os.path.join(HERE, "tools", "cache", "epss.csv.gz")
    if os.path.exists(kp):
        k = json.load(open(kp, encoding="utf-8"))
        kev = {v["cveID"]: v for v in k.get("vulnerabilities", [])}
        meta.append("CISA KEV %s (%d)" % (k.get("catalogVersion", "?"), len(kev)))
    if os.path.exists(ep):
        import gzip
        with gzip.open(ep, "rt") as f:
            first = f.readline()
            for line in f:
                c, _, rest = line.partition(",")
                if c.startswith("CVE-"):
                    epss[c] = float(rest.split(",")[0])
        m = re.search(r"score_date:(\d{4}-\d\d-\d\d)", first)
        meta.append("EPSS %s" % (m.group(1) if m else "?"))
    _PRIO = (kev, epss, " · ".join(meta) or "нет данных (tools/cache/kev.json, epss.csv.gz)")
    return _PRIO


def priorities(rows):
    """rows: [(пакет, установлено, исправлено_в, {CVE})] -> строки отчёта + краткая сводка."""
    kev, epss, meta = prio_load()
    hot, top = [], []
    for pk, ver, fx, cves in rows:
        for c in cves:
            if c in kev:
                v = kev[c]
                hot.append((pk, ver, fx, c, v.get("vulnerabilityName", "")[:70], v.get("knownRansomwareCampaignUse", "") == "Known"))
            if c in epss:
                top.append((epss[c], c, pk, ver, fx))
    top.sort(reverse=True)
    seen, top_u = set(), []
    for t in top:
        if t[1] not in seen:
            seen.add(t[1]); top_u.append(t)
    L = ["", "## Приоритет: что закрыть в первую очередь", "", "Источники: %s. KEV — уязвимости, которые **уже используются в реальных атаках**; EPSS — вероятность атаки в ближайшие 30 дней." % meta, ""]
    if hot:
        L += ["### СРОЧНО — есть в каталоге CISA KEV (%d)" % len(hot), "", "| пакет | установлено | исправлено в | CVE | что это | вымогатели |", "|---|---|---|---|---|---|"]
        L += ["| %s | %s | %s | %s | %s | %s |" % (a, b, c, d, e, "да" if f else "—") for a, b, c, d, e, f in hot]
    else:
        L += ["- В каталоге CISA KEV совпадений нет — уязвимостей, которые сейчас массово используют в атаках, не найдено."]
    if top_u:
        L += ["", "### Наибольший шанс атаки (EPSS, топ-10)", "", "| CVE | EPSS | пакет | установлено | исправлено в |", "|---|---|---|---|---|"]
        L += ["| %s | %.1f%% | %s | %s | %s |" % (c, e * 100, pk, ver, fx) for e, c, pk, ver, fx in top_u[:10]]
    summary = "приоритет: KEV %d · EPSS≥10%%: %d · макс. EPSS %s" % (len(hot), sum(1 for t in top_u if t[0] >= 0.1), ("%.1f%% (%s)" % (top_u[0][0] * 100, top_u[0][1])) if top_u else "—")
    return L, summary, hot, top_u


def to_html(md, title):
    """Markdown отчёта -> один самодостаточный HTML (тёмная тема, цвета уровней)."""
    import html as H
    out, intable, inlist, incode = [], False, False, False
    def inl(t):
        t = H.escape(t)
        t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
        t = re.sub(r"`(.+?)`", r"<code>\1</code>", t)
        t = re.sub(r"\b(CRITICAL|КРИТИЧ\w*|ВЫСОКИЙ|СРОЧНО)\b", r'<span class="c">\1</span>', t)
        t = re.sub(r"\b(HIGH|СРЕДНИЙ)\b", r'<span class="h">\1</span>', t)
        t = re.sub(r"\b(CVE-\d{4}-\d+)\b", r'<a href="https://nvd.nist.gov/vuln/detail/\1">\1</a>', t)
        return t
    for line in md.splitlines():
        if line.startswith("```"):
            out.append("</pre>" if incode else "<pre>"); incode = not incode; continue
        if incode:
            out.append(H.escape(line)); continue
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(re.fullmatch(r"-+", c) for c in cells):
                continue
            if not intable:
                out.append("<table><tr>" + "".join("<th>%s</th>" % inl(c) for c in cells) + "</tr>"); intable = True
            else:
                out.append("<tr>" + "".join("<td>%s</td>" % inl(c) for c in cells) + "</tr>")
            continue
        if intable:
            out.append("</table>"); intable = False
        if line.startswith("- "):
            if not inlist:
                out.append("<ul>"); inlist = True
            out.append("<li>%s</li>" % inl(line[2:])); continue
        if inlist:
            out.append("</ul>"); inlist = False
        m = re.match(r"^(#{1,3}) (.*)", line)
        if m:
            out.append("<h%d>%s</h%d>" % (len(m.group(1)), inl(m.group(2)), len(m.group(1))))
        elif line.strip():
            out.append("<p>%s</p>" % inl(line))
    if intable: out.append("</table>")
    if inlist: out.append("</ul>")
    css = ("body{background:#0f1419;color:#e6e6e6;font:15px/1.5 system-ui,sans-serif;max-width:1150px;margin:24px auto;padding:0 16px}"
           "h1{color:#7ee787;border-bottom:2px solid #30363d;padding-bottom:8px}h2{color:#79c0ff;margin-top:32px}h3{color:#ffa657}"
           "table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}th,td{border:1px solid #30363d;padding:5px 8px;text-align:left;vertical-align:top}"
           "th{background:#161b22}tr:nth-child(even) td{background:#12171d}code,pre{background:#161b22;border-radius:4px;padding:2px 5px}pre{padding:10px;overflow-x:auto}"
           ".c{color:#ff7b72;font-weight:700}.h{color:#ffa657;font-weight:700}a{color:#79c0ff}"
           "footer{margin-top:40px;color:#8b949e;font-size:12px;border-top:1px solid #30363d;padding-top:8px}")
    return ("<!doctype html><html lang=ru><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>%s</title><style>%s</style>"
            "<body>%s<footer>white_hat · проверка только чтением · отчёт для администратора · каждое действие в журнале с цепочкой SHA-256 (wh verify)</footer></body></html>"
            % (H.escape(title), css, "\n".join(out)))


def write_report(rep, L, title):
    md = "\n".join(L) + "\n"
    open(rep, "w", encoding="utf-8").write(md)
    hp = rep[:-3] + ".html"
    open(hp, "w", encoding="utf-8").write(to_html(md, title))
    print("отчёт:", rep, "\nкрасивый отчёт (браузер):", hp)
    return hp


def offline(path, sec, host, osname):
    """Сверка БЕЗ интернета: слепок сервера (os-release + dpkg status из выгрузки) -> trivy на локальной базе."""
    import shutil, subprocess
    tr = shutil.which("trivy") or os.path.join(HERE, "tools", "bin", "trivy")
    root = os.path.join(HERE, "tools", "dl", "rootfs_" + re.sub(r"[^\w.-]", "_", host))
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(os.path.join(root, "etc")); os.makedirs(os.path.join(root, "var", "lib", "dpkg"))
    osl = "\n".join(l for l in sec["host"] if re.match(r"^\w+=", l)) + "\n"
    open(os.path.join(root, "etc", "os-release"), "w").write(osl)
    kv = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', osl, re.M))
    if kv.get("ID", "").lower() == "debian":
        open(os.path.join(root, "etc", "debian_version"), "w").write(kv.get("VERSION_ID", "12") + "\n")
    if kv.get("ID", "").lower() == "ubuntu":
        open(os.path.join(root, "etc", "lsb-release"), "w").write("DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=%s\nDISTRIB_CODENAME=%s\n" % (kv.get("VERSION_ID", ""), kv.get("VERSION_CODENAME", "")))
    n = 0
    with open(os.path.join(root, "var", "lib", "dpkg", "status"), "w") as f:
        for l in sec["packages"]:
            p = l.split()
            if len(p) < 2:
                continue
            src = ("Source: %s\n" % p[2]) if len(p) > 2 and p[2] and p[2] != p[0] else ""
            f.write("Package: %s\nStatus: install ok installed\nArchitecture: amd64\n%sVersion: %s\n\n" % (p[0], src, p[1])); n += 1
    env = dict(os.environ, TRIVY_CACHE_DIR=os.path.join(HERE, "tools", "cache", "trivy"))
    print("офлайн: слепок %d пакетов -> trivy (локальная база, без сети)…" % n, flush=True)
    r = subprocess.run([tr, "rootfs", "--skip-db-update", "--offline-scan", "--scanners", "vuln", "--format", "json", "--quiet", root],
                       capture_output=True, text=True, env=env, timeout=600)
    if r.returncode != 0 or not r.stdout.strip():
        print("trivy не смог:", r.stderr[-300:]); return 4
    d = json.loads(r.stdout)
    rows = {}
    for res in d.get("Results", []) or []:
        for v in res.get("Vulnerabilities") or []:
            key = (v.get("SrcName") or v["PkgName"], v.get("SrcVersion") or v.get("InstalledVersion", ""))
            e = rows.setdefault(key, {"fixed": set(), "sev": collections.Counter(), "cves": set(), "open": 0, "olist": []})
            if v.get("FixedVersion"):
                e["fixed"].add(v["FixedVersion"]); e["sev"][v.get("Severity", "UNKNOWN")] += 1; e["cves"].add(v["VulnerabilityID"])
            else:
                e["open"] += 1
                e["olist"].append((v["VulnerabilityID"], v.get("Severity", "UNKNOWN"), (v.get("Title") or v.get("Description") or "")[:110]))
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    fix = sorted([(k, e) for k, e in rows.items() if e["fixed"]], key=lambda x: [-x[1]["sev"].get(s, 0) for s in order])
    opn = sorted([(k, e["open"]) for k, e in rows.items() if e["open"]], key=lambda x: -x[1])
    tot = collections.Counter()
    for _, e in fix:
        tot.update(e["sev"])
    now = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    rep = os.path.join(HERE, "report_%s.md" % re.sub(r"[^\w.-]", "_", host))
    L = ["# Проверка версий ПО — %s" % host, "",
         "Дата: %s · ОС: %s · база: trivy (локальная, офлайн) · пакетов: %d" % (now, osname, n), "",
         "Метод: только чтение. На сервере снят список пакетов; сверка у себя без сети по локальной базе trivy.", "",
         "## Итог", "",
         "- Пакетов, где обновление закрывает уязвимости: **%d** — CRITICAL %d · HIGH %d · MEDIUM %d · LOW %d" % (len(fix), tot["CRITICAL"], tot["HIGH"], tot["MEDIUM"], tot["LOW"]),
         "- Пакетов с уязвимостями без исправления (следить): %d" % len(opn), "",
         "## Обновить в первую очередь", "", "| пакет | установлено | исправлено в | CRIT | HIGH | MED | LOW | CVE (примеры) |", "|---|---|---|---|---|---|---|---|"]
    for (pk, ver), e in fix:
        L.append("| %s | %s | %s | %d | %d | %d | %d | %s |" % (pk, ver, max(e["fixed"], key=vkey), e["sev"]["CRITICAL"], e["sev"]["HIGH"], e["sev"]["MEDIUM"], e["sev"]["LOW"], ", ".join(sorted(e["cves"])[:4])))
    PL, psum, _, _ = priorities([(pk, ver, max(e["fixed"], key=vkey), e["cves"]) for (pk, ver), e in fix])
    L[L.index("## Итог") + 2:L.index("## Итог") + 2] = ["- **" + psum + "**"]
    L += PL
    olist = sorted([(order.index(sv) if sv in order else 9, cid, sv, k[0], k[1], tt) for k, e in rows.items() for cid, sv, tt in e["olist"]])
    L += ["", "## Без исправления пока — закрывать настройкой и следить (%d)" % len(olist), "",
          "| CVE | уровень | пакет | установлено | суть |", "|---|---|---|---|---|"] + ["| %s | %s | %s | %s | %s |" % (c, sv, pk, ver, tt) for _, c, sv, pk, ver, tt in olist]
    hy = hygiene(sec)
    if hy:
        L += ["", "## Гигиена сервера (настройки, только чтение)", ""] + ["- **%s** — %s" % (lv, tx) for lv, tx in hy]
    print("\nОБНОВИТЬ: %d пакетов · CRITICAL %d · HIGH %d · MEDIUM %d · LOW %d" % (len(fix), tot["CRITICAL"], tot["HIGH"], tot["MEDIUM"], tot["LOW"]))
    for (pk, ver), e in fix[:12]:
        print("  %-20s %-26s -> %-26s C%d H%d M%d" % (pk, ver, max(e["fixed"], key=vkey), e["sev"]["CRITICAL"], e["sev"]["HIGH"], e["sev"]["MEDIUM"]))
    if len(fix) > 12:
        print("  … ещё %d пакетов — полный список в отчёте" % (len(fix) - 12))
    print("БЕЗ ИСПРАВЛЕНИЯ (закрывать настройкой, следить): %d уязвимостей" % len(olist))
    for _, c, sv, pk, ver, tt in olist[:10]:
        print("  %-16s %-8s %-16s %s" % (c, sv, pk, tt[:80]))
    if len(olist) > 10:
        print("  … ещё %d — полный список в отчёте" % (len(olist) - 10))
    for lv, tx in hy:
        print("  [%s] %s" % (lv, tx))
    print("  " + psum)
    write_report(rep, L, "Проверка версий ПО — " + host)
    add(path, "выгрузка версий " + host); add(rep, "отчёт сверки (офлайн, trivy) " + host)
    return 0


def banner_pkg(banner):
    """SSH-баннер -> (ОС, версия ОС, пакет, версия пакета) для Debian/Ubuntu. Пример: OpenSSH_9.2p1 Debian-2+deb12u10."""
    m = re.search(r"OpenSSH_([\w.]+)\s+(Debian|Ubuntu)-(\S+)", banner)
    if not m:
        return None
    up, dist, rev = m.groups()
    ver = "1:%s-%s" % (up, rev)
    if dist == "Debian":
        d = re.search(r"deb(\d+)u", rev)
        rel = d.group(1) if d else {"9.2p1": "12", "8.4p1": "11", "7.9p1": "10", "9.7p1": "13", "10.0p1": "13"}.get(up, "")
        return ("debian", rel, "openssh", ver) if rel else None
    rel = {"8.2p1": "20.04", "8.9p1": "22.04", "9.6p1": "24.04", "7.6p1": "18.04", "9.3p1": "23.04", "9.7p1": "24.10", "9.9p1": "25.04"}.get(up, "")
    return ("ubuntu", rel, "openssh", ver) if rel else None


def outside(host, banner, web):
    """Проверка СНАРУЖИ без входа: версия из SSH-баннера -> офлайн-сверка; веб — раскрытые версии в заголовках."""
    L = ["# Проверка снаружи (без входа) — %s" % host, "", "Дата: %s · только обычные подключения: рукопожатие SSH, по одному запросу HTTP/HTTPS" %
         datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z"), ""]
    findings = []
    if banner:
        L += ["## SSH", "", "Баннер: `%s`" % banner.strip()]
        bp = banner_pkg(banner)
        if bp:
            osid, rel, pk, ver = bp
            L += ["Восстановлено: %s %s, пакет %s %s" % (osid, rel, pk, ver)]
            sec = collections.defaultdict(list)
            sec["host"] = [host, 'ID=%s' % osid, 'VERSION_ID="%s"' % rel, 'PRETTY_NAME="%s %s (по баннеру SSH)"' % (osid, rel)] + (['VERSION="%s LTS"' % rel] if osid == "ubuntu" else [])
            sec["packages"] = ["openssh-server %s openssh" % ver]
            tmp = os.path.join(HERE, "out", "banner_%s.txt" % re.sub(r"[^\w.-]", "_", host))
            open(tmp, "w", encoding="utf-8").write("== host\n" + "\n".join(sec["host"]) + "\n== packages\n" + sec["packages"][0] + "\n")
            print("SSH: %s -> %s %s, openssh %s — сверяю офлайн…" % (banner.strip(), osid, rel, ver), flush=True)
            offline(tmp, sec, host + "_ssh", "%s %s" % (osid, rel))
            L += ["Сверка уязвимостей пакета: см. report_%s_ssh.md" % re.sub(r"[^\w.-]", "_", host)]
            findings.append(("ИНФО", "SSH раскрывает точную версию пакета (%s) — по ней видно, обновлён ли сервер" % ver))
        else:
            findings.append(("ИНФО", "SSH-баннер без ревизии дистрибутива — точную версию пакета снаружи не определить"))
    if web:
        L += ["", "## Веб", "", "```"] + web + ["```"]
        for l in web:
            if re.search(r"\[(Welcome to nginx!|Apache2 (Ubuntu|Debian) Default Page[^\]]*|IIS Windows Server|Test Page for the (Apache|Nginx)[^\]]*)\]", l, re.I):
                findings.append(("СРЕДНИЙ", "стандартная страница веб-сервера (%s) — сервер поставлен и не настроен: убрать или закрыть (%s)" % (re.search(r"\[([^\]]*(Welcome|Default|IIS|Test Page)[^\]]*)\]", l, re.I).group(1), l.split()[0])))
            for m in re.finditer(r"(nginx|Apache|PHP|Microsoft-IIS|OpenSSL|lighttpd|Tomcat|Jetty|Express|WordPress|Bitrix|Drupal|Joomla)[/ ]?([\d.]+\w*)", l, re.I):
                findings.append(("НИЗКИЙ", "веб раскрывает версию: %s %s (%s) — скрыть в заголовках (server_tokens off / ServerTokens Prod / expose_php Off)" % (m.group(1), m.group(2), l.split()[0])))
    L += ["", "## Находки", ""] + ["- **%s** — %s" % f for f in findings]
    rep = os.path.join(HERE, "report_%s_outside.md" % re.sub(r"[^\w.-]", "_", host))
    open(rep, "w", encoding="utf-8").write("\n".join(L) + "\n")
    for f in findings:
        print("  [%s] %s" % f)
    print("отчёт:", rep); add(rep, "отчёт снаружи " + host)
    return 0


def scan(path, force_offline=False):
    sec = parse(path)
    host = (sec["host"][0].strip() if sec["host"] else "host") or "host"
    if sec.get("packages_windows"):
        return windows(path, sec)
    eco, osname = ecosystem(sec)
    if not eco:
        print("ОС не поддерживается сверкой OSV:", osname); return 2
    rpm = eco.split(":")[0] in ("AlmaLinux", "Rocky Linux")
    pk = packages(sec, rpm)
    print("хост:", host, "|", osname, "| экосистема OSV:", eco, "| пакетов:", len(sec["packages"]), "| исходных:", len(pk))
    if force_offline and not rpm:
        return offline(path, sec, host, osname)
    try:
        found = query(eco, list(pk))
    except OSError as e:
        if not rpm:
            print("НЕТ СВЯЗИ с базой OSV (%s) — перехожу на офлайн-сверку" % str(e)[:60])
            return offline(path, sec, host, osname)
        print("НЕТ СВЯЗИ с базой OSV — выгрузка сохранена, сверка позже: wh check %s" % path)
        add(path, "выгрузка версий (не сверена: нет сети) " + host); return 3
    nrec = sum(len(x) for x in found.values())
    print("пакетов с известными уязвимостями:", len(found), "| записей OSV:", nrec, "— загружаю подробности по пакетам…", flush=True)

    failed = []

    def full(key):
        n, v = key
        vs, tok = [], None
        while True:
            q = {"package": {"name": n, "ecosystem": eco}, "version": v}
            if tok:
                q["page_token"] = tok
            for attempt in range(3):
                try:
                    r = post("/query", q); break
                except Exception:
                    r = None
            if r is None:
                failed.append(key); return key, vs
            vs += r.get("vulns", [])
            tok = r.get("next_page_token")
            if not tok:
                return key, vs

    det = {}
    with ThreadPoolExecutor(32) as ex:
        for k, (key, vs) in enumerate(ex.map(full, list(found)), 1):
            det[key] = vs
            if k % 40 == 0:
                print("  …", k, "из", len(found), flush=True)
    det_by_id = {d.get("id"): d for vs in det.values() for d in vs}
    fix_rows, open_rows = [], []
    for (n, v), vids in found.items():
        fx, op, lab, cv = set(), set(), collections.Counter(), set()
        for d in det.get((n, v), []):
            vid = d.get("id")
            f = fixed_in(d, n, eco)
            (fx if f else op).add((vid, f))
            if f and label(d):
                lab[label(d)] += 1
            if f:
                cv.update(cves(d))
        if fx:
            target = max({f for _, f in fx}, key=vkey)
            fix_rows.append((n, v, target, len(fx), dict(lab), sorted(cv), pk[(n, v)]))
        if op:
            open_rows.append((n, v, len(op), pk[(n, v)], [(vid, label(det_by_id.get(vid, {})) or "—", (det_by_id.get(vid, {}).get("summary") or "")[:100]) for vid, _ in sorted(op)]))
    fix_rows.sort(key=lambda r: (-sum(r[4].get(k, 0) for k in ("high", "critical", "бюллетень")), -r[3]))
    open_rows.sort(key=lambda r: -r[2])
    now = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    rep = os.path.join(HERE, "report_%s.md" % re.sub(r"[^\w.-]", "_", host))
    L = ["# Проверка версий ПО — %s" % host, "",
         "Дата: %s · ОС: %s · база: OSV.dev (%s) · пакетов в выгрузке: %d" % (now, osname, eco, len(sec["packages"])), "",
         "Метод: только чтение. На сервере снят список установленных пакетов (version.sh); сервер не сканировался, нагрузки не было. Сверка версий — у себя, по открытой базе уязвимостей.", "",
         "## Итог", "",
         "- Пакетов, где обновление закрывает известные уязвимости: **%d** (уязвимостей: %d)" % (len(fix_rows), sum(r[3] for r in fix_rows)),
         "- Пакетов с уязвимостями без выпущенного исправления (следить): %d" % len(open_rows), "",
         "## Обновить в первую очередь (исправление уже выпущено)", "",
         "| пакет | установлено | исправлено в | уязвимостей | метки | CVE (примеры) |", "|---|---|---|---|---|---|"]
    for n, v, t, c, lab, cv, bins in fix_rows:
        L.append("| %s | %s | %s | %d | %s | %s |" % (n, v, t, c, ", ".join("%s %d" % kv for kv in lab.items()) or "—", ", ".join(cv[:6]) or "—"))
    PL, psum, _, _ = priorities([(n, v, t, set(cv)) for n, v, t, c, lab, cv, bins in fix_rows])
    L[L.index("## Итог") + 2:L.index("## Итог") + 2] = ["- **" + psum + "**"]
    L += PL
    L += ["", "## Без исправления пока (следить за обновлениями)", "", "| пакет | установлено | уязвимостей |", "|---|---|---|"]
    L += ["| %s | %s | %d |" % (n, v, c) for n, v, c, _, _ in open_rows]
    L += ["", "### Номера и суть — полный список", "", "| CVE/ID | метка | пакет | суть |", "|---|---|---|---|"] + ["| %s | %s | %s | %s |" % (i, lb, n, sm) for n, v, c, _, lst in open_rows for i, lb, sm in lst]
    if failed:
        L += ["", "## НЕ ПРОВЕРЕНО: %d пакетов (база OSV не ответила) — повторить сверку" % len(failed), ""] + ["- %s %s" % k for k in failed]
    hy = hygiene(sec)
    if hy:
        L += ["", "## Гигиена сервера (настройки, только чтение)", ""] + ["- **%s** — %s" % (lv, tx) for lv, tx in hy]
    if sec.get("stack"):
        L += ["", "## Версии веб-стека из выгрузки", "", "```"] + sec["stack"] + ["```"]
    print("\nОБНОВИТЬ (есть исправление): %d пакетов" % len(fix_rows))
    for n, v, t, c, lab, cv, bins in fix_rows[:12]:
        print("  %-22s %-28s -> %-28s уязв %-3d %s" % (n, v, t, c, " ".join(cv[:3])))
    if len(fix_rows) > 12:
        print("  … ещё %d пакетов — полный список в отчёте" % (len(fix_rows) - 12))
    print("без исправления: %d пакетов — номера и суть в отчёте" % len(open_rows))
    for n, v, c, _, lst in open_rows[:5]:
        print("  %-20s %s" % (n, ", ".join(i for i, _, _ in lst[:4])))
    if failed:
        print("  ВНИМАНИЕ: не проверено %d пакетов (OSV не ответил) — повтори wh check" % len(failed))
    for lv, tx in hy:
        print("  [%s] %s" % (lv, tx))
    print("  " + psum)
    write_report(rep, L, "Проверка версий ПО — " + host)
    add(path, "выгрузка версий " + host)
    add(rep, "отчёт сверки " + host)
    return 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a:
        print(__doc__ or "check.py <выгрузка.txt> | add <файл> <что> | verify"); sys.exit(2)
    if a[0] == "verify":
        sys.exit(verify())
    if a[0] == "add":
        add(a[1], a[2] if len(a) > 2 else "файл"); sys.exit(0)
    if a[0] == "--outside":
        web = open(a[3], encoding="utf-8").read().splitlines() if len(a) > 3 and os.path.exists(a[3]) else []
        sys.exit(outside(a[1], a[2], web))
    if a[0] == "--offline":
        sys.exit(scan(a[1], force_offline=True))
    sys.exit(scan(a[0]))
