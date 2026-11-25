#!/usr/bin/env python3
# Скачать официальные релизы инструментов с GitHub, сверить SHA-256 по файлу сумм проекта, распаковать в tools/bin.
import json, os, re, sys, hashlib, tarfile, zipfile, urllib.request, shutil, stat
from concurrent.futures import ThreadPoolExecutor
HERE = os.path.dirname(os.path.abspath(__file__)); BIN = os.path.join(HERE, "bin"); DL = os.path.join(HERE, "dl")
R = {
 "osv-scanner": ("google/osv-scanner", r"^osv-scanner_linux_amd64$"),
 "trivy": ("aquasecurity/trivy", r"^trivy_[\d.]+_Linux-64bit\.tar\.gz$"),
 "grype": ("anchore/grype", r"^grype_[\d.]+_linux_amd64\.tar\.gz$"),
 "syft": ("anchore/syft", r"^syft_[\d.]+_linux_amd64\.tar\.gz$"),
 "nuclei": ("projectdiscovery/nuclei", r"^nuclei_[\d.]+_linux_amd64\.zip$"),
 "httpx": ("projectdiscovery/httpx", r"^httpx_[\d.]+_linux_amd64\.zip$"),
 "subfinder": ("projectdiscovery/subfinder", r"^subfinder_[\d.]+_linux_amd64\.zip$"),
 "gitleaks": ("gitleaks/gitleaks", r"^gitleaks_[\d.]+_linux_x64\.tar\.gz$"),
 "gh": ("cli/cli", r"^gh_[\d.]+_linux_amd64\.tar\.gz$"),
}
UA = {"User-Agent": "white-hat-fetch/1.0", "Accept": "application/vnd.github+json"}
def get(u, raw=False):
    b = urllib.request.urlopen(urllib.request.Request(u, headers=UA), timeout=180).read()
    return b if raw else json.loads(b)
def one(name):
    repo, pat = R[name]
    try:
        rel = get("https://api.github.com/repos/%s/releases/latest" % repo)
        assets = {a["name"]: a["browser_download_url"] for a in rel["assets"]}
        an = next(n for n in assets if re.match(pat, n))
        d = os.path.join(DL, name); os.makedirs(d, exist_ok=True)
        data = get(assets[an], raw=True); p = os.path.join(d, an); open(p, "wb").write(data)
        h = hashlib.sha256(data).hexdigest(); ok = "сумм нет"
        cs = next((n for n in assets if re.search(r"(checksums|sha256)", n, re.I) and n.endswith((".txt", "sha256")) and "sig" not in n), None)
        if cs:
            txt = get(assets[cs], raw=True).decode(errors="replace")
            ok = "SHA-256 совпала" if any(l.split()[0] == h and an in l for l in txt.splitlines() if l.strip()) else "SHA-256 НЕ СОВПАЛА"
        if "НЕ" in ok:
            return "%-12s %s %s — %s, не ставлю" % (name, rel["tag_name"], an, ok)
        if an.endswith(".zip"):
            zipfile.ZipFile(p).extractall(d)
        elif an.endswith(".tar.gz"):
            tarfile.open(p).extractall(d, filter="data") if sys.version_info >= (3, 12) else tarfile.open(p).extractall(d)
        src = p if not an.endswith((".zip", ".tar.gz")) else (os.path.join(d, name) if os.path.exists(os.path.join(d, name)) else os.path.join(d, an[:-7], "bin", name))
        dst = os.path.join(BIN, name); shutil.copy(src, dst); os.chmod(dst, os.stat(dst).st_mode | stat.S_IXUSR)
        return "%-12s %-10s %s (%d МБ) — %s" % (name, rel["tag_name"], an, len(data) >> 20, ok)
    except Exception as e:
        return "%-12s ОШИБКА %s" % (name, str(e)[:120])
with ThreadPoolExecutor(8) as ex:
    for line in ex.map(one, sys.argv[1:] or list(R)):
        print(line, flush=True)
