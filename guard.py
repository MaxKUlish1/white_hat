#!/usr/bin/env python3
# Сторож ИИ (хук Claude Code PreToolUse, ВСЕ инструменты). Решает ДО выполнения, пишет в журнал (jlog, цепочка SHA-256).
# Падает ЗАКРЫТЫМ: любая ошибка сторожа = запрет.
import sys, os, re, json, hashlib, ipaddress
HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
import jlog

SCOPE = os.path.join(HERE, "scope.txt")
SERVICES = {"api.osv.dev", "nvd.nist.gov", "github.com", "osv.dev", "security-tracker.debian.org", "ubuntu.com"}
PROTECTED = {"guard.py", "nadzor.py", "check.py", "jlog.py", "wh", "env.sh", "version.sh", "version.ps1", "scope.txt",
             "journal.tsv", "task.txt", ".claude", "keys", ".git", ".gitignore"}
NET = r"\b(ssh|scp|sftp|rsync|curl|wget|nc|ncat|socat|telnet|ping|ftp|psql|mysql|nuclei|httpx|subfinder|testssl\.sh|testssl|ssh-audit|ssh-keyscan|git\s+(push|clone|fetch|pull))\b"
WH_NET = r"^\s*(\./)?wh\s+(versions|winversions|fp|tls|web|sshaudit|outside)\s+(\S+)(\s+[\w.-]+)?\s*$"
FORBID = [
    (r"\bsudo\b|\bsu\b|\bpkexec\b|\bdoas\b", "повышение прав (sudo/su)"),
    (r"\b(systemctl|service)\s+(restart|stop|start|reload|disable|enable|mask)\b", "управление службами"),
    (r"\b(reboot|shutdown|poweroff|halt|init\s+[06])\b", "перезагрузка/выключение"),
    (r"\b(apt|apt-get|yum|dnf|rpm|dpkg|pip3?|npm|gem|cargo|go)\s+(install|remove|purge|-i|-e|upgrade|get)\b", "установка/удаление ПО"),
    (r"\b(nmap|masscan|zmap|nikto|hydra|medusa|sqlmap|hping3|metasploit|msfconsole|ffuf|gobuster|dirb)\b", "сканирование/подбор/атака"),
    (r"\brm\b[^|;&]*\s-[a-zA-Z]*[rR]|\brm\s+--recursive|\bfind\b[^|;&]*-delete|\bshred\b|\bmkfs|\bdd\b[^|;&]*of=", "удаление/затирание"),
    (r"\b(mysqldump|pg_dump|pg_dumpall|mongodump)\b", "выгрузка баз данных"),
    (r"/dev/(tcp|udp)/|\bpython[0-9.]*\s+-c\b|\bperl\s+-e\b|\bruby\s+-e\b|\bnode\s+-e\b|\b(ba|z|da)?sh\s+-c\b|\beval\b|\bbase64\s+(-d|--decode)\b|\bxxd\s+-r\b", "обход сторожа (сокеты/eval/скрытый код)"),
    (r"(^|[\s;&|])(\./)?wh\s+(start|nuclei|key|ssh|shell|undo|publish)\b", "это решает только человек (wh start/nuclei/key/ssh/shell/undo/publish)"),
    (r"keys/(?!wh_ed25519\.pub\b)|wh_ed25519(?!\.pub)|\bkeys/\*|id_(rsa|ed25519|ecdsa)\b|\.ssh/", "ключи — только человеку"),
    (r"\b(curl|wget)\b[^|;&]*\s(-d|--data\S*|-F|--form|-T|--upload-file|-X\s*(POST|PUT|PATCH|DELETE))\b", "отправка данных наружу"),
]
WRITE_OPS = r"(>>?|\btee\b|\bcp\b|\bmv\b|\binstall\b|\bln\b|\bchmod\b|\bchown\b|\btruncate\b|\bsed\s+-i\b|\btouch\b|\bmkdir\b|\brm\b|\bunlink\b)"


def load_scope():
    nets, hosts = [], set()
    if os.path.exists(SCOPE):
        for l in open(SCOPE, encoding="utf-8"):
            l = l.split("#")[0].strip()
            if not l:
                continue
            try:
                n = ipaddress.ip_network(l, strict=False)
                if n.prefixlen >= 24:
                    nets.append(n)
            except ValueError:
                pass
    return nets, hosts


def in_scope(h):
    nets, hosts = load_scope()
    h = h.lower().strip("[]")
    try:
        return any(ipaddress.ip_address(h) in n for n in nets)
    except ValueError:
        return False


def real(p, cwd):
    return os.path.realpath(os.path.join(cwd or HERE, os.path.expanduser(p)))


def inside(ap):
    return ap == HERE or ap.startswith(HERE + os.sep)


def protected(ap):
    if not inside(ap):
        return False
    rel = os.path.relpath(ap, HERE).split(os.sep)[0]
    return rel in PROTECTED


def check_bash(cmd, cwd):
    n = re.sub(r"['\"\\]", "", cmd)
    for c in (cmd, n):
        for pat, why in FORBID:
            if re.search(pat, c):
                return why
    m0 = re.match(WH_NET, n)
    if m0 and not in_scope(m0.group(3)):
        return "адрес вне разрешённой области: " + m0.group(3)
    if re.search(NET, n):
        m = re.match(WH_NET, n)
        if not m:
            return "сеть — только через пульт: wh versions|fp|tls|web|sshaudit <IP из scope.txt>"
        if not in_scope(m.group(3)):
            return "адрес вне разрешённой области: " + m.group(3)
    if re.search(WRITE_OPS, n):
        for p in re.findall(r"(?:^|[\s=>])((?:/|~/|\.\./)[^\s;&|<>()]+)", n):
            ap = real(p, cwd)
            if ap in ("/dev/null",) or ap.startswith("/proc/self/fd"):
                continue
            if not inside(ap):
                return "запись/изменение вне папки проекта: " + ap
            if protected(ap):
                return "защищённый файл надзора: " + os.path.relpath(ap, HERE)
        for name in PROTECTED:
            if re.search(r"(>>?|\btee\b|\bsed\s+-i\b|\bcp\b|\bmv\b|\brm\b|\btruncate\b|\bchmod\b)[^|;&]*(^|[\s/])" + re.escape(name) + r"(\s|$|/)", n):
                return "защищённый файл надзора: " + name
    return None


def decide(ev):
    tool, inp, cwd = ev.get("tool_name", "?"), ev.get("tool_input") or {}, ev.get("cwd") or HERE
    if tool == "Bash":
        text = inp.get("command", "")
        return text, check_bash(text, cwd)
    path = inp.get("file_path") or inp.get("notebook_path") or inp.get("path") or ""
    text = path or inp.get("url") or inp.get("pattern") or inp.get("query") or json.dumps(inp, ensure_ascii=False)[:200]
    if path:
        ap = real(path, cwd)
        if os.path.join(HERE, "keys") in (ap, os.path.dirname(ap)) and not ap.endswith(".pub") or "/.ssh" in ap:
            return text, "ключи — только человеку"
        if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            if not inside(ap):
                return text, "запись вне папки проекта: " + ap
            if protected(ap):
                return text, "защищённый файл надзора: " + os.path.relpath(ap, HERE)
    if inp.get("url"):
        host = re.sub(r"^https?://([^/:]+).*$", r"\1", inp["url"]).lower()
        if host not in SERVICES and not in_scope(host):
            return text, "веб-запрос вне белого списка: " + host
    return text, None


def main():
    ev = json.load(sys.stdin)
    text, reason = decide(ev)
    jlog.append(("инструмент ИИ: %s — " % ev.get("tool_name", "?")) + ("ЗАПРЕЩЕНО (" + reason + ")" if reason else "разрешено"),
                text, hashlib.sha256(text.encode()).hexdigest())
    if reason:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                 "permissionDecisionReason": "Сторож white_hat: " + reason}}, ensure_ascii=False))


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "inscope":
        sys.exit(0 if in_scope(sys.argv[2]) else 1)
    try:
        main()
    except Exception as e:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                 "permissionDecisionReason": "Сторож white_hat: ошибка сторожа, действие запрещено (%s)" % str(e)[:80]}}, ensure_ascii=False))
    sys.exit(0)
