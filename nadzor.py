#!/usr/bin/env python3
# Надзор white_hat (переносная часть): капсула после каждой команды ИИ + автокоммит + откат.
#   хук PostToolUse:  python3 nadzor.py post        (stdin: JSON события Claude Code)
#   python3 nadzor.py log [N]   — последние N капсул (ДЕЛАЛ -> ПОЛУЧИЛ)
#   python3 nadzor.py undo      — откатить последнее изменение файлов (журнал не трогается)
#   python3 nadzor.py verify    — проверить цепочку журнала и файлы
#   python3 nadzor.py task "<чем занимаюсь>" — объявить задачу (клятва): пишется в каждую капсулу
import sys, os, re, json, hashlib, datetime, subprocess
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import jlog

HERE = os.path.dirname(os.path.abspath(__file__))
JOURNAL = os.environ.get("WH_JOURNAL", os.path.join(HERE, "journal.tsv"))
TASK = os.path.join(HERE, "task.txt")


def git(*a):
    return subprocess.run(["git", "-C", HERE, "-c", "core.quotepath=false", "-c", "user.name=white_hat", "-c", "user.email=white_hat@localhost"] + list(a), capture_output=True, text=True)


def last_hash():
    if not os.path.exists(JOURNAL):
        return "0" * 64
    ls = [l for l in open(JOURNAL, encoding="utf-8").read().splitlines() if l.strip()]
    return ls[-1].split("\t")[-1] if ls else "0" * 64


def record(what, text, digest):
    return jlog.append(what, text, digest)


def task():
    return open(TASK, encoding="utf-8").read().strip() if os.path.exists(TASK) else "задача не объявлена"


def post():
    try:
        ev = json.load(sys.stdin)
    except Exception:
        return 0
    tool, inp = ev.get("tool_name", "?"), ev.get("tool_input") or {}
    cmd = inp.get("command") if tool == "Bash" else "%s %s" % (tool, inp.get("file_path") or inp.get("url") or inp.get("pattern") or "")
    r = ev.get("tool_response") or {}
    out = r.get("stdout", "") if isinstance(r, dict) else str(r)
    err = r.get("stderr", "") if isinstance(r, dict) else ""
    changed = [l[3:] for l in git("status", "--porcelain").stdout.splitlines() if l[3:] != "journal.tsv"]
    sha = ""
    if changed:
        git("add", "-A")
        git("commit", "-q", "-m", "ИИ: " + cmd[:200])
        sha = git("rev-parse", "--short", "HEAD").stdout.strip()
    got = "out %d симв · err %d симв · файлы: %s%s" % (len(out), len(err), ", ".join(changed[:6]) or "—",
                                                         (" · коммит " + sha) if sha else "")
    record("капсула [%s]" % task(), "ДЕЛАЛ: %s → ПОЛУЧИЛ: %s" % (cmd[:200], got),
           hashlib.sha256((cmd + out + err).encode()).hexdigest())
    git("add", "journal.tsv")
    git("commit", "-q", "-m", "журнал")
    return 0


def show(n=15):
    if not os.path.exists(JOURNAL):
        print("журнал пуст"); return 0
    for l in open(JOURNAL, encoding="utf-8").read().splitlines()[-n:]:
        p = l.split("\t")
        print("%s  %-34s %s" % (p[0][11:19], p[1][:34], p[2][:150]))
    return 0


def undo():
    log = git("log", "--format=%h %s", "-n", "30").stdout.splitlines()
    tgt = next((l for l in log if not l.split(" ", 1)[1].startswith(("журнал", "откат"))), None)
    if not tgt:
        print("нечего откатывать"); return 1
    h = tgt.split()[0]
    files = [f for f in git("diff-tree", "--no-commit-id", "--name-only", "-r", h).stdout.split() if f not in ("journal.tsv", "task.txt")]
    for f in files:
        if git("cat-file", "-e", "%s~1:%s" % (h, f)).returncode == 0:
            git("checkout", h + "~1", "--", f)
        else:
            git("rm", "-q", "-f", "--", f)
    git("add", "-A")
    git("commit", "-q", "-m", "откат " + h)
    record("откат", "откат изменения %s: %s" % (h, ", ".join(files)), hashlib.sha256(h.encode()).hexdigest())
    git("add", "journal.tsv"); git("commit", "-q", "-m", "журнал")
    print("откатил", tgt, "файлы:", ", ".join(files) or "—")
    return 0


if __name__ == "__main__":
    a = sys.argv[1:] or ["log"]
    if a[0] == "post":
        sys.exit(post())
    if a[0] == "log":
        sys.exit(show(int(a[1]) if len(a) > 1 else 15))
    if a[0] == "human":
        txt = " ".join(a[1:])
        changed = [l[3:] for l in git("status", "--porcelain").stdout.splitlines() if l[3:] != "journal.tsv"]
        sha = ""
        if changed:
            git("add", "-A"); git("commit", "-q", "-m", ("ИИ через пульт: " if os.environ.get("CLAUDECODE") else "человек: ") + txt[:200])
            sha = git("rev-parse", "--short", "HEAD").stdout.strip()
        who = "ИИ через пульт" if os.environ.get("CLAUDECODE") else "человек"
        record("%s [%s]" % (who, task()), txt + ((" → файлы: %s · коммит %s" % (", ".join(changed[:6]), sha)) if sha else ""),
               hashlib.sha256(txt.encode()).hexdigest())
        git("add", "journal.tsv"); git("commit", "-q", "-m", "журнал"); sys.exit(0)
    if a[0] == "add":
        sys.path.insert(0, HERE); import check
        check.add(a[1], a[2] if len(a) > 2 else "файл"); git("add", "-A"); git("commit", "-q", "-m", "журнал: " + a[1]); sys.exit(0)
    if a[0] == "undo":
        sys.exit(undo())
    if a[0] == "task":
        open(TASK, "w", encoding="utf-8").write(" ".join(a[1:]).strip() + "\n")
        record("клятва", "я занимаюсь: " + " ".join(a[1:]), hashlib.sha256(" ".join(a[1:]).encode()).hexdigest())
        print("задача:", " ".join(a[1:])); sys.exit(0)
    if a[0] == "verify":
        sys.path.insert(0, HERE)
        import check
        sys.exit(check.verify())
    print(__doc__ if __doc__ else "nadzor.py post|log|undo|verify|task")
