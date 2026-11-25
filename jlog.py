# Общий журнал white_hat: одна функция записи с блокировкой (нет гонок между хуками), цепочка SHA-256.
import os, re, hashlib, datetime, fcntl
HERE = os.path.dirname(os.path.abspath(__file__))
JOURNAL = os.environ.get("WH_JOURNAL", os.path.join(HERE, "journal.tsv"))
ZERO = "0" * 64

def append(what, text, digest):
    t = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    flat = re.sub(r"[\t\r\n]+", " ", text)[:400]
    with open(JOURNAL, "a+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        ls = [l for l in f.read().splitlines() if l.strip()]
        prev = ls[-1].split("\t")[-1] if ls else ZERO
        body = "\t".join([t, what, flat, digest, prev])
        h = hashlib.sha256(body.encode()).hexdigest()
        f.write(body + "\t" + h + "\n")
        f.flush(); os.fsync(f.fileno())
    return h
