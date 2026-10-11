#!/usr/bin/env python3
# LEGION log witness, minimal: Python 3 stdlib + the `openssl` CLI (>= 1.1.1). No pip install. Run from cron.
# Once: openssl genpkey -algorithm ed25519 -out witness.pem    Then: python3 witness_min.py <your-name>   (e.g. hourly)
# It fetches the signed checkpoint, checks LEGION's signature (pinned key below), checks that it extends the last one you
# cosigned (RFC 9162 consistency proof), then writes public/checkpoint.txt = the note + YOUR cosignature. Publish that file
# at a URL you control. Exit 2 = inconsistency (nothing signed). Apache-2.0.
import base64, hashlib, json, os, struct, subprocess, sys, tempfile, time, urllib.request
LOG_VKEY = os.environ.get("LEGION_LOG_VKEY", "legion-mcp-tlog+cfc0988f+AfE4wYMFGnFlhk/ON4Qnf98XNiOTUJNJY3y08DAv9hxk")   # LEGION log key (pinned; also at /tlog/v1/witnesses)
BASE, NAME, H = os.environ.get("LEGION_BASE", "https://tlog.legion-api.com/tlog/v1"), sys.argv[1], lambda b: hashlib.sha256(b).digest()
get = lambda p: urllib.request.urlopen(urllib.request.Request(BASE + p, headers={"User-Agent": "legion-witness-min/1.0"}), timeout=30).read()
def ossl(args, data):  # openssl pkeyutl -rawin on a temp file (Ed25519 signs the message itself)
    with tempfile.NamedTemporaryFile() as f:
        f.write(data); f.flush(); return subprocess.run(["openssl", "pkeyutl", "-rawin", "-in", f.name] + args, capture_output=True)
def kid(name, kind, pub): return H(name.encode() + b"\n" + bytes([kind]) + pub)[:4]
lname, lkid, lkey = LOG_VKEY.split("+", 2); lpub = base64.b64decode(lkey)[1:]
note = get("/checkpoint").decode(); body = note.split("\n\n", 1)[0] + "\n"
origin, size, root = body.split("\n")[0], int(body.split("\n")[1]), base64.b64decode(body.split("\n")[2])
sig = next(base64.b64decode(l.rsplit(" ", 1)[1]) for l in note.split("\n\n", 1)[1].splitlines() if l.startswith("— " + lname + " "))
spki = "MCowBQYDK2VwAyEA"  # DER prefix of an Ed25519 public key, base64
with tempfile.NamedTemporaryFile(suffix=".pem", mode="w") as k, tempfile.NamedTemporaryFile() as s:
    k.write("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" % base64.b64encode(base64.b64decode(spki) + lpub).decode()); k.flush()
    s.write(sig[4:]); s.flush()
    if sig[:4] != kid(lname, 1, lpub) or ossl(["-verify", "-pubin", "-inkey", k.name, "-sigfile", s.name], body.encode()).returncode:
        sys.exit("REFUSED: checkpoint not signed by the pinned LEGION key")
st = json.load(open("state.json")) if os.path.exists("state.json") else None
if st:
    m, old = st["size"], bytes.fromhex(st["root"])
    if size < m or (size == m and root != old):
        print("INCONSISTENT: rollback or fork", file=sys.stderr); sys.exit(2)
    if size > m:
        p = [bytes.fromhex(x) for x in json.loads(get("/proof/consistency?old_size=%d&new_size=%d" % (m, size)))["proof"]]
        p = ([old] + p) if m & (m - 1) == 0 else p
        fn, sn, fr, sr = m - 1, size - 1, p[0], p[0]
        while fn & 1: fn >>= 1; sn >>= 1
        for c in p[1:]:
            if sn == 0: sys.exit(2)
            if fn & 1 or fn == sn:
                fr, sr = H(b"\x01" + c + fr), H(b"\x01" + c + sr)
                while not fn & 1 and fn: fn >>= 1; sn >>= 1
            else: sr = H(b"\x01" + sr + c)
            fn >>= 1; sn >>= 1
        if not (sn == 0 and fr == old and sr == root):
            print("INCONSISTENT: bad consistency proof", file=sys.stderr); sys.exit(2)
ts = int(time.time())
cs = ossl(["-sign", "-inkey", "witness.pem"], ("cosignature/v1\ntime %d\n" % ts).encode() + body.encode()).stdout
wpub = subprocess.run(["openssl", "pkey", "-in", "witness.pem", "-pubout", "-outform", "DER"], capture_output=True).stdout[-32:]
os.makedirs("public", exist_ok=True)
open("public/checkpoint.txt", "w").write(note.rstrip("\n") + "\n— %s %s\n" % (NAME, base64.b64encode(kid(NAME, 4, wpub) + struct.pack(">Q", ts) + cs).decode()))
json.dump({"size": size, "root": root.hex()}, open("state.json", "w"))
print("cosigned %d; your vkey: %s+%s+%s" % (size, NAME, kid(NAME, 4, wpub).hex(), base64.b64encode(b"\x04" + wpub).decode()))
