#!/usr/bin/env python3
"""RÉSURRECTION — reconstruit et vérifie le journal MCP LEGION depuis un miroir, sans aucun serveur LEGION.

  python3 resurrect.py MIROIR_URL EMPREINTE_CLE_RACINE --out DOSSIER_VIDE [--bitcoin-node] [--json]

Entrées : UNIQUEMENT l'URL d'un miroir (https://…, http://… ou file://…) et l'empreinte sha256 (64 hex) de la clé racine.
Dépendances : Python 3.8+ et le paquet `cryptography` (Ed25519). Aucune ligne de code LEGION n'est importée.

Contrôles (tout échec = code de sortie 1, rien n'est déclaré « réussi ») :
  1. trousseau : l'entrée 0 a l'empreinte donnée ; chaque sous-clé est chaînée (prev_hash, hash), approuvée par la racine
     et prouve la possession de sa clé ; révocations appliquées ;
  2. checkpoint C2SP signé par une sous-clé « mcp-tlog » du trousseau (signed-note Ed25519) ;
  3. chaque entrée : haché de feuille = tuile de niveau 0 ; JCS(entrée) identique octet pour octet ; leaf_index = position ;
     signature Ed25519 de l'enregistrement valide avec la clé que le trousseau associe à son key_id ;
  4. tuiles de niveau >= 1 recalculées depuis le niveau inférieur ; racine recalculée = racine du checkpoint ;
  5. chaque tête signée de heads.jsonl : signature valide, racine = racine recalculée à sa taille, preuve de cohérence
     RFC 6962 de cette taille vers le checkpoint calculée puis vérifiée ;
  6. ancrages OpenTimestamps : head.canon.json = une tête signée vérifiée, le .ots engage bien sha256(head.canon.json),
     blocs Bitcoin déclarés dans le .ots. Statut « sealed » UNIQUEMENT si `ots verify` réussit avec un nœud Bitcoin
     (--bitcoin-node) ; sinon « pending ».
"""
import argparse
import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request

TILE = 256
LOG_NOTE_NAME = "legion-mcp-tlog"
PURPOSE = "mcp-tlog"
SIG_FIELDS = ("hash", "self_sig", "endorsement_sig")


class Fail(Exception):
    pass


# ---------- JSON canonique RFC 8785 (JCS), sans flottants (le journal n'en contient pas : un flottant = échec explicite)
def jcs(o):
    if o is None:
        return "null"
    if o is True:
        return "true"
    if o is False:
        return "false"
    if isinstance(o, int):
        if abs(o) > 2 ** 53:
            raise Fail("JCS : entier hors de l'intervalle sûr")
        return str(o)
    if isinstance(o, float):
        raise Fail("JCS : flottant non pris en charge par ce vérificateur")
    if isinstance(o, str):
        return json.dumps(o, ensure_ascii=False)
    if isinstance(o, list):
        return "[" + ",".join(jcs(x) for x in o) + "]"
    if isinstance(o, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(o[k])
                              for k in sorted(o, key=lambda k: k.encode("utf-16-be"))) + "}"
    raise Fail("JCS : type %r" % type(o))


def canon(o):
    return jcs(o).encode("utf-8")


# ---------- Merkle RFC 6962 / 9162
def leaf_hash(b):
    return hashlib.sha256(b"\x00" + b).digest()


def node_hash(a, b):
    return hashlib.sha256(b"\x01" + a + b).digest()


def _k(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _k(n)
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def consistency_proof(m, leaves):
    """RFC 6962 §2.1.2 SUBPROOF(m, D[n], true)."""
    def sub(m, d, b):
        n = len(d)
        if m == n:
            return [] if b else [mth(d)]
        k = _k(n)
        if m <= k:
            return sub(m, d[:k], b) + [mth(d[k:])]
        return sub(m - k, d[k:], False) + [mth(d[:k])]
    return sub(m, leaves, True)


def verify_consistency(m, n, old_root, new_root, proof):
    """RFC 9162 §2.1.4.2."""
    if m == n:
        return not proof and old_root == new_root
    if m == 0 or m > n:
        return False
    proof = list(proof)
    if m & (m - 1) == 0:   # m puissance de 2
        proof.insert(0, old_root)
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if not proof:
        return False
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0


# ---------- tuiles C2SP
def tile_path(level, n, width=TILE):
    s = "%d" % n
    s = "0" * ((-len(s)) % 3) + s
    parts = [s[i:i + 3] for i in range(0, len(s), 3)]
    return "%s/%s" % (level, "/".join(["x" + x for x in parts[:-1]] + [parts[-1]])) + (".p/%d" % width if width < TILE else "")


# ---------- Ed25519
def ed_verify(pub_raw, sig, msg):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, msg)
        return True
    except Exception:
        return False


def b64(s):
    return base64.b64decode(s, validate=True)


# ---------- trousseau
def load_keyring(text, root_pin):
    keys, revoked, limits, compromised = {}, set(), {}, set()
    prev, root_pub = None, None
    for n, line in enumerate(l for l in text.splitlines() if l.strip()):
        e = json.loads(line)
        if n == 0:
            if e.get("type") != "key_register" or e.get("alg") != "Ed25519" or \
                    hashlib.sha256(b64(e["public_key_b64"])).hexdigest() != root_pin:
                raise Fail("trousseau : l'entrée 0 n'est pas la clé racine d'empreinte %s" % root_pin)
            root_pub = b64(e["public_key_b64"])
            keys[root_pin] = dict(e, purpose="root")
            prev = e.get("hash") or hashlib.sha256(canon({k: v for k, v in e.items() if k not in SIG_FIELDS})).hexdigest()
            continue
        body = canon({k: v for k, v in e.items() if k not in SIG_FIELDS})
        if e.get("prev_hash") != prev or e.get("hash") != hashlib.sha256(body).hexdigest():
            raise Fail("trousseau : chaîne rompue à l'entrée %d" % n)
        if not ed_verify(root_pub, b64(e.get("endorsement_sig", "")), body):
            raise Fail("trousseau : entrée %d non approuvée par la racine" % n)
        if e["type"] == "key_register":
            pub = b64(e["public_key_b64"])
            pin = hashlib.sha256(pub).hexdigest()
            if e.get("alg") != "Ed25519" or e.get("key_id") != "k1:" + pin[:32]:
                raise Fail("trousseau : key_id incohérent à l'entrée %d" % n)
            if not ed_verify(pub, b64(e.get("self_sig", "")), body):
                raise Fail("trousseau : preuve de possession absente à l'entrée %d" % n)
            keys[pin] = e
        elif e["type"] == "key_revoke":
            revoked.add(e["key_id"])
            if isinstance(e.get("valid_until_tree_size"), int):
                limits[e["key_id"]] = min(e["valid_until_tree_size"], limits.get(e["key_id"], e["valid_until_tree_size"]))
            else:
                limits.pop(e["key_id"], None)
                compromised.add(e["key_id"])
        else:
            raise Fail("trousseau : type inconnu %r" % e["type"])
        prev = e["hash"]
    if root_pub is None:
        raise Fail("trousseau vide")

    def pub_for(pin, purpose, leaf_index=None, tree_size=None):
        e = keys.get(pin)
        if e is None:
            return None
        kid = "k1:" + pin[:32]
        if kid in revoked:
            lim = None if kid in compromised else limits.get(kid)
            if lim is None or not ((leaf_index is not None and leaf_index < lim) or (tree_size is not None and tree_size <= lim)):
                return None
        if e.get("purpose") not in (purpose, "root"):
            return None
        return b64(e["public_key_b64"])
    return keys, pub_for


def note_key_id(name, pub_raw, kind=0x01):
    return hashlib.sha256(name.encode() + b"\n" + bytes([kind]) + pub_raw).digest()[:4]


# ---------- OpenTimestamps (lecture du .ots, sans confiance : seul `ots verify` + nœud scelle)
OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
BTC_TAG = bytes.fromhex("0588960d73d71901")


def ots_info(ots):
    if not ots.startswith(OTS_MAGIC):
        raise Fail(".ots : en-tête invalide")
    p = len(OTS_MAGIC) + 1          # + octet de version
    if ots[p] != 0x08:               # op SHA256
        raise Fail(".ots : le fichier n'engage pas un sha256")
    digest = ots[p + 1:p + 33]
    blocks, i = [], 0
    while True:
        i = ots.find(BTC_TAG, i)
        if i < 0:
            break
        j = i + len(BTC_TAG)
        ln, sh, k = 0, 0, j       # varuint de la longueur de charge utile
        while True:
            b = ots[k]; ln |= (b & 0x7f) << sh; k += 1; sh += 7
            if not b & 0x80:
                break
        h, sh, q = 0, 0, k
        while q < k + ln:
            b = ots[q]; h |= (b & 0x7f) << sh; q += 1; sh += 7
            if not b & 0x80:
                break
        blocks.append(h)
        i = j
    return digest, sorted(set(blocks))


# ---------- récupération
# Redirections (ex. CDN de Hugging Face) : suivies, comptées et rapportées. Aucune confiance accordée à l'hôte final :
# chaque octet reçu est vérifié par les hachés de Merkle, la racine signée et les signatures (contrôles 2 à 6).
REDIRECTS = {"count": 0, "hosts": {}}


class _CountRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        REDIRECTS["count"] += 1
        h = urllib.parse.urlsplit(newurl).hostname or "?"
        REDIRECTS["hosts"][h] = REDIRECTS["hosts"].get(h, 0) + 1
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_CountRedirects)


def fetch(base, path, required=True):
    url = base.rstrip("/") + "/" + path
    try:
        with _OPENER.open(urllib.request.Request(url, headers={"User-Agent": "legion-resurrect/0.1",
                                                               "Accept-Encoding": "identity"}), timeout=60) as r:
            return r.read()
    except Exception as e:
        if required:
            raise Fail("récupération impossible : %s (%s)" % (url, e))
        return None


def resurrect(mirror, root_pin, out, bitcoin_node=False, log=print):
    t0 = time.time()
    REDIRECTS.update(count=0, hosts={})
    root_pin = root_pin.lower()
    if len(root_pin) != 64 or any(c not in "0123456789abcdef" for c in root_pin):
        raise Fail("empreinte racine : 64 caractères hexadécimaux attendus")
    if os.path.exists(out) and os.listdir(out):
        raise Fail("le dossier de sortie doit être vide : %s" % out)
    os.makedirs(out, exist_ok=True)
    rep = {"mirror": mirror, "root_pin": root_pin, "checks": {}}
    C = rep["checks"]

    kr_text = fetch(mirror, "keyring.jsonl").decode("utf-8")
    keys, pub_for = load_keyring(kr_text, root_pin)
    C["keyring_chain"] = "ok : %d clés (racine + %d sous-clés)" % (len(keys), len(keys) - 1)
    log("[1] trousseau vérifié depuis la racine épinglée :", C["keyring_chain"])

    note = fetch(mirror, "checkpoint").decode("utf-8")
    body, _, sigs = note.partition("\n\n")
    body += "\n"
    lines = body.split("\n")
    origin, size, root = lines[0], int(lines[1]), b64(lines[2])
    signed_by = None
    for sl in sigs.splitlines():
        if not sl.startswith("— "):
            continue
        name, sb = sl[2:].rsplit(" ", 1)
        raw = b64(sb)
        for pin, e in keys.items():
            pub = pub_for(pin, PURPOSE, tree_size=size)
            if pub and name == LOG_NOTE_NAME and raw[:4] == note_key_id(name, pub) and ed_verify(pub, raw[4:], body.encode()):
                signed_by = pin
    if not signed_by:
        raise Fail("checkpoint : aucune signature valide d'une clé mcp-tlog du trousseau")
    C["checkpoint"] = "ok : %s taille %d racine %s signé par %s" % (origin, size, root.hex(), signed_by)
    log("[2] checkpoint signé :", C["checkpoint"])

    leaves, entries = [], []
    for t in range((size + TILE - 1) // TILE):
        w = min(TILE, size - t * TILE)
        lvl0 = fetch(mirror, "tile/" + tile_path(0, t, w))
        bundle = fetch(mirror, "tile/entries-u32/" + tile_path(0, t, w)[2:])
        if len(lvl0) != 32 * w:
            raise Fail("tuile 0/%d : %d octets, %d attendus" % (t, len(lvl0), 32 * w))
        p, k = 0, 0
        while p < len(bundle):
            (ln,) = struct.unpack(">I", bundle[p:p + 4])
            e = bundle[p + 4:p + 4 + ln]
            if len(e) != ln:
                raise Fail("paquet d'entrées %d tronqué" % t)
            if leaf_hash(e) != lvl0[32 * k:32 * k + 32]:
                raise Fail("entrée %d : haché de feuille différent de la tuile de niveau 0" % (t * TILE + k))
            entries.append(e)
            leaves.append(lvl0[32 * k:32 * k + 32])
            p += 4 + ln
            k += 1
        if k != w:
            raise Fail("paquet d'entrées %d : %d entrées, %d attendues" % (t, k, w))
    C["entries_vs_level0_tiles"] = "ok : %d entrées, chacune hachée = tuile de niveau 0" % len(entries)
    log("[3] entrées :", C["entries_vs_level0_tiles"])

    # niveaux supérieurs : chaque tuile servie doit égaler le recalcul
    level, L, n_up = list(leaves), 0, 0
    while True:
        full = len(level) // TILE
        nxt = []
        for t in range(full):
            h = level[t * TILE:(t + 1) * TILE]
            while len(h) > 1:
                h = [node_hash(h[i], h[i + 1]) for i in range(0, len(h), 2)]
            nxt.append(h[0])
        if not nxt:
            break
        L += 1
        for t in range((len(nxt) + TILE - 1) // TILE):
            chunk = nxt[t * TILE:(t + 1) * TILE]
            if fetch(mirror, "tile/" + tile_path(L, t, len(chunk))) != b"".join(chunk):
                raise Fail("tuile %d/%d différente du recalcul" % (L, t))
            n_up += 1
        level = nxt
    recomputed = mth(leaves)
    if recomputed != root:
        raise Fail("racine recalculée %s != racine signée %s" % (recomputed.hex(), root.hex()))
    C["root"] = "ok : racine recalculée = racine signée = %s (%d tuile(s) de niveau >= 1 vérifiées)" % (root.hex(), n_up)
    log("[4] racine :", C["root"])

    recs = []
    for i, e in enumerate(entries):
        r = json.loads(e)
        if canon(r) != e:
            raise Fail("entrée %d : JSON non canonique (JCS)" % i)
        if r.get("leaf_index") != i:
            raise Fail("entrée %d : leaf_index %r (séquence rompue)" % (i, r.get("leaf_index")))
        pub = pub_for(r.get("key_id", ""), PURPOSE, leaf_index=i)
        body_r = canon({k: v for k, v in r.items() if k != "signature_ed25519"})
        if pub is None or not ed_verify(pub, b64(r.get("signature_ed25519", "")), body_r):
            raise Fail("entrée %d : signature invalide ou clé non autorisée (%s)" % (i, r.get("key_id")))
        recs.append(r)
    by_key = {}
    for r in recs:
        by_key[r["key_id"][:16]] = by_key.get(r["key_id"][:16], 0) + 1
    C["records"] = "ok : %d enregistrements signés, séquence 0..%d sans trou ; clés %s" % (len(recs), len(recs) - 1, by_key)
    log("[5] enregistrements :", C["records"])

    heads_raw = fetch(mirror, "heads.jsonl").decode("utf-8")
    heads = {}
    for line in heads_raw.splitlines():
        if not line.strip():
            continue
        h = json.loads(line)
        th = h["tree_head"]
        m = th["tree_size"]
        pub = pub_for(th["issuer_pin_sha256"], PURPOSE, tree_size=m)
        if pub is None or not ed_verify(pub, b64(h["signature_ed25519"]), canon(th)):
            raise Fail("tête %d : signature invalide" % m)
        if m > size or mth(leaves[:m]).hex() != th["root_sha256"]:
            raise Fail("tête %d : racine différente du journal reconstruit" % m)
        proof = consistency_proof(m, leaves)
        if not verify_consistency(m, size, bytes.fromhex(th["root_sha256"]), root, proof):
            raise Fail("tête %d : preuve de cohérence vers %d invalide" % (m, size))
        heads[m] = th
    C["signed_heads"] = "ok : têtes %s, signatures valides, cohérentes avec le checkpoint %d (preuves RFC 6962 vérifiées)" % (sorted(heads), size)
    log("[6] têtes signées :", C["signed_heads"])

    manifest = json.loads(fetch(mirror, "phoenix.json", required=False) or b"{}")
    anchors = []
    for m in manifest.get("anchors", []):
        hc = fetch(mirror, "anchors/%d/head.canon.json" % m)
        ots = fetch(mirror, "anchors/%d/head.canon.json.ots" % m, required=False)
        th = json.loads(hc)
        if canon(th) != hc or heads.get(m) != th:
            raise Fail("ancrage %d : head.canon.json n'est pas une tête signée vérifiée" % m)
        a = {"tree_size": m, "root": th["root_sha256"], "consistent_with_checkpoint": True}
        if ots is None:
            a.update(status="absent")
        else:
            digest, blocks = ots_info(ots)
            if digest != hashlib.sha256(hc).digest():
                raise Fail("ancrage %d : le .ots n'engage pas sha256(head.canon.json)" % m)
            a.update(ots_commits_head=True, bitcoin_blocks_declared=blocks, status="pending",
                     status_detail="blocs déclarés dans le .ots, non vérifiés par un nœud Bitcoin complet")
            if bitcoin_node and shutil.which("ots"):
                d = os.path.join(out, "anchors", str(m))
                os.makedirs(d, exist_ok=True)
                open(os.path.join(d, "head.canon.json"), "wb").write(hc)
                open(os.path.join(d, "head.canon.json.ots"), "wb").write(ots)
                r = subprocess.run(["ots", "verify", "-f", os.path.join(d, "head.canon.json"), os.path.join(d, "head.canon.json.ots")],
                                   capture_output=True, text=True, timeout=300)
                if r.returncode == 0 and "Success" in (r.stdout + r.stderr):
                    a.update(status="sealed", status_detail="ots verify réussi avec un nœud Bitcoin")
                else:
                    a.update(status_detail="ots verify non concluant : %s" % (r.stdout + r.stderr).strip()[-200:])
        anchors.append(a)
        log("[7] ancrage %d : %s %s" % (m, a["status"], a.get("bitcoin_blocks_declared", "")))
    C["anchors"] = anchors or "aucun ancrage annoncé par le miroir"

    # le journal renaît : écriture dans le dossier vide
    with open(os.path.join(out, "records.jsonl"), "w", encoding="utf-8") as f:
        for e in entries:
            f.write(e.decode("utf-8") + "\n")
    open(os.path.join(out, "heads.jsonl"), "w", encoding="utf-8").write(heads_raw)
    open(os.path.join(out, "keyring.jsonl"), "w", encoding="utf-8").write(kr_text)
    open(os.path.join(out, "checkpoint"), "w", encoding="utf-8").write(note)
    rep["redirects"] = {"count": REDIRECTS["count"], "hosts": dict(REDIRECTS["hosts"]),
                        "note": "contenu redirigé vérifié par Merkle + signatures, comme le reste"}
    rep.update(result="RÉSURRECTION RÉUSSIE", origin=origin, tree_size=size, root_sha256=root.hex(),
               signed_by=signed_by, elapsed_s=round(time.time() - t0, 1),
               finished_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    json.dump(rep, open(os.path.join(out, "resurrection_report.json"), "w"), indent=1, ensure_ascii=False)
    return rep


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mirror")
    ap.add_argument("root_pin")
    ap.add_argument("--out", required=True)
    ap.add_argument("--bitcoin-node", action="store_true", help="tenter `ots verify` (nœud Bitcoin Core requis)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    quiet = (lambda *x: None) if a.json else print
    try:
        rep = resurrect(a.mirror, a.root_pin, a.out, a.bitcoin_node, quiet)
    except Fail as e:
        rep = {"result": "RÉSURRECTION ÉCHOUÉE", "mirror": a.mirror, "error": str(e)}
        print(json.dumps(rep, ensure_ascii=False) if a.json else "ÉCHEC : %s" % e)
        return 1
    print(json.dumps(rep, ensure_ascii=False) if a.json else
          "%s : %s taille %d racine %s (%.1f s)" % (rep["result"], rep["origin"], rep["tree_size"], rep["root_sha256"], rep["elapsed_s"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
