#!/usr/bin/env python3
"""LEGION — vérifie TOUT le journal MCP depuis un miroir public, fichier unique, sans pip, sans serveur LEGION.

  python3 legion_verify_mirror.py EMPREINTE_CLE_RACINE [--mirror URL] [--out DOSSIER_VIDE] [--bitcoin-node] [--json]

Entrées : UNIQUEMENT l'URL d'un miroir (https://…, http://… ou file://…) et l'empreinte sha256 (64 hex) de la clé racine.
Dépendances : Python 3.8+ seul (Ed25519 pur Python embarqué, vecteurs RFC 8032 contrôlés à chaque lancement ;
`cryptography` utilisé s'il est déjà installé, plus rapide). Aucune autre ligne de code LEGION n'est importée.

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
import urllib.error
import urllib.parse
import urllib.request

TILE = 256
ORIGIN = "tlog.legion-api.com/mcp/v0"
SCHEMA_COMMIT = "legion-mcp-tlog-key-commitment/0.1"
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
    if m == 0 or m > n:          # taille 0 : aucune preuve possible (vecteurs transparency-dev)
        return False
    if m == n:
        return not proof and old_root == new_root
    if m > n:
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


# ---------- Ed25519 (vérification seule, RFC 8032 §5.1.7, pur Python embarqué ; `cryptography` utilisé s'il est déjà là)
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _padd(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % _P
    B_ = (y1 + x1) * (y2 + x2) % _P
    C = 2 * t1 * t2 * _D % _P
    D_ = 2 * z1 * z2 % _P
    E, F, G, H = B_ - A, D_ - C, D_ + C, B_ + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _pmul(s, pt):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _padd(q, pt)
        pt = _padd(pt, pt)
        s >>= 1
    return q


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    if x & 1 != sign:
        x = _P - x
    return x


def _decode(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _encode(pt):
    x, y, z, _ = pt
    zi = pow(z, _P - 2, _P)
    x, y = x * zi % _P, y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_GY = 4 * pow(5, _P - 2, _P) % _P
_G = (_recover_x(_GY, 0), _GY, 1, _recover_x(_GY, 0) * _GY % _P)
_GTAB = []
_q = _G
for _ in range(253):
    _GTAB.append(_q)
    _q = _padd(_q, _q)


def _gmul(s):
    q = (0, 1, 1, 0)
    i = 0
    while s:
        if s & 1:
            q = _padd(q, _GTAB[i])
        s >>= 1
        i += 1
    return q


def ed_verify_pure(pub_raw, sig, msg):
    if len(pub_raw) != 32 or len(sig) != 64:
        return False
    A = _decode(pub_raw)
    if A is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub_raw + msg).digest(), "little") % _L
    negA = ((_P - A[0]) % _P, A[1], A[2], (_P - A[3]) % _P)
    return _encode(_padd(_gmul(s), _pmul(k, negA))) == sig[:32]    # [S]B - [k]A == R (sans cofacteur, comme OpenSSL)


try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as _EPK
    ED_BACKEND = "cryptography"
except Exception:
    _EPK = None
    ED_BACKEND = "pur-python"
if os.environ.get("LEGION_ED25519") == "pure":
    _EPK, ED_BACKEND = None, "pur-python"


def ed_verify(pub_raw, sig, msg):
    if _EPK is None:
        return ed_verify_pure(pub_raw, sig, msg)
    try:
        _EPK.from_public_bytes(pub_raw).verify(sig, msg)
        return True
    except Exception:
        return False


# Vecteurs officiels RFC 8032 §7.1 (tests 1 à 3) + 1 falsification : contrôlés à chaque lancement.
_RFC8032 = [
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


def ed_selftest():
    for pk, m, sg in _RFC8032:
        if not ed_verify_pure(bytes.fromhex(pk), bytes.fromhex(sg), bytes.fromhex(m)):
            return False
    pk, m, sg = _RFC8032[2]
    bad = bytearray(bytes.fromhex(sg)); bad[5] ^= 1
    return not ed_verify_pure(bytes.fromhex(pk), bytes(bad), bytes.fromhex(m))


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


LIMITS = {"keyring.jsonl": 1 << 20, "checkpoint": 64 << 10, "heads.jsonl": 16 << 20, "phoenix.json": 1 << 20}
LIMIT_TILE, LIMIT_BUNDLE, LIMIT_ANCHOR = 8192, 64 << 20, 1 << 20
RETRIES = 5          # erreurs passagères (DNS, connexion coupée, délai, 429, 5xx) : 2, 4, 8, 16, 32 s d'attente


def fetch(base, path, required=True, limit=None):
    """Lit un fichier du miroir, plafonné : un miroir hostile ne peut pas faire télécharger plus que `limit` octets."""
    if limit is None:
        limit = LIMITS.get(path) or (LIMIT_TILE if path.startswith("tile/") and not path.startswith("tile/entries")
                                     else LIMIT_BUNDLE if path.startswith("tile/entries") else LIMIT_ANCHOR)
    url = base.rstrip("/") + "/" + path
    for attempt in range(RETRIES + 1):
        try:
            with _OPENER.open(urllib.request.Request(url, headers={"User-Agent": "legion-resurrect/0.1",
                                                                   "Accept-Encoding": "identity"}), timeout=60) as r:
                data = r.read(limit + 1)
            if len(data) > limit:
                raise Fail("%s : plus de %d octets (plafond anti-saturation)" % (path, limit))
            return data
        except Fail:
            raise
        except Exception as e:
            transient = not isinstance(e, urllib.error.HTTPError) or e.code == 429 or e.code >= 500
            if transient and attempt < RETRIES:
                time.sleep(2 ** (attempt + 1))
                continue
            if required:
                raise Fail("récupération impossible : %s (%s)" % (url, e))
            return None


def parse_note(note):
    body, _, sigs = note.partition("\n\n")
    body += "\n"
    lines = body.split("\n")
    if len(lines) < 4 or any(ord(c) < 0x20 and c != "\n" for c in note):
        raise Fail("checkpoint : format C2SP invalide (lignes manquantes ou caractère de contrôle)")
    if not lines[1].isascii() or not (lines[1] == "0" or (lines[1][:1] in "123456789" and lines[1].isdigit())):
        raise Fail("checkpoint : taille non canonique %r (C2SP : décimal ASCII sans zéro initial)" % lines[1][:20])
    root = b64(lines[2])
    if len(root) != 32 or base64.b64encode(root).decode() != lines[2]:
        raise Fail("checkpoint : racine non canonique (C2SP : base64 canonique de 32 octets)")
    return body, sigs, lines[0], int(lines[1]), root


def note_signer(note, keys, pub_for):
    body, sigs, origin, size, root = parse_note(note)
    for sl in sigs.splitlines():
        if not sl.startswith("— "):
            continue
        name, sb = sl[2:].rsplit(" ", 1)
        raw = b64(sb)
        for pin in keys:
            pub = pub_for(pin, PURPOSE, tree_size=size)
            if pub and name == LOG_NOTE_NAME and raw[:4] == note_key_id(name, pub) and ed_verify(pub, raw[4:], body.encode()):
                return pin
    return None


def load_previous(path):
    """--previous : un checkpoint signé (note C2SP) OU le state.json d'une vérification précédente."""
    text = open(path, encoding="utf-8").read()
    try:
        st = json.loads(text)
    except ValueError:
        st = {"checkpoint": text}
    if not isinstance(st, dict) or "checkpoint" not in st:
        raise Fail("--previous : ni checkpoint signé ni state.json")
    return st


def resurrect(mirror, root_pin, out, bitcoin_node=False, log=print, previous=None, origin_pin=ORIGIN):
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
    kr_lines = [json.loads(l) for l in kr_text.splitlines() if l.strip()]
    if previous and "keyring_len" in previous:
        pl, ph = previous["keyring_len"], previous["keyring_last_hash"]
        if len(kr_lines) < pl or (kr_lines[pl - 1].get("hash") or "") != ph:
            raise Fail("trousseau : RETOUR EN ARRIÈRE ou fourche (déjà vu %d entrées, dernière %s… ; servi %d)" % (pl, ph[:16], len(kr_lines)))
    C["keyring_chain"] = "ok : %d clés (racine + %d sous-clés)" % (len(keys), len(keys) - 1)
    log("[1] trousseau vérifié depuis la racine épinglée :", C["keyring_chain"])

    note = fetch(mirror, "checkpoint").decode("utf-8")
    body, sigs, origin, size, root = parse_note(note)
    if origin != origin_pin:
        raise Fail("checkpoint : origine %r, attendue %r" % (origin, origin_pin))
    signed_by = note_signer(note, keys, pub_for)
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
    if previous:
        pn = previous["checkpoint"]
        _, _, porigin, psize, proot = parse_note(pn)
        if porigin != origin_pin or not note_signer(pn, keys, pub_for):
            raise Fail("--previous : checkpoint précédent non signé par une clé mcp-tlog du trousseau (ou autre origine)")
        if psize > size:
            raise Fail("RETOUR EN ARRIÈRE : déjà vu la taille %d, le miroir sert %d" % (psize, size))
        if mth(leaves[:psize]) != proot:
            raise Fail("FOURCHE (split-view) : la taille %d déjà vue avait la racine %s, ce journal donne %s"
                       % (psize, proot.hex(), mth(leaves[:psize]).hex()))
        C["previous"] = "ok : extension de la taille %d déjà vue (racine identique à cette taille)" % psize
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
    current, committed, enforced, legacy, rot = None, None, False, 0, []
    for i, r in enumerate(recs):
        kid = r["key_id"]
        if current is not None and kid != current:
            if enforced:
                if committed is None:
                    raise Fail("entrée %d : rotation vers %s… sans engagement préalable (pré-rotation en vigueur)" % (i, kid[:16]))
                if kid != committed:
                    raise Fail("entrée %d : rotation vers %s… non conforme à l'engagement %s…" % (i, kid[:16], committed[:16]))
                rot.append(i)
            else:
                legacy += 1
            committed = None
        current = kid
        if r.get("schema") == SCHEMA_COMMIT:
            enforced, committed = True, r.get("next_key_digest")
    C["succession"] = ("pré-rotation en vigueur : %d rotation(s) conformes ; %d rotation(s) antérieures sans engagement" % (len(rot), legacy)
                       if enforced else "aucune feuille d'engagement : pré-rotation non appliquée (%d rotation(s) sans engagement)" % legacy)
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
            a.update(ots_commits_head=True, bitcoin_blocks_declared=blocks, bitcoin_blocks_verified=False, status="pending",
                     status_detail="blocs DÉCLARÉS par le fichier .ots (le miroir peut écrire n'importe quel numéro) ; "
                                   "seul `ots verify` avec votre nœud Bitcoin les établit")
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
    if previous:
        gone = sorted(set(previous.get("anchors", [])) - set(manifest.get("anchors", [])))
        if gone:
            raise Fail("ancrages déjà vus retirés par le miroir : %s" % gone)

    # le journal renaît : écriture dans le dossier vide
    with open(os.path.join(out, "records.jsonl"), "w", encoding="utf-8") as f:
        for e in entries:
            f.write(e.decode("utf-8") + "\n")
    open(os.path.join(out, "heads.jsonl"), "w", encoding="utf-8").write(heads_raw)
    open(os.path.join(out, "keyring.jsonl"), "w", encoding="utf-8").write(kr_text)
    open(os.path.join(out, "checkpoint"), "w", encoding="utf-8").write(note)
    json.dump({"checkpoint": note, "keyring_len": len(kr_lines), "keyring_last_hash": kr_lines[-1].get("hash") or "",
               "anchors": sorted(manifest.get("anchors", []))}, open(os.path.join(out, "state.json"), "w"), indent=1)
    rep["redirects"] = {"count": REDIRECTS["count"], "hosts": dict(REDIRECTS["hosts"]),
                        "note": "contenu redirigé vérifié par Merkle + signatures, comme le reste"}
    rep.update(result="RÉSURRECTION RÉUSSIE", origin=origin, tree_size=size, root_sha256=root.hex(),
               signed_by=signed_by, elapsed_s=round(time.time() - t0, 1),
               finished_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    json.dump(rep, open(os.path.join(out, "resurrection_report.json"), "w"), indent=1, ensure_ascii=False)
    return rep


DEFAULT_MIRROR = "https://legion33shadow.github.io/legion-tlog-mirror"


def main(argv):
    import tempfile
    ap = argparse.ArgumentParser(description="Vérifie tout le journal MCP LEGION depuis un miroir public.")
    ap.add_argument("root_pin", help="empreinte sha256 (64 hex) de la clé racine, obtenue hors bande")
    ap.add_argument("--mirror", default=DEFAULT_MIRROR, help="URL du miroir (défaut : %(default)s)")
    ap.add_argument("--out", help="dossier vide pour la copie vérifiée (défaut : dossier temporaire neuf)")
    ap.add_argument("--bitcoin-node", action="store_true", help="tenter `ots verify` (nœud Bitcoin Core requis)")
    ap.add_argument("--previous", help="checkpoint signé déjà vu, ou state.json d'une vérification précédente : "
                                       "détecte retour en arrière, fourche, trousseau tronqué, ancrages retirés")
    ap.add_argument("--origin", default=ORIGIN, help="origine attendue du checkpoint (défaut : %(default)s)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if not ed_selftest():
        print("ÉCHEC : l'Ed25519 embarqué ne passe pas les vecteurs RFC 8032 ; rien n'est vérifié")
        return 1
    out = a.out or tempfile.mkdtemp(prefix="legion-tlog-mirror-")
    quiet = (lambda *x: None) if a.json else print
    quiet("miroir : %s\ncopie : %s\nEd25519 : %s (RFC 8032 : ok)" % (a.mirror, out, ED_BACKEND))
    try:
        rep = resurrect(a.mirror, a.root_pin, out, a.bitcoin_node, quiet,
                        previous=load_previous(a.previous) if a.previous else None, origin_pin=a.origin)
    except (Fail, ValueError, TypeError, KeyError, IndexError, AttributeError, UnicodeError, RecursionError, struct.error, OSError) as e:
        if not isinstance(e, Fail):
            e = Fail("entrée malformée servie par le miroir (%s : %s)" % (type(e).__name__, str(e)[:120]))
        rep = {"result": "RÉSURRECTION ÉCHOUÉE", "mirror": a.mirror, "error": str(e)}
        print(json.dumps(rep, ensure_ascii=False) if a.json else "ÉCHEC : %s" % e)
        return 1
    rep["ed25519_backend"] = ED_BACKEND
    print(json.dumps(rep, ensure_ascii=False) if a.json else
          "%s : %s taille %d racine %s (%.1f s)" % (rep["result"], rep["origin"], rep["tree_size"], rep["root_sha256"], rep["elapsed_s"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
