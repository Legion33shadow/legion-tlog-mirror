#!/usr/bin/env python3
"""Vérificateur hors ligne autonome du journal de transparence MCP de LEGION.

Dépendances : Python 3 stdlib + `cryptography` (Ed25519, ECDSA). Aucun accès réseau, aucun autre fichier LEGION.

Entrées : un enregistrement signé, sa preuve d'inclusion, la tête d'arbre signée (STH), la clé publique LEGION
(base64 brute 32 octets), et au moins une preuve d'ancrage tiers :
  --ots FICHIER.ots --btc-headers HEADERS.json   (OpenTimestamps ; en-têtes tirés de VOTRE nœud Bitcoin)
  --rekor-entry ENTREE.json --rekor-pubkey REKOR.pem   (entrée Rekor v1 brute de l'API ; clé Rekor épinglée par vous)

Contrôles : 1) intégrité de l'enregistrement  2) signature LEGION  3) inclusion dans la tête signée
            4) horodatage externe de la tête (donc de l'enregistrement inclus).
Sortie : JSON, code 0 uniquement si tous les contrôles demandés passent.

Sous-commandes : receipt (racine legion-receipts ancrée), badge (SVG signé), freeze (gel mensuel), alert (changement signé) ; voir --help.

Exemple :
  python3 verify_tlog.py --record rec.json --proof proof.json --sth sth.json --pubkey legion_pub.b64 \
      --ots head.canon.json.ots --btc-headers headers.json --rekor-entry rekor_entry.json --rekor-pubkey rekor_pub.pem
"""
import argparse
import base64
import hashlib
import json
import struct
import sys

# ---------- décodage STRICT (durcissement) : un texte unique accepté par valeur binaire ----------
import re as _re
_HEX = _re.compile(r"\A(?:[0-9a-f]{2})*\Z")


def _hx(s):
    """Hexadécimal minuscule, longueur paire, sans espace : sinon refus (pas de malléabilité)."""
    if not isinstance(s, str) or not _HEX.match(s):
        raise ValueError("hexadécimal non canonique")
    return bytes.fromhex(s)


def _b64(s):
    """Base64 RFC 4648 canonique (avec padding, sans caractère parasite) : sinon refus."""
    if not isinstance(s, str):
        raise ValueError("base64 attendu")
    raw = base64.b64decode(s, validate=True)
    if base64.b64encode(raw).decode() != s:
        raise ValueError("base64 non canonique")
    return raw


RECORD_SCHEMA = "legion-mcp-tlog-record/0.1"
CORRECTION_SCHEMA = "legion-mcp-tlog-correction/0.1"
STH_SCHEMA = "legion-mcp-tlog-sth/0.1"


# ---------- primitives (mêmes définitions que legion-receipts / common/legion_proof.py) ----------
# --- JSON canonique RFC 8785 (JCS), recopié de jcs/jcs.py (le test de synchronisation vérifie l'identité) ---
import math

_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
MAX_SAFE = 2 ** 53


class JCSError(ValueError):
    pass


def _str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise JCSError("moitié de paire de substitution isolée")
        if ch in _ESC:
            out.append(_ESC[ch])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(s):
    return s.encode("utf-16-be")


def _num(x, exact_bigint=False):
    if isinstance(x, bool):
        raise JCSError("booléen inattendu")
    if isinstance(x, int):
        if abs(x) > MAX_SAFE and not exact_bigint:
            raise JCSError("entier hors de ±2**53 : non représentable exactement en IEEE 754")
        return str(x)   # empreinte v3 seulement (exact_bigint) : décimal exact au-delà de ±2**53
    if not math.isfinite(x):
        raise JCSError("NaN/Infinity interdits")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    r = repr(abs(x))  # plus court aller-retour (comme ECMAScript), à reformater
    if "e" in r:
        mant, e = r.split("e")
        e = int(e)
    else:
        mant, e = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    lead_zeros = len(ip + fp) - len((ip + fp).lstrip("0"))
    n = len(ip) + e - lead_zeros          # position du point décimal : valeur = 0.d1d2… × 10^n
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        exp = n - 1
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if exp >= 0 else "-") + str(abs(exp))
    return sign + s


def _ser(o, out, xb=False):
    if o is None:
        out.append("null")
    elif o is True:
        out.append("true")
    elif o is False:
        out.append("false")
    elif isinstance(o, str):
        out.append(_str(o))
    elif isinstance(o, (int, float)):
        out.append(_num(o, xb))
    elif isinstance(o, (list, tuple)):
        out.append("[")
        for i, v in enumerate(o):
            if i:
                out.append(",")
            _ser(v, out, xb)
        out.append("]")
    elif isinstance(o, dict):
        if any(not isinstance(k, str) for k in o):
            raise JCSError("nom de membre non textuel")
        out.append("{")
        for i, k in enumerate(sorted(o, key=_utf16_key)):
            if i:
                out.append(",")
            out.append(_str(k))
            out.append(":")
            _ser(o[k], out, xb)
        out.append("}")
    else:
        raise JCSError("type non JSON : %s" % type(o).__name__)


def _jcs_canonicalize(obj, exact_bigint=False):
    out = []
    _ser(obj, out, exact_bigint)
    return "".join(out).encode("utf-8")


def canon(o):
    """RFC 8785 (JCS) : formats du journal de transparence MCP, Rekor SET."""
    return _jcs_canonicalize(o)


def canon_v1(o):
    """Ancienne canonicalisation : formats tiers signés avec elle (legion-receipts, Phoenix, churn, passeport)."""
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# Empreintes tools/list (tools_fingerprint.algo). Feuilles, têtes, alertes et badges restent en JCS strict (canon).
FP_ALGO_V1 = "sha256(canon(sorted[{name,description,inputSchema}]))/v1"
FP_ALGO_V2 = "sha256(JCS-RFC8785(sorted[{name,description,inputSchema}]))/v2"
FP_ALGO_V3 = "sha256(JCS-RFC8785+exact-bigint(sorted[{name,description,inputSchema}]))/v3"
FP_DIFF_COMPATIBLE = {frozenset((FP_ALGO_V2, FP_ALGO_V3))}   # empreintes PAR OUTIL comparables entre ces deux algos


def canon_fp_v3(o):
    """Empreinte v3 : JCS RFC 8785, sauf un entier hors ±2**53 écrit en décimal exact (au lieu d'être refusé).
    Identique octet pour octet à v2 sur tout ce que v2 accepte."""
    return _jcs_canonicalize(o, exact_bigint=True)


def canon_fp_for(algo):
    """Règle de recalcul d'une empreinte depuis les définitions archivées : /v1 -> json.dumps trié ; /v2 et /v3 ->
    canon_fp_v3 (= v2 sur le domaine de v2) ; algo inconnu -> refus explicite."""
    if algo == FP_ALGO_V1:
        return canon_v1
    if algo in (FP_ALGO_V2, FP_ALGO_V3):
        return canon_fp_v3
    raise ValueError("algo d'empreinte inconnu : %r" % (algo,))


def fp_algos_comparable(a, b):
    return a == b or frozenset((a, b)) in FP_DIFF_COMPATIBLE


def H(b):
    return hashlib.sha256(b).digest()


def leaf_hash(b):
    return H(b"\x00" + b)


def node_hash(l, r):
    return H(b"\x01" + l + r)


def _hash32(*xs):
    return all(isinstance(x, (bytes, bytearray)) and len(x) == 32 for x in xs)


def verify_inclusion(leaf, index, size, path, root):
    if index < 0 or index >= size:
        return False
    if not _hash32(leaf, root) or not all(_hash32(p) for p in path):   # RFC 9162 : hachages de 32 octets exactement
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def key_pin(pub_b64):
    return hashlib.sha256(_b64(pub_b64)).hexdigest()


def ed25519_ok(pub_raw, sig, msg):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, msg)
        return True
    except Exception:
        return False


def ecdsa_ok(pub, sig_der, msg):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        pub.verify(sig_der, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ---------- contrôles LEGION ----------
def _pub(keys, pin):
    """keys = clé publique base64 (comportement historique) ou dict {pin sha256: clé} issu d'un keyring vérifié."""
    if isinstance(keys, dict):
        return keys.get(pin) or ""
    return keys


KEYRING_SIG_FIELDS = ("hash", "self_sig", "endorsement_sig")


def load_keyring(text, root_pub_b64):
    """keyring.jsonl du journal -> {pin: clé publique} des clés VALIDES. Ancre : la clé racine épinglée (--pubkey).
    Première entrée = racine (même empreinte que --pubkey). Chaque entrée suivante : chaîne prev_hash/hash, approuvée
    par la racine (endorsement_sig) ; key_register exige en plus la preuve de possession (self_sig). key_revoke retire
    la clé. Toute anomalie lève une exception : le keyring entier est alors refusé."""
    root_pin = key_pin(root_pub_b64)
    keys, revoked, prev, limits, compromised = {}, set(), None, {}, set()
    for n, line in enumerate(l for l in text.splitlines() if l.strip()):
        e = json.loads(line)
        body = {k: v for k, v in e.items() if k not in KEYRING_SIG_FIELDS}
        if n == 0:
            if e.get("type") != "key_register" or key_pin(e.get("public_key_b64", "")) != root_pin:
                raise ValueError("keyring : la première entrée n'est pas la clé racine épinglée")
            keys[root_pin] = root_pub_b64
            prev = e.get("hash") or H(canon(body)).hex()
            continue
        c = canon(body)
        if e.get("prev_hash") != prev or e.get("hash") != H(c).hex():
            raise ValueError("keyring : chaîne rompue à l'entrée %d" % n)
        if not ed25519_ok(_b64(root_pub_b64), _b64(e.get("endorsement_sig", "")), c):
            raise ValueError("keyring : entrée %d non approuvée par la racine" % n)
        if e.get("type") == "key_register":
            pub = e["public_key_b64"]
            if e.get("key_id") != "k1:" + key_pin(pub)[:32] or not ed25519_ok(_b64(pub), _b64(e.get("self_sig", "")), c):
                raise ValueError("keyring : sous-clé invalide à l'entrée %d" % n)
            keys[key_pin(pub)] = pub
        elif e.get("type") == "key_revoke":
            revoked.add(e["key_id"])
            if isinstance(e.get("valid_until_tree_size"), int) and e["key_id"] not in compromised:
                limits[e["key_id"]] = min(e["valid_until_tree_size"], limits.get(e["key_id"], e["valid_until_tree_size"]))
            elif not isinstance(e.get("valid_until_tree_size"), int):   # compromission : l'emporte sur toute retraite
                limits.pop(e["key_id"], None)
                compromised.add(e["key_id"])
        else:
            raise ValueError("keyring : type inconnu à l'entrée %d" % n)
        prev = e["hash"]
    out = _Keys({p: k for p, k in keys.items() if "k1:" + p[:32] not in revoked or "k1:" + p[:32] in limits})
    out.limits = {p: limits["k1:" + p[:32]] for p in keys if "k1:" + p[:32] in limits}
    return out


class _Keys(dict):
    """{pin: clé publique} + limits {pin: N} pour les sous-clés retirées (valides seulement avant la taille N)."""
    limits = {}


def _within(keys, pin, leaf_index=None, tree_size=None):
    lim = getattr(keys, "limits", {}).get(pin)
    if lim is None:
        return True
    return (leaf_index is not None and leaf_index < lim) or (tree_size is not None and tree_size <= lim)


def check_record(rec, pub_b64):
    """Intégrité interne + signature. Renvoie (intégrité, signature, détail)."""
    try:
        body = {k: v for k, v in rec.items() if k != "signature_ed25519"}
        if rec.get("schema") == CORRECTION_SCHEMA:   # feuille de correction : référence une feuille antérieure
            integ = (rec.get("kind") == "canonicalization_artifact" and isinstance(rec.get("corrects_leaf_index"), int)
                     and 0 <= rec["corrects_leaf_index"] < rec["leaf_index"] and isinstance(rec["server_id"], str)
                     and isinstance(rec["observed_at"], str) and rec.get("artifact") in ("array_order", "number_format"))
        else:
            fp = rec["tools_fingerprint"]
            names = [n for n, _ in fp["per_tool_sha256"]]
            integ = (rec.get("schema") == RECORD_SCHEMA and fp["tool_count"] == len(names)
                     and names == sorted(names) and len(set(names)) == len(names)
                     and isinstance(rec["server_id"], str) and isinstance(rec["observed_at"], str))
        keys_ = pub_b64
        pub_b64 = _pub(pub_b64, rec.get("key_id"))
        sig_ok = (bool(pub_b64) and rec.get("key_id") == key_pin(pub_b64)
                  and (not isinstance(keys_, dict) or _within(keys_, rec.get("key_id"), leaf_index=rec.get("leaf_index")))
                  and ed25519_ok(_b64(pub_b64), _b64(rec["signature_ed25519"]), canon(body)))
        return integ, sig_ok, None
    except Exception as e:
        return False, False, "%s: %s" % (type(e).__name__, e)


def check_sth(sth, pub_b64):
    try:
        head = sth["tree_head"]
        keys_ = pub_b64
        pub_b64 = _pub(pub_b64, head.get("issuer_pin_sha256"))
        if isinstance(keys_, dict) and not _within(keys_, head.get("issuer_pin_sha256"), tree_size=head.get("tree_size")):
            return False
        return (bool(pub_b64) and head.get("schema") == STH_SCHEMA and head.get("issuer_pin_sha256") == key_pin(pub_b64)
                and ed25519_ok(_b64(pub_b64), _b64(sth["signature_ed25519"]), canon(head)))
    except Exception:
        return False


def check_inclusion(rec, proof, sth):
    try:
        head = sth["tree_head"]
        return (proof["tree_size"] == head["tree_size"] and proof["leaf_index"] == rec["leaf_index"]
                and verify_inclusion(leaf_hash(canon(rec)), proof["leaf_index"], proof["tree_size"],
                                     [_hx(h) for h in proof["audit_path"]], _hx(head["root_sha256"])))
    except Exception:
        return False


# ---------- OpenTimestamps (lecteur minimal du format .ots, sans dépendance) ----------
OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
BTC_TAG = _hx("0588960d73d71901")
PENDING_TAG = _hx("83dfe30d2ef90c8e")


class _R:
    def __init__(self, b):
        self.b, self.i = b, 0

    def read(self, n):
        if self.i + n > len(self.b):
            raise ValueError("fichier .ots tronqué")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def varuint(self):
        v, shift = 0, 0
        while True:
            c = self.read(1)[0]
            v |= (c & 0x7f) << shift
            if not c & 0x80:
                return v
            shift += 7
            if shift > 63:
                raise ValueError("varuint trop long")

    def varbytes(self, maxlen=8192):
        n = self.varuint()
        if n > maxlen:
            raise ValueError("champ trop long")
        return self.read(n)


def _apply(tag, arg, msg):
    if tag == 0xf0:
        return msg + arg
    if tag == 0xf1:
        return arg + msg
    if tag == 0x08:
        return hashlib.sha256(msg).digest()
    if tag == 0x02:
        return hashlib.sha1(msg).digest()
    if tag == 0x03:
        return hashlib.new("ripemd160", msg).digest()
    if tag == 0xf2:
        return msg[::-1]
    if tag == 0xf3:
        return msg.hex().encode()
    raise ValueError("opération .ots inconnue 0x%02x" % tag)


def _walk(r, msg, out, depth=0):
    if depth > 256:
        raise ValueError("arbre .ots trop profond")

    def one(tag):
        if tag == 0x00:
            atag = r.read(8)
            payload = _R(r.varbytes())
            if atag == BTC_TAG:
                out.append(("bitcoin", payload.varuint(), msg))
            elif atag == PENDING_TAG:
                out.append(("pending", payload.varbytes().decode("utf-8", "replace"), msg))
            else:
                out.append(("unknown", atag.hex(), msg))
        else:
            arg = r.varbytes() if tag in (0xf0, 0xf1) else b""
            _walk(r, _apply(tag, arg, msg), out, depth + 1)

    tag = r.read(1)[0]
    while tag == 0xff:
        one(r.read(1)[0])
        tag = r.read(1)[0]
    one(tag)


def parse_ots(data):
    """Renvoie (digest_horodaté, [(type, détail, message_final)])."""
    r = _R(data)
    if r.read(len(OTS_MAGIC)) != OTS_MAGIC:
        raise ValueError("ce n'est pas un fichier OpenTimestamps")
    if r.varuint() != 1:
        raise ValueError("version .ots non prise en charge")
    if r.read(1)[0] != 0x08:
        raise ValueError("hachage du fichier : SHA-256 uniquement")
    digest = r.read(32)
    out = []
    _walk(r, digest, out)
    if r.i != len(data):
        raise ValueError("octets en trop après la preuve")
    return digest, out


def _check_ots_impl(ots_bytes, artifact, headers):
    """headers = {"HAUTEUR": {"merkleroot": hex affiché par bitcoin-cli, "time": unix}} issus de VOTRE nœud."""
    res = {"status": "failed", "detail": None}
    try:
        digest, atts = parse_ots(ots_bytes)
    except Exception as e:
        res["detail"] = "preuve illisible : %s" % e
        return res
    if digest != hashlib.sha256(artifact).digest():
        res["detail"] = "le .ots horodate un autre contenu que cette tête d'arbre"
        return res
    btc = [a for a in atts if a[0] == "bitcoin"]
    if not btc:
        res["status"] = "pending" if any(a[0] == "pending" for a in atts) else "failed"
        res["detail"] = "aucune attestation Bitcoin (lancer `ots upgrade`)"
        return res
    verified = []
    for _, height, msg in btc:
        h = (headers or {}).get(str(height))
        if h is None:
            continue
        if len(msg) == 32 and msg == _hx(h["merkleroot"])[::-1]:
            verified.append({"height": height, "block_time": h.get("time")})
        else:
            res["detail"] = "racine Merkle du bloc %d différente : ancrage falsifié ou mauvais en-tête" % height
            return res
    if not verified:
        res["status"] = "unverified"
        res["detail"] = "en-têtes Bitcoin non fournis pour les hauteurs %s (--btc-headers)" % sorted({a[1] for a in btc})
        return res
    best = min(verified, key=lambda v: v["height"])
    return {"status": "verified", "detail": "existait au plus tard au bloc %d" % best["height"],
            "bitcoin_height": best["height"], "block_time": best["block_time"]}


# ---------- Sigstore Rekor v1 (entrée « rekord » brute de /api/v1/log/entries) ----------
def _parse_checkpoint(text):
    """Format « signed note » exact : corps (origine, taille, racine b64, lignes éventuelles) + ligne vide
    + une ou plusieurs lignes « — nom sig », chacune terminée par \\n. Tout écart = refus (pas de texte parasite)."""
    if not isinstance(text, str) or not text.endswith("\n"):
        raise ValueError("checkpoint mal terminé")
    body, sep, sigs = text.partition("\n\n")
    if not sep:
        raise ValueError("checkpoint sans signature")
    lines = body.split("\n")
    if len(lines) < 3 or not lines[1].isdigit() or str(int(lines[1])) != lines[1]:
        raise ValueError("checkpoint : taille non canonique")
    sig_lines = sigs[:-1].split("\n")
    if not sig_lines or any(not l.startswith("\u2014 ") or len(l.split(" ")) != 3 for l in sig_lines):
        raise ValueError("checkpoint : ligne de signature invalide")
    return (body + "\n").encode(), int(lines[1]), _b64(lines[2]), sig_lines


def check_rekor(entry, artifact, legion_pub_b64, rekor_pub_pem):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    res = {"status": "failed", "detail": None}
    try:
        if isinstance(entry, dict) and len(entry) == 1 and "body" not in entry:
            entry = next(iter(entry.values()))
        rekor_pub = serialization.load_pem_public_key(rekor_pub_pem)
        rekor_der = rekor_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        body_raw = _b64(entry["body"])
        body = json.loads(body_raw)
        spec = body["spec"]
        if body.get("kind") != "rekord":
            res["detail"] = "type d'entrée inattendu : %s" % body.get("kind")
            return res
        if spec["data"]["hash"]["value"] != hashlib.sha256(artifact).hexdigest():
            res["detail"] = "l'entrée Rekor porte sur un autre contenu"
            return res
        pk = serialization.load_pem_public_key(_b64(spec["signature"]["publicKey"]["content"]))
        if not isinstance(pk, Ed25519PublicKey) or base64.b64encode(
                pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode() != legion_pub_b64:
            res["detail"] = "l'entrée Rekor est signée par une autre clé que LEGION"
            return res
        if not ed25519_ok(_b64(legion_pub_b64), _b64(spec["signature"]["content"]), artifact):
            res["detail"] = "signature LEGION invalide dans l'entrée Rekor"
            return res
        if entry["logID"] != hashlib.sha256(rekor_der).hexdigest():
            res["detail"] = "logID ne correspond pas à la clé Rekor épinglée"
            return res
        v = entry["verification"]
        set_payload = canon({"body": entry["body"], "integratedTime": entry["integratedTime"],
                             "logID": entry["logID"], "logIndex": entry["logIndex"]})
        if not ecdsa_ok(rekor_pub, _b64(v["signedEntryTimestamp"]), set_payload):
            res["detail"] = "horodatage signé (SET) Rekor invalide"
            return res
        ip = v["inclusionProof"]
        root = _hx(ip["rootHash"])
        if not verify_inclusion(leaf_hash(body_raw), ip["logIndex"], ip["treeSize"],
                                [_hx(h) for h in ip["hashes"]], root):
            res["detail"] = "preuve d'inclusion Rekor invalide"
            return res
        signed, size, cp_root, sig_lines = _parse_checkpoint(ip["checkpoint"])
        if size != ip["treeSize"] or cp_root != root:
            res["detail"] = "checkpoint Rekor incohérent avec la preuve"
            return res
        if not any(ecdsa_ok(rekor_pub, _b64(l.split(" ")[-1])[4:], signed) for l in sig_lines):
            res["detail"] = "signature du checkpoint Rekor invalide"
            return res
        return {"status": "verified", "detail": "inscrit dans Rekor (index %d)" % entry["logIndex"],
                "integrated_time": entry["integratedTime"], "log_index": entry["logIndex"]}
    except Exception as e:
        res["detail"] = "entrée illisible : %s: %s" % (type(e).__name__, e)
        return res


# ---------- orchestration ----------
def _verify_all_impl(rec, proof, sth, pub_b64, ots=None, headers=None, rekor_entry=None, rekor_pub_pem=None,
               require_anchor=True):
    integ, sig, err = check_record(rec, pub_b64)
    out = {"record_integrity": integ, "record_signature": sig, "head_signature": check_sth(sth, pub_b64),
           "inclusion": check_inclusion(rec, proof, sth), "anchors": {}}
    if err:
        out["error"] = err
    artifact = canon(sth.get("tree_head", {}))
    if ots is not None:
        out["anchors"]["opentimestamps"] = check_ots(ots, artifact, headers)
    if rekor_entry is not None:
        out["anchors"]["rekor"] = check_rekor(rekor_entry, artifact, _pub(pub_b64, sth.get("tree_head", {}).get("issuer_pin_sha256")),
                                              rekor_pub_pem)
    statuses = [a["status"] for a in out["anchors"].values()]
    anchored = "verified" in statuses and "failed" not in statuses
    if require_anchor and "unverified" in statuses:
        anchored = False  # ancrage exigé : une preuve présente mais non vérifiable (en-tête absent) ne passe pas
    base_ok = integ and sig and out["head_signature"] and out["inclusion"]
    out["external_timestamp"] = anchored
    if not base_ok:
        out["claim_state"] = "rejected"
    elif "failed" in statuses:
        out["claim_state"] = "rejected_anchor"
    elif anchored:
        out["claim_state"] = "anchored_observation"
    else:
        out["claim_state"] = "signed_observation_not_anchored"
    out["ok"] = bool(base_ok and (anchored or not require_anchor) and "failed" not in statuses)
    return out


# ---------- 5) racine legion-receipts ancrée (non signée) ----------
RECEIPTS_ANCHOR_SCHEMA = "legion-mcp-receipts-root-anchor/0.1"
RECEIPTS_ROOT_KEYS = ("schema", "generated_at", "tree_size", "root_sha256", "hash", "canonicalization")


def receipts_root_artifact(root_doc):
    return canon_v1({"schema": RECEIPTS_ANCHOR_SCHEMA, "source": {k: root_doc[k] for k in RECEIPTS_ROOT_KEYS}})


def verify_receipt_root(receipt, root_doc, ots=None, headers=None, require_anchor=True):
    """Un reçu legion-receipts (ligne de receipts.jsonl) + ROOT.json + .ots de root_anchor.canon.json."""
    out = {"anchors": {}}
    try:
        leaf = leaf_hash(canon_v1({k: receipt[k] for k in ("schema", "source", "record")}))
        out["receipt_integrity"] = leaf.hex() == receipt["leaf_hash"]
        out["inclusion"] = (receipt["tree_size"] == root_doc["tree_size"] and verify_inclusion(
            leaf, receipt["index"], receipt["tree_size"], [_hx(h) for h in receipt["proof"]],
            _hx(root_doc["root_sha256"])))
    except Exception as e:
        out.update(receipt_integrity=False, inclusion=False, error="%s: %s" % (type(e).__name__, e))
    if ots is not None:
        out["anchors"]["opentimestamps"] = check_ots(ots, receipts_root_artifact(root_doc), headers)
    st = [a["status"] for a in out["anchors"].values()]
    base = out["receipt_integrity"] and out["inclusion"]
    anchored = "verified" in st and "failed" not in st
    out["claim_state"] = ("rejected" if not base else "rejected_anchor" if "failed" in st
                          else "unsigned_root_anchored" if anchored else "unsigned_root_not_anchored")
    out["claim_boundary"] = ("La ligne existait dans la table locale au plus tard à la date du bloc. "
                             "Racine non signée par LEGION ; rien n'est affirmé sur le registre MCP source.")
    out["ok"] = bool(base and (anchored or not require_anchor) and "failed" not in st)
    return out


# ---------- 6) badge SVG signé ----------
BADGE_SCHEMA = "legion-mcp-badge/0.1"
_BADGE_TPL = ('<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="{label}: {msg}">'
              '<title>{title}</title>'
              '<metadata id="legion-attestation">{meta}</metadata>'
              '<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
              '<stop offset="1" stop-opacity=".1"/></linearGradient>'
              '<clipPath id="r"><rect width="{w}" height="20" rx="3" fill="#fff"/></clipPath>'
              '<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#555"/>'
              '<rect x="{lw}" width="{rw}" height="20" fill="{color}"/><rect width="{w}" height="20" fill="url(#s)"/></g>'
              '<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
              '<text x="{lx}" y="14">{label}</text><text x="{rx}" y="14">{msg}</text></g></svg>\n')


def _xml(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def render_badge(statement, signature_b64):
    """Rendu déterministe : le texte visible est entièrement dérivé de la déclaration signée."""
    label = "MCP tools"
    msg = "no change observed since %s" % statement["last_change_observed_at"][:10]
    title = ("Observed by LEGION. Same tools/list fingerprint for %s from %s to %s. "
             "An observation at those dates, not a guarantee. Verify: %s" % (
                 statement["server_id"], statement["last_change_observed_at"], statement["last_checked_at"],
                 statement["verify_url"]))
    meta = base64.b64encode(canon({"statement": statement, "signature_ed25519": signature_b64})).decode()
    lw, rw = 10 + 7 * len(label), 10 + 7 * len(msg)
    return _BADGE_TPL.format(w=lw + rw, lw=lw, rw=rw, lx=lw // 2, rx=lw + rw // 2, label=_xml(label), msg=_xml(msg),
                             title=_xml(title), meta=meta, color="#2e7d32")


def _verify_badge_impl(svg_text, pub_b64, record=None, proof=None, sth=None, now=None, max_age_days=None):
    import datetime
    import re
    out = {"ok": False}
    m = re.search(r'<metadata id="legion-attestation">([A-Za-z0-9+/=]+)</metadata>', svg_text)
    if not m:
        out["detail"] = "aucune attestation LEGION dans le SVG"
        return out
    try:
        doc = json.loads(_b64(m.group(1)))
        st, sig = doc["statement"], doc["signature_ed25519"]
    except Exception:
        out["detail"] = "attestation illisible"
        return out
    out["statement"] = st
    keys = pub_b64
    pub_b64 = _pub(keys, st.get("key_id"))
    out["signature"] = (bool(pub_b64) and st.get("schema") == BADGE_SCHEMA and st.get("key_id") == key_pin(pub_b64)
                        and ed25519_ok(_b64(pub_b64), _b64(sig), canon(st)))
    out["rendering_matches"] = render_badge(st, sig) == svg_text
    ok = out["signature"] and out["rendering_matches"] and st.get("last_change_observed_at", "") <= st.get("last_checked_at", "")
    if record is not None:
        out["record_matches"] = (record.get("server_id") == st["server_id"]
                                 and record.get("tools_fingerprint", {}).get("sha256") == st["tools_sha256"]
                                 and record.get("observed_at") == st["last_change_observed_at"]
                                 and record.get("leaf_index") == st["record_leaf_index"])
        out["record_signature"] = check_record(record, keys)[1]
        out["head_signature"] = check_sth(sth, keys) if sth else False
        out["inclusion"] = check_inclusion(record, proof, sth) if (sth and proof) else False
        out["head_matches"] = bool(sth) and sth["tree_head"]["root_sha256"] == st["root_sha256"] \
            and sth["tree_head"]["tree_size"] == st["tree_size"]
        ok = ok and all(out[k] for k in ("record_matches", "record_signature", "head_signature", "inclusion", "head_matches"))
    if now and max_age_days is not None:
        t = lambda s: datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
        out["stale"] = (t(now) - t(st["last_checked_at"])).total_seconds() > max_age_days * 86400
        ok = ok and not out["stale"]
    out["claim_state"] = "no_change_observed" if ok else "rejected"
    out["ok"] = bool(ok)
    return out


# ---------- 7) gel mensuel ----------
def _sha_file(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def _verify_freeze_impl(d, pub_b64, headers=None, require_anchor=True):
    import os
    j = lambda n: json.load(open(os.path.join(d, n), encoding="utf-8"))
    out = {"anchors": {}}
    man_ok, missing = True, []
    for line in open(os.path.join(d, "MANIFEST.sha256"), encoding="utf-8"):
        h, n = line.rstrip("\n").split("  ", 1)
        p = os.path.join(d, n)
        if not os.path.exists(p):
            missing.append(n)
            man_ok = False
        elif _sha_file(p) != h:
            man_ok = False
    out["manifest"] = man_ok
    if missing:
        out["manifest_missing"] = missing
    try:
        meta, sth = j("FREEZE.json"), j("sth.json")
        recs = [json.loads(l) for l in open(os.path.join(d, "records.jsonl"), encoding="utf-8")]
        sth["tree_head"]["root_sha256"], meta["tree_size"]
    except Exception as e:
        out.update(ok=False, claim_state="rejected", ready_to_deposit=False, error="%s: %s" % (type(e).__name__, e))
        return out
    leaves = [leaf_hash(canon(r)) for r in recs]

    def mth(h):
        if not h:
            return H(b"")
        if len(h) == 1:
            return h[0]
        k = 1
        while k * 2 < len(h):
            k *= 2
        return node_hash(mth(h[:k]), mth(h[k:]))
    out["records_signed"] = all(check_record(r, pub_b64)[1] and r["leaf_index"] == i for i, r in enumerate(recs))
    out["head_signature"] = check_sth(sth, pub_b64)
    out["root_recomputed"] = (len(recs) == sth["tree_head"]["tree_size"]
                              and mth(leaves).hex() == sth["tree_head"]["root_sha256"])
    out["metadata_matches"] = (meta["tree_size"] == sth["tree_head"]["tree_size"]
                               and meta["root_sha256"] == sth["tree_head"]["root_sha256"])
    if os.path.exists(os.path.join(d, "previous_sth.json")):
        prev, cp = j("previous_sth.json"), j("consistency.json")
        out["previous_head_signature"] = check_sth(prev, pub_b64)
        out["consistent_with_previous"] = out["previous_head_signature"] and _verify_consistency(
            prev["tree_head"]["tree_size"], sth["tree_head"]["tree_size"], _hx(prev["tree_head"]["root_sha256"]),
            _hx(sth["tree_head"]["root_sha256"]), [_hx(x) for x in cp["proof"]])
    artifact = canon(sth["tree_head"])
    ad = os.path.join(d, "anchor")
    if os.path.exists(os.path.join(ad, "head.canon.json.ots")):
        out["anchors"]["opentimestamps"] = check_ots(open(os.path.join(ad, "head.canon.json.ots"), "rb").read(), artifact, headers)
    if os.path.exists(os.path.join(ad, "rekor_entry.json")):
        out["anchors"]["rekor"] = check_rekor(json.load(open(os.path.join(ad, "rekor_entry.json"))), artifact, pub_b64,
                                              open(os.path.join(ad, "rekor_pub.pem"), "rb").read())
    rd = lambda n: open(os.path.join(d, n), encoding="utf-8").read() if os.path.exists(os.path.join(d, n)) else ""
    blob = json.dumps(meta) + rd("CITATION.cff") + rd(".zenodo.json")
    out["metadata_placeholders"] = sorted(set(__import__("re").findall(r"A-COMPLETER-[A-Z]+", blob)))
    st = [a["status"] for a in out["anchors"].values()]
    keys = [k for k in ("manifest", "records_signed", "head_signature", "root_recomputed", "metadata_matches",
                        "previous_head_signature", "consistent_with_previous") if k in out]
    base = all(out[k] for k in keys)
    anchored = "verified" in st and "failed" not in st
    out["claim_state"] = ("rejected" if not base else "rejected_anchor" if "failed" in st
                          else "anchored_freeze" if anchored else "signed_freeze_not_anchored")
    out["ready_to_deposit"] = bool(base and anchored and not out["metadata_placeholders"])
    out["ok"] = bool(base and (anchored or not require_anchor) and "failed" not in st)
    return out


def _verify_consistency(m, n, old_root, new_root, proof):
    if m <= 0:   # taille 0 : aucune tête signée possible (comme la référence transparency-dev)
        return False
    if m != n and (not _hash32(old_root, new_root) or not all(_hash32(p) for p in proof)):
        return False
    if m == n:
        return old_root == new_root and not proof
    if m == 0 or m > n:
        return False
    proof = list(proof)
    if m & (m - 1) == 0:
        proof = [old_root] + proof
    if not proof:
        return False
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node_hash(c, fr), node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


# ---------- 8) alerte signée de changement d'outils ----------
ALERT_SCHEMA = "legion-mcp-tools-alert/1"


def _diff_fp(before, after):
    b, a = dict(before["per_tool_sha256"]), dict(after["per_tool_sha256"])
    return {"added": sorted(set(a) - set(b)), "removed": sorted(set(b) - set(a)),
            "modified": sorted(k for k in set(a) & set(b) if a[k] != b[k])}


def verify_alert(alert, pub_b64):
    """L'alerte embarque : enregistrement précédent, nouvel enregistrement, leurs preuves d'inclusion, la tête signée."""
    out = {"ok": False}
    try:
        body = {k: v for k, v in alert.items() if k != "signature_ed25519"}
        st, prev, new, sth = alert["statement"], alert["previous_record"], alert["new_record"], alert["sth"]
        out["alert_signature"] = (alert.get("schema") == ALERT_SCHEMA and st.get("key_id") == key_pin(pub_b64)
                                  and ed25519_ok(_b64(pub_b64), _b64(alert["signature_ed25519"]), canon(body)))
        out["records_signed"] = check_record(prev, pub_b64)[1] and check_record(new, pub_b64)[1]
        out["head_signature"] = check_sth(sth, pub_b64)
        out["inclusion"] = check_inclusion(prev, alert["previous_proof"], sth) and check_inclusion(new, alert["new_proof"], sth)
        out["chain"] = (prev["server_id"] == new["server_id"] == st["server_id"] and new["prev_leaf_index"] == prev["leaf_index"]
                        and prev["observed_at"] <= new["observed_at"])
        pa, na = prev["tools_fingerprint"].get("algo"), new["tools_fingerprint"].get("algo")
        out["same_fingerprint_algo"] = pa == na
        out["fingerprint_algos_comparable"] = fp_algos_comparable(pa, na)   # même algo, ou paire {v2, v3}
        if not out["fingerprint_algos_comparable"]:
            raise ValueError("empreintes de versions différentes : diff non recalculable")
        recomputed = _diff_fp(prev["tools_fingerprint"], new["tools_fingerprint"])
        out["change_matches"] = (recomputed == {k: st["change"][k] for k in ("added", "removed", "modified")}
                                 == {k: new["change"][k] for k in ("added", "removed", "modified")}
                                 and st["previous_tools_sha256"] == prev["tools_fingerprint"]["sha256"]
                                 and st["new_tools_sha256"] == new["tools_fingerprint"]["sha256"]
                                 and st["previous_tools_sha256"] != st["new_tools_sha256"])
        out["statement"] = st
        out["ok"] = all(out[k] for k in ("alert_signature", "records_signed", "head_signature", "inclusion", "chain", "change_matches"))
    except Exception as e:
        out["detail"] = "%s: %s" % (type(e).__name__, e)
    out["claim_state"] = "change_observed" if out["ok"] else "rejected"
    return out


def _emit(res):
    print(json.dumps(res, indent=1, ensure_ascii=False, sort_keys=True))
    print("RESULTAT:", "VALIDE" if res["ok"] else "INVALIDE")
    return 0 if res["ok"] else 1


UA = "mcp-tlog-verifier/1.0 (+https://legion-api.com/tlog/)"
DEFAULT_BASE = "https://tlog.legion-api.com/tlog/v0"
ROOT_KEY_URL = "https://legion-api.com/passport/legion-ed25519.pub"
ROOT_PIN = "a7c6a35b1c2c81d589a30c2ad628679bdea9da4139d49aa3c42cdde6e1c65036"


def _get(url, limit=20 * 1024 * 1024):
    """Téléchargement avec un User-Agent explicite (l'agent Python par défaut est refusé par Cloudflare : erreur 1010)."""
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json, */*"})
    with urllib.request.urlopen(req, timeout=30) as r:
        b = r.read(limit + 1)
    if len(b) > limit:
        raise ValueError("réponse trop grande : %s" % url)
    return b


def fetch_and_verify(leaf, pin=ROOT_PIN, base=DEFAULT_BASE, outdir=None, pubkey_file=None):
    """Télécharge enregistrement, preuve d'inclusion, tête signée, keyring (et .ots s'il existe), puis vérifie HORS LIGNE.
    La confiance repose sur l'empreinte épinglée de la clé racine (--pin), pas sur le serveur."""
    import os
    root = open(pubkey_file).read().strip() if pubkey_file else _get(ROOT_KEY_URL).decode().strip()
    if key_pin(root) != pin:
        return {"ok": False, "claim_state": "rejected", "error": "clé racine : empreinte %s != épinglée %s" % (key_pin(root), pin)}
    head = json.loads(_get(base + "/head"))
    n = head["sth"]["tree_head"]["tree_size"]
    rec = json.loads(_get("%s/records/%d" % (base, leaf)))
    proof = json.loads(_get("%s/proof/inclusion?leaf_index=%d&tree_size=%d" % (base, leaf, n)))
    keys = load_keyring(_get(base + "/keyring").decode("utf-8"), root)
    ots = None
    try:
        ots = _get("%s/anchor/%d/ots" % (base, n))
    except Exception:
        pass
    if outdir:
        os.makedirs(outdir, exist_ok=True)
        for name, obj in (("record.json", rec), ("proof.json", proof), ("sth.json", head["sth"])):
            json.dump(obj, open(os.path.join(outdir, name), "w"), indent=1, sort_keys=True, ensure_ascii=False)
        if ots:
            open(os.path.join(outdir, "head.ots"), "wb").write(ots)
    res = verify_all(rec, proof, head["sth"], keys, ots=ots, headers=None, require_anchor=False)
    res.update(server_id=rec.get("server_id"), leaf_index=leaf, tree_size=n, change=rec.get("change"),
               observed_at=rec.get("observed_at"), root_pin=pin,
               anchor_note="OTS téléchargé : statut indiqué sans en-têtes Bitcoin ; pour une date vérifiée, voir --btc-headers (votre nœud)."
               if ots else "aucun .ots publié pour cette tête")
    return res



# ---------- vérifications 100 % hors ligne (aucun appel réseau) ----------
def verify_consistency_offline(old_sth, new_sth, proof, keys):
    """Deux têtes signées + preuve RFC 9162 : signatures des deux têtes (keyring) et cohérence append-only."""
    o, n = old_sth["tree_head"], new_sth["tree_head"]
    out = {"old_head_signature": check_sth(old_sth, keys), "new_head_signature": check_sth(new_sth, keys),
           "old_size": o["tree_size"], "new_size": n["tree_size"]}
    p = proof.get("proof", proof) if isinstance(proof, dict) else proof
    out["consistent"] = _verify_consistency(o["tree_size"], n["tree_size"], _hx(o["root_sha256"]), _hx(n["root_sha256"]), [_hx(h) for h in p])
    out["ok"] = out["old_head_signature"] and out["new_head_signature"] and out["consistent"]
    return out


def verify_bundle_offline(bundle, keys, anchored_sth=None, anchor_consistency=None, ots=None, headers=None):
    """Bundle /tlog/v1/servers/{id}/latest : signature de l'enregistrement, inclusion dans la tête, signature de la tête.
    Option ancrage : tête ancrée (sth) + son .ots + en-têtes Bitcoin (votre nœud ou explorateur) + preuve de cohérence
    tête ancrée -> tête du bundle. Sans ces fichiers, l'ancrage est déclaré non vérifié (jamais supposé)."""
    rec, sth = bundle["record"], bundle["sth"]
    integ, sig, err = check_record(rec, keys)
    out = {"server_id": rec.get("server_id"), "leaf_index": rec.get("leaf_index"), "tree_size": sth["tree_head"]["tree_size"],
           "record_integrity": integ, "record_signature": sig, "head_signature": check_sth(sth, keys),
           "inclusion": check_inclusion(rec, bundle["inclusion"], sth), "error": err}
    out["ok"] = bool(integ and sig and out["head_signature"] and out["inclusion"])
    if anchored_sth is not None:
        a = verify_consistency_offline(anchored_sth, sth, anchor_consistency or [], keys) if anchored_sth["tree_head"]["tree_size"] != sth["tree_head"]["tree_size"] \
            else {"ok": anchored_sth == sth, "consistent": anchored_sth == sth}
        out["anchored_head"] = anchored_sth["tree_head"]["tree_size"]
        out["anchored_head_extends_to_bundle_head"] = bool(a.get("ok"))
        if ots is not None:
            st = check_ots(ots, canon(anchored_sth["tree_head"]), headers)
            out["anchor"] = st
        else:
            out["anchor"] = {"status": "not_checked", "reason": "no .ots given"}
    else:
        out["anchor"] = {"status": "not_checked", "reason": "no anchored head given"}
    return out


# ---------- tête contresignée par N témoins (C2SP signed-note + tlog-cosignature) ----------
def _vkey(v):
    name, kid_hex, b64 = v.strip().split("+", 2)
    raw = base64.b64decode(b64)
    return name, bytes.fromhex(kid_hex), raw[0], raw[1:]


def verify_witnessed(note_text, log_vkey, witness_vkeys, n_required):
    """La note est signée par la clé du journal (log_vkey) ET contresignée (cosignature/v1) par au moins n_required clés
    parmi witness_vkeys, la liste des témoins que VOUS jugez indépendants. Clé inconnue : ignorée. Clé connue qui échoue :
    rejet (règle C2SP signed-note). Renvoie le détail."""
    out = {"ok": False, "log_signature": False, "witnesses_valid": [], "required": n_required}
    try:
        body, rest = note_text.split("\n\n", 1)
        body += "\n"
        lines = [l for l in rest.split("\n") if l.strip()]
        lname, lkid, ltype, lpub = _vkey(log_vkey)
        ws = {}
        for v in witness_vkeys:
            n, k, t, p = _vkey(v)
            if t == 0x04:
                ws[n] = (k, p)
        H_ = lambda b: hashlib.sha256(b).digest()
        for l in lines:
            if not l.startswith("\u2014 "):
                return dict(out, error="ligne de signature malformée")
            name, b64 = l[2:].rsplit(" ", 1)
            raw = base64.b64decode(b64, validate=True)
            if name == lname and raw[:4] == lkid and ltype == 0x01:
                out["log_signature"] = ed25519_ok(lpub, raw[4:], body.encode())
            elif name in ws:
                k, p = ws[name]
                if raw[:4] != k or len(raw) != 76 or H_(name.encode() + b"\n" + b"\x04" + p)[:4] != k:
                    return dict(out, error="cosignature du témoin connu %s : identifiant de clé incohérent" % name)
                ts = struct.unpack(">Q", raw[4:12])[0]
                if not ed25519_ok(p, raw[12:], ("cosignature/v1\ntime %d\n" % ts).encode() + body.encode()):
                    return dict(out, error="cosignature invalide du témoin connu %s" % name)
                out["witnesses_valid"].append(name)
        lines0 = body.split("\n")
        out.update(origin=lines0[0], tree_size=int(lines0[1]), root_sha256=base64.b64decode(lines0[2]).hex())
        out["witnesses_valid"] = sorted(set(out["witnesses_valid"]))
        out["ok"] = out["log_signature"] and len(out["witnesses_valid"]) >= n_required
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    return out

def main():
    ld = lambda p: json.load(open(p, encoding="utf-8")) if p else None
    if len(sys.argv) > 1 and sys.argv[1] == "fetch":
        ap = argparse.ArgumentParser(prog="verify_tlog.py fetch",
                                     description="Télécharge (User-Agent mcp-tlog-verifier/1.0) puis vérifie hors ligne une feuille du journal.")
        ap.add_argument("--leaf", type=int, required=True)
        ap.add_argument("--pin", default=ROOT_PIN, help="empreinte SHA-256 épinglée de la clé racine LEGION")
        ap.add_argument("--pubkey", help="clé racine locale (base64) au lieu de la télécharger")
        ap.add_argument("--base", default=DEFAULT_BASE)
        ap.add_argument("--out", help="dossier où garder les fichiers téléchargés")
        a = ap.parse_args(sys.argv[2:])
        import urllib.error
        try:
            res = fetch_and_verify(a.leaf, a.pin, a.base, a.out, a.pubkey)
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            # Téléchargement impossible (réseau, limite de débit 429, serveur absent) : ce n'est PAS un verdict sur la preuve.
            code = getattr(e, "code", None)
            print(json.dumps({"ok": None, "error": "téléchargement impossible : %s%s" % (type(e).__name__, " HTTP %s" % code if code else ""),
                              "hint": "réessayer plus tard (limite 60 requêtes/min/IP) ou vérifier des fichiers locaux sans 'fetch'"},
                             ensure_ascii=False))
            print("RESULTAT: ERREUR_RESEAU")
            return 3
        print(json.dumps(res, indent=1, ensure_ascii=False, sort_keys=True))
        print("RESULTAT:", "VALIDE" if res.get("ok") else "INVALIDE")
        return 0 if res.get("ok") else 1
    if len(sys.argv) > 1 and sys.argv[1] == "witnessed":
        ap = argparse.ArgumentParser(prog="verify_tlog.py witnessed", description="Tête signée par le journal ET contresignée par >= N témoins de VOTRE liste (hors ligne).")
        ap.add_argument("note", help="note C2SP (ex. /tlog/v1/checkpoint/<taille>)")
        ap.add_argument("--log-vkey", required=True, help="clé du journal au format vkey (log_vkey de /tlog/v1/witnesses, à épingler)")
        ap.add_argument("--witness-vkeys", required=True, help="fichier : une vkey de témoin par ligne, ceux que VOUS jugez indépendants")
        ap.add_argument("--min", type=int, default=1)
        a = ap.parse_args(sys.argv[2:])
        res = verify_witnessed(open(a.note, encoding="utf-8").read(), a.log_vkey,
                               [l for l in open(a.witness_vkeys) if l.strip() and not l.startswith("#")], a.min)
        print(json.dumps(res, indent=1, ensure_ascii=False, sort_keys=True)); print("RESULTAT:", "VALIDE" if res["ok"] else "INVALIDE")
        return 0 if res["ok"] else 1
    if len(sys.argv) > 1 and sys.argv[1] in ("consistency", "bundle"):
        sub = sys.argv[1]
        ap = argparse.ArgumentParser(prog="verify_tlog.py " + sub, description="Vérification 100 % hors ligne (aucun appel réseau).")
        ap.add_argument("--pubkey", required=True, help="clé racine LEGION (base64) ; son empreinte doit valoir --pin")
        ap.add_argument("--pin", default=ROOT_PIN)
        ap.add_argument("--keyring", required=True, help="keyring.jsonl (sous-clés approuvées par la racine)")
        if sub == "consistency":
            ap.add_argument("--old", required=True); ap.add_argument("--new", required=True); ap.add_argument("--proof", required=True)
        else:
            ap.add_argument("bundle"); ap.add_argument("--anchored-sth"); ap.add_argument("--anchor-consistency")
            ap.add_argument("--ots"); ap.add_argument("--btc-headers")
        a = ap.parse_args(sys.argv[2:])
        root = open(a.pubkey).read().strip()
        if key_pin(root) != a.pin:
            print(json.dumps({"ok": False, "error": "clé racine : empreinte %s != épinglée %s" % (key_pin(root), a.pin)})); print("RESULTAT: INVALIDE"); return 1
        keys = load_keyring(open(a.keyring, encoding="utf-8").read(), root)
        if sub == "consistency":
            res = verify_consistency_offline(ld(a.old).get("sth", ld(a.old)), ld(a.new).get("sth", ld(a.new)), ld(a.proof), keys)
        else:
            an = ld(a.anchored_sth); an = an.get("sth", an) if an else None
            ac = ld(a.anchor_consistency); ac = ac.get("proof", ac) if isinstance(ac, dict) else ac
            res = verify_bundle_offline(ld(a.bundle), keys, an, ac, open(a.ots, "rb").read() if a.ots else None, ld(a.btc_headers))
        print(json.dumps(res, indent=1, ensure_ascii=False, sort_keys=True, default=str))
        print("RESULTAT:", "VALIDE" if res.get("ok") else "INVALIDE")
        return 0 if res.get("ok") else 1
    if len(sys.argv) > 1 and sys.argv[1] == "alert":
        ap = argparse.ArgumentParser(prog="verify_tlog.py alert")
        ap.add_argument("alert"); ap.add_argument("--pubkey", required=True)
        a = ap.parse_args(sys.argv[2:])
        return _emit(verify_alert(ld(a.alert), open(a.pubkey).read().strip()))
    if len(sys.argv) > 1 and sys.argv[1] in ("receipt", "badge", "freeze"):
        sub = sys.argv[1]
        ap = argparse.ArgumentParser(prog="verify_tlog.py " + sub)
        if sub == "receipt":
            ap.add_argument("--receipt", required=True, help="une ligne de receipts.jsonl (fichier JSON)")
            ap.add_argument("--root", required=True, help="ROOT.json")
        elif sub == "badge":
            ap.add_argument("svg")
            ap.add_argument("--record")
            ap.add_argument("--proof")
            ap.add_argument("--sth")
            ap.add_argument("--now")
            ap.add_argument("--max-age-days", type=float)
            ap.add_argument("--keyring", help="keyring.jsonl du journal (sous-clés approuvées par la clé --pubkey)")
        else:
            ap.add_argument("dir")
            ap.add_argument("--keyring", help="keyring.jsonl (sous-clés approuvées par la clé --pubkey)")
        if sub != "receipt":
            ap.add_argument("--pubkey", required=True)
        ap.add_argument("--ots")
        ap.add_argument("--btc-headers")
        ap.add_argument("--no-anchor", action="store_true")
        a = ap.parse_args(sys.argv[2:])
        if sub == "receipt":
            return _emit(verify_receipt_root(ld(a.receipt), ld(a.root), open(a.ots, "rb").read() if a.ots else None,
                                             ld(a.btc_headers), require_anchor=not a.no_anchor))
        pub = open(a.pubkey).read().strip()
        if sub in ("badge", "freeze") and a.keyring:
            pub = load_keyring(open(a.keyring, encoding="utf-8").read(), pub)
        if sub == "badge":
            return _emit(verify_badge(open(a.svg, encoding="utf-8").read(), pub, ld(a.record), ld(a.proof), ld(a.sth),
                                      a.now, a.max_age_days))
        return _emit(verify_freeze(a.dir, pub, ld(a.btc_headers), require_anchor=not a.no_anchor))
    return _main_record()


def _main_record():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--record", required=True)
    ap.add_argument("--proof", required=True)
    ap.add_argument("--sth", required=True)
    ap.add_argument("--pubkey", required=True, help="clé publique LEGION, base64 des 32 octets bruts")
    ap.add_argument("--ots")
    ap.add_argument("--btc-headers")
    ap.add_argument("--rekor-entry")
    ap.add_argument("--rekor-pubkey")
    ap.add_argument("--no-anchor", action="store_true", help="vérifier 1-3 seulement (horodatage externe non exigé)")
    ap.add_argument("--keyring", help="keyring.jsonl du journal : clés résolues par key_id, ancrées sur --pubkey (racine)")
    a = ap.parse_args()
    ld = lambda p: json.load(open(p, encoding="utf-8"))
    pub = open(a.pubkey).read().strip()
    if a.keyring:
        pub = load_keyring(open(a.keyring, encoding="utf-8").read(), pub)
    res = verify_all(ld(a.record), ld(a.proof), ld(a.sth), pub,
                     ots=open(a.ots, "rb").read() if a.ots else None,
                     headers=ld(a.btc_headers) if a.btc_headers else None,
                     rekor_entry=ld(a.rekor_entry) if a.rekor_entry else None,
                     rekor_pub_pem=open(a.rekor_pubkey, "rb").read() if a.rekor_pubkey else None,
                     require_anchor=not a.no_anchor)
    print(json.dumps(res, indent=1, ensure_ascii=False, sort_keys=True))
    print("RESULTAT:", "VALIDE" if res["ok"] else "INVALIDE")
    return 0 if res["ok"] else 1


def _safe(fn):
    """Point d'entrée : toute entrée illisible (JSON tronqué, fichier absent, structure inattendue) donne un refus propre,
    code 1, jamais une trace Python ni un succès."""
    try:
        return fn()
    except SystemExit:
        raise
    except Exception as e:
        print(json.dumps({"ok": False, "claim_state": "rejected", "error": "%s: %s" % (type(e).__name__, str(e)[:200])},
                         ensure_ascii=False))
        print("RESULTAT: INVALIDE")
        return 1




# ---------- durcissement (fuzzing 2026-10-09) : une entrée inexploitable donne un refus propre, jamais une exception ----------
def verify_all(*a, **k):
    try:
        return _verify_all_impl(*a, **k)
    except Exception as e:
        return {"ok": False, "claim_state": "rejected", "error": "entrée inexploitable : %s: %s" % (type(e).__name__, str(e)[:160]),
                "anchors": {}, "external_timestamp": False}


def verify_badge(*a, **k):
    try:
        return _verify_badge_impl(*a, **k)
    except Exception as e:
        return {"ok": False, "claim_state": "rejected", "detail": "badge inexploitable : %s: %s" % (type(e).__name__, str(e)[:160])}


def verify_freeze(*a, **k):
    try:
        return _verify_freeze_impl(*a, **k)
    except Exception as e:
        return {"ok": False, "claim_state": "rejected", "ready_to_deposit": False, "anchors": {},
                "error": "gel inexploitable : %s: %s" % (type(e).__name__, str(e)[:160])}


def check_ots(*a, **k):
    try:
        return _check_ots_impl(*a, **k)
    except Exception as e:
        return {"status": "failed", "detail": "preuve .ots ou en-têtes inexploitables : %s: %s" % (type(e).__name__, str(e)[:160])}

if __name__ == "__main__":
    sys.exit(_safe(main))
