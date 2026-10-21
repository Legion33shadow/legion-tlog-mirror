// verify-badge-go — vérifieur INDÉPENDANT d'un badge LEGION « recorded leaf N ».
// Implémentation indépendante écrite par LEGION, pas un audit tiers.
// Aucune ligne de code LEGION n'est importée : bibliothèques externes seulement —
// golang.org/x/mod/sumdb/note (checkpoint C2SP signé), golang.org/x/mod/sumdb/tlog (preuve d'inclusion RFC 6962),
// github.com/gowebpki/jcs (RFC 8785), crypto/ed25519 et crypto/sha256 (stdlib).
//
// Usage : verify-badge-go CASE_DIR
// CASE_DIR : claim.json, record.json, proof.json, sth.json, keyring.jsonl, checkpoint.note, log_vkey.txt, tools.json
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gowebpki/jcs"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const label = "implémentation indépendante écrite par LEGION, pas un audit tiers"

var dir string

func fail(step, f string, a ...any) {
	fmt.Printf("  [ÉCHEC] %s : %s\n", step, fmt.Sprintf(f, a...))
	fmt.Printf("VERDICT : INVALIDE (%s)\n", label)
	os.Exit(1)
}
func pass(step, f string, a ...any) { fmt.Printf("  [ok] %s : %s\n", step, fmt.Sprintf(f, a...)) }

func read(name string) []byte {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		fail("lecture", "%s : %v", name, err)
	}
	return b
}

func decode(name string, b []byte) any {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		fail("lecture", "%s : JSON illisible : %v", name, err)
	}
	return v
}

func canon(step string, v any) []byte {
	raw, err := json.Marshal(v)
	if err == nil {
		raw, err = jcs.Transform(raw)
	}
	if err != nil {
		fail(step, "JCS : %v", err)
	}
	return raw
}

func b64(step, s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		fail(step, "base64 invalide")
	}
	return b
}

func pin(pub []byte) string { h := sha256.Sum256(pub); return hex.EncodeToString(h[:]) }

func without(m map[string]any, keys ...string) map[string]any {
	o := map[string]any{}
	for k, v := range m {
		o[k] = v
	}
	for _, k := range keys {
		delete(o, k)
	}
	return o
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func num(m map[string]any, k string) int64 {
	n, ok := m[k].(json.Number)
	if !ok {
		return -1
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil {
		return -1
	}
	return i
}

// falsy au sens de la règle d'empreinte (« x or défaut ») : absent, null, "", false, 0, {} ou [].
func falsy(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case bool:
		return !x
	case json.Number:
		f, err := x.Float64()
		return err == nil && f == 0
	case map[string]any:
		return len(x) == 0
	case []any:
		return len(x) == 0
	}
	return false
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage : verify-badge-go CASE_DIR")
		os.Exit(2)
	}
	dir = os.Args[1]
	fmt.Printf("verify-badge-go — %s\n", label)
	claim := decode("claim.json", read("claim.json")).(map[string]any)
	fmt.Printf("badge : %s — « %s »\n", str(claim, "server_id"), str(claim, "badge_message"))

	// 1. Keyring : racine épinglée, chaîne de hachage, approbation par la racine, preuve de possession.
	var root ed25519.PublicKey
	keys := map[string]ed25519.PublicKey{}
	revoked := map[string]bool{}
	prev := ""
	for n, line := range strings.Split(strings.TrimSpace(string(read("keyring.jsonl"))), "\n") {
		e := decode("keyring.jsonl", []byte(line)).(map[string]any)
		body := canon("keyring", without(e, "hash", "self_sig", "endorsement_sig"))
		h := sha256.Sum256(body)
		if n == 0 {
			root = b64("keyring", str(e, "public_key_b64"))
			if pin(root) != str(claim, "root_pin_sha256") {
				fail("keyring", "la racine ne correspond pas à l'empreinte épinglée")
			}
			prev = str(e, "hash")
			continue
		}
		if str(e, "prev_hash") != prev || str(e, "hash") != hex.EncodeToString(h[:]) {
			fail("keyring", "chaîne rompue à l'entrée %d", n)
		}
		if !ed25519.Verify(root, body, b64("keyring", str(e, "endorsement_sig"))) {
			fail("keyring", "entrée %d non approuvée par la racine", n)
		}
		switch str(e, "type") {
		case "key_register":
			pub := ed25519.PublicKey(b64("keyring", str(e, "public_key_b64")))
			if str(e, "key_id") != "k1:"+pin(pub)[:32] || !ed25519.Verify(pub, body, b64("keyring", str(e, "self_sig"))) {
				fail("keyring", "sous-clé invalide à l'entrée %d", n)
			}
			keys[pin(pub)] = pub
		case "key_revoke":
			revoked[str(e, "key_id")] = true
		default:
			fail("keyring", "type inconnu à l'entrée %d", n)
		}
		prev = str(e, "hash")
	}
	pass("keyring", "racine épinglée %s…, %d sous-clés approuvées", str(claim, "root_pin_sha256")[:16], len(keys))

	rec := decode("record.json", read("record.json")).(map[string]any)
	logPin := str(rec, "key_id")
	logKey, ok := keys[logPin]
	if !ok || revoked["k1:"+logPin[:32]] {
		fail("clé", "key_id de la feuille absent du keyring ou révoqué")
	}

	// 2. Checkpoint C2SP signé (note) : la clé du vkey doit être la sous-clé du keyring.
	vkey := strings.TrimSpace(string(read("log_vkey.txt")))
	parts := strings.SplitN(vkey, "+", 3) // nom+keyid+base64 : le base64 peut contenir « + » (correctif 2026-10-20)
	if len(parts) != 3 {
		fail("vkey", "format nom+keyid+clé attendu")
	}
	vk := b64("vkey", parts[2])
	if len(vk) != 33 || vk[0] != 1 || !bytes.Equal(vk[1:], logKey) {
		fail("vkey", "la clé du vkey n'est pas la sous-clé du journal du keyring")
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		fail("vkey", "%v", err)
	}
	nt, err := note.Open(read("checkpoint.note"), note.VerifierList(v))
	if err != nil {
		fail("checkpoint", "note : %v", err)
	}
	lines := strings.Split(nt.Text, "\n")
	size, _ := strconv.ParseInt(lines[1], 10, 64)
	cpRoot := b64("checkpoint", lines[2])
	if len(cpRoot) != 32 {
		fail("checkpoint", "racine malformée")
	}
	pass("checkpoint", "note signée valide (x/mod/sumdb/note), origine %s, taille %d", lines[0], size)

	// 3. Tête JSON signée : Ed25519 sur JCS(tree_head), même taille et même racine que le checkpoint.
	sth := decode("sth.json", read("sth.json")).(map[string]any)
	head := sth["tree_head"].(map[string]any)
	if str(head, "issuer_pin_sha256") != logPin || !ed25519.Verify(logKey, canon("sth", head), b64("sth", str(sth, "signature_ed25519"))) {
		fail("tête", "signature de la tête invalide")
	}
	if num(head, "tree_size") != size || str(head, "root_sha256") != hex.EncodeToString(cpRoot) {
		fail("tête", "tête JSON ≠ checkpoint (taille ou racine)")
	}
	pass("tête", "signature valide, taille %d, racine %s… = checkpoint", size, str(head, "root_sha256")[:16])

	// 4. Feuille : signature, même feuille que le badge.
	if !ed25519.Verify(logKey, canon("feuille", without(rec, "signature_ed25519")), b64("feuille", str(rec, "signature_ed25519"))) {
		fail("feuille", "signature de la feuille invalide")
	}
	if str(rec, "server_id") != str(claim, "server_id") || num(rec, "leaf_index") != num(claim, "leaf_index") {
		fail("feuille", "feuille %d (%s) ≠ badge (leaf %d, %s)", num(rec, "leaf_index"), str(rec, "server_id"), num(claim, "leaf_index"), str(claim, "server_id"))
	}
	pass("feuille", "signature valide, leaf %d = badge, serveur identique", num(rec, "leaf_index"))

	// 5. Empreinte tools/list v2 recalculée depuis la réponse brute archivée.
	fp := rec["tools_fingerprint"].(map[string]any)
	if str(fp, "algo") != str(claim, "fingerprint_algo") {
		fail("empreinte", "algo %q ≠ v2", str(fp, "algo"))
	}
	tools, ok := decode("tools.json", read("tools.json")).([]any)
	if !ok {
		fail("empreinte", "tools.json n'est pas une liste")
	}
	norm := []map[string]any{}
	seen := map[string]bool{}
	for _, t := range tools {
		m, ok := t.(map[string]any)
		name, ok2 := m["name"].(string)
		if !ok || !ok2 || seen[name] {
			fail("empreinte", "outil sans nom texte ou nom dupliqué")
		}
		seen[name] = true
		d, s := m["description"], m["inputSchema"]
		if falsy(d) {
			d = ""
		}
		if falsy(s) {
			s = map[string]any{}
		}
		norm = append(norm, map[string]any{"name": name, "description": d, "inputSchema": s})
	}
	sort.Slice(norm, func(i, j int) bool { return norm[i]["name"].(string) < norm[j]["name"].(string) })
	sum := sha256.Sum256(canon("empreinte", norm))
	got := hex.EncodeToString(sum[:])
	if got != str(fp, "sha256") || got != str(claim, "tools_sha256") {
		fail("empreinte", "recalculée %s… ≠ feuille %s… / badge %s…", got[:16], str(fp, "sha256")[:16], str(claim, "tools_sha256")[:16])
	}
	pass("empreinte", "v2 recalculée = feuille = badge : %s (%d outils)", got, len(norm))

	// 6. Inclusion : racine recalculée depuis la feuille et le chemin d'audit (x/mod/sumdb/tlog).
	pr := decode("proof.json", read("proof.json")).(map[string]any)
	if num(pr, "leaf_index") != num(rec, "leaf_index") || num(pr, "tree_size") != size {
		fail("inclusion", "preuve pour une autre feuille ou une autre taille")
	}
	var proof tlog.RecordProof
	for _, x := range pr["audit_path"].([]any) {
		b, err := hex.DecodeString(x.(string))
		if err != nil || len(b) != 32 {
			fail("inclusion", "chemin d'audit malformé")
		}
		var h tlog.Hash
		copy(h[:], b)
		proof = append(proof, h)
	}
	var r tlog.Hash
	copy(r[:], cpRoot)
	if err := tlog.CheckRecord(proof, size, r, num(rec, "leaf_index"), tlog.RecordHash(canon("inclusion", rec))); err != nil {
		fail("inclusion", "%v", err)
	}
	pass("inclusion", "racine recalculée = racine signée (%d hachés, x/mod/sumdb/tlog)", len(proof))

	// 7. Badge SVG (facultatif) : attestation signée intégrée, même feuille, même empreinte, même tête.
	if svg, err := os.ReadFile(filepath.Join(dir, "badge.svg")); err == nil {
		s := string(svg)
		const tag = `<metadata id="legion-attestation">`
		i := strings.Index(s, tag)
		j := strings.Index(s, "</metadata>")
		if i < 0 || j < i {
			fail("badge.svg", "aucune attestation LEGION dans le SVG")
		}
		doc := decode("badge.svg", b64("badge.svg", s[i+len(tag):j])).(map[string]any)
		st, ok := doc["statement"].(map[string]any)
		if !ok || str(st, "schema") != "legion-mcp-badge/0.1" || str(st, "key_id") != logPin ||
			!ed25519.Verify(logKey, canon("badge.svg", st), b64("badge.svg", str(doc, "signature_ed25519"))) {
			fail("badge.svg", "déclaration signée invalide")
		}
		if num(st, "record_leaf_index") != num(rec, "leaf_index") || str(st, "tools_sha256") != got ||
			num(st, "tree_size") != size || str(st, "root_sha256") != hex.EncodeToString(cpRoot) {
			fail("badge.svg", "la déclaration signée ne correspond pas à la feuille, à l'empreinte ou à la tête vérifiées")
		}
		pass("badge.svg", "déclaration signée valide : leaf %d, empreinte et tête identiques", num(st, "record_leaf_index"))
	} else {
		fmt.Println("  [—] badge.svg : absent, non testé")
	}
	fmt.Printf("VERDICT : VALIDE (%s)\n", label)
}
