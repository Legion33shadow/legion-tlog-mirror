# verify-badge-go

Independent re-check of a LEGION MCP log record ("matches recorded leaf N"), written in Go.

- Written by LEGION on third-party primitives: `golang.org/x/mod/sumdb/note` (signed C2SP checkpoint),
  `golang.org/x/mod/sumdb/tlog` (RFC 6962 inclusion proof), `github.com/gowebpki/jcs` (RFC 8785),
  Go stdlib Ed25519 and SHA-256. No LEGION code is imported. **It is not a third-party audit.**
- Scope: records whose tools/list fingerprint is v2 or v3. Records in the older v1 format (the log's first days)
  and leaves signed by the root key are not handled; use `verify_tlog.py` in this repository for those.
- Both note names are accepted through the vkey you pass: the historical `legion-mcp-tlog+cfc0988f+…`
  and the origin name `tlog.legion-api.com/mcp/v0+2a81e496+…` (same key).

## Build

```sh
go build -trimpath -o verify-badge-go .
```

Built with Go 1.27.3 (linux/amd64), `x/mod v0.40.0`, `gowebpki/jcs v1.0.2` (pinned in `go.sum`).
With that toolchain the binary's SHA-256 starts with `387c2ee16b618385`.

## Use

```sh
./verify-badge-go CASE_DIR   # last line: VERDICT : VALIDE  (exit 0)  or  VERDICT : INVALIDE  (exit 1)
```

`CASE_DIR` holds `claim.json record.json proof.json sth.json keyring.jsonl checkpoint.note log_vkey.txt tools.json`
(and optionally `badge.svg`). Compare the root key pin (SHA-256 of the first keyring entry's public key) with a copy
obtained out of band before trusting the verdict.

Checks, in order: pinned root key and keyring chain → signed C2SP checkpoint → signed JSON head equal to the checkpoint
→ signed leaf → tools/list fingerprint recomputed from the archived tool list → inclusion proof → signed badge, if present.

What this does not prove: when a change happened between two probes, what other clients are served, or that a server
is safe. Ordering rests on LEGION-signed heads; no external witness cosigns them today.

## Change log

- 2026-10-20: the vkey is split with `SplitN(vkey, "+", 3)`. The previous `Split` took the last `+`-separated part,
  which breaks when the base64 key contains `+`. The current log key does not contain `+`, so the bug was latent.
