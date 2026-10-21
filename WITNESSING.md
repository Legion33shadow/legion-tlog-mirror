# Witness the LEGION MCP log in 5 minutes

> **Status: prototype, testing only, and can be withdrawn.** The LEGION MCP transparency log is run by one operator. It has
> **no independent witness yet**. Its only cosignature today is `legion-self.legion-api.com`, which belongs to the same
> operator and is **not** a witness. If you witness this log, you can stop at any time. The log can also be withdrawn,
> with notice in this file.

## What the log is
An append-only Merkle log (RFC 6962 / RFC 9162 hashing) of public observations of MCP servers. It publishes a C2SP
`tlog-checkpoint` signed note, and it pushes that note to witnesses with C2SP `tlog-witness` (`add-checkpoint`).

## Parameters to add to your witness
| field | value |
|---|---|
| origin | `tlog.legion-api.com/mcp/v0` |
| log vkey (key name = origin, recommended) | `tlog.legion-api.com/mcp/v0+2a81e496+AfE4wYMFGnFlhk/ON4Qnf98XNiOTUJNJY3y08DAv9hxk` |
| log vkey (historical name, same Ed25519 key) | `legion-mcp-tlog+cfc0988f+AfE4wYMFGnFlhk/ON4Qnf98XNiOTUJNJY3y08DAv9hxk` |
| checkpoint (pull, read-only) | `https://tlog.legion-api.com/tlog/v1/checkpoint` and `/tlog/v1/checkpoint/{tree_size}` |
| consistency proof | `https://tlog.legion-api.com/tlog/v1/proof/consistency?old_size=A&new_size=B` |
| transport | **push**: the log POSTs to **your** `/add-checkpoint` (c2sp.org/tlog-witness). The log has no add-checkpoint endpoint of its own. |
| rate | measured from 2026-10-15 to 2026-10-21: 3 to 5 new signed heads per day. Planned: at most one push per new head, so under 10 requests per day. |

Configure **one** of the two vkeys. Both verify the same signature bytes. Since tree size 30914, every note carries one
signature line under each name.

## Exact note format (real, tree size 32091)
```
tlog.legion-api.com/mcp/v0
32091
Iuc/BbdYB10J3kucFyrV7767BzTHlwq+/hi3H47XOCg=

— tlog.legion-api.com/mcp/v0 KoHklmzoIY7Rfy1+Fudlx9S75dB17acfe2bgRVNHN6V93aUl4WVwVCjKCrgfhcCt+L6JzNknSwMNbqGglpr7onrvDgI=
— legion-mcp-tlog z8CYj2zoIY7Rfy1+Fudlx9S75dB17acfe2bgRVNHN6V93aUl4WVwVCjKCrgfhcCt+L6JzNknSwMNbqGglpr7onrvDgI=
— legion-self.legion-api.com dwhzIgAAAABq2Pod4IAtaSE8oZyziE5vQVxl+EOzZUIa/yiLjsaFHzbsv94njGIwSPA4npTrXhDuGuBfrv5vV9hV0/qVQUMS8h/oAQ==
```
The body has three lines: origin, decimal tree size, and the base64 root. These are followed by an empty line and the
signature lines (`— ` U+2014 + space + key name + base64 of the 4-byte key ID followed by the signature). The third line
is the operator's own cosignature/v1, which your witness ignores. Witness cosignatures that LEGION has verified are
appended to `/tlog/v1/checkpoint`.

## Verify the log signature yourself (offline-checkable, one dependency: `cryptography`)
```python
#!/usr/bin/env python3
"""Vérifie la signature du journal LEGION MCP sur sa dernière note C2SP. Dépendance : cryptography. Usage : python3 verify_legion_checkpoint.py"""
import base64, hashlib, sys, urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
VKEY = "tlog.legion-api.com/mcp/v0+2a81e496+AfE4wYMFGnFlhk/ON4Qnf98XNiOTUJNJY3y08DAv9hxk"
URL = "https://tlog.legion-api.com/tlog/v1/checkpoint"
name, kid, b64 = VKEY.split("+", 2)
raw = base64.b64decode(b64)
assert raw[0] == 1 and hashlib.sha256(name.encode() + b"\n" + raw).digest()[:4].hex() == kid, "vkey incohérente"
note = urllib.request.urlopen(urllib.request.Request(URL, headers={"User-Agent": "verify-legion-checkpoint"}), timeout=30).read().decode()
body, sigs = note.split("\n\n", 1)
body += "\n"
for line in sigs.splitlines():
    _, n, s = line.split(" ")
    sig = base64.b64decode(s)
    if n == name and sig[:4].hex() == kid:
        Ed25519PublicKey.from_public_bytes(raw[1:]).verify(sig[4:], body.encode())   # lève InvalidSignature si faux
        print("OK", body.splitlines()[0], "tree_size", body.splitlines()[1], "root", body.splitlines()[2])
        sys.exit(0)
sys.exit("FAIL : aucune signature au nom %s" % name)
```
Expected output: `OK tlog.legion-api.com/mcp/v0 tree_size <n> root <base64>`. A wrong key or a modified body is rejected.

## Interop evidence (local, reproducible)
- LEGION's push client was tested against two independent witness implementations, both run on 127.0.0.1 with
  throwaway keys:
  - `litewitness` from filippo.io/torchwood v0.10.0;
  - a minimal witness built only from `github.com/transparency-dev/witness` at commit ea1ba4f57591, with Go 1.27.3.
- litewitness: frozen public notes 26501 → 27212 → 27743 (17/17, 2026-10-19), plus a dual-name note (HTTP 200,
  2026-10-20).
- transparency-dev witness: frozen public notes 30914 → 32091 with the consistency proof between them, tested against
  both log vkeys (12/12, 2026-10-22). It accepted a first push, accepted an extension backed by an RFC 6962
  consistency proof, and returned a valid cosignature/v1. It rejected the following:
  - rollback (409);
  - a modified body (403);
  - an unknown origin (404).
- None of this is an independent witness of the live log. It shows only that the format and protocol interoperate.

## To start witnessing
Contact: open an issue at https://github.com/Legion33shadow/legion-tlog-mirror/issues. Send your witness `name`, its
cosignature/v1 vkey, its `add-checkpoint` URL, and who operates it. LEGION will:
1. send one manual push;
2. verify your cosignature;
3. list you in `/tlog/v1/witnesses` only after the steps above, with a public evidence link.

`/tlog/v1/witnesses` currently shows `"witnesses": []`.

## Limits
- One operator, one log key, no HSM.
- There is no automated cadence yet: pushes are manual until a witness accepts.
- Pre-30914 notes carry only the historical key name.
- Testing log: entries are observations, not certifications of any MCP server.
