# `freerdp_vectors/` — what FreeRDP's key derivation, MAC and key update produce

`vectors.txt` is the expected value for `justrdp_security::standard`. No published vector covers
the session keys: `[MS-RDPBCGR]` 4.1 dumps a whole encrypted connection, but its client random is
not in the document and 4.8's private key is not that server's. These come from a second
implementation instead.

`run.sh` fetches `libfreerdp/core/security.c` at a pinned commit, removes its `#include` lines, and
compiles it unchanged against `shim.h`, which supplies `rdpRdp`, the settings it reads and the
digests over OpenSSL. `harness.c` then drives one client and one server. FreeRDP's own receiver
checks every packet, and a disagreement fails the run.

The output is not committed in full: 8200 packets each way at three strengths. `vectors.txt` holds:

- `method=` the encryption method, with the first keys;
- `c2s` and `s2c` the signature and ciphertext of packets 0, 1, 2, 4095 to 4098 and 8192;
- `md5_all=` the MD5 over every signature and ciphertext in that direction.

Packet `i` is `1 + i % 31` bytes of `(i + j) & 0xff`, and every third MAC is salted. So the file
covers each strength, both directions, both MACs, and two key updates. It does not cover FIPS,
which this layer does not implement.

The shim is the part that is ours. It replaces no logic of `security.c`, but the digests and RC4
behind it are OpenSSL, not winpr.
