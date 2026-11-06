# 0020 — Standard RDP Security exists, off unless the host opts in

- Status: Accepted
- Date: 2026-11-06
- Kind: **judgement**. The maintainer chose it; a better derivation does not reopen it.
- Issue: #596

## Context

justrdp refused Standard RDP Security, the RC4 protection of `[MS-RDPBCGR]` 5.3, from its first
slice. The refusal has a line in a commit (`522b18a`, "Rejects standard RC4"), a list entry in
ADR-0009's description of what the code already did, and comments citing ADR-0002. ADR-0002 does not
contain it: its text has no `rc4`, `standard rdp` or `standard security`. So nothing recorded why,
and this record reverses a behaviour, not an argued decision.

The reason to reverse it is a consumer. A host that does not run justrdp's session terminates a
client's TLS on one side and relays that client's PDUs to the server on the other. It has to reach
servers that accept only this protection.

What #596 measured on Windows Server 2019 with `SecurityLayer=0`, `UserAuthentication=0`: `mstsc`
reached the desktop after an identity warning; IronRDP 0.12's connector, requesting TLS and CredSSP,
got `enhanced RDP security not allowed by server`.

## Decision

1. **justrdp implements Standard RDP Security.** The layer is `justrdp_security::standard`: sans-IO,
   usable with no connect machine and no session, and with no codec in its dependency tree. It is
   client side only.
2. **It stays off unless the host asks for it.** The default request does not change. A server that
   selects this protection for a host that did not ask is refused, which is ADR-0009's strict side.
3. **A wrong MAC is a failure**, on every path, as 5.3.6.1 says. FreeRDP downgrades it to a warning
   (`rdp_decrypt` in `libfreerdp/core/rdp.c`, with the comment that the mechanism cannot protect
   against a man in the middle anyway). That argument is true and does not change this: the check
   catches a desynchronised stream, and a server that fails it has not been seen.
4. **An unencrypted PDU is refused at a level where the server must encrypt**, except the four whose
   own sections allow it at any level: licensing (2.2.1.12), Auto-Detect Request (2.2.14.3), Initiate
   Multitransport Request (2.2.15.1) and Heartbeat (2.2.16.1). The layer reads this from the flags,
   whatever the phase, so an attacker can still inject those four; the connect machine reads a
   licensing PDU only while licensing runs, and ignores the other three. FreeRDP accepts whatever the flag
   says, for every PDU.
5. **The core exposes the server certificate to the host and does not verify its signature.** Trust
   is the host's (ADR-0005), and it cannot judge what it cannot see. The signature proves nothing: the
   signing key's private half is printed in 5.3.3.1.1. FreeRDP skips the check too
   (`certificate_process_server_public_signature`, `libfreerdp/crypto/certificate.c`). The maintainer
   chose this over verifying the signature as well, and over leaving the certificate unexposed.

6. **FIPS is not advertised, and a server's close after the Connect-Initial is reported as its
   refusal** (`ConnectFailure::StandardSecurityRefusedByServer`). Measured on Windows Server 2019 at
   `MinEncryptionLevel=4`: offered 40, 56 and 128 bits it resets the connection, so the client never
   learns the level; offered FIPS too, it selects FIPS and the client can name it. The maintainer was
   shown four options on 2026-11-06, with these measurements: this one, advertising FIPS by default,
   leaving the bit to the host, and implementing Triple DES. Advertising what the core cannot honour
   is what ADR-0016 refuses. This changes #599's acceptance line "a level that is not supported fails
   with a typed error naming it": the error names the possibilities, because the server's close
   cannot say which. A server that does select FIPS still gets `UnsupportedMethod` by value.

## Consequences

- **This protection does not authenticate the server and does not resist an active attacker.** A
  host that opts in accepts that. The opt-in is the whole control.
- The session's send methods take `&mut self`, because each frame advances the cipher. A host must
  write frames in the order it received them.
- `justrdp-security` carries a second use of the primitives `license_crypto` already held. `BigUint`
  stays the only RSA code.

## What this did not cover

- **FIPS** (`ENCRYPTION_METHOD_FIPS`, level 4) is Triple DES and is not implemented.
- **An X.509 chain, for a host that uses this layer alone.** The layer takes an RSA key. Reaching it
  from a chain needs an X.509 parser, which `justrdp` has through `x509-cert` and this crate does not.
- **Any server below Windows Server 2019**, unmeasured when this was decided.
- **Turning it on by default**, the relay itself, and a server role are out of scope.
