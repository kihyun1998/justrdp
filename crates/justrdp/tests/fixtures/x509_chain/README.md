# `x509_chain/` — an X.509 chain from a server license request

`license_server.der` and `server.der` are the two certificates of a chain, root first as
`[MS-RDPBCGR]` 5.3.3.2 orders it. `server_public_key.der` is the `RSAPublicKey` a second
implementation expects from the last one.

They are copied from IronRDP at commit `b553ed43`,
`crates/ironrdp-pdu/src/rdp/server_license/server_license_request/tests.rs`: `CERT_1_BUFFER`,
`CERT_2_BUFFER`, and the array in `get_public_key_correctly_gets_key_from_server_certificate`.

**IronRDP does not say where the chain was captured.** Neither test environment here sends a chain:
a server needs a certificate from a Domain or Enterprise License Server for that. So this proves the
steps against a chain of the shape a license server issues, and says nothing about what any
particular server sends.
