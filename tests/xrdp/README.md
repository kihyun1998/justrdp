# xrdp E2E test harness

Disposable xrdp server used by `.github/workflows/e2e-xrdp.yml` to
exercise the full `justrdp-blocking::RdpClient::connect` path against
a real Linux RDP server.

## Contents

- `Dockerfile` — Ubuntu 22.04 + xrdp + xorgxrdp + XFCE + test user
- `start.sh` — container entrypoint (runs xrdp-sesman + xrdp in foreground)

## Credentials

| field    | value      |
| -------- | ---------- |
| host     | `localhost` (when mapped with `-p 3389:3389`) |
| port     | `3389`     |
| user     | `testuser` |
| password | `testpass` |
| domain   | _(empty)_  |

**Never publish the built image.** The password is baked in and only
safe inside ephemeral CI containers.

## Local run

```bash
# Build
docker build -t justrdp-xrdp -f tests/xrdp/Dockerfile tests/xrdp

# Start
docker run --rm -d -p 3389:3389 --name justrdp-xrdp justrdp-xrdp

# Wait until the healthcheck reports healthy (~10 s)
while [ "$(docker inspect -f '{{.State.Health.Status}}' justrdp-xrdp)" != "healthy" ]; do
  sleep 1
done

# Drive connect_test against it
cargo run -p justrdp-blocking --example connect_test -- \
    --host localhost \
    --port 3389 \
    --user testuser \
    --password testpass \
    --domain '' \
    --max-events 30

# Tear down
docker stop justrdp-xrdp
```

## Known limits

- xrdp's default self-signed TLS certificate is accepted via
  `RustlsUpgrader::new()` / `AcceptAll`. Production code should pin
  the server SPKI instead — see `justrdp-tls::PinnedSpki`.
- xrdp on GitHub runners uses the snakeoil certificate bundled with
  `ssl-cert`; the CI workflow does not rotate or validate it.
- The `testuser` account is reachable over RDP only — no SSH, no
  exposed ports beyond 3389. Still, do not run this image on a
  machine with a public NIC.
