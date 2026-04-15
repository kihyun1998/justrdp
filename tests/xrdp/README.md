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
| password | set via `--build-arg XRDP_TEST_PASSWORD=...` at build time; defaults to `changeme` if unset |
| domain   | _(empty)_  |

The password is **not** baked into the Dockerfile. CI pulls it from
the `XRDP_TEST_PASSWORD` GitHub Actions secret; local runs can set
their own. The built image still contains the password in
`/etc/shadow` (via `chpasswd`), so **never publish the image
regardless of which password you chose**.

## Local run

```bash
# Build (pick your own password; default is `changeme`)
docker build \
    --build-arg XRDP_TEST_PASSWORD=hunter2 \
    -t justrdp-xrdp \
    -f tests/xrdp/Dockerfile \
    tests/xrdp

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
    --password hunter2 \
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
