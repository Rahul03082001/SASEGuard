# Host a live SASEGuard demo

Run the existing four services on one Linux server with Docker Compose.
The hosted overlay adds Caddy for HTTPS and certificate renewal. Identity,
policy, and mock applications retain their internal networks; the gateway
retains its public-key-only mount. SQLite data stays on the server across
container restarts and upgrades.

This publishes the synthetic security lab. It does not turn it into a
production security product; the [threat model](threat-model.md) still applies,
including the absence of login throttling. Keep the generated credentials
private, especially the administrator account.

## Server and domain

- A Linux server with Docker Engine and the Docker Compose plugin. Start
  with 2 GB RAM and 20 GB disk for a small demonstration; this is a starting
  size, not a tested capacity guarantee.
- A non-root deployment user who can run Docker.
- A hostname such as `saseguard.example.com` whose DNS A record points to
  the server's public IPv4 address. Set an AAAA record only if IPv6 works.
- Allow inbound TCP 80 and 443; UDP 443 is optional for HTTP/3. Restrict
  SSH to your own IP. Do not open ports 8080–8083 in the cloud firewall.
  Caddy needs outbound DNS and HTTPS to obtain certificates.

See the official [Docker installation guide](https://docs.docker.com/engine/install/ubuntu/)
and [Caddy HTTPS requirements](https://caddyserver.com/docs/automatic-https).

## First deployment

Run these commands as the deployment user on the server. Use a checkout
that contains `docker-compose.hosted.yml` and `deploy/Caddyfile`.
Generate fresh credentials on the server; do not copy a developer's `.env`,
`secrets/`, or `data/` there.

```bash
git clone https://github.com/Rahul03082001/SASEGuard.git
cd SASEGuard
mkdir -p secrets data
chmod 700 secrets data

# Setup runs from the application image, so host Python is not required.
docker build -t saseguard:local .
docker run --rm --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$PWD,target=/app" \
  saseguard:local python scripts/setup.py

cp deploy/hosting.env.example deploy/hosting.env
# Edit deploy/hosting.env with your real hostname and contact email.
```

Define this helper in the server shell; use it for all hosted operations:

```bash
sg() {
  docker compose --env-file .env --env-file deploy/hosting.env \
    -f docker-compose.yml -f docker-compose.hosted.yml "$@"
}

sg config --quiet
sg run --rm --no-deps caddy caddy validate --config /etc/caddy/Caddyfile
sg up --build -d --wait --wait-timeout 120
sg ps
```

Open `https://YOUR_HOSTNAME`. Caddy redirects HTTP to HTTPS and obtains
the certificate once DNS and ports are reachable. `sg up --wait` checks the
application health checks but does not prove that public DNS or TLS works;
verify the public URL separately:

```bash
curl --fail --show-error https://YOUR_HOSTNAME/healthz
curl --head http://YOUR_HOSTNAME

# Full functional smoke test through the HTTPS endpoint.
# The credentials file is mounted only into this short-lived test process.
docker run --rm --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$PWD/secrets/demo_credentials.txt,target=/app/secrets/demo_credentials.txt,readonly" \
  saseguard:local python scripts/smoke.py --base-url https://YOUR_HOSTNAME
```

The smoke test writes synthetic audit records, changes Alice's posture and
restores it, and tests token revocation. Run it before sharing the demo.
Read `secrets/demo_credentials.txt` privately on the server for the generated
logins; this file also contains the internal service credential and must not
be published or handed to visitors as a whole.

## Device freshness after 24 hours

The policy intentionally denies devices last seen more than 24 hours ago.
This includes the administrator's device. There is no endpoint agent to
refresh those timestamps, so an unattended demo will eventually deny access.

Before a demonstration, explicitly refresh the synthetic devices on the
server. This only changes timestamps: it keeps compliance, risk, passwords,
revocations, and audit history intact. It is an operator assertion of lab
posture, not a real device attestation or an audited dashboard action.

```bash
sg exec -T policy python - <<'PY'
from apps.common import iso, utcnow
from apps.policy import PolicyStore

store = PolicyStore()
now = iso(utcnow())
for device in store.list_devices():
    store.update_device(device.device_id, {"last_seen": now})
print("Refreshed demo device timestamps.")
PY
```

Do not use `setup.py --force` as maintenance: it rotates credentials and
keys and resets posture. Do not disable the stale-device policy to keep a
demo running.

## Updates, backups, and stopping

Update from a reviewed source revision, then rebuild. Existing bind-mounted
databases and credentials are preserved; do not rerun setup for an update.

```bash
git pull --ff-only
sg up --build -d --wait --wait-timeout 120
sg logs --tail 100
```

For a consistent backup, briefly stop the application while copying SQLite
and its sidecar files together with the credentials. Store the resulting
archive securely off the server; it contains secrets. Caddy's certificate
state lives separately in the `caddy_data` and `caddy_config` Docker volumes.

```bash
sg stop
umask 077
tar -czf "$HOME/saseguard-backup-$(date +%Y%m%d-%H%M%S).tar.gz" \
  .env deploy/hosting.env secrets data
sg up -d --wait --wait-timeout 120
```

To restore, stop the stack, restore the archive into the project directory
as the same deployment user (preserving permissions), and start it again.
If the user's numeric UID/GID changed, correct ownership and the
`SASEGUARD_UID`/`SASEGUARD_GID` entries in `.env` before starting.

`sg down` takes the demo offline and preserves data and certificates.
Avoid `sg down -v`: it also deletes Caddy's certificate volumes.

Only Caddy binds public ports. The original gateway port remains accessible
on server loopback for diagnostics. Container logs rotate at 10 MB, three
files per service; the SQLite audit database still needs disk monitoring
and an operator-managed retention policy.
