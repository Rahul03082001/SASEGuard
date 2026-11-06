#!/usr/bin/env bash
# Runs as root on a fresh Ubuntu 24.04 GCE VM. The release archive is appended
# by deploy_gcp.sh. Generated credentials never enter instance metadata.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# Startup scripts also run after reboots. Docker restarts existing services;
# never regenerate secrets or overwrite a working installation on reboot.
if [ -f /srv/saseguard/.provisioned ]; then
  systemctl start docker
  exit 0
fi

apt-get update
apt-get install -y docker.io docker-compose-v2 ca-certificates curl
systemctl enable --now docker
if ! id saseguard >/dev/null 2>&1; then
  useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin saseguard
fi
install -d -m 0750 -o saseguard -g saseguard /srv/saseguard
base64 -d /tmp/saseguard-release.b64 > /tmp/saseguard-release.tar.gz
tar -xzf /tmp/saseguard-release.tar.gz -C /srv/saseguard
chown -R saseguard:saseguard /srv/saseguard
cd /srv/saseguard
install -d -m 0700 -o saseguard -g saseguard secrets data
docker build -t saseguard:local .
docker run --rm --user "$(id -u saseguard):$(id -g saseguard)" \
  --mount type=bind,source=/srv/saseguard,target=/app \
  saseguard:local python scripts/setup.py

saseguard_ip=$(curl --fail --silent --show-error --retry 5 \
  -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)
# SASEGUARD_DOMAIN defaults to a name that resolves to this instance without
# anyone having to own a domain: sslip.io answers any <name>.<ip>.sslip.io
# with that IP. Override it in deploy/gcp.env to use a real domain.
saseguard_host="${SASEGUARD_DOMAIN:-saseguard.${saseguard_ip}.sslip.io}"
{
  printf 'SASEGUARD_DOMAIN=%s\n' "$saseguard_host"
  printf 'SASEGUARD_IP=%s\n' "$saseguard_ip"
} > deploy/gcp.env
chown saseguard:saseguard deploy/gcp.env
chmod 0600 deploy/gcp.env

cat > /usr/local/bin/saseguard-compose <<'SH'
#!/usr/bin/env bash
set -euo pipefail
cd /srv/saseguard
exec docker compose --env-file .env --env-file deploy/gcp.env \
  -f docker-compose.yml -f docker-compose.gcp.yml "$@"
SH
chmod 0755 /usr/local/bin/saseguard-compose
saseguard-compose config --quiet
saseguard-compose run --rm --no-deps caddy caddy validate --config /etc/caddy/Caddyfile
saseguard-compose up -d --wait --wait-timeout 180
touch /srv/saseguard/.provisioned
printf 'SASEGUARD_READY https://%s\n' "$saseguard_ip"
