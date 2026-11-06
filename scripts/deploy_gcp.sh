#!/usr/bin/env bash
# Run in the authorized Cloud Shell from the reviewed, secret-free release.
# Creates a separate VM/network; does not modify RankForge or billing.
set -euo pipefail
saseguard_project="${1:?Supply the authorized Google Cloud project ID}"
saseguard_zone="${2:-us-east1-b}"
saseguard_region="${saseguard_zone%-*}"
cd "$(dirname "$0")/.."

command -v gcloud >/dev/null
gcloud services enable compute.googleapis.com iap.googleapis.com \
  --project="$saseguard_project" --quiet
if gcloud compute instances describe saseguard --zone="$saseguard_zone" \
  --project="$saseguard_project" >/dev/null 2>&1; then
  echo 'A SASEGuard VM already exists. Inspect it before making an update.' >&2
  exit 1
fi

# Strict allowlist: no local .env, keys, databases, nested checkout, or Git.
saseguard_stage=$(mktemp -d)
trap 'rm -rf "$saseguard_stage"' EXIT
python3 - "$saseguard_stage" <<'PY'
import base64, hashlib, pathlib, sys, tarfile

root = pathlib.Path.cwd()
stage = pathlib.Path(sys.argv[1])
files = [root / p for p in (
    'Dockerfile', '.dockerignore', 'requirements.txt', 'docker-compose.yml',
    'docker-compose.gcp.yml', 'deploy/Caddyfile.gcp', 'scripts/setup.py',
    'scripts/smoke.py',
)]
for folder, pattern in [('apps', '*.py'), ('config', '*.json'),
                        ('config', '*.yaml'), ('web', '*.html'),
                        ('web', '*.css'), ('web', '*.js')]:
    files.extend(sorted((root / folder).glob(pattern)))
with tarfile.open(stage / 'release.tar.gz', 'w:gz') as archive:
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise SystemExit(f'Expected regular release file: {path}')
        archive.add(path, arcname=str(path.relative_to(root)), recursive=False)
payload = (stage / 'release.tar.gz').read_bytes()
encoded = base64.b64encode(payload).decode()
bootstrap = (root / 'deploy/gcp-startup.sh').read_text()
startup = '#!/usr/bin/env bash\nset -euo pipefail\numask 077\n'
startup += "cat > /tmp/saseguard-release.b64 <<'SASEGUARD_RELEASE'\n"
startup += encoded + '\nSASEGUARD_RELEASE\n'
startup += bootstrap
if len(startup.encode()) > 240_000:
    raise SystemExit('Release exceeds the startup metadata size budget.')
(stage / 'startup.sh').write_text(startup)
print('Release SHA-256:', hashlib.sha256(payload).hexdigest())
print('Release files:', len(files))
PY

if ! gcloud compute networks describe saseguard-network \
  --project="$saseguard_project" >/dev/null 2>&1; then
  gcloud compute networks create saseguard-network --subnet-mode=custom \
    --project="$saseguard_project" --quiet
fi
if ! gcloud compute networks subnets describe saseguard-subnet \
  --region="$saseguard_region" --project="$saseguard_project" >/dev/null 2>&1; then
  gcloud compute networks subnets create saseguard-subnet \
    --network=saseguard-network --range=10.42.0.0/24 \
    --region="$saseguard_region" --project="$saseguard_project" --quiet
fi
if ! gcloud compute firewall-rules describe saseguard-web \
  --project="$saseguard_project" >/dev/null 2>&1; then
  gcloud compute firewall-rules create saseguard-web \
    --network=saseguard-network --direction=INGRESS --action=ALLOW \
    --rules=tcp:80,tcp:443 --source-ranges=0.0.0.0/0 --target-tags=saseguard \
    --project="$saseguard_project" --quiet
fi
if ! gcloud compute firewall-rules describe saseguard-iap-ssh \
  --project="$saseguard_project" >/dev/null 2>&1; then
  gcloud compute firewall-rules create saseguard-iap-ssh \
    --network=saseguard-network --direction=INGRESS --action=ALLOW \
    --rules=tcp:22 --source-ranges=35.235.240.0/20 --target-tags=saseguard \
    --project="$saseguard_project" --quiet
fi
if ! gcloud compute addresses describe saseguard-ip \
  --region="$saseguard_region" --project="$saseguard_project" >/dev/null 2>&1; then
  gcloud compute addresses create saseguard-ip --region="$saseguard_region" \
    --project="$saseguard_project" --quiet
fi
saseguard_ip=$(gcloud compute addresses describe saseguard-ip \
  --region="$saseguard_region" --project="$saseguard_project" --format='value(address)')
gcloud compute instances create saseguard --zone="$saseguard_zone" \
  --project="$saseguard_project" --machine-type=e2-micro \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=20GB --boot-disk-type=pd-standard --no-boot-disk-auto-delete \
  --network=saseguard-network --subnet=saseguard-subnet --address="$saseguard_ip" \
  --tags=saseguard --labels=app=saseguard --no-service-account --no-scopes \
  --shielded-secure-boot \
  --metadata=enable-oslogin=TRUE,block-project-ssh-keys=TRUE \
  --metadata-from-file="startup-script=$saseguard_stage/startup.sh" --quiet
printf 'Provisioning SASEGuard at https://%s\n' "$saseguard_ip"
echo 'Wait for SASEGUARD_READY in the startup logs, then verify HTTPS and run smoke.py.'
