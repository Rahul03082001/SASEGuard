# SASEGuard on Google Cloud

The GCP deployment uses Compute Engine in the same project as RankForge.
RankForge's Cloud Run service remains separate. SASEGuard uses local SQLite
for its audit log, device posture, and token revocations, so a persistent VM
preserves the existing behavior without a database migration or losing
state when a Cloud Run instance is replaced.

## Deployment configuration

- VM: `saseguard`, `e2-micro`, `us-east1-b` by default.
- Disk: 20 GB standard persistent boot disk, retained if the VM is deleted.
- Network: dedicated `saseguard-network` and `saseguard-subnet`.
- Public traffic: TCP 80 and 443 only; HTTP redirects to HTTPS.
- Administration: SSH through Google IAP, with OS Login. No public SSH rule.
- Runtime: no attached Google service account or cloud API permissions.
- Endpoint: reserved `saseguard-ip` address, with a trusted Let's Encrypt
  IP certificate. Caddy renews the short-lived certificate automatically.
- Secrets: generated on the VM, mounted only into the services needing them.
  No credentials or databases are uploaded with the source or embedded in
  instance metadata.
- Storage: `/srv/saseguard/data` and `/srv/saseguard/secrets`; Caddy's
  certificate state persists in Docker volumes.

This is still a synthetic lab. The [threat model](threat-model.md) applies.
The VM runs continuously; unlike RankForge, it does not scale to zero.
The instance, disk, reserved IPv4, and network traffic are subject to GCP
pricing and free-tier limits. The selected account was confirmed to have an
unupgraded Free Trial on November 5, 2026. Deployment must not upgrade billing.
An unupgraded trial stops resources when its credit or time expires.
See [Google's trial terms](https://docs.cloud.google.com/free/docs/free-cloud-features).

## Publish from Cloud Shell

Upload only the prepared source release to the authorized Cloud Shell.
It contains application source and deployment scripts, never the developer's
credentials, databases, Git directory, or nested checkout. Extract into a new
directory and run:

```bash
bash scripts/deploy_gcp.sh YOUR_PROJECT_ID us-east1-b
```

The script creates dedicated SASEGuard resources and refuses to overwrite an
existing VM. The startup metadata contains only the allowlisted source
archive and installation instructions. The guest installs Docker from the
Ubuntu repositories, generates credentials, and starts all services.

Inspect provisioning progress without printing credentials:

```bash
gcloud compute instances get-serial-port-output saseguard \
  --zone=us-east1-b --project=YOUR_PROJECT_ID
```

Wait for `SASEGUARD_READY https://PUBLIC_IP`, then verify the HTTPS URL from
outside GCP. A successful VM creation alone does not verify deployment.
The first certificate request can take additional time.

## Access, checks, and updates

Connect through IAP:

```bash
gcloud compute ssh saseguard --zone=us-east1-b \
  --project=YOUR_PROJECT_ID --tunnel-through-iap
```

On the VM, the helper always selects the GCP overlay and environment:

```bash
sudo saseguard-compose ps
sudo saseguard-compose logs --tail 100
```

Privately read `/srv/saseguard/secrets/demo_credentials.txt` on the VM to
obtain login details. It also includes an internal service credential;
never publish the entire file. Share only individual demo-user credentials
with intended visitors, and keep administrator credentials private.

Run the functional checks through the public endpoint from the VM:

```bash
sudo docker run --rm --user "$(id -u saseguard):$(id -g saseguard)" \
  --mount type=bind,source=/srv/saseguard/secrets/demo_credentials.txt,target=/app/secrets/demo_credentials.txt,readonly \
  saseguard:local python scripts/smoke.py --base-url https://PUBLIC_IP
```

The test creates synthetic audit records, temporarily changes and restores
Alice's posture, and checks revocation. Do it before sharing access.

For updates, copy the reviewed source to `/srv/saseguard`, preserving `.env`,
`deploy/gcp.env`, `data/`, and `secrets/`. Rebuild with
`sudo saseguard-compose up --build -d --wait --wait-timeout 180` and rerun
the public checks. Do not rerun the provisioning script or force setup.

Device timestamps expire after 24 hours, including the administrator's.
Use the explicit timestamp refresh described in
[deployment.md](deployment.md#device-freshness-after-24-hours), replacing
`sg` with `sudo saseguard-compose`. This is a manual lab assertion and
preserves the stale-device policy; no automatic freshness bypass is installed.

## Backup and shutdown

Use the backup procedure in [deployment.md](deployment.md#updates-backups-and-stopping)
from `/srv/saseguard` with `sudo saseguard-compose`, including `deploy/gcp.env`
instead of `deploy/hosting.env`. Keep archives private and off the VM.

Stop the VM to take the demo offline while preserving its disk. Reserved IP
and disk resources remain allocated. Removing the VM does not remove the
retained boot disk, IP reservation, or dedicated firewall/network resources;
review these separately when retiring the demo. Never delete the retained
disk before obtaining a verified backup.

Implementation references: [Cloud Run filesystem lifetime](https://docs.cloud.google.com/run/docs/container-contract),
[Caddy ACME profiles](https://caddyserver.com/docs/caddyfile/directives/tls),
and [Let's Encrypt IP certificates](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability/).
