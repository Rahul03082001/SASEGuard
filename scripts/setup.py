#!/usr/bin/env python3
"""One-time local setup: generate keys, demo credentials, and databases.

Everything secret in this lab is generated *here*, on the machine running it,
and written to ``secrets/`` and ``.env`` — both git-ignored. Nothing secret is
committed, and there are no shared default passwords baked into the source.
That is a deliberate property: a reader who clones this repository gets no
usable credentials, and two people who clone it do not end up with the same
ones.

What gets generated:

* a 2048-bit RSA keypair — the private half for the identity issuer only;
* a random password per demo user, stored only as a salted PBKDF2 hash;
* a random service credential for the private policy APIs;
* ``.env`` wiring the services together;
* the SQLite audit and policy databases, with the device registry seeded.

The plaintext demo passwords are written once to
``secrets/demo_credentials.txt`` (mode 0600) because a demo you cannot log
into is useless. That file is the one place they exist; it is git-ignored and
excluded from the Docker build context.

Usage::

    python scripts/setup.py             # create anything missing, keep the rest
    python scripts/setup.py --force     # regenerate everything from scratch
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import secrets
import stat
import sys

# Make `apps` importable when this script is run directly.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from apps.audit import AuditStore  # noqa: E402
from apps.common import (  # noqa: E402
    CREDENTIALS_FILE,
    DATA_DIR,
    ENV_FILE,
    PBKDF2_ITERATIONS,
    PRIVATE_KEY_FILE,
    PUBLIC_KEY_FILE,
    SECRETS_DIR,
    USERS_FILE,
    hash_password,
    iso,
    load_policy,
    new_salt_hex,
    utcnow,
)
from apps.policy import PolicyStore  # noqa: E402

#: The demo population. Roles must exist in config/policy.yaml, and each
#: device must exist in config/devices.json with a matching owner.
DEMO_USERS: tuple[dict[str, str], ...] = (
    {"username": "alice", "role": "finance", "device_id": "dev-alice-laptop",
     "note": "Finance analyst. May read payroll and wiki, and may upload."},
    {"username": "bob", "role": "engineer", "device_id": "dev-bob-laptop",
     "note": "Engineer. May read engineering and wiki, and may upload."},
    {"username": "carol", "role": "contractor", "device_id": "dev-carol-byod",
     "note": "Contractor. May read wiki only, and may NOT upload."},
    {"username": "admin", "role": "administrator", "device_id": "dev-admin-workstation",
     "note": "Administrator. May read all apps and manage posture and audit."},
)

#: Characters for generated demo passwords. Ambiguous glyphs (O/0, l/1) are
#: left out so a password read off the screen can actually be typed.
PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
PASSWORD_LENGTH = 20


def _secure_write(path: pathlib.Path, content: str) -> None:
    """Write a secret to disk readable only by the current user.

    The mode is set *before* the content is written, so there is no window in
    which the file exists with default permissions.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def generate_keypair(force: bool) -> bool:
    """Create the RSA signing keypair if absent. Returns True if written."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    if PRIVATE_KEY_FILE.exists() and PUBLIC_KEY_FILE.exists() and not force:
        return False

    # 2048 bits is the floor for RS256 and plenty for a local lab. The key is
    # generated here and never leaves this machine.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        # No passphrase: the issuer must start unattended. The protection is
        # file permissions plus the fact that this key is worthless outside
        # the lab.
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    _secure_write(PRIVATE_KEY_FILE, private_pem)
    # The public key is not secret, but keeping both files 0600 avoids any
    # "which one was safe to expose?" confusion later.
    _secure_write(PUBLIC_KEY_FILE, public_pem)
    return True


def generate_users(force: bool) -> dict[str, str]:
    """Create the user table with random passwords. Returns plaintexts."""
    if USERS_FILE.exists() and not force:
        return {}

    plaintexts: dict[str, str] = {}
    users: dict[str, object] = {}

    for entry in DEMO_USERS:
        password = "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(PASSWORD_LENGTH))
        salt = new_salt_hex()
        plaintexts[entry["username"]] = password
        users[entry["username"]] = {
            "role": entry["role"],
            "salt": salt,
            "password_hash": hash_password(password, salt),
            "iterations": PBKDF2_ITERATIONS,
            "devices": [entry["device_id"]],
            "note": entry["note"],
        }

    _secure_write(
        USERS_FILE,
        json.dumps({"generated_at": iso(utcnow()), "users": users}, indent=2) + "\n",
    )
    return plaintexts


def generate_service_credential(force: bool, existing: str | None) -> str:
    """Return the service credential, generating one when needed."""
    if existing and not force:
        return existing
    return secrets.token_urlsafe(32)


def read_existing_env() -> dict[str, str]:
    """Parse the current .env, if any, so a re-run preserves settings."""
    if not ENV_FILE.exists():
        return {}
    values: dict[str, str] = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, _, value = stripped.partition("=")
            values[key.strip()] = value.strip()
    return values


def write_env(service_credential: str) -> None:
    content = f"""# Generated by scripts/setup.py -- do not commit (see .gitignore).
#
# SASEGUARD_SERVICE_CREDENTIAL authenticates the gateway to the private
# policy service. Treat it like a password.
SASEGUARD_SERVICE_CREDENTIAL={service_credential}

# Private service URLs. Only the gateway is bound to a host port.
SASEGUARD_IDENTITY_URL=http://127.0.0.1:8081
SASEGUARD_POLICY_URL=http://127.0.0.1:8082
SASEGUARD_APPS_URL=http://127.0.0.1:8083

# Bounded outbound timeout, in seconds, for service-to-service calls.
SASEGUARD_HTTP_TIMEOUT=3.0
"""
    _secure_write(ENV_FILE, content)


def write_credentials_file(plaintexts: dict[str, str], service_credential: str) -> None:
    lines = [
        "SASEGuard generated demo credentials",
        "=" * 52,
        "",
        f"Generated at: {iso(utcnow())}",
        "",
        "These passwords exist only in this file and as salted hashes in",
        "secrets/users.json. They are random per setup run, git-ignored, and",
        "excluded from the Docker build context. Re-run setup.py --force to",
        "rotate them.",
        "",
        "Demo users",
        "-" * 52,
    ]
    for entry in DEMO_USERS:
        username = entry["username"]
        password = plaintexts.get(username, "(unchanged -- see a previous run of this file)")
        lines += [
            f"  username : {username}",
            f"  password : {password}",
            f"  role     : {entry['role']}",
            f"  device   : {entry['device_id']}",
            f"  notes    : {entry['note']}",
            "",
        ]
    lines += [
        "Private service credential",
        "-" * 52,
        f"  {service_credential}",
        "",
        "Log in from the dashboard at http://127.0.0.1:8080 using a username,",
        "its password, and its enrolled device ID. A device ID that is not",
        "enrolled to that account will be refused.",
        "",
    ]
    _secure_write(CREDENTIALS_FILE, "\n".join(lines))


def main() -> int:
    parser = argparse.ArgumentParser(description="Set up the SASEGuard lab.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Regenerate keys, passwords, the service credential, and reseed devices.",
    )
    args = parser.parse_args()

    print("SASEGuard setup")
    print("=" * 52)

    # Validate policy.yaml before generating anything, so a typo in config is
    # reported now rather than at the first request.
    policy = load_policy()
    print(f"  policy          : {policy.label}")

    undefined = [u["role"] for u in DEMO_USERS if policy.role(u["role"]) is None]
    if undefined:
        print(f"  ERROR: roles not defined in policy.yaml: {', '.join(undefined)}")
        return 1

    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    SECRETS_DIR.chmod(0o700)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    wrote_keys = generate_keypair(args.force)
    print(f"  RSA keypair     : {'generated' if wrote_keys else 'already present'}")

    plaintexts = generate_users(args.force)
    print(f"  demo users      : {'generated' if plaintexts else 'already present'}")

    env = read_existing_env()
    credential = generate_service_credential(
        args.force, env.get("SASEGUARD_SERVICE_CREDENTIAL")
    )
    rotated = credential != env.get("SASEGUARD_SERVICE_CREDENTIAL")
    write_env(credential)
    print(f"  service cred    : {'generated' if rotated else 'preserved'}")

    AuditStore().initialize()
    print(f"  audit database  : ready ({DATA_DIR / 'audit.sqlite3'})")

    store = PolicyStore()
    store.initialize()
    seeded = store.seed_devices(force=args.force)
    print(f"  policy database : ready, {seeded} device(s) seeded")

    if plaintexts or args.force:
        write_credentials_file(plaintexts, credential)
        print(f"  credentials file: {CREDENTIALS_FILE}")
    else:
        print("  credentials file: left as-is (use --force to rotate)")

    print()
    print("Next steps")
    print("-" * 52)
    print("  1. cat secrets/demo_credentials.txt      # your generated logins")
    print("  2. python scripts/run_local.py           # start all four services")
    print("  3. open http://127.0.0.1:8080            # the dashboard")
    print("  4. python -m pytest                      # run the test suite")
    print()
    if not plaintexts and not args.force:
        print("Note: existing credentials were kept. Run with --force to rotate them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
