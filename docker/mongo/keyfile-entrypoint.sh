#!/usr/bin/env bash
# =============================================================================
# H-Vault — MongoDB entrypoint wrapper: provision the replica-set key file
# =============================================================================
# H-Vault needs BOTH of these from MongoDB, and they interact:
#
#   * a REPLICA SET — the app's transactional paths (vault key rotation, account
#     cascade-delete, refresh-token rotation) are gated on the driver reporting a
#     replica set, and MongoDB only offers multi-document transactions there. A
#     single-node set (rs0) provides them without a second data-bearing node.
#
#   * AUTHENTICATION — MONGO_INITDB_ROOT_USERNAME/PASSWORD, which makes the
#     official entrypoint add `--auth`.
#
# Combine those two and mongod refuses to start at all:
#
#     BadValue: security.keyFile is required when authorization is enabled
#               with replica sets
#
# The key file is how replica-set members authenticate to EACH OTHER. A one-member
# set has no peers to authenticate to, but mongod enforces the requirement anyway,
# so one must exist. It cannot be bind-mounted from the host: mongod rejects a key
# file whose permissions are wider than 0400 or that is not owned by the running
# user, and a host bind mount cannot satisfy that portably (Windows/WSL bind mounts
# in particular do not carry POSIX ownership). So it is generated here instead —
# inside the container, on the first boot, onto a named volume — which also means
# the key is never committed, never baked into an image layer, and never leaves the
# stack.
#
# This runs as root before the official entrypoint drops to the `mongodb` user via
# gosu; that is why the mongo service keeps CHOWN/SETUID/SETGID/FOWNER/DAC_OVERRIDE
# in docker-compose.yml while dropping every other capability.
set -Eeuo pipefail

KEYFILE="${HVAULT_MONGO_KEYFILE:-/data/configdb/replica.key}"
KEYFILE_DIR="$(dirname "$KEYFILE")"

if [ "$(id -u)" = '0' ]; then
  mkdir -p "$KEYFILE_DIR"

  # Generated once, then reused. `-s` (non-empty) rather than `-f` so a truncated
  # file from a half-finished first boot is regenerated instead of failing mongod
  # with an unhelpful "security key file is empty".
  if [ ! -s "$KEYFILE" ]; then
    if command -v openssl >/dev/null 2>&1; then
      openssl rand -base64 756 > "$KEYFILE"
    else
      # Fallback with no openssl dependency. mongod accepts 6..1024 base64
      # characters; 567 random bytes encode to exactly 756 of them.
      head -c 567 /dev/urandom | base64 > "$KEYFILE"
    fi
  fi

  # mongod validates both of these and exits if either is wrong.
  chown mongodb:mongodb "$KEYFILE"
  chmod 0400 "$KEYFILE"
fi

# Hand off to the stock entrypoint with the original command. It creates the root
# user on first boot (starting a temporary mongod with --replSet, --keyFile and
# --auth stripped so the user can actually be written), then execs the real mongod
# with the arguments below plus the --auth it adds itself.
exec /usr/local/bin/docker-entrypoint.sh "$@"
