# syntax=docker/dockerfile:1
# =============================================================================
# H-Vault — MongoDB image
# =============================================================================
# The stock mongo image plus one thing it cannot do on its own: provision the
# replica-set key file that mongod demands whenever authentication and a replica
# set are enabled together (see docker/mongo/keyfile-entrypoint.sh for the full
# reasoning). Everything else — root-user creation, the gosu drop to the
# `mongodb` user, signal handling — is left to the official entrypoint, which
# this wrapper execs.
#
# Pinned to the 8.0 series: the current MongoDB LTS, supported until 2029-10-31
# (the previous LTS, 7.0, runs out on 2027-08-31). Mongoose 9 / the Node driver 7.x
# this app ships speak it natively.
#
# 8.0 is also the line affected by SERVER-121912 — its TCMalloc violates the rseq
# ABI as it changed in Linux 6.19 (Ubuntu 26.04), and mongod aborts at startup on
# such a host unless `GLIBC_TUNABLES=glibc.pthread.rseq=1` is set. That variable is
# set on EVERY mongod launch site in this repo (docker-compose.yml,
# docker-compose.dev.yml, the server test setup, and the E2E harness — the last two
# because mongodb-memory-server downloads and spawns a real mongod). Never set it
# to 0: that is mongod's own default and precisely the value that crash-loops.
FROM mongo:8.0

# 0755 is set explicitly rather than inherited: the repo may be checked out on a
# filesystem that does not carry the executable bit (Windows/WSL, a zip export),
# and an entrypoint that is not executable turns into an unbootable stack.
COPY --chmod=0755 docker/mongo/keyfile-entrypoint.sh /usr/local/bin/hvault-mongo-entrypoint.sh

# The least-privilege user provisioner, baked in rather than bind-mounted for the
# same reason the Nginx config is: a bind mount makes the stack non-portable and
# deploys mutable. It is read-only (0444) — nothing in the stack should be able to
# rewrite the script that hands out database grants.
#
# NOT placed in /docker-entrypoint-initdb.d/. That directory is honoured ONLY on a
# first boot against an empty data directory (the official entrypoint probes for
# /data/db/WiredTiger and friends and skips initialisation if any exists), so on
# any existing deployment the script would be silently ignored, the app user would
# never be created, and the app would crash-loop on authentication. It is instead
# run explicitly by the `hvault-db-init` one-shot, which overrides `entrypoint:`
# and therefore bypasses the key-file wrapper below.
#
# The directory is created FIRST, deliberately. A `COPY --chmod=0444` into a path
# whose parent does not exist applies that same mode to the directory BuildKit
# creates for it, producing `dr--r--r--` — no execute bit, so the directory cannot
# be traversed and every non-root user gets EACCES on the file inside. The image
# runs as `mongodb`, so the one-shot failed with "permission denied" while `ls` as
# root still showed a world-readable file. Creating the directory up front leaves
# it 0755 and COPY then only sets the mode of the file itself.
RUN mkdir -p /usr/local/share/hvault
COPY --chmod=0444 docker/mongo/provision-app-user.js /usr/local/share/hvault/provision-app-user.js

ENTRYPOINT ["/usr/local/bin/hvault-mongo-entrypoint.sh"]
CMD ["mongod"]
