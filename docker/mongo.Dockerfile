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

ENTRYPOINT ["/usr/local/bin/hvault-mongo-entrypoint.sh"]
CMD ["mongod"]
