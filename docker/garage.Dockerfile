# =============================================================================
# OPTIONAL: the object storage engine, run as a non-root user
# =============================================================================
# NOT used by the default stack. docker-compose.yml runs the engine image as it
# is published, and that image declares no USER, so its process is root inside
# its container. SECURITY.md ("The object storage service") records that as an
# accepted residual and states its bound; this file is the way to close it for an
# operator who wants to. The commented alternative in docker-compose.yml (search
# for "OPTIONAL: run the object storage engine as a non-root user") shows how to
# switch to it, together with the one-shot that hands the two data volumes to the
# same user first.
#
# Why it is not the default: a volume the stock image wrote is owned by root, so
# an engine started as 1000 on it cannot open its own metadata and exits, and
# `restart: unless-stopped` turns that into a crash loop. The one-shot in the
# alternative re-owns both volumes before the engine starts, on every `up`; it is
# validated against a fresh volume and against one the stock image had filled.
#
# The SAME image, pinned by the SAME digest as `hvault-s3` in docker-compose.yml
# (a test holds the two equal), so switching changes the user and nothing else.
# The image has no shell and no package manager, which is why there is no RUN
# here: the engine is one static binary, `/garage`.
FROM dxflrs/garage:v2.3.0@sha256:866bd13ed2038ba7e7190e840482bc27234c4afaf77be8cfa439ae088c1e4690

# Numeric, like every other USER in this repository: the image has no
# /etc/passwd entry to resolve a name against, and the tmpfs the alternative
# mounts is pinned to the same uid/gid, which is the pairing whose mismatch makes
# a container die silently on its first restart.
USER 1000:1000
