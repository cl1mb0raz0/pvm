#!/usr/bin/env bash
# Start the PVM stack from any location, local disk or network share.
#
# Postgres refuses a data directory that is not 0700/0750 and owned by the
# user it runs as (PVM_USER, "uid:gid", default 1000:1000; 0:0 for root,
# where the images fix the folder themselves and nothing is checked here). A VMware share (vmhgfs-fuse)
# ignores chmod/chown, so this script checks data/postgres first and, when
# it is wrong, fixes it (chmod/chown with sudo, or for a vmhgfs share a
# mount of that one sub-folder with umask=077). Then it runs
# `docker compose up -d` (building the images first if they do not exist yet); every argument is passed on ("./start.sh --build").
#
# The mount is not permanent (gone after a reboot or a re-mount of the
# share): run this script again instead of `docker compose up -d`.
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

PGDIR="data/postgres"

env_value() {
    # Value of KEY in .env (last one wins, quotes removed), empty if absent.
    local key="$1" line=""
    [ -f .env ] && line="$(grep -E "^${key}=" .env | tail -n 1 || true)"
    line="${line#*=}"
    line="${line%\"}"; line="${line#\"}"; line="${line%\'}"; line="${line#\'}"
    printf '%s' "$line"
}

as_root() {
    if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

pg_ok() {
    # Mode 700 or 750, owned by the Postgres user.
    local mode owner
    mode="$(stat -c '%a' "$PGDIR")"
    owner="$(stat -c '%u' "$PGDIR")"
    { [ "$mode" = "700" ] || [ "$mode" = "750" ]; } && [ "$owner" = "$PVM_UID" ]
}

mount_share_subfolder() {
    # For vmhgfs-fuse: mount the share's sub-folder over data/postgres with
    # a umask, so it reports 0700 and the owner Postgres runs as.
    local abs source target rel
    abs="$(readlink -f "$PGDIR")"
    target="$(findmnt -n -T "$abs" -o TARGET)"
    # The kernel does not keep the share name (".host:/Home"): it is only in
    # the arguments of the vmhgfs-fuse process that serves this mount point.
    source="$(ps -eo args | awk -v t="$target" '$1 ~ /vmhgfs-fuse$/ && $3 == t {print $2; exit}')"
    if [ -z "$source" ]; then
        echo "Cannot find which share is mounted on $target (no matching vmhgfs-fuse process)." >&2
        return 1
    fi
    if [ "$target" = "$abs" ]; then
        echo "data/postgres is already a separate mount that still reports the wrong mode:" >&2
        echo "unmount it (sudo umount '$abs') and run this script again." >&2
        return 1
    fi
    rel="${abs#"$target"}"
    echo "Mounting ${source}${rel} over $abs with umask=077 (sudo)..."
    as_root vmhgfs-fuse "${source}${rel}" "$abs" -o "allow_other,uid=${PVM_UID},gid=${PVM_GID},umask=077"
}

fix_permissions() {
    # All the bind-mounted folders, as this user: if Docker creates them it makes them root's.
    mkdir -p "$PGDIR" data/redis data/scan_imports data/backups
    pg_ok && return 0

    local fstype
    fstype="$(findmnt -n -T "$(readlink -f "$PGDIR")" -o FSTYPE)"
    echo "data/postgres is $(stat -c '%a' "$PGDIR") owned by uid $(stat -c '%u' "$PGDIR") on '$fstype': fixing."

    if [ "$fstype" = "fuse.vmhgfs-fuse" ]; then
        mount_share_subfolder
    else
        as_root chown "${PVM_UID}:${PVM_GID}" "$PGDIR"
        as_root chmod 700 "$PGDIR"
    fi

    if ! pg_ok; then
        echo "data/postgres is still $(stat -c '%a' "$PGDIR") (uid $(stat -c '%u' "$PGDIR")): Postgres would not start." >&2
        exit 1
    fi
    echo "data/postgres is now $(stat -c '%a' "$PGDIR"): ok."
}

PVM_USER="$(env_value PVM_USER)"; PVM_USER="${PVM_USER:-1000:1000}"
PVM_UID="${PVM_USER%%:*}"
PVM_GID="${PVM_USER#*:}"

# Sourced only to test the functions.
if [ "${BASH_SOURCE[0]}" != "$0" ]; then return 0; fi

if [ "$PVM_UID" = "0" ]; then
    mkdir -p "$PGDIR" data/redis data/scan_imports data/backups
else
    fix_permissions
fi
# worker, worker-background and beat use the pvm-app image built by "web" but
# have no build section of their own: on a fresh install Compose would try to
# pull it from Docker Hub and print "pull access denied". Build it first.
if ! docker image inspect pvm-app >/dev/null 2>&1; then
    echo "First start: the pvm images do not exist yet, building them (a few minutes)..."
    docker compose build
fi
docker compose up -d "$@"
