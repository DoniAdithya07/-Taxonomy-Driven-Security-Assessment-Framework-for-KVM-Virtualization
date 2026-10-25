#!/bin/sh
# Run one Volatility 3 command with limits, on a memory dump that may contain hostile data.
#   run_vol_sandboxed.sh [--allow-unsandboxed-fs] <dump> <vol> [vol args...]
# - refuses to run as root; refuses a dump the current user could write to (chmod 444 it first: read-only input)
# - limits (all must be accepted by the shell, else the run is refused):
#     ulimit -v  VOL_MEM_KB   address space, default 8388608 (8 GiB), range 262144..67108864 KB
#     ulimit -t  VOL_CPU_S    CPU seconds, default 3600, range 10..86400
#     ulimit -f  VOL_FSIZE_MB largest file it may write, default 1024 MB, range 1..16384
#                             (ulimit -f counts 512- or 1024-byte blocks depending on the shell: up to 2x slack)
#     ulimit -u  VOL_NPROC    processes of this user, default 256, range 16..4096
#     ulimit -c 0             no core files (a core dump of a hostile-dump run would copy dump data)
#   Each value must be plain digits: 'unlimited', empty or negative values are rejected, not passed on.
# - isolation, best first:
#     bwrap (bubblewrap): --unshare-all (no network, own pid/ipc/uts/user namespaces), --die-with-parent, the
#       host tree mounted READ-ONLY, tmpfs /tmp, /run and /var/run (no D-Bus/agent sockets), $HOME hidden behind a
#       tmpfs, the dump and the symbols dir (the vol `-s` argument) bound read-only, --clearenv with only
#       PATH (fixed safe value) and HOME=/tmp set: SSH_AUTH_SOCK, tokens etc. are NOT inherited. Because $HOME is
#       hidden, vol itself must live outside $HOME (e.g. /opt or a system-wide venv).
#     else `unshare -Un` (network only, NO filesystem isolation): only with the explicit argument
#       --allow-unsandboxed-fs or VOL_ALLOW_WEAK_SANDBOX=1; otherwise the script refuses (exit 2).
#     else refuse. VOL_ALLOW_NETWORK=1 skips all isolation (explicit opt-out; a notice is printed).
# - Ubuntu 24.04 and newer: AppArmor blocks unprivileged user namespaces by default
#   (kernel.apparmor_restrict_unprivileged_userns=1), so bwrap AND `unshare -Un` fail with "Operation not
#   permitted"/"setting up uid map". To allow them on a dedicated analysis host run
#       sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
#   (put it in /etc/sysctl.d/ to persist), or ship an AppArmor profile for bwrap. That relaxes a system-wide
#   hardening setting: do it only on the analysis host, and prefer it to the weak fallback.
# - passes --offline to vol only if `vol --help`, run inside the same isolation, mentions it
# Residual risk (honest): limits and namespaces do not make a parser exploit harmless. With bwrap the whole host
# file tree stays READABLE to vol (no network to send it anywhere, but a hostile dump could still read files and
# shape the JSON output); with the unshare fallback it can also WRITE anything this user can. For a dump you do
# not trust at all, run this inside a throwaway VM or a dedicated unprivileged user.
set -eu
ALLOW_WEAK=0
[ "${VOL_ALLOW_WEAK_SANDBOX:-0}" != 1 ] || ALLOW_WEAK=1
if [ "${1:-}" = --allow-unsandboxed-fs ]; then ALLOW_WEAK=1; shift; fi
[ "$#" -ge 2 ] || { echo "usage: $0 [--allow-unsandboxed-fs] <dump> <vol> [vol args...]" >&2; exit 2; }
DUMP=$1
VOL=$2
shift 2
[ "$(id -u)" -ne 0 ] || { echo "refusing to run as root" >&2; exit 1; }
[ -f "$DUMP" ] && [ -r "$DUMP" ] || { echo "dump not found or not readable: $DUMP" >&2; exit 1; }
[ ! -w "$DUMP" ] || { echo "dump is writable by this user; run: chmod 444 '$DUMP'" >&2; exit 1; }

clamp() {  # clamp <name> <value> <min> <max>: print the value, or explain and fail. Digits only, <= 12 of them.
    case $2 in
        '' | *[!0-9]*) echo "$1 must be plain digits (not '$2'; 'unlimited' is not allowed)" >&2; exit 2 ;;
    esac
    [ "${#2}" -le 12 ] || { echo "$1 is too long: $2" >&2; exit 2; }
    if [ "$2" -lt "$3" ] || [ "$2" -gt "$4" ]; then
        echo "$1=$2 is outside the allowed range $3..$4" >&2
        exit 2
    fi
    echo "$2"
}
# "${VAR-default}" (no colon): an UNSET variable gets the default, but a variable that is set to the empty string is an
# error, never silently replaced by the default (an empty override is almost certainly a mistake)
MEM_KB=$(clamp VOL_MEM_KB "${VOL_MEM_KB-8388608}" 262144 67108864)
CPU_S=$(clamp VOL_CPU_S "${VOL_CPU_S-3600}" 10 86400)
FSIZE_MB=$(clamp VOL_FSIZE_MB "${VOL_FSIZE_MB-1024}" 1 16384)
NPROC=$(clamp VOL_NPROC "${VOL_NPROC-256}" 16 4096)
ulimit -c 0
ulimit -v "$MEM_KB"
ulimit -t "$CPU_S"
ulimit -f $((FSIZE_MB * 2048))
if (ulimit -u >/dev/null 2>&1); then
    ulimit -u "$NPROC"  # bash, ksh, zsh
elif ulimit -a 2>/dev/null | grep -q '^process'; then
    ulimit -p "$NPROC"  # dash (the /bin/sh of Debian/Ubuntu): -p is the process limit there, not -u
else
    echo "this shell has no process-count limit (ulimit -u/-p); run with bash or dash" >&2
    exit 1
fi

abs() {  # absolute physical path of an existing file or directory
    if [ -d "$1" ]; then (cd "$1" && pwd -P); else printf '%s/%s\n' "$(cd "$(dirname "$1")" && pwd -P)" "$(basename "$1")"; fi
}
SYMS=
prev=
for a in "$@"; do
    [ "$prev" != -s ] || SYMS=$a
    prev=$a
done
BIND_DUMP=$(abs "$DUMP")
BIND_SYMS=$BIND_DUMP  # binding the dump twice is harmless when there is no -s argument
[ -z "$SYMS" ] || BIND_SYMS=$(abs "$SYMS")
HIDE=/tmp  # a second tmpfs on /tmp is harmless; $HOME is hidden by default
if [ -n "${HOME:-}" ] && [ "$HOME" != / ]; then HIDE=$HOME; fi
SAFE_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

isolated() {  # isolated <cmd> [args...]: run under the chosen isolation (not exec: the --help probe uses it too)
    case $MODE in
        bwrap)
            bwrap --unshare-all --die-with-parent --new-session --ro-bind / / --dev /dev --proc /proc \
                --tmpfs /tmp --tmpfs /run --tmpfs /var/run --tmpfs "$HIDE" \
                --ro-bind "$BIND_DUMP" "$BIND_DUMP" --ro-bind "$BIND_SYMS" "$BIND_SYMS" \
                --clearenv --setenv PATH "$SAFE_PATH" --setenv HOME /tmp -- "$@" ;;
        unshare) unshare -Un "$@" ;;
        *) "$@" ;;
    esac
}

MODE=none
if [ "${VOL_ALLOW_NETWORK:-0}" = 1 ]; then
    echo "notice: VOL_ALLOW_NETWORK=1: running with NO network or filesystem isolation" >&2
elif command -v bwrap >/dev/null 2>&1 && bwrap --unshare-all --ro-bind / / true 2>/dev/null; then
    MODE=bwrap
elif command -v unshare >/dev/null 2>&1 && unshare -Un true 2>/dev/null; then
    [ "$ALLOW_WEAK" = 1 ] || {
        echo "bwrap is not usable and 'unshare -Un' would give NO filesystem isolation; refusing." >&2
        echo "Fix bwrap (on Ubuntu 24.04: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0), or pass --allow-unsandboxed-fs / set VOL_ALLOW_WEAK_SANDBOX=1 to accept." >&2
        exit 2
    }
    MODE=unshare
    echo "notice: bwrap not usable; using 'unshare -Un' (network only): filesystem isolation is NOT applied" >&2
else
    echo "cannot isolate the network (no bwrap, no 'unshare -Un'); set VOL_ALLOW_NETWORK=1 to accept" >&2
    exit 1
fi
OFFLINE=
if isolated "$VOL" --help 2>&1 | grep -q -- '--offline'; then OFFLINE=1; fi
rc=0
isolated "$VOL" ${OFFLINE:+--offline} "$@" || rc=$?
exit "$rc"
