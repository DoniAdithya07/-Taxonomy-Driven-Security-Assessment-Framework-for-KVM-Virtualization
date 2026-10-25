#!/bin/sh
# One M4 boot session: all 4 workloads in random order, then meta.json.
#   scripts/run_session.sh [--allow-unscheduled] [--retry] <native|kvm-plain|kvm-masked> <session_id> [window_ms] [n_windows] [out_root]
# Needs the compiled bench (gcc -O2 -o bench vsec/m4_detect/bench.c -lm; override path with BENCH=...),
# python3 and shuf. Run as root (cpufreq). Run from the repo root unless out_root is an absolute path.
# Before the session: same background services, mains power, VM overlay freshly rebuilt.
# CPU governor and turbo are set for the run and restored on exit. TEMP_C=<celsius> and the clocksource
# are passed through to session_meta.py unchanged.
# Hardening: files are created private (umask 077); the bench path is resolved (symlinks followed) and the
# bench and its directory must be root's or ours and not group/world-writable. Arguments are checked with
# `case` patterns on the whole string (a newline in an argument cannot slip through a line-based grep).
# A session folder carries a FAILED marker from the start; it is removed only when meta.json was written and
# scripts/session_qc.py passed (a QC failure keeps the data for inspection, exits nonzero, and leaves FAILED).
# The session folder is created with plain `mkdir` (it must not exist; out_root is created separately and must be
# owned by root or you and not world-writable) and `set -C` (noclobber) keeps every later write from following a
# pre-planted file or symlink. The schedule is REQUIRED: a session id missing from it, or a missing schedule file,
# fails the run unless --allow-unscheduled is given. A pilot (out_root ending in /pilot or containing '/pilot')
# is always allowed to be unscheduled and gets "pilot": true in meta.json. BENCH_PATH is exported for session_meta.py.
# --retry re-runs a failed session id: a folder with a FAILED marker and no meta.json is renamed to
# <folder>.failed-<UTC timestamp> (kept for inspection, never deleted) and the session starts fresh; without --retry
# such a folder is an error that prints the exact command. A folder with meta.json is never retried.
# Not done: refusing to run while another libvirt domain is up (virsh list --name). The matching domain name
# is not known to this script, so such a check could wrongly block or wrongly allow a run; stop other VMs by hand.
set -eu
set -C  # noclobber: `>` never overwrites an existing file or follows a planted symlink (use `>|` deliberately)
umask 077
LC_ALL=C; export LC_ALL
MARK=""  # set once this run owns the session folder: die() then records the reason in it
die() {
  echo "run_session: $*" >&2
  [ -z "$MARK" ] || echo "$*" >| "$MARK" 2>/dev/null || true
  exit 1
}
# whole-string checks (case patterns match newlines too, grep -E would test line by line)
is_id() { case $1 in ''|[!A-Za-z0-9]*|*[!A-Za-z0-9_.-]*) return 1;; esac; }
is_pos_int() { case $1 in ''|0*|*[!0-9]*) return 1;; esac; }
# check_trusted <path> <label> [other-only]: owned by root or by us, and not group/world-writable
# (with a third argument, only world-writable is refused)
check_trusted() {
  _st=$(stat -c '%u %a' "$1" 2>/dev/null) || die "cannot stat $1"
  _uid=${_st% *}; _mode=${_st#* }
  { [ "$_uid" = 0 ] || [ "$_uid" = "$(id -u)" ]; } || die "$2 $1 must be owned by root or by you (owner uid $_uid)"
  _m=000$_mode; _go=${_m#"${_m%??}"}  # group and other digits; write bit set in 2, 3, 6, 7
  case $_go in
    ?[2367]) die "$2 $1 must not be world-writable (mode $_mode)";;
    [2367]?) [ -n "${3:-}" ] || die "$2 $1 must not be group- or world-writable (mode $_mode)";;
  esac
}

ALLOW_UNSCHED=""; RETRY=""
while [ $# -gt 0 ]; do
  case $1 in
    --allow-unscheduled) ALLOW_UNSCHED=1; shift;;
    --retry) RETRY=1; shift;;
    *) break;;
  esac
done
[ $# -ge 2 ] || die "usage: $0 [--allow-unscheduled] [--retry] <native|kvm-plain|kvm-masked> <session_id> [window_ms] [n_windows] [out_root]"
CLS=$1; ID=$2; WIN=${3:-100}; N=${4:-300}; OUT=${5:-data/m4}
case $CLS in native|kvm-plain|kvm-masked) ;; *) die "class must be native, kvm-plain or kvm-masked (got '$CLS')";; esac
is_id "$ID" || die "bad session id (use letters, digits, _ . -; start with letter or digit)"
is_pos_int "$WIN" || die "window_ms must be a whole number >= 1 (got '$WIN')"
is_pos_int "$N" || die "n_windows must be a whole number >= 1 (got '$N')"

ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
SCHEDULE=${SCHEDULE:-$ROOT/data/m4/schedule.json}  # session_meta.py fails if it is missing or lacks the session
BENCH=${BENCH:-$ROOT/bench}
BENCH_REAL=$(realpath "$BENCH" 2>/dev/null || readlink -f "$BENCH" 2>/dev/null) || BENCH_REAL=""
[ -n "$BENCH_REAL" ] || die "cannot resolve bench path: $BENCH"
BENCH=$BENCH_REAL
BENCH_PATH=$BENCH; export BENCH_PATH  # session_meta.py records its sha256
[ -f "$BENCH" ] && [ -x "$BENCH" ] || die "bench not found or not executable: $BENCH (compile it, or set BENCH=)"
check_trusted "$BENCH" bench
check_trusted "$(dirname "$BENCH")" "bench directory"
command -v shuf >/dev/null 2>&1 || die "shuf is required (coreutils)"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
case $OUT in
  /*) ;;
  *) [ "$(pwd -P)" = "$ROOT" ] || die "run from the repo root ($ROOT) or give an absolute out_root";;
esac

PILOT=""
case $OUT in pilot|pilot/*|*/pilot*) PILOT=1;; esac
mkdir -p -- "$OUT" || die "cannot create out_root $OUT"
check_trusted "$OUT" "out_root" other-only
D="$OUT/$ID"
if [ -e "$D/meta.json" ] || [ -L "$D/meta.json" ]; then die "$D/meta.json already exists; use a new session id"; fi
# A session folder with a FAILED marker and no meta.json can be re-run with --retry: it is RENAMED (never deleted)
# to <folder>.failed-<UTC time> and the session starts fresh. A folder with meta.json is never retried (above).
if [ -d "$D" ] && [ ! -L "$D" ] && [ -f "$D/FAILED" ] && [ ! -L "$D/FAILED" ]; then
  [ -n "$RETRY" ] || die "$D is a failed session (FAILED marker, no meta.json). Inspect it first (cat $D/FAILED; cat $D/qc.json), then move it aside and start fresh with: $0 --retry $CLS $ID $WIN $N $OUT"
  MOVED="$D.failed-$(date -u +%Y%m%dT%H%M%SZ)"
  [ ! -e "$MOVED" ] && [ ! -L "$MOVED" ] || die "$MOVED already exists; wait a second and retry"
  mv -- "$D" "$MOVED" || die "cannot rename $D to $MOVED"
  echo "run_session: moved the failed session $D to $MOVED (kept, not deleted)" >&2
elif [ -n "$RETRY" ] && { [ -e "$D" ] || [ -L "$D" ]; }; then
  die "--retry: $D exists but has no FAILED marker (not a failed session); not touching it"
fi
mkdir -- "$D" || die "cannot create session folder $D (it must not exist already; use a new session id)"
MARK="$D/FAILED"
echo "session started and not finished" > "$MARK"

# --- CPU governor and turbo: save, set (abort if impossible), restore on exit ---
SAVED_GOV=""; SAVED_TURBO=""
NT=/sys/devices/system/cpu/intel_pstate/no_turbo
restore() {
  trap - EXIT INT TERM HUP
  for entry in $SAVED_GOV; do echo "${entry#*=}" > "${entry%%=*}" 2>/dev/null || echo "run_session: could not restore ${entry%%=*}" >&2; done
  [ -z "$SAVED_TURBO" ] || echo "$SAVED_TURBO" > "$NT" 2>/dev/null || echo "run_session: could not restore no_turbo" >&2
}
trap 'restore' EXIT
trap 'restore; exit 130' INT
trap 'restore; exit 143' TERM
trap 'restore; exit 129' HUP

for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  [ -e "$g" ] || continue
  SAVED_GOV="$SAVED_GOV $g=$(cat "$g")"
  echo performance > "$g" 2>/dev/null || die "cannot set governor in $g (run as root)"
  [ "$(cat "$g")" = performance ] || die "governor in $g did not change to performance"
done
if [ -e "$NT" ]; then
  SAVED_TURBO=$(cat "$NT")
  echo 1 > "$NT" 2>/dev/null || die "cannot set no_turbo (run as root)"
  [ "$(cat "$NT")" = 1 ] || die "no_turbo did not change to 1"
fi

# --- workloads: write to a temp name, rename when finished ---
hottest() { cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | sort -n | tail -1; }
: > "$D/thermal.txt"
for W in $(printf 'idle\ncpu\nmem\nmixed\n' | shuf); do
  echo "$ID $W"
  T0=$(hottest)
  "$BENCH" "$W" "$WIN" "$N" > "$D/$W.csv.tmp" 2> "$D/$W.bench.txt" || die "bench failed for $W (see $D/$W.bench.txt)"
  mv "$D/$W.csv.tmp" "$D/$W.csv"
  T1=$(hottest)
  echo "$W before=${T0:-na} after=${T1:-na} uptime_s=$(cut -d. -f1 /proc/uptime)" >> "$D/thermal.txt"
done

# --- every workload must have produced a header plus at least one row ---
CNT=0
for W in idle cpu mem mixed; do
  [ -f "$D/$W.csv" ] && [ "$(wc -l < "$D/$W.csv")" -gt 1 ] || die "missing or empty $D/$W.csv; no meta.json written"
  CNT=$((CNT + 1))
done
[ "$CNT" -eq 4 ] || die "expected 4 workload CSVs, found $CNT"
[ "$(ls "$D"/*.csv | wc -l)" -eq 4 ] || die "unexpected extra CSV files in $D"

python3 "$ROOT/scripts/session_meta.py" --schedule "$SCHEDULE" --session "$ID" \
  ${PILOT:+--pilot} ${ALLOW_UNSCHED:+--allow-unscheduled} -- "$CLS" "$D" "${TEMP_C:-}" \
  || die "session_meta.py failed (message above); $D has no meta.json and is not a usable session"
[ -f "$D/meta.json" ] || die "session_meta.py wrote no meta.json in $D"
# QC writes its own reason into FAILED, so on failure keep that marker instead of overwriting it
python3 "$ROOT/scripts/session_qc.py" "$D" || { MARK=""; echo "run_session: QC failed for $D (see $D/qc.json); data kept, FAILED marker left: re-run this session" >&2; exit 1; }
rm -f "$MARK"  # success: only now does the folder look like a complete session
MARK=""
chmod 700 "$D" 2>/dev/null || true
echo "done $D"
