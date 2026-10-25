#!/bin/sh
# HOST-side: build the Volatility 3 symbol file (ISF) for the pinned guest kernel. Never run this inside the
# `target` VM: after a rootkit might have been loaded the guest cannot be trusted to build its own symbols.
#
#   build_symbols.sh <vmlinux-debug-file> <expected-sha256-of-vmlinux> <dwarf2json-binary> \
#                    <expected-sha256-of-dwarf2json> [out-dir]
#
# Get linux-image-<ver>-dbgsym (ddebs.ubuntu.com) and dwarf2json (github.com/volatilityfoundation/dwarf2json)
# on the host; the vmlinux file must be named vmlinux-<ver>. Both inputs are COPIED into a private 0700 temp dir, the
# COPIES are verified with sha256sum (64 hex characters required; empty or short values are rejected) and the copy
# of dwarf2json is the one executed, so nothing can swap the files between the check and the use.
# Output: <out-dir>/ubuntu-<ver>.json plus ubuntu-<ver>.json.sha256 (default out-dir: current folder).
# The sha256 of the ISF printed at the end goes into prereg.md. It is MANDATORY at analysis time: m3_forensics.detect
# refuses to run without it (env VSEC_SYMBOLS_SHA256 or argument), copies the ISF and re-hashes the copy first. Then copy the .json into Volatility's symbols/linux/.
set -eu
umask 077
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    echo "usage: $0 <vmlinux> <sha256> <dwarf2json> <sha256> [out-dir]" >&2
    exit 2
fi
VMLINUX=$1
VM_SHA=$2
D2J=$3
D2J_SHA=$4
OUT=${5:-.}
case $D2J in */*) ;; *) D2J=./$D2J ;; esac  # a bare name must not be looked up on PATH
hex64() {  # hex64 <value>: print it lower-case with whitespace removed; fail unless exactly 64 hex characters
    v=$(printf '%s' "$1" | tr 'A-F' 'a-f' | tr -d '[:space:]')  # accept upper case and stray whitespace
    case $v in *[!0-9a-f]*) return 1 ;; esac
    [ "${#v}" -eq 64 ] || return 1
    printf '%s' "$v"
}
VM_WANT=$(hex64 "$VM_SHA") || { echo "expected vmlinux sha256 must be exactly 64 hex characters (got '$VM_SHA')" >&2; exit 2; }
D2J_WANT=$(hex64 "$D2J_SHA") || { echo "expected dwarf2json sha256 must be exactly 64 hex characters (got '$D2J_SHA')" >&2; exit 2; }
BASE=$(basename "$VMLINUX")
case "$BASE" in
    vmlinux-?*) K=${BASE#vmlinux-} ;;
    *) echo "vmlinux file must be named vmlinux-<ver>, got $BASE" >&2; exit 1 ;;
esac
[ -d "$OUT" ] || { echo "out-dir not found: $OUT" >&2; exit 1; }
WORK=$(mktemp -d) || { echo "cannot create a private temp dir" >&2; exit 1; }
chmod 700 "$WORK"
TMP=""
trap 'rm -rf "$WORK"; [ -z "$TMP" ] || rm -f "$TMP" "$TMP.sha256"' EXIT
stage() {  # stage <original> <copy> <expected-sha256>: copy once, hash the COPY; the original is never read again
    [ -f "$1" ] || { echo "not found: $1" >&2; exit 1; }
    cp -- "$1" "$2" || { echo "cannot copy $1" >&2; exit 1; }
    got=$(sha256sum "$2") || { echo "sha256sum failed for $1" >&2; exit 1; }
    got=${got%% *}
    [ "$got" = "$3" ] || { echo "SHA-256 mismatch for $1: got $got, expected $3" >&2; exit 1; }
}
stage "$VMLINUX" "$WORK/$BASE" "$VM_WANT"
stage "$D2J" "$WORK/dwarf2json" "$D2J_WANT"
chmod 700 "$WORK/dwarf2json"
[ -x "$WORK/dwarf2json" ] || { echo "dwarf2json is not executable: $D2J" >&2; exit 1; }
FINAL=$OUT/ubuntu-$K.json
TMP=$(mktemp "$OUT/ubuntu-$K.json.XXXXXX")
"$WORK/dwarf2json" linux --elf "$WORK/$BASE" > "$TMP" || { echo "dwarf2json failed; no symbol file written" >&2; exit 1; }
[ -s "$TMP" ] || { echo "dwarf2json produced an empty file; no symbol file written" >&2; exit 1; }
SUM=$(sha256sum "$TMP") || { echo "sha256sum failed for the symbol file" >&2; exit 1; }
SUM=${SUM%% *}
echo "$SUM  ubuntu-$K.json" > "$TMP.sha256"
mv "$TMP.sha256" "$FINAL.sha256"
mv "$TMP" "$FINAL"
TMP=""
echo "wrote $FINAL"
echo "ISF sha256: $SUM   (put this in prereg.md)"
