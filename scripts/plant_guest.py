#!/usr/bin/env python3
"""Run INSIDE the `target` VM (no network, snapshot reverted before each experiment).
Plants one synthetic secret in one memory state and writes the manifest the host needs.

    python3 plant_guest.py <ssh_key|aws|jwt|hex32> <live|freed|exited> <manifest.json>

Needs only the Python standard library plus secrets_gen.py in the SAME folder as this script (it does
not use vsec/guards.py).
Then, on the host:  virsh dump target dump.mem --memory-only --format raw
and copy the manifest next to the dump as dump.json (same base name, .mem + .json).
"""
import functools
import importlib.util
import json
import os
import random
import subprocess
import sys
import time

KINDS = ("ssh_key", "aws", "jwt", "hex32")
STATES = ("live", "freed", "exited")


@functools.lru_cache(maxsize=None)
def _load_secrets_gen():
    """Loaded on first use, so importing this file for its offline checks (guard_rootkit.py) needs no secrets_gen."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secrets_gen.py")
    spec = importlib.util.spec_from_file_location("secrets_gen", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _lines(path, required=True):
    try:
        with open(path) as f:
            return f.read().splitlines()
    except FileNotFoundError:
        if required:
            raise
        return []


def _fib_trie_addresses(lines):
    """Local IPv4 addresses from /proc/net/fib_trie ('|-- a.b.c.d' followed by '/32 host LOCAL')."""
    found = []
    for prev, line in zip(lines, lines[1:]):
        if "/32 host LOCAL" in line and prev.strip().startswith("|--"):
            found.append(prev.split()[-1])
    return [a for a in found if not a.startswith("127.")]


def offline_problems(root="/"):
    """List why the guest looks online ([] = offline). `root` is the filesystem root to read /proc and /sys
    from (a fake tree in tests). Fails closed: any non-lo interface whose operstate is not 'down' (so 'unknown'
    counts as online), any non-lo IPv4/IPv6 address or route, and any default route."""
    problems = []
    for line in _lines(os.path.join(root, "proc/net/route"))[1:]:
        cols = line.split()
        if len(cols) > 1 and cols[0] != "lo":
            problems.append(f"default route via {cols[0]}" if cols[1] == "00000000"
                            else f"IPv4 route on interface {cols[0]}")
    for line in _lines(os.path.join(root, "proc/net/if_inet6"), required=False):
        cols = line.split()
        if len(cols) >= 6 and cols[5] != "lo":
            problems.append(f"IPv6 address on interface {cols[5]}")
    for addr in _fib_trie_addresses(_lines(os.path.join(root, "proc/net/fib_trie"), required=False)):
        problems.append(f"IPv4 address {addr}")
    net = os.path.join(root, "sys/class/net")
    for name in sorted(os.listdir(net)):
        if name == "lo":
            continue
        with open(os.path.join(net, name, "operstate")) as f:
            state = f.read().strip()
        if state != "down":
            problems.append(f"network interface {name} is not down (operstate {state!r})")
    return problems


def check_offline(root="/"):
    """Exit unless offline_problems() is empty. Convenience only: the authoritative gate is the host-side
    scripts/preflight_target.py, because a guest can lie about its own state."""
    problems = offline_problems(root)
    if problems:
        sys.exit("REFUSING TO RUN: the guest must be offline: " + "; ".join(problems)
                 + ". (The host-side gate scripts/preflight_target.py is the authoritative check.)")


def plant(kind, state, secret):
    """Put the secret in memory. Returns the object to keep alive: the text for 'live', None otherwise,
    so after 'freed' (or 'exited') no reference to the secret remains; only stale heap bytes do."""
    text = _load_secrets_gen().plant_text(kind, secret).encode()
    buf = bytearray(text * 4)  # noqa: F841  (touches fresh memory; dies when this frame returns)
    return text if state == "live" else None


def hold(kind, state):
    keep = plant(kind, state, sys.stdin.read())  # the secret arrives on stdin, never on argv
    if state == "exited":
        return  # the process just exits; the page stays behind
    while True:  # `keep` stays referenced here for 'live'; it is None for 'freed'
        time.sleep(60)


def start_child(kind, state, secret):
    """Start the holder child and hand it the secret on stdin. Returns (ok, message). A broken pipe, timeout or
    OS error kills the child and returns (False, message): no traceback, and no child left behind."""
    proc = subprocess.Popen([sys.executable, os.path.abspath(__file__), "--hold", kind, state],
                            stdin=subprocess.PIPE, text=True)
    try:
        proc.stdin.write(secret)
        proc.stdin.close()
        if state == "exited":
            code = proc.wait(timeout=30)
            return code == 0, f"child exit code {code}"
        time.sleep(2)
        return proc.poll() is None, f"child exited early with code {proc.poll()}"
    except (BrokenPipeError, subprocess.TimeoutExpired, OSError) as e:
        proc.kill()
        proc.wait()
        return False, f"{type(e).__name__}: {e}"


def main(argv):
    if len(argv) == 3 and argv[0] == "--hold":
        hold(argv[1], argv[2])
        return
    if len(argv) != 3 or argv[0] not in KINDS or argv[1] not in STATES:
        sys.exit(__doc__)
    kind, state, manifest = argv
    check_offline()
    secret = _load_secrets_gen().make_secret(kind, random.Random())
    ok, msg = start_child(kind, state, secret)
    if not ok:
        sys.exit(f"planting failed: {msg}")  # nonzero exit, one message, no traceback
    with open(manifest, "w") as f:
        json.dump({"cell": f"{kind}/{state}", "needles": [secret.encode().hex()],
                   "planted": [_load_secrets_gen().plant_text(kind, secret).encode().hex()]}, f)
    print("planted", kind, state)


if __name__ == "__main__":
    main(sys.argv[1:])
