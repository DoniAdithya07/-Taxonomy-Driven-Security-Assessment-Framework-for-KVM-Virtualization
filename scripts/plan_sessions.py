#!/usr/bin/env python3
"""Blocked, randomised M4 session schedule. Seeded and saved.

    python scripts/plan_sessions.py [per_class] [per_day] [output] [--seed N]
    (defaults: 15, 6, <repo>/data/m4/schedule.json, 2025)

Blocked design: every block of 3 consecutive sessions holds native, kvm-plain and kvm-masked once, in random
order, and a day holds per_day/3 blocks. So every day contains all three classes and day effects cannot line
up with class. per_day must be a multiple of 3. Refuses to overwrite an existing schedule. Every entry records
the seed ("seed"); the same arguments and seed always give the same schedule. The file is written under a
temporary name and renamed, so a failure never leaves a half-written schedule.
"""
import argparse
import json
import os
import random
import sys
from pathlib import Path

CLASSES = ("native", "kvm-plain", "kvm-masked")
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "data" / "m4" / "schedule.json"


def make_schedule(per_class, per_day, seed):
    rng = random.Random(seed)
    order = []
    for _ in range(per_class):
        block = list(CLASSES)
        rng.shuffle(block)
        order += block
    return [{"session": f"s{i:03d}", "cls": c, "day": i // per_day + 1, "batch": i // per_day + 1, "seed": seed}
            for i, c in enumerate(order)]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("per_class", nargs="?", type=int, default=15)
    ap.add_argument("per_day", nargs="?", type=int, default=6)
    ap.add_argument("output", nargs="?", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--seed", type=int, default=2025)
    a = ap.parse_args(argv)
    if a.per_class < 1:
        ap.error("per_class must be a whole number >= 1")
    if a.per_day < 3 or a.per_day % 3:
        ap.error("per_day must be a multiple of 3 (and >= 3) so that every day holds all three classes")
    out = a.output
    if out.exists():
        sys.exit(f"{out} already exists; refusing to overwrite (delete it by hand if you really want a new plan)")
    sched = make_schedule(a.per_class, a.per_day, a.seed)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    try:
        tmp.write_text(json.dumps(sched, indent=1))
        os.replace(tmp, out)
    finally:
        tmp.unlink(missing_ok=True)
    print(f"wrote {out} ({len(sched)} sessions over {sched[-1]['day']} days, seed {a.seed})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
