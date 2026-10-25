#!/usr/bin/env python3
"""HOST-side gate: run before every `virsh dump` / `virsh save` of the `target` VM. This is the authoritative
isolation check (the guest-side check in plant_guest.py can be lied to by a compromised guest).

    python3 scripts/preflight_target.py --mark-reverted   # right after `virsh snapshot-revert target <snap>` worked
    python3 scripts/preflight_target.py                   # the gate: exit 0 = safe, nonzero = refused

The gate checks, in order: the revert marker .local/target.reverted is valid (a JSON file {vm, created_utc,
pid, uuid, state}: not a symlink, for this VM and its libvirt uuid (`virsh domuuid`), younger than --max-age-minutes, default 15; single use: a passing gate deletes
it, so every experiment needs a fresh revert); no other libvirt domain is running; the domain XML has no way out
(host devices, shared folders, vsock, guest channels, network sockets, non-network NICs, raw QEMU arguments,
non-loopback consoles); every interface is on an isolated libvirt network (no forward, ip, dhcp or dns
forwarder); every link is down (`virsh domif-getlink` AND <link state='down'/> in the XML).
Every failure prints `PREFLIGHT FAILED: <reason>` and exits 1; there is never a traceback. --vm must be `target`.

Every virsh call is pinned to `-c qemu:///system` (LIBVIRT_DEFAULT_URI is ignored).

Standard library only: it loads vsec/guards.py by file path, so it needs neither scipy nor yaml.
"""
import argparse
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_guards():
    spec = importlib.util.spec_from_file_location("vsec_guards", ROOT / "vsec" / "guards.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


guards = _load_guards()
MARKER = ROOT / ".local" / "target.reverted"
VM = "target"


def _virsh(*args, timeout=60):
    return guards.virsh(*args, timeout=timeout)


def check_vm(vm):
    """Raise ValueError unless `vm` is a valid libvirt name AND the one VM this gate is for."""
    if not isinstance(vm, str) or not guards.VM_NAME.fullmatch(vm):
        raise ValueError(f"invalid --vm {vm!r}")
    if vm != VM:
        raise ValueError(f"--vm must be {VM!r}, not {vm!r}")


def mark_reverted(marker=MARKER, vm=VM):
    """Record the revert, bound to this domain's uuid and its current `virsh domstate`."""
    check_vm(vm)
    guards.write_marker(Path(marker), vm, uuid=guards.domain_uuid(vm, _virsh), state=guards.domain_state(vm, _virsh))


def run_gate(vm=VM, marker=MARKER, max_age_minutes=15):
    """Raise RuntimeError with a clear message on the first failed check. On success delete the marker."""
    check_vm(vm)
    marker = Path(marker)
    uuid = guards.domain_uuid(vm, _virsh)
    try:
        guards.check_marker(marker, vm, max_age_minutes, uuid=uuid)
    except RuntimeError as e:
        raise RuntimeError(f"{e}: run `virsh snapshot-revert {vm} <snapshot>`, then "
                           "`python3 scripts/preflight_target.py --mark-reverted`") from None
    guards.assert_no_other_running_domain(vm, _virsh)
    guards.assert_no_hostdev(vm, _virsh)
    guards.assert_vm_isolated(vm, _virsh)
    guards.assert_links_down(vm, _virsh)
    marker.unlink()  # single use


def main(argv=None):
    try:
        ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
        ap.add_argument("--mark-reverted", action="store_true", help="record that the snapshot was just reverted")
        ap.add_argument("--vm", default=VM)
        ap.add_argument("--max-age-minutes", type=float, default=15)
        args = ap.parse_args(argv)
        if not 0 < args.max_age_minutes <= 24 * 60:
            raise ValueError("--max-age-minutes must be between 0 and 1440")
        check_vm(args.vm)
        if args.mark_reverted:
            mark_reverted(MARKER, args.vm)
            print(f"marked: {MARKER}")
            return 0
        run_gate(args.vm, MARKER, args.max_age_minutes)
    except Exception as e:  # the gate must answer yes/no, never crash (ParseError, TimeoutExpired, OSError ...)
        print(f"PREFLIGHT FAILED: {e if isinstance(e, (RuntimeError, ValueError)) else f'{type(e).__name__}: {e}'}",
              file=sys.stderr)
        return 1
    print(f"preflight OK for {args.vm!r}: marker consumed, safe to dump once")
    return 0


if __name__ == "__main__":
    sys.exit(main())
