# vsec: taxonomy-driven security assessment for KVM virtualization

**Scope and AI assistance.** This project was built by one student using an AI coding assistant (Claude). The assistant produced most of the code, tests, documentation and first drafts of this paper and the slides under the student's direction. Code review was done by automated AI reviewers only; no person has independently reviewed or reproduced the work. The tests were written by the same assistant, so they show internal consistency, not correctness. No real measurements exist: the multi-signal hypervisor-detection experiment (M4), the secret scanner on real memory dumps (M2) and the forensics module (M3) have not been run on real hardware. Anything from simulated or synthetic data is a pipeline check and is not a result.

Plan: `FINAL_PROJECT_PLAN.md`. Pre-registration: `prereg.md`. `PASS` means "this control passed its test", not "the system is secure".

## Status

| Part | Built | Verified here (Windows, no KVM) |
|---|---|---|
| Common framework (`taxonomy.yaml`, findings, `report.py`, `python -m vsec run`) | yes | yes |
| M1 auditor (28 controls) + 50 fixtures + scoring | yes | yes (unit tests; M1 fixtures are self-consistency tests) |
| M2 scanner, redaction, scoring | yes | on synthetic dumps only |
| M3 Volatility wrapper + scoring | yes | scoring only; needs Volatility and real dumps |
| M4 `bench.c`, features, nested CV, H1-H4 | yes | Python side on simulated data; `bench.c` compiles with zero warnings (gcc 13 and the zig cross-compiler) and has run once in WSL2 as a functional check (real CSV loads, QC passes); **never run on the E1 native machine or in a KVM guest**, so no real M4 result exists |
| E1 (native machine), real VMs, real data | scripts only | no |

**Change log and what comes next:** see `FINAL_PROJECT_PLAN.md` section 12 (what was done, round by round) and section 13 (planned changes). Short version: Rounds 2, 4 and 5 were AI-agent review waves, all fixed. Built on Windows and checked once on Linux under WSL2. After that, everything depends on real hardware, listed step by step in `docs/YOUR_TASKS.md`. Treat all numbers from `--simulate` and synthetic dumps as not citable.

## Setup (project-local)
```
python -m venv .local/venv
.local/venv/Scripts/pip install -r requirements.txt     # Linux: .local/venv/bin/pip
.local/venv/Scripts/python -m pytest                      # Linux: .local/venv/bin/python -m pytest; full suite is about 4 min
.local/venv/Scripts/python -m pytest -q -m "not slow"    # quick subset: about 5 min, roughly 1008 passed 19 skipped 1 deselected
```

## Commands
Use `.local/venv/Scripts/python` (Windows) or `.local/venv/bin/python` (Linux) in all commands:
```
.local/venv/Scripts/python -m vsec run --simulate         # report in out/, M4 from SIMULATED data (pipeline check only)
.local/venv/Scripts/python -m vsec run --vm weak=cases/weak --vm hardened=cases/hardened --m2-dumps data/m2 --m3-results data/m3.json --m4-data data/m4 --t-short <seconds>
.local/venv/Scripts/python -m vsec run --env E0 --simulate # override environment label
.local/venv/Scripts/python -m vsec run --fast              # quick M4: 200 bootstrap reps, 1 CV repeat, logreg only (not citable)
.local/venv/Scripts/python -m vsec audit <case-folder> [--env E0|E1] # M1 on one captured case folder (exit 1 if FAIL, 2 if missing)
.local/venv/Scripts/python -m vsec.collect <vm-name> <out-folder>    # on the KVM host: capture files M1 reads (output only under cases/ or .local/)
.local/venv/Scripts/python -m vsec m3 <dump.mem> --symbols <file> --symbols-sha256 <hash> [--allow-unverified]  # hidden process/module check
.local/venv/Scripts/python -m vsec pilot --data <dir> [--per-class-min N]  # print T_short for PILOT window (exit 0 if ok, 2 if missing)
.local/venv/Scripts/python scripts/plan_sessions.py [per_class] [per_day] [output] [--seed N]  # create M4 session schedule
.local/venv/Scripts/python tests/make_fixtures.py         # regenerate the M1 ground truth
```

**Exit codes:**
- `run`: 1 if any module crashed (ERROR); NA modules only warn
- `audit`: 1 if any FAIL; 2 if folder missing
- `pilot`: 0 if T_short was chosen; 1 if no T_short chosen (data quality issue); 2 if missing or malformed data
- `m3`: 0 if ok; 1 on crash (RuntimeError, etc.); 2 if tools missing or symbols hash required
- `collect`: 0 if complete; 1 if a LIVE file missing; 2 on error

## Preflight and safety scripts (W1+)
```
scripts/preflight_target.py [--mark-reverted]     # host gate: confirm no other VM, target offline, hostdev-free
scripts/guard_rootkit.py                          # prepare isolated target VM for rootkit test
scripts/run_vol_sandboxed.sh <dump> <vol> [vol-args...]  # run Volatility in no-network, memory-capped, unprivileged (refuses root and writable dumps)
scripts/build_symbols.sh <vmlinux> <vmlinux-sha256> <dwarf2json> <dwarf2json-sha256> [out-dir]  # build symbol file on host-side with pinned sha256
```

## Real-data steps
**E0 (WSL2 Ubuntu 24.04 + libvirt):** `sudo apt install qemu-system-x86 libvirt-daemon-system virtinst`; define `weak` and `hardened` VMs; run `python -m vsec.collect <vm> cases/<vm>`.

**E1 (native machine, external SSD):** Write BitLocker recovery key on paper offline. Disconnect the internal disk during the Ubuntu install; `apt-mark hold` kernel and QEMU and disable `unattended-upgrades`; add `clocksource=tsc` to the kernel command line. For native boots only, add `maxcpus=2 mem=4G` (to match the 2-vCPU guests). VMs' XMLs pin vCPUs 0-1 to host CPUs 2-3 (so native also needs only 2 online CPUs to match). Keep one **read-only base image** (`/var/lib/libvirt/images/base.raw`) and write the same image to a spare partition for native boots. Each VM gets its own qcow2 overlay on that base:
```
qemu-img create -f qcow2 -b /var/lib/libvirt/images/base.raw -F raw /var/lib/libvirt/images/vsec-plain.qcow2
qemu-img create -f qcow2 -b /var/lib/libvirt/images/base.raw -F raw /var/lib/libvirt/images/vsec-masked.qcow2
virsh net-define vms/isolated-network.xml; virsh net-start isolated     # must have no <forward>: virsh net-dumpxml isolated
virsh define vms/kvm-plain.xml; virsh define vms/kvm-masked.xml
gcc -O2 -Wall -o bench vsec/m4_detect/bench.c -lm                        # on the target E1 machine
python3 scripts/plan_sessions.py                                         # writes data/m4/schedule.json, refuses to overwrite
# For M4 sessions: overlay rebuild, then run_session.sh per session (no preflight needed)
# For M2/M3 dumps: virsh snapshot-revert target <snap> → virsh domif-setlink target <vnetN> down → python scripts/preflight_target.py --mark-reverted → python scripts/preflight_target.py (gate) → virsh dump target ...
sudo scripts/run_session.sh <class> <session_id> [window_ms] [n_windows]  # from the repo root, native boot, or from inside a guest
```

**Before M4 sessions:** compile bench and install it for root-only use (it reads CPU frequency control which requires root):
```bash
gcc -O2 -Wall -o bench vsec/m4_detect/bench.c -lm
sudo install -D -o root -g root -m 755 bench /opt/vsec/bench
```

**Before every M4 session:** rebuild the overlay (delete it, then `qemu-img create -f qcow2 -b /var/lib/libvirt/images/base.raw -F raw /var/lib/libvirt/images/vsec-<class>.qcow2`). Never run both VMs at once. Run `run_session.sh` from the repo root with the BENCH variable:
```bash
sudo BENCH=/opt/vsec/bench TEMP_C=25 scripts/run_session.sh <class> <id> <window_ms> <n_windows> [out_root]
```
The script sets the CPU governor to `performance` and turbo off (it aborts if it cannot, e.g. when not root) and restores both on exit. It writes one CSV per workload (`idle`, `cpu`, `mem`, `mixed`) and `meta.json`; if any CSV is missing or empty it exits with an error, writes a `FAILED` marker in the session folder, and produces no `meta.json`. Bench must be owned by root or the invoking uid and not group/world-writable. After all sessions complete: `sudo chown -R $USER data/m4` (root-owned mode-700 folders block your own reads).

**If a session fails:** look at `<session_folder>/FAILED` and `<session_folder>/qc.json`, fix the cause, and re-run:
```bash
sudo BENCH=/opt/vsec/bench TEMP_C=25 scripts/run_session.sh --retry <class> <id> <window_ms> <n_windows> [out_root]
```
The `--retry` flag moves the failed folder aside to `<id>.failed-<UTC>` (never deleted) and re-runs. A session with `meta.json` already present is final and should never be retried.

**Bench usage:** `./bench <idle|cpu|mem|mixed> <window_ms> <n_windows>`
- Positional `<workload>`: one of `idle`, `cpu`, `mem`, `mixed`.
- Positional `<window_ms>`: only scales probe size (clamped to 1..100 ms equivalent); it is NOT a duration.
- Positional `<n_windows>`: number of measurement windows to run.

`bench` CSV columns (contract for features.load()): `window,workload,elapsed_ms,cpuid_tsc,rdtsc_tsc,syscall_ns,pagefault_ns,seq_ns,stride_ns,rand_ns,sleep_jitter_us,ipc,dtlb_miss`, plus a `#` metadata line on stderr. `elapsed_ms` is the real measured wall-clock time of each window (not window_ms, which only scales probe size). The `*_tsc` columns are in TSC ticks. Columns with NaN are dropped before model training (recorded in load_report).

**Privacy of data:** case folders (`cases/`) and memory dumps are sensitive (they can hold keys and logs). Create them with mode 0700 (`umask 077`, `chmod 700`); do not commit dumps (`*.mem`, `*.dump`, `*.save`, `data/m2/`, `data/m3/` are gitignored).

**M2 (target VM, no network, snapshot reverted before every run):** `virsh snapshot-revert target <snap>` → `virsh domif-setlink target <vnetN> down` (needed after every revert unless snapshot XML has `<link state='down'/>`; guest refuses to plant and gate fails while link is up) → `python scripts/preflight_target.py --mark-reverted` → copy `scripts/plant_guest.py` and `vsec/secrets_gen.py` into guest → inside guest run `python3 plant_guest.py <ssh_key|aws|jwt|hex32> <live|freed|exited> m.json` → back on host `python scripts/preflight_target.py` (gate, WITHIN 15 MINUTES) → `virsh dump target data/m2/<kind>_<state>_<n>.mem --memory-only --format raw` → copy m.json out as same base name .json → `chmod 444` the dump. 4 kinds × 3 states = 12 cells; n=5 first then 10 per cell; revert marker is single-use and expires in 15 minutes.

**M3:** `scripts/build_symbols.sh` builds the symbol file on the host-side with pinned sha256 for vmlinux and dwarf2json. Requires Volatility 3 installed locally (OUTSIDE $HOME on E1, e.g., `/opt/vsec-venv`). Check plugin names in `vsec/m3_forensics.py` against your Volatility version.

**M3 results integration:**
```bash
# For each dump (e.g., from Task E), run m3 and append results:
VSEC_SYMBOLS_SHA256=$(cat .local/symbols/ubuntu-<version>.sha256)
export VSEC_SYMBOLS_SHA256

for dump in data/m2/*.mem; do
  name=$(basename "$dump" .mem)  # e.g., "ssh_key_live_5"
  python -m vsec m3 "$dump" \
    --symbols .local/symbols/ubuntu-<version>.json \
    --row-name "$name" \
    --truth-hidden PID1,PID2 \
    --append data/m3/results.json
done

# Then run the full analysis with M3 results:
python -m vsec run \
  --m3-results data/m3/results.json \
  --symbols-sha256 "$VSEC_SYMBOLS_SHA256" \
  --m4-data data/m4 \
  --t-short <value-from-pilot>
```
Note: `--row-name`, `--truth-hidden`, and `--append` are new flags for building results files. Rows without a matching verified symbols hash give C30 = NA.

**C16 (network isolation):** Requires `collect.py` to write a host-verified `net_isolation.txt` confirming network isolation (checked via virsh against the actual network definition, not guest-side). Guest scan is corroboration only. `collect.py` redacts VNC/SPICE password values and only writes to `cases/` or `.local/`.

## Layout
```
vsec/        taxonomy.yaml cves.yaml collect.py score.py report.py __main__.py m1_audit.py m2_snapshot.py m3_forensics.py m4_detect/ secrets_gen.py guards.py
tests/       fixtures/ (GENERATED by make_fixtures.py; gitignored; `run` regenerates into .local/work/fixtures)
scripts/     plan_sessions.py plant_guest.py preflight_target.py guard_rootkit.py guest_scan.py run_vol_sandboxed.sh build_symbols.sh run_session.sh session_qc.py session_meta.py make_submission_zip.py
docs/        DEMO_SCRIPT.md YOUR_TASKS.md E1_CHECKLIST.md DATA_SOURCES.md paper/ (paper.md, README.md, references.md) slides/
vsec/m4_detect/  bench.c simulate.py stats.py features.py classify.py
vms/         kvm-plain.xml kvm-masked.xml isolated-network.xml
.local/      venv, VMs, dumps, datasets, logs (gitignored)
prereg.md FINAL_PROJECT_PLAN.md THIRD_PARTY.md SUBMISSION.md requirements.txt requirements-dev.txt requirements.lock pytest.ini
```

## Known limits
- **M1 fixtures are self-consistency tests:** written by the same author as the checker, showing internal consistency, not external correctness. Independent evidence comes from live Lynis/OpenSCAP comparison and real-world configurations.
- **M2 synthetic dumps:** cannot distinguish live, freed and exited data; the scanner's results say nothing about temporal state.
- **M4 one real run:** `bench.c` was compiled and run once in WSL2 (Ubuntu 24.04, gcc 13.3) on 2026-10-04 as a functional check. WSL2 is itself a VM under Hyper-V, so this is **not** a native-vs-VM comparison. No measurements from it are findings.
- **M3 never run:** Volatility integration is code-complete but has not been executed against real dumps.
- **M2 real data pending:** Real memory dumps from the E1 target VM have not been collected. The scanner has been validated on synthetic planted secrets only.
- **CVE list:** `vsec/cves.yaml` entries are marked `verified:false` and have not been checked against NVD. C23 and C24 return NA while any CVE entry is unverified and for distro builds (Ubuntu/Debian backports) even when verified.
- **Report banner:** when data is simulated or synthetic, the report shows a clear banner; `.local/venv/Scripts/python -m vsec pilot --data data/m4/pilot` prints the T_short.
- **Test results:** Windows: 1009 passed, 19 skipped (symlinks, POSIX permissions, bash/sandbox), about 4 minutes. One full Linux run on WSL2 (Ubuntu 24.04, Python 3.12, `D:` with metadata): 985 passed, 2 failed, 1 skipped. Both failures were fixed in code; the 6 affected tests re-run green; the full Linux suite was not re-run after the fixes. Quick subset test takes about 5 minutes (roughly 1008 passed, 19 skipped, 1 deselected). `.gitattributes` forces LF for scripts so a Windows checkout does not break them on Linux. There is still no CI service.

## Compile check without gcc
Windows has no gcc; this only checks that `bench.c` compiles for Linux (it does not run it):
```
.local\venv\Scripts\python -m pip install ziglang
python -m ziglang cc -target x86_64-linux-gnu -O2 -Wall -c vsec/m4_detect/bench.c -o .local/work/bench.o
```
