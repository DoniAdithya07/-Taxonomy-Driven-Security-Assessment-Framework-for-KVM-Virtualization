# Demo script (about 8 minutes, you record it yourself)

This script is for you to follow while screen-recording. Everything in Part 1 uses simulated or synthetic data from Windows. Part 2 requires the E1 machine and real data.

**Say this once, at the start and in the video description:** "This project was built by one student using an AI assistant. Everything in Part 1 uses simulated or synthetic data. It checks that the pipeline works. It is not a result."

Run all commands from the project root (`D:\malay case study`). Windows PowerShell shown; on E1 use `.local/venv/bin/python`.

```powershell
$env:TMP = "$PWD\.local\tmp"; $env:TEMP = "$PWD\.local\tmp"     # keep scratch inside the project
$PY = ".local\venv\Scripts\python"
```

## Part 1: what works today (simulated and synthetic only)

| Time | Step |
|---|---|
| 0:00-0:45 | Intro, framework, honesty rules |
| 0:45-2:30 | Tests |
| 2:30-4:30 | `audit` on a fixture |
| 4:30-6:00 | `run --fast --simulate` |
| 6:00-7:45 | `report.html` walk-through |
| 7:45-8:00 | Close |

### 0:00 Intro (no command)
Say: "This is vsec, a solo university project. It maps the threat taxonomy of a 2020 virtualization-security survey onto four modules and tests them on KVM. PASS means a control passed its defined test, never that the system is secure. NA is never PASS. Anything simulated is not citable. What you will see now is the pipeline running on simulated and synthetic data. Real measurements are pending the E1 machine."

### 0:45 Tests (about 1.5 min on screen; the run itself is longer)
```powershell
& $PY -m pytest -q -m "not slow"
```
Duration: expect roughly 5 minutes (about 1008 passed, 19 skipped, 1 deselected). The full suite takes about 4 minutes with 1009 passed and 19 skipped on Windows. Start it before recording and show only the end, or speed up that part of the video, and say that you cut it.
Say: "Passed and skipped counts. The 19 skips are tests that need Linux: symlinks, POSIX permissions, bash."
Do not claim: that this proves the tool works on real KVM hosts. It does not.

### 2:30 `audit` on one fixture
Generate the synthetic cases into a project-local folder (about 1 s, prints `50 cases, 84 seeded faults`):
```powershell
& $PY tests/make_fixtures.py .local/work/fx
& $PY -m vsec audit .local/work/fx/case00 --env E1
```
Output: one line per control: `C01 PASS iommu_cmdline <evidence>`. Columns are control id, status, control name, evidence. Exit code is 1 when any control FAILs (this is expected here; it is not a crash). Check with `echo $LASTEXITCODE`.
Lines to point at (fixtures are generated, so check your output before saying the following):
- A `PASS` line with evidence: "PASS means the test passed, and the evidence shows what was read."
- `C02 iommu_groups` was `NA` with "input not available": "NA means not testable with this input. It is never a PASS."
- `C23 qemu_cve` and `C24 kernel_cve` were `NA` with "entries are unverified": "The CVE list is not verified against NVD, so these return NA instead of guessing."
- `C17 image_permissions` and `C25 cpu_vulnerabilities` were `FAIL`, each with a fix in the taxonomy (`vsec/taxonomy.yaml`).
Say: "`--env E1` matters: on E0 (WSL2) IOMMU is NA. This fixture is synthetic, written by the same author as the checker, so a score on it shows self-consistency, not correctness."

### 4:30 Full report from simulated data
```powershell
& $PY -m vsec run --fast --simulate --out .local/work/out
```
Duration: about 1 minute. `--fast` = 200 bootstrap repeats, 1 CV repeat, logistic regression only. Expected shape:
- stderr line `warning: not real results: M2 (snapshot privacy) (synthetic/simulated), M3 (forensics) (NA), M4 (hypervisor detection) (synthetic/simulated)`
- then the fixtures line and the path `.local\work\out\report.html` (also `report.json`).
Say: "Look at the warning first: M2 and M4 are marked not real, M3 is NA because no dump was provided. The command still exits 0 because no module crashed. A crashed module would be ERROR with a red banner and exit code 1."

### 6:00 Walk through `report.html`
```powershell
start .local\work\out\report.html
```
Top to bottom (these are the headings in the file):
1. **Banner**: "CONTAINS SIMULATED/SYNTHETIC DATA: not citable", plus the FAST-mode notice and the M1/M2/M4 caveat lines. Read them aloud. Keep this banner on screen while any number is visible.
2. **Threat classes**: columns Label, Controls, Tested, N/A. In this run, with no `--vm` given, the classes show "Not tested in this run" and everything N/A. Say: "That is the honest outcome when I gave it no real VM: nothing is claimed as tested."
3. **Per VM**: layout of the matrix (class by VM). Cells read `NA (0/12 tested)`. Say: "A class would only show PASS when every control in it was tested."
4. **M1 / M2 / M4 sections**: scroll quickly. Say clearly: "These numbers come from synthetic dumps, simulated sessions and my own fixtures. I am not quoting any of them." Do **not** read out recall, AUROC or p-values.
5. **M3**: NA, no results given.
Close: "Real measurements are pending the E1 machine. The next part of the plan is below."

Clean up after recording:
```powershell
Remove-Item -Recurse -Force .local\work\out, .local\work\fx, .local\work\fixtures
```

## Part 2: REAL DEMO (after E1)

**Do not record or show any of this before it has really run on E1.** Each step lists the command and the *shape* of the output only. Fill in what you actually see; do not copy numbers from anywhere else. Flags below were checked against `vsec/__main__.py`, `scripts/run_session.sh` and `docs/YOUR_TASKS.md`, but **not executed** (they need Linux, root, KVM).

1. **Compile and run bench.c (Task A)**
   ```bash
   gcc -O2 -Wall -o bench vsec/m4_detect/bench.c -lm
   ./bench idle 100 20 > t.csv ; head -5 t.csv
   ```
   Expected shape: a CSV header `window,workload,elapsed_ms,cpuid_tsc,rdtsc_tsc,syscall_ns,pagefault_ns,seq_ns,stride_ns,rand_ns,sleep_jitter_us,ipc,dtlb_miss`, then one row per window; compiler prints no warnings. Note: `elapsed_ms` is real wall time (not the window_ms parameter, which only scales probe size). `bench.c` has been compiled and tested once in WSL2, but not on native hardware; be ready for unexpected issues and note what you see.
2. **One M4 session (script `run_session.sh`)**
   ```bash
   sudo install -D -o root -g root -m 755 bench /opt/vsec/bench
   sudo BENCH=/opt/vsec/bench TEMP_C=25 scripts/run_session.sh --allow-unscheduled native p01 100 300 data/m4/pilot
   ```
   Expected shape: sets governor to `performance` and turbo off, writes `idle.csv cpu.csv mem.csv mixed.csv meta.json` in `data/m4/pilot/p01/`; on failure a `FAILED` marker and no `meta.json`. Show `ls data/m4/pilot/p01` and `cat data/m4/pilot/p01/meta.json`. Note: `elapsed_ms` values are real wall time (measured 135-310 ms in the one WSL2 run), not the nominal window size. For `kvm-masked`, rebuild the qcow2 overlay first and run the script inside the guest (README.md, "Before every M4 session").
3. **Pilot (Task C, 5 native + 5 kvm-masked)**
   ```bash
   python -m vsec pilot --data data/m4/pilot
   ```
   Expected shape: per-T single and combined session AUROC grid, then either `Put this value into prereg.md PILOT: T_short = <t> s` (exit 0), or `no T_short chosen: <reason>` (exit 1), exit 2 for missing or malformed data. Say what you got, including if it is "untestable".
4. **M2 flow (Task E), one cell**
   ```bash
   virsh snapshot-revert target clean
   virsh domif-setlink target <vnetN> down
   python scripts/preflight_target.py --mark-reverted
   # inside the guest: python3 plant_guest.py ssh_key live m.json
   python scripts/preflight_target.py          # gate, within 15 minutes of the revert
   virsh dump target data/m2/ssh_key_live_1.mem --memory-only --format raw
   ```
   Expected shape: gate prints why it passes or fails (other VM running, target not reverted, link up...), the dump file appears, you copy `m.json` next to it as `.json` and `chmod 444` both. Show a gate FAILING on purpose once (for example skip the revert): that is the best safety demo.
5. **M3 on a dump, with row flags**
   ```bash
   export VSEC_SYMBOLS_SHA256=$(cat .local/symbols/ubuntu-<version>.sha256)
   python -m vsec m3 data/m2/ssh_key_live_1.mem --symbols .local/symbols/ubuntu-<version>.json \
     --row-name ssh_key_live_1 --truth-hidden PID1,PID2 --append data/m3/results.json
   ```
   Expected shape: found processes/modules as JSON, a line stating whether the sandbox was used, and one row appended to `data/m3/results.json` (fields `name`, `detected`, `truth_hidden`, `symbols_sha_verified`). Exit codes: 0 ok, 1 crash, 2 tools missing or symbols hash required. Symbols come from `scripts/build_symbols.sh` (Task G).
6. **Final report on real data**
   ```bash
   python -m vsec run --vm weak=cases/weak --vm hardened=cases/hardened --env E1 --m2-dumps data/m2 \
     --m3-results data/m3/results.json --symbols-sha256 "$VSEC_SYMBOLS_SHA256" --m4-data data/m4 --t-short <value from pilot>
   ```
   Expected shape: same `report.html`, but with no simulated banner only if every module really used real data; M4 shows "EXPLORATORY" unless there are exactly 15 sessions per class with 4 workloads each. Read results only from the report, and report negative or "untestable" outcomes as they are. Set `--env` honestly for each host (`E0` or `E1`).

## Recording checklist

- [ ] Screen resolution 1920x1080 (or 1280x720), terminal font size 18 or larger, light or high-contrast theme.
- [ ] Close every other window and app; turn off notifications (Do Not Disturb).
- [ ] Hide secrets: no real keys, tokens, passwords or BitLocker recovery key anywhere on screen; hide the browser bookmarks and email; check the terminal prompt for your username if you do not want it shown.
- [ ] Only synthetic secrets in Part 2 (the planted fake keys). Never real credentials.
- [ ] Run the commands once before recording; do `Remove-Item` clean-up so the output folders do not exist.
- [ ] Say "simulated, not a result" for Part 1; keep the report banner visible when showing numbers.
- [ ] Do not show or say any number from the simulated run as a finding.
- [ ] Save the recording under `.local\` or outside the repo; do not commit video files.
- [ ] Speak slowly; leave 2 seconds after each command finishes.
