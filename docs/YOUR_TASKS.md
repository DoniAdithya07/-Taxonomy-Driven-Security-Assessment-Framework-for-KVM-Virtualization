# Your Tasks (Hands-On, Hardware-Only)

This document lists the exact things only you (the owner, hands, and hardware) can do. Each task explains **why it matters**, **how long** it takes, **what commands** to run, and **what to send back to Claude so it can continue**.

---

## Task A: Compile and sanity-check bench.c on E1 (W1, 15 min)

**Why it matters:** `bench.c` is the heart of M4. It must compile and run on the target E1 machine to collect timing/memory signals. This is your first real test of E1.

**How long:** 10–15 minutes.

**Prerequisites:** E1 is booted, connected to network (apt install still needed), and Task B (E1 setup) is complete.

**Commands on E1:**
```bash
sudo apt update && sudo apt install -y gcc make
cd /path/to/project
gcc -O2 -Wall -o bench vsec/m4_detect/bench.c -lm
./bench idle 100 20 > t.csv
head -5 t.csv && tail -5 t.csv
```

**What to check:**
- `bench` binary is created (about 20 KB).
- `t.csv` has 5+ rows, with columns: `window,workload,elapsed_ms,cpuid_tsc,rdtsc_tsc,...`
- `elapsed_ms` is the real wall time of each window (not window_ms, which only scales probe size; expect 135–310 ms for a 100 ms window).

**What to send back to Claude:**
- First 5 lines of `t.csv` (the header and first 4 data rows).
- Output of `gcc --version`.
- Confirm: "bench.c compiled and ran, elapsed_ms range is X–Y ms (expected 135–310 ms for a 100 ms window)".

---

## Task B: Build E1 and install Ubuntu (W1, 1–2 hours) — DO THIS FIRST

**Why it matters:** E1 is the native machine for M4. It runs bare-metal (one virtualization layer), unlike E0 (two layers in WSL). M4 results stand or fall on E1's quality. **Complete this before Task A.**

**How long:** 1–2 hours (mostly unattended).

**Prerequisites:**
- External SSD, 64 GB or larger, bootable via USB.
- BitLocker recovery key written on paper, kept offline (see `docs/E1_CHECKLIST.md`).
- Internal disk physically disconnected OR you know its name and will avoid it during install.

**Commands on Windows (before reboot):**
```bash
# Identify disks:
Get-Disk | Format-Table Number, Model, SerialNumber
# Write down the external SSD serial number
```

**Steps:**
1. Write BitLocker recovery key on paper (do this first).
2. If you can physically disconnect the internal disk, do so now.
3. Create Ubuntu 24.04 LTS bootable USB (Rufus or Balena Etcher on Windows).
4. Reboot to the USB.
5. In Ubuntu installer:
   - Choose "Ubuntu Server" (not desktop).
   - In "Guided Storage Configuration", if your internal disk is still visible, use "Advanced" and manually select only the external SSD's partitions.
   - Install.
6. Reboot into E1 Ubuntu.
7. On E1, run:
   ```bash
   lsblk -o NAME,MODEL,SERIAL | head -10
   cat /proc/cmdline  # should NOT mention Hyper-V
   ```
8. Freeze packages (see `docs/E1_CHECKLIST.md`): `sudo systemctl disable apt-daily apt-daily-upgrade`, `sudo apt-mark hold linux-image-generic qemu-system-x86`.

**What to check:**
- E1 boots into Ubuntu (no Windows login).
- `/proc/cmdline` does NOT mention "Hyper-V" or "hypervisor=off".
- `lsblk` shows only the external SSD (no internal disk if you disconnected it).

**What to send back to Claude:**
- Confirm: "E1 is booted, internal disk [disconnected / on partition X], packages frozen".
- Paste: `lsblk -o NAME,MODEL,SERIAL` output (first 5 lines).
- Paste: `cat /proc/cmdline`.

---

## Task C: W1 pilot – 10 boots and fill PILOT values (W1, 30 min)

**Why it matters:** The pilot is a tiny experiment (5 native + 5 kvm-masked boots = 10 total; >= 5 per class for M4's pilot minimum) to estimate the session length and the measurement window (T_short). These values are burned into `prereg.md` before W2, so the pilot must be high-quality.

**How long:** 20–30 minutes, single-threaded.

**Prerequisites:**
- E1 booted, packages frozen.
- `bench.c` compiled on E1 (Task A).
- VMs set up on E1: `kvm-plain` and `kvm-masked` (you may need to ask Claude to confirm the XML; they're in `vms/`).

**Commands on E1:**
```bash
cd /path/to/project
# Pilot: 5 native + 5 kvm-masked boots (both needed for M4's >= 5 sessions per class minimum)
# Run one session:
sudo BENCH=/opt/vsec/bench TEMP_C=25 scripts/run_session.sh --allow-unscheduled native p01 100 300 data/m4/pilot
# Time one complete session (4 workloads); typical Windows run was ~4 minutes per session

# Repeat for all 10 sessions (5 native, 5 kvm-masked).
```

**What to check:**
- Each session writes `idle.csv`, `cpu.csv`, `mem.csv`, `mixed.csv`, and `meta.json` to `data/m4/pilot/<id>/`.
- Each CSV has 20+ rows (windows).
- `elapsed_ms` in each CSV is the real wall time of each window (typically 2-3× the nominal window_ms; expect 135–310 ms for a 100 ms window).
- `meta.json` records session metadata (time, temperature, kernel version, etc.).
- No `FAILED` file remains after successful sessions.

**What to send back to Claude:**
- Paste: first 5 lines of one `idle.csv` (header + data).
- Paste: one `meta.json` file (full, ~10 lines).
- Confirm: "pilot completed, 10 boots (5 native + 5 kvm-masked), window elapsed_ms is X–Y ms per window, session time is Z min total".
- Run and paste output of: `python -m vsec pilot --data data/m4/pilot` (this prints T_short for the analysis plan).

**Pilot exit codes:**
- `0`: success, T_short was chosen and printed (proceed to Task D).
- `1`: no T_short was chosen; investigate the `auroc_grid` output for reasons (e.g., "best single signal already at ceiling", "no valid T window").
- `2`: error (missing or malformed data).

---

## Task D: Pre-registration dry-run and commit (W2, 30 min)

**Why it matters:** `prereg.md` is a signed contract. You commit it **before collecting real data** so there's no double-dipping (fitting thresholds to data you're supposed to be testing on).

**How long:** 20–30 minutes.

**Prerequisites:**
- Pilot data from Task C (10 boots in `data/m4/pilot/`).
- PILOT values (window size, session length, T_short) estimated from `python -m vsec pilot --data data/m4/pilot`.

**Commands on E1 or E0 (laptop):**
```bash
cd /path/to/project
git init  # if not already done
# Edit prereg.md and fill in the PILOT section:
nano prereg.md
# Lines to fill:
# **Date committed:** (fill with today's date)
# **Researcher:** (your name/email)
# **Window size (PILOT, in ms):** (from Task C, e.g., 100)
# **T_short (PILOT, seconds):** (output of `python -m vsec pilot --data data/m4/pilot`)
# **bench window_ms:** (the window_ms value, e.g., 100)
# **n_windows:** (the n_windows value, e.g., 300)
# **ISF sha256:** (to be filled after Task G, or leave blank for now)

# Commit:
git add prereg.md
git commit -m "Pre-register M4 analysis (PILOT T_short from pilot data, before W3 collection)"
git tag -a prereg-w2 -m "Pre-registration before W3 data collection"
```

**What to check:**
- `git log` shows the commit.
- `git tag -l` shows the tag.
- No uncommitted changes: `git status` should be clean.

**What to send back to Claude:**
- Paste: output of `git log --oneline -5` (confirm the new commit is there).
- Paste: `git show HEAD:prereg.md | head -30` (confirm PILOT values are filled).
- Confirm: "prereg.md committed and tagged".

---

## Task E: M2 planting and real dumps (target VM, W2–W3, 1–2 hours)

**Why it matters:** M2 tests whether snapshots leak secrets. You plant synthetic secrets in the target VM, dump memory, and the scanner looks for them. The dumps are ground truth.

**How long:** 1–2 hours (highly parallelizable per cell).

**Prerequisites:**
- `target` VM defined on E1 (or E0), with snapshot `clean` already taken.
- Network interface link DOWN: `virsh domif-setlink target <vnetN> down` (must be done after every revert unless the snapshot XML already has `<link state='down'/>`).
- `scripts/plant_guest.py` and `vsec/secrets_gen.py` copied into the guest.
- `virsh dump` command available.

**Per-dump sequence (revert marker is single-use, expires in 15 min):**

```bash
# For each of 12 kinds/states cells (4 kinds: ssh_key, aws, jwt, hex32 × 3 states: live, freed, exited):
for kind in ssh_key aws jwt hex32; do
  for state in live freed exited; do
    # Each cell: collect 5 dumps in the first pass, then scale to 10 per cell
    for n in $(seq 1 10); do
      # 1. Revert the target VM to the baseline snapshot
      virsh snapshot-revert target clean
      
      # 2. CRITICAL: Set network link down (needed after every revert unless snapshot XML already has it)
      virsh domif-setlink target <vnetN> down
      
      # 3. Mark the revert for the gate
      .local/venv/bin/python scripts/preflight_target.py --mark-reverted
      
      # 4. Inside the guest (via console or SSH before network is down):
      #    Copy plant_guest.py and secrets_gen.py into guest, then run:
      python3 plant_guest.py <kind> <state> m.json
      #    This plants the secret and writes m.json
      
      # 5. Host gate: confirm reverted, offline, target is clean (WITHIN 15 MINUTES OF REVERT)
      .local/venv/bin/python scripts/preflight_target.py
      
      # 6. Dump memory (WITHIN 15 MINUTES OF REVERT, before marker expires)
      virsh dump target data/m2/${kind}_${state}_${n}.mem --memory-only --format raw
      
      # 7. Copy manifest out and secure the dump
      cp m.json data/m2/${kind}_${state}_${n}.json
      chmod 444 data/m2/${kind}_${state}_${n}.mem data/m2/${kind}_${state}_${n}.json
      
      # After first pass at n=5, increase to n=10 per cell if space and time allow
    done
  done
done
```

**What to check:**
- `data/m2/` contains 120 dumps (12 cells: 4 kinds × 3 states; 10 dumps per cell = 120; first pass at 5 per cell = 60).
- Each dump is 1–4 GB (RAM size of target).
- Each dump has a `.json` metadata file with the planted secret hash.
- No `FAILED` marker remains in the session folder after the 15-minute window.
- All dumps are read-only (`chmod 444`).

**Important:** The manifest is guest-written, so it cannot be trusted for ground truth (the guest could lie). The `make_manifest` function in `vsec/m2_snapshot.py` verifies planted secrets against the dumps on the host side.

**What to send back to Claude:**
- Confirm: "M2 planting complete, 120 dumps, XXX GB total".
- Paste: `ls -lh data/m2/ | head -20` (to confirm file sizes and counts).
- Confirm: "15-minute gates passed for all dumps; all reverts were clean".

---

## Task F: M4 collection batch 1 (W3, 1–2 hours)

**Why it matters:** M4 is the centrepiece. You collect 15 sessions per class (45 boots total, 3 batches). Batch 1 is the first 15 sessions, spread over days.

**How long:** 1–2 hours per session (parallelizable).

**Prerequisites:**
- E1 preflight checklist completed (`docs/E1_CHECKLIST.md`).
- Schedule: `data/m4/schedule.json` (lists which class to run in which order, created by `python3 scripts/plan_sessions.py`).
- All three classes bootable: native, kvm-plain, kvm-masked (all on the same machine, E1).
- T_short recorded in `prereg.md` from Task D.

**Commands on E1:**
```bash
# Create the session schedule (only once):
python3 scripts/plan_sessions.py

# List sessions and their classes:
python3 -c "import json;[print(e['session'],e['cls']) for e in json.load(open('data/m4/schedule.json'))][:15]"

# Before compiling bench, install it as root:
gcc -O2 -Wall -o bench vsec/m4_detect/bench.c -lm
sudo install -D -o root -g root -m 755 bench /opt/vsec/bench

# Run one session (e.g., session s000, its class from schedule.json, window 100 ms, 300 windows):
sudo BENCH=/opt/vsec/bench TEMP_C=25 scripts/run_session.sh native s000 100 300 data/m4
# Time one complete session (4 workloads); typical Windows run was ~4 minutes per session

# Repeat for all sessions in batch 1 (e.g., first 5 sessions per schedule, randomized).
# Before each session: rebuild the overlay for the VM class.
# No preflight_target.py needed (it's for M2/M3 dumps, not M4 sessions).
# After all batches are done: sudo chown -R $USER data/m4 (root-owned mode-700 folders block your own pilot/run)
```

**What to check:**
- Sessions are stored in `data/m4/<id>/` with 5th argument path.
- Each session produces all 4 CSVs (idle.csv, cpu.csv, mem.csv, mixed.csv) and meta.json.
- No `FAILED` file remains in any session folder after successful completion.
- `meta.json` records the session ID, class, temperature, kernel version, clocksource, etc.

**If a session fails:**
1. Look at `data/m4/<id>/FAILED` to see why.
2. Check `data/m4/<id>/qc.json` for quality control details.
3. Fix the cause (e.g., overlay not rebuilt, bench path wrong, wrong governor settings).
4. Re-run the SAME session id with: `sudo BENCH=/opt/vsec/bench TEMP_C=25 scripts/run_session.sh --retry native <id> 100 300 data/m4`
5. The failed folder is moved aside to `data/m4/<id>.failed-<UTC>` (never deleted).
6. A session with `meta.json` is final and should never be retried (its data is complete).

**What to send back to Claude:**
- Paste: `ls -1 data/m4/s000/` (confirm CSVs and meta.json exist).
- Paste: first 5 lines of `data/m4/s000/idle.csv` (header + data).
- Paste: `cat data/m4/s000/meta.json` (one example).
- Confirm: "Batch 1 complete, X sessions, Y boots, all passed preflight".

---

## Task G: M3 symbol build (host-side, W2–W3, 10 min)

**Why it matters:** M3 runs Volatility to find hidden processes. Volatility needs a symbol file for the guest kernel. This is built once, on the host, with pinned sha256.

**How long:** 5–10 minutes.

**Prerequisites:**
- Kernel version identified on the **guest** (e.g., `6.8.0-48-generic` on Ubuntu 24.04).
- Debug kernel and dwarf2json installed (see below).
- dwarf2json is a Go binary from https://github.com/volatilityfoundation/dwarf2json/releases

**Commands on the host (E0 or E1):**
```bash
# Check the guest kernel version (from guest or from boot logs):
# uname -r inside guest, or look at the kernel version label in the VM image

# Download debug kernel symbols from ddebs.ubuntu.com (the TARGET guest kernel):
# Follow https://wiki.ubuntu.com/Debug%20Symbol%20Packages
# For Ubuntu 24.04 with kernel 6.8.0-48-generic, download the linux-image-<version>-dbgsym package
# The debug vmlinux lands in /usr/lib/debug/boot/vmlinux-<version>

# Download dwarf2json (a Go binary) from volatilityfoundation/dwarf2json releases
# and put it in your PATH or pass the full path to scripts/build_symbols.sh

# Compute the SHA256 of the vmlinux and dwarf2json:
sha256sum /usr/lib/debug/boot/vmlinux-6.8.0-48-generic
sha256sum /usr/local/bin/dwarf2json

# Build the symbol file (create output dir first):
mkdir -p .local/symbols
scripts/build_symbols.sh /usr/lib/debug/boot/vmlinux-6.8.0-48-generic \
  abc123def456... \
  /usr/local/bin/dwarf2json \
  ghi789jkl012... \
  .local/symbols
# The script outputs: ubuntu-<version>.json and ubuntu-<version>.sha256

# Verify:
ls -lh .local/symbols/ubuntu-*.json
cat .local/symbols/ubuntu-*.sha256
```

**What to check:**
- `.local/symbols/ubuntu-<version>.json` exists and is ~5–50 MB.
- The script wrote a `.sha256` file with the hash.
- JSON is valid: `python -m json.tool < .local/symbols/ubuntu-*.json | head -20`.

**What to send back to Claude:**
- Paste: output of `scripts/build_symbols.sh` (including sha256 and the command line).
- Paste: `cat .local/symbols/ubuntu-*.sha256`.
- Paste: the guest kernel version (uname -r output from the guest).
- Confirm: "M3 symbols built, sha256 recorded in .local/symbols/, ready for Volatility".

---

## Task H: M3 public image test (W5, 30 min–1 hour)

**Why it matters:** M3 tests offline memory forensics on public ground-truth memory dumps. You download a public dump (with documented hidden processes) and run Volatility to confirm M3 finds them.

**How long:** 30 min–1 hour per image.

**Prerequisites:**
- Volatility 3 installed: `pip install volatility3` (also available via `.local/venv`).
- Public memory image downloaded (document in `docs/DATA_SOURCES.md`).
- Volatility installed OUTSIDE $HOME (the sandbox hides $HOME). For example: `/opt/vsec-venv/`. Set `VOL=/opt/vsec-venv/bin/vol`.
- Symbol file built with `scripts/build_symbols.sh` (Task G).
- **Ubuntu 24.04 AppArmor fix (if on E1):** The default kernel restricts the Volatility sandbox. Make the fix persistent:
  ```bash
  echo "kernel.apparmor_restrict_unprivileged_userns=0" | sudo tee /etc/sysctl.d/99-vsec-sandbox.conf
  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
  ```
  If the wrapper still refuses, use weak mode: `VOL_ALLOW_WEAK_SANDBOX=1 python -m vsec m3 ...` or `python -m vsec m3 ... --allow-unsandboxed`. The wrapper logs which mode it is using.

**Commands on E0/E1:**
```bash
# Download a public Linux forensic image (e.g., from Volatility Foundation):
# wget <URL> -O .local/tmp/public_image.mem
# chmod 444 .local/tmp/public_image.mem  # make it read-only

# Set the Volatility path (install outside $HOME if on E1):
export VOL=/opt/vsec-venv/bin/vol

# Run M3 on it (with verified symbols):
python -m vsec m3 .local/tmp/public_image.mem \
  --symbols .local/symbols/ubuntu-<version>.json \
  --symbols-sha256 <hash-from-ubuntu-version.sha256>

# Check output:
# The command prints found processes and modules in JSON format.
# Compare against the documented ground truth (e.g., "3 hidden processes documented, M3 found 2").
```

**What to check:**
- Volatility runs without errors.
- Processes and modules are listed in the JSON output.
- The symbols hash is verified.
- Compare detected against ground truth documentation.
- Confirm sandbox mode (logged to stderr): "sandboxed=true" (full) or "sandboxed=false" (weak/unsandboxed).

**What to send back to Claude:**
- Paste: first 30 lines of output from `python -m vsec m3 ...` (showing processes/modules found).
- Confirm: "Public image X tested, M3 found N hidden processes (documented: M, match: Y%)".
- Confirm: "Sandbox available: yes/no (weak mode: yes/no)".
- Update `docs/DATA_SOURCES.md` with the image details and results.

### M3 results flow (real dumps and M4 integration)

After collecting real dumps from `target` (Task E) or using public images (Task H), integrate the results into the M4 run:

```bash
# For each memory dump, run M3 and append results:
VSEC_SYMBOLS_SHA256=$(cat .local/symbols/ubuntu-<version>.sha256)
export VSEC_SYMBOLS_SHA256

for dump in data/m2/*.mem; do
  kind_state=$(basename "$dump" .mem)  # e.g., "ssh_key_live_5"
  python -m vsec m3 "$dump" \
    --symbols .local/symbols/ubuntu-<version>.json \
    --row-name "$kind_state" \
    --truth-hidden PID1,PID2,PID3 \
    --append data/m3/results.json
done

# Then run the full M4 pipeline with M3 results:
python -m vsec run \
  --m3-results data/m3/results.json \
  --symbols-sha256 "$VSEC_SYMBOLS_SHA256" \
  --m4-data data/m4 \
  --t-short <value-from-pilot>
```

**M3 results JSON schema** (one row per dump):
- `name`: identifier for this result (e.g., "ssh_key_live_5")
- `detected`: list of process/module PIDs that were found hidden
- `truth_hidden`: list of expected PIDs (from planting or ground truth)
- `symbols_sha_verified`: true if hash matches VSEC_SYMBOLS_SHA256

**Data layout:**
- `data/m3/results.json`: one JSON row per image (not per-image JSON files). Each row appended by the m3 command.
- The row schema must match what the run pipeline expects (verified by a contract test).

---

## Task I: Lynis and OpenSCAP live runs on weak/hardened (W5–W6, 1 hour)

**Why it matters:** M1 is evaluated against Lynis and OpenSCAP, independent host auditors. This gives external evidence that M1 is correct.

**How long:** 30 min–1 hour.

**Prerequisites:**
- `weak` and `hardened` VMs running on E0.
- Lynis and OpenSCAP installed: `sudo apt install -y lynis openscap-utils`.

**Commands on E0 (laptop), inside each VM (or from host via SSH):**
```bash
# On weak VM:
sudo lynis audit system --quiet
# Generates: /var/log/lynis-report.dat

# On hardened VM (same):
sudo lynis audit system --quiet

# Copy results:
scp <weak_vm_user>@<weak_vm_ip>:/var/log/lynis-report.dat cases/weak_lynis.txt
scp <hardened_vm_user>@<hardened_vm_ip>:/var/log/lynis-report.dat cases/hardened_lynis.txt

# OpenSCAP (if available):
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_standard /usr/share/openscap/scap-security-guide.xml
# (command may vary by version; check OpenSCAP docs)
```

**What to check:**
- Lynis report generated (readable text or binary .dat file).
- OpenSCAP produces output with rule results (PASS/FAIL per control).

**What to send back to Claude:**
- Paste: first 30 lines of weak VM's Lynis report.
- Paste: count of PASS vs FAIL rules from OpenSCAP on weak and hardened VMs.
- Confirm: "Lynis and OpenSCAP runs complete on weak/hardened, results saved to cases/".

---

## Task J: Finish decisions – licence and final checks (W8, 30 min)

**Why it matters:** Before you submit the paper, you must decide on a licence for your code and verify all data sources.

**How long:** 20–30 minutes.

**Prerequisites:**
- Paper nearly complete.
- All CVE entries verified against NVD (see `docs/DATA_SOURCES.md`).

**Decisions:**
1. **Code licence:** Choose one:
   - MIT (permissive, widely compatible)
   - GPL-3.0 (copyleft, requires downstream code to also be GPL)
   - Academic/research (cite only, no redistribution)
   - Proprietary (no external use)
   
   Document your choice in a new `LICENSE` file in the repo root.

2. **Final data checks:**
   - Check CVE verification status in `vsec/cves.yaml`.
   - Confirm all unverified ones are noted as "exploratory" or marked "not citable" in the paper.

**Commands:**
```bash
# Check CVE status (look for "verified: true" with the space):
grep -c "cve: .*verified: true" vsec/cves.yaml
grep -c "cve: .*verified: false" vsec/cves.yaml

# Verify repo cleanup (before final push):
git status  # should be clean
find . -name "*.key" -o -name "*.pem" -o -name ".env"  # should find nothing (no secrets)
du -sh .local/  # check size of scratch; nothing large should be committed
```

**What to send back to Claude:**
- Confirm: "Licence chosen: [MIT / GPL-3.0 / other]".
- Paste: CVE verification counts (N with "verified: true", M with "verified: false").
- Confirm: "No keys, credentials, or secrets in the repo".
- Confirm: "Paper and slides ready for submission".

---

## Summary and Handoff

Once you complete all tasks A–J:

1. **Repository is clean:** no uncommitted changes, no secrets, no big binaries.
2. **Data is documented:** all public sources cited in `docs/DATA_SOURCES.md`, all downloads in `.local/` (gitignored).
3. **Decisions recorded:** licence chosen, E1 availability documented, fallbacks chosen if needed.
4. **Paper is ready:** all modules (M1–M4) have results, figures, and tables; limitations section is honest about what was tested and what was not.

**Send final summary to Claude:** Paste the output of:
```bash
git log --oneline -10
du -sh data/m4 data/m2 data/m3 .local/
wc -l FINAL_PROJECT_PLAN.md README.md vsec/*.py
```

Claude will then generate the final report, compile the paper into PDF/slides, and prepare for submission.

---

## Questions?

- **E1 not available?** Proceed with the E0 fallback (M4 on 2 VL vs 1 VL). Document in `FINAL_PROJECT_PLAN.md` § 1.
- **Public images not found?** Use the optional rootkit test (M3 on a rootkit you install). Document the choice in `docs/DATA_SOURCES.md`.
- **Time running short?** Prioritize the "Never cut" items in `FINAL_PROJECT_PLAN.md` § 7. Skip SHAP, performance counters, extra kernels, redaction.
- **Preflight check fails?** The `scripts/preflight_target.py` will tell you why (other VM running, target not reverted, etc.). Fix and retry.

See `FINAL_PROJECT_PLAN.md` for the full project plan and `docs/E1_CHECKLIST.md` for the pre-flight checklist.
