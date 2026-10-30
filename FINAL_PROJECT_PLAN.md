# Final Project Plan: Taxonomy-Driven Security Assessment Framework for KVM Virtualization

## 0. Summary

**Research question:** Can the threats and controls identified in the 2020 virtualization-security survey be turned into experimentally testable controls on a modern KVM stack? Which of them hold, which fail, and which cannot be tested on this hardware?

**Centrepiece question (M4):** Against a hypervisor that hides its static indicators, does combining several *behaviour* signals detect it with less measurement time, or more reliably, than the best single behaviour signal?

**Contribution:** A framework that maps the survey's taxonomy onto 4 modules and evaluates each module against ground truth. Its centrepiece is a pre-specified multi-signal experiment (analysis plan in `prereg.md`, a draft that is not yet committed or tagged) against an indicator-masked hypervisor.

**Claims:**

- **PASS** means "this control passed its defined test". It does **not** mean "the system is secure".
- **M4** detects *hypervisor-related anomalies* from a **non-adaptive** hypervisor on **one machine**. It does **not** prove that a VMBR exists, and it does not cover a hypervisor that fakes time.
- **M3** is *offline memory forensics* on dumps. It is not live VMI, and the claim is limited to **unlinked (hidden) processes and modules**.
- **M1 synthetic fixtures** are self-consistency tests: they were written by the same author who built the checker, not an independent evaluator. Independent evidence comes only from live Lynis/OpenSCAP comparison and real-world configurations.
- Anything this hardware cannot test is marked **N/A**, never PASS.
- Negative results are reported.

---

## 1. Environments

The laptop's Windows already runs on Hyper-V, so the laptop has no "native" (bare-metal) setup. That is why there are two environments.

| Env | What | Used by |
|---|---|---|
| **E0** | Laptop: WSL2 Ubuntu 24.04 + KVM/libvirt (one virtualization layer under Hyper-V) | M1, M2, M3 |
| **E1** | A PC booted from Ubuntu on an **external SSD** (persistent install, Hyper-V not loaded). This is the true native machine. | M4, plus M1 live checks (sVirt, IOMMU, seccomp) |

**E1 safety (before booting the external SSD):**

- Write down the **BitLocker recovery key** on paper, kept offline. Changing the boot order can trigger BitLocker recovery.
- **Disconnect the internal disk** during the Ubuntu install, or explicitly point the bootloader at the external SSD's EFI partition. The Ubuntu installer otherwise often writes GRUB to the internal disk.
- Freeze packages: disable `unattended-upgrades` and `apt-mark hold` the kernel and QEMU for the whole collection period.

**VMs** (images kept in `.local/`, never in git):

- `weak`, `hardened`: M1 and the demo
- `target`: M2 and M3. No network, reverted to a snapshot before every experiment.
- `kvm-plain`, `kvm-masked`: M4 on E1

**`kvm-masked`** hides the static virtualization indicators using standard libvirt options. It is a safe stand-in for an indicator-masked, *non-adaptive* hypervisor:

```xml
<features><kvm><hidden state='on'/></kvm></features>
<cpu mode='host-passthrough'><feature policy='disable' name='hypervisor'/></cpu>
<sysinfo type='smbios'><system><entry name='manufacturer'>Dell Inc.</entry></system></sysinfo>
<os><smbios mode='sysinfo'/></os>
<!-- plus non-virtio disk and NIC models so device names do not reveal the VM -->
```

**If E1 is impossible:** M4 compares 1 virtualization layer against 2 (WSL vs KVM-in-WSL), plain and masked. The claim becomes "detecting an extra virtualization layer", and this is listed as a limitation.

---

## 2. Common Framework (build in W1, before any module)

Every module emits the same finding format:

```json
{"id":"C07","module":"M1","taxonomy":"Guest→Host","control":"qemu_seccomp",
 "status":"PASS|FAIL|NA","severity":1,"evidence":"...","fix":"...","env":"E0","vm":"weak"}
```

- Severity runs from 1 to 4.
- **M4 status:** PASS when the detected environment equals the declared environment, FAIL otherwise.
- **`taxonomy.yaml`** is the backbone. Each control has: id, threat class, module, test, expected result, **test type** (`live` / `config` / `version`), and source (survey section, CIS benchmark, libvirt docs).
- **`report.py`** produces the matrix and the JSON/HTML report from **dummy findings in W1**. Each module plugs in as soon as it is ready.

### Threat classes and how each is tested

Each class is labelled **Tested** (a real experiment), **Config-proxy** (only its configuration or version is checked) or **N/A**.

| Threat class | Test | Label |
|---|---|---|
| Guest→Host | M1 config + live checks (seccomp, sVirt label, devices, permissions) | Tested |
| Host→VMM | M1: libvirt and QEMU hardening, socket and image permissions | Config-proxy |
| Guest→Guest | Host-side check of the libvirt network definition (isolated, no forward/ip) plus network-mode and shared-memory config checks; a guest reachability scan is only corroboration and can add a FAIL, never a PASS | Config-proxy |
| VMM vulnerabilities | QEMU and kernel versions checked against a CVE list | Config-proxy |
| Side channels | `/sys/devices/system/cpu/vulnerabilities/*`, SMT state, KSM | Config-proxy |
| DMA/IOMMU | IOMMU groups on E1 (E0 = N/A) | Tested on E1 |
| Snapshot privacy | M2 | Tested |
| VMI / hidden processes | M3 | Tested |
| Hypervisor/VMBR presence | M4 | Tested |

### Result matrix layout

- **Per threat class:** label, number of controls, number tested, number N/A.
- **Per VM** (`weak`, `hardened`, real-world configs): PASS/FAIL per class.

PASS/FAIL counts are never summed across different VMs.

---

## 3. Modules

### M1: Configuration Auditor

- **Controls (25–30):**
  - IOMMU
  - QEMU seccomp sandbox
  - sVirt (AppArmor or SELinux)
  - KSM off
  - nested virtualization off
  - unused devices removed
  - VNC/SPICE authentication
  - network mode
  - permissions on disk images and libvirt sockets
  - plus the Guest→Guest, CVE and side-channel checks from §2
- **Two kinds of check:**
  - **Config:** reads files (`qemu.conf`, VM XML, kernel command line).
  - **Live:** proves the control is actually active:
    - the `Seccomp:` field in `/proc/<qemu-pid>/status`
    - the security label of the QEMU process
    - the real file permissions
    - IOMMU groups

    Live checks run on E0 and **on E1**, where sVirt and IOMMU can really be tested.
- **Output:** PASS, FAIL or N/A for each control, with evidence and a fix command.
- **Attack paths:** reported as **illustrative only**. Each chain of FAILs cites a real CVE or documented attack, and no accuracy is claimed for them.
- **Ground truth (synthetic):**
  - Self-written 50 test cases. A case may contain several faults.
  - **At least 3 seeded faults per control**, with known answer key.
  - Each test case is a **folder**: the VM XML plus captured host files (`/sys`, `/proc`, `/etc/libvirt`, `qemu.conf`, the kernel command line).
  - N/A scoring is fixed in advance: an N/A on a seeded fault counts as a **miss**.
- **Ground truth (real-world):** about **10 real configs**: the default Ubuntu libvirt install, plus public Proxmox/OpenStack-generated XML. These are labelled by hand and reported **separately** from the synthetic set.
- **Metrics:**
  - The unit of analysis is the **(test case, control) pair**.
  - Precision, recall, F1 and false-positive rate, overall and **per control**, with **Wilson 95% CIs**.
  - Runtime.
- **Tool comparison:** run M1, Lynis and OpenSCAP on the **live** `weak` and `hardened` hosts. Use a small hand-made ground truth for those two hosts, since Lynis and OpenSCAP cannot read fixture folders. This independent comparison provides the main evidence that M1 is correct.
- **Demo:** audit the weak VM, apply the fixes, re-audit, and show the change in PASS/FAIL per class.

### M2: Snapshot Privacy (W1–W4)

- **Planted secrets (synthetic only).** There are 4 types:
  - a fake SSH private key
  - an AWS-style key ID and secret
  - a JWT
  - 32-byte random hex keys

  Each type is placed in 3 memory states:
  - live in a running process
  - freed but not overwritten
  - left behind by a process that has exited

  That gives **12 cells**, with **at least 10 dumps per cell**.
- **Held-out variants:** the scanner's rules are written without seeing these. They are reported as their own column:
  - secrets split across page boundaries
  - UTF-16 encoded
  - base64 encoded
- **Real programs:** `ssh-agent` holding a throwaway key, and `openssl s_server` with a throwaway certificate. Here keys sit in memory in binary form. Reported as their own column.
- **Ground truth:** a secret counts as "present" only when an exact search for the planted bytes confirms it is in that dump.
- **Negative controls:**
  - dumps with no secrets
  - dumps padded with random high-entropy data
- **Scanner:** pattern matching on secret formats, plus an entropy filter.
- **Scanning input vs protection input:**
  - Scanning uses `virsh dump --memory-only` output, which is for analysis only and cannot be restored.
  - The protection test uses **`virsh save` images**: redact or encrypt the secrets, re-scan, `virsh restore`, then check the VM resumes and its service still runs.
- **Metrics:**
  - recall per cell, held-out variant and real program
  - **false positives per GB scanned**
  - scan time
  - size overhead
  - restore success rate

### M3: Offline Memory Forensics (W5–W7)

- **Method:** run Volatility 3 on `virsh dump` output. Compare:
  - `pslist` against `psscan` (process list vs raw memory scan)
  - `lsmod` against a scan of memory for kernel modules
- **Kernel:** pin one guest kernel version and build its Volatility symbol file on the host.
- **Ground truth, main:** **public Linux forensic memory images whose hidden processes are already documented** (from the Volatility project and memory-forensics course datasets).
  - **Gate:** confirm suitable *Linux* images exist **by the end of W2**. If not, the optional rootkit test becomes the main test.
- **Ground truth, false positives:** clean dumps from `target`, including dumps taken **while processes are rapidly starting and exiting**. Processes exiting at the moment of the dump are a real source of false positives.
- **Optional second test:** a public research rootkit, only inside `target` in isolation, with no network and a snapshot revert after every run. Repeated on 2 more kernel versions to record where detection breaks.
- **Metrics:**
  - **exact counts** (e.g. 7/8 detected) with **exact (Clopper-Pearson) 95% CIs**, not bare rates
  - scan time
  - a failure-case table
- **Stated limits:**
  - Checks happen only when a dump is taken, so an attacker can act between dumps.
  - Only unlinked processes and modules are covered.

### M4: Multi-Signal Hypervisor Detection (W1–W8)

**Threat model:** a **non-adaptive** hypervisor that hides its static indicators but does not fake time (no TSC offsetting, no faking of VM-exit latency). The machine is **one CPU model** (E1). A hypervisor that does fake time is out of scope and listed as future work.

**Classes:** `native`, `kvm-plain`, `kvm-masked` (all on E1).

**Signal groups.** Any signal the hardware does not expose is marked unavailable.

| Group | Measured | In H1? |
|---|---|---|
| Timing | CPUID latency, RDTSC, syscall and page-fault cost | Yes |
| Memory | Sequential and random latency, TLB-miss proxy (page-stride walk) | Yes |
| Performance counters | Linux `perf`, where exposed | Yes |
| Scheduler noise | Jitter on a fixed-sleep loop | Yes |
| System indicators | CPUID hypervisor bit, DMI strings, device models | **No.** Reported separately in the indicator-leak table |

**Controlled conditions:** native and VM runs must differ **only in virtualization**.

- **Same image:** the same Ubuntu disk image and kernel, booted on bare metal and as the VM.
- **CPU:** fixed frequency (`performance` governor), turbo off, vCPUs pinned to physical cores.
- **Environment:** the same background services, mains power, packages frozen.
- **Clock source:**
  - Record `current_clocksource` and the kernel command line in every run.
  - Force the **same clock source in all classes** (e.g. `clocksource=tsc`).
  - If a class cannot use it, report this as a **confound**. Masking removes kvm-clock, so differences between plain and masked might otherwise come from guest kernel timekeeping, not from virtualization.
- **Logged per session:** date, time of day, temperature, CPU/BIOS/kernel/QEMU versions, random seed.

**Data design:**

- **Unit of analysis = one boot session.** Each boot runs all 4 workloads (idle, CPU, memory, mixed) in **random order**.
- **15 boot sessions per class**, i.e. **45 boots** in total.
- **Session order is randomised across classes and spread over days.** Classes are interleaved, never collected one class per week.
- **Balance check:** after collection, confirm that temperature and time of day are balanced across classes.
- **vCPU variation (1/2/4)** is dropped from the core design. It is an extension only, if time allows.
- **Per-session budget:** the minutes per session and the window size are set from the W1 pilot, and the full collection is budgeted before W3.

**Analysis (pre-specified):** written to `prereg.md` (a draft: it becomes a pre-registration only once it is committed and tagged, which must happen **before any real data collection**).

- **Session-level decisions:** each session's measurement window is pooled into **one decision per session**.
- **Cross-validation:** grouped k-fold by session. All tuning, and the choice of the "best single signal", happen **inside nested CV**, never on test folds.
- **Like-for-like model comparison:** single vs combined uses the **same model family**: logistic regression vs logistic regression, random forest vs random forest.
- **Uncertainty:** **paired session-level bootstrap** (same resampled sessions for both models, stratified by class), one-sided for H1. CIs are conditional on the repeated-CV scores (selection variability is not resampled).
- **Measurement seconds are real** (from `elapsed_ms`). The short window `T_short` is chosen on pilot data only: the shortest T where the best single signal's AUROC is below 0.90. If the best single signal has AUROC >= 0.99 at every T, H1 is reported as **untestable**, not failed. A behaviour-only run (no CPUID probe) is reported next to H1.
- **Primary endpoint (one):** see H1 below. H2, H3 and the two secondary combined-vs-single tests form the **Holm family**; `supported` = raw criterion AND adjusted p < 0.05.

**Hypotheses (falsifiable; amended 2026-10-03, before any data collection, see `prereg.md` Amendments):**

| | Hypothesis | Test | Supported if |
|---|---|---|---|
| **H1 (primary)** | Combined behaviour signals beat the best single behaviour signal on native vs kvm-masked | Session-level **AUROC at `T_short`**; also the smallest T with session AUROC >= 0.95 | Combined AUROC higher and one-sided paired session bootstrap p < 0.05. **A tie means "not supported"; a ceiling means "untestable".** |
| H2 | Combining lowers false alarms on native (estimation, low power) | False-positive rate at **TPR >= 0.90** (15 positives: 0.95 would mean 15/15) | CI of (single - combined) excludes 0 AND Holm-adjusted p < 0.05 |
| H3 | Robust to unseen workloads | One decision per session: in-distribution vs leave-one-workload-out F1 at 0.5 | Upper 95% bound of the F1 drop < **0.05** AND Holm-adjusted p < 0.05 (only reachable near the ceiling) |
| H4 | Practical cost | Cost of one session decision at T95 (sum over workloads of 1.0 s warm-up + 0.5 s load start + measured seconds, about 4 x (T + 1.5) s); overhead = 100 x seconds / 300 (one run per 300 s) | < **10 s** AND < **5%** overhead (the 10 s limit binds: 3.3%); both numbers reported with a bootstrap CI for T95 |

**Power:** with 15 vs 15 sessions the AUROC standard error is about 0.08 and the minimum detectable AUROC difference is roughly 0.15 to 0.2. A null result is not evidence of no difference.

**Why H1 is measured this way:** CPUID always causes a VM exit, so with long measurement windows timing alone likely reaches AUROC ≈ 1.0. A combination cannot beat that, which would make H1 untestable. Short windows, the ceiling rule and the behaviour-only run keep H1 honest. If timing alone still wins, report it: that is a valid answer to H1.

**Comparisons reported:**

| Comparison | Role |
|---|---|
| native vs kvm-plain | Sanity check (expected to be easy) |
| **native vs kvm-masked** | **Primary (H1)** |
| kvm-plain vs kvm-masked | Secondary |

Also reported: the **indicator-leak table** (which system indicators masking did and did not hide) and the **F1 vs measurement-time curve**.

---

## 4. Solo Weekly Plan (8 weeks, real-data risk first)

| Week | Focus | Goals | Exit gate |
|---|---|---|---|
| **W1** | Foundation + E1 build + M4 pilot | Find format & dummy `report.py`, repo, test strategy. Build E1 safely (BitLocker key on paper, internal disk disconnected, packages frozen). E0 libvirt + `weak`/`hardened` VMs. `taxonomy.yaml` (controls, test type, sources). M1 fixture folders (≥3 faults per control). **M4 pilot: 5 native + 5 kvm-masked boots (10 total), fill PILOT values in `prereg.md`**, run `python -m vsec pilot --data data/m4/pilot` to check T_short. Compile `bench.c` on the target PC (`gcc -O2 -Wall -o bench vsec/m4_detect/bench.c -lm`). | E1 boots and is frozen; pilot gives window size and session length; dummy report renders |
| **W2** | Pre-registration + M1/M2 planting | Commit `prereg.md` and tag it **before collecting real data**. Feature extraction code. `bench.c` and feature tests on E0. M1: config + live checks; confirm Linux forensic images exist (gate). **M2: planting (12 cells + held-out variants + real programs).** Set up `kvm-plain` and `kvm-masked`. Start paper (literature review). | `prereg.md` committed and tagged; forensic image gate answered; M2 planting complete |
| **W3** | M4 batch 1 + M1 live checks | **M4: collection batch 1 (about 15 sessions, 5 per class, randomised order; overlay rebuilt before each session).** M1: fix list, attack paths, JSON output. M3: plan clean-dump collection under process churn. M2: scanner + negative controls. | Batch 1 (~15 sessions, 5 per class) collected; M1 fixtures evaluated (Wilson CIs) |
| **W4** | M4 batch 2 + M1 real-world + M2 results | **M4: collection batch 2** (randomised). M1: **hidden-key scoring, M1 real-world configs, Lynis/OpenSCAP live on weak/hardened.** **M2: redaction, `virsh save`/restore, final scoring.** | M1 and M2 results with CIs exist |
| **W5** | M4 batch 3 + M3 setup | **M4: collection batch 3, performance counters, overhead (H4).** M3: build symbols (pinned sha256, host-side), test on public Linux images. M1 demo: before/after audit. Guest→Guest, CVE, side-channel. | 45 boots total (15 per class); M3 on public images complete |
| **W6** | M4 analysis + M3 clean dumps | **M4: session pipeline, nested CV, bootstrap, balance check (temperature, time of day), H1–H4 results.** M1: live checks on E1 (sVirt, IOMMU). M3: clean dumps under churn, optional rootkit test. | M4 results with thresholds; M3 exact CIs with failure table |
| **W7** | Integration + M1 live E1 | End-to-end `python -m vsec run` test. Final matrix (per class + per VM). M1 live checks on E1 (repeat). Re-run any failed M4 sessions. | Full report renders; all modules plugged in |
| **W8** | Deliver | Paper (10 chapters), slides, demo video, final folder cleanup. | Paper, slides, video, report delivered |

### Phases

These five phases group the work, each with an exit gate that must hold before the next phase starts.

| Phase | Weeks | Goal | Main work | Exit gate |
|---|---|---|---|---|
| **1. Foundation** | W1 | Everything needed to start measuring and auditing | Finding format and dummy `report.py`; repo and test strategy; E0 libvirt + VMs; E1 built safely (BitLocker key on paper, frozen packages, fixed frequency/clock); M4 pilot (5 native + 5 kvm-masked boots = 10 total); `taxonomy.yaml`; M1 fixture folders + key; `bench.c` compile on target | E1 boots and is frozen; pilot fills PILOT; dummy report renders |
| **2. Build and Pre-register** | W2 | Tools ready and the analysis locked before collecting real data | `bench.c` feature extraction; `kvm-plain` and `kvm-masked`; indicator-leak table; M1 config + live checks; M2 planting; **`prereg.md` committed and tagged**; **Linux forensic image gate** | `prereg.md` committed and tagged; forensic image gate answered |
| **3. Data Collection and Module Evaluation** | W3–W5 | Collect all M4 data (overlay rebuilt per session); evaluate M1 and M2; start M3 | M4 collection batches 1–3 (randomised, interleaved, 15 sessions per class = 45 boots); overlay rebuild before each session; session-level pipeline, nested CV, baselines; M1 evaluation + Lynis/OpenSCAP live; M2 scanner, redaction and results (preflight_target.py gates per M2 dump); M3 on public images; Guest→Guest, CVE and side-channel checks | 45 boots collected (15 per class); M1 and M2 results with CIs |
| **4. Analysis and Integration** | W6–W7 | Final results and one combined report | M4 H1–H4 with Holm correction, F1-vs-time curve; balance check; M1 live checks on E1; M3 clean dumps under churn, optional rootkit test, exact CIs; re-run failed sessions; end-to-end run; final matrix | `python -m vsec run` produces the full report; all four modules plugged in; result matrix complete |
| **5. Delivery** | W8 | Hand-over | Paper (10 chapters), slides, demo video; final folder cleanup | Paper, slides, video and report delivered |

---

## 5. Deliverables

1. **Taxonomy result matrix:**
   - per threat class: Tested / Config-proxy / N/A, and how many controls were tested
   - per VM: PASS/FAIL

   This answers: "How many of the paper's threat classes can be tested on our hardware?"
2. **Evaluation table for each module:** ground truth, metric, result with CIs.
3. **M4 tables:**
   - H1–H4 results with pre-specified thresholds
   - single vs combined (same model family)
   - the indicator-leak table
   - the F1-vs-measurement-time curve
4. **`prereg.md`:** committed before data collection.
5. **One command:** `python -m vsec run` produces the full JSON/HTML report.
6. **Paper.** Chapters:
   1. Introduction
   2. Literature review
   3. Research gap
   4. Framework
   5. Experimental setup
   6. Implementation
   7. Results
   8. Discussion
   9. Limitations
   10. Conclusion

   Plus slides and a demo video.

---

## 6. Limitations (stated in the paper)

- **One machine:** M4 results come from one CPU model. They may not generalise to other hardware.
- **Not a real VMBR:** `kvm-masked` is a full QEMU/KVM stack, not a thin VMBR. It is also non-adaptive, i.e. it does not fake time.
- **Synthetic ground truth:** M1's synthetic test cases come from our own specification. The real-world configs only partly offset this.
- **Dump-time only:** M3 sees only what is in a dump at that moment, and only unlinked processes and modules.
- **Config-proxy classes:** Host→VMM, VMM vulnerabilities and side channels are checked by configuration or version, not by attack.

---

## 7. Risks and Fallbacks

| Risk | Fallback |
|---|---|
| E1 not possible | M4 compares 1 vs 2 virtualization layers in WSL, with the claim renamed |
| libvirt fails in WSL | M1 runs on fixture folders only |
| No public Linux forensic images (W2 gate) | The optional rootkit test in isolated `target` becomes the main M3 test |
| Volatility cannot read the kernel | Use an older Ubuntu kernel that already has symbol files |
| Timing too noisy | Lengthen the windows. If still noisy, report it as a negative result |
| Clock source cannot be equalised | Report it as a confound in the results |
| Masking misses an indicator | Record it in the indicator-leak table |
| Collection falls behind | Fewer workloads per boot. Never fewer than 10 sessions per class |

**Cut order if behind schedule:**

1. SHAP and MAD aggregation (stretch, not required)
2. Performance counters (M4 secondary)
3. M3's extra kernels and the rootkit test
4. M2's redaction
5. Lynis/OpenSCAP comparison
6. Real-world M1 configs

**Never cut:**

- `prereg.md` and the gate (W2 commit before any real data)
- randomised, interleaved M4 sessions
- the session-level, grouped CV analysis
- M4's indicator-masked class
- M1's self-consistency evaluation
- the result matrix
- preflight gate before every M4 session

---

## 8. Scope and Responsible Use

**This is defensive research on your own hardware.**

- **Masking:** uses only standard libvirt options (`<features><kvm><hidden>`, `mode='host-passthrough'`, `<smbios>`, non-virtio devices). No time-faking or anti-detection code.
- **Rootkit:** only inside the isolated `target` VM, after the preflight gate (`scripts/preflight_target.py`) confirms no other VM is running, the target is offline, hostdev is free, and the machine is reverted. Never on the host or host tools.
- **Real malware:** not used. No VMBR, no production code, no real credentials.
- **Scope:** one PC, one CPU model, non-adaptive hypervisor. The results do not generalise to other hardware or adaptive attackers.

## 9. Lab Safety Rules

- Use synthetic secrets and throwaway keys only. Never use real credentials.
- Get the BitLocker recovery key on paper (kept offline) before changing the boot order.
- Disconnect the internal disk during Ubuntu install on E1, or point the bootloader at the external SSD's EFI partition.
- All project files stay inside the project folder. Scratch files and data go in `.local/`, which is gitignored.
- Before every M4 session, run `scripts/preflight_target.py` to confirm the host is clean and the target VM is reverted.

---

## 10. Code Layout

```
vsec/
  taxonomy.yaml   collect.py   score.py   report.py   __main__.py
  m1_audit.py     m2_snapshot.py   m3_forensics.py
  m4_detect/  bench.c   features.py   classify.py   stats.py
tests/
  fixtures/       # M1 case folders, small dumps
  test_*.py
prereg.md         # committed before W3
.local/           # VMs, dumps, datasets, logs (gitignored)
```

---

## 11. Solo Decisions (You)

1. **E1 available?** You need an external SSD of at least 64 GB, a PC that can boot from USB, and your BitLocker recovery key on paper. If not, M4 falls back to WSL layering (1 vs 2 VLayers).
2. **Real deadline?** This plan assumes 8 weeks. Compress or extend as needed.
3. **Licence for your code.** Decide before W8 and document in `docs/YOUR_TASKS.md`. You are not required to add a LICENSE file; this is your choice.
4. **Drop the M1 illustrative attack-path output?** Recommended: yes (stretch only, first on the cut list with SHAP).
5. **Add `defusedxml` as a dependency?** Low real risk (`vm.xml` comes from the host's `virsh`), one extra package.

---

## 12. Change Log (what has been done)

Everything was built on a Windows laptop without KVM. The only real hardware run was Round 6 (bench.c compiled and run once in WSL2 on 2026-10-04 as a functional check; no real KVM host or E1 native machine has been used). Dates are 2026-10-03/04.

**Round 1: first build.** Common framework (`taxonomy.yaml` with 31 controls, findings, report, `python -m vsec run`); M1 auditor (28 checks, 50 generated fixtures, scoring with Wilson CIs); M2 scanner, redaction and scoring on synthetic dumps; M3 Volatility wrapper and scoring; M4 `bench.c`, features, nested grouped CV, H1-H4, simulator; `prereg.md` draft; 18 tests.

**Round 2: AI-agent review wave 1** (python, security, statistics, QA, silent-failure and C reviewers; about 90 findings).
- M1: a missing, empty or unreadable file gives NA, never PASS; crashing checks give NA with the error; real-world value formats parsed (C01, C05, C07, C12, C19, C20, versions).
- Scoring and report: undefined ratios are None; NA predictions counted separately; per-VM matrix shows PASS only when every control in the class was tested.
- `collect.py`: name validation, `--security-info`, restrictive permissions, symlink refusal.
- M2/M3: manifests validated, dumps memory-mapped, chunked redaction, `restore_test` limited to `target` on an isolated network, `plant_guest.py` offline check, Volatility errors raise instead of looking clean.
- M4: real elapsed seconds (`elapsed_ms`), H4 single criterion (10 s and 5%), Holm applied, H3 per session, H1 ceiling rule and CPUID-excluded analysis, paired session bootstrap, leave-one-day-out CV, clock-source gate, standardized mean differences.
- `bench.c`: compiles with zero warnings under the zig cross-compiler (never run); `elapsed_ms` column, 256 MB working sets, pinning check, orphan-proof load child, grouped perf counters.
- Scripts and VMs: input validation, CPU settings restored on exit, one qcow2 overlay per VM, isolated-network XML, blocked session schedule.

**Round 3: solo rewrite and safety gates.** Plan rewritten for one person (no team roles); M1 relabelled as self-consistency tests; `docs/YOUR_TASKS.md`, `docs/E1_CHECKLIST.md`, `docs/DATA_SOURCES.md`, `THIRD_PARTY.md`; `requirements.lock` (real freeze); `.gitignore` extended. New: C16 needs a host-written `net_isolation.txt` (guest scan can only add a FAIL); `scripts/preflight_target.py` (host gate before dumping `target`), `scripts/guard_rootkit.py`, `scripts/run_vol_sandboxed.sh`, host-side `scripts/build_symbols.sh` with pinned hashes; `python -m vsec pilot`; banner and flags for simulated/synthetic data; `session_meta.py` records day, order, batch, minutes since boot, CPU count, SMT and thermal readings. State then: 236 passed, 10 skipped (Windows-only skips); fresh-copy install from the lock passed, `pip-audit` clean.

**Round 4: AI-agent review wave 2 (about 70 findings) and fix wave 3: DONE (2026-10-04, 588 tests).** Four agents applied fixes; all results verified against code.
- Verdict honesty: C23/C24 return NA while CVE entries are unverified; C29 and C30 no longer pass on "nothing detected"; C16 strict parsing and more exit paths (passed-through NIC, `qemu:commandline`, filesystem shares, vsock, TCP channels, networks with an `<ip>`); a crashed module becomes `ERROR` with a red banner and exit code 1; `--t-short` validated and required for real runs; `pilot` no longer writes a false "untestable" or picks a value from noise.
- Security: session-id validation by `case` patterns (newline bypass), manifest needles at least 16 bytes, password redaction by XML parse with a fail-closed verifier, bounded SSH-key scan rule, mandatory symbols hash with copy-and-rehash, time-limited JSON revert marker, stronger Volatility sandbox.
- Robustness: malformed schedule/`meta.json` handled, `plan_sessions.py` validates before writing, `collect.py` writes a manifest and cleans up after failure; new session-QC step (`session_qc.py`, writes `qc.json`); failed QC leaves a `FAILED` marker.
- Docs: `docs/YOUR_TASKS.md` commands corrected (session ids, pilot size, M2 loop, symbol build, Task B before A, --allow-unscheduled flag), pilot is 5 native + 5 `kvm-masked` boots (10 total), E1_CHECKLIST and README updated with correct `domif-setlink` order, `clocksource=tsc` on every boot and `maxcpus=2 mem=4G` only on separate native boot, bench install as root-owned in /opt/vsec, vms/*.xml comments with absolute paths and virt-copy-out usage.

**Round 5: AI-agent review wave 3 (ML engineering blocker and security third pass), completed 2026-10-04.**
- ML engineering: bench.c vs features CSV column-order BLOCKER, fixed by reading columns by name with a contract test `tests/test_bench_contract.py`.
- Security: guard allow-lists, redaction comma-aware, hash-pinned symbols/rootkit module copies, session QC step.
- Wave 4: measured startup, load-child liveness, host-side `make_manifest` generator for M2 ground truth, `--allow-unsandboxed` flag for Volatility, results marked "EXPLORATORY" if not exactly 15 sessions per class with 4 workloads each.
- Documentation: failing session workflow (retry with moved backup folder), M3 results flow (--row-name, --truth-hidden, --append flags), pilot exit codes (0/1/2), AppArmor fix for Ubuntu 24.04, C23/C24 CVE caveat (NA while unverified or distro builds), Linux test skips (19 on Windows), Volatility outside $HOME.
- Code state at the end of round 5 (2026-10-04): 954 tests passed, 19 skipped on Windows (symlinks, POSIX permissions, bash/sandbox), in 486 s on a busy laptop. Later, with more tests and no other load, a full Windows run gave 1009 passed, 19 skipped in about 4 minutes (1028 tests collected; `-m "not slow"` skips the calibration test). The five slowest M4 statistics tests dominate the runtime. bench.c compiles with zero warnings (zig cross-compiler; first real run came later, see Round 6); 3 shell scripts pass `bash -n`; 7 Python scripts compile. One earlier run took 52 minutes because of a one-off stall on the laptop, not a test problem.

**Round 6: first real run of `bench.c` (2026-10-04, WSL2 Ubuntu 24.04, gcc 13.3, kernel 6.6.87.2-microsoft-standard-WSL2, Intel i5-12450H).** Functional validation only: WSL2 is itself a VM under Hyper-V, so this is NOT a native-vs-VM comparison and no number from it is a finding. What it showed: (1) a real gcc compile found a `-Wformat-truncation` warning that the zig cross-compiler missed in `read_line`; fixed. (2) `bench` ran to exit 0 for all four workloads, printed a correct metadata line (hypervisor bit 1, clocksource tsc, THP madvise, startup 2.7-2.9 s per workload), reported the load child alive for every workload and left no orphaned child process. (3) The real CSV loads through `features._read_csv`/`features.load` with every value in the right column; `session_meta.py` and `session_qc.py` accept the real session folder (`ok: true`; perf counters not exposed under WSL, recorded as such). (4) A window takes 135-310 ms of wall time, not `window_ms`, and the `cpu` workload's windows take about twice as long as idle (the load shares the pinned core): measured elapsed time, not nominal, drives T. (5) Startup of 2.7-2.9 s per workload is higher than the 1.5 s assumed for H4, so H4 uses the measured `bench_startup_ms`. (6) **Full test suite on Linux** (WSL2 Ubuntu 24.04, Python 3.12, user-approved `python3-venv` install; project-local venv under `.local/venv-wsl`): on the default `/mnt/d` mount (no POSIX permission metadata) 13 tests failed, of which 11 were `chmod`-dependent and are filesystem artefacts; with `D:` re-mounted with `metadata` the result was 985 passed, 2 failed, 1 skipped. The 2 real failures were fixed: `test_marker_is_created_exclusively_without_following_links` called a real `virsh` (the test now fakes it), and `run_vol_sandboxed.sh` silently replaced an explicitly empty `VOL_*` limit by its default (a set-but-empty limit is now an error; unset still means the default). The 6 affected tests were re-run green on Linux; the full Linux suite was not repeated after these two fixes. Still NOT run on real hardware: the E1 native machine, the KVM guests, `virsh`/libvirt, Volatility, `bwrap`.

---

## 13. Planned Changes (what needs to happen next)

**A. Final verification and Linux test run.** Re-run the full test suite on Linux after the two Round 6 fixes (`.local/venv/bin/python -m pytest -q`): confirm final skip/failure counts and that symlink/POSIX-permission/bash tests pass. Verify all three shell scripts pass `bash -n`. Then a native Linux run on E1 hardware (`.local/venv/bin/python -m pytest -q`). See `docs/YOUR_TASKS.md` for all hands-on steps (tasks A–J).

**B. Needs your hardware (see `docs/YOUR_TASKS.md`, tasks A-J).** Task B before Task A. Compile and run `bench.c` on Linux (Task A); build E1 safely with BitLocker key offline (Task B); 10-boot pilot and `python -m vsec pilot` (Task C); fill `prereg.md` PILOT and T_short (Task D); `git init`, commit and tag `prereg.md` before any real session (Task D); real M2 dumps from `target` with 15-minute gates and domif-setlink after each revert (Task E); M3 symbols build with sha256 and public image test (Tasks G–H); final M4 batch collection (Tasks F) with real data (nothing in M4 has touched real data on Windows); Lynis/OpenSCAP runs (Task I); licence and CVE verification (Task J).

**C. Improvements ranked by value (from the product review).**
1. Run the full M4 pipeline on real pilot data (Tasks C–F) and verify nested CV, bootstrap, H1–H4, and balance check produce sensible numbers.
2. Independent M1 evidence: Lynis and OpenSCAP on the live `weak`/`hardened` hosts (Task I) and about 10 real-world configs, since the 50 fixtures are self-consistency only.
3. Real M3: at least 5 real dumps per image (hidden vs clean) with Clopper-Pearson CIs and a failure table (Tasks G–H).
4. Real M2: all 12 cells from actual VM memory (n=5 first then 10), including `ssh-agent` and `openssl` as real-program cells (Task E).
5. Verify `collect_manifest.json` and `session_qc.py` catch real errors; test the QC gate under failure (Task F).
6. Tag `prereg.md` before real data collection (Task D).
Cut: M1 attack-path chains and SHAP (stretch only); M3 second kernel and optional rootkit test if time runs short; M2 redaction if time runs short.

**D. Technical debt I want to address.**
- Time every `bench.c` probe with the TSC instead of `clock_gettime` (a guest falling back to hpet or acpi_pm would inflate its timings); today the analysis only flags and excludes such sessions.
- Wire the `collect_manifest.json` reports from M2 and the `session_qc.json` from M4 into the final report so failed checks are visible.
- Add CI (pytest on Linux) so the symlink, POSIX-permission and `bash` tests run on every change; they skip on Windows, and the one full Linux run so far was manual (see Round 6).
- Split the slow M4 calibration tests behind the `slow` marker and keep the default suite under about 2 minutes.
- Check Volatility plugin names (`linux.psscan`, `linux.hidden_modules`, `linux.lsmod`) against the installed release.
- Pin the rootkit module hash in `guard_rootkit.py` and verify the window between check and `insmod`.
- Improve the M2 scanner only where the plan allows (held-out variants stay "rules written without seeing them"); a real SHA-256 stays a documented false positive.

**E. Open decisions** (also in section 11): licence; `defusedxml`; drop attack paths; whether M1 should carry the synthetic banner (currently marked by `kind: self_consistency` and a note instead); M4 results reported as "EXPLORATORY" if the 15-per-class threshold was not met (affects what analysis section says).

---

## 14. External Plan Review Addendum (2026-10-25)

An outside review (via GPT) of this plan was checked against the actual repo. Per-module pass/fail evidence now lives in `docs/DEFINITION_OF_DONE.md` — tick boxes only once there is a test, log or file behind them. Summary: M1/M2 code and synthetic-test obligations are done; M3 code is done but never run against a real image; M4 analysis code is done but `prereg.md` is still uncommitted and no real session exists. Nothing unchecked there is a coding gap — all of it needs E1, Volatility, or Lynis/OpenSCAP, which only the project owner's hardware can supply.

**Frontend/dashboard decision:** a local Flask dashboard (4 screens: overview, security assessment, experiment results, reports) was proposed as a W7, lowest-priority addition, explicitly the first thing to cut if time is short. It was **not built** during this review: no module has produced real output yet, so there is nothing a dashboard would show beyond the same banners the existing `report.html` already renders. The unified CLI (`python -m vsec run`) already is the single orchestrator — it already standardizes output schemas across M1-M4 and already reports a crashed module as `ERROR` without stopping the others (`vsec/report.py:failed_modules`, covered by `tests/test_report.py`). Build the dashboard only after real M4/M2/M3 data exists, if there's still time.

**Daily routine (solo):** review the day's goal (15 min) → one focused implementation task (2-3 h) → write/update tests (1 h) → run tests and investigate failures (45-60 min) → commit and update docs (20-30 min). Keep one issue list with four severities: **Critical** (wrong security finding, invalid research result, data corruption, unsafe execution), **High** (broken module workflow, major validation failure, unreproducible experiment), **Medium** (edge-case gap, reporting defect), **Low** (cosmetic/doc). Never start a new feature while a Critical is open.

**Statistical caution already covered:** the suggestion to justify the 45-session M4 plan's precision instead of assuming it's "enough" is already in `prereg.md` (Power and limits): AUROC standard error ≈0.08 at 15-per-class, minimum detectable difference ≈0.15-0.2, explicitly stating a null result is not evidence of no difference. No change needed there.
