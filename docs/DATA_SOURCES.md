# Data Sources and Collection Rules

This document tracks external data sources used in M3 and M4, and documents where data is downloaded, stored, and how it is cited.

## Rule: Download-Only, Local Storage, No Redistribution

External data is organized as follows:
1. **Real measured data** (M2 dumps, M4 sessions, M3 results) → `data/` (gitignored).
2. **External downloads** (public memory images, symbol files, rootkit source) → `.local/` (gitignored).
3. **All data** is downloaded only (never committed), stored locally, and not redistributed.

## M3: Public Linux Forensic Memory Images

Fill in the table below with each public memory dump you use for ground truth in M3.

| Name | Source URL | Size | License | Terms of Use | Citation | Redistribution Allowed? | Download Date | Status |
|---|---|---|---|---|---|---|---|---|
| | | | | | | | | |
| | | | | | | | | |

**Sources are unchecked until a specific image with licence and terms is entered below.** Potential sources:
- [Volatility Foundation](https://www.volatilityfoundation.org/): public memory dumps and courses.
- [Champlain College DFIR Datasets](https://www.champlain.edu/digital-forensics-and-cybersecurity/academic-programs): programs page (datasets must be confirmed).
- [NIST CFREDS](https://www.cfreds.nist.gov/): curated forensic datasets.

**Verification in W2:** identify and confirm at least 2–3 suitable *Linux* images with documented license/terms and confirmed hidden processes before proceeding with M3 testing.

---

## M3: Rootkit (Optional)

If you use a public research rootkit for M3 testing, fill in:

| Rootkit Name | Source Repo | Source Commit | License | Notes | Download Path |
|---|---|---|---|---|---|
| | | | | | |

**Rule:** Install only in the isolated `target` VM, with no network. Run `scripts/preflight_target.py` before every test to confirm the host is clean.

**Rootkit candidates:**
- [Suterusu](https://github.com/mncoppola/suterusu) (simple LKM rootkit, GPL)
- [diamorphine](https://github.com/m0nad/diamorphine) (LKM rootkit, GPL)

Note the commit hash you use, so results are reproducible.

---

## CVE Entries to Verify

Fill in the table below with each CVE you reference in M1 (C23/C24: QEMU, kernel, libvirt version checks).

| CVE ID | Advisory URL | Affected Versions | Fixed-In Version | Retrieved Date | Verified? | Notes |
|---|---|---|---|---|---|---|
| | | | | | | |
| | | | | | | |

**Verification checklist per CVE:**
1. Confirm the CVE ID matches the NVD advisory.
2. Verify affected versions overlap with your E0/E1 setup.
3. Confirm fixed-in version (mark `verified:false` in `vsec/cves.yaml` until you check against NVD).
4. Document the check date (when you last verified against NVD).

**Important caveat (C23/C24):** Both C23 (QEMU CVEs) and C24 (kernel CVEs) return **NA** (not applicable) while any CVE entry is **unverified**, AND for distro builds (Ubuntu/Debian backports) **even when verified**. The reason: a distro backport may include security patches not reflected in the official CVE version numbers. Fill in the CVE table with advisory URLs before C23/C24 can ever PASS or FAIL.

**Starting sources:**
- [NVD CVE Search](https://nvd.nist.gov/vuln/search)
- [QEMU Security](https://wiki.qemu.org/Security_Advisories)
- [Linux Kernel CVE](https://www.kernel.org/doc/html/latest/admin-guide/security-bugs.html)

---

## References and Attribution

When you cite external data or benchmarks in the paper:

1. **Public memory images** → cite by name, source (Volatility Foundation / Champlain College), and URL.
2. **Rootkit source** → cite repository, commit hash, and license.
3. **CIS Benchmarks** → cite by name and version (e.g., "CIS Benchmarks v3.1.0"), do not copy text.
4. **2020 Virtualization Security Survey** → cite the original paper (author, year, venue).
5. **NVD CVE data** → link to the CVE page, cite as "NIST NVD".

---

## Data File Layout

All real data lives in the project's `data/` folder (gitignored), not in `.local/`:

```
data/
  m4/                            # M4 collection (gitignored)
    schedule.json                # session plan from plan_sessions.py
    <session_id>/
      idle.csv                   # bench output for idle workload
      cpu.csv                    # bench output for cpu workload
      mem.csv                    # bench output for memory workload
      mixed.csv                  # bench output for mixed workload
      idle.bench.txt, cpu.bench.txt, mem.bench.txt, mixed.bench.txt  # bench stderr (metadata)
      meta.json                  # session metadata (class, day, session order, kernel, etc.)
      thermal.txt                # temperature readings per workload
  m2/                            # M2 snapshots (gitignored)
    <kind>_<state>_<n>.mem       # memory dump (virsh dump output, raw)
    <kind>_<state>_<n>.json      # manifest (what secret was planted, where)
  m3/                            # M3 forensic results (gitignored)
    results.json                 # one JSON row per dump (appended by m3 command with --append)

.local/
  tmp/                           # temporary test files, venv, logs
  symbols/                       # M3 symbol files (ubuntu-<version>.json, ubuntu-<version>.sha256)
  rootkit/                       # optional rootkit source (download only)
```

**M3 results.json** (one line per image/dump):
```json
{"name": "ssh_key_live_5", "detected": [1234, 1235], "truth_hidden": [1234, 1235], "symbols_sha_verified": true}
```

All data in `data/` and `.local/` is gitignored and never committed.

---

## Completion Checklist (W2 gate + final)

**Before M3 data collection (W2):**
- [ ] At least 2 public Linux forensic images identified and verified.
- [ ] Source, license, and terms documented in the table above.

**Before W8 paper submission:**
- [ ] All CVE entries verified against NVD and marked `verified:true` in `vsec/cves.yaml`.
- [ ] All public data sources cited with full URLs and license information.
- [ ] No sensitive data (keys, credentials, real malware) left in the repo or `.local/`.
