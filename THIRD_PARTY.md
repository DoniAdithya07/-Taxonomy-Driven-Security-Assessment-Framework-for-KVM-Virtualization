# Third-Party Dependencies and Tools

This document lists all external tools and libraries used in this project, their purpose, how they are integrated, and their licenses.

## Python Libraries (imported at runtime)

| Tool/Library | Purpose | How Used | License | Version |
|---|---|---|---|---|
| **numpy** | [VERIFY] Numerical computing | Imported directly for array operations | BSD | (pinned in requirements.txt) |
| **scipy** | Scientific computing | Imported for rankdata, beta distribution (stats) | BSD | (pinned in requirements.txt) |
| **scikit-learn** | [VERIFY] Machine learning | Imported for classifiers, CV, metrics | BSD | (pinned in requirements.txt) |
| **pyyaml** | YAML parsing | Imported to read `taxonomy.yaml` and `cves.yaml` | MIT | (in requirements.txt) |
| **pytest** | Testing framework | Imported for unit tests in `tests/` | MIT | (in requirements.txt) |
| **python-pptx** | Presentation generation | Imported (if cited) for slides | MIT | (in requirements-dev.txt) |
| **joblib** | Parallelization | Transitive: imported by scikit-learn | BSD | (transitive) |
| **threadpoolctl** | Thread control | Transitive: imported by scikit-learn | BSD | (transitive) |

Install all with: `pip install -r requirements.txt`. Versions are unpinned in requirements.txt; pinned versions are in requirements.lock (Windows-only freeze, excluding colorama on Linux).

## Build-Time Tools (development only, not shipped)

| Tool | Purpose | How Used | License |
|---|---|---|---|
| **ziglang** | C compilation check | Windows-only check that `bench.c` compiles for Linux | MIT |

Install with: `pip install -r requirements-dev.txt`

## External System Tools (must be installed separately)

| Tool | Purpose | How Used | License | Repository |
|---|---|---|---|---|
| **Volatility 3** | Memory forensics | Run separately on memory dumps for M3; not vendored | [Volatility Software License](https://github.com/volatilityfoundation/volatility3/blob/develop/LICENSE.txt) | https://github.com/volatilityfoundation/volatility3 |
| **dwarf2json** | Symbol extraction | Called by `scripts/build_symbols.sh` for Volatility; licence unverified | [Licence TBD] | https://github.com/volatilityfoundation/dwarf2json |
| **QEMU** | Hypervisor | E0 (WSL2) and E1; run via libvirt | GPL-2.0 / LGPL-2.1 | https://www.qemu.org |
| **libvirt** | VM management | Daemon and tools for VM lifecycle (`virsh`, `virt-install`) | LGPL-2.1+ | https://libvirt.org |
| **Linux kernel** | Guest OS and M4 native boot | Ubuntu 24.04 kernel on guest and E1 | GPL-2.0 | https://kernel.org |
| **Lynis** | Host auditor | Standalone tool for live host security auditing (M1 comparison); planned, never run | GPLv3 | https://github.com/CISOfy/lynis |
| **OpenSCAP** | Host auditor | Standalone tool for live host security auditing (M1 comparison); planned, never run | LGPL-2.1+ | https://www.open-scap.org |

Install on Ubuntu:
```bash
sudo apt install -y python3-venv gcc qemu-system-x86 qemu-utils ovmf libvirt-daemon-system libvirt-clients virtinst bubblewrap
sudo apt install -y lynis openscap-scanner ssg-base ssg-debian ssg-applications
python3 -m venv .local/venv
.local/venv/bin/pip install -r requirements.txt
.local/venv/bin/pip install volatility3
# dwarf2json is a Go binary: download from github.com/volatilityfoundation/dwarf2json releases
```

## Data and References (not redistributed)

| Source | Use | License | Terms | Attribution |
|---|---|---|---|---|
| **CVE data (M1 C23/C24)** | CVE reference list for QEMU and kernel vulnerability checks (M1 controls C23/C24 only, not M4) | `vsec/cves.yaml` entries marked `verified:false`; not checked against NVD; returns NA | Do not redistribute; verify against NVD if used for claims | https://nvd.nist.gov |
| **2020 Virtualization Security Survey** | Threat taxonomy source (cited as [SURVEY-2020]); nine threat classes and 31 controls are this project's own mapping | Academic paper; full citation required | Cite in paper | Citation unknown; mark as TODO |
| **CIS Benchmarks** | Security hardening baselines (referenced in M1 controls documentation, not copied) | Proprietary | Cite by name/version in paper, do not copy text | CIS, https://www.cisecurity.org |
| **Volatility public memory dumps** | Ground truth for M3 (public Linux forensic images); to be downloaded for evaluation | Varies (academic, course datasets) | Check per dump; verify licence; do not redistribute | Volatility Foundation, Champlain College |

For M3 public images: download only, keep in `.local/`, do not redistribute.

## Summary

- **No vendored code:** all Python dependencies are installed via `pip` and unpinned in `requirements.txt`. Version locks (Windows-only) are in `requirements.lock`.
- **No proprietary software:** CIS benchmarks are cited but not copied. Lynis and OpenSCAP are free tools; their comparison with M1 is planned but has never been run.
- **No real malware:** no production code, rootkits, or real credentials in the repo.
- **Masking uses only standard libvirt options:** no time-faking or anti-detection code.
- **joblib and threadpoolctl:** transitive dependencies of scikit-learn; not explicitly installed.
- **External tools not shipped:** Volatility 3, QEMU, libvirt, dwarf2json, Lynis, OpenSCAP must be installed separately on the host.
- **CVE list unverified:** `vsec/cves.yaml` is not checked against NVD; M1 C23/C24 return NA when any entry is unverified or for distro builds.
- **Licence verification pending:** dwarf2json licence status unverified; 2020 survey citation not yet located.
