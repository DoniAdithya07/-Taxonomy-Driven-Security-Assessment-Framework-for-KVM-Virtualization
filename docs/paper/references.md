# References

Complete the following citations as you fill them in. Remove the TODO lines and provide full bibliographic details.

**NOTE ON UNVERIFIED CITATIONS:** The citations in this document for scikit-learn (Pedregosa et al., JMLR 12, 2011) and NumPy (Harris et al., Nature 585, 2020) are included from memory and have not been verified against the publisher pages. Before final submission, verify all such citations against the original publication venues. Citations marked [VERIFY against the publisher page before submission] must be checked.

## Primary Source: The 2020 Survey

**[SURVEY-2020]**  
TODO: student to supply full citation.  
TODO: Provide author(s), year, title, venue (journal/conference), and DOI/URL if available.  
*This is the taxonomy source for all threat classes and controls.*

## Tools and Systems

**[QEMU]**  
QEMU Project. QEMU Emulator and Virtualizer.  
https://www.qemu.org/  
TODO: Document the QEMU version used in E0 and E1 (from environment setup, e.g., `qemu-system-x86 --version`).

**[LIBVIRT]**  
Libvirt Project. libvirt: The Virtualization API.  
https://libvirt.org/  
TODO: Document the libvirt version used (from `virsh --version`).

**[VOLATILITY]**  
Volatility Foundation. Volatility 3 Memory Forensics Framework.  
https://github.com/volatilityfoundation/volatility3  
TODO: Document the Volatility version (from `vol --version`).

**[DWARF2JSON]**  
Volatility Foundation. dwarf2json: Symbol extraction tool.  
https://github.com/volatilityfoundation/dwarf2json  
TODO: Document version used.

**[LINUX-KERNEL]**  
Linux Kernel Organization. The Linux Kernel.  
https://kernel.org/  
TODO: Document the kernel version used in E0 (WSL2 Ubuntu) and E1 (native Ubuntu).  
*E.g., "Ubuntu 24.04 with kernel 6.8.0"*

**[LYNIS]**  
CISOfy. Lynis Security Auditing Tool.  
https://github.com/CISOfy/lynis  
Distributed under GPLv3.  
TODO: Document Lynis version used for M1 comparison (from `lynis --version`).

**[OPENSCAP]**  
OpenSCAP Project. OpenSCAP: Open Security Content Automation Protocol.  
https://www.open-scap.org/  
TODO: Document OpenSCAP version (from `openscap --version` or similar).

## Standards and Benchmarks

**[CIS]**  
CIS Benchmarks. https://www.cisecurity.org/benchmarks/  
Proprietary; cite by name and version.  
*Used for hardening recommendations in M1 (controls C03–C20, etc.)*  
TODO: Document which CIS benchmark versions were referenced (e.g., "CIS Benchmarks for Kubernetes v1.x", "CIS Docker Benchmark v1.x").

**[NVD]**  
National Institute of Standards and Technology. National Vulnerability Database (NVD).  
https://nvd.nist.gov/  
US government data; free to use. See NVD's current terms of use.  
*Used for CVE verification in M1 (controls C23, C24).*  
TODO: Document any CVE data retrieval date or version used.

## Related Work on Hypervisor Detection

TODO: Add citations for prior work on hypervisor detection, timing side channels, and behavior-based detection.  
TODO: Provide at least one citation for each of the following (if not in the 2020 survey):
- Hypervisor detection using timing signals (CPUID, RDTSC, syscalls)
- Memory latency as a hypervisor indicator
- Scheduler jitter and noise analysis
- Static indicator masking and anti-detection techniques
- Machine learning for VM detection

*Suggested search terms: "hypervisor detection", "VM detection", "timing side channels", "performance counter side channels"*

## Security Hardening and Virtualization

TODO: Add citations for:
- QEMU seccomp sandbox (configuration and effectiveness)
- SELinux and AppArmor confinement of QEMU processes
- KVM nested virtualization security implications
- Kernel samepage merging (KSM) side channels
- IOMMU and DMA isolation (VT-d, AMD-Vi)
- Memory forensics and hidden process detection
- Snapshot privacy and secret leakage in memory

## Machine Learning and Statistics

**[SCIKIT-LEARN] [VERIFY]**  
Pedregosa, F., Varoquaux, G., Gramfort, A., et al. (2011).  
scikit-learn: Machine Learning in Python.  
*Journal of Machine Learning Research*, 12, 2825–2830.

**[SCIPY]**  
SciPy Contributors. SciPy: Scientific Python.  
https://scipy.org/  
*Used for statistical tests: Wilson confidence intervals, Clopper-Pearson CIs, rankdata, beta distribution.*

**[NUMPY] [VERIFY]**  
Harris, C. R., Millman, K. J., van der Walt, S. J., et al. (2020).  
Array programming with NumPy.  
*Nature*, 585, 357–362.

## Defensive Security and Responsible Disclosure

TODO: Add any citations related to:
- Defensive research practices
- Responsible vulnerability disclosure
- Ethical considerations in hypervisor research
- Sandbox and isolation for security testing

## Additional References

TODO: Add any other papers, tools, or documentation that informed the design or analysis of this framework.

---

## Completion Checklist

Before submission, ensure:

- [ ] Every TODO: line is resolved with a full citation.
- [ ] The 2020 survey has a complete author, year, title, and venue.
- [ ] All tool versions are documented (QEMU, libvirt, Volatility, etc.).
- [ ] CIS benchmark versions are specified.
- [ ] Related work citations (at least 5–10 papers on hypervisor detection and side channels).
- [ ] No TODO: lines remain in the final version.

---

## Citation Style

Use the following format consistently:

**Author(s) (Year). Title. *Journal or Conference Name*, Volume(Issue), Pages. DOI or URL.**

Example:
```
Pedregosa, F., Varoquaux, G., & Gramfort, A. (2011). scikit-learn: Machine Learning in Python. Journal of Machine Learning Research, 12, 2825–2830.
```

For web resources without traditional publication info:
```
Project Name. Description. https://url/. Retrieved [date] or version [X.Y.Z].
```

---

This file is a template. Replace the TODO lines with actual citations as you research and write the paper.
