# E1 Pre-Flight Checklist

Before touching E1, you (the owner) must complete this checklist. E1 is your PC running Ubuntu on an external SSD, and its setup is critical for data quality and hardware safety.

## Before any changes to boot order

- [ ] **BitLocker recovery key written on paper, kept offline.**
  - This is essential. Changing the boot order can trigger BitLocker recovery mode.
  - Write it down before you touch anything.

## Before Ubuntu install (external SSD, persistent)

- [ ] **Internal disk identified and noted.**
  - On Windows, run: `Get-Disk | Format-Table Number, Model, SerialNumber`.
  - Write down the internal disk name and serial number.
  - You will explicitly exclude this disk or disconnect it during install.

- [ ] **Internal disk physically disconnected OR EFI target explicit.**
  - Either: physically disconnect the internal SSD/HDD from the PC before Ubuntu install.
  - Or: during Ubuntu install, use the "Advanced" partitioning option and explicitly choose the external SSD's EFI partition (e.g., `/dev/sdb1`).
  - The Ubuntu installer often writes GRUB to the internal disk if you don't.

- [ ] **External SSD identified by device serial.**
  - Run: `lsblk -o NAME,MODEL,SERIAL` and confirm which device is your external SSD.
  - Verify the serial number matches your disk label.
  - Do not proceed with `dd` or any disk write without this confirmation.

## After Ubuntu install (on E1, before W1)

**Initial E1 setup (one time):**
```bash
sudo apt update
sudo apt install -y python3-venv gcc qemu-system-x86 qemu-utils ovmf libvirt-daemon-system libvirt-clients virtinst bubblewrap
python3 -m venv .local/venv
.local/venv/bin/pip install -r requirements.txt
chmod +x scripts/*.sh
sudo usermod -aG libvirt $USER
# Re-login for libvirt group to take effect
export LIBVIRT_DEFAULT_URI=qemu:///system
# If you later use Volatility 3, also install it (OUTSIDE $HOME, e.g., /opt/vsec-venv):
# pip install volatility3  # or: pip install -r requirements.txt in /opt/vsec-venv
# Set VOL=/opt/vsec-venv/bin/vol when running M3 tests
```

**Ubuntu 24.04 AppArmor fix for Volatility sandbox (required for M3):**
```bash
# The default kernel restricts unprivileged namespace usage (needed for the sandbox).
# Make the fix persistent:
echo "kernel.apparmor_restrict_unprivileged_userns=0" | sudo tee /etc/sysctl.d/99-vsec-sandbox.conf
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
# Verify: sysctl kernel.apparmor_restrict_unprivileged_userns should return 0
```

If the wrapper still refuses after this fix, weak mode is available: `VOL_ALLOW_WEAK_SANDBOX=1 python -m vsec m3 ...` or `python -m vsec m3 ... --allow-unsandboxed`.

**Packages and environment:**

- [ ] **Packages frozen.**
  - Run: `sudo systemctl disable --now apt-daily.timer apt-daily-upgrade.timer` (disable auto-updates).
  - Run: `sudo systemctl disable --now unattended-upgrades` (disable automatic upgrades).
  - Run: `sudo apt-mark hold linux-image-generic qemu-system-x86` (freeze kernel and QEMU for the collection period).
  - Verify: `sudo apt-mark showhold` lists them both.

- [ ] **No secrets or keys in the repo.**
  - Search: `grep -r "BEGIN RSA" .` and `grep -r "password" .` in the project folder.
  - All keys are synthetic and throwaway for testing only.
  - Confirm you have not accidentally added `.env` or credentials files.

- [ ] **Clock source fixed in kernel command line (grub)**
  - For **VM boots** (kvm-plain, kvm-masked): edit `/etc/default/grub` and add `clocksource=tsc` (sets clock source on every boot).
  - For **native boot only** (separate GRUB menu entry): edit `/etc/default/grub` and add `clocksource=tsc maxcpus=2 mem=4G` (match the 2-vCPU guests and limit to 4GB RAM).
  - Run: `sudo update-grub`.
  - Verify on every boot: `cat /proc/cmdline | grep clocksource` (must include `clocksource=tsc`).

- [ ] **CPU frequency and turbo fixed.**
  - Run once at boot: `echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor`.
  - For Intel: run: `echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo`.
  - The `run_session.sh` script will enforce this per session, but you should verify it works on your hardware.

## Before W1 data collection (preflight per session)

**Note on environment variables:** When calling run_session.sh as root (via sudo), environment variables like TEMP_C are stripped by sudo. Pass them explicitly: `sudo TEMP_C=25 scripts/run_session.sh <class> <id>`. The script never prompts for temperature; if TEMP_C is not set, temperature readings are recorded as "na".

- [ ] **No other VM is running.**
  - Run: `virsh list` (should show nothing or only `--not run--` VMs).
  - `scripts/preflight_target.py` will check this before every dump.

- [ ] **Target VM is offline and reverted to baseline snapshot.**
  - Run: `virsh snapshot-list target` (should show the snapshot).
  - For M2/M3 dumps (not M4 sessions): you must manually run `virsh snapshot-revert target <snap>` before each dump.
  - M4 sessions use run_session.sh on native or VM boots; they do not use target.

- [ ] **Host device (PCIe) is free (if IOMMU/GPU passthrough is used).**
  - Run: `find /sys/kernel/iommu_groups -type l` to list IOMMU groups (or `lspci | grep -i "IOMMU"` for a full list).
  - Confirm no device is claimed by a running guest.
  - `scripts/preflight_target.py` will check this.

- [ ] **Single-use 'reverted' marker file workflow (15-minute window).**
  - After `virsh snapshot-revert target <snap>`: CRITICAL: run `virsh domif-setlink target <vnetN> down` **immediately** (unless the snapshot XML already has `<link state='down'/>`). The guest refuses to plant secrets while the network link is up.
  - Then run: `python scripts/preflight_target.py --mark-reverted` (creates `.local/target.reverted`).
  - Before `virsh dump`, run: `python scripts/preflight_target.py` (the gate: checks marker exists and age <= 15 min, other VMs offline, target isolated, links down; then deletes marker).
  - This marker is single-use and expires in 15 minutes: every dump needs a fresh revert, link-down, re-mark and gate within the 15-minute window.
  - **Order (for M2/M3 dumps):** revert → setlink down → --mark-reverted → (plant secret in guest) → gate → dump.

## Checklist use

Print this checklist or keep it in a text editor. Tick off each item as you complete it. Do not skip any—each is a gate:

- Missing BitLocker key → risk of data loss if boot order is changed.
- Internal disk not disconnected → risk of GRUB install to wrong disk, making Windows unbootable.
- Packages not frozen → risk of kernel/QEMU changes during collection, breaking reproducibility.
- No preflight check → risk of collecting data with the wrong VM state (not reverted, or other VM running).

**If E1 is not available**, the fallback is to run M4 on E0 (WSL with two virtualization layers), and the claim becomes "detecting an extra virtualization layer". Document this decision in the final paper.
