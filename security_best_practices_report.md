# Security Best Practices Report

## Executive Summary
This best‑effort review covers the Bash (`Kali-build-script.sh`) and PowerShell (`windows11-build-script.ps1`) build scripts. There are several high‑impact security risks, primarily around disabling Windows Firewall, broad Defender exclusions, and unverified downloads executed or placed in privileged locations. These issues materially increase exposure if a workstation is reachable from untrusted networks or if supply‑chain sources are compromised.

## Scope
- `Kali-build-script.sh` (Bash)
- `windows11-build-script.ps1` (PowerShell)

## Method
Best‑effort static review of the scripts. There are no skill reference guides for Bash/PowerShell in the local security skill set, so findings are based on general secure‑by‑default practices for workstation provisioning.

---

## Critical Findings

### [WIN-CRIT-1] Windows Firewall Disabled for All Profiles
**Evidence:** `windows11-build-script.ps1` lines 75–80
**Issue:** The script disables Windows Firewall for Domain, Private, and Public profiles.
**Impact:** Disabling the firewall exposes the host to unsolicited inbound traffic on all networks, dramatically increasing the likelihood of remote compromise.
**Recommendation:** Keep the firewall enabled and add a scoped inbound rule for RDP only, limited to trusted subnets. Consider making firewall disablement an explicit opt‑in flag rather than a default action.

---

## High Findings

### [WIN-HIGH-1] Broad Microsoft Defender Exclusion for `C:\tools`
**Evidence:** `windows11-build-script.ps1` lines 294–299
**Issue:** The script excludes the entire `C:\tools` directory from Microsoft Defender scanning.
**Recommendation:** Restrict exclusions to specific executables or subdirectories, or use temporary exclusions only during downloads and remove them afterward. Prefer hash- or process‑based exclusions where feasible.

### [WIN-HIGH-2] LGPO.exe Downloaded from a Non‑Official Source Without Verification
**Evidence:** `windows11-build-script.ps1` lines 123–141
**Issue:** LGPO.exe is fetched from a GitHub repository and used by the baseline installer without integrity validation.
**Recommendation:** Require LGPO.exe from the official Microsoft Security Compliance Toolkit, validate its signature and/or checksum, and fail fast if verification cannot be completed.

### [KALI-HIGH-1] Unverified Binary Downloads Installed With Elevated Privileges
**Evidence:** `Kali-build-script.sh` lines 234–263
**Issue:** Multiple binaries are downloaded via `wget` and moved into privileged locations without checksum/signature verification.
**Recommendation:** Pin versions and verify SHA256 checksums or signatures before install. Store expected hashes in the script or a separate manifest.

### [KALI-HIGH-2] Unpinned Git Repository Clones as Root
**Evidence:** `Kali-build-script.sh` lines 203–231
**Issue:** Repositories are cloned from public sources without pinning to commits/tags or verifying signed tags.
**Recommendation:** Pin to known‑good tags/commits and verify signed tags where possible. Consider mirroring vetted repos internally.

---

## Medium Findings

### [WIN-MED-1] Multiple Downloads Without Integrity Verification
**Evidence:** `windows11-build-script.ps1` lines 176–233
**Issue:** Tools and extensions are downloaded using `curl.exe` without hash/signature verification.
**Recommendation:** Add checksum validation for each download. For vendor tools, verify Authenticode signatures where applicable.

### [KALI-MED-1] SSH Password Authentication Enabled by Default
**Evidence:** `Kali-build-script.sh` lines 45–55
**Issue:** `PasswordAuthentication yes` increases brute‑force exposure if the host is network‑reachable.
**Recommendation:** Default to key‑only SSH and make password authentication an explicit opt‑in flag. If password auth is required, pair it with fail2ban in all install modes.

### [KALI-MED-2] RDP Enabled Without Network Scoping
**Evidence:** `Kali-build-script.sh` lines 64–103
**Issue:** RDP is enabled without firewall restrictions or explicit scoping to trusted networks.
**Recommendation:** Add an option to restrict RDP to specific subnets or disable RDP unless explicitly requested.

### [KALI-MED-3] PyPI Installs Without Hash Pinning
**Evidence:** `Kali-build-script.sh` lines 176–190
**Issue:** `pipx` and `pip3` installs are performed without hash pinning or version constraints.
**Recommendation:** Pin package versions and (where feasible) use `--require-hashes` or a vetted wheelhouse to reduce supply‑chain risk.

---

## Low Findings

### [KALI-LOW-1] APT Key Import Without Fingerprint Validation
**Evidence:** `Kali-build-script.sh` lines 22–30
**Issue:** The archive key is fetched over HTTPS but not fingerprint‑verified, and failures are ignored.
**Recommendation:** Verify the key fingerprint and avoid `apt-key` by using `/usr/share/keyrings` with `signed-by` in the APT source list. Fail loudly if key retrieval fails.

---

## Notes
- No dynamic tests were run.
- The above findings focus on secure‑by‑default posture. In tightly controlled lab networks, some defaults may be acceptable but should remain explicit opt‑ins.
