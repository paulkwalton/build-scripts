# Build Scripts

Automated build scripts for provisioning penetration testing workstations on Kali Linux and Windows 11.

**Version:** Unreleased
**Last updated:** 2026-02-04

## Overview

This repository contains two automated build scripts designed to rapidly deploy and configure penetration testing environments:

- **Kali-build-script.sh** - Bash script for Kali Linux systems
- **windows11-build-script.ps1** - PowerShell script for Windows 11 workstations

## Kali-build-script.sh

### Description

Comprehensive Kali Linux provisioning script with three installation modes. Automates system hardening, tool installation, repository cloning, and service configuration for penetration testing environments.

### Features

- Three installation modes: Minimal, Default, and Full
- Automated pentest user creation with secure password generation
- SSH server installation and hardening
- RDP access via xrdp with Xfce desktop configuration
- System hardening with fail2ban and unattended-upgrades
- SSH host key rotation
- Kali archive key management
- PATH normalization for pipx and local binaries
- PostgreSQL database setup
- Nuclei template updates
- Service disabling for unused daemons
- Comprehensive tool and repository installation

### Installation Modes

#### 1. Minimal Install
```bash
sudo ./Kali-build-script.sh --minimal
```
- Installs `kali-linux-core` package
- Enables SSH with hardening
- Enables RDP access
- Normalizes PATH variables
- Creates pentest user account

#### 2. Default Install
```bash
sudo ./Kali-build-script.sh --default
```
- Installs `kali-linux-default` package (standard Kali tools)
- Enables SSH with hardening
- Enables RDP access
- Normalizes PATH variables
- Creates pentest user account

#### 3. Full Install
```bash
sudo ./Kali-build-script.sh --full
```
Includes everything from minimal/default plus:
- System hardening (fail2ban, unattended-upgrades)
- Extensive tool installation via apt
- Python tools via pipx (certipy-ad, sublist3r, dirsearch, eyewitness, mitm6, hashid, spray) and pip (`pyftpdlib`, `Cython`, `pysmb`)
- Git repository cloning to `/opt` (LinEnum, PEASS-ng, WES-NG, RemotePotato0, JuicyPotato, PrintSpoofer, Donut, psgetsystem, Invoke-Obfuscation, GodPotato, KeeThief, Kekeo, LAPSToolkit, krbrelayx, kerbrute, Coercer, ICS-Security-Tools, SharpHound, hoaxshell, GraphRunner)
- Binary/downloaded assets (Sysinternals Procdump, kerbrute, windapsearch, ruler, PingCastle, chisel, SCADA password list)
- SSH key rotation
- Nuclei template updates
- PostgreSQL service enablement
- Service cleanup and system hardening

### Tools Installed (Full Mode)

**Core Packages:**
- curl, wget, ca-certificates, git, jq, build-essential, macchanger
- python3, python3-pip, python3-venv, python3-impacket
- netcat-traditional, sqlmap, gobuster, dirb, nikto, nuclei, dnsrecon
- metasploit-framework, tcpdump, smbclient, enum4linux, responder, yersinia, seclists, ligolo-ng
- iputils-ping, net-tools, snapd, prips, rdesktop, sqlitebrowser, sshpass, powershell, nano
- postgresql

**Optional Packages (best-effort):**
- default-jdk, tilix, novnc, default-mysql-client
- auditd, audispd-plugins, filezilla, winetricks, libpcap-dev
- wireguard, awscli, lldpd

**Pipx Tools:**
- certipy-ad, sublist3r, dirsearch, spray, eyewitness, mitm6, hashid

**Pip Packages:**
- pyftpdlib, Cython, pysmb

### Interactive Mode

Run without flags for an interactive menu:
```bash
sudo ./Kali-build-script.sh
```
You'll be prompted to select:
1. Minimal Kali install
2. Default Kali install
3. Full Kali install

### Prerequisites

- Kali Linux system (bare metal or VM)
- Root privileges (run with `sudo`)
- Internet connection for package downloads

### Security Features

- **SSH Hardening**: Prohibits root login with password, enables pubkey authentication, sets client alive intervals
- **Fail2ban**: Configured for SSH with progressive ban times
- **Service Disabling**: Stops unnecessary services (bluetooth, avahi, cups, isc-dhcp-server/isc-dhcp-server6, slapd, nfs-server, bind9, vsftpd, dovecot, smbd, squid, snmpd)
- **Unattended Upgrades**: Automatic security updates
- **SSH Key Rotation**: Removes default SSH host keys and generates new ones
- **Secure Password Generation**: Uses OpenSSL for cryptographically secure passwords

### Credentials

After installation, pentest user credentials are saved to:
```
/root/pentest-credentials.txt
```
This file has 600 permissions (root-only access).

### Post-Installation

- Default SSH port: 22
- Default RDP port: 3389
- Remember to change the root password: `passwd root`
- Review and customize SSH hardening in `/etc/ssh/sshd_config.d/10-hardening.conf`

### Usage Notes

- Script uses `set -euo pipefail` for error handling
- Runs with `DEBIAN_FRONTEND=noninteractive` to avoid prompts
- All git repositories have `.git` directories removed to save space
- xrdp configured for Xfce desktop (Kali default)

---

## windows11-build-script.ps1

### Description

PowerShell script for provisioning Windows 11 penetration testing workstations. Automates bloatware removal, tool installation via winget, pentest tool downloads, and optional security baseline hardening.

### Features

- Removes Windows 11 bloatware and unnecessary apps
- Disables IPv6 across all network adapters
- Installs penetration testing tools via winget
- Downloads Burp Suite extensions, Sysinternals tools, and Nessus updates
- Enables all RSAT (Remote Server Administration Tools) features
- Optional Windows 11 v25H2 Security Baseline application
- Windows Defender exclusion for C:\tools directory
- Firewall configuration for RDP access

### Prerequisites

- Windows 11 (v25H2 or compatible)
- Administrator privileges (run PowerShell as Administrator)
- Internet connection
- Execution policy set to allow scripts:
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
  ```

### Usage

Run as Administrator:
```powershell
.\windows11-build-script.ps1
```

The script executes automatically and performs all configured tasks sequentially.

### Tools Installed

**Via Winget:**
- Microsoft Windows Terminal
- Cyberduck (file transfer)
- Tenable Nessus
- Burp Suite Professional
- Nmap
- Wireshark
- Docker Desktop
- Git
- Sysinternals Suite
- Azure Data Studio
- Azure Storage Explorer
- Azure CLI
- Google Chrome
- kubectl (Kubernetes)
- Python 3.14
- Bruno (API client)
- SQL Server Management Studio
- AzCopy
- OpenJDK 21
- BGInfo
- PuTTY
- LM Studio
- OpenAI Codex

**Downloaded to C:\tools:**
- Sysinternals ADExplorer.exe
- Sysinternals PSTools.zip
- Jython standalone (for Burp extensions)
- JRuby complete (for Burp extensions)
- Burp Suite extensions:
  - 403 Bypasser
  - Autorize
  - JSON Web Tokens
  - SAML Raider
  - JS Miner
  - Software Version Reporter
  - Logger++
  - Retire.JS
- Nessus updates (10.9.4)

### Security Baseline

The script includes commented-out code for applying the Windows 11 v25H2 Security Baseline (Non-Domain Joined). This is disabled by default as it may interfere with RDP functionality. The baseline ZIP is downloaded from Microsoft; LGPO.exe is fetched from the configured GitHub URL only.

To enable:
1. Uncomment the line that calls `Install-WindowsSecurityBaselineNonDomainJoined`
2. The baseline will be applied with `-Win11NonDomainJoined` flag
3. LGPO.exe is automatically downloaded from the configured GitHub source (the baseline ZIP no longer bundles LGPO.exe)
4. Reboot required after baseline application

### Network Configuration

- Sets Windows region to United Kingdom (GeoId: 244) for winget/Microsoft Store compatibility
- Disables IPv6 via registry (DisabledComponents = 0xFF)
- Disables Windows Firewall for all profiles (Domain, Private, Public)

### Functions

- `Remove-UnwantedApps` - Removes bloatware (Xbox, Zune, Maps, Solitaire, etc.)
- `Disable-IPv6` - Disables IPv6 protocol stack
- `Allow-RDP-InboundFirewall` - Disables Windows Firewall for RDP access
- `Install-WindowsSecurityBaselineNonDomainJoined` - Applies Microsoft security baseline (optional)
- `Download-PentestTool` - Downloads tools to C:\tools using parallel jobs
- `Enable-AllRSATTools` - Installs all Remote Server Administration Tools

### Post-Installation

- Review installed tools in Start Menu
- Configure Burp Suite Professional license
- Configure Nessus (requires license/activation)
- Review Windows Defender exclusions
- Verify network adapter settings
- Consider re-enabling Windows Firewall with custom rules if needed

### Security Warnings

- Windows Firewall is disabled by default for testing convenience - **not recommended for production**
- C:\tools is excluded from Windows Defender scanning
- IPv6 is disabled - may affect dual-stack network environments
- Security baseline application is commented out - review before enabling
- Script runs tools downloaded from the internet - verify sources before use

---

## Security Considerations

### General Warnings

- These scripts are designed for **controlled penetration testing environments only**
- **Do not** run these scripts on production systems
- Review all downloaded tools and repositories before use
- Change all default credentials immediately after installation
- Both scripts disable security features for testing convenience (firewall, defender exclusions)
- Ensure systems built with these scripts are isolated from production networks

### Credential Management

- Kali script stores credentials in `/root/pentest-credentials.txt`
- Always use secure password storage (password manager)
- Rotate credentials regularly
- Never commit credential files to version control

### Network Isolation

- Deploy these systems in isolated lab/testing environments
- Use VLANs or separate physical networks
- Implement network monitoring for baseline traffic analysis
- Apply firewall rules appropriate to your testing methodology

---

## Troubleshooting

### Kali Script

**Issue**: SSH key import fails
- **Solution**: Manually download from `https://archive.kali.org/archive-keyring.gpg`

**Issue**: xrdp won't start
- **Solution**: Check `/var/log/xrdp.log` and verify Xfce is installed

**Issue**: Tools fail to install
- **Solution**: Update package lists with `apt update` and retry

### Windows Script

**Issue**: Winget source unreachable
- **Solution**: Run `winget source reset --force` as Administrator

**Issue**: LGPO.exe download fails
- **Solution**: Manually download the Security Compliance Toolkit from Microsoft and place LGPO.exe at:
  `Windows 11 v25H2 Security Baseline\Scripts\Tools\LGPO.exe`

**Issue**: Burp extensions fail to download
- **Solution**: Manually download from PortSwigger BApp Store

---

## Contributing

This is a personal repository. If you've forked this project:
- Test changes in isolated environments
- Document modifications
- Review security implications of any changes

## License

Review and comply with licenses of all installed tools and downloaded software.

## Disclaimer

These scripts are provided as-is for authorized penetration testing and security research only. Users are responsible for ensuring compliance with applicable laws and regulations. Unauthorized use of these tools against systems you do not own or have explicit permission to test is illegal.
