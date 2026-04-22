#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# =========================================
# Kali archive key import (legacy line requested)
# We run this safely in import_kali_key() below. Shown here for clarity:
# wget -O - https://archive.kali.org/archive-keyring.gpg | sudo apt-key add
# =========================================

# =========================================
# Build-result tracking
# =========================================
# BUILD_RESULTS is a flat pipe-delimited array: "Category|Item|Status|Detail"
# add_build_result appends one entry. track_step runs a named function with
# set -e locally disabled, captures the exit code, and records Success/Failed.
# final_summary_and_warnings (below) iterates this array to emit a machine-
# parseable summary compatible with the harness's lib/report.sh parser.
declare -a BUILD_RESULTS=()

add_build_result() {
  # $1=category, $2=item, $3=status (Success|Failed|Skipped), $4=detail
  BUILD_RESULTS+=("$1|$2|$3|$4")
}

track_step() {
  # $1=human description, $2=function name to call, $3=category (default "Step")
  local desc="$1" func="$2" cat="${3:-Step}"
  echo "[*] ${desc}..."
  # Locally disable set -e so a single step failure doesn't abort the script.
  # We want the harness to see every step's result, not just the first failure.
  set +e
  "$func"
  local rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    echo "[OK] ${desc}"
    add_build_result "$cat" "$desc" "Success" ""
  else
    echo "[X] ${desc} failed (exit $rc)"
    add_build_result "$cat" "$desc" "Failed" "exit $rc"
  fi
  # Always return 0 so the caller's set -e doesn't abort — we track failures
  # in BUILD_RESULTS and the script exits non-zero at the end of main().
  return 0
}


# =========================================
# Utility
# =========================================

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Please run as root (sudo)."
    exit 1
  fi
}

github_latest_asset_url() {
  local repo="$1"
  local pattern="$2"
  local api="https://api.github.com/repos/${repo}/releases/latest"

  if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    return 1
  fi

  curl -fsSL "$api" | jq -r '.assets[].browser_download_url' | grep -E -m 1 "$pattern"
}

download_github_asset() {
  local repo="$1"
  local pattern="$2"
  local dest="$3"
  local fallback="$4"
  local url=""

  url="$(github_latest_asset_url "$repo" "$pattern")" || true
  if [ -z "$url" ]; then
    url="$fallback"
    echo "[!] GitHub latest lookup failed for ${repo}; using pinned URL"
  else
    echo "[*] Using latest GitHub release for ${repo}"
  fi

  wget -q -O "$dest" "$url" || true
}

import_kali_key() {
  echo "[*] Importing Kali archive signing key..."
  if command -v apt-key >/dev/null 2>&1; then
    # Your exact requested line (sudo is redundant when running as root)
    wget -qO - https://archive.kali.org/archive-keyring.gpg | apt-key add - >/dev/null 2>&1 || true
  else
    # Fallback for systems without apt-key
    wget -qO /usr/share/keyrings/kali-archive-keyring.gpg https://archive.kali.org/archive-keyring.gpg || true
  fi
}

update_system() {
  echo "[*] Updating and upgrading Kali..."
  apt update -y && apt upgrade -y
}

enable_ssh() {
  echo "[*] Ensuring SSH server is installed and enabled..."
  apt install -y openssh-server
  systemctl enable --now ssh.service
  harden_ssh
}

harden_ssh() {
  echo "[*] Applying SSH hardening (balanced defaults)..."
  install -d /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/10-hardening.conf <<'EOF'
# Balanced, image-friendly SSH defaults
PermitRootLogin prohibit-password
PasswordAuthentication yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
ClientAliveInterval 300
ClientAliveCountMax 2
# Keep RSA for compatibility while preferring ed25519
HostKeyAlgorithms +ssh-ed25519,ssh-rsa
PubkeyAcceptedKeyTypes +ssh-ed25519,ssh-rsa
EOF
  systemctl reload ssh || systemctl restart ssh
}

enable_rdp() {
  echo "[*] Installing and configuring xrdp for RDP access..."
  apt install -y xrdp xorgxrdp || {
    echo "[!] Failed to install xrdp packages"
    return 1
  }

  # Configure xrdp to use Xfce if available (Kali default desktop)
  if [ -f /etc/xrdp/startwm.sh ] && command -v startxfce4 >/dev/null 2>&1; then
    echo "[*] Configuring xrdp for Xfce desktop..."
    cp /etc/xrdp/startwm.sh /etc/xrdp/startwm.sh.bak
    cat >/etc/xrdp/startwm.sh <<'EOF'
#!/bin/sh
# xrdp session startup script
if [ -r /etc/default/locale ]; then
  . /etc/default/locale
  export LANG LANGUAGE
fi

# Start Xfce session
startxfce4
EOF
    chmod +x /etc/xrdp/startwm.sh
  fi

  # Add xrdp user to ssl-cert group for certificate access
  usermod -aG ssl-cert xrdp 2>/dev/null || true

  # Fix xrdp port binding - Kali defaults to vsock which doesn't bind to network
  if grep -q "^port=vsock://" /etc/xrdp/xrdp.ini 2>/dev/null; then
    echo "[*] Fixing xrdp port configuration for TCP access..."
    sed -i 's|^port=vsock://-1:3389|port=3389|' /etc/xrdp/xrdp.ini
  fi

  # Enable and start xrdp service (both xrdp and xrdp-sesman are required
  # for a working RDP session; xrdp alone just accepts the TCP connection).
  systemctl enable xrdp xrdp-sesman
  systemctl restart xrdp-sesman
  systemctl restart xrdp

  # Give the service a moment to bind before we probe it.
  sleep 2

  # Runtime verification: the step must fail loudly if xrdp is not active
  # or not listening on TCP 3389. Without this, a broken service could
  # silently ship and only be discovered when someone tries to connect.
  local rdp_ok=1

  if ! systemctl is-active --quiet xrdp; then
    echo "[X] xrdp.service is not active after restart"
    systemctl status xrdp --no-pager | sed 's/^/    /' || true
    rdp_ok=0
  fi

  if ! systemctl is-active --quiet xrdp-sesman; then
    echo "[X] xrdp-sesman.service is not active after restart"
    systemctl status xrdp-sesman --no-pager | sed 's/^/    /' || true
    rdp_ok=0
  fi

  # Port listen check via ss (preferred) with netstat fallback.
  local listening=""
  if command -v ss >/dev/null 2>&1; then
    listening="$(ss -H -ltn 'sport = :3389' 2>/dev/null || true)"
  elif command -v netstat >/dev/null 2>&1; then
    listening="$(netstat -ltn 2>/dev/null | awk '$4 ~ /:3389$/ {print}')"
  fi

  if [[ -z "$listening" ]]; then
    echo "[X] Nothing is listening on TCP 3389"
    rdp_ok=0
  else
    echo "[*] xrdp is listening on TCP 3389: $(echo "$listening" | head -1 | tr -s ' ')"
  fi

  if (( rdp_ok == 0 )); then
    echo "[X] RDP verification failed — xrdp is not reachable on port 3389"
    return 1
  fi

  echo "[OK] RDP verified: xrdp + xrdp-sesman active, listening on TCP 3389"
}

normalise_paths() {
  echo "[*] Normalising PATH for pipx and local binaries..."
  cat >/etc/profile.d/pentest-paths.sh <<'EOF'
export PATH="$PATH:/root/.local/bin:/usr/local/bin"
EOF
  export PATH="$PATH:/root/.local/bin:/usr/local/bin"
}

# =========================================
# User provisioning
# =========================================

# =========================================
# Burp Suite Professional configuration
# =========================================
BURP_PRO_VERSION="2025.12.5"
BURP_PRO_INSTALL_DIR="/opt/BurpSuitePro"
SKIP_BURP_PRO=""

PENTEST_USER="pentest"
PENTEST_PASS=""

create_pentest_user() {
  echo "[*] Creating '${PENTEST_USER}' user and adding to sudo..."
  if ! id -u "${PENTEST_USER}" >/dev/null 2>&1; then
    useradd -m -s /bin/bash -G sudo "${PENTEST_USER}"
  else
    usermod -aG sudo "${PENTEST_USER}"
  fi

  if command -v openssl >/dev/null 2>&1; then
    PENTEST_PASS="$(openssl rand -base64 24)"
  else
    PENTEST_PASS="$(tr -dc 'A-Za-z0-9!@#$%^&*()_+-=' </dev/urandom | head -c 24)"
  fi

  echo "${PENTEST_USER}:${PENTEST_PASS}" | chpasswd

  umask 077
  cat >/root/pentest-credentials.txt <<EOF
Username: ${PENTEST_USER}
Password: ${PENTEST_PASS}
Created:  $(date -Is)
EOF
  chmod 600 /root/pentest-credentials.txt
  echo "[*] Credentials saved to /root/pentest-credentials.txt (root-only)."
}

# =========================================
# Packages (apt, pipx, pip)
# =========================================

install_base_tools() {
  echo "[*] Installing core packages..."
  apt install -y \
    curl wget ca-certificates git jq build-essential \
    macchanger python3 python3-pip python3-venv python3-impacket \
    netcat-traditional sqlmap gobuster iputils-ping dirb nano nikto \
    net-tools metasploit-framework tcpdump smbclient \
    enum4linux snapd prips rdesktop dnsrecon \
    sqlitebrowser responder yersinia postgresql \
    sshpass powershell seclists ligolo-ng nuclei || true

  echo "[*] Installing optional packages (some may fail due to dependencies)..."
  # These packages have known dependency issues on some Kali versions
  # Install individually to prevent one failure from blocking others
  for pkg in default-jdk tilix novnc default-mysql-client auditd audispd-plugins \
             libpcap-dev filezilla winetricks wireguard awscli lldpd; do
    apt install -y "$pkg" 2>/dev/null || echo "[!] Optional package $pkg failed to install (may have dependency conflicts)"
  done

  # Start services only if they exist
  if systemctl list-unit-files | grep -q lldpd; then
    systemctl start lldpd || true
  fi
  systemctl enable --now postgresql || true
}

install_pipx_and_tools() {
  echo "[*] Installing pipx and CLI tools via pipx..."
  apt install -y pipx
  pipx ensurepath || true

  pipx install certipy-ad || true
  pipx install sublist3r || true
  pipx install dirsearch || true
  pipx install spray || true
  pipx install --include-deps eyewitness || true
  pipx install mitm6 || true
  pipx install hashid || true

  pip3 install --break-system-packages \
    pyftpdlib Cython pysmb || true
}

# =========================================
# Repo tree & clones
# =========================================

prepare_opt_tree() {
  echo "[*] Preparing /opt tree..."
  mkdir -p /opt/{sysinternals,privesc/{linux,windows},buildreview,password,network,persistence/windows,adtools,bof,filehosting,ics,packetcapture,icspasswords,sharphound,hoaxshell,invoke-obfuscation,graphrunner}
  chown -R root:root /opt
}

_clone() { git clone --depth 1 "$1" "$2" 2>/dev/null || true; }

clone_repos() {
  echo "[*] Cloning Git repos..."
  _clone https://github.com/rebootuser/LinEnum.git                /opt/privesc/linux/linenum
  _clone https://github.com/carlospolop/PEASS-ng.git              /opt/privesc/linux/peass-ng
  _clone https://github.com/bitsadmin/wesng.git                   /opt/privesc/windows/exploit-suggester
  _clone https://github.com/antonioCoco/RemotePotato0.git         /opt/privesc/windows/remotepotato
  _clone https://github.com/ohpe/juicy-potato.git                 /opt/privesc/juicypotato
  _clone https://github.com/itm4n/PrintSpoofer.git                /opt/privesc/printspoofer
  _clone https://github.com/TheWover/donut.git                    /opt/privesc/donut
  _clone https://github.com/decoder-it/psgetsystem.git            /opt/privesc/psgetsystem
  _clone https://github.com/danielbohannon/Invoke-Obfuscation.git /opt/invoke-obfuscation
  _clone https://github.com/BeichenDream/GodPotato.git            /opt/privesc/godpotato

  _clone https://github.com/GhostPack/KeeThief.git                /opt/password/keethief
  _clone https://github.com/gentilkiwi/kekeo.git                  /opt/password/kekeo
  _clone https://github.com/leoloobeek/LAPSToolkit.git            /opt/password/lapstoolkit
  _clone https://github.com/dirkjanm/krbrelayx.git                /opt/adtools/krbrelayx
  _clone https://github.com/ropnop/kerbrute.git                   /opt/adtools/kerbrute

  _clone https://github.com/p0dalirius/Coercer.git                /opt/network/coercer

  _clone https://github.com/ITI/ICS-Security-Tools.git            /opt/ics/resources
  _clone https://github.com/BloodHoundAD/SharpHound.git           /opt/sharphound
  _clone https://github.com/t3l3machus/hoaxshell.git              /opt/hoaxshell
  _clone https://github.com/dafthack/GraphRunner.git              /opt/graphrunner

  find /opt -type d -name ".git" -prune -exec rm -rf {} + || true
}

download_binaries() {
  echo "[*] Downloading additional binaries..."
  mkdir -p /opt/sysinternals /opt/icspasswords /opt/network /opt/adtools
  wget -q -O /opt/sysinternals/Procdump.zip \
    https://download.sysinternals.com/files/Procdump.zip || true
  wget -q -O /opt/icspasswords/scada.csv \
    https://raw.githubusercontent.com/ITI/ICS-Security-Tools/f829a32f98fadfa5206d3a41fc3612dd4741c8b3/configurations/passwords/scadapass.csv || true
  download_github_asset \
    "ropnop/kerbrute" \
    "kerbrute_linux_amd64$" \
    "/opt/network/kerbrute-linux-64" \
    "https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64"
  chmod +x /opt/network/kerbrute-linux-64 || true
  download_github_asset \
    "ropnop/go-windapsearch" \
    "windapsearch-linux-amd64$" \
    "/opt/adtools/windapsearch" \
    "https://github.com/ropnop/go-windapsearch/releases/download/v0.3.0/windapsearch-linux-amd64"
  chmod +x /opt/adtools/windapsearch || true
  download_github_asset \
    "sensepost/ruler" \
    "ruler-linux64$" \
    "/opt/ruler-linux64" \
    "https://github.com/sensepost/ruler/releases/download/2.4.1/ruler-linux64"
  chmod +x /opt/ruler-linux64 || true
  download_github_asset \
    "netwrix/pingcastle" \
    "PingCastle_.*\\.zip$" \
    "/opt/pingcastle.zip" \
    "https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip"

  # Download chisel directly from official GitHub releases (secure alternative to curl|bash)
  echo "[*] Downloading chisel from official GitHub releases..."
  download_github_asset \
    "jpillora/chisel" \
    "chisel_.*_linux_amd64\\.gz$" \
    "/tmp/chisel.gz" \
    "https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz"
  if [ -f /tmp/chisel.gz ]; then
    gunzip -f /tmp/chisel.gz 2>/dev/null || true
    if [ -f /tmp/chisel ]; then
      mv /tmp/chisel /usr/local/bin/chisel
      chmod +x /usr/local/bin/chisel
      echo "[*] Chisel installed to /usr/local/bin/chisel"
    fi
  fi
}

install_burpsuite_pro() {
  if [[ -n "$SKIP_BURP_PRO" ]]; then
    echo "[*] Skipping Burp Suite Professional install (--skip-burp-pro)"
    return 0
  fi

  echo "[*] Installing Burp Suite Professional ${BURP_PRO_VERSION}..."

  # Check if already installed
  if [[ -x "${BURP_PRO_INSTALL_DIR}/BurpSuitePro" ]]; then
    echo "[*] Burp Suite Professional already installed at ${BURP_PRO_INSTALL_DIR}"
    return 0
  fi

  # Detect architecture
  local arch
  arch="$(uname -m)"
  local download_type=""
  case "$arch" in
    x86_64)  download_type="Linux" ;;
    aarch64) download_type="LinuxArm64" ;;
    *)
      echo "[!] Unsupported architecture for Burp Suite Pro: ${arch}"
      return 1
      ;;
  esac

  local installer="/tmp/burpsuite_pro_installer.sh"
  local varfile="/tmp/burp_response.varfile"
  local download_url="https://portswigger.net/burp/releases/startdownload?product=pro&version=${BURP_PRO_VERSION}&type=${download_type}"

  # Download installer
  echo "[*] Downloading Burp Suite Professional installer (${download_type})..."
  wget -q --show-progress -O "$installer" "$download_url" || {
    echo "[!] Failed to download Burp Suite Professional installer"
    rm -f "$installer"
    return 1
  }

  # Verify we got an actual installer (should be >50MB, not an error page)
  local file_size
  file_size="$(stat -c%s "$installer" 2>/dev/null || stat -f%z "$installer" 2>/dev/null || echo 0)"
  if [[ "$file_size" -lt 52428800 ]]; then
    echo "[!] Downloaded file too small (${file_size} bytes) — expected >50MB installer"
    rm -f "$installer"
    return 1
  fi

  chmod +x "$installer"

  # Create install4j response varfile for silent installation
  cat > "$varfile" <<EOF
sys.adminRights\$Boolean=true
sys.installationDir=${BURP_PRO_INSTALL_DIR}
sys.languageId=en
EOF

  # Run silent installer
  echo "[*] Running Burp Suite Professional silent installer..."
  "$installer" -q -varfile "$varfile" || {
    echo "[!] Burp Suite Professional installer failed"
    rm -f "$installer" "$varfile"
    return 1
  }

  # Clean up temp files
  rm -f "$installer" "$varfile"

  # Verify installation
  if [[ -x "${BURP_PRO_INSTALL_DIR}/BurpSuitePro" ]]; then
    echo "[*] Burp Suite Professional installed successfully to ${BURP_PRO_INSTALL_DIR}"
    # Create symlink for PATH access
    ln -sf "${BURP_PRO_INSTALL_DIR}/BurpSuitePro" /usr/local/bin/burpsuite-pro
    echo "[*] Symlink created: /usr/local/bin/burpsuite-pro"
  else
    echo "[!] Burp Suite Professional binary not found after installation"
    return 1
  fi
}

update_nuclei_templates() {
  echo "[*] Updating Nuclei templates..."
  if command -v nuclei >/dev/null 2>&1; then
    nuclei -update-templates || echo "[!] Failed to update Nuclei templates"
  else
    echo "[!] Nuclei is not installed or not in PATH"
  fi
}

# =========================================
# Hardening (Fail2ban etc.)
# =========================================

harden_kali() {
  echo "[*] Base hardening..."
  apt install -y unattended-upgrades fail2ban
  dpkg-reconfigure -fnoninteractive unattended-upgrades || true

  local services_to_disable=(
    bluetooth.service avahi-daemon.service cups.service isc-dhcp-server.service
    isc-dhcp-server6.service slapd.service nfs-server.service bind9.service
    vsftpd.service dovecot.service smbd.service squid.service snmpd.service
  )
  for svc in "${services_to_disable[@]}"; do
    systemctl disable --now "$svc" 2>/dev/null || true
  done

  systemctl enable --now fail2ban
  install -d /etc/fail2ban/jail.d
  cat >/etc/fail2ban/jail.d/ssh.local <<'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 10m
bantime.increment = true
EOF
  systemctl restart fail2ban
}

rotate_ssh_keys() {
  echo "[*] Rotating default SSH host keys..."
  mkdir -p /etc/ssh/old_keys
  mv /etc/ssh/ssh_host_* /etc/ssh/old_keys/ 2>/dev/null || true
  dpkg-reconfigure openssh-server
}

cleanup_and_info() {
  echo "[*] Cleaning up apt caches..."
  apt autoremove -y || true
  apt clean || true
  apt autoclean -y || true

  echo "[*] System info:"
  echo "═══════════════════════════════════════════"
  echo "Hostname: $(hostname)"
  echo "Kernel: $(uname -r)"
  echo "Architecture: $(uname -m)"
  echo "OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
  echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
  echo "Memory: $(free -h | awk '/^Mem:/ {print $3 " / " $2}')"
  echo "Disk: $(df -h / | awk 'NR==2 {print $3 " / " $2 " (" $5 " used)"}')"
  echo "═══════════════════════════════════════════"
}

final_summary_and_warnings() {
  echo
  echo "========================================"
  echo "           BUILD SUMMARY"
  echo "========================================"
  echo "Timestamp : $(date '+%Y-%m-%d %H:%M:%S')"
  echo "Hostname  : $(hostname)"
  echo "========================================"

  # Group BUILD_RESULTS by category while preserving insertion order within
  # each category. We iterate twice: first to collect unique categories in
  # order, then to emit the entries for each category.
  local -a categories=()
  local entry cat
  for entry in "${BUILD_RESULTS[@]:-}"; do
    [[ -z "$entry" ]] && continue
    cat="${entry%%|*}"
    local already=0
    local c
    for c in "${categories[@]:-}"; do
      if [[ "$c" == "$cat" ]]; then already=1; break; fi
    done
    if (( ! already )); then categories+=("$cat"); fi
  done

  local success=0 failed=0 skipped=0 total=0
  for cat in "${categories[@]:-}"; do
    [[ -z "$cat" ]] && continue
    echo
    echo "--- ${cat} ---"
    for entry in "${BUILD_RESULTS[@]:-}"; do
      [[ -z "$entry" ]] && continue
      local e_cat="${entry%%|*}"
      if [[ "$e_cat" != "$cat" ]]; then continue; fi
      # Split the remainder on '|'
      local rest="${entry#*|}"
      local item="${rest%%|*}"
      rest="${rest#*|}"
      local status="${rest%%|*}"
      local detail="${rest#*|}"
      local line="  [${status}] ${item}"
      if [[ -n "$detail" ]]; then line+=" - ${detail}"; fi
      echo "$line"
      # Use $(( x + 1 )) instead of (( x++ )) because post-increment
      # evaluates to the OLD value. When x=0, (( x++ )) returns 0 which
      # is falsy in bash arithmetic — and set -e would kill the script.
      case "$status" in
        Success) success=$(( success + 1 )) ;;
        Failed)  failed=$(( failed + 1 ))   ;;
        Skipped) skipped=$(( skipped + 1 )) ;;
      esac
      total=$(( total + 1 ))
    done
  done

  echo
  echo "========================================"
  echo "  ${success} succeeded, ${failed} failed, ${skipped} skipped (of ${total} total)"
  echo "========================================"
  echo

  # Preserve the original human-readable warnings block so direct users of
  # this script (without the harness) still see the reminders.
  echo "Pentest user: ${PENTEST_USER}"
  echo "Pentest credentials saved to: /root/pentest-credentials.txt (permissions 600)"
  echo "SSH: enabled and hardened (port 22)"
  echo "RDP: enabled via xrdp (port 3389)"
  echo
  echo "[!!!] IMPORTANT: Ensure the ROOT PASSWORD has been changed from any defaults."
  echo "      Run:  passwd root"
  echo "      (Never use default creds like root/root or root/kali.)"
  echo
  echo "[!!!] SECURITY: View pentest credentials with:  cat /root/pentest-credentials.txt"
  echo

  # Expose the failure count so main() can decide the exit code.
  BUILD_FAILURE_COUNT=$failed
}

# =========================================
# Install type meta
# =========================================

full_install() {
  track_step "Update system"                     update_system            "System"
  track_step "Harden Kali (fail2ban etc.)"       harden_kali              "Hardening"
  track_step "Install base tools"                install_base_tools       "Packages"
  track_step "Install pipx and Python tools"     install_pipx_and_tools   "Packages"
  track_step "Normalise PATH"                    normalise_paths          "System"
  track_step "Prepare /opt tree"                 prepare_opt_tree         "Filesystem"
  track_step "Clone git repos"                   clone_repos              "Repos"
  track_step "Download pentest binaries"         download_binaries        "Downloads"
  track_step "Install Burp Suite Professional"   install_burpsuite_pro    "Packages"
  track_step "Update Nuclei templates"           update_nuclei_templates  "Tools"
  track_step "Rotate SSH host keys"              rotate_ssh_keys          "Hardening"
  track_step "Enable and harden SSH"             enable_ssh               "Services"
  track_step "Enable RDP (xrdp)"                 enable_rdp               "Services"
  track_step "Cleanup apt caches and info"       cleanup_and_info         "System"
}

# =========================================
# CLI flags
# =========================================
#
# The script is non-interactive: it always runs the full build. The only
# flags accepted are --skip-burp-pro (skip the Burp Suite Pro download) and
# --full / --help. --full is a backwards-compatible no-op retained so
# existing automation (including the Parallels test harness, which passes
# KALI_INSTALL_MODE=--full) keeps working without modification.

usage() {
  cat <<EOF
Usage: $0 [--full] [--skip-burp-pro]
Runs the full Kali build non-interactively: hardening, tools, repos,
Nuclei, PostgreSQL, SSH, RDP, and cleanup.
  --full           Backwards-compatible no-op (full is the only mode).
  --skip-burp-pro  Skip Burp Suite Professional download and installation.
  -h, --help       Show this help and exit.
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --full) shift ;;                       # accepted for back-compat, no-op
      --skip-burp-pro) SKIP_BURP_PRO=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
  done
}

main() {
  require_root
  parse_args "$@"

  # Initialise the failure counter so it's always defined.
  BUILD_FAILURE_COUNT=0

  track_step "Import Kali archive signing key"  import_kali_key       "Setup"
  track_step "Create pentest user"               create_pentest_user   "Setup"

  full_install
  final_summary_and_warnings
  echo "[+] Full install complete."

  # Exit non-zero if any tracked step failed, so CI / the test harness can
  # detect failures via the process exit code in addition to parsing the
  # BUILD SUMMARY markers.
  if (( BUILD_FAILURE_COUNT > 0 )); then
    echo "[!] Build completed with ${BUILD_FAILURE_COUNT} failed step(s)."
    exit 1
  fi
  exit 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
