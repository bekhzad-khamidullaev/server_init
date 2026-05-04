#!/usr/bin/env bash
# Ubuntu production init + hardening wizard (TUI)

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

export DEBIAN_FRONTEND=noninteractive

VERSION="3.0.0"
LOG_FILE="/var/log/ubuntu_server_init.log"
TMP_DIR="$(mktemp -d /tmp/ubuntu-server-init.XXXXXX)"
BACKUP_DIR="/var/backups/ubuntu_server_init_$(date +%Y%m%d_%H%M%S)"

OS_ID=""
OS_VERSION_ID=""
OS_CODENAME=""
OS_PRETTY_NAME=""
SSH_SERVICE=""
SSH_UNIT=""
CURRENT_TIMEZONE=""
CURRENT_SSH_PORT="22"
SFTP_SERVER_PATH="/usr/lib/openssh/sftp-server"
VIRT_TYPE=""
RAM_GB=0
HAS_SWAP=0

TIMEZONE="${TIMEZONE:-}"
SSH_PORT="${SSH_PORT:-}"
ADMIN_USER="${ADMIN_USER:-}"
ADMIN_PUBKEY="${ADMIN_PUBKEY:-}"
PRIMARY_USER="${PRIMARY_USER:-}"
ROOT_SSH_KEY="${ROOT_SSH_KEY:-}"
ALLOW_HTTP="${ALLOW_HTTP:-1}"
ALLOW_HTTPS="${ALLOW_HTTPS:-1}"
DISABLE_PASSWORD_AUTH="${DISABLE_PASSWORD_AUTH:-1}"
DISABLE_ROOT_SSH="${DISABLE_ROOT_SSH:-1}"
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-1}"
ENABLE_UNATTENDED="${ENABLE_UNATTENDED:-1}"
DISABLE_IPV6="${DISABLE_IPV6:-0}"
INSTALL_QEMU_AGENT="${INSTALL_QEMU_AGENT:-0}"
INSTALL_FISH="${INSTALL_FISH:-1}"
ENABLE_ROOT_KEY_LOGIN="${ENABLE_ROOT_KEY_LOGIN:-0}"
AUTO_SWAP="${AUTO_SWAP:-0}"
REBOOT_AFTER="${REBOOT_AFTER:-0}"
EXTRA_TCP_PORTS="${EXTRA_TCP_PORTS:-}"
EXTRA_UDP_PORTS="${EXTRA_UDP_PORTS:-}"
SERVER_ROLE="${SERVER_ROLE:-general}"
NONINTERACTIVE="${NONINTERACTIVE:-0}"

cleanup() {
  rm -rf "$TMP_DIR"
}

backup_file() {
  local source="$1"
  [[ -f "$source" ]] || return 0
  mkdir -p "$BACKUP_DIR"
  cp -a "$source" "${BACKUP_DIR}/$(basename "$source")"
}

reload_or_restart_service() {
  local service="$1"
  if ! systemctl reload "$service" >>"$LOG_FILE" 2>&1; then
    run_quiet systemctl restart "$service"
  fi
}

fail() {
  local message="$1"
  printf '[ERROR] %s\n' "$message" >&2
  printf '[ERROR] %s\n' "$message" >>"$LOG_FILE"
  if command -v dialog >/dev/null 2>&1; then
    dialog --title "Error" --msgbox "$message\n\nLog: $LOG_FILE" 10 80 || true
  fi
  cleanup
  exit 1
}

trap 'fail "Line ${LINENO}: command failed. See ${LOG_FILE}."' ERR
trap cleanup EXIT

log() {
  printf '[INFO] %s\n' "$*" | tee -a "$LOG_FILE" >/dev/null
}

run_quiet() {
  "$@" >>"$LOG_FILE" 2>&1
}

wait_for_apt_lock() {
  local waited=0
  local max_wait="${1:-300}"

  while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
    if (( waited >= max_wait )); then
      fail "Timed out waiting for apt/dpkg lock."
    fi
    log "Waiting for apt/dpkg lock to be released..."
    sleep 5
    ((waited+=5))
  done
}

ui_msg() {
  dialog --title "${2:-Ubuntu Server Init}" --msgbox "$1" 14 84
}

ui_yesno() {
  dialog --title "${2:-Ubuntu Server Init}" --yes-label "${3:-Yes}" --no-label "${4:-No}" --yesno "$1" 14 84
}

ui_input() {
  local outfile="$TMP_DIR/input.$$"
  dialog --title "${3:-Ubuntu Server Init}" --inputbox "$1" 14 84 "$2" 2>"$outfile"
  cat "$outfile"
}

parse_env_bool() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

normalize_bool() {
  if parse_env_bool "${1:-0}"; then
    printf '1'
  else
    printf '0'
  fi
}

require_root() {
  [[ $(id -u) -eq 0 ]] || fail "Run this script as root or via sudo."
}

require_ubuntu() {
  [[ -r /etc/os-release ]] || fail "Cannot read /etc/os-release."
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_VERSION_ID="${VERSION_ID:-}"
  OS_CODENAME="${VERSION_CODENAME:-}"
  OS_PRETTY_NAME="${PRETTY_NAME:-Ubuntu}"
  [[ "$OS_ID" == "ubuntu" ]] || fail "This script supports Ubuntu only. Detected: ${OS_ID:-unknown}."
}

ensure_dialog() {
  if parse_env_bool "$NONINTERACTIVE"; then
    return 0
  fi
  if command -v dialog >/dev/null 2>&1; then
    return 0
  fi
  printf '[INFO] Installing dialog...\n'
  apt-get update -y >>"$LOG_FILE" 2>&1
  apt-get install -y dialog >>"$LOG_FILE" 2>&1
}

detect_ssh_service() {
  if systemctl list-unit-files --type=service --no-legend 'ssh.service' 2>/dev/null | grep -q '^ssh\.service'; then
    SSH_SERVICE="ssh"
  elif systemctl list-unit-files --type=service --no-legend 'sshd.service' 2>/dev/null | grep -q '^sshd\.service'; then
    SSH_SERVICE="sshd"
  elif systemctl status ssh >/dev/null 2>&1; then
    SSH_SERVICE="ssh"
  else
    SSH_SERVICE="sshd"
  fi
  SSH_UNIT="${SSH_SERVICE}.service"
}

detect_sftp_server_path() {
  local candidate
  if dpkg -L openssh-sftp-server >/dev/null 2>&1; then
    candidate="$(dpkg -L openssh-sftp-server | awk '/\/sftp-server$/ {print; exit}')"
    if [[ -n "$candidate" ]]; then
      SFTP_SERVER_PATH="$candidate"
    fi
  fi
}

detect_current_ssh_port() {
  if command -v sshd >/dev/null 2>&1; then
    while read -r key value _; do
      if [[ "$key" == "port" && -n "$value" ]]; then
        CURRENT_SSH_PORT="$value"
        break
      fi
    done < <(sshd -T 2>/dev/null)
  fi
  CURRENT_SSH_PORT="${CURRENT_SSH_PORT:-22}"
}

detect_environment() {
  detect_ssh_service
  detect_sftp_server_path
  detect_current_ssh_port
  CURRENT_TIMEZONE="$(timedatectl show --property=Timezone --value 2>/dev/null || echo UTC)"
  VIRT_TYPE="$(systemd-detect-virt 2>/dev/null || true)"
  RAM_GB="$(awk '/MemTotal/ {printf "%d", ($2 / 1024 / 1024) + 0.5}' /proc/meminfo)"
  swapon --noheadings --raw 2>/dev/null | grep -q . && HAS_SWAP=1 || HAS_SWAP=0
  [[ "$VIRT_TYPE" == "qemu" || "$VIRT_TYPE" == "kvm" ]] && INSTALL_QEMU_AGENT=1
  if (( RAM_GB < 4 )) && (( HAS_SWAP == 0 )); then
    AUTO_SWAP=1
  fi
}

show_intro() {
  if parse_env_bool "$NONINTERACTIVE"; then
    log "Running in noninteractive mode on ${OS_PRETTY_NAME}, role=${SERVER_ROLE}, ssh_service=${SSH_SERVICE}."
    return 0
  fi
  ui_msg "Version: ${VERSION}

Detected system:
- OS: ${OS_PRETTY_NAME}
- Ubuntu version: ${OS_VERSION_ID}
- SSH service: ${SSH_SERVICE}
- Current SSH port: ${CURRENT_SSH_PORT}
- Timezone: ${CURRENT_TIMEZONE}
- Virtualization: ${VIRT_TYPE:-bare-metal}
- RAM: ${RAM_GB} GB

The wizard will build a production-oriented baseline:
- version-aware SSH handling (${SSH_SERVICE} vs sshd)
- firewall, fail2ban, unattended upgrades
- journald, limits, sysctl, BBR when available
- safe SSH hardening with lockout checks
- optional admin user and swap provisioning" "Detected Environment"
}

collect_role() {
  if parse_env_bool "$NONINTERACTIVE"; then
    SERVER_ROLE="${SERVER_ROLE:-general}"
    return 0
  fi
  local outfile="$TMP_DIR/role"
  dialog --stdout --title "Server Role" --menu \
    "Select the tuning profile. You can still override ports and security options later." \
    18 90 8 \
    "general" "Balanced profile for most production servers" \
    "web" "Aggressive network tuning for web/reverse-proxy workloads" \
    "database" "Conservative network tuning, lower swappiness, DB-friendly defaults" \
    "container" "Host tuned for Docker/container workloads" >"$outfile"
  SERVER_ROLE="$(cat "$outfile")"
}

collect_main_settings() {
  if parse_env_bool "$NONINTERACTIVE"; then
    TIMEZONE="${TIMEZONE:-$CURRENT_TIMEZONE}"
    SSH_PORT="${SSH_PORT:-$CURRENT_SSH_PORT}"
    EXTRA_TCP_PORTS="${EXTRA_TCP_PORTS:-}"
    EXTRA_UDP_PORTS="${EXTRA_UDP_PORTS:-}"
  else
  TIMEZONE="$(ui_input "Enter timezone" "$CURRENT_TIMEZONE" "Timezone")"
  TIMEZONE="${TIMEZONE:-$CURRENT_TIMEZONE}"

  SSH_PORT="$(ui_input "Enter SSH port" "$CURRENT_SSH_PORT" "SSH Port")"
  fi
  [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || fail "SSH port must be numeric."
  (( SSH_PORT >= 1 && SSH_PORT <= 65535 )) || fail "SSH port must be between 1 and 65535."

  if ! parse_env_bool "$NONINTERACTIVE"; then
    ADMIN_USER="$(ui_input "Enter sudo admin username.\nLeave empty to skip user creation." "${ADMIN_USER:-}" "Admin User")"
  fi
  if [[ -n "$ADMIN_USER" ]] && ! [[ "$ADMIN_USER" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
    fail "Admin username '${ADMIN_USER}' is not valid."
  fi

  if [[ -n "$ADMIN_USER" ]] && ! parse_env_bool "$NONINTERACTIVE"; then
    ADMIN_PUBKEY="$(ui_input "Paste a public SSH key for ${ADMIN_USER}.\nLeave empty to reuse /root/.ssh/authorized_keys if available." "" "Admin SSH Key")"
  fi

  if ! parse_env_bool "$NONINTERACTIVE"; then
    EXTRA_TCP_PORTS="$(ui_input "Extra TCP ports to open in UFW.\nUse comma-separated values, e.g. 8080,8443,5432" "$EXTRA_TCP_PORTS" "Extra Ports")"
    EXTRA_UDP_PORTS="$(ui_input "Extra UDP ports/ranges to open in UFW.\nUse comma-separated values, e.g. 3478,5349,10000:20000" "$EXTRA_UDP_PORTS" "Extra UDP Ports")"
  fi
}

collect_flags() {
  if parse_env_bool "$NONINTERACTIVE"; then
    ALLOW_HTTP="$(normalize_bool "${ALLOW_HTTP:-1}")"
    ALLOW_HTTPS="$(normalize_bool "${ALLOW_HTTPS:-1}")"
    DISABLE_PASSWORD_AUTH="$(normalize_bool "${DISABLE_PASSWORD_AUTH:-1}")"
    DISABLE_ROOT_SSH="$(normalize_bool "${DISABLE_ROOT_SSH:-1}")"
    ENABLE_FAIL2BAN="$(normalize_bool "${ENABLE_FAIL2BAN:-1}")"
    ENABLE_UNATTENDED="$(normalize_bool "${ENABLE_UNATTENDED:-1}")"
    DISABLE_IPV6="$(normalize_bool "${DISABLE_IPV6:-0}")"
    INSTALL_QEMU_AGENT="$(normalize_bool "${INSTALL_QEMU_AGENT:-0}")"
    AUTO_SWAP="$(normalize_bool "${AUTO_SWAP:-0}")"
    REBOOT_AFTER="$(normalize_bool "${REBOOT_AFTER:-0}")"
    return 0
  fi
  local outfile="$TMP_DIR/flags"
  dialog --stdout --separate-output --checklist \
    "Select production options." \
    22 96 14 \
    "allow_http" "Open TCP/80 in UFW" on \
    "allow_https" "Open TCP/443 in UFW" on \
    "disable_password_auth" "Disable SSH password authentication when keys exist" on \
    "disable_root_ssh" "Disable root SSH login when admin key is available" on \
    "enable_fail2ban" "Install and configure fail2ban" on \
    "enable_unattended" "Enable unattended security updates" on \
    "disable_ipv6" "Disable IPv6 via sysctl" off \
    "install_qemu_agent" "Enable qemu-guest-agent when suitable" "$([[ $INSTALL_QEMU_AGENT -eq 1 ]] && echo on || echo off)" \
    "auto_swap" "Auto-create swap if host RAM is low and swap is missing" "$([[ $AUTO_SWAP -eq 1 ]] && echo on || echo off)" \
    "reboot_after" "Reboot automatically at the end if changes require it" off >"$outfile"

  ALLOW_HTTP=0
  ALLOW_HTTPS=0
  DISABLE_PASSWORD_AUTH=0
  DISABLE_ROOT_SSH=0
  ENABLE_FAIL2BAN=0
  ENABLE_UNATTENDED=0
  DISABLE_IPV6=0
  INSTALL_QEMU_AGENT=0
  AUTO_SWAP=0
  REBOOT_AFTER=0

  while read -r flag; do
    case "$flag" in
      allow_http) ALLOW_HTTP=1 ;;
      allow_https) ALLOW_HTTPS=1 ;;
      disable_password_auth) DISABLE_PASSWORD_AUTH=1 ;;
      disable_root_ssh) DISABLE_ROOT_SSH=1 ;;
      enable_fail2ban) ENABLE_FAIL2BAN=1 ;;
      enable_unattended) ENABLE_UNATTENDED=1 ;;
      disable_ipv6) DISABLE_IPV6=1 ;;
      install_qemu_agent) INSTALL_QEMU_AGENT=1 ;;
      auto_swap) AUTO_SWAP=1 ;;
      reboot_after) REBOOT_AFTER=1 ;;
    esac
  done <"$outfile"
}

show_plan() {
  if parse_env_bool "$NONINTERACTIVE"; then
    log "Plan: role=${SERVER_ROLE}, timezone=${TIMEZONE}, ssh_port=${SSH_PORT}, admin_user=${ADMIN_USER:-skip}, backup_dir=${BACKUP_DIR}"
    return 0
  fi
  ui_msg "Selected configuration:

- Role: ${SERVER_ROLE}
- Timezone: ${TIMEZONE}
- SSH service: ${SSH_SERVICE}
- SSH port: ${SSH_PORT}
- Admin user: ${ADMIN_USER:-skip}
- HTTP: $( [[ $ALLOW_HTTP -eq 1 ]] && echo enabled || echo disabled )
- HTTPS: $( [[ $ALLOW_HTTPS -eq 1 ]] && echo enabled || echo disabled )
- Disable password auth: $( [[ $DISABLE_PASSWORD_AUTH -eq 1 ]] && echo yes || echo no )
- Disable root SSH: $( [[ $DISABLE_ROOT_SSH -eq 1 ]] && echo yes || echo no )
- Fail2ban: $( [[ $ENABLE_FAIL2BAN -eq 1 ]] && echo enabled || echo disabled )
- Unattended upgrades: $( [[ $ENABLE_UNATTENDED -eq 1 ]] && echo enabled || echo disabled )
- Disable IPv6: $( [[ $DISABLE_IPV6 -eq 1 ]] && echo yes || echo no )
- qemu-guest-agent: $( [[ $INSTALL_QEMU_AGENT -eq 1 ]] && echo enabled || echo skipped )
- Auto swap: $( [[ $AUTO_SWAP -eq 1 ]] && echo enabled || echo disabled )
- Reboot at end: $( [[ $REBOOT_AFTER -eq 1 ]] && echo yes || echo no )
- Extra ports: ${EXTRA_TCP_PORTS:-none}
- Extra UDP ports: ${EXTRA_UDP_PORTS:-none}

Log file: ${LOG_FILE}" "Execution Plan"

  ui_yesno "Proceed with production hardening and tuning?" "Execute Changes" "Start" "Cancel" || exit 0
}

step() {
  if parse_env_bool "$NONINTERACTIVE"; then
    log "$1"
    return 0
  fi
  dialog --title "Applying" --infobox "$1" 8 84
  sleep 0.4
}

apt_upgrade_and_install() {
  step "Updating apt metadata and installing production baseline packages..."
  wait_for_apt_lock

  local packages=(
    ca-certificates
    curl
    wget
    gnupg
    lsb-release
    software-properties-common
    openssh-server
    ufw
    fail2ban
    unattended-upgrades
    apt-listchanges
    needrestart
    vim
    nano
    tmux
    git
    jq
    rsync
    htop
    iotop
    sysstat
    lsof
    ncdu
    ethtool
    net-tools
    chrony
    auditd
    debsums
    fish
  )

  if (( INSTALL_QEMU_AGENT == 1 )); then
    packages+=(qemu-guest-agent)
  fi

  run_quiet apt-get update -y
  run_quiet apt-get dist-upgrade -y
  run_quiet apt-get install -y --no-install-recommends "${packages[@]}"

  detect_ssh_service
  detect_sftp_server_path
}

configure_apt_behavior() {
  step "Configuring apt reliability, cleanup and non-interactive restart policy..."
  backup_file /etc/apt/apt.conf.d/20auto-upgrades

  cat <<'EOF' >/etc/apt/apt.conf.d/80production-tuning
APT::Install-Recommends "0";
APT::Install-Suggests "0";
APT::Acquire::Retries "5";
APT::Acquire::http::Timeout "30";
APT::Acquire::https::Timeout "30";
Dpkg::Use-Pty "0";
EOF

  mkdir -p /etc/needrestart/conf.d
  cat <<'EOF' >/etc/needrestart/conf.d/50-production-auto.conf
$nrconf{restart} = 'a';
EOF
}

configure_timezone() {
  step "Setting timezone and NTP..."
  run_quiet timedatectl set-timezone "$TIMEZONE"
  run_quiet timedatectl set-ntp true
  run_quiet systemctl enable --now chrony
}

ensure_admin_user() {
  [[ -n "$ADMIN_USER" ]] || return 0
  step "Ensuring admin user ${ADMIN_USER} exists and has sudo + SSH access..."

  if ! id "$ADMIN_USER" >/dev/null 2>&1; then
    run_quiet adduser --disabled-password --gecos "" "$ADMIN_USER"
  fi
  run_quiet usermod -aG sudo "$ADMIN_USER"

  local home_dir
  home_dir="$(getent passwd "$ADMIN_USER" | cut -d: -f6)"
  install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$home_dir/.ssh"

  if [[ -n "$ADMIN_PUBKEY" ]]; then
    printf '%s\n' "$ADMIN_PUBKEY" >"$home_dir/.ssh/authorized_keys"
    chown "$ADMIN_USER:$ADMIN_USER" "$home_dir/.ssh/authorized_keys"
    chmod 600 "$home_dir/.ssh/authorized_keys"
  elif [[ -s /root/.ssh/authorized_keys ]]; then
    install -m 600 -o "$ADMIN_USER" -g "$ADMIN_USER" /root/.ssh/authorized_keys "$home_dir/.ssh/authorized_keys"
  fi
}

ensure_root_ssh_key() {
  (( ENABLE_ROOT_KEY_LOGIN == 1 )) || return 0
  [[ -n "$ROOT_SSH_KEY" ]] || return 0
  step "Installing provided SSH public key for root..."

  install -d -m 700 /root/.ssh
  touch /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys

  if ! grep -Fqx "$ROOT_SSH_KEY" /root/.ssh/authorized_keys; then
    printf '%s\n' "$ROOT_SSH_KEY" >>/root/.ssh/authorized_keys
  fi
}

rewrite_ssh_access_directive() {
  local file="$1"
  local directive="$2"
  local mode="$3"
  local tmp="${TMP_DIR}/$(basename "$file").${directive}.tmp"

  [[ -f "$file" ]] || return 0

  awk -v directive="$directive" -v mode="$mode" '
    $1 == directive {
      if (mode == "remove_root") {
        out = directive
        count = 0
        for (i = 2; i <= NF; i++) {
          if ($i != "root") {
            out = out " " $i
            count++
          }
        }
        if (count > 0) {
          print out
        } else {
          print "# " $0 " # disabled by ubuntu_server_init"
        }
        next
      }

      if (mode == "add_root") {
        has_root = 0
        for (i = 2; i <= NF; i++) {
          if ($i == "root") {
            has_root = 1
          }
        }
        print $0 (has_root ? "" : " root")
        next
      }
    }

    { print }
  ' "$file" >"$tmp"

  cat "$tmp" >"$file"
}

configure_root_key_login() {
  (( ENABLE_ROOT_KEY_LOGIN == 1 )) || return 0
  step "Allowing root SSH login by key..."

  backup_file /etc/ssh/sshd_config
  rewrite_ssh_access_directive /etc/ssh/sshd_config DenyUsers remove_root
  rewrite_ssh_access_directive /etc/ssh/sshd_config AllowUsers add_root

  if ls /etc/ssh/sshd_config.d/*.conf >/dev/null 2>&1; then
    local file
    for file in /etc/ssh/sshd_config.d/*.conf; do
      backup_file "$file"
      rewrite_ssh_access_directive "$file" DenyUsers remove_root
      rewrite_ssh_access_directive "$file" AllowUsers add_root
    done
  fi

  mkdir -p /etc/ssh/sshd_config.d
  cat <<'EOF' >/etc/ssh/sshd_config.d/98-root-key-login.conf
PermitRootLogin prohibit-password
PubkeyAuthentication yes
EOF
}

configure_fish_shell() {
  (( INSTALL_FISH == 1 )) || return 0
  step "Configuring fish as default shell for root and primary user..."

  command -v fish >/dev/null 2>&1 || return 0

  if ! grep -Fxq "/usr/bin/fish" /etc/shells; then
    printf '/usr/bin/fish\n' >>/etc/shells
  fi

  chsh -s /usr/bin/fish root
  if [[ -n "$PRIMARY_USER" ]] && id "$PRIMARY_USER" >/dev/null 2>&1; then
    chsh -s /usr/bin/fish "$PRIMARY_USER"
  fi
}

user_has_keys() {
  local user="$1"
  local home_dir
  home_dir="$(getent passwd "$user" | cut -d: -f6)"
  [[ -n "$home_dir" && -s "$home_dir/.ssh/authorized_keys" ]]
}

has_any_authorized_keys() {
  [[ -s /root/.ssh/authorized_keys ]] && return 0
  [[ -n "$ADMIN_USER" ]] && user_has_keys "$ADMIN_USER" && return 0
  return 1
}

configure_ssh() {
  step "Applying SSH hardening for ${SSH_SERVICE}..."
  backup_file /etc/ssh/sshd_config
  backup_file /etc/ssh/sshd_config.d/99-production-hardening.conf

  local password_auth="yes"
  local root_login="prohibit-password"

  if (( DISABLE_PASSWORD_AUTH == 1 )); then
    if has_any_authorized_keys; then
      password_auth="no"
    else
      log "No authorized_keys found. Keeping PasswordAuthentication enabled to avoid lockout."
    fi
  fi

  if (( DISABLE_ROOT_SSH == 1 )) && [[ -n "$ADMIN_USER" ]] && user_has_keys "$ADMIN_USER"; then
    root_login="no"
  fi

  mkdir -p /etc/ssh/sshd_config.d
  cat <<EOF >/etc/ssh/sshd_config.d/99-production-hardening.conf
Port ${SSH_PORT}
Protocol 2
PermitRootLogin ${root_login}
PasswordAuthentication ${password_auth}
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
UsePAM yes
X11Forwarding no
AllowAgentForwarding yes
AllowTcpForwarding yes
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 20
MaxAuthTries 3
MaxSessions 10
MaxStartups 10:30:60
AuthorizedKeysFile .ssh/authorized_keys
PrintMotd no
EOF

  run_quiet sshd -t
  run_quiet systemctl enable "$SSH_SERVICE"
  reload_or_restart_service "$SSH_SERVICE"
}

configure_ufw() {
  step "Configuring UFW with SSH-safe production defaults..."

  run_quiet ufw --force reset
  run_quiet ufw default deny incoming
  run_quiet ufw default allow outgoing
  run_quiet ufw limit "${SSH_PORT}/tcp" comment "SSH rate limit"

  if (( ALLOW_HTTP == 1 )); then
    run_quiet ufw allow 80/tcp comment "HTTP"
  fi
  if (( ALLOW_HTTPS == 1 )); then
    run_quiet ufw allow 443/tcp comment "HTTPS"
  fi

  if [[ -n "$EXTRA_TCP_PORTS" ]]; then
    local port
    while read -r port; do
      [[ -z "$port" ]] && continue
      if [[ "$port" =~ ^[0-9]+$ ]]; then
        (( port >= 1 && port <= 65535 )) || fail "Invalid extra TCP port: $port"
        run_quiet ufw allow "${port}/tcp" comment "Custom TCP"
      elif [[ "$port" =~ ^[0-9]+:[0-9]+$ ]]; then
        run_quiet ufw allow "${port}/tcp" comment "Custom TCP range"
      else
        fail "Invalid extra TCP port or range: $port"
      fi
    done < <(tr ', ' '\n\n' <<<"$EXTRA_TCP_PORTS" | awk 'NF')
  fi

  if [[ -n "$EXTRA_UDP_PORTS" ]]; then
    local port
    while read -r port; do
      [[ -z "$port" ]] && continue
      if [[ "$port" =~ ^[0-9]+$ ]]; then
        (( port >= 1 && port <= 65535 )) || fail "Invalid extra UDP port: $port"
        run_quiet ufw allow "${port}/udp" comment "Custom UDP"
      elif [[ "$port" =~ ^[0-9]+:[0-9]+$ ]]; then
        run_quiet ufw allow "${port}/udp" comment "Custom UDP range"
      else
        fail "Invalid extra UDP port or range: $port"
      fi
    done < <(tr ', ' '\n\n' <<<"$EXTRA_UDP_PORTS" | awk 'NF')
  fi

  run_quiet ufw logging medium
  run_quiet ufw --force enable
}

configure_fail2ban() {
  (( ENABLE_FAIL2BAN == 1 )) || return 0
  step "Configuring fail2ban for SSH on ${SSH_UNIT}..."
  backup_file /etc/fail2ban/jail.d/sshd-production.local

  mkdir -p /etc/fail2ban/jail.d
  cat <<EOF >/etc/fail2ban/jail.d/sshd-production.local
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
banaction = ufw
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
backend = systemd
port = ${SSH_PORT}
journalmatch = _SYSTEMD_UNIT=${SSH_UNIT}
EOF

  run_quiet systemctl enable --now fail2ban
  run_quiet fail2ban-client reload
}

configure_unattended_upgrades() {
  (( ENABLE_UNATTENDED == 1 )) || return 0
  step "Enabling unattended security and stable updates..."
  backup_file /etc/apt/apt.conf.d/51production-unattended-upgrades
  backup_file /etc/apt/apt.conf.d/20auto-upgrades

  cat <<'EOF' >/etc/apt/apt.conf.d/51production-unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
  "${distro_id}:${distro_codename}-security";
  "${distro_id}:${distro_codename}-updates";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::MailOnlyOnError "true";
EOF

  cat <<'EOF' >/etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
EOF
}

role_sysctl_block() {
  case "$SERVER_ROLE" in
    web)
      cat <<'EOF'
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
vm.swappiness = 10
vm.dirty_background_ratio = 5
vm.dirty_ratio = 15
EOF
      ;;
    database)
      cat <<'EOF'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
vm.swappiness = 1
vm.dirty_background_ratio = 3
vm.dirty_ratio = 10
EOF
      ;;
    container)
      cat <<'EOF'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
vm.swappiness = 5
vm.dirty_background_ratio = 5
vm.dirty_ratio = 15
user.max_user_namespaces = 28633
EOF
      ;;
    *)
      cat <<'EOF'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
vm.swappiness = 10
vm.dirty_background_ratio = 5
vm.dirty_ratio = 15
EOF
      ;;
  esac
}

configure_sysctl() {
  step "Applying kernel, network and VM tuning for ${SERVER_ROLE}..."
  backup_file /etc/sysctl.d/99-production-tuning.conf

  {
    cat <<'EOF'
fs.file-max = 2097152
fs.nr_open = 2097152
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 1
fs.protected_regular = 1
fs.inotify.max_user_instances = 1024
fs.inotify.max_user_watches = 1048576
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.pid_max = 4194304
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 1
vm.max_map_count = 262144
vm.overcommit_memory = 1
net.core.default_qdisc = fq
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 65535
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
EOF
    role_sysctl_block
    if (( DISABLE_IPV6 == 1 )); then
      cat <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
    fi
  } >/etc/sysctl.d/99-production-tuning.conf

  run_quiet sysctl --system
}

configure_limits() {
  step "Raising process and file descriptor limits..."
  backup_file /etc/security/limits.d/99-production-limits.conf
  backup_file /etc/systemd/system.conf.d/90-default-limits.conf
  backup_file /etc/systemd/user.conf.d/90-default-limits.conf

  mkdir -p /etc/security/limits.d
  cat <<'EOF' >/etc/security/limits.d/99-production-limits.conf
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 65535
* hard nproc 65535
root soft nofile 1048576
root hard nofile 1048576
EOF

  mkdir -p /etc/systemd/system.conf.d /etc/systemd/user.conf.d
  cat <<'EOF' >/etc/systemd/system.conf.d/90-default-limits.conf
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=65535
EOF

  cat <<'EOF' >/etc/systemd/user.conf.d/90-default-limits.conf
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=65535
EOF

  run_quiet systemctl daemon-reexec
}

configure_journald() {
  step "Enabling persistent journald with bounded retention..."
  backup_file /etc/systemd/journald.conf.d/10-production-persistent.conf

  mkdir -p /etc/systemd/journald.conf.d
  cat <<'EOF' >/etc/systemd/journald.conf.d/10-production-persistent.conf
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=1G
SystemMaxFileSize=128M
RuntimeMaxUse=256M
MaxRetentionSec=1month
RateLimitIntervalSec=30s
RateLimitBurst=20000
EOF

  run_quiet systemctl restart systemd-journald
}

configure_monitoring_baseline() {
  step "Enabling baseline observability services..."
  run_quiet systemctl enable --now sysstat
  run_quiet systemctl enable --now auditd
}

configure_qemu_agent() {
  (( INSTALL_QEMU_AGENT == 1 )) || return 0
  if systemctl list-unit-files qemu-guest-agent.service --no-legend >/dev/null 2>&1; then
    step "Enabling qemu-guest-agent..."
    run_quiet systemctl enable --now qemu-guest-agent
  fi
}

maybe_create_swap() {
  (( AUTO_SWAP == 1 )) || return 0
  (( HAS_SWAP == 0 )) || return 0
  (( RAM_GB < 8 )) || return 0

  step "Creating swap file because RAM is limited and no swap exists..."

  local swap_size="2G"
  if (( RAM_GB <= 2 )); then
    swap_size="2G"
  elif (( RAM_GB <= 4 )); then
    swap_size="4G"
  else
    swap_size="2G"
  fi

  run_quiet fallocate -l "$swap_size" /swapfile
  run_quiet chmod 600 /swapfile
  run_quiet mkswap /swapfile
  run_quiet swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || printf '/swapfile none swap sw 0 0\n' >>/etc/fstab
}

final_cleanup() {
  step "Cleaning package cache and removing obsolete packages..."
  wait_for_apt_lock 120
  run_quiet apt-get autoremove -y
  run_quiet apt-get clean
}

show_completion() {
  local swap_summary
  swap_summary="$(swapon --show=NAME --noheadings 2>/dev/null | paste -sd ',' -)"
  swap_summary="${swap_summary:-none}"

  if parse_env_bool "$NONINTERACTIVE"; then
    log "Completed successfully. backup_dir=${BACKUP_DIR} log_file=${LOG_FILE} swap=${swap_summary}"
    return 0
  fi

  ui_msg "Production baseline applied successfully.

Summary:
- Ubuntu: ${OS_PRETTY_NAME}
- SSH service: ${SSH_SERVICE}
- SSH port: ${SSH_PORT}
- Role: ${SERVER_ROLE}
- Admin user: ${ADMIN_USER:-not created}
- Firewall: enabled
- Fail2ban: $( [[ $ENABLE_FAIL2BAN -eq 1 ]] && echo enabled || echo skipped )
- Unattended upgrades: $( [[ $ENABLE_UNATTENDED -eq 1 ]] && echo enabled || echo skipped )
- IPv6: $( [[ $DISABLE_IPV6 -eq 1 ]] && echo disabled || echo unchanged )
- Swap: ${swap_summary}

Important:
- Reconnect using SSH on port ${SSH_PORT}.
- If root login was disabled, verify access via ${ADMIN_USER:-your admin user}.
- Backup dir: ${BACKUP_DIR}
- Full execution log: ${LOG_FILE}" "Completed"
}

main() {
  : >"$LOG_FILE"
  require_root
  require_ubuntu
  ensure_dialog
  detect_environment
  show_intro
  collect_role
  collect_main_settings
  collect_flags
  show_plan

  apt_upgrade_and_install
  configure_apt_behavior
  configure_timezone
  ensure_admin_user
  ensure_root_ssh_key
  configure_root_key_login
  configure_ssh
  configure_ufw
  configure_fail2ban
  configure_unattended_upgrades
  configure_sysctl
  configure_limits
  configure_journald
  configure_monitoring_baseline
  configure_qemu_agent
  configure_fish_shell
  maybe_create_swap
  final_cleanup
  show_completion

  if (( REBOOT_AFTER == 1 )); then
    dialog --title "Reboot" --infobox "Rebooting in 5 seconds..." 6 50
    sleep 5
    reboot
  fi
}

main "$@"
