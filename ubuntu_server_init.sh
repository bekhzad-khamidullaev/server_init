#!/usr/bin/env bash
# Harden and baseline an Ubuntu server for production.
# Idempotent-ish: safe to run multiple times.
# Tunables via env vars:
#   TIMEZONE=UTC                # System timezone
#   SSH_PORT=22                 # SSH port to keep open
#   ALLOW_HTTP=1                # Allow TCP/80 in UFW (0 to disable)
#   ALLOW_HTTPS=1               # Allow TCP/443 in UFW (0 to disable)
#   DISABLE_IPV6=0              # 1 to disable IPv6 via sysctl
#   DISABLE_PASSWORD_AUTH=1     # 1 to disable SSH password auth when keys exist
#   NEW_SUDO_USER=""            # Optional sudo-capable user to create
#   NEW_SUDO_PUBKEY=""          # Public key to install for NEW_SUDO_USER
#   REBOOT_AFTER=0              # 1 to reboot automatically at the end

set -euo pipefail
IFS=$'\n\t'
umask 027

export DEBIAN_FRONTEND=noninteractive
VERSION="1.2.0"

log()   { printf "[INFO] %s\n" "$*"; }
warn()  { printf "[WARN] %s\n" "$*"; }
fail()  { printf "[ERROR] %s\n" "$*" >&2; exit 1; }

trap 'fail "Line ${LINENO}: command failed"' ERR

require_root() {
  if [[ $(id -u) -ne 0 ]]; then
    fail "Run as root (sudo)."
  fi
}

require_ubuntu() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ ${ID:-} == "ubuntu" ]] || fail "This script targets Ubuntu; found ${ID:-unknown}."
  else
    fail "/etc/os-release missing; cannot verify OS."
  fi
}

apt_install() {
  apt-get update -y
  apt-get upgrade -y
  apt-get install -y --no-install-recommends "$@"
}

ensure_user() {
  local user="$1" pubkey="$2"
  if [[ -z $user ]]; then
    return 0
  fi

  if id "$user" >/dev/null 2>&1; then
    log "User $user already exists"
  else
    log "Creating sudo user $user"
    adduser --disabled-password --gecos "" "$user"
    usermod -aG sudo "$user"
  fi

  local home_dir
  home_dir=$(getent passwd "$user" | cut -d: -f6)
  mkdir -p "$home_dir/.ssh"
  chmod 700 "$home_dir/.ssh"

  if [[ -n $pubkey ]]; then
    printf '%s\n' "$pubkey" >"$home_dir/.ssh/authorized_keys"
    chmod 600 "$home_dir/.ssh/authorized_keys"
    chown -R "$user:$user" "$home_dir/.ssh"
    log "Installed provided public key for $user"
  elif [[ -f /root/.ssh/authorized_keys ]]; then
    install -m 600 /root/.ssh/authorized_keys "$home_dir/.ssh/authorized_keys"
    chown "$user:$user" "$home_dir/.ssh/authorized_keys"
    log "Copied root authorized_keys to $user"
  else
    warn "No public key provided for $user and /root/.ssh/authorized_keys missing"
  fi
}

has_any_authorized_keys() {
  [[ -s /root/.ssh/authorized_keys ]] && return 0
  if [[ -n ${NEW_SUDO_USER:-} ]]; then
    local home_dir
    home_dir=$(getent passwd "$NEW_SUDO_USER" | cut -d: -f6)
    [[ -s "$home_dir/.ssh/authorized_keys" ]] && return 0
  fi
  return 1
}

configure_timezone() {
  local tz="$1"
  log "Setting timezone to $tz"
  timedatectl set-timezone "$tz"
  timedatectl set-ntp true
}

configure_ufw() {
  local ssh_port="$1" http="$2" https="$3"
  log "Configuring UFW"
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw limit "$ssh_port"/tcp comment "SSH (rate limited)"
  [[ $http == "1" ]] && ufw allow 80/tcp comment "HTTP"
  [[ $https == "1" ]] && ufw allow 443/tcp comment "HTTPS"
  ufw logging medium
  ufw --force enable
}

configure_fail2ban() {
  local ssh_port="$1"
  log "Configuring fail2ban"
  cat <<EOF >/etc/fail2ban/jail.d/ssh-hardening.local
[sshd]
enabled  = true
backend  = systemd
port     = ${ssh_port}
maxretry = 5
findtime = 10m
bantime  = 1h
ignoreip = 127.0.0.1/8 ::1
banaction = ufw
EOF
  systemctl enable --now fail2ban
}

user_has_keys() {
  local user="$1" home_dir
  home_dir=$(getent passwd "$user" | cut -d: -f6)
  [[ -n $home_dir && -s "$home_dir/.ssh/authorized_keys" ]]
}

configure_ssh() {
  local ssh_port="$1" disable_pw="$2" sudo_user="$3"

  if [[ $disable_pw == "1" ]] && ! has_any_authorized_keys; then
    warn "No authorized_keys found; keeping password authentication enabled to avoid lockout"
    disable_pw=0
  fi

  local root_login="prohibit-password"
  if [[ -n $sudo_user ]] && user_has_keys "$sudo_user"; then
    root_login="no"
  fi

  log "Hardening SSH (port $ssh_port)"
  cat <<EOF >/etc/ssh/sshd_config.d/99-hardening.conf
Port $ssh_port
Protocol 2
PermitRootLogin $root_login
PasswordAuthentication $( [[ $disable_pw == "1" ]] && echo no || echo yes )
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
UsePAM yes
ClientAliveInterval 300
ClientAliveCountMax 3
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 4
X11Forwarding no
AllowTcpForwarding yes
AllowAgentForwarding yes
PrintMotd no
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
  systemctl reload sshd
}

configure_unattended_upgrades() {
  log "Enabling unattended upgrades"
  cat <<'EOF' >/etc/apt/apt.conf.d/51custom-unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
        "${distro_id}:${distro_codename}-updates";
};
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailOnlyOnError "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

  cat <<'EOF' >/etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Verbose "0";
EOF
}

configure_needrestart() {
  log "Configuring needrestart for noninteractive runs"
  mkdir -p /etc/needrestart/conf.d
  cat <<'EOF' >/etc/needrestart/conf.d/50auto.conf
$nrconf{restart} = 'a';
EOF
}

configure_sysctl() {
  log "Applying sysctl hardening"
  cat <<'EOF' >/etc/sysctl.d/99-hardening.conf
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 1
fs.protected_regular = 1
EOF

  if [[ ${DISABLE_IPV6:-0} == "1" ]]; then
    cat <<'EOF' >>/etc/sysctl.d/99-hardening.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
  fi

  sysctl --system >/dev/null
}

configure_journald() {
  log "Configuring persistent journald with rotation"
  mkdir -p /etc/systemd/journald.conf.d
  cat <<'EOF' >/etc/systemd/journald.conf.d/10-persistent.conf
[Journal]
Storage=persistent
SystemMaxUse=1G
SystemMaxFileSize=200M
MaxRetentionSec=1month
EOF
  systemctl restart systemd-journald
}

configure_qemu_guest_agent() {
  if systemctl list-unit-files | grep -q '^qemu-guest-agent'; then
    log "Enabling qemu-guest-agent"
    systemctl enable --now qemu-guest-agent
  fi
}

clean_packages() {
  apt-get autoremove -y
  apt-get clean
}

main() {
  require_root
  require_ubuntu

  SSH_PORT=${SSH_PORT:-22}
  TIMEZONE=${TIMEZONE:-UTC}
  ALLOW_HTTP=${ALLOW_HTTP:-1}
  ALLOW_HTTPS=${ALLOW_HTTPS:-1}
  DISABLE_IPV6=${DISABLE_IPV6:-0}
  DISABLE_PASSWORD_AUTH=${DISABLE_PASSWORD_AUTH:-1}
  NEW_SUDO_USER=${NEW_SUDO_USER:-}
  NEW_SUDO_PUBKEY=${NEW_SUDO_PUBKEY:-}
  REBOOT_AFTER=${REBOOT_AFTER:-0}

  log "ubuntu_server_init v${VERSION}"

  apt_install \
    ca-certificates gnupg lsb-release curl wget git openssh-server \
    ufw fail2ban unattended-upgrades apt-listchanges \
    needrestart net-tools htop tmux vim nano jq software-properties-common \
    qemu-guest-agent auditd

  configure_timezone "$TIMEZONE"
  configure_ufw "$SSH_PORT" "$ALLOW_HTTP" "$ALLOW_HTTPS"
  configure_fail2ban "$SSH_PORT"
  ensure_user "$NEW_SUDO_USER" "$NEW_SUDO_PUBKEY"
  configure_ssh "$SSH_PORT" "$DISABLE_PASSWORD_AUTH" "$NEW_SUDO_USER"
  configure_unattended_upgrades
  configure_needrestart
  configure_sysctl
  configure_journald
  configure_qemu_guest_agent

  systemctl enable --now systemd-timesyncd auditd

  clean_packages

  log "Baseline hardening complete"
  if [[ $REBOOT_AFTER == "1" ]]; then
    log "Rebooting in 5 seconds (REBOOT_AFTER=1)"
    sleep 5
    reboot
  else
    log "Reboot recommended after kernel updates"
  fi
}

main "$@"
