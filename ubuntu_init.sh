#!/bin/bash

# Function to check if a command is available
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if the dialog command is available, and install it if not
if ! command_exists dialog; then
    echo "Installing dialog..."
    apt update > /dev/null
    apt install -y dialog > /dev/null
fi

# Function to generate a strong password
generate_password() {
    head -c 32 /dev/urandom | base64 | tr -dc '[:alnum:]!@#$%^&*()_+' | head -c 20
}

# Function to display a step in the pseudo UI
display_step() {
    dialog --title "Step $1" --infobox "$2" 7 70
}

# Function to check if the script is run as root
check_root() {
    [ "$(id -u)" -eq 0 ] || { dialog --title "Error" --msgbox "Please run the script as root or using sudo." 7 50; exit 1; }
}

update_system() {
    display_step 1 "Updating the system"
    apt update -y > /dev/null && apt upgrade -y > /dev/null
}

enable_root_ssh() {
    display_step 2 "Enabling root login over SSH"
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
    systemctl restart ssh
}

enable_pubkey_auth() {
    display_step 3 "Enabling public key authentication"
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    systemctl restart ssh
}

download_pubkey() {
    display_step 4 "Downloading and adding public key from GitHub"
    mkdir -p /root/.ssh
    wget -O /root/.ssh/authorized_keys https://github.com/bekhzad-khamidullaev.keys
}

set_strong_password() {
    display_step 5 "Generating and setting a strong root password"
    root_password=$(generate_password)
    echo "root:$root_password" | chpasswd
    echo $root_password > /root/root_password.txt
    chmod 700 /root/root_password
}

install_essential_packages() {
    display_step 6 "Installing essential packages"
    apt install -y git curl htop unzip net-tools qemu-guest-agent
}

configure_firewall() {
    display_step 7 "Configuring the firewall (UFW)"
    ufw allow OpenSSH
    ufw --force enable
}

set_timezone() {
    display_step 8 "Setting the timezone to Asia/Tashkent"
    timedatectl set-timezone Asia/Tashkent
}

install_fail2ban() {
    display_step 9 "Installing and configuring fail2ban"
    apt install -y fail2ban
    systemctl enable fail2ban
    systemctl start fail2ban
}

install_logwatch() {
    display_step 10 "Installing and configuring logwatch"
    apt install -y logwatch
    logwatch_conf="/etc/logwatch/conf/logwatch.conf"
    [ -f "$logwatch_conf" ] && sed -i 's/Detail = Low/Detail = Med/' "$logwatch_conf"
}

disable_root_ssh() {
    display_step 11 "Disabling root login via SSH after initial setup"
    sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    systemctl restart ssh
}

set_automatic_updates() {
    display_step 12 "Setting up automatic updates"
    apt install -y unattended-upgrades
    dpkg-reconfigure --priority=low unattended-upgrades
}

configure_basic_firewall() {
    display_step 13 "Installing and configuring a basic firewall with UFW"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    echo "y" | ufw enable
}

configure_intrusion_detection() {
    display_step 14 "Installing and configuring a basic intrusion detection system with AIDE"
    apt install -y aide
    aideinit
    systemctl enable aide.timer
    systemctl start aide.timer
}

set_basic_log_rotation() {
    display_step 15 "Setting up basic log rotation"
    cat <<EOL > /etc/logrotate.d/custom_logs
/var/log/custom/*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
}
EOL
}

optimize_system_performance() {
    display_step 16 "Optimizing the system for best performance"
    # Set performance-related kernel parameters
    cat <<EOL > /etc/sysctl.conf
# Recommended sysctl settings for improved performance

# Increase the maximum number of open file descriptors
fs.file-max = 2097152

# Allow for more PIDs (processes/threads)
kernel.pid_max = 65536

# Increase system file descriptor limit
fs.nr_open = 1048576

# Increase network buffer limits
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# Increase the maximum amount of option memory buffers
net.core.optmem_max = 25165824

# Increase TCP buffer size
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Enable TCP window scaling
net.ipv4.tcp_window_scaling = 1

# Enable fast recycling of TIME_WAIT sockets
net.ipv4.tcp_tw_recycle = 1

# Enable TCP quick acknowledgment
net.ipv4.tcp_quickack = 1

# Increase the maximum number of backlogged sockets
net.core.somaxconn = 65535

# Increase the maximum number of TCP connections
net.ipv4.tcp_max_syn_backlog = 8192

# Increase the maximum number of memory map areas a process may have
vm.max_map_count = 262144

# Avoid swapping
vm.swappiness = 10

# Use a more aggressive preemption model for better desktop responsiveness
kernel.sched_min_granularity_ns = 10000000
kernel.sched_wakeup_granularity_ns = 15000000
EOL

# Apply the new sysctl settings
sysctl -p
}

optimize_io_scheduler() {
    block_device=$(lsblk -no NAME,MOUNTPOINT | awk '$2=="/" {print $1}' | sed 's/[^a-zA-Z0-9]//g')
    [ -n "$block_device" ] && echo "deadline" > "/sys/block/$block_device/queue/scheduler"
}

enable_tcp_bbr() {
    display_step 17 "Enabling TCP BBR congestion control algorithm"
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
}

configure_thp() {
    display_step 18 "Configuring Transparent Huge Pages (THP)"
    cat <<EOL > /etc/sysctl.d/99-transparent-huge-pages.conf
# Disable Transparent Huge Pages (THP)
kernel/mm/transparent_hugepage/enabled = never
kernel/mm/transparent_hugepage/defrag = never
EOL
    sysctl -p /etc/sysctl.d/99-transparent-huge-pages.conf
}

disable_unnecessary_services() {
    display_step 19 "Disabling unnecessary services"
    systemctl stop postfix
    systemctl disable postfix
}

remove_ubuntu_motd() {
    display_step 20 "Removing the Ubuntu motd"
    rm -f /etc/update-motd.d/*
}

install_fish_shell() {
    display_step 21 "Installing Fish shell and setting it as the default shell for root"
    apt install -y fish
    chsh -s /usr/bin/fish root
}

set_custom_greeting() {
    display_step 22 "Setting custom greeting in ~/.config/fish/config.fish"
    config_fish_file="/root/.config/fish/config.fish"
    echo 'set fish_greeting ""' > "$config_fish_file"
}

enable_qemu_guest_agent() {
    display_step 23 "Enabling Qemu guest agent"
    systemctl enable qemu-guest-agent
    systemctl start qemu-guest-agent
}

install_docker_compose() {
    display_step 24 "Installing Docker Compose"
    apt install -y docker.io docker-compose
}

download_docker_compose_config() {
    display_step 25 "Downloading Docker Compose configuration for Node Exporter"
    curl -fsSL -o /root/docker-compose.yml https://raw.githubusercontent.com/prometheus/node_exporter/main/examples/prometheus-node-exporter-docker/docker-compose.yml
}

start_node_exporter() {
    display_step 26 "Starting Node Exporter Docker container"
    cd /root
    docker-compose up -d
}

final_completion_message() {
    dialog --title "Completion" --msgbox "Initialization and optimization script completed!\n\nRoot access is enabled with the generated password: $root_password\n\nPublic key added to authorized_keys.\n\nSystem updated, essential packages installed.\n\nFirewall (UFW) configured to allow SSH.\n\nTimezone set to Asia/Tashkent.\n\nfail2ban installed and configured.\n\nlogwatch installed for log analysis.\n\nRoot login disabled via SSH after initial setup.\n\nAutomatic updates configured.\n\nBasic firewall (UFW) and intrusion detection system (AIDE) set up.\n\nBasic log rotation configured.\n\nSystem optimized for best performance.\n\nNode Exporter Docker container started." 20 70
}

main() {
    check_root
    update_system
    enable_root_ssh
    enable_pubkey_auth
    download_pubkey
    set_strong_password
    install_essential_packages
    configure_firewall
    set_timezone
    install_fail2ban
    install_logwatch
    disable_root_ssh
    set_automatic_updates
    configure_basic_firewall
    configure_intrusion_detection
    set_basic_log_rotation
    optimize_system_performance
    optimize_io_scheduler
    enable_tcp_bbr
    configure_thp
    disable_unnecessary_services
    remove_ubuntu_motd
    install_fish_shell
    set_custom_greeting
    enable_qemu_guest_agent
    install_docker_compose
    download_docker_compose_config
    start_node_exporter
    final_completion_message
}

main
