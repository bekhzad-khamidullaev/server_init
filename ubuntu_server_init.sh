#!/bin/bash

# Function to generate a strong password
generate_password() {
    head -c 32 /dev/urandom | base64 | tr -dc '[:alnum:]!@#$%^&*()_+' | head -c 20
}

# Function to display a step in the pseudo UI
display_step() {
    echo
    echo "------------------------------------------------------------"
    echo "| Step $1: $2"
    echo "------------------------------------------------------------"
}

# Function to check if a package is installed
is_package_installed() {
  dpkg -s "$1" > /dev/null 2>&1
}


# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run the script as root or using sudo."
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# Update the system
display_step 1 "Updating the system"
apt update -y
apt upgrade -y

# Install essential packages for server management and security
display_step 2 "Installing essential packages"
apt install -y git curl htop unzip net-tools vim nano wget screen tmux iotop iftop bmon nload nmap traceroute ethtool sysstat dstat tcpdump socat lsof iptraf-ng whois dnsutils ufw

# Configure the firewall (UFW)
display_step 3 "Configuring the firewall (UFW)"
ufw allow OpenSSH
ufw default deny incoming
ufw default allow outgoing
ufw logging on
ufw --force enable

# Set the timezone to Asia/Tashkent
display_step 4 "Setting the timezone to Asia/Tashkent"
timedatectl set-timezone Asia/Tashkent

# Install and configure fail2ban
display_step 5 "Installing and configuring fail2ban"
apt install -y fail2ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Customize fail2ban jail.local with specific rules (adjust bantime, findtime, maxretry as needed)
sed -i 's/;bantime  = 10m/bantime = 1h/' /etc/fail2ban/jail.local  # Example: Ban for 1 hour
sed -i 's/;findtime = 10m/findtime = 10m/' /etc/fail2ban/jail.local
sed -i 's/;maxretry = 5/maxretry = 5/' /etc/fail2ban/jail.local

# Configure common jails (adjust as needed)
sed -i 's/enabled = false/enabled = true/' /etc/fail2ban/jail.local
systemctl enable fail2ban
systemctl start fail2ban

# Install and configure logwatch for log analysis
display_step 6 "Installing and configuring logwatch"
apt install -y logwatch
logwatch_conf="/etc/logwatch/conf/logwatch.conf"
if [ -f "$logwatch_conf" ]; then
    display_step 6 "Modifying logwatch.conf"
    sed -i 's/Detail = Low/Detail = Med/' "$logwatch_conf"
    sed -i 's/Output = stdout/Output = mail/' "$logwatch_conf"
    sed -i 's/MailTo = root/MailTo = your_email@example.com/' "$logwatch_conf" # Replace with your email
else
    echo "Warning: logwatch.conf not found at $logwatch_conf. Skipping modification."
fi

# Set up automatic updates
display_step 7 "Setting up automatic updates"
apt install -y unattended-upgrades apt-listchanges
dpkg-reconfigure --priority=low unattended-upgrades
# Configure unattended-upgrades
cat <<EOL > /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}:\${distro_codename}-updates";
    "\${distro_id}:\${distro_codename}-proposed";
    "\${distro_id}:\${distro_codename}-backports";
};

Unattended-Upgrade::Package-Blacklist {
    # Put packages to exclude from automatic upgrades here
    # Example:
    # "linux-image-generic";
};

Unattended-Upgrade::Mail "your_email@example.com"; # Replace with your email
Unattended-Upgrade::MailOnlyOnError "true";
EOL

# Install and configure a basic intrusion detection system with AIDE
display_step 8 "Installing and configuring a basic intrusion detection system with AIDE"
apt install -y aide
aideinit
systemctl enable aide.timer
systemctl start aide.timer

# Schedule daily AIDE checks and run it in the background, suppressing output
echo "0 0 * * * root /usr/sbin/aide --check >/dev/null 2>&1" > /etc/cron.d/aide

# Set up basic log rotation
display_step 9 "Setting up basic log rotation"
cat <<EOL > /etc/logrotate.d/custom_logs
/var/log/custom/*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
EOL

# System performance optimization
display_step 10 "Optimizing the system for best performance"

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

# Increase TCP buffer size (adapt to available RAM, example for 16GB RAM)
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Enable TCP window scaling
net.ipv4.tcp_window_scaling = 1

# Enable fast recycling of TIME_WAIT sockets (use with caution, might cause issues)
# net.ipv4.tcp_tw_recycle = 1 #Deprecated and removed in newer kernels

# Enable TCP quick acknowledgment
net.ipv4.tcp_quickack = 1

# Increase the maximum number of backlogged sockets
net.core.somaxconn = 65535

# Increase the maximum number of TCP connections
net.ipv4.tcp_max_syn_backlog = 8192

# Increase the maximum number of memory map areas a process may have
vm.max_map_count = 262144

# Reduce the tendency to swap (adjust to system requirements)
vm.swappiness = 10

# Control the cache pressure (adjust to system requirements)
vm.vfs_cache_pressure = 50

# TCP SYN cookies protection
net.ipv4.tcp_syncookies = 1

# Prevent against SYN flood attacks
net.ipv4.tcp_synack_retries = 5
net.ipv4.tcp_abort_on_overflow = 1

# Ignore broadcasts request
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Don't accept source routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Enable TCP BBR congestion control algorithm
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# Improve connection tracking hash table size for busy servers
net.netfilter.nf_conntrack_max = 655360
net.nf_conntrack_max = 655360  # Legacy setting, might be needed on older kernels
net.netfilter.nf_conntrack_tcp_timeout_established = 7200 # Keep established connections longer (in seconds)

# Protection against ICMP attacks
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable Reverse Path Filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

EOL

# Apply the new sysctl settings
sysctl -p

# Determine the block device and optimize the I/O scheduler
block_device=$(lsblk -no NAME,MOUNTPOINT | awk '$2=="/" {print $1}' | sed 's/[^a-zA-Z0-9]//g')
if [ -n "$block_device" ]; then
    display_step 11 "Optimizing the I/O scheduler for $block_device"
    # Use 'mq-deadline' if available, otherwise fallback to 'deadline'
    if grep -q "mq-deadline" "/sys/block/$block_device/queue/scheduler"; then
        echo "mq-deadline" > "/sys/block/$block_device/queue/scheduler"
        echo "Setting I/O scheduler to mq-deadline"
    else
        echo "deadline" > "/sys/block/$block_device/queue/scheduler"
        echo "Setting I/O scheduler to deadline"
    fi
else
    echo "Error: Unable to determine the root block device."
fi


# Configure Transparent Huge Pages (THP)
display_step 12 "Configuring Transparent Huge Pages (THP)"
echo "never" > /sys/kernel/mm/transparent_hugepage/enabled
echo "never" > /sys/kernel/mm/transparent_hugepage/defrag

# Disable unnecessary services
display_step 13 "Disabling unnecessary services"
systemctl stop postfix 2>/dev/null || true
systemctl disable postfix 2>/dev/null || true
systemctl stop apport 2>/dev/null || true # Error Reporting
systemctl disable apport 2>/dev/null || true

# Remove the Ubuntu motd
display_step 14 "Removing the Ubuntu motd"
rm -f /etc/update-motd.d/*

#  Set custom greeting in ~/.config/fish/config.fish
display_step 15 "Setting custom greeting in ~/.config/fish/config.fish"
config_fish_file="/root/.config/fish/config.fish"
mkdir -p /root/.config/fish/
echo 'set fish_greeting ""' > "$config_fish_file"


# Enabling Qemu guest agent
display_step 16 "Enabling Qemu guest agent"
if is_package_installed "qemu-guest-agent"; then
    systemctl enable qemu-guest-agent
    systemctl start qemu-guest-agent
else
    echo "Qemu guest agent not installed, skipping..."
fi

# Security Hardening

# Disable IPv6 if not needed
display_step 17 "Disabling IPv6 (if not needed)"
if ! grep -q "disable_ipv6=1" /etc/sysctl.conf; then
    echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.lo.disable_ipv6=1" >> /etc/sysctl.conf
    sysctl -p
fi

# Harden SSH Configuration
display_step 18 "Hardening SSH Configuration"

#  Disable root login and password authentication (recommended for production)
#  Requires setting up key-based authentication first.
#  Uncomment the following lines *AFTER* verifying key-based authentication works!

sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 3/' /etc/ssh/sshd_config
systemctl restart ssh

# Add Message of the Day
display_step 19 "Adding Message of the Day (MOTD)"
cat <<EOL > /etc/motd
##################################################################################
#                                                                                #
#                   Welcome to $(hostname) - Secure Server                       #
#                       Managed by: Bekhzad Khamidullah                          #
#                                                                                #
#          This system is actively monitored. Unauthorized access is             #
#          strictly prohibited and will be prosecuted to the fullest             #
#          extent of the law.                                                    #
#                                                                                #
#          Last login: $(last -n 1 | head -n 1 | sed 's/  */ /g')                #
#                                                                                #
#          System Uptime: $(uptime | sed 's/.*up //g' | sed 's/,  .*//g')        #
#                                                                                #
##################################################################################
EOL

chmod 644 /etc/motd

# Remove old kernels

display_step 20 "Removing old kernels"
apt autoremove -y
apt clean

# Install unattended reboot
display_step 21 "Configuring unattended reboots"
apt install -y needrestart

# Completion message
echo
echo "***********************************************************************"
echo "* Server Initialization and Optimization Script Completed!            *"
echo "***********************************************************************"
echo "* Key security settings have been applied.                            *"
echo "* REMEMBER TO REVIEW AND SECURE SSH FURTHER.                          *"
echo "* Regularly check logs and system performance.                        *"
echo "* Ensure backups are configured appropriately.                        *"
echo "***********************************************************************"
