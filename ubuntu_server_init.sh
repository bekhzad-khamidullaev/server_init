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

# Enable root login over SSH
display_step 2 "Enabling root login over SSH"
sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Enable public key authentication
display_step 3 "Enabling public key authentication"
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Restart SSH service
display_step 4 "Restarting SSH service"
systemctl restart ssh

# Download and append public key from GitHub to authorized_keys
display_step 5 "Downloading and adding public key from GitHub"
mkdir -p /root/.ssh
wget -O /root/.ssh/authorized_keys https://github.com/bekhzad-khamidullaev.keys

# Generate and set a strong root password
display_step 6 "Generating and setting a strong root password"
root_password=$(generate_password)
echo "root:$root_password" | chpasswd
echo $root_password > /root/root_password.txt
chmod 700 /root/root_password



# Install essential packages
display_step 7 "Installing essential packages"
apt install -y git curl htop unzip net-tools

# Configure the firewall (UFW)
display_step 8 "Configuring the firewall (UFW)"
ufw allow OpenSSH
ufw --force enable

# Set the timezone to Asia/Tashkent
display_step 9 "Setting the timezone to Asia/Tashkent"
timedatectl set-timezone Asia/Tashkent

# Install and configure fail2ban
display_step 10 "Installing and configuring fail2ban"
apt install -y fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# Install and configure logwatch for log analysis
display_step 11 "Installing and configuring logwatch"
apt install -y logwatch
logwatch_conf="/etc/logwatch/conf/logwatch.conf"
if [ -f "$logwatch_conf" ]; then
    display_step 11 "Modifying logwatch.conf"
    sed -i 's/Detail = Low/Detail = Med/' "$logwatch_conf"
else
    echo "Warning: logwatch.conf not found at $logwatch_conf. Skipping modification."
fi

# Disable root login via SSH after initial setup
display_step 12 "Disabling root login via SSH after initial setup"
sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
systemctl restart ssh

# Set up automatic updates
display_step 13 "Setting up automatic updates"
apt install -y unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades

# Install and configure a basic firewall with UFW
display_step 14 "Installing and configuring a basic firewall with UFW"
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
echo "y" | ufw enable

# Install and configure a basic intrusion detection system with AIDE
display_step 15 "Installing and configuring a basic intrusion detection system with AIDE"
apt install -y aide
aideinit
systemctl enable aide.timer
systemctl start aide.timer

# Set up basic log rotation
display_step 16 "Setting up basic log rotation"
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

# System performance optimization
display_step 17 "Optimizing the system for best performance"

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

# Determine the block device and optimize the I/O scheduler
block_device=$(lsblk -no NAME,MOUNTPOINT | awk '$2=="/" {print $1}' | sed 's/[^a-zA-Z0-9]//g')
if [ -n "$block_device" ]; then
    display_step 18 "Optimizing the I/O scheduler for $block_device"
    echo "deadline" > "/sys/block/$block_device/queue/scheduler"
else
    echo "Error: Unable to determine the root block device."
fi

# Enable TCP BBR congestion control algorithm
display_step 19 "Enabling TCP BBR congestion control algorithm"
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p

# Configure Transparent Huge Pages (THP)
display_step 20 "Configuring Transparent Huge Pages (THP)"
echo "never" > /sys/kernel/mm/transparent_hugepage/enabled
echo "never" > /sys/kernel/mm/transparent_hugepage/defrag

# Disable unnecessary services
display_step 21 "Disabling unnecessary services"
systemctl stop postfix
systemctl disable postfix

# Remove the Ubuntu motd
display_step 22 "Removing the Ubuntu motd"
rm -f /etc/update-motd.d/*

# Install Fish shell and set it as the default shell for root
display_step 23 "Installing Fish shell and setting it as the default shell for root"
apt install -y fish
chsh -s /usr/bin/fish root

# Set custom greeting in ~/.config/fish/config.fish
display_step 24 "Setting custom greeting in ~/.config/fish/config.fish"
config_fish_file="/root/.config/fish/config.fish"
echo 'set fish_greeting ""' > "$config_fish_file"


# Display completion message
echo
echo "***********************************************************************"
echo "* Initialization and optimization script completed!                   *"
echo "* Root access is enabled with the generated password: $root_password  *"
echo "* Public key added to authorized_keys.                                *"
echo "* System updated, essential packages installed.                       *"
echo "* Firewall (UFW) configured to allow SSH.                             *"
echo "* Timezone set to Asia/Tashkent.                                      *"
echo "* fail2ban installed and configured.                                  *"
echo "* logwatch installed for log analysis.                                *"
echo "* Root login disabled via SSH after initial setup.                    *"
echo "* Automatic updates configured.                                       *"
echo "* Basic firewall (UFW) and intrusion detection system (AIDE) set up.  *"
echo "* Basic log rotation configured.                                      *"
echo "* System optimized for best performance.                              *"
echo "***********************************************************************"
