#!/bin/bash

# Check if the script is run with sudo privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo privileges."
    exit 1
fi

# Check if the system is Arch Linux and exit if it is
if [ -f /etc/arch-release ] || grep -q 'Arch Linux' /etc/os-release 2>/dev/null; then
    echo "This script does not support Arch Linux. Exiting."
    exit 1
fi

# Function to prompt user for confirmation
confirm() {
    read -r -p "$1 [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY]) 
            true
            ;;
        *)
            false
            ;;
    esac
}

# Function to clear the terminal
clear_terminal() {
    if command -v tput &> /dev/null; then
        tput reset
    else
        echo -ne "\033c"
    fi
}

# Function to update and upgrade system packages
update_system() {
    if confirm "Do you want to update and upgrade system packages?"; then
        echo "Updating and upgrading system packages... Please wait."
        if [ -f /etc/debian_version ]; then
            sudo apt update && sudo apt upgrade -y
        elif [ -f /etc/redhat-release ]; then
            sudo dnf update -y
        fi
        clear_terminal
        echo "System packages have been updated and upgraded."
    fi
}

# Function to create a new user and grant sudo privileges
create_user() {
    if confirm "Do you want to create a new user and grant sudo privileges?"; then
        read -r -p "Enter the new username: " newuser
        echo "Creating new user $newuser and granting sudo privileges... Please wait."
        if [ -f /etc/debian_version ]; then
            sudo adduser "$newuser"
            sudo usermod -aG sudo "$newuser"
        elif [ -f /etc/redhat-release ]; then
            sudo adduser "$newuser"
            sudo usermod -aG wheel "$newuser"
        fi
        clear_terminal
        echo "New user $newuser has been created and added to the sudo group."
    fi
}

# Function to disable root login via SSH
disable_root_ssh() {
    if confirm "Do you want to disable root login via SSH?"; then
        echo "Disabling root login via SSH... Please wait."
        sudo mkdir -p /etc/ssh/sshd_config.d
        echo "PermitRootLogin no" | sudo tee /etc/ssh/sshd_config.d/disable_root.conf
        if [ -f /etc/debian_version ]; then
            sudo systemctl restart ssh
        else
            sudo systemctl restart sshd
        fi
        clear_terminal
        echo "Root login via SSH has been disabled."
    fi
}

# Function to disable SSH login with password and allow SSH with authorized key only
setup_ssh_key_auth() {
    if confirm "Do you want to disable SSH login with password and allow SSH with authorized key only?"; then
        read -r -p "Enter the username for SSH key setup: " ssh_user
        read -r -p "Enter the server IP address: " server_ip
        echo "Please run the following command on your local machine to generate an SSH key pair:"
        echo "ssh-keygen -t rsa -b 4096"
        echo "Then run the following command on your local machine to copy the SSH key to the server:"
        echo "ssh-copy-id $ssh_user@$server_ip"
        read -r -p "Press Enter after you have generated and copied the SSH key..."
        echo "Configuring SSH to disable password authentication and enable key authentication... Please wait."
        sudo mkdir -p /etc/ssh/sshd_config.d
        {
            echo "PasswordAuthentication no"
            echo "PubkeyAuthentication yes"
        } | sudo tee /etc/ssh/sshd_config.d/ssh_key_auth.conf > /dev/null
        if [ -f /etc/debian_version ]; then
            sudo systemctl restart ssh
        else
            sudo systemctl restart sshd
        fi
        clear_terminal
        echo "SSH login with password has been disabled and SSH key authentication has been enabled."
    fi
}

# Function to further harden SSH configuration
harden_ssh() {
    if confirm "Do you want to harden SSH configuration further?"; then
        echo "Hardening SSH configuration... Please wait."
        sudo mkdir -p /etc/ssh/sshd_config.d
        
        # Ask for allowed users
        read -r -p "Enter space-separated usernames to allow SSH access (leave empty to allow all): " ssh_allowed_users
        
        # Ask for allowed groups
        read -r -p "Enter space-separated groups to allow SSH access (leave empty to allow all): " ssh_allowed_groups
        
        # Create the SSH hardening configuration
        {
            echo "# SSH hardening configuration"
            echo "Protocol 2"
            echo "MaxAuthTries 3"
            echo "MaxSessions 2"
            echo "LoginGraceTime 30"
            echo "ClientAliveInterval 300"
            echo "ClientAliveCountMax 2"
            echo "X11Forwarding no"
            echo "AllowAgentForwarding no"
            echo "AllowTcpForwarding no"
            echo "PermitEmptyPasswords no"
            
            # Only add AllowUsers if specified
            if [ -n "$ssh_allowed_users" ]; then
                echo "AllowUsers $ssh_allowed_users"
            fi
            
            # Only add AllowGroups if specified
            if [ -n "$ssh_allowed_groups" ]; then
                echo "AllowGroups $ssh_allowed_groups"
            fi
            
            # Add strong ciphers, MACs and key exchange algorithms
            echo "# Strong encryption algorithms"
            echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
            echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
            echo "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"
            
            # Increase verbosity of logging
            echo "LogLevel VERBOSE"
            
        } | sudo tee /etc/ssh/sshd_config.d/hardening.conf > /dev/null
        
        # Restart SSH service
        if [ -f /etc/debian_version ]; then
            sudo systemctl restart ssh
        else
            sudo systemctl restart sshd
        fi
        clear_terminal
        echo "SSH configuration has been hardened."
    fi
}

# Function to setup UFW or firewalld
setup_firewall() {
    if confirm "Do you want to setup a firewall?"; then
        echo "Setting up firewall... Please wait."
        if [ -f /etc/debian_version ]; then
            sudo apt install ufw -y
            sudo ufw allow OpenSSH
            sudo ufw enable
        elif [ -f /etc/redhat-release ]; then
            sudo dnf install firewalld -y
            sudo systemctl start firewalld
            sudo systemctl enable firewalld
            sudo firewall-cmd --permanent --add-service=ssh
            sudo firewall-cmd --reload
        fi
        clear_terminal
        echo "Firewall has been set up."
    fi
}

# Function to setup Fail2Ban
setup_fail2ban() {
    if confirm "Do you want to setup Fail2Ban?"; then
        echo "Setting up Fail2Ban... Please wait."
        if [ -f /etc/debian_version ]; then
            sudo apt install fail2ban -y
            sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
            sudo sed -i 's/^#enabled.*/enabled = true/' /etc/fail2ban/jail.local
            sudo systemctl restart fail2ban
        elif [ -f /etc/redhat-release ]; then
            sudo dnf install fail2ban -y
            sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
            sudo sed -i 's/^#enabled.*/enabled = true/' /etc/fail2ban/jail.local
            sudo systemctl restart fail2ban
        fi
        clear_terminal
        echo "Fail2Ban has been set up."
    fi
}

# Function to secure network protocols
secure_network_protocols() {
    if confirm "Do you want to disable potentially unnecessary network protocols?"; then
        echo "Reviewing network protocols for disabling..."
        
        # Create a temporary file to build up our configuration
        temp_file=$(mktemp)
        echo "# Disable unused network protocols" > "$temp_file"
        
        # Ask about each protocol individually
        if confirm "Disable DCCP (Datagram Congestion Control Protocol)? This is rarely used and can pose security risks."; then
            echo "install dccp /bin/true" >> "$temp_file"
            echo "DCCP protocol will be disabled."
        fi
        
        if confirm "Disable SCTP (Stream Control Transmission Protocol)? Unless you use telecom applications, this can typically be disabled."; then
            echo "install sctp /bin/true" >> "$temp_file"
            echo "SCTP protocol will be disabled."
        fi
        
        if confirm "Disable RDS (Reliable Datagram Sockets)? This is primarily used in high-performance computing and can be disabled on most servers."; then
            echo "install rds /bin/true" >> "$temp_file"
            echo "RDS protocol will be disabled."
        fi
        
        if confirm "Disable TIPC (Transparent Inter-Process Communication)? This is a specialized protocol for cluster communication."; then
            echo "install tipc /bin/true" >> "$temp_file"
            echo "TIPC protocol will be disabled."
        fi
        
        # Move temp file to actual location if any protocols were selected
        if [ "$(wc -l < "$temp_file")" -gt 1 ]; then
            sudo cp "$temp_file" /etc/modprobe.d/disable-protocols.conf
            echo "Selected network protocols have been disabled."
        else
            echo "No network protocols were selected for disabling."
        fi
        
        # Clean up temp file
        rm "$temp_file"
        clear_terminal
        echo "Network protocol security configuration complete."
    fi
}

# Function to harden kernel parameters
harden_kernel_parameters() {
    if confirm "Do you want to harden kernel parameters?"; then
        echo "Configuring secure kernel parameters... Please wait."
        {
            echo "# IP Spoofing protection"
            echo "net.ipv4.conf.all.rp_filter = 1"
            echo "net.ipv4.conf.default.rp_filter = 1"
            
            echo "# Disable IP source routing"
            echo "net.ipv4.conf.all.accept_source_route = 0"
            echo "net.ipv4.conf.default.accept_source_route = 0"
            
            echo "# Ignore ICMP broadcast requests"
            echo "net.ipv4.icmp_echo_ignore_broadcasts = 1"
            
            echo "# Disable IPv6 if not needed (ask user first)"
            read -r -p "Do you want to disable IPv6? [y/N] " disable_ipv6
            case "$disable_ipv6" in
                [yY][eE][sS]|[yY]) 
                    echo "net.ipv6.conf.all.disable_ipv6 = 1"
                    echo "net.ipv6.conf.default.disable_ipv6 = 1"
                    ;;
            esac
            
            echo "# Additional kernel hardening"
            echo "kernel.sysrq = 0"
            echo "kernel.core_uses_pid = 1"
            echo "kernel.dmesg_restrict = 1"
            echo "kernel.yama.ptrace_scope = 1"
            
        } | sudo tee /etc/sysctl.d/99-security.conf > /dev/null
        
        # Apply sysctl settings
        sudo sysctl -p /etc/sysctl.d/99-security.conf
        clear_terminal
        echo "Kernel parameters have been hardened."
    fi
}

# Function to set up intrusion detection with auditd
setup_auditd() {
    if confirm "Do you want to set up auditd for system auditing?"; then
        echo "Setting up auditd... Please wait."
        if [ -f /etc/debian_version ]; then
            sudo apt install auditd audispd-plugins -y
        elif [ -f /etc/redhat-release ]; then
            sudo dnf install audit audit-libs -y
        fi
        
        # Configure basic audit rules
        {
            echo "# Monitor changes to authentication configuration"
            echo "-w /etc/pam.d/ -p wa -k auth_changes"
            echo "-w /etc/nsswitch.conf -p wa -k auth_changes"
            echo "-w /etc/ssh/sshd_config -p wa -k auth_changes"
            
            echo "# Monitor privileged commands"
            echo "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -k privileged_actions"
            
            echo "# Monitor file system mounts"
            echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k mount_operations"
            echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -k mount_operations"
            
            echo "# Monitor user/group modifications"
            echo "-w /etc/group -p wa -k group_changes"
            echo "-w /etc/passwd -p wa -k passwd_changes"
            echo "-w /etc/shadow -p wa -k shadow_changes"
            
            echo "# Monitor network configurations"
            echo "-w /etc/hosts -p wa -k network_changes"
            echo "-w /etc/network/ -p wa -k network_changes"
            
            echo "# Monitor system startup scripts"
            echo "-w /etc/init.d/ -p wa -k init_changes"
            echo "-w /etc/systemd/ -p wa -k systemd_changes"
            
        } | sudo tee -a /etc/audit/rules.d/audit.rules > /dev/null
        
        # Enable and restart auditd
        sudo systemctl enable auditd
        sudo systemctl restart auditd
        clear_terminal
        echo "Auditd has been set up for system auditing."
    fi
}

# Function to enforce password policy
enforce_password_policy() {
    if confirm "Do you want to enforce a strong password policy?"; then
        echo "Setting up password policy... Please wait."
        if [ -f /etc/debian_version ]; then
            sudo apt install libpam-pwquality -y
        elif [ -f /etc/redhat-release ]; then
            sudo dnf install libpwquality -y
        fi
        
        # Configure password quality
        if [ -f /etc/pam.d/common-password ]; then
            sudo sed -i 's/^password.*requisite.*pam_pwquality\.so.*/password    requisite     pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 reject_username enforce_for_root/' /etc/pam.d/common-password 2>/dev/null || true
        elif [ -f /etc/pam.d/system-auth ]; then
            # For RHEL/CentOS systems
            sudo sed -i 's/^password.*requisite.*pam_pwquality\.so.*/password    requisite     pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 reject_username enforce_for_root/' /etc/pam.d/system-auth 2>/dev/null || true
        fi
        
        # Ask for password expiration policy
        if confirm "Do you want to configure password expiration policy?"; then
            echo "Default values: Maximum age: 90 days, Minimum age: 1 day, Warning period: 7 days"
            
            read -r -p "Enter maximum password age in days (leave empty for default 90): " pass_max_days
            read -r -p "Enter minimum password age in days (leave empty for default 1): " pass_min_days  
            read -r -p "Enter password expiration warning period in days (leave empty for default 7): " pass_warn_age
            
            # Apply settings with defaults if not specified
            [[ -n "$pass_max_days" ]] && sudo sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   $pass_max_days/" /etc/login.defs || sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
            [[ -n "$pass_min_days" ]] && sudo sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   $pass_min_days/" /etc/login.defs || sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
            [[ -n "$pass_warn_age" ]] && sudo sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE   $pass_warn_age/" /etc/login.defs || sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
            
            echo "Password expiration policy has been configured."
        fi
        
        clear_terminal
        echo "Password policy has been enforced."
    fi
}

# Function to secure critical files
secure_critical_files() {
    if confirm "Do you want to secure critical system files?"; then
        echo "Securing critical system files... Please wait."
        
        # Restrict access to critical files
        sudo chmod 644 /etc/passwd
        sudo chmod 644 /etc/group
        sudo chmod 600 /etc/shadow
        sudo chmod 600 /etc/gshadow
        
        # Ask about immutable flag (warning, can be problematic for system updates)
        if command -v chattr &> /dev/null; then
            if confirm "Do you want to set the immutable flag on critical files? (Warning: This may interfere with system updates)"; then
                sudo chattr +i /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null || true
                echo "Immutable flags have been set. Use 'sudo chattr -i <file>' to remove them when needed."
            fi
        fi
        
        clear_terminal
        echo "Critical system files have been secured."
    fi
}

# Function to enable automatic security updates
enable_auto_updates() {
    if confirm "Do you want to enable automatic security updates?"; then
        echo "Enabling automatic security updates... Please wait."
        if [ -f /etc/debian_version ]; then
            sudo apt install unattended-upgrades -y
            sudo dpkg-reconfigure --priority=low unattended-upgrades
            clear_terminal
            echo "Automatic security updates have been enabled."
        elif [ -f /etc/redhat-release ]; then
            sudo dnf install dnf-automatic -y
            sudo systemctl enable --now dnf-automatic.timer
            clear_terminal
            echo "Automatic security updates have been enabled."
        fi
    fi
}

# Function to configure time synchronization
configure_time_sync() {
    if confirm "Do you want to configure time synchronization?"; then
        echo "Configuring time synchronization... Please wait."
        if [ -f /etc/debian_version ]; then
            sudo apt install chrony -y
            sudo systemctl enable chrony
            sudo systemctl start chrony
        elif [ -f /etc/redhat-release ]; then
            sudo dnf install chrony -y
            sudo systemctl enable chrony
            sudo systemctl start chrony
        fi
        clear_terminal
        echo "Time synchronization has been configured."
    fi
}

# Function to secure shared memory
secure_shared_memory() {
    if confirm "Do you want to secure shared memory?"; then
        echo "Securing shared memory... Please wait."
        if [ -f /etc/debian_version ] || [ -f /etc/redhat-release ]; then
            echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" | sudo tee -a /etc/fstab
        fi
        clear_terminal
        echo "Shared memory has been secured."
    fi
}

# Function to install and configure Logwatch
setup_logwatch() {
    if confirm "Do you want to install and configure Logwatch?"; then
        echo "Installing and configuring Logwatch... Please wait."
        if [ -f /etc/debian_version ]; then
            sudo apt install logwatch -y
        elif [ -f /etc/redhat-release ]; then
            sudo dnf install logwatch -y
        fi
        read -r -p "Enter the email address for Logwatch reports: " email
        sudo sed -i "s/^MailTo.*/MailTo = $email/" /usr/share/logwatch/default.conf/logwatch.conf
        sudo sed -i "s/^Range.*/Range = yesterday/" /usr/share/logwatch/default.conf/logwatch.conf
        sudo sed -i "s/^Detail.*/Detail = Low/" /usr/share/logwatch/default.conf/logwatch.conf
        clear_terminal
        echo "Logwatch has been installed and configured."
    fi
}

# Main script execution
update_system
create_user
disable_root_ssh
setup_ssh_key_auth
harden_ssh
setup_firewall
setup_fail2ban
secure_network_protocols
harden_kernel_parameters
setup_auditd
enforce_password_policy
secure_critical_files
enable_auto_updates
configure_time_sync
secure_shared_memory
setup_logwatch

echo "Initial Linux server setup is complete."

