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
setup_firewall
setup_fail2ban
enable_auto_updates
configure_time_sync
secure_shared_memory
setup_logwatch

echo "Initial Linux server setup is complete."

