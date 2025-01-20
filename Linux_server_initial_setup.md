![linux-server](https://gist.github.com/user-attachments/assets/5bf6a8f0-dab4-41d8-8030-9de9f6e3eb7a)

# Initial Linux Server Setup Guide

This guide covers the initial setup process for a new Linux server, focusing on basic security and maintenance tasks.

## 1. Update and Upgrade System Packages (Must-Do)

Keeping your system packages up to date is crucial for security and stability.


### Debian/Ubuntu based systems
```sh
sudo apt update && sudo apt upgrade -y
```

- `sudo apt update`: Updates the package lists for upgrades and new package installations.
- `sudo apt upgrade -y`: Upgrades all the installed packages to their latest versions. The `-y` flag automatically confirms the upgrade.

### RHEL/CentOS/Fedora based systems
```sh
sudo dnf update -y
```

- `sudo dnf update -y`: Updates all the installed packages to their latest versions. The `-y` flag automatically confirms the update.

### Arch Linux based systems
```sh
sudo pacman -Syu
```

- `sudo pacman -Syu`: Updates the package lists and upgrades all the installed packages to their latest versions.

## 2. Create a New User and Grant Sudo Privileges (Must-Do)

It's a good practice to avoid using the root account for daily operations.

### Debian/Ubuntu based systems
```sh
# Replace 'newuser' with your desired username
sudo adduser newuser
sudo usermod -aG sudo newuser
```

- `sudo adduser newuser`: Creates a new user with the username `newuser`.
- `sudo usermod -aG sudo newuser`: Adds the new user to the `sudo` group, granting them administrative privileges.

### RHEL/CentOS/Fedora based systems
```sh
# Replace 'newuser' with your desired username
sudo adduser newuser
sudo usermod -aG wheel newuser
```

- `sudo adduser newuser`: Creates a new user with the username `newuser`.
- `sudo usermod -aG wheel newuser`: Adds the new user to the `wheel` group, granting them administrative privileges.


### Arch Linux based systems
```sh
# Replace 'newuser' with your desired username
sudo useradd -m -G wheel newuser
sudo passwd newuser
```

- `sudo useradd -m -G wheel newuser`: Creates a new user with the username `newuser` and adds them to the `wheel` group.
- `sudo passwd newuser`: Sets a password for the new user.

## 3. Disable Root User Login via SSH (Recommended)

Disabling root login over SSH adds an extra layer of security.

Edit the SSH configuration file:

```sh
sudo nano /etc/ssh/sshd_config
```

Find and change the following line:

```sh
PermitRootLogin no
```

- `PermitRootLogin no`: Disables SSH login for the root user.

Restart the SSH service:

```sh
sudo systemctl restart ssh  # Debian/Ubuntu
sudo systemctl restart sshd # RHEL/CentOS/Fedora or Arch Linux
```

- `sudo systemctl restart ssh`: Restarts the SSH service to apply the changes.

## 4. Disable SSH Login with Password and Allow SSH with Authorized Key Only (Recommended)

Using SSH key authentication is more secure than password-based authentication.

Generate an SSH key pair on your local machine:

```sh
ssh-keygen -t rsa -b 4096
```

- `ssh-keygen -t rsa -b 4096`: Generates a new SSH key pair using the RSA algorithm with a 4096-bit key length.

Copy the public key to the server:

```sh
ssh-copy-id newuser@your_server_ip
```

- `ssh-copy-id newuser@your_server_ip`: Copies your public key to the server's authorized keys file for the `newuser` account.

Edit the SSH configuration file:

```sh
sudo nano /etc/ssh/sshd_config
```

Find and change the following lines:

```sh
PasswordAuthentication no
PubkeyAuthentication yes
```

- `PasswordAuthentication no`: Disables password authentication for SSH.
- `PubkeyAuthentication yes`: Enables public key authentication for SSH.

Restart the SSH service:

```sh
sudo systemctl restart ssh  # Debian/Ubuntu
sudo systemctl restart sshd # RHEL/CentOS/Fedora or Arch Linux
```

- `sudo systemctl restart ssh`: Restarts the SSH service to apply the changes.

## 5. Setup UFW (Uncomplicated Firewall) (Must-Do)

A firewall protects your server by controlling incoming and outgoing network traffic.

### Debian/Ubuntu based systems

Install UFW:

```sh
sudo apt install ufw -y
```

- `sudo apt install ufw -y`: Installs the UFW firewall package.

Allow OpenSSH through the firewall:

```sh
sudo ufw allow OpenSSH
```

- `sudo ufw allow OpenSSH`: Allows SSH connections through the firewall.

Enable the firewall:

```sh
sudo ufw enable
```

- `sudo ufw enable`: Enables the UFW firewall.

### RHEL/CentOS/Fedora and Arch Linux based systems

Install and configure `firewalld` as UFW is not typically used on these distributions.

Install `firewalld`:

```sh
sudo dnf install firewalld -y  # RHEL/CentOS/Fedora
sudo pacman -S firewalld       # Arch Linux
```

- `sudo dnf install firewalld -y`: Installs the `firewalld` package on RHEL/CentOS/Fedora.
- `sudo pacman -S firewalld`: Installs the `firewalld` package on Arch Linux.

Start and enable `firewalld`:

```sh
sudo systemctl start firewalld
sudo systemctl enable firewalld
```

- `sudo systemctl start firewalld`: Starts the `firewalld` service.
- `sudo systemctl enable firewalld`: Enables the `firewalld` service to start at boot.

Allow OpenSSH through the firewall:

```sh
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload
```

- `sudo firewall-cmd --permanent --add-service=ssh`: Allows SSH connections through the firewall.
- `sudo firewall-cmd --reload`: Reloads the firewall rules to apply the changes.

## 6. Setup Fail2Ban for SSH Jail (Recommended)

Fail2Ban helps protect your server from brute-force attacks by banning IPs that show malicious signs.

### Debian/Ubuntu and RHEL/CentOS/Fedora based systems
Install Fail2Ban:

```sh
sudo apt install fail2ban -y    # Debian/Ubuntu
sudo dnf install fail2ban -y    # RHEL/CentOS/Fedora
```

- `sudo apt install fail2ban -y`: Installs the Fail2Ban package.

Create a local configuration file:

```sh
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

- `sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local`: Copies the default configuration file to a local configuration file for customization.

Edit the local configuration file:

```sh
sudo nano /etc/fail2ban/jail.local
```

Find and change the following lines:

```sh
[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
bantime = 3600
findtime = 600
maxretry = 3
```

- `[sshd]`: Section for SSH settings.
- `enabled = true`: Enables the SSH jail.
- `port = ssh`: Specifies the port for SSH (default is 22).
- `logpath = %(sshd_log)s`: Specifies the log file path for SSH logs.
- `bantime = 3600`: Sets the ban time to 1 hour (3600 seconds).
- `findtime = 600`: Sets the time window to 10 minutes (600 seconds) for considering failed attempts.
- `maxretry = 3`: Sets the maximum number of failed attempts before banning.

Restart Fail2Ban:

```sh
sudo systemctl restart fail2ban
```

- `sudo systemctl restart fail2ban`: Restarts the Fail2Ban service to apply the changes.

### Arch Linux based systems

We may use `sshguard` instead of `fail2ban` on Arch Linux.

Install `sshguard`:

```sh
sudo pacman -S sshguard
```

- `sudo pacman -S sshguard`: Installs the `sshguard` package.

Enable and start the `sshguard` service:

```sh
sudo systemctl enable sshguard
sudo systemctl start sshguard
```

- `sudo systemctl enable sshguard`: Enables the `sshguard` service to start at boot.
- `sudo systemctl start sshguard`: Starts the `sshguard` service.


## 7. Enable Automatic Security Updates (Recommended)

Automatic updates help ensure your server stays secure with the latest security patches.

### Debian/Ubuntu based systems
Install the unattended-upgrades package:

```sh
sudo apt install unattended-upgrades -y
```

- `sudo apt install unattended-upgrades -y`: Installs the unattended-upgrades package.

Enable automatic updates:

```sh
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

- `sudo dpkg-reconfigure --priority=low unattended-upgrades`: Configures the package to enable automatic updates.

### RHEL/CentOS/Fedora based systems
Fedora and CentOS systems can use the `dnf-automatic` package for automatic updates.

Install the `dnf-automatic` package:

```sh
sudo dnf install dnf-automatic -y
```

- `sudo dnf install dnf-automatic -y`: Installs the `dnf-automatic` package.

Enable and start the `dnf-automatic` service:

```sh
sudo systemctl enable --now dnf-automatic.timer
```

- `sudo systemctl enable --now dnf-automatic.timer`: Enables and starts the `dnf-automatic` service to run automatically.

### Arch Linux based systems
Automatic updates are not recommended on Arch Linux due to its rolling release nature. It's best to manually update the system regularly.

## 8. Configure Time Synchronization (Optional)

Ensuring your server's time is synchronized can prevent various issues.

### Debian/Ubuntu and RHEL/CentOS/Fedora based systems
Install and enable `chrony`:

```sh
sudo apt install chrony -y  # Debian/Ubuntu
sudo dnf install chrony -y  # RHEL/CentOS/Fedora
sudo systemctl enable chrony    # Debian/Ubuntu and RHEL/CentOS/Fedora
sudo systemctl start chrony     # Debian/Ubuntu and RHEL/CentOS/Fedora
```

- `sudo apt install chrony -y`: Installs the Chrony package.
- `sudo systemctl enable chrony`: Enables the Chrony service to start at boot.
- `sudo systemctl start chrony`: Starts the Chrony service.

### Arch Linux based systems
We can use `ntp` for time synchronization on Arch Linux.

Install and enable `ntp`:

```sh
sudo pacman -S ntp
sudo systemctl enable ntpd
sudo systemctl start ntpd
```

- `sudo pacman -S ntp`: Installs the NTP package.
- `sudo systemctl enable ntpd`: Enables the NTP service to start at boot.
- `sudo systemctl start ntpd`: Starts the NTP service.

## 9. Secure Shared Memory (Optional)

Securing shared memory can help prevent certain types of attacks.

Edit the `/etc/fstab` file:

```sh
sudo nano /etc/fstab
```

### Debian/Ubuntu and RHEL/CentOS/Fedora based systems
Add the following line at the end of the file: 

```sh
tmpfs     /run/shm     tmpfs     defaults,noexec,nosuid     0     0
```

- `tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0`: Mounts the shared memory with `noexec` and `nosuid` options to prevent execution of binaries and set-user-identifier bits.

### Arch Linux based systems
Add the following line at the end of the file:

```sh
tmpfs     /dev/shm     tmpfs     defaults,noexec,nosuid     0     0
```

- `tmpfs /dev/shm tmpfs defaults,noexec,nosuid 0 0`: Mounts the shared memory with `noexec` and `nosuid` options to prevent execution of binaries and set-user-identifier bits.

## 10. Install and Configure Logwatch for System Monitoring (Optional)

Logwatch provides a daily summary of system logs.

Install Logwatch:

```sh
sudo apt install logwatch -y    # Debian/Ubuntu
sudo dnf install logwatch -y    # RHEL/CentOS/Fedora
sudo pacman -S logwatch         # Arch Linux
```

- `sudo apt install logwatch -y`: Installs the Logwatch package.

Edit the Logwatch configuration file:

```sh
sudo nano /usr/share/logwatch/default.conf/logwatch.conf
```

Find and change the following lines:

```sh
MailTo = your_email@example.com
Range = yesterday
Detail = Low
```

- `MailTo = your_email@example.com`: Sets the email address to send the log reports to.
- `Range = yesterday`: Sets the report range to the previous day.
- `Detail = Low`: Sets the detail level of the report to low.

## 11. Regular Backups (Recommended)

Regular backups are crucial for data recovery in case of failures.

Set up regular backups using tools like `rsnapshot`, `rsync`, or a cloud-based backup service. Ensure you have a strategy for both local and offsite backups.

## 12. Monitor System Performance (Optional)

Monitoring tools help you keep an eye on your server's health and performance.

Install and configure tools like `htop`, `netdata`, or `Prometheus` for monitoring your server's performance and health.

```sh
sudo apt install htop -y    # Debian/Ubuntu
sudo dnf install htop -y    # RHEL/CentOS/Fedora
sudo pacman -S htop         # Arch Linux
```

- `sudo apt install htop -y`: Installs `htop`, an interactive process viewer.

## Conclusion

By following these steps, you will significantly improve the security and stability of your Linux server. Regular maintenance and monitoring are crucial to ensure your server remains secure and performs optimally.

If you see any mistake or any better approach, feel free to share them in the comment.

## Regards
[SR Tamim](https://sr-tamim.vercel.app)

[![sr-tamim's Profilator](https://profilator.deno.dev/sr-tamim?v=1.0.0.alpha.4)](https://github.com/sr-tamim)