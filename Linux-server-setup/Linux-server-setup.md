![linux-server](https://github.com/user-attachments/assets/6e89ec54-052b-404a-827c-908640d9dd13)

# Initial Linux Server Setup Guide

This guide covers the initial setup process for a new Linux server, focusing on basic security and maintenance tasks. The guide now includes advanced security measures like network protocol security, kernel hardening, intrusion detection, password policies and critical file security.

#### For those interested in automating this setup process, please refer to the [Linux Server Setup Script](Linux-server-setup-script.md)

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
sudo systemctl restart sshd # RHEL/CentOS/Fedora
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

Add some SSH configuration in a new .conf file:

```sh
# make sure that drop-in directory exists
sudo mkdir -p /etc/ssh/sshd_config.d

# create a new .conf file
sudo nano /etc/ssh/sshd_config.d/ssh_key_auth.conf
```

Write the following configuration in the file:

```sh
PasswordAuthentication no
PubkeyAuthentication yes
```

- `PasswordAuthentication no`: Disables password authentication for SSH.
- `PubkeyAuthentication yes`: Enables public key authentication for SSH.

Save the file (`Ctrl + S`) and exit (`Ctrl + X`). Then, reload the SSH service:

```sh
sudo systemctl restart ssh  # Debian/Ubuntu
sudo systemctl restart sshd # RHEL/CentOS/Fedora
```

- `sudo systemctl restart ssh`: Restarts the SSH service to apply the changes.

## 5. Further Harden SSH Configuration (Recommended)

Implementing additional SSH hardening measures helps protect your server from various attacks.

Create a new SSH hardening configuration file:

```sh
sudo mkdir -p /etc/ssh/sshd_config.d
sudo nano /etc/ssh/sshd_config.d/hardening.conf
```

Add the following security configurations:

```sh
# SSH hardening configuration
Protocol 2
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitEmptyPasswords no

# Optional: restrict SSH access to specific users
# AllowUsers user1 user2

# Optional: restrict SSH access to specific groups
# AllowGroups sshusers admins

# Strong encryption algorithms
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# Increase verbosity of logging
LogLevel VERBOSE
```

- `Protocol 2`: Uses only SSH protocol version 2 which is more secure
- `MaxAuthTries 3`: Limits authentication attempts to 3 before disconnecting
- `MaxSessions 2`: Limits the number of sessions per connection
- `LoginGraceTime 30`: Sets timeout to 30 seconds for authentication
- `ClientAliveInterval 300`: Sends a keepalive message every 300 seconds
- `ClientAliveCountMax 2`: Disconnects after 2 missed client responses
- `X11Forwarding no`: Disables X11 forwarding which can be a security risk
- `AllowAgentForwarding no`: Disables SSH agent forwarding
- `AllowTcpForwarding no`: Disables TCP forwarding
- `PermitEmptyPasswords no`: Prohibits empty passwords
- Strong encryption algorithms: Uses only high-security ciphers and algorithms

Restart the SSH service to apply the changes:

```sh
sudo systemctl restart ssh  # Debian/Ubuntu
sudo systemctl restart sshd # RHEL/CentOS/Fedora
```

## 6. Setup UFW (Uncomplicated Firewall) (Must-Do)

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

### RHEL/CentOS/Fedora based systems

Install and configure `firewalld` as UFW is not typically used on these distributions.

Install `firewalld`:

```sh
sudo dnf install firewalld -y  # RHEL/CentOS/Fedora
```

- `sudo dnf install firewalld -y`: Installs the `firewalld` package on RHEL/CentOS/Fedora.

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

## 7. Setup Fail2Ban for SSH Jail (Recommended)

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

## 8. Enable Automatic Security Updates (Recommended)

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

## 9. Configure Time Synchronization (Optional)

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

## 10. Secure Shared Memory (Optional)

Securing shared memory can help prevent certain types of attacks.

Edit the `/etc/fstab` file:

```sh
sudo nano /etc/fstab
```

Add the following line at the end of the file:

```sh
tmpfs     /run/shm     tmpfs     defaults,noexec,nosuid     0     0
```

- `tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0`: Mounts the shared memory with `noexec` and `nosuid` options to prevent execution of binaries and set-user-identifier bits.

## 11. Secure Network Protocols (Recommended)

Disabling unnecessary network protocols can reduce the attack surface of your server.

```sh
sudo nano /etc/modprobe.d/disable-protocols.conf
```

Add the following lines as needed:

```sh
# Disable unused network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
```

- `install dccp /bin/true`: Disables the Datagram Congestion Control Protocol, which is rarely used.
- `install sctp /bin/true`: Disables the Stream Control Transmission Protocol, typically used in telecom applications.
- `install rds /bin/true`: Disables the Reliable Datagram Sockets, mainly used in high-performance computing.
- `install tipc /bin/true`: Disables the Transparent Inter-Process Communication protocol, a specialized cluster protocol.

## 12. Harden Kernel Parameters (Recommended)

Kernel hardening helps protect against various network-based attacks.

Create or edit the kernel security configuration:

```sh
sudo nano /etc/sysctl.d/99-security.conf
```

Add the following configuration:

```sh
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Additional kernel hardening
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
```

Apply the changes:

```sh
sudo sysctl -p /etc/sysctl.d/99-security.conf
```

## 13. Set up Intrusion Detection with Auditd (Recommended)

Auditd helps monitor system calls and security events.

### Debian/Ubuntu and RHEL/CentOS/Fedora based systems

Install auditd:

```sh
sudo apt install auditd audispd-plugins -y    # Debian/Ubuntu
sudo dnf install audit audit-libs -y          # RHEL/CentOS/Fedora
```

Configure basic audit rules:

```sh
sudo nano /etc/audit/rules.d/audit.rules
```

Add the following rules:

```sh
# Monitor changes to authentication configuration
-w /etc/pam.d/ -p wa -k auth_changes
-w /etc/nsswitch.conf -p wa -k auth_changes
-w /etc/ssh/sshd_config -p wa -k auth_changes

# Monitor user/group modifications
-w /etc/group -p wa -k group_changes
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
```

Enable and restart auditd:

```sh
sudo systemctl enable auditd
sudo systemctl restart auditd
```

## 14. Enforce Password Policy (Recommended)

Implement strong password policies to enhance security.

### Debian/Ubuntu and RHEL/CentOS/Fedora based systems

Install password quality packages:

```sh
sudo apt install libpam-pwquality -y    # Debian/Ubuntu
sudo dnf install libpwquality -y        # RHEL/CentOS/Fedora
```

Configure password strength requirements:

For Debian/Ubuntu:

```sh
sudo nano /etc/pam.d/common-password
```

For RHEL/CentOS/Fedora:

```sh
sudo nano /etc/pam.d/system-auth
```

Add or modify:

```sh
password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 reject_username enforce_for_root
```

Configure password expiration policy:

```sh
sudo nano /etc/login.defs
```

Set the following parameters:

```sh
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_WARN_AGE   7
```

- `PASS_MAX_DAYS 90`: Forces users to change passwords every 90 days
- `PASS_MIN_DAYS 1`: Prevents users from changing passwords more than once per day
- `PASS_WARN_AGE 7`: Warns users 7 days before password expiration

## 15. Secure Critical Files (Recommended)

Set secure permissions for critical system files:

```sh
sudo chmod 644 /etc/passwd
sudo chmod 644 /etc/group
sudo chmod 600 /etc/shadow
sudo chmod 600 /etc/gshadow
```

Optionally, set immutable flags on critical files (use with caution):

```sh
sudo chattr +i /etc/passwd /etc/shadow /etc/group /etc/gshadow
```

To remove immutable flags when needed:

```sh
sudo chattr -i /etc/passwd /etc/shadow /etc/group /etc/gshadow
```

## 16. Install and Configure Logwatch for System Monitoring (Optional)

Logwatch provides a daily summary of system logs.

Install Logwatch:

```sh
sudo apt install logwatch -y    # Debian/Ubuntu
sudo dnf install logwatch -y    # RHEL/CentOS/Fedora
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

## 17. Regular Backups (Recommended)

Regular backups are crucial for data recovery in case of failures.

Set up regular backups using tools like `rsnapshot`, `rsync`, or a cloud-based backup service. Ensure you have a strategy for both local and offsite backups.

## 18. Monitor System Performance (Optional)

Monitoring tools help you keep an eye on your server's health and performance.

Install and configure tools like `htop`, `netdata`, or `Prometheus` for monitoring your server's performance and health.

```sh
sudo apt install htop -y    # Debian/Ubuntu
sudo dnf install htop -y    # RHEL/CentOS/Fedora
```

- `sudo apt install htop -y`: Installs `htop`, an interactive process viewer.

## 19. Docker and Nginx Security (When Applicable)

If your server will run Docker containers and use Nginx as a web server or reverse proxy, additional security measures should be implemented.

### Securing Docker

```sh
# Create a more secure Docker daemon configuration
sudo mkdir -p /etc/docker
sudo nano /etc/docker/daemon.json
```

Add the following configuration:

```json
{
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "userns-remap": "default",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "icc": false
}
```

- `live-restore`: Keeps containers running during Docker daemon upgrades
- `userland-proxy`: Disables the userland proxy for improved performance
- `no-new-privileges`: Prevents container processes from gaining new privileges
- `userns-remap`: Enables user namespace remapping for better isolation
- `icc`: Disables inter-container communication by default for better isolation

Create Docker group and add your user to it:

```sh
sudo groupadd docker
sudo usermod -aG docker $USER
```

Add Docker content trust environment variable for signed images:

```sh
echo "export DOCKER_CONTENT_TRUST=1" >> ~/.bashrc
```

### Securing Nginx

```sh
# Install Nginx
sudo apt install nginx -y    # Debian/Ubuntu
sudo dnf install nginx -y    # RHEL/CentOS/Fedora

# Generate strong Diffie-Hellman parameters
sudo openssl dhparam -out /etc/nginx/dhparam.pem 2048

# Edit Nginx configuration
sudo nano /etc/nginx/nginx.conf
```

Add these security settings to your Nginx configuration:

```nginx
# Security headers
add_header X-Content-Type-Options nosniff;
add_header X-Frame-Options SAMEORIGIN;
add_header X-XSS-Protection "1; mode=block";
add_header Content-Security-Policy "default-src 'self'";
add_header Referrer-Policy strict-origin-when-cross-origin;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# SSL settings
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_dhparam /etc/nginx/dhparam.pem;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
```

### Using Docker with Nginx

When using Docker and Nginx together:

1. Create a dedicated bridge network for your containers:
```sh
docker network create --driver bridge web-network
```

2. Use Docker volumes instead of bind mounts where possible:
```sh
docker volume create nginx-config
docker volume create nginx-data
```

3. Run containers with least privilege:
```sh
docker run --name nginx -d \
  --restart=unless-stopped \
  --network web-network \
  --read-only \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  -p 80:80 -p 443:443 \
  -v nginx-config:/etc/nginx \
  -v nginx-data:/var/www/html \
  nginx:alpine
```

4. Regularly scan your Docker images for vulnerabilities:
```sh
# Install Trivy vulnerability scanner
sudo apt install trivy -y    # Debian/Ubuntu
sudo dnf install trivy -y    # RHEL/CentOS/Fedora

# Scan an image
trivy image nginx:alpine
```

5. Implement Docker Content Trust for verified images:
```sh
export DOCKER_CONTENT_TRUST=1
docker pull nginx:alpine
```

## Conclusion

By following these steps, you will significantly improve the security and stability of your Linux server. The advanced security measures including network hardening, kernel security, intrusion detection, password policies, and specialized Docker/Nginx configurations add multiple layers of protection to your server infrastructure. Regular maintenance and monitoring are crucial to ensure your server remains secure and performs optimally.

If you see any mistake or any better approach, feel free to share them in the comment.

### For those interested in automating this setup process, please refer to the [Linux Server Setup Script](Linux-server-setup-script.md)

## Regards

[SR Tamim](https://sr-tamim.vercel.app)

[![sr-tamim's Profilator](https://profilator.deno.dev/sr-tamim?v=1.0.0.alpha.4)](https://github.com/sr-tamim)
