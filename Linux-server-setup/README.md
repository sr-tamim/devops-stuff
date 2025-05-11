# Linux Server Setup Script

This script automates the initial setup process for a new Linux server, focusing on basic security and maintenance tasks. It is designed to save time and ensure consistency when configuring multiple servers.

## Why Use This Script?

Manually setting up a Linux server can be time-consuming and prone to errors. This script automates the essential steps, ensuring that your server is configured securely and efficiently. It covers:

1. Updating and upgrading system packages
2. Creating a new user and granting sudo privileges
3. Disabling root login via SSH
4. Setting up SSH key authentication
5. Further hardening SSH configuration
6. Configuring a firewall
7. Setting up Fail2Ban
8. Securing network protocols
9. Hardening kernel parameters
10. Setting up intrusion detection with auditd
11. Enforcing password policy with expiration controls
12. Securing critical system files
13. Enabling automatic security updates
14. Configuring time synchronization
15. Securing shared memory
16. Installing and configuring Logwatch
17. Installing and securing Docker
18. Installing and securing Nginx
19. Configuring Docker with Nginx as a secure reverse proxy

## How to Use This Script

1. **Download the Script**: Save the `Linux-server-setup.sh` script to your local machine.
    - [Download Linux-server-setup.sh](Linux-server-setup.sh)

2. **Make the Script Executable**: Run the following command to make the script executable:

    ```sh
    chmod +x Linux-server-setup.sh
    ```

3. **Run the Script with Sudo Privileges**: Execute the script with sudo privileges to perform the setup tasks:

    ```sh
    sudo ./Linux-server-setup.sh
    ```

4. **Follow the Prompts**: The script will prompt you for confirmation before performing each task. Follow the prompts to complete the setup.

## Key Security Features

The script implements multiple layers of security through:

1. **Access Control**: Creates non-root users, disables root SSH access, and enforces key-based authentication
2. **Network Security**: Configures firewall rules, disables unnecessary protocols, and hardens the kernel against network attacks
3. **Intrusion Prevention**: Sets up Fail2Ban to block malicious login attempts
4. **Container Security**: Implements Docker security best practices, including least privilege configurations and regular vulnerability scanning
5. **Web Server Hardening**: Configures Nginx with secure headers, strong SSL/TLS settings, and restrictive permissions
4. **System Monitoring**: Configures auditd for system auditing and Logwatch for log monitoring
5. **Password Management**: Enforces strong password requirements and expiration policies
6. **File System Security**: Applies appropriate permissions and optional immutable attributes to critical files

## Conclusion

Using this script will help you quickly and securely set up your Linux server, implementing multiple layers of security hardening that follow industry best practices. All essential security and maintenance tasks are performed consistently across your servers, reducing the risk of configuration errors.

For more detailed information on each step, refer to the [Initial Linux Server Setup Guide](README.md).
