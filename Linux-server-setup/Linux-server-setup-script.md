# Linux Server Setup Script

This script automates the initial setup process for a new Linux server, focusing on basic security and maintenance tasks. It is designed to save time and ensure consistency when configuring multiple servers.

## Why Use This Script?

Manually setting up a Linux server can be time-consuming and prone to errors. This script automates the essential steps, ensuring that your server is configured securely and efficiently. It covers:

1. Updating and upgrading system packages
2. Creating a new user and granting sudo privileges
3. Disabling root login via SSH
4. Setting up SSH key authentication
5. Configuring a firewall
6. Setting up Fail2Ban or sshguard
7. Enabling automatic security updates
8. Configuring time synchronization
9. Securing shared memory
10. Installing and configuring Logwatch

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

## Conclusion

Using this script will help you quickly and securely set up your Linux server, ensuring that all essential security and maintenance tasks are performed consistently.

For more detailed information on each step, refer to the [Initial Linux Server Setup Guide](README.md).

