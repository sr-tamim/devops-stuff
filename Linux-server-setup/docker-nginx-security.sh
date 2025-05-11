#!/bin/bash

# Function to secure Docker installation
secure_docker_installation() {
    if confirm "Do you want to install and secure Docker?"; then
        echo "Installing and securing Docker... Please wait."
        
        # Install Docker based on distribution
        if [ -f /etc/debian_version ]; then
            # Update the apt package index
            sudo apt-get update
            
            # Install packages to allow apt to use a repository over HTTPS
            sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common gnupg lsb-release
            
            # Add Docker's official GPG key
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
            
            # Set up the stable repository
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            
            # Install Docker Engine
            sudo apt-get update
            sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        elif [ -f /etc/redhat-release ]; then
            # Install required packages
            sudo dnf -y install dnf-plugins-core
            
            # Add Docker repository
            sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
            
            # Install Docker
            sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        fi
        
        # Start and enable Docker service
        sudo systemctl start docker
        sudo systemctl enable docker
        
        # Create docker group and add user to it
        read -r -p "Enter the username to add to the Docker group (leave empty for current user): " docker_user
        if [ -z "$docker_user" ]; then
            docker_user=$(whoami)
        fi
        
        sudo groupadd -f docker
        sudo usermod -aG docker "$docker_user"
        echo "User $docker_user has been added to the Docker group. Log out and back in for changes to take effect."
        
        # Create a daemon.json file with security settings
        echo "Creating secure Docker daemon configuration..."
        
        # Create Docker daemon.json with security settings
        sudo mkdir -p /etc/docker
        cat <<EOF | sudo tee /etc/docker/daemon.json > /dev/null
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
    "icc": false,
    "default-ulimit": {
        "nofile": {
            "Name": "nofile",
            "Hard": 64000,
            "Soft": 64000
        }
    }
}
EOF

        # Create Docker security systemd drop-in directory
        sudo mkdir -p /etc/systemd/system/docker.service.d/
        
        # Create a drop-in file to add security options
        cat <<EOF | sudo tee /etc/systemd/system/docker.service.d/override.conf > /dev/null
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd --iptables=false
EOF

        # Reload systemd, restart Docker
        sudo systemctl daemon-reload
        sudo systemctl restart docker
        
        # Configure Docker to start on boot
        sudo systemctl enable docker
        
        # Apply default Docker content trust
        echo "export DOCKER_CONTENT_TRUST=1" | sudo tee -a /etc/profile.d/docker-content-trust.sh > /dev/null
        sudo chmod +x /etc/profile.d/docker-content-trust.sh

        # Create directory for Docker security audit
        sudo mkdir -p /etc/docker/security-audits
        
        # Set up weekly Docker security audit script
        cat <<'EOF' | sudo tee /etc/docker/security-audits/weekly-audit.sh > /dev/null
#!/bin/bash
DATE=$(date +%Y-%m-%d)
AUDIT_DIR="/etc/docker/security-audits"
LOG_FILE="$AUDIT_DIR/audit-$DATE.log"

# Check for running containers
echo "=== Running containers on $DATE ===" > "$LOG_FILE" 
docker ps -a >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Check images
echo "=== Docker images on $DATE ===" >> "$LOG_FILE"
docker images >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Check networks
echo "=== Docker networks on $DATE ===" >> "$LOG_FILE"
docker network ls >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Check volumes
echo "=== Docker volumes on $DATE ===" >> "$LOG_FILE"
docker volume ls >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Check if any containers are running in privileged mode
echo "=== Privileged containers on $DATE ===" >> "$LOG_FILE"
docker ps --quiet --all | xargs -I % docker inspect --format='Name: {% .Name %}, Privileged: {% .HostConfig.Privileged %}' % | grep "Privileged: true" >> "$LOG_FILE" || echo "No privileged containers detected" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Keep only the latest 10 audit logs
find "$AUDIT_DIR" -name "audit-*.log" -type f | sort -r | tail -n +11 | xargs --no-run-if-empty rm
EOF

        # Make the audit script executable
        sudo chmod +x /etc/docker/security-audits/weekly-audit.sh
        
        # Create a weekly cron job for security audit
        cat <<EOF | sudo tee /etc/cron.weekly/docker-security-audit > /dev/null
#!/bin/bash
/etc/docker/security-audits/weekly-audit.sh
EOF
        
        sudo chmod +x /etc/cron.weekly/docker-security-audit
        
        # Configure Docker firewall rules
        echo "Configuring firewall rules for Docker..."
        
        if [ -f /etc/debian_version ]; then
            # UFW for Ubuntu/Debian
            # Disable Docker's iptables modifications (we already did this in daemon.json)
            # Configure UFW for Docker
            sudo ufw allow ssh
            sudo ufw allow 80/tcp
            sudo ufw allow 443/tcp
            
            # Only if we need direct access to the Docker API
            # sudo ufw allow 2376/tcp
            
            echo 'y' | sudo ufw enable

        elif [ -f /etc/redhat-release ]; then
            # firewalld for Fedora/RHEL
            sudo systemctl start firewalld
            sudo systemctl enable firewalld
            sudo firewall-cmd --permanent --zone=public --add-service=ssh
            sudo firewall-cmd --permanent --zone=public --add-service=http
            sudo firewall-cmd --permanent --zone=public --add-service=https
            
            # Only if we need direct access to the Docker API
            # sudo firewall-cmd --permanent --zone=public --add-port=2376/tcp
            
            sudo firewall-cmd --reload
        fi
        
        echo "Docker has been installed and secured."
        clear_terminal
    fi
}

# Function to secure Nginx installation
secure_nginx_installation() {
    if confirm "Do you want to set up Nginx with secure configurations?"; then
        echo "Setting up Nginx with secure configurations... Please wait."
        
        # Install Nginx based on distribution
        if [ -f /etc/debian_version ]; then
            sudo apt-get update
            sudo apt-get install -y nginx
        elif [ -f /etc/redhat-release ]; then
            sudo dnf install -y nginx
        fi
        
        # Start and enable Nginx
        sudo systemctl start nginx
        sudo systemctl enable nginx
        
        # Create directory for SSL certificates
        sudo mkdir -p /etc/nginx/ssl
        
        # Generate self-signed certificate for testing (in production, use Let's Encrypt)
        if confirm "Do you want to generate a self-signed SSL certificate for testing?"; then
            sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt -subj "/C=US/ST=State/L=City/O=Organization/CN=example.com"
            sudo chmod 400 /etc/nginx/ssl/nginx.key
        fi
        
        # Create secure Nginx configuration
        echo "Creating secure Nginx configuration..."
        
        # Backup the original nginx.conf
        sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
        
        # Create a new secure nginx.conf
        cat <<EOF | sudo tee /etc/nginx/nginx.conf > /dev/null
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    multi_accept on;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # MIME types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Gzip Settings
    gzip on;
    gzip_disable "msie6";
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    
    # Security Headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'self'; form-action 'self';";
    add_header Referrer-Policy strict-origin-when-cross-origin;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # SSL Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # DH parameters for DHE ciphersuites
    # Generate with: openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048
    # ssl_dhparam /etc/nginx/ssl/dhparam.pem;
    
    # Include site configurations
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

        # Create a secure default site configuration
        cat <<EOF | sudo tee /etc/nginx/sites-available/default > /dev/null
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    
    # Redirect all HTTP requests to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;
    
    # SSL certificates
    ssl_certificate /etc/nginx/ssl/nginx.crt;
    ssl_certificate_key /etc/nginx/ssl/nginx.key;
    
    # Document root
    root /var/www/html;
    index index.html index.htm;
    
    # Security headers set at http level for all servers
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # Disable access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Restricting access to backups, source code, etc.
    location ~* \.(bak|config|sql|fla|md|psd|ini|log|sh|inc|swp|dist|git|svn)$ {
        deny all;
    }
    
    # Additional nginx security rules
    location ~ /\.(?!well-known).* {
        deny all;
    }
}
EOF

        # Generate DH parameters (will take some time, comment out if not needed)
        if confirm "Do you want to generate Diffie-Hellman parameters? This may take several minutes but improves security."; then
            sudo openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048
            # Uncomment the dhparam line in nginx.conf
            sudo sed -i 's/# ssl_dhparam/ssl_dhparam/' /etc/nginx/nginx.conf
        fi
        
        # Fix write permissions for default HTML directory
        sudo mkdir -p /var/www/html
        sudo chown -R www-data:www-data /var/www/html
        sudo chmod -R 755 /var/www/html
        
        # Create a simple index.html
        echo "<html><body><h1>Secure Nginx Server</h1><p>Configuration successful.</p></body></html>" | sudo tee /var/www/html/index.html > /dev/null
        
        # Test Nginx configuration
        nginx_test=$(sudo nginx -t 2>&1)
        if echo "$nginx_test" | grep -q "successful"; then
            echo "Nginx configuration test passed."
            sudo systemctl reload nginx
            echo "Nginx has been installed and secured."
        else
            echo "Nginx configuration test failed. Please check the configuration:"
            echo "$nginx_test"
            echo "Reverting to backup configuration..."
            sudo cp /etc/nginx/nginx.conf.backup /etc/nginx/nginx.conf
            sudo systemctl reload nginx
        fi
        
        # Configure firewall for Nginx
        echo "Opening ports for Nginx in firewall..."
        if [ -f /etc/debian_version ]; then
            sudo ufw allow 'Nginx Full'
        elif [ -f /etc/redhat-release ]; then
            sudo firewall-cmd --permanent --zone=public --add-service=http
            sudo firewall-cmd --permanent --zone=public --add-service=https
            sudo firewall-cmd --reload
        fi
        
        clear_terminal
        echo "Nginx has been installed with secure configurations."
    fi
}

# Function to secure Docker & Nginx together
configure_docker_with_nginx() {
    if confirm "Do you want to configure Nginx as a reverse proxy for Docker containers?"; then
        echo "Setting up Nginx as a reverse proxy for Docker... Please wait."
        
        # Create Docker network for Nginx and containers
        docker network create --driver bridge nginx-proxy-network
        
        # Create a directory for Docker Compose files
        sudo mkdir -p /opt/docker-compose/nginx-proxy
        
        # Create Docker Compose file for Nginx Proxy
        cat <<EOF | sudo tee /opt/docker-compose/nginx-proxy/docker-compose.yml > /dev/null
version: '3'

services:
  nginx-proxy:
    image: nginx:alpine
    container_name: nginx-proxy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/conf.d:/etc/nginx/conf.d
      - ./nginx/ssl:/etc/nginx/ssl
      - ./nginx/html:/usr/share/nginx/html
      - ./nginx/logs:/var/log/nginx
    networks:
      - nginx-proxy-network

networks:
  nginx-proxy-network:
    external: true
EOF

        # Create directories for Nginx configuration
        sudo mkdir -p /opt/docker-compose/nginx-proxy/nginx/{conf.d,ssl,html,logs}
        
        # Create a sample Nginx proxy configuration
        cat <<EOF | sudo tee /opt/docker-compose/nginx-proxy/nginx/conf.d/default.conf > /dev/null
server {
    listen 80;
    server_name localhost;
    
    # Redirect all HTTP requests to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name localhost;
    
    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/nginx.crt;
    ssl_certificate_key /etc/nginx/ssl/nginx.key;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'self'; form-action 'self';";
    add_header Referrer-Policy strict-origin-when-cross-origin;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Root directory for static content
    root /usr/share/nginx/html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # Example proxy configuration for a Docker container (commented out)
    # location /app1/ {
    #     proxy_pass http://app1:8080/;
    #     proxy_set_header Host \$host;
    #     proxy_set_header X-Real-IP \$remote_addr;
    #     proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    #     proxy_set_header X-Forwarded-Proto \$scheme;
    # }
}
EOF

        # Generate self-signed SSL certificate for Docker Nginx
        sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /opt/docker-compose/nginx-proxy/nginx/ssl/nginx.key \
            -out /opt/docker-compose/nginx-proxy/nginx/ssl/nginx.crt \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
        
        # Create a simple HTML file
        cat <<EOF | sudo tee /opt/docker-compose/nginx-proxy/nginx/html/index.html > /dev/null
<!DOCTYPE html>
<html>
<head>
    <title>Docker Nginx Proxy</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #333;
        }
    </style>
</head>
<body>
    <h1>Docker Nginx Proxy</h1>
    <p>Your Docker Nginx proxy is working correctly.</p>
    <p>Configure additional services by editing the Nginx configuration file.</p>
</body>
</html>
EOF

        # Create a script to help users add services
        cat <<'EOF' | sudo tee /opt/docker-compose/nginx-proxy/add-service.sh > /dev/null
#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <service_name> <container_name> <container_port>"
    echo "Example: $0 api api-container 8080"
    exit 1
fi

SERVICE_NAME="$1"
CONTAINER_NAME="$2"
CONTAINER_PORT="$3"

CONFIG_FILE="/opt/docker-compose/nginx-proxy/nginx/conf.d/default.conf"

# Add service configuration to Nginx
sed -i "/# Example proxy configuration/i \    # Configuration for $SERVICE_NAME\n    location /$SERVICE_NAME/ {\n        proxy_pass http://$CONTAINER_NAME:$CONTAINER_PORT/;\n        proxy_set_header Host \$host;\n        proxy_set_header X-Real-IP \$remote_addr;\n        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto \$scheme;\n    }\n" "$CONFIG_FILE"

echo "Service $SERVICE_NAME has been added to proxy to $CONTAINER_NAME:$CONTAINER_PORT"
echo "Restarting Nginx proxy..."
cd /opt/docker-compose/nginx-proxy && docker-compose restart nginx-proxy
EOF

        # Make the script executable
        sudo chmod +x /opt/docker-compose/nginx-proxy/add-service.sh
        
        # Start the Nginx proxy
        cd /opt/docker-compose/nginx-proxy && sudo docker-compose up -d
        
        # Create a README file with instructions
        cat <<EOF | sudo tee /opt/docker-compose/nginx-proxy/README.md > /dev/null
# Docker Nginx Proxy Setup

This directory contains a Docker Compose configuration for running Nginx as a reverse proxy for Docker containers.

## Directory Structure

- \`docker-compose.yml\` - Docker Compose configuration
- \`nginx/\` - Directory containing Nginx configuration files
  - \`conf.d/\` - Contains server block configurations
  - \`ssl/\` - Contains SSL certificates
  - \`html/\` - Contains static HTML files
  - \`logs/\` - Contains Nginx logs

## Adding a new service

To add a new service to the proxy, use the provided script:

\`\`\`
./add-service.sh <service_name> <container_name> <container_port>
\`\`\`

Example:
\`\`\`
./add-service.sh api api-container 8080
\`\`\`

This will add a location block to the Nginx configuration and restart the proxy.

## Manual Configuration

If you prefer to manually configure services, edit the file:
\`nginx/conf.d/default.conf\`

Then restart the proxy with:
\`docker-compose restart nginx-proxy\`

## Connecting Containers

When creating a new container that should be accessible through the proxy, make sure to:

1. Connect it to the \`nginx-proxy-network\` Docker network
2. Use an appropriate hostname that matches your proxy configuration

Example docker-compose.yml section:

\`\`\`yaml
services:
  app-service:
    image: your-app-image
    container_name: app-container
    networks:
      - nginx-proxy-network
    # Other configuration...

networks:
  nginx-proxy-network:
    external: true
\`\`\`
EOF

        echo "Docker Nginx proxy configuration complete."
        echo "Proxy is running at http://localhost and https://localhost"
        echo "Directory: /opt/docker-compose/nginx-proxy"
        echo "Use the add-service.sh script to add services to the proxy."
        echo "See the README.md file for more information."
        
        clear_terminal
    fi
}

# Add these functions to main script execution
# secure_docker_installation
# secure_nginx_installation
# configure_docker_with_nginx
