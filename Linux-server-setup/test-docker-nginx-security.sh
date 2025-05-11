#!/bin/bash

# Script to test Docker and Nginx security configurations
# This script verifies the security settings of Docker and Nginx installations

# Colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print section headers
print_header() {
    echo -e "\n${YELLOW}=== $1 ===${NC}\n"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if a service is active
service_active() {
    systemctl is-active --quiet "$1"
}

# Function to test Docker security configurations
test_docker_security() {
    print_header "Testing Docker Security Configuration"
    
    # Check if Docker is installed
    if ! command_exists docker; then
        echo -e "${RED}Docker is not installed.${NC}"
        return 1
    else
        echo -e "${GREEN}Docker is installed.${NC}"
    fi
    
    # Check Docker service status
    if service_active docker; then
        echo -e "${GREEN}Docker service is running.${NC}"
    else
        echo -e "${RED}Docker service is not running.${NC}"
    fi
    
    # Check Docker daemon configuration
    if [ -f /etc/docker/daemon.json ]; then
        echo -e "${GREEN}Docker daemon configuration exists.${NC}"
        
        # Check specific security settings
        if grep -q "\"no-new-privileges\": true" /etc/docker/daemon.json; then
            echo -e "${GREEN}Security: no-new-privileges is enabled.${NC}"
        else
            echo -e "${RED}Security: no-new-privileges is not enabled.${NC}"
        fi
        
        if grep -q "\"userns-remap\":" /etc/docker/daemon.json; then
            echo -e "${GREEN}Security: User namespace remapping is configured.${NC}"
        else
            echo -e "${RED}Security: User namespace remapping is not configured.${NC}"
        fi
        
        if grep -q "\"icc\": false" /etc/docker/daemon.json; then
            echo -e "${GREEN}Security: Inter-container communication is disabled.${NC}"
        else
            echo -e "${RED}Security: Inter-container communication is not disabled.${NC}"
        fi
    else
        echo -e "${RED}Docker daemon configuration file does not exist.${NC}"
    fi
    
    # Check if Docker Content Trust is enabled
    if grep -q "DOCKER_CONTENT_TRUST=1" /etc/profile.d/docker-content-trust.sh 2>/dev/null; then
        echo -e "${GREEN}Docker Content Trust is enabled system-wide.${NC}"
    else
        echo -e "${RED}Docker Content Trust is not enabled system-wide.${NC}"
    fi
    
    # Check Docker bench security tool
    if command_exists docker-bench; then
        echo -e "${GREEN}Docker Bench Security tool is installed.${NC}"
    else
        echo -e "${RED}Docker Bench Security tool is not installed.${NC}"
    fi
    
    # Check for Trivy vulnerability scanner
    if command_exists trivy; then
        echo -e "${GREEN}Trivy vulnerability scanner is installed.${NC}"
    else
        echo -e "${RED}Trivy vulnerability scanner is not installed.${NC}"
    fi
    
    # Check if weekly security audit is configured
    if [ -f /etc/systemd/system/docker-security-audit.timer ] && \
       [ -f /etc/systemd/system/docker-security-audit.service ]; then
        echo -e "${GREEN}Docker security audit service is configured.${NC}"
        
        if systemctl is-enabled --quiet docker-security-audit.timer; then
            echo -e "${GREEN}Docker security audit timer is enabled.${NC}"
        else
            echo -e "${RED}Docker security audit timer is not enabled.${NC}"
        fi
    else
        echo -e "${RED}Docker security audit service is not configured.${NC}"
    fi
}

# Function to test Nginx security configurations
test_nginx_security() {
    print_header "Testing Nginx Security Configuration"
    
    # Check if Nginx is installed
    if ! command_exists nginx; then
        echo -e "${RED}Nginx is not installed.${NC}"
        return 1
    else
        echo -e "${GREEN}Nginx is installed.${NC}"
    fi
    
    # Check Nginx service status
    if service_active nginx; then
        echo -e "${GREEN}Nginx service is running.${NC}"
    else
        echo -e "${RED}Nginx service is not running.${NC}"
    fi
    
    # Check Nginx configuration
    nginx_test=$(nginx -t 2>&1)
    if echo "$nginx_test" | grep -q "successful"; then
        echo -e "${GREEN}Nginx configuration syntax is valid.${NC}"
    else
        echo -e "${RED}Nginx configuration has errors:${NC}"
        echo "$nginx_test"
    fi
    
    # Check for SSL configuration
    if grep -q "ssl_protocols TLSv1.2 TLSv1.3;" /etc/nginx/nginx.conf 2>/dev/null; then
        echo -e "${GREEN}Secure SSL protocols (TLSv1.2, TLSv1.3) are configured.${NC}"
    else
        echo -e "${RED}Secure SSL protocols may not be properly configured.${NC}"
    fi
    
    # Check for server_tokens off
    if grep -q "server_tokens off;" /etc/nginx/nginx.conf 2>/dev/null; then
        echo -e "${GREEN}Server tokens are disabled.${NC}"
    else
        echo -e "${RED}Server tokens may be enabled.${NC}"
    fi
    
    # Check for security headers
    security_headers=("X-Content-Type-Options" "X-Frame-Options" "X-XSS-Protection" "Content-Security-Policy" "Strict-Transport-Security")
    
    for header in "${security_headers[@]}"; do
        if grep -q "add_header $header" /etc/nginx/nginx.conf 2>/dev/null; then
            echo -e "${GREEN}Security header $header is configured.${NC}"
        else
            echo -e "${RED}Security header $header may not be configured.${NC}"
        fi
    done
    
    # Check for DH parameters
    if [ -f /etc/nginx/ssl/dhparam.pem ]; then
        echo -e "${GREEN}DH parameters file exists.${NC}"
    else
        echo -e "${YELLOW}DH parameters file does not exist. This is optional but recommended.${NC}"
    fi
    
    # Check for HTTP to HTTPS redirection
    if grep -q "return 301 https://\$host\$request_uri;" /etc/nginx/sites-available/default 2>/dev/null; then
        echo -e "${GREEN}HTTP to HTTPS redirection is configured.${NC}"
    else
        echo -e "${RED}HTTP to HTTPS redirection may not be configured.${NC}"
    fi
}

# Function to test Docker with Nginx integration
test_docker_nginx_integration() {
    print_header "Testing Docker and Nginx Integration"
    
    # Check if the nginx-proxy-network exists
    if docker network ls | grep -q "nginx-proxy-network"; then
        echo -e "${GREEN}Docker network 'nginx-proxy-network' exists.${NC}"
    else
        echo -e "${RED}Docker network 'nginx-proxy-network' does not exist.${NC}"
    fi
    
    # Check if the Docker Compose directory exists
    if [ -d /opt/docker-compose/nginx-proxy ]; then
        echo -e "${GREEN}Docker Compose directory for Nginx proxy exists.${NC}"
        
        # Check for Docker Compose file
        if [ -f /opt/docker-compose/nginx-proxy/docker-compose.yml ]; then
            echo -e "${GREEN}Docker Compose file exists.${NC}"
        else
            echo -e "${RED}Docker Compose file does not exist.${NC}"
        fi
        
        # Check for Nginx configuration directory
        if [ -d /opt/docker-compose/nginx-proxy/nginx/conf.d ]; then
            echo -e "${GREEN}Nginx configuration directory exists.${NC}"
        else
            echo -e "${RED}Nginx configuration directory does not exist.${NC}"
        fi
        
        # Check for add-service.sh script
        if [ -f /opt/docker-compose/nginx-proxy/add-service.sh ] && [ -x /opt/docker-compose/nginx-proxy/add-service.sh ]; then
            echo -e "${GREEN}Add-service script exists and is executable.${NC}"
        else
            echo -e "${RED}Add-service script does not exist or is not executable.${NC}"
        fi
        
        # Check if the nginx-proxy container is running
        if docker ps | grep -q "nginx-proxy"; then
            echo -e "${GREEN}Nginx proxy container is running.${NC}"
        else
            echo -e "${RED}Nginx proxy container is not running.${NC}"
        fi
    else
        echo -e "${RED}Docker Compose directory for Nginx proxy does not exist.${NC}"
    fi
}

# Determine the distribution
detect_distribution() {
    print_header "Detecting Linux Distribution"
    
    if [ -f /etc/debian_version ]; then
        echo -e "${GREEN}Debian/Ubuntu based distribution detected.${NC}"
        DISTRO="debian"
    elif [ -f /etc/redhat-release ]; then
        echo -e "${GREEN}RHEL/CentOS/Fedora based distribution detected.${NC}"
        DISTRO="redhat"
    else
        echo -e "${RED}Unknown distribution.${NC}"
        DISTRO="unknown"
    fi
}

# Main function
main() {
    print_header "Docker and Nginx Security Configuration Test"
    
    detect_distribution
    test_docker_security
    test_nginx_security
    test_docker_nginx_integration
    
    print_header "Test Complete"
}

main
