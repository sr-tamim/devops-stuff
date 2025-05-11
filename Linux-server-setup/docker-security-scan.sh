#!/bin/bash

# Docker Security Scan Script
# This script runs daily to scan Docker containers and images for security vulnerabilities
# It uses Trivy for vulnerability scanning

# Configuration
SCAN_DATE=$(date +%Y-%m-%d)
LOG_DIR="/var/log/docker-security"
LOG_FILE="${LOG_DIR}/scan-${SCAN_DATE}.log"
EMAIL_RECIPIENT="admin@example.com"  # Change this to your email
REPORT_CRITICAL_ONLY=true  # Set to false to report all vulnerabilities

# Ensure log directory exists
mkdir -p "${LOG_DIR}"

# Start the log
echo "Docker Security Scan - ${SCAN_DATE}" > "${LOG_FILE}"
echo "=======================================" >> "${LOG_FILE}"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if Docker is running
if ! command_exists docker; then
    echo "Docker is not installed. Exiting." | tee -a "${LOG_FILE}"
    exit 1
fi

# Check if Trivy is installed
if ! command_exists trivy; then
    echo "Trivy is not installed. Attempting to install..." | tee -a "${LOG_FILE}"
    
    # Try to install Trivy based on the distribution
    if [ -f /etc/debian_version ]; then
        apt-get update
        apt-get install -y wget apt-transport-https gnupg lsb-release
        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -
        echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/trivy.list
        apt-get update
        apt-get install -y trivy
    elif [ -f /etc/redhat-release ]; then
        cat > /etc/yum.repos.d/trivy.repo << EOF
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/\$basearch/
gpgcheck=0
enabled=1
EOF
        dnf install -y trivy
    else
        echo "Unsupported distribution. Please install Trivy manually." | tee -a "${LOG_FILE}"
        exit 1
    fi
    
    # Check if installation was successful
    if ! command_exists trivy; then
        echo "Failed to install Trivy. Exiting." | tee -a "${LOG_FILE}"
        exit 1
    fi
fi

# Get a list of all running containers
CONTAINERS=$(docker ps -q)
if [ -z "${CONTAINERS}" ]; then
    echo "No running containers found." | tee -a "${LOG_FILE}"
else
    echo "Found $(echo "${CONTAINERS}" | wc -l) running containers." | tee -a "${LOG_FILE}"
fi

# Scan each running container's image
echo "Scanning running container images..." | tee -a "${LOG_FILE}"
for CONTAINER_ID in ${CONTAINERS}; do
    CONTAINER_NAME=$(docker inspect --format '{{.Name}}' "${CONTAINER_ID}" | sed 's/\///')
    IMAGE_ID=$(docker inspect --format '{{.Image}}' "${CONTAINER_ID}")
    IMAGE_NAME=$(docker inspect --format '{{.Config.Image}}' "${CONTAINER_ID}")
    
    echo "Scanning container: ${CONTAINER_NAME} (Image: ${IMAGE_NAME})" | tee -a "${LOG_FILE}"
    
    if [ "${REPORT_CRITICAL_ONLY}" = true ]; then
        # Only scan for CRITICAL and HIGH severity vulnerabilities
        trivy image --severity HIGH,CRITICAL --no-progress "${IMAGE_NAME}" >> "${LOG_FILE}" 2>&1
    else
        # Scan for all vulnerabilities
        trivy image --no-progress "${IMAGE_NAME}" >> "${LOG_FILE}" 2>&1
    fi
    
    echo "----------------------------------------" >> "${LOG_FILE}"
done

# Scan all images (not just ones used by running containers)
echo "Scanning all Docker images..." | tee -a "${LOG_FILE}"
IMAGES=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>")
for IMAGE in ${IMAGES}; do
    echo "Scanning image: ${IMAGE}" | tee -a "${LOG_FILE}"
    
    if [ "${REPORT_CRITICAL_ONLY}" = true ]; then
        # Only scan for CRITICAL and HIGH severity vulnerabilities
        trivy image --severity HIGH,CRITICAL --no-progress "${IMAGE}" >> "${LOG_FILE}" 2>&1
    else
        # Scan for all vulnerabilities
        trivy image --no-progress "${IMAGE}" >> "${LOG_FILE}" 2>&1
    fi
    
    echo "----------------------------------------" >> "${LOG_FILE}"
done

# Check Docker daemon configuration
echo "Checking Docker daemon configuration..." | tee -a "${LOG_FILE}"
if [ -f /etc/docker/daemon.json ]; then
    echo "Docker daemon configuration:" | tee -a "${LOG_FILE}"
    cat /etc/docker/daemon.json >> "${LOG_FILE}"
else
    echo "No Docker daemon configuration found." | tee -a "${LOG_FILE}"
fi

# Look for common Docker security issues
echo "Checking for common Docker security issues..." | tee -a "${LOG_FILE}"

# Check for privileged containers
PRIVILEGED=$(docker ps --quiet --format '{{.Names}}' | xargs docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}' | grep "true" || echo "None")
if [ "${PRIVILEGED}" != "None" ]; then
    echo "WARNING: Found privileged containers:" | tee -a "${LOG_FILE}"
    echo "${PRIVILEGED}" | tee -a "${LOG_FILE}"
else
    echo "No privileged containers found." | tee -a "${LOG_FILE}"
fi

# Check for containers with hostNetwork mode
HOST_NETWORK=$(docker ps --quiet --format '{{.Names}}' | xargs docker inspect --format '{{.Name}} {{.HostConfig.NetworkMode}}' | grep "host" || echo "None")
if [ "${HOST_NETWORK}" != "None" ]; then
    echo "WARNING: Found containers using host network mode:" | tee -a "${LOG_FILE}"
    echo "${HOST_NETWORK}" | tee -a "${LOG_FILE}"
else
    echo "No containers using host network mode found." | tee -a "${LOG_FILE}"
fi

# Email the report if mail command is available
if command_exists mail; then
    if grep -q -E "CRITICAL|HIGH" "${LOG_FILE}"; then
        cat "${LOG_FILE}" | mail -s "Docker Security Scan - CRITICAL vulnerabilities found - ${SCAN_DATE}" "${EMAIL_RECIPIENT}"
    else
        cat "${LOG_FILE}" | mail -s "Docker Security Scan Report - ${SCAN_DATE}" "${EMAIL_RECIPIENT}"
    fi
fi

echo "Docker security scan complete. Report saved to ${LOG_FILE}"
