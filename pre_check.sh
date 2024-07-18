#!/bin/bash

# This file is part of the OpenShift Installation Pre-Check Script.
#
# The OpenShift Installation Pre-Check Script is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# The OpenShift Installation Pre-Check Script is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with the OpenShift Installation Pre-Check Script.  If not, see <https://www.gnu.org/licenses/>.

# ================================================
# TODO Section
# ================================================

# Additional Checks and Validations
# =================================
# 1. Check Noexec Mount Option
#    - Verify that noexec is not set on the user’s home directory or any directory where containers need to run.
#    - Validation Command: `mount | grep noexec`
#    - Pass Criteria: The user’s home directory and container directories are not listed with noexec.
#    - Fail Criteria: The user’s home directory or container directories are listed with noexec.
#    - Solution: Create an area without noexec (e.g., /opt) and ensure containers run from there.

# 2. Check Storage Configuration for Containers
#    - Ensure that the storage.conf is properly copied and modified in the user’s home directory.
#    - Validation Command: `cat /home/${USER}/.config/containers/storage.conf`
#    - Pass Criteria: runroot is set to /opt/containers/${USER}/run and graphroot is set to /opt/containers/${USER}/storage.
#    - Fail Criteria: runroot or graphroot are not set correctly.
#    - Solution: Copy /etc/containers/storage.conf to /home/${USER}/.config/containers/ and modify runroot and graphroot as specified.

# 3. Check for Specific Directory Creation and Permissions
#    - Verify creation of necessary directories with appropriate permissions.
#    - Validation Command: `ls -ld /opt/containers/${USER} /opt/oc-mirror`
#    - Pass Criteria: Directories exist with correct permissions and ownership.
#    - Fail Criteria: Directories do not exist or have incorrect permissions/ownership.
#    - Solution: Create the directories with `mkdir -p /opt/containers/${USER} /opt/oc-mirror`, set permissions to 755 for /opt/containers/${USER} and 770 for /opt/oc-mirror, and change ownership to ${USER}:${USER}.

# 4. Check mirror-registry Tarball and Extraction
#    - Ensure mirror-registry.tar.gz is copied and extracted correctly.
#    - Validation Command: `ls /opt/oc-mirror/mirror-registry`
#    - Pass Criteria: The extracted files are present in /opt/oc-mirror.
#    - Fail Criteria: The extracted files are not present.
#    - Solution: Copy mirror-registry.tar.gz to /opt/oc-mirror and extract it using `tar xzvf mirror-registry.tar.gz`.

# 5. Check for Specific fapolicyd Ansible Policy
#    - Verify the presence of Ansible-specific policy in fapolicyd rules.
#    - Validation Command: `grep 'allow perm=any all trust=1 : dir=/home/${USER}/.ansible/tmp/' /etc/fapolicyd/rules.d/50-ansible.rules`
#    - Pass Criteria: The rule is present in the file.
#    - Fail Criteria: The rule is not present.
#    - Solution: Add `allow perm=any all trust=1 : dir=/home/${USER}/.ansible/tmp/` to /etc/fapolicyd/rules.d/50-ansible.rules.

# 6. Check Podman Service Status
#    - Verify if the Podman service is enabled and active.
#    - Validation Command: `systemctl is-active podman`
#    - Pass Criteria: The output shows active.
#    - Fail Criteria: The output does not show active.
#    - Solution: Enable and start Podman service using `sudo systemctl enable podman --now` and reboot the system.

# 7. Verify Red Hat Pull Secret Presence
#    - Ensure that the Red Hat Pull Secret file (ocp_pullsecret.json) exists.
#    - Validation Command: `stat ocp_pullsecret.json`
#    - Pass Criteria: The file exists.
#    - Fail Criteria: The file does not exist.
#    - Solution: Ensure that the Red Hat Pull Secret file is saved as ocp_pullsecret.json.

# 8. Install Required/Recommended Packages
#    - Ensure packages are installed.
#    - Validation Command: `rpm -q tree skopeo podman jq wget httpd-tools httpd python3-pip`
#    - Pass Criteria: All packages are installed.
#    - Fail Criteria: One or more packages are not installed.
#    - Solution: Install missing packages using `sudo dnf install -y tree skopeo podman jq wget httpd-tools httpd python3-pip`.

# 9. Install Python Package pexpect (Is this one still needed)
#    - Ensure pexpect package is installed via pip.
#    - Validation Command: `pip3 show pexpect`
#    - Pass Criteria: The package is installed.
#    - Fail Criteria: The package is not installed.
#    - Solution: Install pexpect using `pip3 install pexpect`.

# 10. Ensure lattest version of Installer (if appropriate?)
#    - add installer version verification same way oc and oc-mirror are being done.
#    - Validation Command: `oc version`, `openshift-install version`, `oc-mirror version`
#    - Pass Criteria: The latest versions are installed.
#    - Fail Criteria: The latest versions are not installed.
#    - Solution: Download and extract the tools from OpenShift's mirror using the provided URLs.

# 11. Create Directory Structure for Podman Mirror Registry
#    - Ensure necessary directory structure for the Podman mirror registry is created.
#    - Validation Command: `ls -ld /opt/registry /opt/registry/auth /opt/registry/certs /opt/registry/data ~/.docker`
#    - Pass Criteria: All directories exist with correct permissions.
#    - Fail Criteria: One or more directories do not exist or have incorrect permissions.
#    - Solution: Create the necessary directories and set appropriate permissions.

# 12. Generate and Install Certificates (merge with, or replace pre-existing cert function?)
#    - Ensure that certificates are generated and installed correctly.
#    - Validation Command: `ls /opt/registry/certs/domain.crt`
#    - Pass Criteria: The certificate file exists.
#    - Fail Criteria: The certificate file does not exist.
#    - Solution: Generate the key and certificate for the mirror registry, copy it to the CA trust store, and update the CA trust.

# Documentation Improvements
# ==========================
# * Put better descriptions in the README.md that better explain why each specific check is being performed.
# * Update README to explain why the script requires sudo (or heightened permissions), specifically identifying which commands/functions require root and why they are important to the check.
# * Put a note that if DNS entries don't exist yet, that might be expected behavior depending on the deployment method used, so consider changing missing DNS entries from failure to informational.
# * Add a note in the "next steps/recommendations/considerations" section to explain that if DNS records don't exist and are going to be created later, the OpenShift installation itself may not complete all the way (e.g., it may stop at 97-98% complete and hang there). As soon as records are created, it should complete (assuming they are created within 24 hours).

# Improvements to Pre-existing Checks
# ===================================
# * Implement an output formatter function to help consolidate the output segmentation/divider portion, and another function to break out the command/argument piece (ssh vs local) to help make the code easier to read.
# * Update the report generator to exclude coloring tags from the report portion and only include them in the console output.
# * Work on cleaning up verbose output to make it more useful in some functions.
# * Populate the "next steps" portion with legitimate next steps and valuable information.
# * Add logic that ONLY generates a report if the user specifies an output file for the report. Otherwise, it should only output results to the command line.
# * Heavily comment the code to make it easier to understand what is being done.


# Function to display help message
show_help() {
    echo "Usage: $0 [options]"
    echo "This script can be run either using a configuration file or command-line parameters."
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -c, --config FILE       Specify the configuration file"
    echo "  --ocp_version VERSION   Specify the OCP version"
    echo "  --registry_host HOST    Specify the registry host"
    echo "  --dns_base BASE         Specify the DNS base"
    echo "  --registry_path PATH    Specify the registry path"
    echo "  --cert_path PATH        Specify the certificate path"
    echo "  --username USER         Specify the SSH username"
    echo "  -v, --verbose           Enable verbose output"
    echo "  -o, --output FILE       Specify the output file (default: ./healthcheck_report.txt)"
    echo "  --create-config         Create an example config.ini file with sample values"
    echo ""
    echo "Example commands:"
    echo "  Using a configuration file:"
    echo "    $0 --config config.ini"
    echo ""
    echo "  Using command-line parameters:"
    echo "    $0 --ocp_version 4.15.0 --registry_host my-registry-host --dns_base example.com \\"
    echo "       --registry_path /var/lib/registry --cert_path /etc/ssl/certs/registry.crt \\"
    echo "       --username myuser --verbose"
}

# Function to create an example config.ini file
create_example_config() {
    cat <<EOL > config.ini
# Example config.ini file for OpenShift health check script

[general]
# The version of OpenShift Container Platform you're using
ocp_version = 4.15.0

# The hostname of the registry host (e.g., localhost or a remote host)
registry_host = localhost

[network]
# The base domain for required DNS entries
dns_base = example.com

[registry]
# The path to the directory where registry images are stored
registry_path = /var/lib/registry

[certificates]
# The path to the certificate file for the registry
cert_path = /etc/ssl/certs/registry.crt

[ssh]
# The SSH username for the registry host
username = myuser
EOL

    echo "Example config.ini file created in the current directory."
}

# Default values
CONFIG_FILE=""
VERBOSE=0
OUTPUT_FORMAT="text"
REGISTRY_HOST="localhost"
OCP_VERSION=""
DNS_BASE=""
REGISTRY_PATH=""
CERT_PATH=""
SSH_USERNAME=""
OUTPUT_FILE="./healthcheck_report.txt"  # Default output file

# Hardcoded minimum values
MIN_CPU_CONTROL_PLANE=4        # Hardcoded minimum CPU for control plane
MIN_RAM_CONTROL_PLANE=16384    # Hardcoded minimum RAM for control plane in MB (16 GB)
MIN_DISK_CONTROL_PLANE=120     # Hardcoded minimum disk for control plane in GB

MIN_CPU_REGISTRY=2             # Hardcoded minimum CPU for registry host
MIN_RAM_REGISTRY=8192          # Hardcoded minimum RAM for registry host in MB (8 GB)
MIN_DISK_REGISTRY=100          # Updated to 100 GB

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to parse values from the INI file
parse_value() {
    local section="$1"
    local key="$2"
    awk -F " = " -v section="$section" -v key="$key" '
        $0 ~ "\\[" section "\\]" { in_section=1; next }
        $0 ~ "\\[" { in_section=0 }
        in_section && $1 == key { print $2 }
    ' "$CONFIG_FILE"
}

# Function to load configuration file
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        echo "Loading configuration from $CONFIG_FILE"
        OCP_VERSION=$(parse_value "general" "ocp_version")
        REGISTRY_HOST=$(parse_value "general" "registry_host")
        DNS_BASE=$(parse_value "network" "dns_base")
        REGISTRY_PATH=$(parse_value "registry" "registry_path")
        CERT_PATH=$(parse_value "certificates" "cert_path")
        SSH_USERNAME=$(parse_value "ssh" "username")
        echo "Configuration loaded:"
        echo "OCP Version: $OCP_VERSION"
        echo "Registry Host: $REGISTRY_HOST"
        echo "DNS Base: $DNS_BASE"
        echo "Registry Path: $REGISTRY_PATH"
        echo "Certificate Path: $CERT_PATH"
        echo "SSH Username: $SSH_USERNAME"
        echo ""
    else
        echo "No configuration file found, using default values."
        echo ""
    fi
}

# Function for logging
log() {
    local level="$1"
    shift
    if [[ "$level" == "INFO" && $VERBOSE -eq 1 ]]; then
        echo "[$level] $@" | tee -a "$OUTPUT_FILE"
    elif [[ "$level" == "ERROR" ]]; then
        echo "[$level] $@" | tee -a "$OUTPUT_FILE"
    fi
}

# Function to compare versions
version_gte() {
    # Compare major, minor, and patch versions
    local v1_major v1_minor v1_patch
    local v2_major v2_minor v2_patch

    v1_major=$(echo "$1" | cut -d. -f1)
    v1_minor=$(echo "$1" | cut -d. -f2)
    v1_patch=$(echo "$1" | cut -d. -f3)

    v2_major=$(echo "$2" | cut -d. -f1)
    v2_minor=$(echo "$2" | cut -d. -f2)
    v2_patch=$(echo "$2" | cut -d. -f3)

    if [[ $v1_major -ne $v2_major ]]; then
        return 1
    fi

    if [[ $v1_minor -gt $v2_minor ]]; then
        return 0
    elif [[ $v1_minor -lt $v2_minor ]]; then
        return 1
    fi

    if [[ -z $v1_patch ]]; then
        v1_patch=0
    fi
    if [[ -z $v2_patch ]]; then
        v2_patch=0
    fi

    if [[ $v1_patch -ge $v2_patch ]]; then
        return 0
    else
        return 1
    fi
}

# Parse command-line options
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -h|--help) show_help; exit 0 ;;
        -c|--config) CONFIG_FILE="$2"; shift 2 ;;
        --ocp_version) OCP_VERSION="$2"; shift 2 ;;
        --registry_host) REGISTRY_HOST="$2"; shift 2 ;;
        --dns_base) DNS_BASE="$2"; shift 2 ;;
        --registry_path) REGISTRY_PATH="$2"; shift 2 ;;
        --cert_path) CERT_PATH="$2"; shift 2 ;;
        --username) SSH_USERNAME="$2"; shift 2 ;;
        -v|--verbose) VERBOSE=1; shift ;;
        -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
        --create-config) CREATE_CONFIG=1; shift ;;
        --) shift; break ;;
        -*) echo "Unknown option: $1" >&2; show_help; exit 1 ;;
        *) break ;;
    esac
done

# Check if create config flag is set and no other flags are used
if [[ "$CREATE_CONFIG" -eq 1 && "$#" -eq 0 ]]; then
    create_example_config
    exit 0
fi

# Function to check if FIPS mode is enabled
check_fips_mode() {
    echo -e "\n===============================================" | tee -a "$OUTPUT_FILE"
    echo "Checking if FIPS mode is enabled" | tee -a "$OUTPUT_FILE"
    
    if [[ "$REGISTRY_HOST" == "localhost" ]]; then
        fips_status=$(fips-mode-setup --check)
    else
        fips_status=$(ssh "$SSH_USERNAME@$REGISTRY_HOST" "fips-mode-setup --check")
    fi

    if echo "$fips_status" | grep -q "FIPS mode is enabled"; then
        echo -e "${BLUE}FIPS mode is enabled.${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "FIPS mode is confirmed to be enabled."
        return 0
    else
        echo -e "${BLUE}FIPS mode is not enabled.${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "FIPS mode is not enabled."
        return 1
    fi
}

# WORK IN PROGRESS!!! Function to check if Fapolicyd is active
check_fapolicyd_active() {
    echo -e "\n===============================================" | tee -a "$OUTPUT_FILE"
    echo "Checking if Fapolicyd service is active" | tee -a "$OUTPUT_FILE"
    
    if [[ "$REGISTRY_HOST" == "localhost" ]]; then
        fapolicyd_status=$(systemctl is-active fapolicyd.service)
    else
        fapolicyd_status=$(ssh "$SSH_USERNAME@$REGISTRY_HOST" "systemctl is-active fapolicyd.service")
    fi

    if [[ "$fapolicyd_status" == "active" ]]; then
        echo -e "${BLUE}Fapolicyd service is active.${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "Fapolicyd service is active."
        check_fapolicyd_binaries
    else
        echo -e "${BLUE}Fapolicyd service is not active.${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "Fapolicyd service is not active."
    fi
}

# WORK IN PROGRESS!!! Function to check if required binaries are trusted by Fapolicyd
check_fapolicyd_binaries() {
    local binaries=("oc" "oc-mirror" "mirror-registry" "openshift-install")
    local failed_binaries=()

    for binary in "${binaries[@]}"; do
        if [[ "$REGISTRY_HOST" == "localhost" ]]; then
            if ! fapolicyd-cli --list | grep -q "/usr/local/bin/$binary"; then
                failed_binaries+=("$binary")
            fi
        else
            if ! ssh "$SSH_USERNAME@$REGISTRY_HOST" "fapolicyd-cli --list | grep -q '/usr/local/bin/$binary'"; then
                failed_binaries+=("$binary")
            fi
        fi
    done

    if [[ ${#failed_binaries[@]} -gt 0 ]]; then
        echo -e "${RED}Fail: The following binaries are not trusted by Fapolicyd:${NC}" | tee -a "$OUTPUT_FILE"
        for binary in "${failed_binaries[@]}"; do
            echo "  - $binary" | tee -a "$OUTPUT_FILE"
        done
        log "ERROR" "Binaries not trusted by Fapolicyd: ${failed_binaries[*]}"
        log "INFO" "Solution: Add the binaries to the Fapolicyd trust list using the command: fapolicyd-cli --file add /usr/local/bin/<binary>"
    else
        echo -e "${GREEN}Pass: All required binaries are trusted by Fapolicyd.${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "All required binaries are trusted by Fapolicyd."
    fi
}

# WORK IN PROGRESS!!! Function to check user namespaces setting
check_user_namespaces() {
    echo -e "\n===============================================" | tee -a "$OUTPUT_FILE"
    echo "Checking User Namespaces Setting" | tee -a "$OUTPUT_FILE"
    
    if [[ "$REGISTRY_HOST" == "localhost" ]]; then
        current_value=$(sysctl -n user.max_user_namespaces 2>/dev/null)
    else
        current_value=$(ssh "$SSH_USERNAME@$REGISTRY_HOST" "sysctl -n user.max_user_namespaces")
    fi

    if [[ "$current_value" -ge 100 ]]; then
        echo -e "${GREEN}Pass: User namespaces setting is enabled and set to $current_value.${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "User namespaces setting is enabled and set to $current_value."
    else
        echo -e "${RED}Fail: User namespaces setting is not sufficient (set to $current_value).${NC}" | tee -a "$OUTPUT_FILE"
        log "ERROR" "User namespaces setting is not sufficient (set to $current_value)."

        # Initialize array to store paths of files setting user.max_user_namespaces
        local setting_files=()

        # Check /etc/sysctl.conf
        if [[ "$REGISTRY_HOST" == "localhost" ]]; then
            if grep -q "user.max_user_namespaces" /etc/sysctl.conf; then
                setting_files+=("/etc/sysctl.conf")
            fi

            # Check /etc/sysctl.d/*.conf and if found, add to running list of files
            for file in /etc/sysctl.d/*.conf; do
                if grep -q "user.max_user_namespaces" "$file"; then
                    setting_files+=("$file")
                fi
            done
        else
            if ssh "$SSH_USERNAME@$REGISTRY_HOST" "grep -q 'user.max_user_namespaces' /etc/sysctl.conf"; then
                setting_files+=("/etc/sysctl.conf")
            fi

            for file in $(ssh "$SSH_USERNAME@$REGISTRY_HOST" "ls /etc/sysctl.d/*.conf"); do
                if ssh "$SSH_USERNAME@$REGISTRY_HOST" "grep -q 'user.max_user_namespaces' $file"; then
                    setting_files+=("$file")
                fi
            done
        fi

        if [[ ${#setting_files[@]} -gt 0 ]]; then
            echo -e "${BLUE}Info: Found 'user.max_user_namespaces' setting in the following file(s):${NC}" | tee -a "$OUTPUT_FILE"
            for file in "${setting_files[@]}"; do
                echo "  - $file" | tee -a "$OUTPUT_FILE"
            done
            log "INFO" "Solution: Update 'user.max_user_namespaces = 10000' in the above file(s) and run 'sysctl -p ${setting_files[*]}' to apply the changes."
        else
            echo -e "${BLUE}Info: 'user.max_user_namespaces' not found in /etc/sysctl.conf or any /etc/sysctl.d/*.conf files.${NC}" | tee -a "$OUTPUT_FILE"
            log "INFO" "Solution: Set 'user.max_user_namespaces = 10000' in /etc/sysctl.conf or an appropriate file in /etc/sysctl.d/, and run 'sysctl -p' to apply the changes."
        fi
    fi
}

# Function to check OS and RHEL version
get_os_and_version() {
    echo -e "\n===============================================" | tee -a "$OUTPUT_FILE"
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" == "rhel" ]]; then
            RHEL_VERSION=$VERSION_ID
        else
            RHEL_VERSION=""
        fi
    else
        RHEL_VERSION=""
    fi
    echo -e "${BLUE}Detected OS: $ID, Version: $VERSION_ID${NC}" | tee -a "$OUTPUT_FILE"
    log "INFO" "Operating System detected: $ID, Version: $VERSION_ID"
}

# Function to check if oc binary works in FIPS mode
check_oc_cli_version() {
    echo -e "\n===============================================" | tee -a "$OUTPUT_FILE"
    local required_version="$OCP_VERSION"
    local majorvar minorvar patchvar
    majorvar=$(echo "$required_version" | cut -d. -f1)
    minorvar=$(echo "$required_version" | cut -d. -f2)
    patchvar=$(echo "$required_version" | cut -d. -f3)

    echo "Checking 'oc' CLI version on registry host" | tee -a "$OUTPUT_FILE"
    if [[ "$REGISTRY_HOST" == "localhost" ]]; then
        current_version=$(oc version --client 2>&1 | grep 'Client Version' | awk '{print $3}')
    else
        current_version=$(ssh "$SSH_USERNAME@$REGISTRY_HOST" "oc version --client 2>&1 | grep 'Client Version' | awk '{print \$3}'")
    fi
    
    if echo "$current_version" | grep -q "FIPS mode is enabled, but the required OpenSSL library is not available"; then
        echo -e "${RED}Fail: 'oc' CLI fails due to FIPS mode.${NC}" | tee -a "$OUTPUT_FILE"
        log "ERROR" "'oc' CLI fails due to FIPS mode. Current version output: $current_version"
        if [[ -n "$RHEL_VERSION" ]]; then
            log "INFO" "Make sure to grab the oc binary for RHEL $RHEL_VERSION found at:"
            log "INFO" "https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/$majorvar.$minorvar.$patchvar/openshift-client-linux-amd64-rhel$RHEL_VERSION-$majorvar.$minorvar.$patchvar.tar.gz"
        else
            log "INFO" "The issue seems to be related to FIPS mode, but the OS is not RHEL."
        fi
        return 1
    elif version_gte "$current_version" "$required_version"; then
        echo -e "${GREEN}Pass: 'oc' CLI version is compatible on $REGISTRY_HOST.${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "'oc' CLI version is compatible. Current version: $current_version"
    else
        echo -e "${RED}Fail: 'oc' CLI version on $REGISTRY_HOST is $current_version but needs to be $required_version or newer.${NC}" | tee -a "$OUTPUT_FILE"
        log "ERROR" "'oc' CLI version is incompatible. Current version: $current_version, Required version: $required_version"
        log "INFO" "Solution: Download the binaries from https://mirror.openshift.com/pub/openshift-v$majorvar/x86_64/clients/ocp/$majorvar.$minorvar.$patchvar/"
        log "INFO" "Run the following commands to make the binaries executable and available to everyone:"
        log "INFO" "chmod +x <binary>"
        log "INFO" "sudo mv <binary> /usr/local/bin/"
    fi
    if [[ $VERBOSE -eq 1 ]]; then
        log "INFO" "Registry Host: $REGISTRY_HOST, Desired oc CLI Version: $required_version, Actual: $current_version"
    fi
    echo "" | tee -a "$OUTPUT_FILE"
}

# Function to check if oc-mirror binary is installed and version
check_oc_mirror_version() {
    echo -e "\n===============================================" | tee -a "$OUTPUT_FILE"
    local required_version="$OCP_VERSION"
    local majorvar minorvar
    majorvar=$(echo "$required_version" | cut -d. -f1)
    minorvar=$(echo "$required_version" | cut -d. -f2)

    echo "Checking 'oc-mirror' CLI version on registry host" | tee -a "$OUTPUT_FILE"
    if [[ "$REGISTRY_HOST" == "localhost" ]]; then
        if command -v oc-mirror &> /dev/null; then
            current_version=$(oc-mirror version 2>/dev/null | grep 'GitVersion' | awk -F '"' '{print $6}' | cut -d'.' -f1,2)
        else
            current_version=""
        fi
    else
        if ssh "$SSH_USERNAME@$REGISTRY_HOST" "command -v oc-mirror &> /dev/null"; then
            current_version=$(ssh "$SSH_USERNAME@$REGISTRY_HOST" "oc-mirror version 2>/dev/null | grep 'GitVersion' | awk -F '\"' '{print \$6}' | cut -d'.' -f1,2")
        else
            current_version=""
        fi
    fi

    if [[ -z "$current_version" ]]; then
        echo -e "${RED}Fail: 'oc-mirror' CLI is not installed.${NC}" | tee -a "$OUTPUT_FILE"
        log "ERROR" "'oc-mirror' CLI is not installed."
        log "INFO" "Solution: Download the binaries from https://mirror.openshift.com/pub/openshift-v$majorvar/x86_64/clients/ocp/$majorvar.$minorvar/"
        log "INFO" "Run the following commands to make the binaries executable and available to everyone:"
        log "INFO" "chmod +x <binary>"
        log "INFO" "sudo mv <binary> /usr/local/bin/"
    elif version_gte "$current_version" "$required_version"; then
        echo -e "${GREEN}Pass: 'oc-mirror' CLI version is compatible on $REGISTRY_HOST.${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "'oc-mirror' CLI version is compatible. Current version: $current_version"
    else
        echo -e "${RED}Fail: 'oc-mirror' CLI version on $REGISTRY_HOST is $current_version but needs to be $required_version or newer.${NC}" | tee -a "$OUTPUT_FILE"
        log "ERROR" "'oc-mirror' CLI version is incompatible. Current version: $current_version, Required version: $required_version"
        log "INFO" "Solution: Download the binaries from https://mirror.openshift.com/pub/openshift-v$majorvar/x86_64/clients/ocp/$majorvar.$minorvar/"
        log "INFO" "Run the following commands to make the binaries executable and available to everyone:"
        log "INFO" "chmod +x <binary>"
        log "INFO" "sudo mv <binary> /usr/local/bin/"
    fi
    if [[ $VERBOSE -eq 1 ]]; then
        log "INFO" "Registry Host: $REGISTRY_HOST, Desired oc-mirror CLI Version: $required_version, Actual: $current_version"
    fi
    echo "" | tee -a "$OUTPUT_FILE"
}

# Function to check required DNS entries
check_dns_entries() {
    echo "===============================================" | tee -a "$OUTPUT_FILE"
    echo "Checking required DNS entries for OpenShift installation" | tee -a "$OUTPUT_FILE"

    # List of DNS entry prefixes to check
    required_entries=("api" "foo.apps" "bar.apps" "star.apps")
    missing_entries=()
    wildcard_missing=false

    for entry in "${required_entries[@]}"; do
        fqdn="$entry.$DNS_BASE"
        if ! host "$fqdn" &> /dev/null; then
            if [[ "$entry" == "foo.apps" || "$entry" == "bar.apps" || "$entry" == "star.apps" ]]; then
                wildcard_missing=true
            else
                missing_entries+=("$entry.<obscured>")
            fi
        fi
    done

    # Check if foo.apps, bar.apps, and star.apps resolve to the same IP only if they are not missing
    if ! $wildcard_missing; then
        ip_foo=$(host "foo.apps.$DNS_BASE" | awk '/has address/ { print $4 }')
        ip_bar=$(host "bar.apps.$DNS_BASE" | awk '/has address/ { print $4 }')
        ip_star=$(host "star.apps.$DNS_BASE" | awk '/has address/ { print $4 }')

        if [[ "$ip_foo" != "$ip_bar" || "$ip_foo" != "$ip_star" ]]; then
            echo -e "${RED}Fail: Wildcard DNS (*.apps.<obscured>) is not set up correctly.${NC}" | tee -a "$OUTPUT_FILE"
            log "ERROR" "Wildcard DNS (*.apps.<obscured>) is not set up correctly."
            log "INFO" "Solution: Ensure that all subdomains under *.apps.<obscured> resolve to the same VIP."
            missing_entries+=("*.apps.<obscured>")
        else
            echo -e "${GREEN}Pass: Wildcard DNS (*.apps.<obscured>) is set up correctly.${NC}" | tee -a "$OUTPUT_FILE"
        fi
    else
        missing_entries+=("*.apps.<obscured>")
    fi

    if [[ ${#missing_entries[@]} -gt 0 ]]; then
        echo -e "${RED}Fail: The following DNS entries are missing:${NC}" | tee -a "$OUTPUT_FILE"
        for entry in "${missing_entries[@]}"; do
            echo "  - $entry" | tee -a "$OUTPUT_FILE"
        done
        log "ERROR" "Missing DNS entries: ${missing_entries[*]}"
        log "INFO" "Solution: Ensure that the DNS entries are correctly configured for OpenShift installation."
        return 1
    else
        echo -e "${GREEN}Pass: All required DNS entries are present.${NC}" | tee -a "$OUTPUT_FILE"
        return 0
    fi
}

# Function to check disk space for registry images
check_registry_disk_space() {
    echo -e "\n===============================================" | tee -a "$OUTPUT_FILE"
    echo "Checking disk space for registry images" | tee -a "$OUTPUT_FILE"
    local available_space

    if [[ "$REGISTRY_HOST" == "localhost" ]]; then
        available_space=$(df -BG --output=avail "$REGISTRY_PATH" | tail -1 | tr -dc '0-9')
    else
        available_space=$(ssh "$SSH_USERNAME@$REGISTRY_HOST" "df -BG --output=avail $REGISTRY_PATH | tail -1 | tr -dc '0-9'")
    fi

    echo -e "${BLUE}Available space in $REGISTRY_PATH: ${available_space}GB${NC}" | tee -a "$OUTPUT_FILE"
    log "INFO" "Available space in $REGISTRY_PATH: ${available_space}GB"
    if (( available_space < 100 )); then  # Updated to reflect minimum required space
        echo -e "${RED}Fail: Not enough space for registry images. Required: 100GB, Available: ${available_space}GB.${NC}" | tee -a "$OUTPUT_FILE"
        log "ERROR" "Not enough space for registry images. Required: 100GB, Available: ${available_space}GB."
        log "INFO" "Solution: Ensure that the registry path has enough disk space."
        return 1
    else
        echo -e "${GREEN}Pass: Enough space for registry images.${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "Enough space for registry images. Available: ${available_space}GB."
        return 0
    fi
}

# Function to check CPU and memory for registry host
check_registry_resources() {
    echo -e "\n===============================================" | tee -a "$OUTPUT_FILE"
    echo "Checking CPU and memory for registry host" | tee -a "$OUTPUT_FILE"
    local cpu_cores memory_kb

    if [[ "$REGISTRY_HOST" == "localhost" ]]; then
        cpu_cores=$(nproc)
        memory_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    else
        cpu_cores=$(ssh "$SSH_USERNAME@$REGISTRY_HOST" "nproc")
        memory_kb=$(ssh "$SSH_USERNAME@$REGISTRY_HOST" "grep MemTotal /proc/meminfo | awk '{print \$2}'")
    fi

    local memory_mb=$((memory_kb / 1024))

    if (( cpu_cores < MIN_CPU_REGISTRY )); then
        echo -e "${RED}Fail: Not enough CPU cores for registry host. Required: $MIN_CPU_REGISTRY, Available: $cpu_cores.${NC}" | tee -a "$OUTPUT_FILE"
        log "ERROR" "Not enough CPU cores for registry host. Required: $MIN_CPU_REGISTRY, Available: $cpu_cores."
        log "INFO" "Solution: Increase the number of CPU cores on the registry host."
    else
        echo -e "${GREEN}Pass: Sufficient CPU cores for registry host. Required: $MIN_CPU_REGISTRY, Available: $cpu_cores.${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "Sufficient CPU cores for registry host. Required: $MIN_CPU_REGISTRY, Available: $cpu_cores."
    fi

    if (( memory_mb < MIN_RAM_REGISTRY )); then
        echo -e "${RED}Fail: Not enough memory for registry host. Required: $MIN_RAM_REGISTRY MB, Available: $memory_mb MB.${NC}" | tee -a "$OUTPUT_FILE"
        log "ERROR" "Not enough memory for registry host. Required: $MIN_RAM_REGISTRY MB, Available: $memory_mb MB."
        log "INFO" "Solution: Increase the memory on the registry host."
    else
        echo -e "${GREEN}Pass: Sufficient memory for registry host. Required: $MIN_RAM_REGISTRY MB, Available: $memory_mb MB.${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "Sufficient memory for registry host. Required: $MIN_RAM_REGISTRY MB, Available: $memory_mb MB."
    fi
}

# Function to get network statistics
get_network_stats() {
    echo -e "\n===============================================" | tee -a "$OUTPUT_FILE"
    echo "Getting network statistics for registry host" | tee -a "$OUTPUT_FILE"

    # Function to get the default gateway
    get_gateway() {
        ip route | grep default | awk '{print $3}'
    }

    if [[ "$REGISTRY_HOST" == "localhost" ]]; then
        gateway=$(get_gateway)
        ping_result=$(ping -c 4 "$gateway" 2>&1)
    else
        gateway=$(ssh "$SSH_USERNAME@$REGISTRY_HOST" "$(declare -f get_gateway); get_gateway")
        ping_result=$(ssh "$SSH_USERNAME@$REGISTRY_HOST" "ping -c 4 $gateway" 2>&1)
    fi

    packet_loss=$(echo "$ping_result" | grep -oP '\d+(?=% packet loss)')
    rtt=$(echo "$ping_result" | grep -oP '(?<=rtt min/avg/max/mdev = ).*(?= ms)')

    if [[ "$packet_loss" -eq 100 ]]; then
        echo -e "${RED}Fail: Cannot reach the default gateway from the registry host.${NC}" | tee -a "$OUTPUT_FILE"
        log "ERROR" "Cannot reach the default gateway from the registry host."
        log "INFO" "Solution: Ensure that the registry host has network connectivity."
    else
        echo -e "${GREEN}Pass: Network connectivity is working.${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "Network connectivity is working."
        echo -e "${BLUE}Ping statistics: ${packet_loss}% packet loss, RTT: $rtt ms${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "Ping statistics: ${packet_loss}% packet loss, RTT: $rtt ms"
    fi
}

# Function to check NTP configuration
check_ntp() {
    echo -e "\n===============================================" | tee -a "$OUTPUT_FILE"
    echo "Checking NTP configuration on registry host" | tee -a "$OUTPUT_FILE"
    if [[ "$REGISTRY_HOST" == "localhost" ]]; then
        ntp_status=$(timedatectl status)
    else
        ntp_status=$(ssh "$SSH_USERNAME@$REGISTRY_HOST" "timedatectl status")
    fi

    if echo "$ntp_status" | grep -q "NTP service: active"; then
        echo -e "${GREEN}Pass: NTP is configured.${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "NTP is configured. Status: NTP service is active."
    else
        echo -e "${RED}Fail: NTP is not configured.${NC}" | tee -a "$OUTPUT_FILE"
        log "ERROR" "NTP is not configured."
        log "INFO" "Solution: Configure NTP to ensure time synchronization."
        return 1
    fi
}

# Function to check for valid certificates
check_certificates() {
    echo -e "\n===============================================" | tee -a "$OUTPUT_FILE"
    echo "Checking certificates on registry host" | tee -a "$OUTPUT_FILE"

    if [[ "$REGISTRY_HOST" == "localhost" ]]; then
        if [[ -f "$CERT_PATH" ]]; then
            echo -e "${GREEN}Pass: Certificate found at $CERT_PATH.${NC}" | tee -a "$OUTPUT_FILE"
            log "INFO" "Certificate found at $CERT_PATH."
        else
            echo -e "${RED}Fail: Certificate not found at $CERT_PATH.${NC}" | tee -a "$OUTPUT_FILE"
            log "ERROR" "Certificate not found at $CERT_PATH."
            log "INFO" "Solution: Ensure that the certificate is placed in the correct path."
            return 1
        fi
    else
        if ssh "$SSH_USERNAME@$REGISTRY_HOST" "[[ -f $CERT_PATH ]]"; then
            echo -e "${GREEN}Pass: Certificate found at $CERT_PATH.${NC}" | tee -a "$OUTPUT_FILE"
            log "INFO" "Certificate found at $CERT_PATH."
        else
            echo -e "${RED}Fail: Certificate not found at $CERT_PATH.${NC}" | tee -a "$OUTPUT_FILE"
            log "ERROR" "Certificate not found at $CERT_PATH."
            log "INFO" "Solution: Ensure that the certificate is placed in the correct path."
            return 1
        fi
    fi
}

# Function to check umask setting
check_umask() {
    echo -e "\n===============================================" | tee -a "$OUTPUT_FILE"
    echo "Checking umask setting" | tee -a "$OUTPUT_FILE"
    if [[ "$REGISTRY_HOST" == "localhost" ]]; then
        current_umask=$(umask)
    else
        current_umask=$(ssh "$SSH_USERNAME@$REGISTRY_HOST" 'umask')
    fi
    if [[ "$current_umask" != "0022" ]]; then
        echo -e "${RED}Fail: Current umask on $REGISTRY_HOST is set to $current_umask. OpenShift requires a umask of 0022.${NC}" | tee -a "$OUTPUT_FILE"
        log "ERROR" "Current umask on $REGISTRY_HOST is set to $current_umask. OpenShift requires a umask of 0022."
        log "INFO" "Solution: Run 'umask 0022' to reset the umask temporarily on $REGISTRY_HOST."
    else
        echo -e "${GREEN}Pass: umask setting on $REGISTRY_HOST is correct.${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "umask setting on $REGISTRY_HOST is correct."
    fi
    if [[ $VERBOSE -eq 1 ]]; then
        log "INFO" "Registry Host: $REGISTRY_HOST, Desired umask: 0022, Actual umask: $current_umask"
    fi
}

# Function to check registry accessibility
check_registry_accessibility() {
    echo -e "\n===============================================" | tee -a "$OUTPUT_FILE"
    echo "Checking access to mirror registry" | tee -a "$OUTPUT_FILE"
    if [[ "$REGISTRY_HOST" == "localhost" ]]; then
        echo -e "${BLUE}Skipping mirror registry check as the registry host is set to localhost.${NC}" | tee -a "$OUTPUT_FILE"
        log "INFO" "Skipping mirror registry check as the registry host is set to localhost."
        return
    fi
    if ping -c 1 "$REGISTRY_HOST" &> /dev/null; then
        echo -e "${GREEN}Pass: Mirror registry is accessible from $REGISTRY_HOST.${NC}" | tee -a "$OUTPUT_FILE"
    else
        echo -e "${RED}Fail: Unable to reach the mirror registry at $REGISTRY_HOST.${NC}" | tee -a "$OUTPUT_FILE"
        log "ERROR" "Unable to reach the mirror registry at $REGISTRY_HOST."
        log "INFO" "Solution: Check network connectivity and DNS settings on $REGISTRY_HOST."
    fi
    if [[ $VERBOSE -eq 1 ]]; then
        reachable=$(ping -c 1 "$REGISTRY_HOST" &> /dev/null && echo 'Yes' || echo 'No')
        log "INFO" "Registry Host: $REGISTRY_HOST, Reachable: $reachable"
    fi
}

# Function to run all checks
run_checks() {
    echo "RUNNING REGISTRY HOST CHECKS" | tee -a "$OUTPUT_FILE"
    echo "===============================================" | tee -a "$OUTPUT_FILE"
    check_umask
    check_fips_mode
    check_fapolicyd_active
    check_user_namespaces
    check_registry_accessibility
    check_oc_cli_version
    check_oc_mirror_version
    check_dns_entries
    check_registry_disk_space
    check_registry_resources
    get_network_stats
    check_ntp
    check_certificates
}

# Function to output results based on specified format
output_results() {
    case "$OUTPUT_FORMAT" in
        text) 
            echo "Output in plain text format" | tee -a "$OUTPUT_FILE"
            ;;
        json) 
            echo "{}"  # Placeholder for JSON output format implementation
            ;;
        *) 
            echo "Unknown output format: $OUTPUT_FORMAT" | tee -a "$OUTPUT_FILE"
            ;;
    esac
}

# Function to output important next steps
output_next_steps() {
    echo -e "\n===============================================" | tee -a "$OUTPUT_FILE"
    echo "IMPORTANT NEXT STEPS" | tee -a "$OUTPUT_FILE"
    echo "--------------------" | tee -a "$OUTPUT_FILE"
    echo "1. Minimum CPU for control plane: ${MIN_CPU_CONTROL_PLANE} cores" | tee -a "$OUTPUT_FILE"
    echo "2. Minimum RAM for control plane: ${MIN_RAM_CONTROL_PLANE} MB" | tee -a "$OUTPUT_FILE"
    echo "3. Minimum disk space for control plane: ${MIN_DISK_CONTROL_PLANE} GB" | tee -a "$OUTPUT_FILE"
}

# Main function
main() {
    echo "Starting health checks for OpenShift installation environment..." | tee -a "$OUTPUT_FILE"
    get_os_and_version
    load_config
    run_checks
    output_results
    output_next_steps
    echo "Health checks completed." | tee -a "$OUTPUT_FILE"
}

# Run the main function
main
