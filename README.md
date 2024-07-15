
# OpenShift Installation Pre-Check Script

## Overview

The OpenShift Installation Pre-Check Script is designed to assist Tech Sales, Consultants, and Customers in assessing their environment's readiness for an OpenShift installation. This script is particularly valuable in hardened, STIG'd, and/or disconnected environments, where unforeseen obstacles or challenges may arise. The script provides a comprehensive health check, generating a report that highlights pass, fail, and informational checks, along with recommendations when necessary.

## Use Cases

- **Tech Sales:** Ensure customer environments are ready for OpenShift installations.
- **Consultants:** Pre-validate environments before beginning installation projects.
- **Customers:** Self-assess environment readiness and address potential issues beforehand.

## Importance

Running this pre-check script helps identify potential issues that could hinder an OpenShift installation. It ensures that the environment meets the necessary requirements, providing a smoother installation process. By using this script, users can proactively address issues and avoid common pitfalls in complex environments.

## Features

- Easy to review shell script for transparency and security.
- Generates a report with obscured output (no IP addresses, FQDNs, or passwords).
- Provides pass/fail/informational output with recommendations (when verbose is specified).
- Takes no action against the environment, ensuring safety and security.

## Checks Performed

1. **Operating System and Version:** Detects the OS and its version.
2. **FIPS Mode:** Checks if FIPS mode is enabled.
3. **`oc` CLI Version:** Verifies the installed version of the `oc` CLI tool.
4. **`oc-mirror` CLI Version:** Verifies the installed version of the `oc-mirror` CLI tool.
5. **Required DNS Entries:** Ensures that necessary DNS entries for OpenShift are present.
6. **Disk Space for Registry Images:** Checks available disk space for registry images.
7. **Registry Host Resources:** Verifies CPU and memory resources on the registry host.
8. **Network Statistics:** Provides network connectivity statistics.
9. **NTP Configuration:** Ensures NTP is configured on the registry host.
10. **Certificates:** Checks for the presence of valid certificates.
11. **Umask Setting:** Verifies the umask setting on the registry host.
12. **Registry Accessibility:** Checks if the mirror registry is accessible.

## How to Use

### Running the Script

The script can be run using a configuration file or command-line parameters.

#### Using a Configuration File

```sh
./pre_check.sh --config config.ini
```

#### Using Command-Line Parameters

```sh
./pre_check.sh --ocp_version 4.15.0 --registry_host my-registry-host --dns_base example.com \ 
--registry_path /var/lib/registry --cert_path /etc/ssl/certs/registry.crt --username myuser --verbose
```

### Parameters

- `-h, --help`: Show help message.
- `-c, --config FILE`: Specify the configuration file.
- `--ocp_version VERSION`: Specify the OCP version.
- `--registry_host HOST`: Specify the registry host.
- `--dns_base BASE`: Specify the DNS base.
- `--registry_path PATH`: Specify the registry path.
- `--cert_path PATH`: Specify the certificate path.
- `--username USER`: Specify the SSH username.
- `-v, --verbose`: Enable verbose output.
- `-o, --output FILE`: Specify the output file (default: ./healthcheck_report.txt).
- `--create-config`: Create an example config.ini file with sample values.

### Generating an Output File

To generate a report and save it to a file:

```sh
./pre_check.sh --config config.ini --output /path/to/report.txt
```

### Example Configuration File

Create an example configuration file with sample values:

```sh
./pre_check.sh --create-config
```

### Security and Privacy

- The output is fully obscured, ensuring no sensitive information (IP addresses, FQDNs, passwords) is included.
- The script takes NO action against your environment.
- Provides recommendations (in verbose mode) on how to address issues.

## Steps to Run and Send the Report

1. **Run the Script:**
   - Using a configuration file: `./pre_check.sh --config config.ini`
   - Using command-line parameters: `./pre_check.sh --ocp_version 4.15.0 --registry_host my-registry-host ...`

2. **Generate the Report:**
   - Save the report to a file: `./pre_check.sh --config config.ini --output /path/to/report.txt`

3. **Send the Report:**
   - If requested by a Red Hat representative, send the generated report file.

## Conclusion

The OpenShift Installation Pre-Check Script is a crucial tool for ensuring environment readiness before starting an OpenShift installation. It helps identify and address potential issues, providing a smoother and more successful installation process. By using this script, you can proactively manage and resolve challenges in complex environments, ensuring a better overall experience.
