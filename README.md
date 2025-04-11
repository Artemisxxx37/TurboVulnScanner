
![ChatGPT Image Apr 11, 2025, 06_28_13 AM](https://github.com/user-attachments/assets/a7c0e1ee-dc7c-46e3-982e-545de49a55c3)

# TurboVulnScanner

TurboVulnScanner is an advanced vulnerability scanner built in Python, inspired by RustScan's speed and Nmap's powerful scanning capabilities. This tool allows users to quickly identify open ports, detect services, and assess vulnerabilities in a target system.

## Features

- **Fast Port Scanning**: Utilizes asynchronous I/O for rapid port scanning.
- **Nmap Integration**: Automatically runs Nmap for service detection and vulnerability checks.
- **CVE Lookup**: Queries the National Vulnerability Database (NVD) for known vulnerabilities.
- **Customizable Scans**: Supports various command-line options for flexibility.
- **User -Friendly Output**: Displays results in a clear and colorful format.
- **Error Handling**: Robust error handling for network issues and API requests.

## Requirements

- Python 3.7 or higher
- Nmap installed on your system
- Required Python packages (install via `requirements.txt`)

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/TurboVulnScanner.git
   cd TurboVulnScanner


2. **Install required Python packages**:
     pip install -r requirements.txt


3.  **Install Nmap**:

    On Ubuntu/Debian:

    '''bash

    sudo apt install nmap

  On macOS (using Homebrew):

      '''bash
    brew install nmap

4-1. **Update Nmap vulnerability scripts (optional but recommended)**:

      '''bash
    sudo nmap --script-updatedb

  **Usage**

Run the scanner using the following command:
  python3 scanner.py <target> [options]

  Command-Line Options

    <target>: The IP address or hostname of the target to scan.
    -p, --ports: Specify the ports or ranges to scan (default: 1-1000).
    -t, --timeout: Set the connection timeout in seconds (default: 1.0).
    -r, --rate-limit: Maximum number of concurrent connections (default: 1000).
    --nmap-args: Additional arguments to pass to Nmap (default: -sV --script vulners,vuln).
    --nvd-api-key: Your NVD API key for CVE lookups (optional).



**Example Usage**

# Basic scan of the target with default settings
python scanner.py 192.168.1.1

# Scan specific ports with a custom timeout
python scanner.py 192.168.1.1 -p 80,443,8000-9000 -t 2.0

# Use a custom Nmap argument
python scanner.py 192.168.1.1 --nmap-args "-sS -O"

# Use it with your nist api key
go on https://nvd.nist.gov/ , get registered using your mail and setting up your details ; 
Once done , check you mailbox , you'll have your api-key in there

then:
   python scanner.py 192.168.1.1 --nvd-api-key [API KEY]

![Screenshot_2025-03-27_10_54_55](https://github.com/user-attachments/assets/c2f647fc-7580-4c6e-a04b-cb4d04d841e9)


![Screenshot_2025-03-27_10_54_59](https://github.com/user-attachments/assets/f8522a3c-5d2e-4a57-93cc-7f426e9cb9af)


