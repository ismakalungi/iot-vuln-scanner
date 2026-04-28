# IoT Device Scanner

This project implements a command-line interface (CLI) tool designed to scan a local network for Internet of Things (IoT) devices, identify open ports, and check for common security weaknesses like default or weak credentials. It combines network discovery, port scanning, and basic credential brute-forcing to assess the security posture of IoT devices.

## Features

-   **Network Discovery (ARP Scan):** Identifies active hosts within a specified IP range on the local network.
-   **TCP Connect Port Scanning:** Scans discovered hosts for a list of common IoT-related TCP ports.
-   **Service Banner Grabbing:** Attempts to retrieve service banners from open ports to help identify running services.
-   **Default Credential Brute-Force:** For services like Telnet, SSH, and HTTP, it attempts to log in using a configurable wordlist of common default usernames and passwords.
-   **Detailed Reporting:** Generates a human-readable report (console or JSON format) of active hosts, open ports, identified services, and any successful default credential logins.
-   **Configurable Parameters:** Allows customization of the IP range, ports to scan, credential wordlist, and concurrency.
-   **Logging:** Records all scan activities and findings.

## Project Structure

```
.
├── iot_scanner/
│   ├── __init__.py        # Package initialization
│   ├── cli.py             # Command-line interface using Click
│   ├── scanner.py         # Orchestrates discovery, port scanning, and vulnerability checks
│   ├── discovery.py       # Network discovery (ARP scan) logic
│   ├── port_scan.py       # TCP Connect port scanning and banner grabbing
│   ├── checks.py          # Default credential checking functions (Telnet, SSH, HTTP)
│   ├── reporter.py        # Generates scan reports
│   ├── logger.py          # Configures logging for the scanner
│   └── config.py          # Configuration for IP range, ports, wordlist path, etc.
├── wordlists/
│   └── default_creds.txt  # Default list of common username:password pairs
├── logs/
│   └── iot_scanner.log    # Log file for scan activities
├── tests/
│   ├── __init__.py
│   └── test_scanner.py    # Unit tests for discovery, port_scan, checks, and scanner logic
├── .env.example           # Example environment variables
├── .gitignore
├── conceptual_analysis.txt
├── README.md
└── requirements.txt
```

## Prerequisites

-   Python 3.7+
-   `pip` for installing dependencies
-   **Scapy dependencies:** Scapy often requires `libpcap` (Linux/macOS) or WinPcap/Npcap (Windows). Ensure these are installed on your system.
    -   **Linux:** `sudo apt-get install libpcap-dev` (Debian/Ubuntu) or `sudo yum install libpcap-devel` (RHEL/CentOS)
    -   **Windows:** Install Npcap (recommended over WinPcap) from [nmap.org/npcap/](https://nmap.org/npcap/)
-   **Root Privileges:** Network scanning (especially ARP scan) and some credential checks require root/administrator privileges.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/IoT-Device-Scanner.git
    cd IoT-Device-Scanner
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the IoT Device Scanner from the project root directory. **Note:** This tool requires root/administrator privileges.

```bash
sudo python -m iot_scanner.cli scan
```

**Examples:**

-   **Scan the default IP range (e.g., 192.168.1.0/24) with default ports and wordlist:**
    ```bash
    sudo python -m iot_scanner.cli scan
    ```

-   **Scan a specific IP range:**
    ```bash
    sudo python -m iot_scanner.cli scan -i 192.168.0.0/24
    ```

-   **Scan a specific network interface to derive the IP range:**
    ```bash
    sudo python -m iot_scanner.cli scan -if eth0
    ```

-   **Scan custom ports:**
    ```bash
    sudo python -m iot_scanner.cli scan -p 22,80,8080
    ```

-   **Use a custom wordlist for credentials:**
    ```bash
    sudo python -m iot_scanner.cli scan -w /path/to/my_creds.txt
    ```

-   **Generate a JSON report and save it to a file:**
    ```bash
    sudo python -m iot_scanner.cli scan -f json -o iot_scan_report.json
    ```

## Ethical Considerations

-   **Authorization:** **ONLY SCAN NETWORKS YOU OWN OR HAVE EXPLICIT, WRITTEN PERMISSION TO SCAN.** Unauthorized network scanning and credential brute-forcing are illegal and unethical.
-   **Local Network Only:** This tool is primarily designed for local network scanning. Do not use it to scan the public internet.
-   **Non-Intrusive (mostly):** The tool uses TCP Connect scans and basic credential attempts. While generally not harmful, repeated attempts can be logged by target devices.
-   **Educational Purpose:** This tool is for educational and research purposes to understand IoT security vulnerabilities. It is a simplified scanner and should not be used for malicious activities.

## Testing

To run the automated tests, execute the following command from the project's root directory:

```bash
python -m unittest discover tests
```

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License.