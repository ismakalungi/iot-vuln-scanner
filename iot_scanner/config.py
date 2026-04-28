# iot_scanner/config.py

import os

# Default IP range to scan (e.g., your local subnet).
# IMPORTANT: Only scan networks you own or have explicit permission to scan.
SCAN_IP_RANGE = "192.168.1.0/24"

# Common IoT ports to scan for TCP services.
COMMON_IOT_PORTS = [
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    80,   # HTTP
    443,  # HTTPS
    554,  # RTSP
    8080, # HTTP (Alt)
    8443, # HTTPS (Alt)
    8888, # HTTP (Alt)
]

# Path to the default credentials wordlist.
DEFAULT_CREDS_WORDLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'wordlists', 'default_creds.txt')

# Path for the IoT Scanner log file
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'iot_scanner.log')

# Verbosity level for console output
VERBOSE_CONSOLE_OUTPUT = True
