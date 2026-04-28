# IoT Guardian Scanner

A vulnerability scanning tool for discovering and assessing IoT devices on local networks. Features a web dashboard for managing scans and viewing results.

## Features

- Network Discovery (ARP Scan) - Identifies active hosts on the local network
- TCP Connect Port Scanning - Scans for common IoT-related TCP ports
- Service Banner Grabbing - Identifies running services
- Default Credential Checking - Tests for weak/default credentials
- Web Dashboard - Manage scans and view results via browser

## Project Structure

```
.
├── dashboard/              # Web dashboard application
│   ├── app.py             # Flask application
│   ├── db.py              # Database operations
│   ├── config.py          # Configuration from .env
│   └── templates/         # HTML templates
├── iot_scanner/           # CLI scanner package
│   ├── cli.py             # Command-line interface
│   ├── scanner.py        # Main scanner logic
│   ├── discovery.py      # Network discovery
│   ├── port_scan.py     # Port scanning
│   └── checks.py       # Credential checks
├── src/                  # UI templates
├── wordlists/           # Credential wordlists
├── logs/                 # Log files
├── .env                  # Environment configuration
└── requirements.txt      # Python dependencies
```

## Prerequisites

- Python 3.7+
- Root privileges (required for network scanning)
- libpcap-dev (Linux)

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Copy and configure environment:
```bash
cp .env.example .env
# Edit .env to set your preferences
```

## Running the Dashboard

Start the web dashboard:

```bash
cd dashboard
python app.py
```

Access at: http://localhost:5000

Login credentials (set in .env):
- Username: ismakalungi
- Password: password

## Running the Scanner CLI

From project root:

```bash
sudo python -m iot_scanner.cli scan -i 192.168.1.0/24
```

Options:
- `-i` - IP range to scan
- `-p` - Ports to scan
- `-w` - Custom wordlist
- `-f` - Output format (text/json)

## Configuration

Edit `.env` to configure:
- `DATABASE_PATH` - Path to SQLite database
- `SECRET_KEY` - Flask secret key
- `ADMIN_USERNAME` - Dashboard username
- `ADMIN_PASSWORD` - Dashboard password