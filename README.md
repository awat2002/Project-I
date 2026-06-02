# Network Vulnerability Scanner

Network scanning and risk analysis tool for Linux.

## What This Project Does

The tool scans a target (single IP, CIDR range, or hostname), discovers open ports and running services, flags risky findings against a predefined risk list and any user-defined custom ports, and writes structured reports.

Supported target formats:

- Single IP: `123.456.789.123`

- CIDR range: `123.456.789.123/24`

- Hostname: `scanme.nmap.org`

## Risk Flagging

The analyzer supports two layers of risk flagging:

**Layer 1 — Predefined risky ports (from `config.py`)**

| Port | Service | Severity |
|------|---------|----------|
| 23 | Telnet | CRITICAL |
| 445 | SMB | CRITICAL |
| 3389 | RDP | CRITICAL |
| 21 | FTP | HIGH |
| 135 | MSRPC | HIGH |
| 139 | NetBIOS | HIGH |
| 1433 | MSSQL | HIGH |
| 3306 | MySQL | HIGH |
| 5432 | PostgreSQL | HIGH |
| 6379 | Redis | HIGH |
| 27017 | MongoDB | HIGH |
| 22 | SSH | MEDIUM |
| 25 | SMTP | MEDIUM |
| 53 | DNS | MEDIUM |
| 110 | POP3 | MEDIUM |
| 143 | IMAP | MEDIUM |
| 1521 | Oracle | MEDIUM |
| 5900 | VNC | MEDIUM |
| 8080 | HTTP-Alt | MEDIUM |
| 8443 | HTTPS-Alt | MEDIUM |

**Layer 2 — User-defined custom ports**

Any additional ports to flag as risky, provided at runtime via CLI or interactive menu.

## Project Structure

- `main.py`: CLI entrypoint and session orchestration.

- `scanner.py`: Wraps `python-nmap` and parses raw scan results.

- `analyzer.py`: Applies predefined and custom risk flags, assigns severity.

- `display.py`: Rich terminal UI, host tables, and risky findings summary.

- `reporter.py`: JSON/CSV report generation.

- `config.py`: Risky ports list, severity levels, paths.

## Requirements

- Linux environment (Kali Linux recommended)

- Python 3.10+

- Nmap installed on the system (`sudo apt install nmap`)

- Dependencies listed in `requirements.txt`

## Setup (Kali/Linux)

```bash

cd "~/Desktop/Network Vulnerability Scanner"

python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt

```

If Kali blocks global pip installs, always use the local `.venv` as above.

## Run Modes

### 1) Interactive mode

Run with no arguments:

```bash

python3 main.py

```

Prompts for target and optional custom risky ports, then confirms before scanning.

### 2) CLI mode

Examples:

```bash

# Scan a single IP

python3 main.py --target 123.456.789.123

# Scan a CIDR range

python3 main.py --target 123.456.789.123/24

# Scan a hostname

python3 main.py --target scanme.nmap.org

# Scan with custom risky ports

python3 main.py --target 123.456.789.123 --custom-ports 8000,9000

# Scan specific ports only

python3 main.py --target 123.456.789.123 --ports 22,80,443

# Enable verbose log output in terminal

python3 main.py --target 123.456.789.123 --verbose

```

## Screenshots
<img width="1891" height="716" alt="image1" src="https://github.com/user-attachments/assets/1f5425d9-789b-4af9-b102-3b1abc59c51e" />

<img width="1898" height="449" alt="image2" src="https://github.com/user-attachments/assets/edaf1827-993c-4a4b-b20e-b617eaa1dc04" />




## CLI Arguments

| Argument | Short | Description |
|----------|-------|-------------|
| `--target` | `-t` | Target IP, CIDR range, or hostname |
| `--custom-ports` | `-c` | Comma-separated custom risky ports to flag |
| `--ports` | `-p` | Specific ports to scan (e.g. `22,80,443` or `1-1000`) |
| `--verbose` | `-v` | Enable verbose log output in terminal |

## Output Files

Generated per scan:

- `reports/report.json`

- `reports/report.csv`

Scan log:

- `logs/scan.log`

## Testing Guidance

### Functional validation (authorized targets only)

Scan your own machine router (`123.456.789.123`) to verify port discovery, risk flagging, severity assignment, and report generation end to end.

Authorized public target:

```bash

python3 main.py --target scanme.nmap.org

```

### Custom port flagging

Pass ports you know are open on the target via `--custom-ports` and confirm they appear in the risky findings output.

## Important Behavior Notes

- Nmap must be installed and accessible in PATH before running.

- Scanning targets you do not own or have explicit permission to scan is illegal.

- Safe targets: your own network (`123.456.789.123`), your own public IP, `scanme.nmap.org`.

- Scan duration varies with target size — CIDR ranges with many hosts will take significantly longer.
