from __future__ import annotations
from pathlib import Path

RISKY_PORTS = {
    21: {
        "service": "FTP",
        "reason": "Unencrypted file transfer - credentials sent in plaintext",
    },
    22: {
        "service": "SSH",
        "reason": "Remote access - brute force target if weak credentials",
    },
    23: {
        "service": "Telnet",
        "reason": "Unencrypted remote access - credentials sent in plaintext",
    },
    25: {
        "service": "SMTP",
        "reason": "Email relay - potential for spam/phishing if misconfigured",
    },
    53: {
        "service": "DNS",
        "reason": "DNS service - zone transfer or amplification attack vector",
    },
    110: {
        "service": "POP3",
        "reason": "Unencrypted email retrieval - credentials exposed",
    },
    135: {
        "service": "MSRPC",
        "reason": "Windows RPC - common exploit target",
    },
    139: {
        "service": "NetBIOS",
        "reason": "NetBIOS session service - information disclosure",
    },
    143: {
        "service": "IMAP",
        "reason": "Unencrypted email access - credentials exposed",
    },
    445: {
        "service": "SMB",
        "reason": "Common exploit target - EternalBlue, ransomware spread",
    },
    1433: {
        "service": "MSSQL",
        "reason": "Database service - SQL injection, unauthorized access",
    },
    1521: {
        "service": "Oracle",
        "reason": "Database service - unauthorized data access",
    },
    3306: {
        "service": "MySQL",
        "reason": "Database service - unauthorized data access",
    },
    3389: {
        "service": "RDP",
        "reason": "Remote Desktop - frequent brute force and exploit target",
    },
    5432: {
        "service": "PostgreSQL",
        "reason": "Database service - unauthorized data access",
    },
    5900: {
        "service": "VNC",
        "reason": "Remote desktop - often weak or no authentication",
    },
    6379: {
        "service": "Redis",
        "reason": "In-memory database - often exposed without authentication",
    },
    8080: {
        "service": "HTTP-Alt",
        "reason": "Alternative HTTP - often misconfigured or development server",
    },
    8443: {
        "service": "HTTPS-Alt",
        "reason": "Alternative HTTPS - often misconfigured",
    },
    27017: {
        "service": "MongoDB",
        "reason": "NoSQL database - frequently exposed without authentication",
    },
}

SEVERITY_LEVELS = {
    "CRITICAL": ["23", "445", "3389"],
    "HIGH": ["21", "135", "139", "1433", "3306", "5432", "27017", "6379"],
    "MEDIUM": ["22", "25", "53", "110", "143", "1521", "5900", "8080", "8443"],
    "LOW": [],
}

DEFAULT_SCAN_ARGS = "-sV -sC"

LOG_FILE = Path("logs") / "scan.log"
REPORT_JSON = Path("reports") / "report.json"
REPORT_CSV = Path("reports") / "report.csv"