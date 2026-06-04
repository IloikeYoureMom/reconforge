"""
Port Scanning Utility Module
════════════════════════════
Shared port scanning functions with threading support.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional


COMMON_PORTS = [
    {"port": 21, "service": "FTP"},
    {"port": 22, "service": "SSH"},
    {"port": 23, "service": "Telnet"},
    {"port": 25, "service": "SMTP"},
    {"port": 53, "service": "DNS"},
    {"port": 80, "service": "HTTP"},
    {"port": 110, "service": "POP3"},
    {"port": 143, "service": "IMAP"},
    {"port": 443, "service": "HTTPS"},
    {"port": 445, "service": "SMB"},
    {"port": 993, "service": "IMAPS"},
    {"port": 995, "service": "POP3S"},
    {"port": 1433, "service": "MSSQL"},
    {"port": 3306, "service": "MySQL"},
    {"port": 3389, "service": "RDP"},
    {"port": 5432, "service": "PostgreSQL"},
    {"port": 5900, "service": "VNC"},
    {"port": 6379, "service": "Redis"},
    {"port": 8080, "service": "HTTP-Alt"},
    {"port": 8443, "service": "HTTPS-Alt"},
    {"port": 27017, "service": "MongoDB"},
]


def _check_port(host: str, port: int, timeout: float = 1.5) -> Optional[str]:
    """Check if a single TCP port is open. Returns service string or None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            # Find the service name
            for p in COMMON_PORTS:
                if p["port"] == port:
                    return f"{port}/{p['service']}"
            return f"{port}/?"
        return None
    except (socket.gaierror, OSError):
        return None


def scan_ports(host: str, timeout: float = 1.5, max_workers: int = 20) -> list[str]:
    """Scan common ports using a thread pool for speed."""
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(_check_port, host, p["port"], timeout): p
            for p in COMMON_PORTS
        }
        for future in as_completed(future_map):
            result = future.result()
            if result:
                open_ports.append(result)

    # Sort by port number
    open_ports.sort(key=lambda x: int(x.split("/")[0]))
    return open_ports
