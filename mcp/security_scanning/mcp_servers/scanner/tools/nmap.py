"""
Nmap scanning tool for the Scanner MCP server.
"""

import json
import subprocess
import shutil
from typing import Literal

from pydantic import BaseModel

from ..scope import validate_target


# Scan profiles - predefined nmap configurations
SCAN_PROFILES = {
    "quick": {
        "description": "Fast scan of common ports",
        "args": ["-T4", "-F"],  # Fast timing, top 100 ports
    },
    "full": {
        "description": "Full port scan with service detection",
        "args": ["-T4", "-p-", "-sV"],  # All ports, version detection
    },
    "stealth": {
        "description": "Slower SYN scan to avoid detection",
        "args": ["-sS", "-T2", "-f"],  # SYN scan, slow timing, fragment packets
    },
    "service_version": {
        "description": "Service and version detection on common ports",
        "args": ["-sV", "-sC", "-T4"],  # Version detection, default scripts
    },
    "vuln_scripts": {
        "description": "Run vulnerability detection scripts",
        "args": ["-sV", "--script=vuln", "-T4"],  # Vuln scripts
    },
    "aggressive": {
        "description": "Aggressive scan with OS detection and scripts",
        "args": ["-A", "-T4"],  # OS detection, version, scripts, traceroute
    },
}

ProfileType = Literal["quick", "full", "stealth", "service_version", "vuln_scripts", "aggressive"]


class NmapResult(BaseModel):
    """Structured nmap scan result."""
    target: str
    profile: str
    ports_scanned: str
    command: str
    raw_output: str
    hosts: list[dict]
    error: str | None = None


def get_nmap_path() -> str:
    """Find nmap executable."""
    nmap_path = shutil.which("nmap")
    if nmap_path is None:
        raise FileNotFoundError(
            "nmap not found in PATH. Please install nmap:\n"
            "  - Windows: https://nmap.org/download.html\n"
            "  - Linux: sudo apt install nmap\n"
            "  - macOS: brew install nmap"
        )
    return nmap_path


def parse_nmap_output(output: str) -> list[dict]:
    """
    Parse nmap text output into structured data.

    For production, consider using python-nmap or -oX XML output,
    but text parsing works for PoC.
    """
    hosts = []
    current_host = None

    for line in output.split('\n'):
        line = line.strip()

        # New host found
        if line.startswith("Nmap scan report for"):
            if current_host:
                hosts.append(current_host)
            # Extract IP/hostname
            parts = line.replace("Nmap scan report for ", "").strip()
            current_host = {
                "host": parts,
                "ports": [],
                "os_guess": None,
            }

        # Port line: "21/tcp open ftp vsftpd 2.3.4"
        elif current_host and ("/tcp" in line or "/udp" in line):
            parts = line.split()
            if len(parts) >= 3:
                port_proto = parts[0].split("/")
                # Ensure we have a valid port number
                if len(port_proto) >= 2 and port_proto[0].isdigit():
                    port_info = {
                        "port": int(port_proto[0]),
                        "protocol": port_proto[1],
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "unknown",
                        "version": " ".join(parts[3:]) if len(parts) > 3 else None,
                    }
                    current_host["ports"].append(port_info)

        # OS detection
        elif current_host and "OS details:" in line:
            current_host["os_guess"] = line.replace("OS details:", "").strip()

    # Don't forget the last host
    if current_host:
        hosts.append(current_host)

    return hosts


async def run_nmap_scan(
    target: str,
    profile: ProfileType = "quick",
    ports: str | None = None,
    extra_args: list[str] | None = None,
) -> NmapResult:
    """
    Run an nmap scan against a target.

    Args:
        target: IP address or hostname to scan
        profile: Scan profile (quick, full, stealth, service_version, vuln_scripts, aggressive)
        ports: Optional port specification (e.g., "22,80,443" or "1-1000")
        extra_args: Optional additional nmap arguments

    Returns:
        NmapResult with structured scan data
    """
    # SAFETY: Validate target is in scope
    validate_target(target)

    nmap_path = get_nmap_path()

    # Build command
    profile_config = SCAN_PROFILES.get(profile, SCAN_PROFILES["quick"])
    cmd = [nmap_path] + profile_config["args"]

    # Add port specification if provided
    if ports:
        cmd.extend(["-p", ports])

    # Add any extra args
    if extra_args:
        cmd.extend(extra_args)

    # Add target last
    cmd.append(target)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        output = result.stdout
        error = result.stderr if result.returncode != 0 else None

        # Parse the output
        hosts = parse_nmap_output(output)

        return NmapResult(
            target=target,
            profile=profile,
            ports_scanned=ports or "default",
            command=" ".join(cmd),
            raw_output=output,
            hosts=hosts,
            error=error,
        )

    except subprocess.TimeoutExpired:
        return NmapResult(
            target=target,
            profile=profile,
            ports_scanned=ports or "default",
            command=" ".join(cmd),
            raw_output="",
            hosts=[],
            error="Scan timed out after 5 minutes",
        )
    except Exception as e:
        return NmapResult(
            target=target,
            profile=profile,
            ports_scanned=ports or "default",
            command=" ".join(cmd),
            raw_output="",
            hosts=[],
            error=str(e),
        )
