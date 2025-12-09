"""
Nikto web server scanner tool for the Scanner MCP server.
"""

import subprocess
import shutil
import re

from pydantic import BaseModel

from ..scope import validate_target


class NiktoResult(BaseModel):
    """Structured nikto scan result."""
    target: str
    command: str
    raw_output: str
    findings: list[dict]
    server_info: dict | None = None
    error: str | None = None


def get_nikto_path() -> str:
    """Find nikto executable."""
    nikto_path = shutil.which("nikto")

    # Also check common install locations
    if nikto_path is None:
        import os
        common_paths = [
            "/usr/bin/nikto",
            "/usr/local/bin/nikto",
            "C:\\Program Files\\nikto\\nikto.pl",
            "C:\\nikto\\nikto.pl",
        ]
        for path in common_paths:
            if os.path.exists(path):
                nikto_path = path
                break

    if nikto_path is None:
        raise FileNotFoundError(
            "nikto not found. Please install:\n"
            "  - Linux: sudo apt install nikto\n"
            "  - macOS: brew install nikto\n"
            "  - Windows: Download from https://github.com/sullo/nikto"
        )
    return nikto_path


def parse_nikto_output(output: str) -> tuple[list[dict], dict | None]:
    """
    Parse nikto output into structured findings.

    Returns:
        Tuple of (findings list, server info dict)
    """
    findings = []
    server_info = {}

    for line in output.split('\n'):
        line = line.strip()

        # Server header info
        if "+ Server:" in line:
            server_info["server"] = line.split("Server:", 1)[1].strip()

        # Target info
        elif "+ Target IP:" in line:
            server_info["target_ip"] = line.split("Target IP:", 1)[1].strip()
        elif "+ Target Hostname:" in line:
            server_info["target_hostname"] = line.split("Target Hostname:", 1)[1].strip()
        elif "+ Target Port:" in line:
            server_info["target_port"] = line.split("Target Port:", 1)[1].strip()

        # Findings (lines starting with + that contain OSVDB or other identifiers)
        elif line.startswith("+") and ":" in line:
            # Skip metadata lines
            if any(x in line for x in ["Start Time:", "End Time:", "host(s) tested", "Target"]):
                continue

            finding = {"raw": line[2:].strip()}  # Remove "+ " prefix

            # Try to extract OSVDB ID
            osvdb_match = re.search(r'OSVDB-(\d+)', line)
            if osvdb_match:
                finding["osvdb"] = osvdb_match.group(1)

            # Try to extract path
            path_match = re.search(r'(/[^\s:]+)', line)
            if path_match:
                finding["path"] = path_match.group(1)

            findings.append(finding)

    return findings, server_info if server_info else None


async def run_nikto(
    target: str,
    port: int = 80,
    ssl: bool = False,
    tuning: str | None = None,
    timeout: int = 600,
    extra_args: list[str] | None = None,
) -> NiktoResult:
    """
    Run nikto web vulnerability scanner against a target.

    Args:
        target: Target host (IP or hostname)
        port: Target port (default: 80)
        ssl: Use SSL/HTTPS
        tuning: Nikto tuning options (e.g., "123" for specific tests)
        timeout: Scan timeout in seconds
        extra_args: Additional nikto arguments

    Returns:
        NiktoResult with vulnerability findings
    """
    # SAFETY: Validate target is in scope
    validate_target(target)

    nikto_path = get_nikto_path()

    # Build command
    cmd = [nikto_path, "-h", target, "-p", str(port)]

    if ssl:
        cmd.append("-ssl")

    if tuning:
        cmd.extend(["-Tuning", tuning])

    # Disable interactive prompts
    cmd.append("-nointeractive")

    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        output = result.stdout
        error = result.stderr if result.returncode != 0 and result.returncode != 1 else None

        findings, server_info = parse_nikto_output(output)

        return NiktoResult(
            target=f"{target}:{port}",
            command=" ".join(cmd),
            raw_output=output,
            findings=findings,
            server_info=server_info,
            error=error,
        )

    except subprocess.TimeoutExpired:
        return NiktoResult(
            target=f"{target}:{port}",
            command=" ".join(cmd),
            raw_output="",
            findings=[],
            server_info=None,
            error=f"Scan timed out after {timeout} seconds",
        )
    except Exception as e:
        return NiktoResult(
            target=f"{target}:{port}",
            command=" ".join(cmd),
            raw_output="",
            findings=[],
            server_info=None,
            error=str(e),
        )
