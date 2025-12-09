"""
Feroxbuster directory brute-forcing tool for the Scanner MCP server.
"""

import subprocess
import shutil
from pathlib import Path

from pydantic import BaseModel

from ..scope import validate_target


class FeroxResult(BaseModel):
    """Structured feroxbuster result."""
    url: str
    wordlist: str
    command: str
    raw_output: str
    discovered: list[dict]
    error: str | None = None


def get_feroxbuster_path() -> str:
    """Find feroxbuster executable."""
    ferox_path = shutil.which("feroxbuster")
    if ferox_path is None:
        raise FileNotFoundError(
            "feroxbuster not found in PATH. Please install:\n"
            "  - Windows: Download from https://github.com/epi052/feroxbuster/releases\n"
            "  - Linux: sudo apt install feroxbuster (or cargo install feroxbuster)\n"
            "  - macOS: brew install feroxbuster"
        )
    return ferox_path


def parse_ferox_output(output: str) -> list[dict]:
    """
    Parse feroxbuster output into structured data.

    Feroxbuster output format:
    200      GET       10l       20w      300c http://target/path
    """
    discovered = []

    for line in output.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('['):
            continue

        parts = line.split()
        if len(parts) >= 5 and parts[0].isdigit():
            try:
                entry = {
                    "status_code": int(parts[0]),
                    "method": parts[1],
                    "lines": parts[2].rstrip('l'),
                    "words": parts[3].rstrip('w'),
                    "chars": parts[4].rstrip('c'),
                    "url": parts[5] if len(parts) > 5 else "",
                }
                discovered.append(entry)
            except (ValueError, IndexError):
                continue

    return discovered


async def run_feroxbuster(
    url: str,
    wordlist: str | None = None,
    extensions: list[str] | None = None,
    threads: int = 50,
    depth: int = 2,
    timeout: int = 300,
    extra_args: list[str] | None = None,
) -> FeroxResult:
    """
    Run feroxbuster directory brute-forcing against a URL.

    Args:
        url: Target URL (e.g., http://192.168.1.100)
        wordlist: Path to wordlist file (uses default if not specified)
        extensions: File extensions to check (e.g., ["php", "html", "txt"])
        threads: Number of concurrent threads
        depth: Recursion depth
        timeout: Scan timeout in seconds
        extra_args: Additional feroxbuster arguments

    Returns:
        FeroxResult with discovered paths
    """
    # Extract host from URL for scope validation
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc

    # SAFETY: Validate target is in scope
    validate_target(host)

    ferox_path = get_feroxbuster_path()

    # Build command
    cmd = [ferox_path, "-u", url]

    # Wordlist
    if wordlist:
        cmd.extend(["-w", wordlist])
    else:
        # Try common wordlist locations
        common_wordlists = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "C:\\wordlists\\common.txt",
        ]
        for wl in common_wordlists:
            if Path(wl).exists():
                cmd.extend(["-w", wl])
                wordlist = wl
                break
        else:
            return FeroxResult(
                url=url,
                wordlist="none",
                command=" ".join(cmd),
                raw_output="",
                discovered=[],
                error="No wordlist found. Specify a wordlist path.",
            )

    # Extensions
    if extensions:
        cmd.extend(["-x", ",".join(extensions)])

    # Threads and depth
    cmd.extend(["-t", str(threads)])
    cmd.extend(["-d", str(depth)])

    # Quiet mode for cleaner output
    cmd.append("-q")

    # Extra args
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
        error = result.stderr if result.returncode != 0 else None

        discovered = parse_ferox_output(output)

        return FeroxResult(
            url=url,
            wordlist=wordlist or "default",
            command=" ".join(cmd),
            raw_output=output,
            discovered=discovered,
            error=error,
        )

    except subprocess.TimeoutExpired:
        return FeroxResult(
            url=url,
            wordlist=wordlist or "default",
            command=" ".join(cmd),
            raw_output="",
            discovered=[],
            error=f"Scan timed out after {timeout} seconds",
        )
    except Exception as e:
        return FeroxResult(
            url=url,
            wordlist=wordlist or "default",
            command=" ".join(cmd),
            raw_output="",
            discovered=[],
            error=str(e),
        )
