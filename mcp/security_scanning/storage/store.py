# TODO: Implement ScanStorage class
# See README.md for full specification
#
# This is the main storage interface. Start with JSON files,
# design API to support SQLite later.

"""
Scan storage implementation.

JSON file-based storage for scan data. Designed with an API
that can be swapped to SQLite for production use.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Type, TypeVar

from .models import (
    ScanMetadata,
    Finding,
    ReconFinding,
    ScanFinding,
    AnalysisFinding,
)

T = TypeVar("T", bound=Finding)


class ScanStorage:
    """
    JSON file-based storage for scan data.

    Directory structure:
        {base_path}/
        └── {scan_id}/
            ├── metadata.json
            ├── recon/
            │   └── {finding_id}.json
            ├── scan/
            │   └── {finding_id}.json
            ├── analysis/
            │   └── {finding_id}.json
            └── report/
                ├── report.md
                └── report.json
    """

    def __init__(self, base_path: str | Path = "scans"):
        """
        Initialize storage.

        Args:
            base_path: Base directory for scan data
        """
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)

    def _scan_path(self, scan_id: str) -> Path:
        """Get path to scan directory."""
        return self.base_path / scan_id

    def _metadata_path(self, scan_id: str) -> Path:
        """Get path to metadata file."""
        return self._scan_path(scan_id) / "metadata.json"

    def _phase_path(self, scan_id: str, phase: str) -> Path:
        """Get path to phase directory."""
        return self._scan_path(scan_id) / phase

    # --- Scan Lifecycle ---

    def init_scan(
        self,
        scan_id: str,
        target: str,
        config: dict | None = None,
    ) -> ScanMetadata:
        """
        Create a new scan.

        Args:
            scan_id: Unique scan identifier
            target: Target to scan
            config: Optional scan configuration

        Returns:
            ScanMetadata for the new scan
        """
        # TODO: Implement
        raise NotImplementedError

    def get_scan(self, scan_id: str) -> ScanMetadata | None:
        """Get scan metadata."""
        # TODO: Implement
        raise NotImplementedError

    def update_scan_status(self, scan_id: str, status: str):
        """Update scan status."""
        # TODO: Implement
        raise NotImplementedError

    def list_scans(self) -> list[ScanMetadata]:
        """List all scans."""
        # TODO: Implement
        raise NotImplementedError

    # --- Findings ---

    def store_finding(self, finding: Finding):
        """Store a finding."""
        # TODO: Implement
        raise NotImplementedError

    def get_findings(
        self,
        scan_id: str,
        phase: str | None = None,
        tool: str | None = None,
    ) -> list[Finding]:
        """Get findings with optional filters."""
        # TODO: Implement
        raise NotImplementedError

    def get_finding(self, scan_id: str, finding_id: str) -> Finding | None:
        """Get a specific finding by ID."""
        # TODO: Implement
        raise NotImplementedError

    # --- Convenience Methods ---

    def get_recon_findings(self, scan_id: str) -> list[ReconFinding]:
        """Get all recon findings for a scan."""
        # TODO: Implement
        raise NotImplementedError

    def get_scan_findings(self, scan_id: str) -> list[ScanFinding]:
        """Get all scan findings for a scan."""
        # TODO: Implement
        raise NotImplementedError

    def get_analysis_findings(self, scan_id: str) -> list[AnalysisFinding]:
        """Get all analysis findings for a scan."""
        # TODO: Implement
        raise NotImplementedError

    def get_services(self, scan_id: str) -> list[dict]:
        """
        Get discovered services for analysis phase.

        Returns a simplified list of services suitable for
        vulnerability research.
        """
        # TODO: Implement
        raise NotImplementedError

    # --- Reports ---

    def store_report(self, scan_id: str, format: str, content: str):
        """
        Store a generated report.

        Args:
            scan_id: Scan ID
            format: Report format (md, json)
            content: Report content
        """
        # TODO: Implement
        raise NotImplementedError

    def get_report(self, scan_id: str, format: str) -> str | None:
        """Get a stored report."""
        # TODO: Implement
        raise NotImplementedError


def generate_scan_id(prefix: str = "scan") -> str:
    """Generate a unique scan ID."""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{timestamp}"


def generate_finding_id(tool: str) -> str:
    """Generate a unique finding ID."""
    import uuid
    short_uuid = str(uuid.uuid4())[:8]
    return f"{tool}-{short_uuid}"
