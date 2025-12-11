# TODO: Implement Pydantic models for storage
# See README.md for full specification
#
# Models to implement:
# - ScanMetadata: Scan-level metadata
# - Finding: Base finding class
# - ReconFinding: Passive recon findings
# - ScanFinding: Active scan findings
# - AnalysisFinding: Analysis/enrichment findings
# - VulnerabilityInfo: CVE/vulnerability details
# - ExploitInfo: Exploit details

"""
Storage models for scan data.

These Pydantic models define the schema for all stored data.
They're used by agents to structure findings and by the storage
library to validate/serialize data.
"""

from datetime import datetime
from pydantic import BaseModel, Field
from typing import Any


class ScanMetadata(BaseModel):
    """Metadata for a scan session."""
    scan_id: str
    target: str
    status: str = "pending"  # pending, recon, scanning, analysis, complete, failed
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    phases_completed: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """Base class for all findings."""
    id: str
    scan_id: str
    phase: str  # recon, scan, analysis
    tool: str
    target: str
    timestamp: datetime = Field(default_factory=datetime.now)
    data: dict[str, Any] = Field(default_factory=dict)


class ReconFinding(Finding):
    """Finding from passive reconnaissance."""
    phase: str = "recon"
    record_type: str | None = None  # DNS record type, etc.


class ScanFinding(Finding):
    """Finding from active scanning."""
    phase: str = "scan"
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    version: str | None = None


class ExploitInfo(BaseModel):
    """Information about a known exploit."""
    source: str  # exploit-db, metasploit, github, etc.
    id: str  # EDB-ID, module path, etc.
    title: str
    type: str  # remote, local, webapps, dos, etc.
    platform: str | None = None
    url: str | None = None
    verified: bool = False


class VulnerabilityInfo(BaseModel):
    """Information about a vulnerability."""
    cve_id: str | None = None
    title: str
    description: str
    severity: str  # Critical, High, Medium, Low, Info
    cvss_score: float | None = None
    cvss_vector: str | None = None
    affected_products: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    exploits: list[ExploitInfo] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    remediation: str | None = None


class AnalysisFinding(Finding):
    """Finding from vulnerability analysis."""
    phase: str = "analysis"
    related_finding_id: str | None = None  # ID of recon/scan finding this enriches
    vulnerabilities: list[VulnerabilityInfo] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    remediation: str | None = None
