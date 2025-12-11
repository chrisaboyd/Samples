# Storage Library

Shared library for persisting scan data between agents and phases. This is NOT an MCP server - it's a Python library that agents import directly to avoid extra token/context overhead.

## Why a Shared Library?

Each MCP tool call consumes tokens for:
- Tool description in context
- Request formatting
- Response parsing

Since storage is used heavily by all agents, a shared library is more efficient:
- Direct Python calls (no JSON-RPC overhead)
- No tool definitions eating context
- Simpler error handling
- Easier to extend

## Design: JSON Now, SQLite Later

Current implementation uses JSON files for simplicity:
- Human-readable for debugging
- Easy to inspect/modify during development
- No database setup required

The API is designed to support SQLite later:
- Same interface, different backend
- Enable querying across scans
- Better for production/scaling

## Data Model

```
scans/
└── {scan_id}/
    ├── metadata.json       # Scan metadata (target, timestamps, status)
    ├── recon/              # Passive recon findings
    │   ├── dns.json
    │   ├── whois.json
    │   └── ...
    ├── scan/               # Active scan findings
    │   ├── ports.json
    │   ├── services.json
    │   └── ...
    ├── analysis/           # Analysis results
    │   ├── vulnerabilities.json
    │   ├── exploits.json
    │   └── ...
    └── report/             # Final reports
        ├── report.md
        └── report.json
```

## Models

### ScanMetadata
```python
class ScanMetadata(BaseModel):
    scan_id: str                    # Unique scan identifier
    target: str                     # Target (IP, hostname, CIDR)
    status: str                     # pending, recon, scanning, analysis, complete
    created_at: datetime
    updated_at: datetime
    phases_completed: list[str]     # ["recon", "scan", "analysis"]
    config: dict                    # Scan configuration
```

### Finding (Base)
```python
class Finding(BaseModel):
    id: str                         # Unique finding ID
    scan_id: str                    # Parent scan
    phase: str                      # recon, scan, analysis
    tool: str                       # Tool that produced this
    target: str                     # Specific target
    timestamp: datetime
    data: dict                      # Tool-specific data
```

### ReconFinding
```python
class ReconFinding(Finding):
    phase: str = "recon"
    record_type: str | None         # DNS record type, etc.
```

### ScanFinding
```python
class ScanFinding(Finding):
    phase: str = "scan"
    port: int | None
    protocol: str | None
    service: str | None
    version: str | None
```

### AnalysisFinding
```python
class AnalysisFinding(Finding):
    phase: str = "analysis"
    related_finding_id: str         # ID of recon/scan finding this enriches
    vulnerabilities: list[VulnerabilityInfo]
    mitre_techniques: list[str]
    remediation: str | None
```

## API

### ScanStorage

```python
class ScanStorage:
    def __init__(self, base_path: str = "scans"):
        """Initialize storage with base directory."""

    # Scan lifecycle
    def init_scan(self, scan_id: str, target: str, config: dict = None) -> ScanMetadata:
        """Create a new scan."""

    def get_scan(self, scan_id: str) -> ScanMetadata | None:
        """Get scan metadata."""

    def update_scan_status(self, scan_id: str, status: str):
        """Update scan status."""

    def list_scans(self) -> list[ScanMetadata]:
        """List all scans."""

    # Findings
    def store_finding(self, finding: Finding):
        """Store a finding."""

    def get_findings(
        self,
        scan_id: str,
        phase: str | None = None,
        tool: str | None = None,
    ) -> list[Finding]:
        """Get findings with optional filters."""

    def get_finding(self, scan_id: str, finding_id: str) -> Finding | None:
        """Get a specific finding by ID."""

    # Convenience methods
    def get_recon_findings(self, scan_id: str) -> list[ReconFinding]:
        """Get all recon findings for a scan."""

    def get_scan_findings(self, scan_id: str) -> list[ScanFinding]:
        """Get all scan findings for a scan."""

    def get_analysis_findings(self, scan_id: str) -> list[AnalysisFinding]:
        """Get all analysis findings for a scan."""

    def get_services(self, scan_id: str) -> list[dict]:
        """Get discovered services (for analysis phase input)."""

    # Reports
    def store_report(self, scan_id: str, format: str, content: str):
        """Store a generated report."""

    def get_report(self, scan_id: str, format: str) -> str | None:
        """Get a stored report."""
```

## Usage

```python
from storage import ScanStorage, ScanFinding

# Initialize
storage = ScanStorage()

# Create a scan
metadata = storage.init_scan(
    scan_id="ms2-2024-01-15-001",
    target="192.168.1.100",
    config={"mode": "full"}
)

# Store a finding
finding = ScanFinding(
    id="finding-001",
    scan_id="ms2-2024-01-15-001",
    tool="nmap",
    target="192.168.1.100",
    timestamp=datetime.now(),
    port=21,
    protocol="tcp",
    service="ftp",
    version="vsftpd 2.3.4",
    data={"banner": "220 (vsFTPd 2.3.4)"}
)
storage.store_finding(finding)

# Retrieve for analysis
services = storage.get_services("ms2-2024-01-15-001")
# [{"port": 21, "service": "ftp", "version": "vsftpd 2.3.4", ...}]
```

## Future: SQLite Backend

When ready to scale:

```python
class SQLiteScanStorage(ScanStorage):
    """SQLite implementation with same API."""

    def __init__(self, db_path: str = "scans.db"):
        # Initialize SQLite database
        pass

    # Same methods, but using SQL queries
```

Switch with a config flag:
```python
def get_storage(backend: str = "json") -> ScanStorage:
    if backend == "sqlite":
        return SQLiteScanStorage()
    return ScanStorage()  # JSON default
```
