# Report Generator

Generates final reports from scan data in Markdown and JSON formats.

## Purpose

The report generator is the final phase of the orchestrated workflow:
1. Recon → findings stored
2. Scanning → findings stored
3. Analysis → enriched findings stored
4. **Reporting** → consolidated output

## Output Formats

### Markdown Report
Human-readable report suitable for:
- Sharing with stakeholders
- Including in documentation
- Reviewing findings manually

### JSON Report
Machine-readable report suitable for:
- Importing into other tools
- Automated processing
- API responses

## Report Structure

### Executive Summary
- Target information
- Scan timeline
- High-level findings count by severity
- Key risks identified

### MITRE ATT&CK Coverage
- Phases covered (Reconnaissance, Resource Development)
- Techniques identified
- Explicit note on phases NOT covered (Exploitation, Escalation, Persistence)

### Findings by Phase

#### Reconnaissance Findings
- DNS records discovered
- WHOIS information
- Shodan data (if available)
- Certificate transparency results
- Infrastructure mapping

#### Scanning Findings
- Open ports and services
- Service versions
- Vulnerability script results
- Web content discovered

#### Analysis Findings
- CVEs identified
- CVSS scores and severity
- Available exploits
- Remediation recommendations

### Recommendations
- Prioritized remediation steps
- Quick wins vs long-term fixes
- References to vendor advisories

### Appendix
- Raw tool outputs (optional)
- Full finding details
- Methodology notes

## Usage

```python
from reporting import ReportGenerator
from storage import ScanStorage

storage = ScanStorage()
generator = ReportGenerator(storage)

# Generate both formats
markdown = generator.generate_markdown("scan-id-123")
json_report = generator.generate_json("scan-id-123")

# Or save directly
generator.save_reports("scan-id-123")
# Creates: scans/scan-id-123/report/report.md
#          scans/scan-id-123/report/report.json
```

## Templates

Report templates are in `templates/` subdirectory:
- `report.md.j2` - Jinja2 template for Markdown
- (JSON is generated directly from data structures)

## Customization

Override the default templates or extend `ReportGenerator`:

```python
class CustomReportGenerator(ReportGenerator):
    def _get_executive_summary(self, scan_id: str) -> str:
        # Custom summary logic
        pass
```
