# Analysis MCP Server

Exposes vulnerability research and analysis tools. Takes structured findings from recon/scanning phases and enriches them with CVE data, exploit information, and remediation guidance.

## MITRE ATT&CK Mapping

This server supports the **Weaponization / Resource Development** phase (TA0042):
- T1588.005: Obtain Capabilities: Exploits
- T1588.006: Obtain Capabilities: Vulnerabilities

**Important**: This tool is for RESEARCH ONLY. We gather information about vulnerabilities and exploits but do NOT execute them. This data feeds into reporting and would inform a future exploitation phase (out of scope for this project).

## Purpose

The analysis phase bridges recon/scanning and reporting by:
1. Taking structured findings (open ports, service versions, etc.)
2. Researching known vulnerabilities for those services
3. Finding available exploits/PoCs
4. Mapping to MITRE ATT&CK techniques
5. Providing remediation recommendations

## Tools to Implement

### search_nvd
- **Purpose**: Search NIST National Vulnerability Database
- **Input**: `query` (CPE, keyword, or CVE ID)
- **Output**: CVE details, CVSS scores, descriptions, references
- **Backend**: NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0)
- **Rate Limit**: Be mindful of NVD rate limits (no API key = slower)

### search_exploitdb
- **Purpose**: Search Exploit-DB for known exploits
- **Input**: `query` (service name, CVE, keyword)
- **Output**: Exploit titles, types, platforms, EDB-IDs
- **CLI Backend**: `searchsploit` (from exploit-db package)
- **Behavior**: If searchsploit not installed, return graceful error

### search_metasploit
- **Purpose**: Search Metasploit modules for a target
- **Input**: `query` (service name, CVE, keyword)
- **Output**: Module paths, descriptions, ranks, references
- **CLI Backend**: `msfconsole -q -x "search <query>; exit"`
- **Behavior**: If msfconsole not installed, return graceful error

### lookup_cve
- **Purpose**: Get detailed information for a specific CVE
- **Input**: `cve_id` (e.g., "CVE-2021-44228")
- **Output**: Full CVE details, CVSS, affected products, references, exploits
- **Backend**: Combines NVD + Exploit-DB data

### web_research
- **Purpose**: Web search for vulnerability information
- **Input**: `query` (search terms)
- **Output**: Relevant findings from security sources
- **Backend**: LLM web search capability
- **Use Case**: When CVE/exploit DBs don't have info, or for recent vulns

### map_to_mitre
- **Purpose**: Map a finding to MITRE ATT&CK techniques
- **Input**: `finding` (structured finding from recon/scan)
- **Output**: Relevant MITRE techniques, tactics, mitigations
- **Backend**: Local MITRE ATT&CK data or API

### get_remediation
- **Purpose**: Get remediation recommendations for a vulnerability
- **Input**: `cve_id` or `service_version` (e.g., "vsftpd 2.3.4")
- **Output**: Patch info, workarounds, configuration changes
- **Backend**: Combines vendor advisories, NVD references, best practices

## Output Schema

All tools should return structured output:

```python
class AnalysisResult(BaseModel):
    tool: str                          # Tool name
    query: str                         # What was searched
    timestamp: datetime                # When the query was made
    success: bool                      # Whether query succeeded
    data: dict | list                  # Tool-specific results
    error: str | None                  # Error if success=False

class VulnerabilityInfo(BaseModel):
    cve_id: str | None                 # CVE identifier if known
    title: str                         # Brief description
    description: str                   # Full description
    severity: str                      # Critical/High/Medium/Low/Info
    cvss_score: float | None           # CVSS score if available
    cvss_vector: str | None            # CVSS vector string
    affected_products: list[str]       # CPEs or product names
    references: list[str]              # URLs to advisories, etc.
    exploits: list[ExploitInfo]        # Known exploits
    mitre_techniques: list[str]        # MITRE ATT&CK technique IDs
    remediation: str | None            # Fix recommendations

class ExploitInfo(BaseModel):
    source: str                        # exploit-db, metasploit, github, etc.
    id: str                            # EDB-ID, module path, etc.
    title: str                         # Exploit title
    type: str                          # remote, local, webapps, dos, etc.
    platform: str                      # Target platform
    url: str | None                    # Link to exploit
    verified: bool                     # Whether it's verified/tested
```

## Example Usage

```python
# From agent - research a discovered service
result = await session.call_tool("search_nvd", {
    "query": "vsftpd 2.3.4"
})

# Expected output
{
    "tool": "search_nvd",
    "query": "vsftpd 2.3.4",
    "timestamp": "2024-01-15T10:30:00Z",
    "success": true,
    "data": {
        "total_results": 1,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2011-2523",
                "title": "vsftpd 2.3.4 Backdoor Command Execution",
                "severity": "Critical",
                "cvss_score": 9.8,
                "description": "vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor...",
                "references": ["http://...", "..."]
            }
        ]
    }
}
```

## Combining Sources

The analysis agent should combine multiple sources for comprehensive results:

```
Service: vsftpd 2.3.4
    │
    ├── search_nvd("vsftpd 2.3.4")
    │   └── CVE-2011-2523, CVSS 9.8
    │
    ├── search_exploitdb("vsftpd 2.3.4")
    │   └── EDB-ID: 17491 (Metasploit), 49757 (Python)
    │
    ├── search_metasploit("vsftpd")
    │   └── exploit/unix/ftp/vsftpd_234_backdoor
    │
    ├── map_to_mitre(finding)
    │   └── T1190 (Exploit Public-Facing Application)
    │
    └── get_remediation("CVE-2011-2523")
        └── "Upgrade to vsftpd >= 2.3.5 or verify package integrity"
```

## Error Handling

- **Tool not installed**: Return `success=False` with message indicating which tool is missing
- **API errors**: Return `success=False` with error details
- **No results**: Return `success=True` with empty data (no results is valid)
- **Rate limiting**: Implement backoff, return partial results if available
