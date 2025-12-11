# Passive Recon MCP Server

Exposes passive reconnaissance tools that gather information without directly interacting with the target.

## MITRE ATT&CK Mapping

This server supports the **Reconnaissance** phase (TA0043):
- T1589: Gather Victim Identity Information
- T1590: Gather Victim Network Information
- T1591: Gather Victim Org Information
- T1593: Search Open Websites/Domains
- T1596: Search Open Technical Databases

## Scope Validation

Even though these are passive tools, all targets MUST be validated against `config/targets.yaml` before execution. This ensures we only gather information on authorized targets.

## Tools to Implement

### dns_lookup
- **Purpose**: DNS record lookup (A, AAAA, MX, TXT, NS, PTR, CNAME)
- **Input**: `target` (domain/IP), `record_type` (default: A)
- **Output**: Structured DNS records
- **CLI Backend**: `dig` or Python `dnspython`

### reverse_dns
- **Purpose**: PTR record lookup for IP addresses
- **Input**: `ip`
- **Output**: Hostname(s) associated with IP
- **CLI Backend**: `dig -x` or Python `dnspython`

### whois_lookup
- **Purpose**: Domain/IP registration information
- **Input**: `target` (domain or IP)
- **Output**: Registrar, dates, nameservers, contact info (redacted)
- **CLI Backend**: `whois` or Python `python-whois`

### shodan_host
- **Purpose**: Query Shodan for host information
- **Input**: `ip`
- **Output**: Open ports, banners, vulns, hostnames, location
- **Requires**: `SHODAN_API_KEY` environment variable
- **Behavior**: If API key not set, return graceful error message (don't fail)

### shodan_search
- **Purpose**: Search Shodan for hosts matching criteria
- **Input**: `query` (Shodan search syntax)
- **Output**: List of matching hosts with summary info
- **Requires**: `SHODAN_API_KEY` environment variable

### cert_transparency
- **Purpose**: Search certificate transparency logs
- **Input**: `domain`
- **Output**: Certificates issued for domain, subdomains discovered
- **CLI Backend**: `crt.sh` API or similar

### recon_ng_module
- **Purpose**: Run a recon-ng module
- **Input**: `module` (module path), `options` (dict of module options)
- **Output**: Module results
- **CLI Backend**: `recon-ng` CLI
- **Note**: Requires recon-ng to be installed; graceful error if not available

## Output Schema

All tools should return structured output following this pattern:

```python
class ReconResult(BaseModel):
    tool: str                    # Tool name that produced this
    target: str                  # Target that was queried
    timestamp: datetime          # When the query was made
    success: bool                # Whether the query succeeded
    data: dict | list            # Tool-specific structured data
    raw_output: str | None       # Raw output for debugging
    error: str | None            # Error message if success=False
```

## Error Handling

- **Missing API key**: Return `success=False` with helpful error message
- **Target not in scope**: Return `success=False` with scope violation error
- **Tool not installed**: Return `success=False` indicating tool unavailable
- **Network errors**: Return `success=False` with error details

## Example Usage

```python
# From agent
result = await session.call_tool("dns_lookup", {
    "target": "example.com",
    "record_type": "MX"
})

# Expected output
{
    "tool": "dns_lookup",
    "target": "example.com",
    "timestamp": "2024-01-15T10:30:00Z",
    "success": true,
    "data": {
        "record_type": "MX",
        "records": [
            {"priority": 10, "value": "mail.example.com"},
            {"priority": 20, "value": "mail2.example.com"}
        ]
    },
    "raw_output": "...",
    "error": null
}
```
