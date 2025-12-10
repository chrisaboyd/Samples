# Security Scanner Agent - Project Context

## Project Overview

This is a proof-of-concept security scanning system built with LLM agents and MCP (Model Context Protocol) servers. The goal is to demonstrate automated vulnerability assessment using AI-driven tool orchestration.

**Target environment**: Metasploitable 2 (intentionally vulnerable VM for testing)
- Reference: https://docs.rapid7.com/metasploit/metasploitable-2-exploitability-guide/


## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Orchestrator Agent                         │
│         (planning, task decomposition, scope control)           │
└─────────────────────────┬───────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│ Recon Agent   │ │ Scanner Agent │ │ Analysis Agent│
│ (passive)     │ │ (active)      │ │ (synthesis)   │
└───────┬───────┘ └───────┬───────┘ └───────┬───────┘
        │                 │                 │
        ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│  MCP Server   │ │  MCP Server   │ │  MCP Server   │
│  (Shodan,DNS) │ │ (nmap,ferox)  │ │ (results DB)  │
└───────────────┘ └───────────────┘ └───────────────┘
```

### Why This Separation

**Passive vs Active separation** is the critical boundary:
- **Risk profile**: Passive recon can't break anything or trigger alerts. Active scanning can crash services, trigger IDS, or have legal implications.
- **Rate limiting**: Shodan has API limits; nmap is constrained by network speed and stealth requirements.
- **Permissions model**: Some users may run passive recon but not active scans.

**Analysis as separate agent** enables expansion:
- Receives structured results, not raw tool access
- Can be swapped/improved without touching scanning logic
- Can feed into reporting, ticketing, or remediation workflows

## Repository Structure

```
mcp/
├── README.md
├── pyproject.toml
├── config/
│   └── targets.yaml            # Allowed scan targets (safety guardrail)
│
├── mcp_servers/
│   ├── __init__.py
│   ├── recon/                  # Passive reconnaissance
│   │   ├── __init__.py
│   │   ├── server.py           # MCP server entry point
│   │   ├── tools/
│   │   │   ├── shodan.py
│   │   │   ├── dns.py
│   │   │   └── whois.py
│   │   └── README.md
│   │
│   ├── scanner/                # Active scanning
│   │   ├── __init__.py
│   │   ├── server.py
│   │   ├── tools/
│   │   │   ├── nmap.py
│   │   │   ├── feroxbuster.py
│   │   │   └── nikto.py
│   │   ├── scope.py            # Target validation
│   │   └── README.md
│   │
│   └── results/                # Results storage
│       ├── __init__.py
│       ├── server.py
│       ├── storage.py          # SQLite or file-based
│       └── models.py           # Finding schemas
│
├── agents/
│   ├── __init__.py
│   ├── base.py                 # Shared agent infrastructure
│   ├── recon_agent.py
│   ├── scanner_agent.py
│   ├── analysis_agent.py
│   └── orchestrator.py         # Coordinates others (later phase)
│
├── prompts/                    # System prompts for agents
│   ├── recon.md
│   ├── scanner.md
│   └── analysis.md
│
├── cli.py                      # Main entry point
│
└── tests/
    ├── test_mcp_recon.py
    ├── test_mcp_scanner.py
    └── test_agents.py
```

## MCP Runtime Model

MCP servers run in **stdio mode** for this project (not HTTP). The client spawns the server as a subprocess and communicates via stdin/stdout JSON-RPC. When the client disconnects, the server exits.

```
Agent starts
  → spawns `python -m mcp_servers.recon.server` as subprocess
  → sends JSON-RPC over stdin
  → receives responses over stdout
Agent finishes
  → subprocess exits
```

This is simpler than HTTP/SSE mode and doesn't require hosting infrastructure.

## MCP Server Tool Specifications

### Passive Recon MCP (`mcp_servers/recon/`)

Safe to run freely, no target restrictions needed.

| Tool | Parameters | Description |
|------|------------|-------------|
| `dns_lookup` | target, record_type (A/AAAA/MX/TXT/NS/PTR) | DNS record lookup |
| `reverse_dns` | ip | PTR record lookup |
| `whois` | domain | Domain registration info |
| `shodan_host` | ip | Open ports, banners, vulns, historical data |
| `shodan_search` | query | Discover hosts matching criteria |
| `cert_search` | domain | Certificate transparency logs |

### Active Scanner MCP (`mcp_servers/scanner/`)

Requires target validation against allowlist before execution.

| Tool | Parameters | Description |
|------|------------|-------------|
| `nmap_scan` | target, profile, ports | Port/service scanning. Profiles: quick, full, stealth, service_version, vuln_scripts |
| `feroxbuster` | url, wordlist, extensions, threads | Directory/file brute forcing |
| `nikto` | target | Web server misconfiguration scanning |
| `whatweb` | url | Technology fingerprinting |

### Results MCP (`mcp_servers/results/`)

Persistence and handoff between agents.

| Tool | Parameters | Description |
|------|------------|-------------|
| `store_finding` | scan_id, finding_type, data | Store a finding |
| `get_findings` | scan_id, filters | Retrieve findings |
| `get_scan_summary` | scan_id | Summary statistics |
| `export_results` | scan_id, format | Export as JSON/markdown |

## Structured Finding Format

Agents communicate via structured findings, not raw text:

```yaml
scan_id: "ms2-2024-01-15-001"
target: "192.168.1.100"
findings:
  - type: open_port
    port: 21
    service: vsftpd 2.3.4
    confidence: high
    raw_banner: "220 (vsFTPd 2.3.4)"
    
  - type: potential_vuln
    port: 21
    service: vsftpd
    cve: CVE-2011-2523
    description: "vsftpd 2.3.4 backdoor command execution"
    source: nmap_vuln_scripts
    
  - type: directory_found
    url: "http://192.168.1.100/phpinfo.php"
    status: 200
    notes: "PHP configuration disclosure"
```

## Code Patterns

### MCP Server Pattern

```python
# mcp_servers/recon/server.py
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
import subprocess

server = Server("recon-server")

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="dns_lookup",
            description="Perform DNS lookup for a target domain or IP",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Domain or IP to look up"},
                    "record_type": {"type": "string", "enum": ["A", "AAAA", "MX", "TXT", "NS", "PTR"], "default": "A"}
                },
                "required": ["target"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "dns_lookup":
        result = subprocess.run(
            ["dig", "+short", arguments.get("record_type", "A"), arguments["target"]],
            capture_output=True, text=True
        )
        return [TextContent(type="text", text=result.stdout or "No records found")]
    
    raise ValueError(f"Unknown tool: {name}")

async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

### Agent Pattern

```python
# agents/recon_agent.py
from anthropic import Anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

class ReconAgent:
    def __init__(self):
        self.anthropic = Anthropic()
        self.system_prompt = open("prompts/recon.md").read()
    
    async def run(self, task: str):
        server_params = StdioServerParameters(
            command="python",
            args=["-m", "mcp_servers.recon.server"]
        )
        
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                
                tools_result = await session.list_tools()
                tools = self._convert_to_anthropic_tools(tools_result.tools)
                
                messages = [{"role": "user", "content": task}]
                
                while True:
                    response = self.anthropic.messages.create(
                        model="claude-sonnet-4-20250514",
                        max_tokens=4096,
                        system=self.system_prompt,
                        tools=tools,
                        messages=messages
                    )
                    
                    if response.stop_reason == "end_turn":
                        return self._extract_text(response)
                    
                    if response.stop_reason == "tool_use":
                        tool_results = []
                        for block in response.content:
                            if block.type == "tool_use":
                                result = await session.call_tool(block.name, block.input)
                                tool_results.append({
                                    "type": "tool_result",
                                    "tool_use_id": block.id,
                                    "content": result.content[0].text
                                })
                        
                        messages.append({"role": "assistant", "content": response.content})
                        messages.append({"role": "user", "content": tool_results})
```

## Safety Guardrails

1. **Explicit scope**: Active scanning MCP must validate targets against `config/targets.yaml` allowlist
2. **Audit logging**: Every tool invocation logged with timestamp, parameters, results
3. **Rate limiting**: Especially for Shodan API and to avoid overwhelming targets
4. **Confirmation for destructive operations**: If expanding to exploitation, require human approval

## Development Phases

### Phase 1: Single MCP Server (CURRENT)
- [ ] Set up project structure and dependencies
- [ ] Implement recon MCP server with `dns_lookup` and `reverse_dns`
- [ ] Test MCP server manually with JSON-RPC
- [ ] Implement minimal agent that connects to MCP server
- [ ] Test against Metasploitable 2

### Phase 2: Active Scanning
- [ ] Implement scanner MCP server with `nmap_scan`
- [ ] Add scope validation (targets.yaml allowlist)
- [ ] Add `feroxbuster` tool
- [ ] Create scanner agent

### Phase 3: Results & Analysis
- [ ] Implement results MCP server with SQLite storage
- [ ] Define finding schema (Pydantic models)
- [ ] Implement analysis agent
- [ ] Create structured handoff between scanning → analysis

### Phase 4: Polish
- [ ] CLI interface
- [ ] Error handling and retries
- [ ] Reporting output formats
- [ ] Documentation

## Dependencies

```toml
[project]
dependencies = [
    "mcp",
    "anthropic",
    "python-nmap",
    "shodan",
    "pydantic",
    "click",  # for CLI
    "rich",   # for terminal output
]
```

## Testing Commands

```bash
# Test MCP server directly (JSON-RPC over stdio)
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | python -m mcp_servers.recon.server

# Run agent CLI
python cli.py scan --target 192.168.1.100 --mode passive

# Interactive mode
python cli.py interactive
```

## Key Design Decisions

1. **Monorepo**: All components in one repo for easier iteration during PoC phase
2. **stdio MCP**: Simpler than HTTP, no hosting infrastructure needed
3. **Task-based agents**: Invoked per-task, not long-running services
4. **Structured findings**: JSON/YAML format for agent-to-agent handoff
5. **Python**: Using official `mcp` SDK and `anthropic` SDK

## Reference Links

- MCP Python SDK: https://github.com/modelcontextprotocol/python-sdk
- Anthropic Python SDK: https://github.com/anthropics/anthropic-sdk-python
- Metasploitable 2 Guide: https://docs.rapid7.com/metasploit/metasploitable-2-exploitability-guide/
