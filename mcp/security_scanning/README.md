# Security Scanner PoC

AI-driven security scanning system using MCP (Model Context Protocol).

## Quick Start

### 1. Install Dependencies

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install package
pip install -e .
```

### 2. Install Scanning Tools

The scanner requires these tools to be installed:

- **nmap**: https://nmap.org/download.html
- **feroxbuster**: https://github.com/epi052/feroxbuster
- **nikto**: https://github.com/sullo/nikto

Check installation:
```bash
python cli.py check-tools
```

### 3. Configure Scope

Edit `config/targets.yaml` to add your Metasploitable 2 IP:

```yaml
allowed_targets:
  - name: "metasploitable2"
    hosts:
      - "192.168.56.101"  # Your Metasploitable IP
```

### 4. Set API Key

```bash
export POOLSIDE_API_KEY="your-key-here"
```

### 5. Run a Scan

```bash
# Check if target is in scope
python cli.py check-scope 192.168.56.101

# Run a scan
python cli.py scan 192.168.56.101 -v

# Interactive mode
python cli.py interactive
```

## Project Structure

```
mcp/
├── config/
│   └── targets.yaml          # Allowed scan targets
├── mcp_servers/
│   └── scanner/
│       ├── server.py         # MCP server entry point
│       ├── scope.py          # Target validation
│       └── tools/
│           ├── nmap.py       # Nmap integration
│           ├── feroxbuster.py
│           └── nikto.py
├── agents/
│   ├── base.py               # Base agent class
│   └── scanner_agent.py      # Active scanning agent
├── prompts/
│   └── scanner.md            # Agent system prompt
└── cli.py                    # CLI interface
```

## Testing the MCP Server Directly

```bash
# List available tools
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | python -m mcp_servers.scanner.server
```

## Safety

- All active scans are validated against `config/targets.yaml`
- Targets not in scope are rejected before any scan executes
- This is for authorized security testing only
