# MCP Servers

This directory contains MCP (Model Context Protocol) server implementations. Each server exposes a set of tools that LLM agents can invoke.

## What is an MCP Server?

An MCP server is a process that:
1. Exposes tools via the Model Context Protocol
2. Communicates with agents over stdio (JSON-RPC)
3. Executes tool calls and returns results

## Creating a New MCP Server

### 1. Create the directory structure

```
mcp_servers/
└── your_server/
    ├── __init__.py
    ├── server.py          # MCP server entry point
    ├── README.md          # Document your server
    └── tools/
        ├── __init__.py
        └── your_tool.py   # Individual tool implementations
```

### 2. Implement server.py

```python
import asyncio
import json
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

server = Server("your-server-name")

@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="your_tool",
            description="What this tool does",
            inputSchema={
                "type": "object",
                "properties": {
                    "param1": {
                        "type": "string",
                        "description": "Description of param1"
                    },
                },
                "required": ["param1"]
            }
        ),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Execute a tool."""
    if name == "your_tool":
        result = do_something(arguments["param1"])
        return [TextContent(type="text", text=json.dumps(result))]

    raise ValueError(f"Unknown tool: {name}")

async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
```

### 3. Implement your tools

See [tools/README.md](your_server/tools/README.md) for tool implementation patterns.

## Testing Your Server

### Manual JSON-RPC testing

```bash
# List available tools
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | python -m mcp_servers.your_server.server

# Call a tool
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"your_tool","arguments":{"param1":"value"}}}' | python -m mcp_servers.your_server.server
```

### Python testing

```python
import pytest
from mcp_servers.your_server.tools.your_tool import your_function

@pytest.mark.asyncio
async def test_your_tool():
    result = await your_function(param1="test")
    assert result is not None
```

## Design Patterns

### Structured Output

Always return structured data (JSON) from tools, not raw text:

```python
# Good - structured output
return {"status": "success", "data": [...], "count": 5}

# Bad - raw text
return "Found 5 items"
```

### Error Handling

Return errors in a consistent format:

```python
try:
    result = do_something()
    return [TextContent(type="text", text=json.dumps(result))]
except ValidationError as e:
    return [TextContent(type="text", text=json.dumps({
        "error": "validation_error",
        "message": str(e)
    }))]
```

### Input Validation

Use Pydantic models for complex inputs:

```python
from pydantic import BaseModel, Field

class ToolInput(BaseModel):
    target: str = Field(..., description="Target to process")
    options: dict = Field(default_factory=dict)

# In call_tool:
validated = ToolInput(**arguments)
```

## Common Patterns

### Rate Limiting

```python
import asyncio
from datetime import datetime, timedelta

last_call: datetime | None = None
MIN_INTERVAL = timedelta(seconds=1)

async def rate_limited_call():
    global last_call
    if last_call:
        elapsed = datetime.now() - last_call
        if elapsed < MIN_INTERVAL:
            await asyncio.sleep((MIN_INTERVAL - elapsed).total_seconds())
    last_call = datetime.now()
    # ... proceed with call
```

### Scope Validation

For tools that operate on external resources, validate against an allowlist:

```python
def validate_target(target: str) -> bool:
    allowed = load_allowed_targets()  # From config
    return target in allowed

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if not validate_target(arguments["target"]):
        return [TextContent(type="text", text=json.dumps({
            "error": "scope_violation",
            "message": f"Target {arguments['target']} not in scope"
        }))]
```
