# Tool Implementations

This directory contains individual tool implementations for your MCP server.

## Creating a Tool

### 1. Create a new file

```
tools/
├── __init__.py
├── your_tool.py      # Your new tool
└── another_tool.py
```

### 2. Implement the tool function

```python
"""
Your Tool - Brief description

Detailed explanation of what this tool does and when to use it.
"""

import asyncio
from pydantic import BaseModel, Field


# Define output schema (optional but recommended)
class YourToolResult(BaseModel):
    """Structured output from your tool."""
    status: str
    data: list[str] = Field(default_factory=list)
    message: str | None = None


async def run_your_tool(
    required_param: str,
    optional_param: int = 10,
) -> YourToolResult:
    """
    Execute your tool.

    Args:
        required_param: Description of required parameter
        optional_param: Description of optional parameter (default: 10)

    Returns:
        YourToolResult with the tool output

    Raises:
        ValueError: If parameters are invalid
        RuntimeError: If execution fails
    """
    # Validate inputs
    if not required_param:
        raise ValueError("required_param cannot be empty")

    # Do the work
    # result = await some_async_operation(required_param)

    # Return structured output
    return YourToolResult(
        status="success",
        data=["item1", "item2"],
        message=f"Processed {required_param}"
    )
```

### 3. Wire it up in server.py

```python
from .tools.your_tool import run_your_tool, YourToolResult

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="your_tool",
            description="...",
            inputSchema={...}
        ),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "your_tool":
        result = await run_your_tool(
            required_param=arguments["required_param"],
            optional_param=arguments.get("optional_param", 10),
        )
        return [TextContent(
            type="text",
            text=json.dumps(result.model_dump(), indent=2)
        )]
```

## Tool Design Guidelines

### 1. Single Responsibility

Each tool should do one thing well:

```python
# Good - focused tool
async def lookup_dns(domain: str, record_type: str) -> DNSResult: ...

# Bad - kitchen sink tool
async def network_operations(action: str, target: str, params: dict) -> dict: ...
```

### 2. Clear Input Schema

Help the LLM understand when and how to use the tool:

```python
Tool(
    name="analyze_file",
    description=(
        "Analyze a file for specific patterns. "
        "Use this when you need to search for content within a file. "
        "Returns matching lines with context."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Absolute path to the file to analyze"
            },
            "pattern": {
                "type": "string",
                "description": "Regex pattern to search for"
            },
            "context_lines": {
                "type": "integer",
                "default": 2,
                "description": "Number of lines to include before/after matches"
            }
        },
        "required": ["file_path", "pattern"]
    }
)
```

### 3. Structured Output

Always return structured data:

```python
# Good - machine-readable output
return YourToolResult(
    status="success",
    findings=[
        {"line": 42, "content": "match here", "context": [...]}
    ],
    total_matches=1
)

# Bad - human-only output
return "Found 1 match at line 42: match here"
```

### 4. Error Handling

Be specific about what went wrong:

```python
class ToolError(BaseModel):
    error: str  # Error category
    message: str  # Human-readable description
    details: dict | None = None  # Additional context

# Usage
if not file_exists(path):
    raise FileNotFoundError(f"File not found: {path}")

# In server.py call_tool():
except FileNotFoundError as e:
    return [TextContent(type="text", text=json.dumps({
        "error": "file_not_found",
        "message": str(e)
    }))]
```

### 5. Async When Appropriate

Use async for I/O-bound operations:

```python
# Good - async for network calls
async def fetch_data(url: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        return response.json()

# CPU-bound can be sync
def parse_data(raw: str) -> ParsedData:
    return ParsedData.model_validate_json(raw)
```

## Common Tool Patterns

### Wrapping CLI Tools

```python
import asyncio
import shutil

async def run_cli_tool(target: str) -> CliResult:
    # Check if tool is installed
    tool_path = shutil.which("tool-name")
    if not tool_path:
        raise FileNotFoundError("tool-name not found in PATH")

    # Run the command
    proc = await asyncio.create_subprocess_exec(
        tool_path, "--flag", target,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        raise RuntimeError(f"Command failed: {stderr.decode()}")

    return parse_output(stdout.decode())
```

### API Integrations

```python
import httpx
import os

class APIClient:
    def __init__(self):
        self.api_key = os.environ.get("API_KEY")
        if not self.api_key:
            raise ValueError("API_KEY environment variable required")

    async def query(self, params: dict) -> dict:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.example.com/endpoint",
                headers={"Authorization": f"Bearer {self.api_key}"},
                params=params,
            )
            response.raise_for_status()
            return response.json()
```

### Stateful Tools

If your tool needs to maintain state across calls:

```python
# Use module-level state (reset when server restarts)
_cache: dict[str, Any] = {}

async def cached_lookup(key: str) -> dict:
    if key in _cache:
        return {"cached": True, "data": _cache[key]}

    result = await expensive_lookup(key)
    _cache[key] = result
    return {"cached": False, "data": result}
```
