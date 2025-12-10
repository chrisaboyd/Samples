# System Prompts

System prompts define how your agents behave. They're loaded from markdown files in this directory.

## What Goes in a System Prompt?

A good system prompt includes:

1. **Role definition**: Who/what the agent is
2. **Capabilities**: What tools are available and when to use them
3. **Output format**: How to structure responses
4. **Constraints**: What to avoid or be careful about
5. **Examples** (optional): Demonstrations of desired behavior

## Template

```markdown
# [Agent Name]

You are [role description]. Your purpose is to [primary goal].

## Available Tools

You have access to the following tools:

- `tool_name`: Brief description of when to use this tool
- `another_tool`: When and why to use this one

## How to Approach Tasks

1. [First step in your workflow]
2. [Second step]
3. [Continue as needed]

## Output Format

[Describe how you want the agent to structure its responses]

When reporting results, use this structure:
- Summary: Brief overview
- Details: Specific findings
- Recommendations: Next steps (if applicable)

## Important Guidelines

- [Constraint or rule 1]
- [Constraint or rule 2]
- [Safety consideration]

## Examples

### Example 1: [Scenario]

User: [Example request]

Your approach:
1. [What you would do]
2. [Next step]

Response format:
[Example of expected output format]
```

## Best Practices

### Be Specific About Tool Usage

```markdown
# Good
Use `search_files` when you need to find files by name or pattern.
Use `read_file` when you already know the exact file path.

# Bad
Use the tools to help the user.
```

### Define Clear Output Formats

```markdown
# Good
Return findings as a structured list:
- **Finding**: Description of what was found
- **Location**: Where it was found
- **Severity**: High/Medium/Low
- **Recommendation**: What to do about it

# Bad
Explain what you found.
```

### Set Boundaries

```markdown
# Good
Only operate on files within the project directory.
Never modify files without explicit user confirmation.
If uncertain, ask for clarification before proceeding.

# Bad
Be helpful and do what the user asks.
```

### Include Error Handling Guidance

```markdown
# Good
If a tool returns an error:
1. Explain what went wrong in simple terms
2. Suggest alternatives if available
3. Ask the user how to proceed

# Bad
Handle errors appropriately.
```

## File Naming

Name prompt files to match the `prompt_file` property in your agent:

```python
class YourAgent(BaseAgent):
    @property
    def prompt_file(self) -> str:
        return "your_agent.md"  # -> prompts/your_agent.md
```

## Testing Prompts

Iterate on your prompts by:

1. Running the agent with `verbose=True` to see its reasoning
2. Testing edge cases and error conditions
3. Checking that tool usage matches your guidance
4. Verifying output format consistency

```python
agent = YourAgent()
result = await agent.run("test task", verbose=True)
```
