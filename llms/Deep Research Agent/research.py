from openai import OpenAI
import os, getpass

# Get NGC Key from Environment
if not os.environ.get("NGC_API_KEY", "").startswith("nvapi-"):
    nvapi_key = getpass.getpass("Enter your NVIDIA NGC API key: ")
    assert nvapi_key.startswith("nvapi-"), f"{nvapi_key[:5]}... is not a valid key"
    os.environ["NGC_API_KEY"] = nvapi_key
    print("✅ API key has been set in notebook environment")
else:
    print("✅ API key has been detected from environment")
# Get TAVILY Key from Environment

## Setup the client
client = OpenAI(
    base_url = "https://integrate.api.nvidia.com/v1",  # NVIDIA endpoint
    api_key = os.environ["NGC_API_KEY"]                # Your API key
)

# Standard Request (No Reasoning)
completion_no_reasoning = client.chat.completions.create(
    model="nvidia/nemotron-3.5-super-vl-120b-a12b",
    messages=[
        {"role":"system", "content":"/no_think"},  # Standard system message
        {"role":"user", "content":"How many 'r's are in 'strawberry'?"}
    ],
    temperature=0.6,
    top_p=0.95,
    max_tokens=1024,
    stream=True
)

# Lets print the results
print("📝 Response WITHOUT reasoning:\n")
for chunk in completion_no_reasoning:
    if not chunk.choices:
        continue

    content = chunk.choices[0].delta.content
    if content is not None:
        print(content, end="", flush=True)
print()

# Standard Request (No Reasoning)
completion_with_reasoning = client.chat.completions.create(
    model="nvidia/nemotron-3.5-super-vl-120b-a12b",
    messages=[
        {"role":"system", "content":"/think"},  # Standard system message with thinking enabled
        {"role":"user", "content":"How many 'r's are in 'strawberry'?"}
    ],
    temperature=0.6,
    top_p=0.95,
    max_tokens=65536, # Larger to accomodate reasoning tokens
    stream=True
)

# Lets print the results
print("📝 Response WITH reasoning:\n")
for chunk in completion_with_reasoning:
    if not chunk.choices:
        continue

    content = chunk.choices[0].delta.content
    if content is not None:
        print(content, end="", flush=True)

print()

# Raw curl request
# curl https://integrate.api.nvidia.com/v1/chat/completions \
# -H "Content-Type: application/json" \
# -H "Authorization: Bearer $NGC_API_KEY" \
# -d '{"model": "nvidia/nemotron-3.5-super-vl-120b-a12b", "messages": [{"role": "system", "content": "/think"}, {"role": "user", "content": "How many \"r\"s are in \"strawberry\"?"}], "temperature": 0.6, "top_p": 0.95, "max_tokens": 16, "stream": true}'