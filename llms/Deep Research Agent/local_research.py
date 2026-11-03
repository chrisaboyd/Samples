from openai import OpenAI

client = OpenAI(
    base_url="http://0.0.0.0:8000/v1",  # Local endpoint
    api_key="not-needed-for-local"      # Local deployments typically don't require auth
)

completion = client.chat.completions.create(
    model="nvidia/nvidia-nemotron-nano-9b-v2",
    messages=[
        {"role": "system", "content": "/think"},
        {"role": "user", "content": "Write a limerick about the wonders of GPU computing."}
    ],
    stream=True
)