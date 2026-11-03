#!/bin/bash


# Set your NGC API key
if [[ -z "$NGC_API_KEY" ]]; then
    echo "NGC_API_KEY is not set."
fi


# # Login to NVIDIA Container Registry
echo "${NGC_API_KEY}" | docker login nvcr.io -u '$oauthtoken' --password-stdin


# # Run the NIM container
docker run -it -d --rm \
  --name local-nim \
  --runtime=nvidia \
  --gpus all \
  -p 8000:8000 \
  -v "/tmp:/opt/nim/.cache" \
  -e NGC_API_KEY="${NGC_API_KEY}" \
  --shm-size=20g \
  nvcr.io/nim/nvidia/nvidia-nemotron-nano-9b-v2:latest


# Test the model locally
curl -X 'POST' \
'http://0.0.0.0:8000/v1/chat/completions' \
-H 'accept: application/json' \
-H 'Content-Type: application/json' \
-d '{
    "model": "nvidia/nvidia-nemotron-nano-9b-v2",
    "messages": [{"role": "system", "content": "/think"}, {"role":"user", "content":"Write a limerick about the wonders of GPU computing."}],
    "max_tokens": 2048
}'