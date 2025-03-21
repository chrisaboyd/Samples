FROM python:3.11-slim

WORKDIR /app

# Install curl for health checks
RUN apt-get update \
    && apt-get install -y curl \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download the sentence transformer model
# This workaround helps avoid import errors that can happen
# when the model is downloaded at runtime
RUN mkdir -p /root/.cache/torch/sentence_transformers
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')" || echo "Model download might have failed, but we'll continue anyway"

# Copy application code
COPY . .

# Expose the port
EXPOSE 8081

# Start the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8081"] 