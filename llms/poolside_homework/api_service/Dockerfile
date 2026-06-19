FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code from the current directory (here) to the working directory (/app)
COPY . .

# Expose the port
EXPOSE 8080

# Start the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
