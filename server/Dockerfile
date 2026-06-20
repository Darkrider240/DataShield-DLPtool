FROM python:3.12-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY server/requirements.txt /app/server/requirements.txt
RUN pip install --no-cache-dir -r /app/server/requirements.txt

# Copy application code
COPY crypto/ /app/crypto/
COPY server/ /app/server/
COPY rules/ /app/rules/

# Run init + server
CMD ["sh", "-c", "python -m server.init_db && uvicorn server.main:app --host 0.0.0.0 --port 8000"]
