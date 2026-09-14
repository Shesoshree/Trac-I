# =====================================================================
# TRAC-I: AI Phishing Intelligence & Threat Triage Engine
# Production Container Specification
# =====================================================================

FROM python:3.11-slim

# Set environment flags
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    HOST=0.0.0.0

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and models
COPY . .

# Ensure data directory exists with write permissions for SQLite persistence
RUN mkdir -p /app/data && chmod -R 777 /app/data

# Run security & verification test suite during build
RUN python run_tests.py

# Expose service port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/ || exit 1

# Production entrypoint
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
