FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data

# Install system utilities needed for network scanning (ping, arp)
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY lanscanner ./lanscanner
COPY main.py .

# Persistent storage for SQLite database (lanscanner.db)
VOLUME /data

# Expose web application port
EXPOSE 8000

# Launch FastAPI web application
CMD ["uvicorn", "lanscanner.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
