FROM python:3.12-slim AS base

WORKDIR /app

# Install deps first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download AWS RDS/DocumentDB CA bundle for TLS connections
RUN apt-get update && apt-get install -y --no-install-recommends wget ca-certificates \
    && wget -q https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem \
       -O /tmp/rds-combined-ca-bundle.pem \
    && apt-get purge -y wget && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Copy application code — the app imports resolve relative to api/
COPY api/ ./

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1

# main.py does `from flights.router import ...` so WORKDIR must contain flights/
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
