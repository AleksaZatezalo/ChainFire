# Single-stage image — nuclei installed via pre-built binary from GitHub releases.
# This avoids compiling from source and removes any dependency on Go version.
FROM python:3.11-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei: fetch the latest release binary for linux/amd64
RUN NUCLEI_VERSION=$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
      | grep '"tag_name"' \
      | sed 's/.*"v\([^"]*\)".*/\1/') \
    && curl -fsSL \
       "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
       -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create persistent data directory (mounted as volume in production)
RUN mkdir -p /app/data /workspace

# Pre-warm nuclei templates (best-effort; skipped if no internet at build time)
RUN nuclei -update-templates -disable-update-check 2>/dev/null || true

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
