# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim

LABEL maintainer="Hybrid-IDS Team" \
      description="Production image for Hybrid-IDS: Rule + ML Packet Inspection, IPS Engine, and Dashboard" \
      version="1.0"

# Install system dependencies: Python 3, pip, venv, libpcap (Scapy), curl (healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    libpcap0.8 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Configure isolated Python virtual environment for ML inference engine & feature extraction
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install Python ML dependencies
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r backend/requirements.txt

# Install Node dependencies
COPY package*.json ./
RUN npm ci

# Copy project source tree
COPY . .

# Build Vite frontend production bundle into dist/
RUN npm run build

# Default runtime environment
ENV NODE_ENV=production \
    PORT=3000 \
    PYTHON_BIN=/opt/venv/bin/python3 \
    HYBRID_IDS_DB=/app/data/hybrid_ids.db \
    ADMIN_API_KEY=hybrid-ids-admin-secret

# Expose standard application port
EXPOSE 3000

# Persistent storage volume for SQLite database and logs
VOLUME ["/app/data"]

# Health check to verify HTTP REST API & engine availability
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:3000/api/health || exit 1

# Start the full-stack server
CMD ["npx", "tsx", "server.ts"]
