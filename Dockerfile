FROM python:3.9-slim

LABEL maintainer="Security Community <security@community.org>"
LABEL description="Supply Chain Security Scanner - Detect compromised NPM packages"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY scanner.py .
COPY compromised_packages.txt .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash scanner && \
    chown -R scanner:scanner /app

USER scanner

# Default command
ENTRYPOINT ["python", "scanner.py"]
CMD ["--help"]