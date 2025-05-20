# Use a standard Python base image for reliability and transparency
FROM python:3.10-slim

# Set environment variable for non-interactive apt installs
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    upx \
    build-essential \
    zlib1g-dev \
    patchelf \
    && rm -rf /var/lib/apt/lists/*

# Install Windows cross-compilation tools if TARGETOS is windows
ARG TARGETOS
RUN if [ "$TARGETOS" = "windows" ]; then \
    apt-get update && apt-get install -y \
    mingw-w64 \
    osslsigncode \
    && rm -rf /var/lib/apt/lists/*; \
    fi

# Create and activate a virtual environment
RUN python3 -m venv /venv
ENV PATH="/venv/bin:$PATH"

# Install Python dependencies in the virtual environment
RUN pip install --no-cache-dir \
    pyinstaller==6.0.0 \
    pyarmor==8.3.6 \
    cryptography==42.0.5 \
    pycryptodome==3.20.0 \
    zstandard==0.22.0

# Set working directory
WORKDIR /Mythic/

# Copy project files
COPY . .

# Ensure executable permissions for Python scripts
RUN chmod +x /Mythic/*.py

# Command to run the main script
CMD ["python3", "main.py"]