# Use a standard Python base image for reliability and transparency
FROM python:3.10-slim

# Set environment variable for non-interactive apt installs
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    zlib1g-dev \
    patchelf \
    curl \
    && curl -LO https://github.com/upx/upx/releases/download/v4.2.1/upx-4.2.1-amd64_linux.tar.xz \
    && tar -xf upx-4.2.1-amd64_linux.tar.xz \
    && mv upx-4.2.1-amd64_linux/upx /usr/local/bin/ \
    && rm -rf upx-4.2.1* \
    && rm -rf /var/lib/apt/lists/*

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y wine wine32:i386
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
    zstandard==0.22.0 \
    mythic-container


# Set working directory
WORKDIR /Mythic/

# Copy project files
COPY . .

# Ensure executable permissions for Python scripts
RUN chmod +x /Mythic/*.py

# Command to run the main script
CMD ["python3", "main.py"]