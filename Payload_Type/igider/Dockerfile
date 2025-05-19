FROM itsafeaturemythic/mythic_python_base:latest

# Install system dependencies
RUN apt-get update && apt-get install -y \
    upx \
    build-essential \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    pyinstaller==5.13.2 \
    pyarmor==8.3.6 \
    cryptography==42.0.5 \
    pycryptodome==3.20.0 \
    zstandard==0.22.0

# Install Windows cross-compilation tools (optional)
RUN if [ "$TARGETOS" = "windows" ]; then \
    apt-get install -y \
    mingw-w64 \
    osslsigncode \
    && pip install pyinstaller-cross; \
    fi


WORKDIR /Mythic/

COPY . .
# Ensure executable permissions
RUN chmod +x /Mythic/*.py

CMD ["python3", "main.py"]