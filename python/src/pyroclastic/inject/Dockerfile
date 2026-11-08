FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV ASAN_OPTIONS="symbolize=1:detect_leaks=0:abort_on_error=1"
ENV PYTHONUNBUFFERED=1

# Install core build dependencies, debugging tools, and network utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang-14 \
    lldb-14 \
    llvm-14 \
    gdb \
    gdbserver \
    strace \
    ltrace \
    libc6-dbg \
    curl \
    wget \
    git \
    netcat \
    net-tools \
    iproute2 \
    python3 \
    python3-pip \
    python3-dev \
    libssl-dev \
    libffi-dev \
    ca-certificates \
    && rm -rf /var/lib/apt-get/lists/*

# Set up Python virtual environment and analysis/RPC libraries
RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools \
    && python3 -m pip install --no-cache-dir \
    pwntools \
    scapy \
    requests \
    grpcio \
    grpcio-tools \
    thrift \
    psutil

# Install GEF (GDB Enhanced Features) for structured dynamic state parsing
RUN wget -O ~/.gdbinit-gef.py https://gef.blast.hk/py && \
    echo "source ~/.gdbinit-gef.py" >> ~/.gdbinit

# Create isolated working directory structure
WORKDIR /sandbox
RUN mkdir -p /sandbox/targets /sandbox/payloads /sandbox/logs

# Default entrypoint keeps the container alive for programmatic agent interaction
CMD ["tail", "-f", "/dev/null"]