FROM kalilinux/kali-rolling:latest

LABEL description="Responder — LLMNR/NBT-NS poisoner for SOC red team lab"
LABEL warning="RED TEAM TOOL — only use in isolated lab network"

RUN apt-get update -q && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-netifaces \
        net-tools iputils-ping tcpdump \
        git curl && \
    rm -rf /var/lib/apt/lists/*

# Install Responder from official repo
RUN git clone https://github.com/lgandx/Responder.git /opt/responder && \
    pip3 install --no-cache-dir netifaces

WORKDIR /opt/responder

# Copy custom config
COPY Responder.conf /opt/responder/Responder.conf

# Captured hashes land in /opt/responder/logs
VOLUME ["/opt/responder/logs"]

# Entrypoint — interface injected at runtime via RESPONDER_INTERFACE env
ENTRYPOINT ["python3", "Responder.py"]
CMD ["-I", "eth0", "-wrf", "--profile", "redteam"]
